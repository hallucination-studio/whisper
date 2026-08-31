//! Board-facing UDP receipt and postcommit writer-event delivery.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, watch};

use super::{RuntimeError, RuntimeErrorKind, SocketOperation, SocketRole};
use crate::application::{CaptureRuntime, RuntimeClock};
use crate::{CapturedDatagram, ProjectionCommit};

pub(super) fn bind_socket(
    address: SocketAddr,
    receive_buffer_bytes: usize,
) -> Result<UdpSocket, RuntimeError> {
    let socket = Socket::new(Domain::for_address(address), Type::DGRAM, Some(Protocol::UDP))
        .map_err(|source| {
            RuntimeError::socket(SocketRole::Capture, SocketOperation::Create, address, source)
        })?;
    socket.set_recv_buffer_size(receive_buffer_bytes).map_err(|source| {
        RuntimeError::socket(SocketRole::Capture, SocketOperation::Configure, address, source)
    })?;
    socket.bind(&address.into()).map_err(|source| {
        RuntimeError::socket(SocketRole::Capture, SocketOperation::Bind, address, source)
    })?;
    socket.set_nonblocking(true).map_err(|source| {
        RuntimeError::socket(SocketRole::Capture, SocketOperation::Configure, address, source)
    })?;
    UdpSocket::from_std(socket.into()).map_err(|source| {
        RuntimeError::socket(SocketRole::Capture, SocketOperation::Configure, address, source)
    })
}

pub(super) async fn run(
    capture: Arc<Mutex<Option<CaptureRuntime>>>,
    socket: UdpSocket,
    socket_address: SocketAddr,
    maximum_datagram_bytes: usize,
    mut shutdown: watch::Receiver<bool>,
    queue_drop_count: Arc<AtomicU64>,
    clock: RuntimeClock,
) -> Result<(), RuntimeError> {
    let receive_capacity = maximum_datagram_bytes
        .checked_add(1)
        .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::Capacity("UDP receive buffer")))?;
    let mut buffer = vec![0_u8; receive_capacity];
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (length, peer) = received.map_err(|source| {
                    RuntimeError::socket(
                        SocketRole::Capture,
                        SocketOperation::Receive,
                        socket_address,
                        source,
                    )
                })?;
                if length > maximum_datagram_bytes {
                    continue;
                }
                let (received_monotonic, received_utc) = clock.sample();
                let datagram = CapturedDatagram::new(
                    peer,
                    received_monotonic,
                    received_utc,
                    buffer[..length].to_vec().into_boxed_slice(),
                );
                let capture = Arc::clone(&capture);
                let (result, drops) = tokio::task::spawn_blocking(move || {
                    let mut owner = capture
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let capture = owner.as_mut().ok_or_else(|| {
                        RuntimeError::new(RuntimeErrorKind::State("Capture runtime ownership"))
                    })?;
                    let result = capture.try_submit(datagram);
                    Ok::<_, RuntimeError>((result, capture.queue_drop_count()))
                })
                .await
                .map_err(|error| RuntimeError::join("datagram admission", error))??;
                queue_drop_count.store(drops, Ordering::Release);
                match result {
                    Ok(ticket) => drop(ticket),
                    Err(error) if error.is_writer_stopped() => {
                        return Err(RuntimeError::submit(error));
                    }
                    Err(_) => {}
                }
            }
        }
    }
    Ok(())
}

pub(super) async fn deliver_writer_events(
    mut events: watch::Receiver<Option<crate::application::WriterEvent>>,
    mut shutdown: watch::Receiver<bool>,
    live: broadcast::Sender<ProjectionCommit>,
    store_id: [u8; 32],
) -> Result<(), RuntimeError> {
    let mut stopping = *shutdown.borrow();
    loop {
        tokio::select! {
            changed = shutdown.changed(), if !stopping => {
                stopping = changed.is_err() || *shutdown.borrow();
            }
            changed = events.changed() => {
                if changed.is_err() {
                    return if stopping || *shutdown.borrow() {
                        Ok(())
                    } else {
                        Err(RuntimeError::new(RuntimeErrorKind::WriterStopped))
                    };
                }
                match events.borrow_and_update().clone() {
                    Some(crate::application::WriterEvent::Committed(sequence)) => {
                        if !stopping {
                            let _ = live.send(ProjectionCommit::new(store_id, sequence));
                        }
                    }
                    Some(crate::application::WriterEvent::Fatal(error)) => {
                        return Err(RuntimeError::new(RuntimeErrorKind::Writer(error)));
                    }
                    Some(crate::application::WriterEvent::Stopped { panicked }) => {
                        if stopping || *shutdown.borrow() {
                            return Ok(());
                        }
                        if panicked {
                            return Err(RuntimeError::new(RuntimeErrorKind::Writer(
                                Arc::new(crate::application::HostError::WriterPanicked),
                            )));
                        }
                        return Err(RuntimeError::new(RuntimeErrorKind::WriterStopped));
                    }
                    None => {}
                }
            }
        }
    }
}
