//! Authenticated UDP ingress admission before the sole-writer queue.

use super::*;
pub(super) fn reader_loop(
    config: ReaderConfig,
    ingress: mpsc::SyncSender<AdmittedDatagram>,
    overflow: &OverflowSummary,
    rejections: &Mutex<VecDeque<RejectedDatagram>>,
    stop: &AtomicBool,
) -> Result<(), HostError> {
    let largest_route_datagram = config
        .routes
        .iter()
        .map(|route| route.limits.datagram_bytes.get())
        .max()
        .expect("validated Host has a route");
    let mut buffer = vec![0_u8; largest_route_datagram.saturating_add(1)];
    let mut rates = vec![RouteRateState::new(config.clock.monotonic_now()); config.routes.len()];
    while !stop.load(Ordering::Acquire) {
        let (length, peer) = match config.socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
            {
                continue;
            }
            Err(error) => {
                return Err(HostError::io_during(
                    "receive UDP datagram",
                    None,
                    Some(config.local_addr),
                    Some("whisper-udp-reader"),
                    error,
                ));
            }
        };
        // Receive time is a fact about kernel delivery, so sample it before any
        // parsing, authentication, rate admission, or queue work can delay it.
        let received_utc_ns = utc_now_ns(config.clock.as_ref())?;
        if length > largest_route_datagram {
            record_rejection(rejections, peer, RejectReason::DatagramTooLarge);
            continue;
        }
        let bytes = &buffer[..length];
        let Ok(header) = parse_header(bytes) else {
            record_rejection(rejections, peer, RejectReason::MalformedEnvelope);
            continue;
        };
        let Some((route_index, route)) = config.routes.iter().enumerate().find(|(_, route)| {
            route.peer == peer.ip()
                && route.device_id.get() == header.device_id()
                && route.key_epoch.get() == header.key_epoch()
        }) else {
            record_rejection(rejections, peer, RejectReason::UnknownRoute);
            continue;
        };
        if length > route.limits.datagram_bytes.get() {
            record_rejection(rejections, peer, RejectReason::DatagramTooLarge);
            continue;
        }
        let Ok(authenticated) = authenticate_datagram(route.key.as_bytes(), bytes) else {
            record_rejection(rejections, peer, RejectReason::AuthenticationFailed);
            continue;
        };
        if !rates[route_index].admit(
            config.clock.monotonic_now(),
            length,
            route.limits.packets_per_second.get(),
            route.limits.authenticated_bytes_per_second.get(),
        ) {
            record_rejection(rejections, peer, RejectReason::AuthenticatedRateLimited);
            continue;
        }
        let item = AdmittedDatagram {
            route_index,
            header: authenticated.header(),
            received_utc_ns,
            peer,
            bytes: bytes.into(),
        };
        match ingress.try_send(item) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                overflow.count.fetch_add(1, Ordering::Relaxed);
                record_rejection(rejections, peer, RejectReason::IngressQueueFull);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return Ok(()),
        }
    }
    Ok(())
}
