//! Concrete Host composition and independently owned bounded cleanup.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, atomic::AtomicU64};
use std::time::Duration;

use futures_util::FutureExt;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::JoinHandle;

#[cfg(feature = "ingest-test-hooks")]
use super::TeardownHold;
use super::http::ConnectionRegistry;
use super::{
    HostRuntime, RuntimeCompletion, RuntimeControl, RuntimeError, RuntimeErrorKind,
    SocketOperation, SocketRole, capture, http,
};
#[cfg(feature = "ingest-test-hooks")]
use crate::application::ManualClockControl;
use crate::application::RuntimeClock;
#[cfg(feature = "ingest-test-hooks")]
use crate::store::QueryHold;
#[cfg(feature = "ingest-test-hooks")]
use crate::store::RelationshipFailureStage;
use crate::store::{QueryLimits, QueryStore};
use crate::{Config, LifecycleError};

/// Grace allowed for accepted HTTP connections before forced socket shutdown.
///
/// This is a Host shutdown bound, not a request timeout. Increasing it delays
/// writer/query teardown and Managed-store lease release for every shutdown.
const HTTP_CONNECTION_GRACE: Duration = Duration::from_millis(100);

struct Startup {
    session_id: crate::SessionId,
    capture_address: SocketAddr,
    queue_drop_count: Arc<AtomicU64>,
    http_address: SocketAddr,
    #[cfg(feature = "ingest-test-hooks")]
    query: QueryStore,
}

#[derive(Default)]
struct SupervisorControls {
    hold_writer: bool,
    panic_writer: bool,
    #[cfg(feature = "ingest-test-hooks")]
    hold_query: bool,
    #[cfg(feature = "ingest-test-hooks")]
    teardown_gate: Option<TeardownGate>,
    #[cfg(feature = "ingest-test-hooks")]
    relationship_failure: Option<RelationshipFailureStage>,
    #[cfg(feature = "ingest-test-hooks")]
    manual_clock: bool,
}

#[cfg(feature = "ingest-test-hooks")]
struct TeardownGate {
    entered: Option<oneshot::Sender<()>>,
    release: std::sync::mpsc::Receiver<()>,
}

struct Supervisor {
    config: Config,
    clock: RuntimeClock,
    controls: SupervisorControls,
    control: RuntimeControl,
    #[cfg(feature = "ingest-test-hooks")]
    writer_hold: Arc<Mutex<Option<crate::application::WriterHold>>>,
    #[cfg(feature = "ingest-test-hooks")]
    query_hold: Arc<Mutex<Option<QueryHold>>>,
}

struct SupervisorLaunch {
    supervisor: Supervisor,
    completion: Arc<RuntimeCompletion>,
    ready: oneshot::Sender<Result<Startup, RuntimeError>>,
}

pub(super) async fn start(config: &Config) -> Result<HostRuntime, RuntimeError> {
    start_inner(config, SupervisorControls::default()).await
}

#[cfg(feature = "ingest-test-hooks")]
pub(super) async fn start_with_writer_held(config: &Config) -> Result<HostRuntime, RuntimeError> {
    start_inner(config, SupervisorControls { hold_writer: true, ..SupervisorControls::default() })
        .await
}

#[cfg(feature = "ingest-test-hooks")]
pub(super) async fn start_with_panicked_writer(
    config: &Config,
) -> Result<HostRuntime, RuntimeError> {
    start_inner(config, SupervisorControls { panic_writer: true, ..SupervisorControls::default() })
        .await
}

#[cfg(feature = "ingest-test-hooks")]
pub(super) async fn start_with_relationship_failure(
    config: &Config,
    stage: RelationshipFailureStage,
) -> Result<HostRuntime, RuntimeError> {
    start_inner(
        config,
        SupervisorControls { relationship_failure: Some(stage), ..SupervisorControls::default() },
    )
    .await
}

#[cfg(feature = "ingest-test-hooks")]
pub(super) async fn start_with_manual_clock(config: &Config) -> Result<HostRuntime, RuntimeError> {
    start_inner(config, SupervisorControls { manual_clock: true, ..SupervisorControls::default() })
        .await
}

#[cfg(feature = "ingest-test-hooks")]
pub(super) async fn start_with_query_held(
    config: &Config,
) -> Result<(HostRuntime, QueryHold), RuntimeError> {
    let runtime = start_inner(
        config,
        SupervisorControls { hold_query: true, ..SupervisorControls::default() },
    )
    .await?;
    let hold = runtime
        .query_hold
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::State("query hold")))?;
    Ok((runtime, hold))
}

#[cfg(feature = "ingest-test-hooks")]
pub(super) async fn start_with_teardown_held(
    config: &Config,
) -> Result<(HostRuntime, TeardownHold), RuntimeError> {
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let controls = SupervisorControls {
        teardown_gate: Some(TeardownGate { entered: Some(entered_tx), release: release_rx }),
        ..SupervisorControls::default()
    };
    let runtime = start_inner(config, controls).await?;
    Ok((runtime, TeardownHold { entered: Some(entered_rx), release: Some(release_tx) }))
}

async fn start_inner(
    config: &Config,
    controls: SupervisorControls,
) -> Result<HostRuntime, RuntimeError> {
    #[cfg(feature = "ingest-test-hooks")]
    let (clock, manual_clock): (RuntimeClock, Option<ManualClockControl>) = if controls.manual_clock
    {
        let (clock, control) = RuntimeClock::manual();
        (clock, Some(control))
    } else {
        (RuntimeClock::system(), None)
    };
    #[cfg(not(feature = "ingest-test-hooks"))]
    let clock = RuntimeClock::system();
    let control = RuntimeControl::new();
    let completion = Arc::new(RuntimeCompletion::new());
    #[cfg(feature = "ingest-test-hooks")]
    let writer_hold = Arc::new(Mutex::new(None));
    #[cfg(feature = "ingest-test-hooks")]
    let query_hold = Arc::new(Mutex::new(None));
    let (ready_tx, ready_rx) = oneshot::channel();
    let launch = SupervisorLaunch {
        supervisor: Supervisor {
            config: config.clone(),
            clock,
            controls,
            control: control.clone(),
            #[cfg(feature = "ingest-test-hooks")]
            writer_hold: Arc::clone(&writer_hold),
            #[cfg(feature = "ingest-test-hooks")]
            query_hold: Arc::clone(&query_hold),
        },
        completion: Arc::clone(&completion),
        ready: ready_tx,
    };
    std::thread::Builder::new()
        .name("whisper-host-supervisor".to_owned())
        .spawn(move || run(launch))
        .map_err(|error| RuntimeError::new(RuntimeErrorKind::SupervisorSpawn(error)))?;
    let startup =
        ready_rx.await.map_err(|_| RuntimeError::new(RuntimeErrorKind::SupervisorStopped))??;
    Ok(HostRuntime {
        session_id: startup.session_id,
        capture_address: startup.capture_address,
        queue_drop_count: startup.queue_drop_count,
        http_address: startup.http_address,
        control,
        completion,
        #[cfg(feature = "ingest-test-hooks")]
        writer_hold,
        #[cfg(feature = "ingest-test-hooks")]
        query_hold,
        #[cfg(feature = "ingest-test-hooks")]
        query: Some(startup.query),
        #[cfg(feature = "ingest-test-hooks")]
        manual_clock,
    })
}

fn run(mut launch: SupervisorLaunch) {
    let mut ready = Some(launch.ready);
    let panic_control = launch.supervisor.control.clone();
    let panic_completion = Arc::clone(&launch.completion);
    let result =
        std::panic::catch_unwind(AssertUnwindSafe(|| launch.supervisor.execute(&mut ready)));
    match result {
        Ok(result) => {
            if let Some(ready) = ready.take() {
                if let Err(error) = result {
                    let _ = ready.send(Err(error));
                }
            } else {
                launch.completion.finish(result);
            }
        }
        Err(_) => {
            let error = RuntimeError::new(RuntimeErrorKind::TaskPanicked("Host supervisor"));
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(error));
            } else {
                panic_control.fail(error);
                panic_completion.finish(Err(panic_control.take_fatal().unwrap_or_else(|| {
                    RuntimeError::new(RuntimeErrorKind::TaskPanicked("Host supervisor"))
                })));
            }
        }
    }
}

impl Supervisor {
    fn execute(
        &mut self,
        ready: &mut Option<oneshot::Sender<Result<Startup, RuntimeError>>>,
    ) -> Result<(), RuntimeError> {
        validate_network_roles(&self.config)?;
        let socket_buffer_bytes = usize::try_from(self.config.capture().socket_buffer_bytes())
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::Capacity("capture socket buffer")))?;
        let maximum_datagram_bytes = usize::try_from(self.config.capture().max_datagram_bytes())
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::Capacity("capture datagram")))?;
        let live_capacity = usize::try_from(self.config.server().websocket_queue_capacity())
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::Capacity("WebSocket queue")))?;
        let limits = QueryLimits::try_new(
            self.config.view().max_signal_points(),
            self.config.view().max_time_buckets(),
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| RuntimeError::new(RuntimeErrorKind::Executor(error)))?;
        let (capture_socket, http_listener) = {
            let _runtime_context = runtime.enter();
            (
                capture::bind_socket(self.config.capture().bind(), socket_buffer_bytes)?,
                http::bind_socket(self.config.server().bind())?,
            )
        };
        let capture_address = capture_socket.local_addr().map_err(|source| {
            RuntimeError::socket(
                SocketRole::Capture,
                SocketOperation::LocalAddress,
                self.config.capture().bind(),
                source,
            )
        })?;
        let http_address = http_listener.local_addr().map_err(|source| {
            RuntimeError::socket(
                SocketRole::Http,
                SocketOperation::LocalAddress,
                self.config.server().bind(),
                source,
            )
        })?;
        let capture = crate::application::serve_with_clock(&self.config, self.clock.clone())
            .map_err(LifecycleError::host)?;
        #[cfg(feature = "ingest-test-hooks")]
        let mut capture = capture;
        let store_id = capture.store_id();
        let query = capture.query_store()?;
        #[cfg(feature = "ingest-test-hooks")]
        let query = if self.controls.hold_query {
            let (query, hold) = query.hold_for_test();
            *self.query_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hold);
            query
        } else {
            query
        };
        let session_id = crate::SessionId::new(capture.session_id())
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::State("Capture Session identity")))?;
        let (writer_events_tx, writer_events_rx) = watch::channel(None);
        capture
            .observe_writer(Arc::new(move |event| {
                writer_events_tx.send_replace(Some(event));
            }))
            .map_err(LifecycleError::host)?;
        let relationship_commands = capture.relationship_commands();
        #[cfg(feature = "ingest-test-hooks")]
        if self.controls.hold_writer {
            *self.writer_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(capture.hold_writer().map_err(LifecycleError::host)?);
        }
        #[cfg(not(feature = "ingest-test-hooks"))]
        let _ = self.controls.hold_writer;
        #[cfg(feature = "ingest-test-hooks")]
        if self.controls.panic_writer {
            capture.panic_writer_for_test().map_err(LifecycleError::host)?;
        }
        #[cfg(not(feature = "ingest-test-hooks"))]
        let _ = self.controls.panic_writer;
        #[cfg(feature = "ingest-test-hooks")]
        if let Some(stage) = self.controls.relationship_failure {
            capture.arm_relationship_failure(stage).map_err(LifecycleError::host)?;
        }

        let capture_owner = Arc::new(Mutex::new(Some(capture)));
        let queue_drop_count = Arc::new(AtomicU64::new(0));
        let connections = ConnectionRegistry::default();
        let (live_tx, _) = broadcast::channel(live_capacity);
        let app = http::router(
            query.clone(),
            limits,
            live_tx.clone(),
            relationship_commands,
            self.control.clone(),
        );
        let http_listener = http::TrackedListener::new(
            http_listener,
            connections.clone(),
            self.control.clone(),
            http_address,
        );
        let startup = Startup {
            session_id,
            capture_address,
            queue_drop_count: Arc::clone(&queue_drop_count),
            http_address,
            #[cfg(feature = "ingest-test-hooks")]
            query: query.clone(),
        };
        let mut http_shutdown_rx = self.control.shutdown.subscribe();
        let task_control = self.control.clone();
        let task_capture = Arc::clone(&capture_owner);
        let ready = ready
            .take()
            .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::State("startup completion")))?;
        let mut commit_task = None;
        runtime.block_on(async {
            let http_task = spawn_supervised(
                "HTTP server",
                async move {
                    axum::serve(http_listener, app)
                        .with_graceful_shutdown(async move {
                            while !*http_shutdown_rx.borrow() {
                                if http_shutdown_rx.changed().await.is_err() {
                                    break;
                                }
                            }
                        })
                        .await
                        .map_err(|source| {
                            RuntimeError::socket(
                                SocketRole::Http,
                                SocketOperation::Serve,
                                http_address,
                                source,
                            )
                        })
                },
                task_control.clone(),
            );
            let writer_event_task = spawn_supervised(
                "writer events",
                capture::deliver_writer_events(
                    writer_events_rx,
                    task_control.shutdown.subscribe(),
                    live_tx,
                    store_id,
                ),
                task_control.clone(),
            );
            let capture_task = spawn_supervised(
                "UDP capture",
                capture::run(
                    task_capture,
                    capture_socket,
                    capture_address,
                    maximum_datagram_bytes,
                    task_control.shutdown.subscribe(),
                    queue_drop_count,
                    self.clock.clone(),
                ),
                task_control.clone(),
            );
            if ready.send(Ok(startup)).is_err() {
                task_control.stop();
            }
            stop_transport(capture_task, http_task, connections, query.clone(), task_control).await;
            commit_task = Some(writer_event_task);
        });
        let commit_task = commit_task
            .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::State("writer-event task")))?;

        #[cfg(feature = "ingest-test-hooks")]
        self.writer_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
        #[cfg(feature = "ingest-test-hooks")]
        if let Some(gate) = self.controls.teardown_gate.as_mut() {
            if let Some(entered) = gate.entered.take() {
                let _ = entered.send(());
            }
            let _ = gate.release.recv();
        }
        let capture = Arc::try_unwrap(capture_owner)
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::State("Capture runtime owner")))?
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::State("Capture runtime")))?;
        let shutdown_result = capture.shutdown().map_err(RuntimeError::shutdown);
        runtime.block_on(async {
            if let Err(error) = commit_task.await {
                self.control.fail(RuntimeError::join("writer-event supervisor", error));
            }
        });
        drop(runtime);
        let query_result = query.close().map_err(RuntimeError::from);
        let cleanup_result = shutdown_result.and(query_result);

        match self.control.take_fatal() {
            Some(error) => Err(error),
            None => cleanup_result,
        }
    }
}

fn spawn_supervised<F>(name: &'static str, future: F, control: RuntimeControl) -> JoinHandle<()>
where
    F: Future<Output = Result<(), RuntimeError>> + Send + 'static,
{
    tokio::spawn(async move {
        match AssertUnwindSafe(future).catch_unwind().await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => control.fail(error),
            Err(_) => control.fail(RuntimeError::new(RuntimeErrorKind::TaskPanicked(name))),
        }
    })
}

async fn stop_transport(
    capture_task: JoinHandle<()>,
    mut http_task: JoinHandle<()>,
    connections: ConnectionRegistry,
    query: QueryStore,
    control: RuntimeControl,
) {
    if let Err(error) = capture_task.await {
        control.fail(RuntimeError::join("UDP capture supervisor", error));
    }
    match tokio::time::timeout(HTTP_CONNECTION_GRACE, &mut http_task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => control.fail(RuntimeError::join("HTTP supervisor", error)),
        Err(_) => {
            query.interrupt();
            connections.shutdown_all();
            if let Err(error) = http_task.await {
                control.fail(RuntimeError::join("HTTP supervisor", error));
            }
        }
    }
}

fn validate_network_roles(config: &Config) -> Result<(), RuntimeError> {
    let server_ip = config.server().bind().ip();
    let capture_ip = config.capture().bind().ip();
    if !server_ip.is_loopback()
        || capture_ip.is_loopback()
        || capture_ip.is_multicast()
        || capture_ip == IpAddr::V4(Ipv4Addr::BROADCAST)
    {
        return Err(RuntimeError::new(RuntimeErrorKind::NetworkRole));
    }
    Ok(())
}
