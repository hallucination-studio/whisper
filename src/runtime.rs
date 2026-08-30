//! Async socket and delivery lifetime for the bounded delivery Host.

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering as AtomicOrdering},
};
use std::time::Duration;

use futures_util::FutureExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Notify, broadcast, oneshot, watch};
use tokio::task::JoinHandle;

use crate::{
    Config, LifecycleError, QueryError, QueryLimits, QueryStore, ShutdownError, SubmitError,
};

mod capture;
mod http;
mod websocket;

use capture::ReceiveClock;
use http::ConnectionRegistry;

/// Grace allowed for accepted HTTP connections before forced socket shutdown.
///
/// This is a Host shutdown bound, not a request timeout. Increasing it delays
/// writer/query teardown and Managed-store lease release for every shutdown.
const HTTP_CONNECTION_GRACE: Duration = Duration::from_millis(100);

/// A failure to admit, start, run, or stop the bounded Host runtime.
#[derive(Debug)]
pub struct RuntimeError {
    source: Box<RuntimeErrorKind>,
    backtrace: Backtrace,
}

/// Network role whose socket operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketRole {
    /// Board-facing UDP capture socket.
    Capture,
    /// Loopback HTTP and WebSocket listener or connection.
    Http,
}

/// Socket operation retained by a runtime failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketOperation {
    /// Create an operating-system socket.
    Create,
    /// Apply required socket configuration.
    Configure,
    /// Bind the configured address.
    Bind,
    /// Read the actual bound address.
    LocalAddress,
    /// Accept an HTTP connection.
    Accept,
    /// Receive a capture datagram.
    Receive,
    /// Register an accepted connection for bounded shutdown.
    Track,
    /// Serve accepted HTTP connections.
    Serve,
}

/// Stable subsystem classification for a Host runtime failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RuntimeFailure {
    /// Pre-Store network-role admission failed.
    NetworkRole,
    /// Capture admission or startup failed.
    Capture,
    /// The sole capture writer failed.
    Writer,
    /// Committed Store query failed.
    Query,
    /// A socket operation failed with retained context.
    Socket,
    /// Supervisor or task coordination failed.
    Supervisor,
    /// Blocking teardown failed after stop.
    Shutdown,
}

#[derive(Debug, thiserror::Error)]
enum RuntimeErrorKind {
    #[error("Host network bind roles are invalid")]
    NetworkRole,
    #[error("Capture runtime startup failed: {0}")]
    Capture(#[source] LifecycleError),
    #[error("Query Store startup failed: {0}")]
    Query(#[source] QueryError),
    #[error("{role:?} socket {operation:?} at {address} failed: {source}")]
    Socket {
        role: SocketRole,
        operation: SocketOperation,
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("Capture runtime shutdown failed: {0}")]
    Shutdown(#[source] ShutdownError),
    #[error("captured datagram submission failed: {0}")]
    Submit(#[source] SubmitError),
    #[error("capture writer failed: {0}")]
    Writer(#[source] Arc<crate::application::HostError>),
    #[error("Host runtime task {0} panicked")]
    TaskPanicked(&'static str),
    #[error("Host runtime task {task} failed to join: {source}")]
    Join {
        task: &'static str,
        #[source]
        source: tokio::task::JoinError,
    },
    #[error("Host supervisor thread could not be started: {0}")]
    SupervisorSpawn(#[source] std::io::Error),
    #[error("Host async executor could not be started: {0}")]
    Executor(#[source] std::io::Error),
    #[error("Host supervisor stopped before reporting startup")]
    SupervisorStopped,
    #[error("Host runtime capacity is invalid for {0}")]
    Capacity(&'static str),
    #[error("Host runtime state is unavailable: {0}")]
    State(&'static str),
    #[error("capture writer stopped without a fatal result")]
    WriterStopped,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl RuntimeError {
    /// Returns the stable subsystem classification for this failure.
    #[must_use]
    pub fn failure(&self) -> RuntimeFailure {
        if self.is_network_role() {
            return RuntimeFailure::NetworkRole;
        }
        match self.source.as_ref() {
            RuntimeErrorKind::Capture(_) | RuntimeErrorKind::Submit(_) => RuntimeFailure::Capture,
            RuntimeErrorKind::Writer(_) | RuntimeErrorKind::WriterStopped => RuntimeFailure::Writer,
            RuntimeErrorKind::Query(_) => RuntimeFailure::Query,
            RuntimeErrorKind::Socket { .. } => RuntimeFailure::Socket,
            RuntimeErrorKind::Shutdown(_) => RuntimeFailure::Shutdown,
            RuntimeErrorKind::NetworkRole => RuntimeFailure::NetworkRole,
            RuntimeErrorKind::TaskPanicked(_)
            | RuntimeErrorKind::Join { .. }
            | RuntimeErrorKind::SupervisorSpawn(_)
            | RuntimeErrorKind::Executor(_)
            | RuntimeErrorKind::SupervisorStopped
            | RuntimeErrorKind::Capacity(_)
            | RuntimeErrorKind::State(_) => RuntimeFailure::Supervisor,
        }
    }

    /// Returns whether pre-start network-role admission rejected the configuration.
    #[must_use]
    pub fn is_network_role(&self) -> bool {
        matches!(self.source.as_ref(), RuntimeErrorKind::NetworkRole)
            || matches!(
                self.source.as_ref(),
                RuntimeErrorKind::Socket {
                    role: SocketRole::Capture,
                    operation: SocketOperation::Bind,
                    source,
                    ..
                } if source.raw_os_error() == Some(libc::EADDRNOTAVAIL)
            )
    }

    /// Returns whether the sole writer failed or stopped unexpectedly.
    #[must_use]
    pub fn is_writer_failure(&self) -> bool {
        matches!(
            self.source.as_ref(),
            RuntimeErrorKind::Writer(_)
                | RuntimeErrorKind::WriterStopped
                | RuntimeErrorKind::Shutdown(_)
        )
    }

    /// Returns whether committed query authority failed validation or reading.
    #[must_use]
    pub fn is_query_failure(&self) -> bool {
        matches!(self.source.as_ref(), RuntimeErrorKind::Query(_))
    }

    /// Returns whether another lifecycle still holds the Managed-store lease.
    #[must_use]
    pub fn is_lease_conflict(&self) -> bool {
        matches!(
            self.source.as_ref(),
            RuntimeErrorKind::Capture(error) if error.is_lease_conflict()
        )
    }

    /// Returns the socket role when this is a socket failure.
    #[must_use]
    pub fn socket_role(&self) -> Option<SocketRole> {
        match self.source.as_ref() {
            RuntimeErrorKind::Socket { role, .. } => Some(*role),
            _ => None,
        }
    }

    /// Returns the socket operation when this is a socket failure.
    #[must_use]
    pub fn socket_operation(&self) -> Option<SocketOperation> {
        match self.source.as_ref() {
            RuntimeErrorKind::Socket { operation, .. } => Some(*operation),
            _ => None,
        }
    }

    /// Returns the configured or actual address when this is a socket failure.
    #[must_use]
    pub fn socket_address(&self) -> Option<SocketAddr> {
        match self.source.as_ref() {
            RuntimeErrorKind::Socket { address, .. } => Some(*address),
            _ => None,
        }
    }

    /// Returns the backtrace captured at the runtime interface.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn new(source: RuntimeErrorKind) -> Self {
        Self { source: Box::new(source), backtrace: Backtrace::capture() }
    }

    fn join(task: &'static str, source: tokio::task::JoinError) -> Self {
        Self::new(RuntimeErrorKind::Join { task, source })
    }

    fn socket(
        role: SocketRole,
        operation: SocketOperation,
        address: SocketAddr,
        source: std::io::Error,
    ) -> Self {
        Self::new(RuntimeErrorKind::Socket { role, operation, address, source })
    }
}

impl From<LifecycleError> for RuntimeError {
    fn from(source: LifecycleError) -> Self {
        Self::new(RuntimeErrorKind::Capture(source))
    }
}

impl From<QueryError> for RuntimeError {
    fn from(source: QueryError) -> Self {
        Self::new(RuntimeErrorKind::Query(source))
    }
}

impl From<ShutdownError> for RuntimeError {
    fn from(source: ShutdownError) -> Self {
        Self::new(RuntimeErrorKind::Shutdown(source))
    }
}

impl From<SubmitError> for RuntimeError {
    fn from(source: SubmitError) -> Self {
        Self::new(RuntimeErrorKind::Submit(source))
    }
}

/// One running bounded delivery socket, writer, query, and lifecycle composition.
///
/// Dropping the handle requests background cleanup; call [`HostRuntime::shutdown`] to await it.
#[must_use = "dropping HostRuntime requests stop without waiting for cleanup errors"]
pub struct HostRuntime {
    session_id: crate::SessionId,
    capture_address: SocketAddr,
    queue_drop_count: Arc<AtomicU64>,
    http_address: SocketAddr,
    control: RuntimeControl,
    completion: Arc<RuntimeCompletion>,
    #[cfg(feature = "ingest-test-hooks")]
    writer_hold: Arc<Mutex<Option<crate::application::WriterHold>>>,
    #[cfg(feature = "ingest-test-hooks")]
    query_hold: Arc<Mutex<Option<crate::QueryHold>>>,
}

/// Test-only gate that pauses final teardown on the independent supervisor.
#[cfg(feature = "ingest-test-hooks")]
#[doc(hidden)]
pub struct TeardownHold {
    entered: Option<oneshot::Receiver<()>>,
    release: Option<std::sync::mpsc::SyncSender<()>>,
}

#[cfg(feature = "ingest-test-hooks")]
impl fmt::Debug for TeardownHold {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("TeardownHold").finish_non_exhaustive()
    }
}

#[cfg(feature = "ingest-test-hooks")]
impl TeardownHold {
    /// Waits until transport tasks have stopped and blocking teardown is next.
    pub async fn wait_until_blocked(&mut self) {
        if let Some(entered) = self.entered.take() {
            let _ = entered.await;
        }
    }

    /// Releases blocking teardown.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

#[cfg(feature = "ingest-test-hooks")]
impl Drop for TeardownHold {
    fn drop(&mut self) {
        self.release_inner();
    }
}

#[cfg(feature = "ingest-test-hooks")]
struct TeardownGate {
    entered: Option<oneshot::Sender<()>>,
    release: std::sync::mpsc::Receiver<()>,
}

#[derive(Clone)]
struct RuntimeControl {
    shutdown: watch::Sender<bool>,
    fatal: Arc<Mutex<Option<RuntimeError>>>,
}

struct RuntimeCompletion {
    result: Mutex<Option<Result<(), RuntimeError>>>,
    changed: Notify,
}

impl RuntimeCompletion {
    fn new() -> Self {
        Self { result: Mutex::new(None), changed: Notify::new() }
    }

    fn finish(&self, result: Result<(), RuntimeError>) {
        let mut current = self.result.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.is_none() {
            *current = Some(result);
        }
        drop(current);
        self.changed.notify_waiters();
    }

    async fn wait(&self) -> Result<(), RuntimeError> {
        loop {
            let changed = self.changed.notified();
            if let Some(result) =
                self.result.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take()
            {
                return result;
            }
            changed.await;
        }
    }
}

struct Startup {
    session_id: crate::SessionId,
    capture_address: SocketAddr,
    queue_drop_count: Arc<AtomicU64>,
    http_address: SocketAddr,
}

impl RuntimeControl {
    fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self { shutdown, fatal: Arc::new(Mutex::new(None)) }
    }

    fn stop(&self) {
        self.shutdown.send_replace(true);
    }

    fn is_stopping(&self) -> bool {
        *self.shutdown.borrow()
    }

    fn fail(&self, error: RuntimeError) {
        let mut fatal = match self.fatal.lock() {
            Ok(fatal) => fatal,
            Err(poisoned) => poisoned.into_inner(),
        };
        if fatal.is_none() {
            *fatal = Some(error);
        }
        drop(fatal);
        self.stop();
    }

    fn take_fatal(&self) -> Option<RuntimeError> {
        match self.fatal.lock() {
            Ok(mut fatal) => fatal.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }
}

#[derive(Clone, Copy)]
struct RuntimeSockets {
    capture: fn(SocketAddr, usize) -> Result<UdpSocket, RuntimeError>,
    http: fn(SocketAddr) -> Result<TcpListener, RuntimeError>,
}

impl RuntimeSockets {
    const fn system() -> Self {
        Self { capture: capture::bind_socket, http: http::bind_socket }
    }
}

impl fmt::Debug for HostRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HostRuntime").finish_non_exhaustive()
    }
}

impl HostRuntime {
    /// Starts the bounded delivery after applying network roles before Store access.
    ///
    /// # Errors
    ///
    /// Returns an error if roles, Store startup, query startup, or socket binding fails.
    pub async fn start(config: &Config) -> Result<Self, RuntimeError> {
        Self::start_inner(
            config,
            ReceiveClock::system(),
            RuntimeSockets::system(),
            false,
            false,
            #[cfg(feature = "ingest-test-hooks")]
            false,
            #[cfg(feature = "ingest-test-hooks")]
            None,
        )
        .await
    }

    #[cfg(feature = "ingest-test-hooks")]
    #[doc(hidden)]
    /// Starts the runtime with its sole writer paused for bounded-queue tests.
    ///
    /// # Errors
    ///
    /// Returns the same startup errors as [`HostRuntime::start`], plus writer-control failure.
    pub async fn start_with_writer_held_for_test(config: &Config) -> Result<Self, RuntimeError> {
        Self::start_inner(
            config,
            ReceiveClock::system(),
            RuntimeSockets::system(),
            true,
            false,
            false,
            None,
        )
        .await
    }

    #[cfg(feature = "ingest-test-hooks")]
    #[doc(hidden)]
    /// Starts a runtime whose sole writer panics after supervision attaches.
    ///
    /// # Errors
    ///
    /// Returns the same startup errors as [`HostRuntime::start`].
    pub async fn start_with_panicked_writer_for_test(
        config: &Config,
    ) -> Result<Self, RuntimeError> {
        Self::start_inner(
            config,
            ReceiveClock::system(),
            RuntimeSockets::system(),
            false,
            true,
            false,
            None,
        )
        .await
    }

    #[cfg(feature = "ingest-test-hooks")]
    #[doc(hidden)]
    /// Starts a runtime whose final blocking teardown waits on a test gate.
    ///
    /// # Errors
    ///
    /// Returns the same startup errors as [`HostRuntime::start`].
    pub async fn start_with_teardown_held_for_test(
        config: &Config,
    ) -> Result<(Self, TeardownHold), RuntimeError> {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let runtime = Self::start_inner(
            config,
            ReceiveClock::system(),
            RuntimeSockets::system(),
            false,
            false,
            false,
            Some(TeardownGate { entered: Some(entered_tx), release: release_rx }),
        )
        .await?;
        Ok((runtime, TeardownHold { entered: Some(entered_rx), release: Some(release_tx) }))
    }

    #[cfg(feature = "ingest-test-hooks")]
    #[doc(hidden)]
    /// Starts a runtime whose Store queries wait for shutdown interruption.
    ///
    /// # Errors
    ///
    /// Returns the same startup errors as [`HostRuntime::start`].
    pub async fn start_with_query_held_for_test(
        config: &Config,
    ) -> Result<(Self, crate::QueryHold), RuntimeError> {
        let runtime = Self::start_inner(
            config,
            ReceiveClock::system(),
            RuntimeSockets::system(),
            false,
            false,
            true,
            None,
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

    async fn start_inner(
        config: &Config,
        receive_clock: ReceiveClock,
        sockets: RuntimeSockets,
        hold_writer: bool,
        panic_writer: bool,
        #[cfg(feature = "ingest-test-hooks")] hold_query: bool,
        #[cfg(feature = "ingest-test-hooks")] teardown_gate: Option<TeardownGate>,
    ) -> Result<Self, RuntimeError> {
        let control = RuntimeControl::new();
        let completion = Arc::new(RuntimeCompletion::new());
        #[cfg(feature = "ingest-test-hooks")]
        let writer_hold = Arc::new(Mutex::new(None));
        #[cfg(feature = "ingest-test-hooks")]
        let query_hold = Arc::new(Mutex::new(None));
        #[cfg(not(feature = "ingest-test-hooks"))]
        let _ = (hold_writer, panic_writer);
        let (ready_tx, ready_rx) = oneshot::channel();
        let supervisor_config = config.clone();
        let supervisor_control = control.clone();
        let supervisor_completion = Arc::clone(&completion);
        #[cfg(feature = "ingest-test-hooks")]
        let supervisor_writer_hold = Arc::clone(&writer_hold);
        #[cfg(feature = "ingest-test-hooks")]
        let supervisor_query_hold = Arc::clone(&query_hold);
        std::thread::Builder::new()
            .name("whisper-host-supervisor".to_owned())
            .spawn(move || {
                run_supervisor(
                    supervisor_config,
                    receive_clock,
                    sockets,
                    hold_writer,
                    panic_writer,
                    #[cfg(feature = "ingest-test-hooks")]
                    hold_query,
                    supervisor_control,
                    supervisor_completion,
                    ready_tx,
                    #[cfg(feature = "ingest-test-hooks")]
                    supervisor_writer_hold,
                    #[cfg(feature = "ingest-test-hooks")]
                    supervisor_query_hold,
                    #[cfg(feature = "ingest-test-hooks")]
                    teardown_gate,
                );
            })
            .map_err(|error| RuntimeError::new(RuntimeErrorKind::SupervisorSpawn(error)))?;
        let startup = ready_rx
            .await
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::SupervisorStopped))??;
        Ok(Self {
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
        })
    }

    #[cfg(feature = "ingest-test-hooks")]
    #[doc(hidden)]
    pub fn release_writer_for_test(&mut self) {
        self.writer_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
    }

    /// Returns the actual bound board-facing UDP address.
    #[must_use]
    pub const fn capture_address(&self) -> SocketAddr {
        self.capture_address
    }

    /// Returns the actual bound loopback HTTP address.
    #[must_use]
    pub const fn http_address(&self) -> SocketAddr {
        self.http_address
    }

    /// Returns the Capture Session identity created for this runtime.
    #[must_use]
    pub const fn session_id(&self) -> &crate::SessionId {
        &self.session_id
    }

    /// Returns the capture-to-writer queue drop count observed by this runtime.
    #[must_use]
    pub fn queue_drop_count(&self) -> u64 {
        self.queue_drop_count.load(AtomicOrdering::Acquire)
    }

    /// Waits until a runtime task requests fatal shutdown.
    pub async fn wait_for_stop(&self) {
        let mut shutdown = self.control.shutdown.subscribe();
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    }

    /// Stops the Host and returns its final capture-to-writer queue drop count.
    ///
    /// Cleanup continues on the independent supervisor if the returned future is cancelled.
    ///
    /// # Errors
    ///
    /// Returns the first writer, query, socket, task, or shutdown failure after all tasks join.
    pub async fn shutdown(self) -> Result<u64, RuntimeError> {
        self.control.stop();
        #[cfg(feature = "ingest-test-hooks")]
        self.writer_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
        let result = self.completion.wait().await;
        let queue_drop_count = self.queue_drop_count();
        result.map(|()| queue_drop_count)
    }
}

impl Drop for HostRuntime {
    fn drop(&mut self) {
        self.control.stop();
        #[cfg(feature = "ingest-test-hooks")]
        self.writer_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
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

#[expect(
    clippy::too_many_arguments,
    reason = "Private thread entry receives the complete ownership handoff in one call"
)]
fn run_supervisor(
    config: Config,
    receive_clock: ReceiveClock,
    sockets: RuntimeSockets,
    hold_writer: bool,
    panic_writer: bool,
    #[cfg(feature = "ingest-test-hooks")] hold_query: bool,
    control: RuntimeControl,
    completion: Arc<RuntimeCompletion>,
    ready: oneshot::Sender<Result<Startup, RuntimeError>>,
    #[cfg(feature = "ingest-test-hooks")] writer_hold: Arc<
        Mutex<Option<crate::application::WriterHold>>,
    >,
    #[cfg(feature = "ingest-test-hooks")] query_hold: Arc<Mutex<Option<crate::QueryHold>>>,
    #[cfg(feature = "ingest-test-hooks")] teardown_gate: Option<TeardownGate>,
) {
    let mut ready = Some(ready);
    let panic_control = control.clone();
    let panic_completion = Arc::clone(&completion);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        supervise(
            &config,
            receive_clock,
            sockets,
            hold_writer,
            panic_writer,
            #[cfg(feature = "ingest-test-hooks")]
            hold_query,
            control,
            &mut ready,
            #[cfg(feature = "ingest-test-hooks")]
            writer_hold,
            #[cfg(feature = "ingest-test-hooks")]
            query_hold,
            #[cfg(feature = "ingest-test-hooks")]
            teardown_gate,
        )
    }));
    match result {
        Ok(result) => {
            if let Some(ready) = ready.take() {
                if let Err(error) = result {
                    let _ = ready.send(Err(error));
                }
            } else {
                completion.finish(result);
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

#[expect(
    clippy::too_many_arguments,
    reason = "Private supervisor construction keeps lifecycle ownership out of the public interface"
)]
fn supervise(
    config: &Config,
    receive_clock: ReceiveClock,
    sockets: RuntimeSockets,
    hold_writer: bool,
    panic_writer: bool,
    #[cfg(feature = "ingest-test-hooks")] hold_query: bool,
    control: RuntimeControl,
    ready: &mut Option<oneshot::Sender<Result<Startup, RuntimeError>>>,
    #[cfg(feature = "ingest-test-hooks")] writer_hold: Arc<
        Mutex<Option<crate::application::WriterHold>>,
    >,
    #[cfg(feature = "ingest-test-hooks")] query_hold: Arc<Mutex<Option<crate::QueryHold>>>,
    #[cfg(feature = "ingest-test-hooks")] mut teardown_gate: Option<TeardownGate>,
) -> Result<(), RuntimeError> {
    validate_network_roles(config)?;
    let socket_buffer_bytes = usize::try_from(config.capture().socket_buffer_bytes())
        .map_err(|_| RuntimeError::new(RuntimeErrorKind::Capacity("capture socket buffer")))?;
    let maximum_datagram_bytes = usize::try_from(config.capture().max_datagram_bytes())
        .map_err(|_| RuntimeError::new(RuntimeErrorKind::Capacity("capture datagram")))?;
    let live_capacity = usize::try_from(config.server().websocket_queue_capacity())
        .map_err(|_| RuntimeError::new(RuntimeErrorKind::Capacity("WebSocket queue")))?;
    let limits =
        QueryLimits::try_new(config.view().max_signal_points(), config.view().max_time_buckets())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| RuntimeError::new(RuntimeErrorKind::Executor(error)))?;
    let (capture_socket, http_listener) = {
        let _runtime_context = runtime.enter();
        (
            (sockets.capture)(config.capture().bind(), socket_buffer_bytes)?,
            (sockets.http)(config.server().bind())?,
        )
    };
    let capture_address = capture_socket.local_addr().map_err(|source| {
        RuntimeError::socket(
            SocketRole::Capture,
            SocketOperation::LocalAddress,
            config.capture().bind(),
            source,
        )
    })?;
    let http_address = http_listener.local_addr().map_err(|source| {
        RuntimeError::socket(
            SocketRole::Http,
            SocketOperation::LocalAddress,
            config.server().bind(),
            source,
        )
    })?;
    let capture = crate::application::serve(config).map_err(LifecycleError::host)?;
    #[cfg(feature = "ingest-test-hooks")]
    let mut capture = capture;
    let store_id = capture.store_id();
    let query = capture.query_store()?;
    #[cfg(feature = "ingest-test-hooks")]
    let query = if hold_query {
        let (query, hold) = query.hold_for_test();
        *query_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hold);
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
    #[cfg(feature = "ingest-test-hooks")]
    if hold_writer {
        *writer_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(capture.hold_writer().map_err(LifecycleError::host)?);
    }
    #[cfg(not(feature = "ingest-test-hooks"))]
    let _ = hold_writer;
    #[cfg(feature = "ingest-test-hooks")]
    if panic_writer {
        capture.panic_writer_for_test().map_err(LifecycleError::host)?;
    }
    #[cfg(not(feature = "ingest-test-hooks"))]
    let _ = panic_writer;

    let capture_owner = Arc::new(Mutex::new(Some(capture)));
    let queue_drop_count = Arc::new(AtomicU64::new(0));
    let connections = ConnectionRegistry::default();
    let (live_tx, _) = broadcast::channel(live_capacity);
    let app = http::router(query.clone(), limits, live_tx.clone(), control.clone());
    let http_listener = http::TrackedListener::new(
        http_listener,
        connections.clone(),
        control.clone(),
        http_address,
    );
    let startup = Startup {
        session_id,
        capture_address,
        queue_drop_count: Arc::clone(&queue_drop_count),
        http_address,
    };
    let mut http_shutdown_rx = control.shutdown.subscribe();
    let task_control = control.clone();
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
                receive_clock,
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
    writer_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
    #[cfg(feature = "ingest-test-hooks")]
    if let Some(gate) = teardown_gate.as_mut() {
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
    let shutdown_result =
        capture.shutdown().map_err(crate::ShutdownError::host).map_err(RuntimeError::from);
    runtime.block_on(async {
        if let Err(error) = commit_task.await {
            control.fail(RuntimeError::join("writer-event supervisor", error));
        }
    });
    drop(runtime);
    let query_result = query.close().map_err(RuntimeError::from);
    let cleanup_result = shutdown_result.and(query_result);

    match control.take_fatal() {
        Some(error) => Err(error),
        None => cleanup_result,
    }
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
