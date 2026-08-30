//! Async socket and delivery lifetime for the bounded delivery Host.

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering as AtomicOrdering},
};

#[cfg(feature = "ingest-test-hooks")]
use tokio::sync::oneshot;
use tokio::sync::{Notify, watch};

use crate::store::QueryError;
#[cfg(feature = "ingest-test-hooks")]
use crate::store::QueryHold;
use crate::{Config, LifecycleError};

mod capture;
mod http;
mod supervisor;
mod websocket;

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
    Shutdown(#[source] crate::application::HostError),
    #[error("captured datagram submission failed: {0}")]
    Submit(#[source] crate::application::HostError),
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

    fn shutdown(source: crate::application::HostError) -> Self {
        Self::new(RuntimeErrorKind::Shutdown(source))
    }

    fn submit(source: crate::application::HostError) -> Self {
        Self::new(RuntimeErrorKind::Submit(source))
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
    query_hold: Arc<Mutex<Option<QueryHold>>>,
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
        supervisor::start(config).await
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

#[cfg(feature = "ingest-test-hooks")]
pub(crate) async fn start_with_writer_held(config: &Config) -> Result<HostRuntime, RuntimeError> {
    supervisor::start_with_writer_held(config).await
}

#[cfg(feature = "ingest-test-hooks")]
pub(crate) async fn start_with_panicked_writer(
    config: &Config,
) -> Result<HostRuntime, RuntimeError> {
    supervisor::start_with_panicked_writer(config).await
}

#[cfg(feature = "ingest-test-hooks")]
pub(crate) async fn start_with_teardown_held(
    config: &Config,
) -> Result<(HostRuntime, TeardownHold), RuntimeError> {
    supervisor::start_with_teardown_held(config).await
}

#[cfg(feature = "ingest-test-hooks")]
pub(crate) async fn start_with_query_held(
    config: &Config,
) -> Result<(HostRuntime, QueryHold), RuntimeError> {
    supervisor::start_with_query_held(config).await
}

#[cfg(feature = "ingest-test-hooks")]
pub(crate) fn release_writer(runtime: &mut HostRuntime) {
    runtime.writer_hold.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
}
