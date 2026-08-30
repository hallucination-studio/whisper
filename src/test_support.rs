//! Explicit non-default controls for integration testing Host lifecycle failures.

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt;

#[doc(inline)]
pub use crate::capture::{
    CaptureRecordSequence, CapturedDatagram, CommitOutcome, CommitReceipt, PacketDisposition,
    ProjectionSequence,
};
#[doc(inline)]
pub use crate::domain::time::SessionTime;
#[doc(inline)]
pub use crate::host::TeardownHold;
#[doc(inline)]
pub use crate::store::{
    EmptyEnvelope, ErrorEnvelope, Metric, QueryError, QueryHold, QueryLimits, QueryStore,
    SignalPath, SignalQuery, SignalQueryBuilder, SignalRange, SignalSelection, SignalsOk,
    SignalsResponse, TopologyOk,
};
use crate::{Config, HostRuntime, LifecycleError, RuntimeError};

/// A pre-transaction rejection while admitting one captured datagram.
#[derive(Debug)]
pub struct SubmitError {
    source: crate::application::HostError,
    backtrace: Backtrace,
}

/// A writer failure while waiting for one queued candidate's durable outcome.
#[derive(Debug)]
pub struct CommitError {
    source: std::sync::Arc<crate::application::HostError>,
    backtrace: Backtrace,
}

/// A failure while stopping and joining a Capture runtime writer.
#[derive(Debug)]
pub struct ShutdownError {
    source: crate::application::HostError,
    backtrace: Backtrace,
}

/// A queued candidate whose outcome becomes available after writer processing.
#[derive(Debug)]
pub struct CommitTicket {
    inner: crate::application::CommitTicket,
}

/// A test-only lease that pauses the capture writer until dropped.
#[derive(Debug)]
pub struct WriterHold {
    _inner: crate::application::WriterHold,
}

impl CommitTicket {
    /// Waits for replay rejection or a post-commit receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer encounters a fatal Store failure or stops.
    pub fn wait(self) -> Result<CommitOutcome, CommitError> {
        self.inner.wait().map_err(CommitError::host)
    }
}

/// A newly created Capture Session and its retained Managed-store lifecycle lease.
#[derive(Debug)]
#[must_use = "dropping the Capture runtime stops its writer and releases its lifecycle lease"]
pub struct CaptureRuntime {
    inner: crate::application::CaptureRuntime,
}

impl CaptureRuntime {
    /// Returns the Store-scoped random identity read from the validated Store.
    #[must_use]
    pub const fn store_id(&self) -> [u8; 32] {
        self.inner.store_id()
    }

    /// Returns the random identity of this Capture Session.
    #[must_use]
    pub fn session_id(&self) -> &str {
        self.inner.session_id()
    }

    /// Returns elapsed monotonic time since this Capture Session was created.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.inner.elapsed()
    }

    /// Opens the pinned read-only query capability for this Managed-store lifecycle.
    ///
    /// QueryStore clones retain the lifecycle lease until their pinned reader closes.
    ///
    /// # Errors
    ///
    /// Returns an error when the existing Store cannot be opened and validated read-only.
    pub fn query_store(&self) -> Result<QueryStore, QueryError> {
        self.inner.query_store()
    }

    /// Returns the number of candidates dropped because the writer queue was full.
    #[must_use]
    pub const fn queue_drop_count(&self) -> u64 {
        self.inner.queue_drop_count()
    }

    /// Pauses the writer until the returned test lease is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has stopped or cannot accept the control request.
    pub fn hold_writer(&mut self) -> Result<WriterHold, LifecycleError> {
        self.inner
            .hold_writer()
            .map(|inner| WriterHold { _inner: inner })
            .map_err(LifecycleError::host)
    }

    /// Forces the next conforming CSI candidate through decoded-domain rejection.
    pub fn reject_next_csi_domain(&mut self) {
        self.inner.reject_next_csi_domain();
    }

    /// Authenticates and attempts to enqueue one captured datagram.
    ///
    /// # Errors
    ///
    /// Returns an error for rejected input, rate admission, a full queue, or a stopped writer.
    pub fn try_submit(&mut self, datagram: CapturedDatagram) -> Result<CommitTicket, SubmitError> {
        self.inner
            .try_submit(datagram)
            .map(|inner| CommitTicket { inner })
            .map_err(SubmitError::host)
    }

    /// Stops and joins the capture writer before releasing the lifecycle lease.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer thread panicked.
    pub fn shutdown(self) -> Result<(), ShutdownError> {
        self.inner.shutdown().map_err(ShutdownError::host)
    }
}

impl fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for SubmitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl SubmitError {
    /// Returns whether authenticated packet or byte rate admission rejected the datagram.
    #[must_use]
    pub const fn is_rate_limited(&self) -> bool {
        self.source.is_rate_limited()
    }

    /// Returns whether the bounded candidate queue was full.
    #[must_use]
    pub const fn is_queue_full(&self) -> bool {
        self.source.is_writer_queue_full()
    }

    /// Returns whether the sole capture writer had already stopped.
    #[must_use]
    pub const fn is_writer_stopped(&self) -> bool {
        self.source.is_writer_stopped()
    }

    /// Returns the backtrace captured at the submission boundary.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn host(source: crate::application::HostError) -> Self {
        Self { source, backtrace: Backtrace::capture() }
    }
}

impl fmt::Display for CommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for CommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl CommitError {
    /// Returns whether the writer stopped before returning a durable outcome.
    #[must_use]
    pub fn is_writer_stopped(&self) -> bool {
        self.source.is_writer_stopped()
    }

    /// Returns the backtrace captured while waiting for the durable outcome.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn host(source: std::sync::Arc<crate::application::HostError>) -> Self {
        Self { source, backtrace: Backtrace::capture() }
    }
}

impl fmt::Display for ShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for ShutdownError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl ShutdownError {
    /// Returns the backtrace captured at the shutdown boundary.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn host(source: crate::application::HostError) -> Self {
        Self { source, backtrace: Backtrace::capture() }
    }
}

/// Opens an existing Store and starts one empty Capture Session for integration tests.
///
/// # Errors
///
/// Returns an error if the Store is missing, untrusted, incompatible, or cannot
/// atomically create the Capture Session.
pub fn serve_capture(config: &Config) -> Result<CaptureRuntime, LifecycleError> {
    crate::application::serve(config)
        .map(|inner| CaptureRuntime { inner })
        .map_err(LifecycleError::host)
}

/// Starts a Host whose sole writer remains paused until [`release_writer`] is called.
///
/// # Errors
///
/// Returns any normal Host startup failure or a writer-control failure.
pub async fn start_host_with_writer_held(config: &Config) -> Result<HostRuntime, RuntimeError> {
    crate::host::start_with_writer_held(config).await
}

/// Releases the writer pause installed by [`start_host_with_writer_held`].
pub fn release_writer(runtime: &mut HostRuntime) {
    crate::host::release_writer(runtime);
}

/// Starts a Host whose sole writer panics after supervision attaches.
///
/// # Errors
///
/// Returns any normal Host startup failure or a writer-control failure.
pub async fn start_host_with_panicked_writer(config: &Config) -> Result<HostRuntime, RuntimeError> {
    crate::host::start_with_panicked_writer(config).await
}

/// Starts a Host whose pinned Store query waits for shutdown interruption.
///
/// # Errors
///
/// Returns any normal Host startup failure or an unavailable query-control hold.
pub async fn start_host_with_query_held(
    config: &Config,
) -> Result<(HostRuntime, QueryHold), RuntimeError> {
    crate::host::start_with_query_held(config).await
}

/// Starts a Host whose independent supervisor pauses before blocking teardown.
///
/// # Errors
///
/// Returns any normal Host startup failure.
pub async fn start_host_with_teardown_held(
    config: &Config,
) -> Result<(HostRuntime, TeardownHold), RuntimeError> {
    crate::host::start_with_teardown_held(config).await
}
