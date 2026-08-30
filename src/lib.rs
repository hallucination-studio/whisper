//! Deterministic domain types and validated configuration for the Whisper RF world model.

pub(crate) mod application;
pub(crate) mod capture;
mod config;
pub(crate) mod database;
#[cfg(unix)]
mod demo_store;
#[cfg(feature = "development-fixture")]
pub mod development_fixture;
pub(crate) mod domain;
#[cfg(unix)]
mod hex;
pub(crate) mod key_material;
#[cfg(unix)]
mod managed_store;
#[cfg(unix)]
mod query;
pub(crate) mod session;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Timeline is integrated by a later Engine work package")
)]
pub(crate) mod timeline;
#[expect(dead_code, reason = "wire item surface is consumed by later work packages")]
pub(crate) mod wire;

pub use config::{Config, ConfigError, RouteError, parse_config};
pub use domain::time::SessionTime;
#[cfg(unix)]
pub use query::{
    EmptyEnvelope, ErrorEnvelope, Metric, QueryError, QueryLimits, QueryStore, SignalPath,
    SignalQuery, SignalQueryBuilder, SignalRange, SignalSelection, SignalsOk, SignalsResponse,
    TopologyOk,
};

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime};

/// An application lifecycle failure from a bounded Demo command.
#[derive(Debug)]
pub struct DemoError {
    source: application::HostError,
    backtrace: Backtrace,
}

/// A pre-transaction rejection while admitting one captured datagram.
#[derive(Debug)]
pub struct SubmitError {
    source: application::HostError,
    backtrace: Backtrace,
}

/// A writer failure while waiting for one queued candidate's durable outcome.
#[derive(Debug)]
pub struct CommitError {
    source: application::HostError,
    backtrace: Backtrace,
}

/// A failure while stopping and joining a Capture Run writer.
#[derive(Debug)]
pub struct ShutdownError {
    source: application::HostError,
    backtrace: Backtrace,
}

/// One UDP datagram with receive facts captured before bounded Demo admission.
#[derive(Debug)]
pub struct CapturedDatagram {
    peer: SocketAddr,
    received_monotonic: Instant,
    received_utc: SystemTime,
    bytes: Box<[u8]>,
}

impl CapturedDatagram {
    /// Creates a captured datagram from exact receive facts and encrypted bytes.
    #[must_use]
    pub fn new(
        peer: SocketAddr,
        received_monotonic: Instant,
        received_utc: SystemTime,
        bytes: impl Into<Box<[u8]>>,
    ) -> Self {
        Self { peer, received_monotonic, received_utc, bytes: bytes.into() }
    }

    pub(crate) const fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub(crate) const fn received_monotonic(&self) -> Instant {
        self.received_monotonic
    }

    pub(crate) const fn received_utc(&self) -> SystemTime {
        self.received_utc
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Box<[u8]> {
        self.bytes
    }
}

/// Durable outcome for one candidate accepted by the Demo writer queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// Store-scoped replay admission rejected the packet without writes.
    ReplayRejected,
    /// The admitted packet and its complete write set committed atomically.
    Committed(CommitReceipt),
}

/// Committed packet disposition stored by the bounded Demo ingest path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDisposition {
    /// The authenticated native-frame kind is not defined by version 1.
    UnknownKind,
    /// A known native-frame kind did not satisfy its exact body grammar.
    MalformedKnownBody,
    /// The authenticated capability firmware digest did not match its configured pin.
    BuildMismatch,
    /// The authenticated capability digest did not match its configured pin.
    CapabilityPinMismatch,
    /// A conforming capability epoch row was inserted or exactly validated.
    CapabilityCommitted,
    /// A conforming authenticated health packet committed.
    HealthCommitted,
    /// Authenticated body capability identity did not match durable/configured authority.
    CapabilityMismatch,
    /// CSI arrived before a capability row was committed for its device epoch.
    CapabilityUnavailable,
    /// Authenticated CSI source identity did not match the configured link.
    SourceMismatch,
    /// Authenticated CSI radio facts did not match the configured link policy.
    RadioMismatch,
    /// Authenticated CSI exceeded the configured decoded-body budget.
    BodyBudgetMismatch,
    /// Authenticated CSI could not satisfy the imported typed observation domain.
    DecodedDomainRejected,
    /// A fully conforming native-coordinate CSI observation committed.
    CsiCommitted,
}

impl PacketDisposition {
    pub(crate) const fn as_store_text(self) -> &'static str {
        match self {
            Self::UnknownKind => "unknown_kind",
            Self::MalformedKnownBody => "malformed_known_body",
            Self::BuildMismatch => "build_mismatch",
            Self::CapabilityPinMismatch => "capability_pin_mismatch",
            Self::CapabilityCommitted => "capability_committed",
            Self::HealthCommitted => "health_committed",
            Self::CapabilityMismatch => "capability_mismatch",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::SourceMismatch => "source_mismatch",
            Self::RadioMismatch => "radio_mismatch",
            Self::BodyBudgetMismatch => "body_budget_mismatch",
            Self::DecodedDomainRejected => "decoded_domain_rejected",
            Self::CsiCommitted => "csi_committed",
        }
    }
}

/// Monotonic packet position within one Capture Session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct CaptureRecordSequence(u64);

impl CaptureRecordSequence {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Returns the numeric Capture Session position.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CaptureRecordSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Monotonic query-visible commit position within one Demo Store.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProjectionSequence(u64);

impl ProjectionSequence {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Returns the numeric Store projection position.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ProjectionSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Post-commit identity for one admitted Demo packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    disposition: PacketDisposition,
    record_sequence: CaptureRecordSequence,
    projection_sequence: ProjectionSequence,
}

impl CommitReceipt {
    pub(crate) const fn new(
        disposition: PacketDisposition,
        record_sequence: CaptureRecordSequence,
        projection_sequence: ProjectionSequence,
    ) -> Self {
        Self { disposition, record_sequence, projection_sequence }
    }

    /// Returns the packet's committed first-match disposition.
    #[must_use]
    pub const fn disposition(self) -> PacketDisposition {
        self.disposition
    }

    /// Returns the committed Capture Session record sequence.
    #[must_use]
    pub const fn record_sequence(self) -> CaptureRecordSequence {
        self.record_sequence
    }

    /// Returns the committed Store projection sequence.
    #[must_use]
    pub const fn projection_sequence(self) -> ProjectionSequence {
        self.projection_sequence
    }
}

/// A queued candidate whose outcome becomes available after writer processing.
#[cfg(unix)]
#[derive(Debug)]
pub struct CommitTicket {
    inner: application::CommitTicket,
}

/// A test-only lease that pauses the Demo writer until dropped.
#[cfg(all(unix, feature = "ingest-test-hooks"))]
#[doc(hidden)]
#[derive(Debug)]
pub struct WriterHold {
    _inner: application::WriterHold,
}

#[cfg(unix)]
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
#[must_use = "dropping the Capture Run stops its writer and releases its lifecycle lease"]
pub struct CaptureRun {
    inner: application::CaptureRun,
}

impl CaptureRun {
    /// Returns the Store-scoped random identity read from the validated Demo Store.
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

    /// Returns the number of candidates dropped because the writer queue was full.
    #[cfg(unix)]
    #[must_use]
    pub const fn queue_drop_count(&self) -> u64 {
        self.inner.queue_drop_count()
    }

    /// Pauses the writer until the returned test lease is dropped.
    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    #[doc(hidden)]
    pub fn hold_writer_for_test(&mut self) -> Result<WriterHold, DemoError> {
        self.inner.hold_writer().map(|inner| WriterHold { _inner: inner }).map_err(DemoError::host)
    }

    /// Forces the next conforming CSI candidate through decoded-domain rejection.
    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    #[doc(hidden)]
    pub fn reject_next_csi_domain_for_test(&mut self) {
        self.inner.reject_next_csi_domain();
    }

    /// Authenticates and attempts to enqueue one captured datagram.
    ///
    /// # Errors
    ///
    /// Returns an error for rejected input, rate admission, a full queue, or a stopped writer.
    #[cfg(unix)]
    pub fn try_submit(&mut self, datagram: CapturedDatagram) -> Result<CommitTicket, SubmitError> {
        self.inner
            .try_submit(datagram)
            .map(|inner| CommitTicket { inner })
            .map_err(SubmitError::host)
    }

    /// Stops and joins the Demo writer before releasing the lifecycle lease.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer thread panicked.
    #[cfg(unix)]
    pub fn shutdown(self) -> Result<(), ShutdownError> {
        self.inner.shutdown().map_err(ShutdownError::host)
    }
}

impl fmt::Display for DemoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for DemoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl DemoError {
    /// Returns whether another process or session holds the Managed-store lease.
    #[must_use]
    pub const fn is_lease_conflict(&self) -> bool {
        self.source.is_lease_conflict()
    }

    /// Returns the backtrace captured at the public command boundary.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn host(source: application::HostError) -> Self {
        Self { source, backtrace: Backtrace::capture() }
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

    /// Returns whether the sole Demo writer had already stopped.
    #[must_use]
    pub const fn is_writer_stopped(&self) -> bool {
        self.source.is_writer_stopped()
    }

    /// Returns the backtrace captured at the submission boundary.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn host(source: application::HostError) -> Self {
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
        Some(&self.source)
    }
}

impl CommitError {
    /// Returns whether the writer stopped before returning a durable outcome.
    #[must_use]
    pub const fn is_writer_stopped(&self) -> bool {
        self.source.is_writer_stopped()
    }

    /// Returns the backtrace captured while waiting for the durable outcome.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn host(source: application::HostError) -> Self {
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

    fn host(source: application::HostError) -> Self {
        Self { source, backtrace: Backtrace::capture() }
    }
}

/// Initializes the configured Demo Store and its empty admission epochs.
///
/// # Errors
///
/// Returns an error if Managed-store trust, secret loading, SQLite initialization,
/// validation, or no-replace publication fails. Non-Unix platforms always return
/// an error because they cannot enforce the Managed-store contract.
pub fn init_admission(config: &Config) -> Result<(), DemoError> {
    application::init_admission(config).map_err(DemoError::host)
}

/// Opens an existing Demo Store and starts one empty Capture Session.
///
/// The returned handle retains the Managed-store lifecycle lease and the
/// Capture Session's monotonic origin until it is dropped.
///
/// # Errors
///
/// Returns an error if the Store is missing, untrusted, incompatible, or cannot
/// atomically create the Capture Session. Non-Unix platforms always return an
/// error because they cannot enforce the Managed-store contract.
pub fn serve(config: &Config) -> Result<CaptureRun, DemoError> {
    application::serve(config).map(|inner| CaptureRun { inner }).map_err(DemoError::host)
}
