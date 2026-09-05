//! Supervised authenticated UDP admission and restricted local raw-fact queries.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::key::{EpochKey, SecretStoreError, load_epoch_key};
use crate::native_frame::{Header, authenticate_datagram, parse_header};
use crate::replay::{ReplayAdmission, ReplayDecision, derive_replay_window_identity};
use crate::store::Store;

const DEFAULT_INGRESS_CAPACITY: usize = 256;
const DEFAULT_REPLAY_WINDOW_PACKETS: u16 = 64;
const DEFAULT_MAXIMUM_DATAGRAM_BYTES: usize = 2_048;
const DEFAULT_PEAK_PACKETS_PER_SECOND: u32 = 1_000;
const DEFAULT_MAXIMUM_AUTHENTICATED_BYTES_PER_SECOND: u64 = 2_048_000;
const MAXIMUM_RAW_QUERY_FACTS: usize = 1_024;
/// Rejections are operational diagnostics, not authoritative raw facts. This
/// fixed ceiling prevents hostile traffic from creating an unbounded side log.
const REJECTION_DIAGNOSTIC_CAPACITY: usize = 64;
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// One exact peer, device, key epoch, and secret key admission route.
pub struct NativeFrameRoute {
    peer: IpAddr,
    device_id: u64,
    key_epoch: u16,
    key: EpochKey,
}

impl fmt::Debug for NativeFrameRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeFrameRoute")
            .field("peer", &self.peer)
            .field("device_id", &self.device_id)
            .field("key_epoch", &self.key_epoch)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl NativeFrameRoute {
    /// Loads one epoch key and creates an exact authenticated native-frame route.
    ///
    /// # Errors
    ///
    /// The peer IP must be specified, the key epoch must be nonzero, and the preserved trusted
    /// secret-store policy must accept the selected key file.
    pub fn load(
        peer: IpAddr,
        device_id: u64,
        key_epoch: u16,
        secret_root: impl AsRef<Path>,
    ) -> Result<Self, RouteError> {
        if peer.is_unspecified() {
            return Err(RouteError::new("peer IP address must not be unspecified"));
        }
        if key_epoch == 0 {
            return Err(RouteError::new("key epoch must be non-zero"));
        }
        let key = load_epoch_key(secret_root.as_ref(), device_id, key_epoch)
            .map_err(RouteError::secret)?;
        Ok(Self { peer, device_id, key_epoch, key })
    }
}

/// Invalid construction of an authenticated native-frame route.
#[derive(Debug)]
pub struct RouteError {
    kind: RouteErrorKind,
}

impl RouteError {
    const fn new(reason: &'static str) -> Self {
        Self { kind: RouteErrorKind::Invalid(reason) }
    }

    fn secret(source: SecretStoreError) -> Self {
        Self { kind: RouteErrorKind::Secret(source) }
    }
}

#[derive(Debug, thiserror::Error)]
enum RouteErrorKind {
    #[error("invalid native-frame route: {0}")]
    Invalid(&'static str),
    #[error("could not load the native-frame route key: {0}")]
    Secret(#[source] SecretStoreError),
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for RouteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kind.source()
    }
}

/// The RF Host composition root.
#[derive(Debug)]
pub struct Host;

impl Host {
    /// Begins configuring one independently supervised Host.
    #[must_use]
    pub fn builder(store: Store, deployment: impl Into<String>, bind: SocketAddr) -> HostBuilder {
        HostBuilder {
            store,
            deployment: deployment.into(),
            bind,
            routes: Vec::new(),
            ingress_capacity: DEFAULT_INGRESS_CAPACITY,
            replay_window_packets: DEFAULT_REPLAY_WINDOW_PACKETS,
            maximum_datagram_bytes: DEFAULT_MAXIMUM_DATAGRAM_BYTES,
            peak_packets_per_second: DEFAULT_PEAK_PACKETS_PER_SECOND,
            maximum_authenticated_bytes_per_second: DEFAULT_MAXIMUM_AUTHENTICATED_BYTES_PER_SECOND,
        }
    }
}

/// Builder for the bounded UDP Host runtime.
#[derive(Debug)]
pub struct HostBuilder {
    store: Store,
    deployment: String,
    bind: SocketAddr,
    routes: Vec<NativeFrameRoute>,
    ingress_capacity: usize,
    replay_window_packets: u16,
    maximum_datagram_bytes: usize,
    peak_packets_per_second: u32,
    maximum_authenticated_bytes_per_second: u64,
}

impl HostBuilder {
    /// Adds one exact peer and epoch-key route.
    #[must_use]
    pub fn route(mut self, route: NativeFrameRoute) -> Self {
        self.routes.push(route);
        self
    }

    /// Sets the bounded number of authenticated datagrams awaiting transaction A.
    #[must_use]
    pub fn ingress_capacity(mut self, capacity: usize) -> Self {
        self.ingress_capacity = capacity;
        self
    }

    /// Sets the largest UDP datagram admitted before authentication.
    #[must_use]
    pub fn maximum_datagram_bytes(mut self, maximum: usize) -> Self {
        self.maximum_datagram_bytes = maximum;
        self
    }

    /// Sets the authenticated packet budget applied before replay admission.
    #[must_use]
    pub fn peak_packets_per_second(mut self, maximum: u32) -> Self {
        self.peak_packets_per_second = maximum;
        self
    }

    /// Sets the authenticated byte budget applied before replay admission.
    #[must_use]
    pub fn maximum_authenticated_bytes_per_second(mut self, maximum: u64) -> Self {
        self.maximum_authenticated_bytes_per_second = maximum;
        self
    }

    /// Starts the UDP reader, sole writer, and independent lifecycle supervisor.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, duplicate or missing routes, socket
    /// startup failure, or failure to open the Store writer.
    pub fn start(self) -> Result<HostRuntime, HostError> {
        validate_builder(&self)?;
        let socket = UdpSocket::bind(self.bind).map_err(HostError::io)?;
        let local_addr = socket.local_addr().map_err(HostError::io)?;
        socket.set_read_timeout(Some(SOCKET_POLL_INTERVAL)).map_err(HostError::io)?;

        let database_path = self.store.database_path();
        let stop = Arc::new(AtomicBool::new(false));
        let completion = Arc::new((Mutex::new(Completion::default()), Condvar::new()));
        let rejections =
            Arc::new(Mutex::new(VecDeque::with_capacity(REJECTION_DIAGNOSTIC_CAPACITY)));
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let supervisor_stop = Arc::clone(&stop);
        let supervisor_completion = Arc::clone(&completion);
        let supervisor_rejections = Arc::clone(&rejections);
        thread::Builder::new()
            .name("whisper-host-supervisor".to_owned())
            .spawn(move || {
                supervise(
                    self,
                    socket,
                    supervisor_stop,
                    supervisor_completion,
                    supervisor_rejections,
                    ready_sender,
                );
            })
            .map_err(HostError::io)?;

        ready_receiver
            .recv()
            .map_err(|_| HostError::message("Host supervisor exited during startup"))??;
        Ok(HostRuntime { local_addr, database_path, stop, completion, rejections })
    }
}

/// A running Host handle with the only raw query entry point.
#[derive(Debug)]
pub struct HostRuntime {
    local_addr: SocketAddr,
    database_path: PathBuf,
    stop: Arc<AtomicBool>,
    completion: Arc<(Mutex<Completion>, Condvar)>,
    rejections: Arc<Mutex<VecDeque<RejectedDatagram>>>,
}

impl HostRuntime {
    /// Returns the bound production UDP address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Queries at most `limit` committed raw facts through the local-only handle.
    ///
    /// Facts are returned oldest first within the newest requested suffix.
    ///
    /// # Errors
    ///
    /// The limit must be between one and 1,024, and the Store must remain readable.
    pub fn query_raw(&self, limit: usize) -> Result<Vec<RawFact>, HostError> {
        if !(1..=MAXIMUM_RAW_QUERY_FACTS).contains(&limit) {
            return Err(HostError::message("raw query limit must be between 1 and 1024"));
        }
        query_raw(&self.database_path, limit)
    }

    /// Queries at most `limit` committed raw gap and loss facts.
    ///
    /// # Errors
    ///
    /// The limit must be between one and 1,024, and the Store must remain readable.
    pub fn query_raw_losses(&self, limit: usize) -> Result<Vec<RawLoss>, HostError> {
        if !(1..=MAXIMUM_RAW_QUERY_FACTS).contains(&limit) {
            return Err(HostError::message("raw-loss query limit must be between 1 and 1024"));
        }
        query_raw_losses(&self.database_path, limit)
    }

    /// Returns a bounded newest suffix of non-authoritative rejection diagnostics.
    ///
    /// # Errors
    ///
    /// The limit must be between one and the diagnostic capacity of 64.
    pub fn query_rejections(&self, limit: usize) -> Result<Vec<RejectedDatagram>, HostError> {
        if !(1..=REJECTION_DIAGNOSTIC_CAPACITY).contains(&limit) {
            return Err(HostError::message("rejection query limit must be between 1 and 64"));
        }
        let rejections = self.rejections.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(rejections
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    }

    /// Requests shutdown and waits for the supervisor to release all resources.
    ///
    /// # Errors
    ///
    /// Returns the first fatal reader or writer failure observed by the supervisor.
    pub fn shutdown(self) -> Result<(), HostError> {
        self.stop.store(true, Ordering::Release);
        wait_for_completion(&self.completion)
    }
}

impl Drop for HostRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// One immutable authenticated raw source fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawFact {
    digest: [u8; 32],
    peer: SocketAddr,
    received_at: SystemTime,
    device_id: u64,
    key_epoch: u16,
    boot_generation: u32,
    message_sequence: u64,
    kind_byte: u8,
    datagram: Box<[u8]>,
}

/// Classification of a datagram excluded from the authoritative raw log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    /// The datagram exceeded the configured receive budget.
    DatagramTooLarge,
    /// Its fixed unauthenticated header was malformed or unsupported.
    MalformedEnvelope,
    /// No exact peer, device, and key-epoch route was configured.
    UnknownRoute,
    /// AES-GCM authentication failed.
    AuthenticationFailed,
    /// Authenticated traffic exceeded the configured packet or byte rate.
    AuthenticatedRateLimited,
    /// Durable replay admission rejected a duplicate or stale identity.
    Replay,
    /// The bounded authenticated ingress queue had no available slot.
    IngressQueueFull,
}

/// One bounded operational rejection diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RejectedDatagram {
    peer: SocketAddr,
    reason: RejectReason,
}

impl RejectedDatagram {
    /// Returns the receive peer associated with the rejected datagram.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns why no authoritative raw fact was committed.
    #[must_use]
    pub const fn reason(&self) -> RejectReason {
        self.reason
    }
}

impl RawFact {
    /// Returns the SHA-256 digest of the exact admitted datagram.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the authenticated datagram's receive peer.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the Host wall-clock receive time.
    #[must_use]
    pub const fn received_at(&self) -> SystemTime {
        self.received_at
    }

    /// Returns the authenticated opaque device identity.
    #[must_use]
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Returns the authenticated key epoch.
    #[must_use]
    pub const fn key_epoch(&self) -> u16 {
        self.key_epoch
    }

    /// Returns the authenticated boot generation.
    #[must_use]
    pub const fn boot_generation(&self) -> u32 {
        self.boot_generation
    }

    /// Returns the authenticated transport sequence.
    #[must_use]
    pub const fn message_sequence(&self) -> u64 {
        self.message_sequence
    }

    /// Returns the authenticated native-frame kind byte without semantic decoding.
    #[must_use]
    pub const fn kind_byte(&self) -> u8 {
        self.kind_byte
    }

    /// Returns the exact admitted encrypted native-frame bytes.
    #[must_use]
    pub const fn datagram(&self) -> &[u8] {
        &self.datagram
    }
}

/// A persisted raw discontinuity or bounded-ingress loss classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawLossKind {
    /// A forward transport sequence jump exposed an absent range.
    SequenceGapObserved,
    /// A replay-window-admitted datagram arrived below the last committed sequence.
    ReorderedArrival,
    /// Authenticated traffic exceeded the bounded transaction-A ingress queue.
    IngressQueueOverflow,
}

/// One immutable raw gap or loss fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawLoss {
    kind: RawLossKind,
    count: u64,
    observed_at: SystemTime,
    device_id: Option<u64>,
    boot_generation: Option<u32>,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
}

impl RawLoss {
    /// Returns the persisted loss classification.
    #[must_use]
    pub const fn kind(&self) -> RawLossKind {
        self.kind
    }

    /// Returns the number of coalesced occurrences.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns when the Host observed or summarized the discontinuity.
    #[must_use]
    pub const fn observed_at(&self) -> SystemTime {
        self.observed_at
    }

    /// Returns the affected authenticated device when the loss can identify it.
    #[must_use]
    pub const fn device_id(&self) -> Option<u64> {
        self.device_id
    }

    /// Returns the affected boot generation when the loss can identify it.
    #[must_use]
    pub const fn boot_generation(&self) -> Option<u32> {
        self.boot_generation
    }

    /// Returns the first affected transport sequence when applicable.
    #[must_use]
    pub const fn first_sequence(&self) -> Option<u64> {
        self.first_sequence
    }

    /// Returns the last affected transport sequence when applicable.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }
}

/// Failure to configure, start, query, or shut down the Host.
#[derive(Debug)]
pub struct HostError {
    kind: HostErrorKind,
}

#[derive(Debug, thiserror::Error)]
enum HostErrorKind {
    #[error("{0}")]
    Message(&'static str),
    #[error("Host I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("Host database operation failed: {0}")]
    Database(#[source] rusqlite::Error),
    #[error("Host worker failed: {0}")]
    Worker(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kind.source()
    }
}

impl HostError {
    fn message(message: &'static str) -> Self {
        Self { kind: HostErrorKind::Message(message) }
    }

    fn io(source: io::Error) -> Self {
        Self { kind: HostErrorKind::Io(source) }
    }

    fn database(source: rusqlite::Error) -> Self {
        Self { kind: HostErrorKind::Database(source) }
    }

    fn worker(message: impl Into<String>) -> Self {
        Self { kind: HostErrorKind::Worker(message.into()) }
    }
}

#[derive(Default, Debug)]
struct Completion {
    done: bool,
    failure: Option<String>,
}

#[derive(Debug)]
struct AdmittedDatagram {
    route_index: usize,
    header: Header,
    received_utc_ns: u64,
    peer: SocketAddr,
    bytes: Box<[u8]>,
}

#[derive(Debug)]
struct ReplayWriterState {
    identity: [u8; 32],
    admission: ReplayAdmission,
}

#[derive(Debug)]
struct OverflowSummary {
    count: AtomicU64,
}

#[derive(Debug)]
struct WriterConfig {
    database_path: PathBuf,
    deployment: String,
    replay_window_packets: u16,
    routes: Arc<Vec<NativeFrameRoute>>,
}

#[derive(Debug)]
struct ReaderConfig {
    socket: UdpSocket,
    routes: Arc<Vec<NativeFrameRoute>>,
    maximum_datagram_bytes: usize,
    peak_packets_per_second: u32,
    maximum_authenticated_bytes_per_second: u64,
}

#[derive(Clone, Copy, Debug)]
struct RouteRateState {
    period_started: std::time::Instant,
    packets: u32,
    bytes: u64,
}

impl RouteRateState {
    fn new(now: std::time::Instant) -> Self {
        Self { period_started: now, packets: 0, bytes: 0 }
    }

    fn admit(
        &mut self,
        now: std::time::Instant,
        bytes: usize,
        peak_packets_per_second: u32,
        maximum_authenticated_bytes_per_second: u64,
    ) -> bool {
        if now.duration_since(self.period_started) >= Duration::from_secs(1) {
            *self = Self::new(now);
        }
        let Ok(bytes) = u64::try_from(bytes) else {
            return false;
        };
        let Some(packets) = self.packets.checked_add(1) else {
            return false;
        };
        let Some(total_bytes) = self.bytes.checked_add(bytes) else {
            return false;
        };
        if packets > peak_packets_per_second || total_bytes > maximum_authenticated_bytes_per_second
        {
            return false;
        }
        self.packets = packets;
        self.bytes = total_bytes;
        true
    }
}

struct WorkerExitNotifier {
    worker: &'static str,
    sender: mpsc::Sender<(&'static str, Result<(), String>)>,
    result: Option<Result<(), String>>,
}

impl WorkerExitNotifier {
    fn new(worker: &'static str, sender: mpsc::Sender<(&'static str, Result<(), String>)>) -> Self {
        Self { worker, sender, result: None }
    }

    fn complete(&mut self, result: Result<(), HostError>) {
        self.result = Some(result.map_err(|error| error.to_string()));
    }
}

impl Drop for WorkerExitNotifier {
    fn drop(&mut self) {
        let result = self.result.take().unwrap_or_else(|| Err(format!("{} panicked", self.worker)));
        let _ = self.sender.send((self.worker, result));
    }
}

fn validate_builder(builder: &HostBuilder) -> Result<(), HostError> {
    if builder.deployment.is_empty() {
        return Err(HostError::message("deployment identity must not be empty"));
    }
    if builder.routes.is_empty() {
        return Err(HostError::message("at least one native-frame route is required"));
    }
    if builder.ingress_capacity == 0 {
        return Err(HostError::message("ingress capacity must be non-zero"));
    }
    if builder.replay_window_packets == 0 {
        return Err(HostError::message("replay window must be non-zero"));
    }
    if builder.maximum_datagram_bytes == 0 {
        return Err(HostError::message("maximum datagram bytes must be non-zero"));
    }
    if builder.peak_packets_per_second == 0 {
        return Err(HostError::message("peak packet rate must be non-zero"));
    }
    if builder.maximum_authenticated_bytes_per_second == 0 {
        return Err(HostError::message("authenticated byte rate must be non-zero"));
    }
    let mut exact_routes = BTreeMap::new();
    for route in &builder.routes {
        if exact_routes.insert((route.device_id, route.key_epoch), route.peer).is_some() {
            return Err(HostError::message("native-frame routes must be exact and unique"));
        }
    }
    Ok(())
}

fn supervise(
    builder: HostBuilder,
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    completion: Arc<(Mutex<Completion>, Condvar)>,
    rejections: Arc<Mutex<VecDeque<RejectedDatagram>>>,
    ready: mpsc::SyncSender<Result<(), HostError>>,
) {
    let overflow = Arc::new(OverflowSummary { count: AtomicU64::new(0) });
    let (ingress_sender, ingress_receiver) = mpsc::sync_channel(builder.ingress_capacity);
    let (worker_exit_sender, worker_exit_receiver) = mpsc::channel();
    let (writer_ready_sender, writer_ready_receiver) = mpsc::sync_channel(1);
    let writer_overflow = Arc::clone(&overflow);
    let writer_rejections = Arc::clone(&rejections);
    let writer_exit = worker_exit_sender.clone();
    let routes = Arc::new(builder.routes);
    let writer_config = WriterConfig {
        database_path: builder.store.database_path(),
        deployment: builder.deployment.clone(),
        replay_window_packets: builder.replay_window_packets,
        routes: Arc::clone(&routes),
    };
    let writer = thread::Builder::new().name("whisper-fact-writer".to_owned()).spawn(move || {
        let mut exit = WorkerExitNotifier::new("writer", writer_exit);
        let result = writer_loop(
            writer_config,
            ingress_receiver,
            &writer_overflow,
            &writer_rejections,
            writer_ready_sender,
        );
        exit.complete(result);
    });
    let Ok(writer) = writer else {
        let error = HostError::message("could not spawn the Store writer");
        let _ = ready.send(Err(error));
        finish_completion(&completion, Some("could not spawn the Store writer".to_owned()));
        return;
    };
    match writer_ready_receiver.recv() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let message = error.to_string();
            let _ = ready.send(Err(error));
            let _ = writer.join();
            finish_completion(&completion, Some(message));
            return;
        }
        Err(_) => {
            let message = "Store writer exited during startup".to_owned();
            let _ = ready.send(Err(HostError::worker(message.clone())));
            let _ = writer.join();
            finish_completion(&completion, Some(message));
            return;
        }
    }

    let reader_stop = Arc::clone(&stop);
    let reader_overflow = Arc::clone(&overflow);
    let reader_exit = worker_exit_sender;
    let maximum_datagram_bytes = builder.maximum_datagram_bytes;
    let peak_packets_per_second = builder.peak_packets_per_second;
    let maximum_authenticated_bytes_per_second = builder.maximum_authenticated_bytes_per_second;
    let reader_config = ReaderConfig {
        socket,
        routes,
        maximum_datagram_bytes,
        peak_packets_per_second,
        maximum_authenticated_bytes_per_second,
    };
    let reader = thread::Builder::new().name("whisper-udp-reader".to_owned()).spawn(move || {
        let mut exit = WorkerExitNotifier::new("reader", reader_exit);
        let result =
            reader_loop(reader_config, ingress_sender, &reader_overflow, &rejections, &reader_stop);
        exit.complete(result);
    });
    let Ok(reader) = reader else {
        stop.store(true, Ordering::Release);
        let _ = writer.join();
        let error = HostError::message("could not spawn the UDP reader");
        let _ = ready.send(Err(error));
        finish_completion(&completion, Some("could not spawn the UDP reader".to_owned()));
        return;
    };
    if ready.send(Ok(())).is_err() {
        stop.store(true, Ordering::Release);
    }

    let first_exit = loop {
        if stop.load(Ordering::Acquire) {
            break None;
        }
        match worker_exit_receiver.recv_timeout(SOCKET_POLL_INTERVAL) {
            Ok(exit) => break Some(exit),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break None,
        }
    };
    stop.store(true, Ordering::Release);
    let reader_join = reader.join();
    let writer_join = writer.join();
    let mut failure = first_exit
        .and_then(|(worker, result)| result.err().map(|error| format!("{worker}: {error}")));
    if reader_join.is_err() {
        failure.get_or_insert_with(|| "UDP reader panicked".to_owned());
    }
    if writer_join.is_err() {
        failure.get_or_insert_with(|| "Store writer panicked".to_owned());
    }
    drop(builder.store);
    finish_completion(&completion, failure);
}

fn reader_loop(
    config: ReaderConfig,
    ingress: mpsc::SyncSender<AdmittedDatagram>,
    overflow: &OverflowSummary,
    rejections: &Mutex<VecDeque<RejectedDatagram>>,
    stop: &AtomicBool,
) -> Result<(), HostError> {
    let mut buffer = vec![0_u8; config.maximum_datagram_bytes.saturating_add(1)];
    let mut rates = vec![RouteRateState::new(std::time::Instant::now()); config.routes.len()];
    while !stop.load(Ordering::Acquire) {
        let (length, peer) = match config.socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
            {
                continue;
            }
            Err(error) => return Err(HostError::io(error)),
        };
        if length > config.maximum_datagram_bytes {
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
                && route.device_id == header.device_id()
                && route.key_epoch == header.key_epoch()
        }) else {
            record_rejection(rejections, peer, RejectReason::UnknownRoute);
            continue;
        };
        let Ok(authenticated) = authenticate_datagram(route.key.as_bytes(), bytes) else {
            record_rejection(rejections, peer, RejectReason::AuthenticationFailed);
            continue;
        };
        if !rates[route_index].admit(
            std::time::Instant::now(),
            length,
            config.peak_packets_per_second,
            config.maximum_authenticated_bytes_per_second,
        ) {
            record_rejection(rejections, peer, RejectReason::AuthenticatedRateLimited);
            continue;
        }
        let item = AdmittedDatagram {
            route_index,
            header: authenticated.header(),
            received_utc_ns: utc_now_ns()?,
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

fn writer_loop(
    config: WriterConfig,
    ingress: mpsc::Receiver<AdmittedDatagram>,
    overflow: &OverflowSummary,
    rejections: &Mutex<VecDeque<RejectedDatagram>>,
    ready: mpsc::SyncSender<Result<(), HostError>>,
) -> Result<(), HostError> {
    let mut connection = match Connection::open_with_flags(
        &config.database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => connection,
        Err(error) => {
            let error = HostError::database(error);
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    if let Err(error) =
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
    {
        let error = HostError::database(error);
        let _ = ready.send(Err(error));
        return Ok(());
    }
    let mut replay = match load_replay_states(
        &connection,
        &config.deployment,
        config.replay_window_packets,
        &config.routes,
    ) {
        Ok(replay) => replay,
        Err(error) => {
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    if ready.send(Ok(())).is_err() {
        return Ok(());
    }

    loop {
        persist_overflow(&mut connection, overflow)?;
        match ingress.recv_timeout(SOCKET_POLL_INTERVAL) {
            Ok(item) => {
                persist_admitted(&mut connection, &config.routes, &mut replay, rejections, item)?
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    persist_overflow(&mut connection, overflow)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").map_err(HostError::database)?;
    Ok(())
}

fn load_replay_states(
    connection: &Connection,
    deployment: &str,
    replay_window_packets: u16,
    routes: &[NativeFrameRoute],
) -> Result<Vec<ReplayWriterState>, HostError> {
    routes
        .iter()
        .map(|route| {
            let identity = derive_replay_window_identity(
                deployment,
                route.device_id,
                route.key_epoch,
                &route.key,
            )
            .map_err(|error| HostError::worker(error.to_string()))?;
            let state: Option<Vec<u8>> = connection
                .query_row(
                    "SELECT state FROM replay_windows WHERE identity = ?1",
                    params![identity.as_bytes()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(HostError::database)?;
            let admission = match state {
                Some(state) => ReplayAdmission::decode_state(&state)
                    .map_err(|error| HostError::worker(error.to_string()))?,
                None => ReplayAdmission::new(replay_window_packets)
                    .map_err(|error| HostError::worker(error.to_string()))?,
            };
            Ok(ReplayWriterState { identity: *identity.as_bytes(), admission })
        })
        .collect()
}

fn persist_admitted(
    connection: &mut Connection,
    routes: &[NativeFrameRoute],
    replay: &mut [ReplayWriterState],
    rejections: &Mutex<VecDeque<RejectedDatagram>>,
    item: AdmittedDatagram,
) -> Result<(), HostError> {
    let route = &routes[item.route_index];
    let state = &mut replay[item.route_index];
    let mut next = state.admission.clone();
    if next.admit(item.header.boot_generation(), item.header.message_seq())
        == ReplayDecision::Rejected
    {
        record_rejection(rejections, item.peer, RejectReason::Replay);
        return Ok(());
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(HostError::database)?;
    let previous = latest_sequence(
        &transaction,
        item.header.device_id(),
        item.header.key_epoch(),
        item.header.boot_generation(),
    )?;
    let digest: [u8; 32] = Sha256::digest(&item.bytes).into();
    transaction
        .execute(
            "INSERT INTO raw_facts (
                 digest, received_utc_ns, peer, device_id, key_epoch,
                 boot_generation, message_sequence, kind, datagram
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                digest,
                item.received_utc_ns,
                item.peer.to_string(),
                item.header.device_id().to_be_bytes(),
                item.header.key_epoch(),
                item.header.boot_generation(),
                item.header.message_seq().to_be_bytes(),
                item.header.kind_byte(),
                &item.bytes,
            ],
        )
        .map_err(HostError::database)?;
    persist_sequence_discontinuity(&transaction, previous, &item)?;
    transaction
        .execute(
            "INSERT INTO replay_windows (identity, device_id, key_epoch, state)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(identity) DO UPDATE SET state = excluded.state",
            params![
                state.identity,
                route.device_id.to_be_bytes(),
                route.key_epoch,
                next.encode_state(),
            ],
        )
        .map_err(HostError::database)?;
    transaction.commit().map_err(HostError::database)?;
    state.admission = next;
    Ok(())
}

fn latest_sequence(
    connection: &Connection,
    device_id: u64,
    key_epoch: u16,
    boot_generation: u32,
) -> Result<Option<u64>, HostError> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT message_sequence FROM raw_facts
             WHERE device_id = ?1 AND key_epoch = ?2 AND boot_generation = ?3
             ORDER BY fact_id DESC LIMIT 1",
            params![device_id.to_be_bytes(), key_epoch, boot_generation],
            |row| row.get(0),
        )
        .optional()
        .map_err(HostError::database)?;
    bytes
        .map(|bytes| {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| HostError::message("persisted message sequence is invalid"))?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()
}

fn persist_sequence_discontinuity(
    connection: &Connection,
    previous: Option<u64>,
    item: &AdmittedDatagram,
) -> Result<(), HostError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let current = item.header.message_seq();
    let (kind, first, last) = if current > previous.saturating_add(1) {
        ("sequence_gap_observed", previous + 1, current - 1)
    } else if current < previous {
        ("reordered_arrival", current, current)
    } else {
        return Ok(());
    };
    connection
        .execute(
            "INSERT INTO raw_losses (
                 observed_utc_ns, kind, count, device_id, boot_generation,
                 first_sequence, last_sequence
             ) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6)",
            params![
                item.received_utc_ns,
                kind,
                item.header.device_id().to_be_bytes(),
                item.header.boot_generation(),
                first.to_be_bytes(),
                last.to_be_bytes(),
            ],
        )
        .map_err(HostError::database)?;
    Ok(())
}

fn persist_overflow(
    connection: &mut Connection,
    overflow: &OverflowSummary,
) -> Result<(), HostError> {
    let count = overflow.count.swap(0, Ordering::AcqRel);
    if count == 0 {
        return Ok(());
    }
    let count = i64::try_from(count).unwrap_or(i64::MAX);
    connection
        .execute(
            "INSERT INTO raw_losses (observed_utc_ns, kind, count)
             VALUES (?1, 'ingress_queue_overflow', ?2)",
            params![utc_now_ns()?, count],
        )
        .map_err(HostError::database)?;
    Ok(())
}

fn query_raw(path: &Path, limit: usize) -> Result<Vec<RawFact>, HostError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(HostError::database)?;
    let mut statement = connection
        .prepare(
            "SELECT digest, peer, received_utc_ns, device_id, key_epoch,
                    boot_generation, message_sequence, kind, datagram
             FROM raw_facts
             ORDER BY fact_id DESC LIMIT ?1",
        )
        .map_err(HostError::database)?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("query limit fits i64")], |row| {
            let digest: Vec<u8> = row.get(0)?;
            let peer: String = row.get(1)?;
            let received_utc_ns: i64 = row.get(2)?;
            let device_id: Vec<u8> = row.get(3)?;
            let key_epoch: u16 = row.get(4)?;
            let boot_generation: u32 = row.get(5)?;
            let message_sequence: Vec<u8> = row.get(6)?;
            let kind_byte: u8 = row.get(7)?;
            let datagram: Vec<u8> = row.get(8)?;
            Ok((
                digest,
                peer,
                received_utc_ns,
                device_id,
                key_epoch,
                boot_generation,
                message_sequence,
                kind_byte,
                datagram,
            ))
        })
        .map_err(HostError::database)?;
    let mut facts = Vec::with_capacity(limit);
    for row in rows {
        let (
            digest,
            peer,
            received_utc_ns,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
            kind_byte,
            datagram,
        ) = row.map_err(HostError::database)?;
        let digest =
            digest.try_into().map_err(|_| HostError::message("persisted raw digest is invalid"))?;
        let peer = peer.parse().map_err(|_| HostError::message("persisted raw peer is invalid"))?;
        let received_utc_ns = u64::try_from(received_utc_ns)
            .map_err(|_| HostError::message("persisted receive time is invalid"))?;
        let received_at = UNIX_EPOCH
            .checked_add(Duration::from_nanos(received_utc_ns))
            .ok_or_else(|| HostError::message("persisted receive time is out of range"))?;
        let device_id = u64::from_be_bytes(
            device_id
                .try_into()
                .map_err(|_| HostError::message("persisted device identity is invalid"))?,
        );
        let message_sequence = u64::from_be_bytes(
            message_sequence
                .try_into()
                .map_err(|_| HostError::message("persisted message sequence is invalid"))?,
        );
        facts.push(RawFact {
            digest,
            peer,
            received_at,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
            kind_byte,
            datagram: datagram.into_boxed_slice(),
        });
    }
    facts.reverse();
    Ok(facts)
}

fn query_raw_losses(path: &Path, limit: usize) -> Result<Vec<RawLoss>, HostError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(HostError::database)?;
    let mut statement = connection
        .prepare(
            "SELECT kind, count, observed_utc_ns, device_id, boot_generation,
                    first_sequence, last_sequence
             FROM raw_losses
             ORDER BY loss_id DESC LIMIT ?1",
        )
        .map_err(HostError::database)?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("query limit fits i64")], |row| {
            let kind: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let observed_utc_ns: i64 = row.get(2)?;
            let device_id: Option<Vec<u8>> = row.get(3)?;
            let boot_generation: Option<u32> = row.get(4)?;
            let first: Option<Vec<u8>> = row.get(5)?;
            let last: Option<Vec<u8>> = row.get(6)?;
            Ok((kind, count, observed_utc_ns, device_id, boot_generation, first, last))
        })
        .map_err(HostError::database)?;
    let mut losses = Vec::with_capacity(limit);
    for row in rows {
        let (kind, count, observed_utc_ns, device_id, boot_generation, first, last) =
            row.map_err(HostError::database)?;
        let kind = match kind.as_str() {
            "sequence_gap_observed" => RawLossKind::SequenceGapObserved,
            "reordered_arrival" => RawLossKind::ReorderedArrival,
            "ingress_queue_overflow" => RawLossKind::IngressQueueOverflow,
            _ => return Err(HostError::message("persisted raw-loss kind is invalid")),
        };
        let count = u64::try_from(count)
            .map_err(|_| HostError::message("persisted loss count is invalid"))?;
        let observed_utc_ns = u64::try_from(observed_utc_ns)
            .map_err(|_| HostError::message("persisted loss time is invalid"))?;
        let observed_at = UNIX_EPOCH
            .checked_add(Duration::from_nanos(observed_utc_ns))
            .ok_or_else(|| HostError::message("persisted loss time is out of range"))?;
        losses.push(RawLoss {
            kind,
            count,
            observed_at,
            device_id: decode_optional_u64(device_id, "persisted loss device is invalid")?,
            boot_generation,
            first_sequence: decode_optional_sequence(first)?,
            last_sequence: decode_optional_sequence(last)?,
        });
    }
    losses.reverse();
    Ok(losses)
}

fn decode_optional_u64(
    bytes: Option<Vec<u8>>,
    invalid: &'static str,
) -> Result<Option<u64>, HostError> {
    bytes
        .map(|bytes| {
            let bytes: [u8; 8] = bytes.try_into().map_err(|_| HostError::message(invalid))?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()
}

fn decode_optional_sequence(bytes: Option<Vec<u8>>) -> Result<Option<u64>, HostError> {
    bytes
        .map(|bytes| {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| HostError::message("persisted loss sequence is invalid"))?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()
}

fn utc_now_ns() -> Result<u64, HostError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostError::message("system time is before the Unix epoch"))?;
    u64::try_from(elapsed.as_nanos())
        .map_err(|_| HostError::message("system time exceeds the Store timestamp range"))
}

fn wait_for_completion(completion: &(Mutex<Completion>, Condvar)) -> Result<(), HostError> {
    let (state, changed) = completion;
    let state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = changed
        .wait_while(state, |state| !state.done)
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match &state.failure {
        Some(failure) => Err(HostError::worker(failure.clone())),
        None => Ok(()),
    }
}

fn finish_completion(completion: &(Mutex<Completion>, Condvar), failure: Option<String>) {
    let (state, changed) = completion;
    let mut state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    state.done = true;
    state.failure = failure;
    changed.notify_all();
}

fn record_rejection(
    diagnostics: &Mutex<VecDeque<RejectedDatagram>>,
    peer: SocketAddr,
    reason: RejectReason,
) {
    let mut diagnostics = diagnostics.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if diagnostics.len() == REJECTION_DIAGNOSTIC_CAPACITY {
        diagnostics.pop_front();
    }
    diagnostics.push_back(RejectedDatagram { peer, reason });
}
