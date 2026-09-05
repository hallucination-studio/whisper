//! Supervised authenticated UDP admission and restricted local raw-fact queries.

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::key::{EpochKey, SecretStoreError, load_epoch_key};
use crate::native_frame::{Header, authenticate_datagram, parse_header};
use crate::replay::{ReplayAdmission, ReplayDecision, derive_replay_window_identity};
use crate::store::{Store, StoreSnapshot};
use crate::{BootGeneration, DeploymentId, DeviceId, KeyEpoch, MessageSequence, NativeFrameKind};

/// Authenticated datagrams buffered before transaction A. This initial
/// deployment value is a local memory/back-pressure budget; changing it alters
/// the maximum loss burst summarized when the SQLite writer falls behind.
const DEFAULT_INGRESS_CAPACITY: usize = 256;
/// Conservative allocation ceiling in bytes for one route's UDP payload. The
/// 65,507-byte IPv4 UDP maximum also safely bounds IPv6 routes; changing it
/// changes accepted route configurations and worst-case ingress allocation.
const UDP_PAYLOAD_BYTES: usize = 65_507;
/// Local query result ceiling in facts. It bounds allocations made from an
/// untrusted caller-supplied limit; changing it changes the public query contract.
const MAXIMUM_RAW_QUERY_FACTS: usize = 1_024;
/// Rejections are operational diagnostics, not authoritative raw facts. This
/// fixed ceiling prevents hostile traffic from creating an unbounded side log.
/// Changing it alters only diagnostic retention, never authoritative facts.
const REJECTION_DIAGNOSTIC_CAPACITY: usize = 64;
/// Worker stop/error polling period in milliseconds. The value keeps shutdown
/// latency interactive while avoiding a busy loop; changing it affects both
/// idle wakeups and worst-case cooperative shutdown latency.
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Packet and authenticated-byte budgets reset over one-second wall-independent
/// periods because the configured units are per second. Changing it changes
/// admission semantics and requires renaming those units.
const RATE_PERIOD: Duration = Duration::from_secs(1);

trait Network: Send + Sync {
    fn bind(&self, address: SocketAddr) -> io::Result<Box<dyn DatagramSocket>>;
}

trait DatagramSocket: Send {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

trait Threads: Send + Sync {
    fn spawn(
        &self,
        name: &'static str,
        task: Box<dyn FnOnce() + Send>,
    ) -> io::Result<thread::JoinHandle<()>>;
}

trait Clock: Send + Sync {
    fn monotonic_now(&self) -> Instant;
    fn wall_now(&self) -> SystemTime;
}

#[derive(Debug)]
struct SystemNetwork;

impl Network for SystemNetwork {
    fn bind(&self, address: SocketAddr) -> io::Result<Box<dyn DatagramSocket>> {
        UdpSocket::bind(address).map(|socket| Box::new(socket) as Box<dyn DatagramSocket>)
    }
}

impl DatagramSocket for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UdpSocket::set_read_timeout(self, timeout)
    }

    fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buffer)
    }
}

#[derive(Debug)]
struct SystemThreads;

impl Threads for SystemThreads {
    fn spawn(
        &self,
        name: &'static str,
        task: Box<dyn FnOnce() + Send>,
    ) -> io::Result<thread::JoinHandle<()>> {
        thread::Builder::new().name(name.to_owned()).spawn(task)
    }
}

#[derive(Debug)]
struct SystemClock;

impl Clock for SystemClock {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Exact per-route native-frame admission limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimits {
    datagram_bytes: usize,
    packets_per_second: u32,
    authenticated_bytes_per_second: u64,
    replay_window_packets: u16,
}

impl AdmissionLimits {
    /// Creates one route's datagram, packet-rate, byte-rate, and replay limits.
    ///
    /// # Errors
    ///
    /// Every limit must be nonzero and the datagram limit must fit a UDP payload.
    pub fn new(
        datagram_bytes: usize,
        packets_per_second: u32,
        authenticated_bytes_per_second: u64,
        replay_window_packets: u16,
    ) -> Result<Self, AdmissionLimitsError> {
        if datagram_bytes == 0 || datagram_bytes > UDP_PAYLOAD_BYTES {
            return Err(AdmissionLimitsError);
        }
        if packets_per_second == 0
            || authenticated_bytes_per_second == 0
            || replay_window_packets == 0
        {
            return Err(AdmissionLimitsError);
        }
        Ok(Self {
            datagram_bytes,
            packets_per_second,
            authenticated_bytes_per_second,
            replay_window_packets,
        })
    }
}

/// Invalid zero or out-of-range route admission limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("native-frame admission limits must be nonzero and fit one UDP payload")]
pub struct AdmissionLimitsError;

/// One exact peer, device, key epoch, and secret key admission route.
pub struct NativeFrameRoute {
    peer: IpAddr,
    device_id: DeviceId,
    key_epoch: KeyEpoch,
    key: EpochKey,
    limits: AdmissionLimits,
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
        device_id: DeviceId,
        key_epoch: KeyEpoch,
        limits: AdmissionLimits,
        secret_root: impl AsRef<Path>,
    ) -> Result<Self, RouteError> {
        if peer.is_unspecified() {
            return Err(RouteError::new("peer IP address must not be unspecified"));
        }
        let key = load_epoch_key(secret_root.as_ref(), device_id.get(), key_epoch.get())
            .map_err(RouteError::secret)?;
        Ok(Self { peer, device_id, key_epoch, key, limits })
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
    pub fn builder(store: Store, deployment: DeploymentId, bind: SocketAddr) -> HostBuilder {
        HostBuilder {
            store,
            deployment,
            bind,
            routes: Vec::new(),
            ingress_capacity: DEFAULT_INGRESS_CAPACITY,
            network: Arc::new(SystemNetwork),
            threads: Arc::new(SystemThreads),
            clock: Arc::new(SystemClock),
        }
    }
}

/// Builder for the bounded UDP Host runtime.
pub struct HostBuilder {
    store: Store,
    deployment: DeploymentId,
    bind: SocketAddr,
    routes: Vec<NativeFrameRoute>,
    ingress_capacity: usize,
    network: Arc<dyn Network>,
    threads: Arc<dyn Threads>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for HostBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostBuilder")
            .field("store", &self.store)
            .field("deployment", &self.deployment)
            .field("bind", &self.bind)
            .field("routes", &self.routes)
            .field("ingress_capacity", &self.ingress_capacity)
            .finish_non_exhaustive()
    }
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

    /// Starts the UDP reader, sole writer, and independent lifecycle supervisor.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, duplicate or missing routes, socket
    /// startup failure, or failure to open the Store writer.
    pub fn start(self) -> Result<HostRuntime, HostError> {
        validate_builder(&self)?;
        let replay_snapshot = self.store.database_snapshot().map_err(HostError::io)?;
        let socket = self.network.bind(self.bind).map_err(HostError::io)?;
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
        let supervisor_threads = Arc::clone(&self.threads);
        let launch_threads = Arc::clone(&self.threads);
        launch_threads
            .spawn(
                "whisper-host-supervisor",
                Box::new(move || {
                    supervise(
                        self,
                        SupervisorContext {
                            socket,
                            threads: supervisor_threads,
                            replay_snapshot,
                            stop: supervisor_stop,
                            completion: supervisor_completion,
                            rejections: supervisor_rejections,
                            ready_sender,
                        },
                    );
                }),
            )
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
    device_id: DeviceId,
    key_epoch: KeyEpoch,
    boot_generation: BootGeneration,
    message_sequence: MessageSequence,
    kind: NativeFrameKind,
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
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the authenticated key epoch.
    #[must_use]
    pub const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    /// Returns the authenticated boot generation.
    #[must_use]
    pub const fn boot_generation(&self) -> BootGeneration {
        self.boot_generation
    }

    /// Returns the authenticated transport sequence.
    #[must_use]
    pub const fn message_sequence(&self) -> MessageSequence {
        self.message_sequence
    }

    /// Returns the authenticated native-frame kind byte without semantic decoding.
    #[must_use]
    pub const fn kind(&self) -> NativeFrameKind {
        self.kind
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
    device_id: Option<DeviceId>,
    boot_generation: Option<BootGeneration>,
    first_sequence: Option<MessageSequence>,
    last_sequence: Option<MessageSequence>,
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
    pub const fn device_id(&self) -> Option<DeviceId> {
        self.device_id
    }

    /// Returns the affected boot generation when the loss can identify it.
    #[must_use]
    pub const fn boot_generation(&self) -> Option<BootGeneration> {
        self.boot_generation
    }

    /// Returns the first affected transport sequence when applicable.
    #[must_use]
    pub const fn first_sequence(&self) -> Option<MessageSequence> {
        self.first_sequence
    }

    /// Returns the last affected transport sequence when applicable.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<MessageSequence> {
        self.last_sequence
    }
}

/// Failure to configure, start, query, or shut down the Host.
#[derive(Debug)]
pub struct HostError {
    kind: HostErrorKind,
    operation: &'static str,
    path: Option<PathBuf>,
    backtrace: Box<Backtrace>,
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
        write!(formatter, "Host {}", self.operation)?;
        if let Some(path) = &self.path {
            write!(formatter, " at {}", path.display())?;
        }
        write!(formatter, ": {}", self.kind)
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kind.source()
    }
}

impl HostError {
    fn message(message: &'static str) -> Self {
        Self::new("operation", None, HostErrorKind::Message(message))
    }

    fn io(source: io::Error) -> Self {
        Self::new("network or thread I/O", None, HostErrorKind::Io(source))
    }

    fn database(source: rusqlite::Error) -> Self {
        Self::new("Store database operation", None, HostErrorKind::Database(source))
    }

    fn database_at(path: &Path, source: rusqlite::Error) -> Self {
        Self::new(
            "Store database operation",
            Some(path.to_owned()),
            HostErrorKind::Database(source),
        )
    }

    fn worker(message: impl Into<String>) -> Self {
        Self::new("worker supervision", None, HostErrorKind::Worker(message.into()))
    }

    fn new(operation: &'static str, path: Option<PathBuf>, kind: HostErrorKind) -> Self {
        Self { kind, operation, path, backtrace: Box::new(Backtrace::capture()) }
    }

    /// Returns the filesystem path involved in the failed operation, when applicable.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns the captured failure backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        self.backtrace.as_ref()
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
struct ReplayStartup {
    states: Vec<ReplayWriterState>,
    provision: bool,
}

#[derive(Debug)]
struct OverflowSummary {
    count: AtomicU64,
}

struct WriterConfig {
    database_path: PathBuf,
    replay_snapshot: StoreSnapshot,
    deployment: DeploymentId,
    routes: Arc<Vec<NativeFrameRoute>>,
    clock: Arc<dyn Clock>,
}

struct ReaderConfig {
    socket: Box<dyn DatagramSocket>,
    routes: Arc<Vec<NativeFrameRoute>>,
    clock: Arc<dyn Clock>,
}

struct SupervisorContext {
    socket: Box<dyn DatagramSocket>,
    threads: Arc<dyn Threads>,
    replay_snapshot: StoreSnapshot,
    stop: Arc<AtomicBool>,
    completion: Arc<(Mutex<Completion>, Condvar)>,
    rejections: Arc<Mutex<VecDeque<RejectedDatagram>>>,
    ready_sender: mpsc::SyncSender<Result<(), HostError>>,
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
        if now.duration_since(self.period_started) >= RATE_PERIOD {
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
    if builder.routes.is_empty() {
        return Err(HostError::message("at least one native-frame route is required"));
    }
    if builder.ingress_capacity == 0 {
        return Err(HostError::message("ingress capacity must be non-zero"));
    }
    let mut exact_routes = BTreeMap::new();
    for route in &builder.routes {
        if exact_routes.insert((route.device_id, route.key_epoch), route.peer).is_some() {
            return Err(HostError::message("native-frame routes must be exact and unique"));
        }
    }
    Ok(())
}

#[path = "host/supervision.rs"]
mod supervision;
use supervision::supervise;
#[path = "host/ingress.rs"]
mod ingress;
use ingress::reader_loop;
mod persistence;
use persistence::writer_loop;
mod query;
use query::{query_raw, query_raw_losses};
fn utc_now_ns(clock: &dyn Clock) -> Result<u64, HostError> {
    let elapsed = clock
        .wall_now()
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
