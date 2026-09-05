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

use crate::admission::AdmissionLimits;
use crate::key::{EpochKey, SecretStoreError, load_epoch_key};
use crate::measurement::{
    AssemblyClose, AssemblyLimits, MeasurementFragment, QualificationRelation, SourceInstance,
    SourceTick,
};
use crate::native_csi::{
    CapabilityIdentity, ChannelPolicy, FirmwareBuildIdentity, NativeCapabilityFact, NativeCsiFact,
    NativeFact, NativeHealthFact, RadioRxS3, S3BandwidthKind, S3PhyKind, S3SecondaryKind,
    SourceMac,
};
use crate::native_frame::{
    AuthenticatedDatagram, Header, Message, authenticate_datagram, decode_authenticated,
    parse_header,
};
use crate::replay::{
    ReplayAdmission, ReplayDecision, ReplayIdentityError, ReplayStateError,
    derive_replay_window_identity,
};
use crate::store::{Store, StoreSnapshot};
use crate::{
    BootGeneration, DeploymentId, DeviceId, KeyEpoch, MessageSequence, NativeFrameKind, SensorId,
};

/// Authenticated datagrams buffered before transaction A. This initial
/// deployment value is a local memory/back-pressure budget; changing it alters
/// the maximum loss burst summarized when the SQLite writer falls behind.
const DEFAULT_INGRESS_CAPACITY: usize = 256;
/// Local query result ceiling in facts. It bounds allocations made from an
/// untrusted caller-supplied limit; changing it changes the public query contract.
const MAXIMUM_RAW_QUERY_FACTS: usize = 1_024;
/// Rejections are operational diagnostics, not authoritative raw facts. This
/// fixed ceiling prevents hostile traffic from creating an unbounded side log.
/// Changing it alters only diagnostic retention, never authoritative facts.
const REJECTION_DIAGNOSTIC_CAPACITY: usize = 64;
/// Independently established qualification revisions awaiting the sole writer.
/// This count bound limits control-plane memory and each pre-ingress writer batch.
const CONTROL_QUEUE_CAPACITY: usize = 64;
/// Total estimated command bytes allowed in the bounded writer control queue.
const CONTROL_QUEUE_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum time a caller waits for count and byte capacity in the control queue.
const CONTROL_ENQUEUE_DEADLINE: Duration = Duration::from_millis(100);
/// Maximum time a caller waits for the sole writer's persistence response.
const CONTROL_RESPONSE_DEADLINE: Duration = Duration::from_millis(500);
/// Maximum control commands processed before the writer rotates to ingress.
/// Increasing it improves control throughput but increases ingress latency.
const CONTROL_BATCH_PER_TURN: usize = 8;
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

/// The radio identity fields that a configured decoded route admits exactly.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RadioRouteFacts {
    phy: S3PhyKind,
    bandwidth: S3BandwidthKind,
    secondary: S3SecondaryKind,
    stbc: bool,
    rate: u8,
    mcs: u8,
    rx_antenna: u8,
}

impl RadioRouteFacts {
    /// Captures the stable radio identity fields from one validated CSI radio value.
    #[must_use]
    pub const fn from_radio(radio: RadioRxS3) -> Self {
        Self {
            phy: radio.phy(),
            bandwidth: radio.bandwidth(),
            secondary: radio.secondary(),
            stbc: radio.stbc(),
            rate: radio.rate(),
            mcs: radio.mcs(),
            rx_antenna: radio.rx_antenna(),
        }
    }

    /// Returns the admitted PHY category.
    #[must_use]
    pub const fn phy(self) -> S3PhyKind {
        self.phy
    }

    /// Returns the admitted channel bandwidth.
    #[must_use]
    pub const fn bandwidth(self) -> S3BandwidthKind {
        self.bandwidth
    }

    /// Returns the admitted secondary-channel placement.
    #[must_use]
    pub const fn secondary(self) -> S3SecondaryKind {
        self.secondary
    }

    /// Returns whether the admitted route requires STBC.
    #[must_use]
    pub const fn stbc(self) -> bool {
        self.stbc
    }

    /// Returns the admitted Non-HT rate field.
    #[must_use]
    pub const fn rate(self) -> u8 {
        self.rate
    }

    /// Returns the admitted HT MCS field.
    #[must_use]
    pub const fn mcs(self) -> u8 {
        self.mcs
    }

    /// Returns the admitted receive antenna ordinal.
    #[must_use]
    pub const fn rx_antenna(self) -> u8 {
        self.rx_antenna
    }

    fn matches(self, radio: RadioRxS3) -> bool {
        self == Self::from_radio(radio)
    }
}

/// Explicit post-authentication identity and capability admission for one sensor.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DecodedRoute {
    sensor: SensorId,
    link: DecodedRouteLink,
    firmware_build: FirmwareBuildIdentity,
    capability: CapabilityIdentity,
}

impl DecodedRoute {
    /// Creates a decoded route whose sensor, link, firmware build, and capability are all pinned.
    pub fn new(
        sensor: SensorId,
        link: DecodedRouteLink,
        firmware_build: FirmwareBuildIdentity,
        capability: CapabilityIdentity,
    ) -> Self {
        Self { sensor, link, firmware_build, capability }
    }

    /// Returns the configured sensor identity.
    #[must_use]
    pub const fn sensor(&self) -> &SensorId {
        &self.sensor
    }

    /// Returns the authenticated CSI source MAC that is admitted.
    #[must_use]
    pub const fn source_mac(&self) -> SourceMac {
        self.link.source_mac()
    }

    /// Returns the exact primary channel admitted by this route.
    #[must_use]
    pub const fn channel(&self) -> ChannelPolicy {
        self.link.channel()
    }

    /// Returns the stable radio identity fields admitted by this route.
    #[must_use]
    pub const fn radio(&self) -> RadioRouteFacts {
        self.link.radio()
    }

    /// Returns the firmware build digest pinned by this route.
    #[must_use]
    pub const fn firmware_build(&self) -> FirmwareBuildIdentity {
        self.firmware_build
    }

    /// Returns the capability digest pinned by this route.
    #[must_use]
    pub const fn capability(&self) -> CapabilityIdentity {
        self.capability
    }

    fn admits_radio(&self, radio: RadioRxS3) -> bool {
        self.channel().get() == radio.channel() && self.radio().matches(radio)
    }
}

/// The authenticated source, channel, and stable radio tuple admitted for one route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DecodedRouteLink {
    source_mac: SourceMac,
    channel: ChannelPolicy,
    radio: RadioRouteFacts,
}

impl DecodedRouteLink {
    /// Creates one route link from already validated semantic identity values.
    #[must_use]
    pub const fn new(
        source_mac: SourceMac,
        channel: ChannelPolicy,
        radio: RadioRouteFacts,
    ) -> Self {
        Self { source_mac, channel, radio }
    }

    /// Returns the admitted authenticated source MAC.
    #[must_use]
    pub const fn source_mac(self) -> SourceMac {
        self.source_mac
    }

    /// Returns the admitted primary channel policy.
    #[must_use]
    pub const fn channel(self) -> ChannelPolicy {
        self.channel
    }

    /// Returns the admitted stable radio tuple.
    #[must_use]
    pub const fn radio(self) -> RadioRouteFacts {
        self.radio
    }
}

/// One exact peer, device, key epoch, secret key, and decoded identity route.
#[derive(Clone)]
pub struct NativeFrameRoute {
    peer: IpAddr,
    device_id: DeviceId,
    key_epoch: KeyEpoch,
    key: EpochKey,
    limits: AdmissionLimits,
    decoded: DecodedRoute,
}

impl fmt::Debug for NativeFrameRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeFrameRoute")
            .field("peer", &self.peer)
            .field("device_id", &self.device_id)
            .field("key_epoch", &self.key_epoch)
            .field("key", &"[REDACTED]")
            .field("decoded", &self.decoded)
            .finish()
    }
}

impl NativeFrameRoute {
    /// Loads one epoch key and creates an exact authenticated native-frame route.
    ///
    /// The caller must provide the decoded sensor identity, source, radio tuple, firmware build,
    /// and capability digest that are already configured for this route. The Host never learns
    /// these values from the first authenticated datagram.
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
        decoded: DecodedRoute,
        secret_root: impl AsRef<Path>,
    ) -> Result<Self, RouteError> {
        let secret_root = secret_root.as_ref();
        if peer.is_unspecified() {
            return Err(RouteError::invalid(
                peer,
                device_id,
                key_epoch,
                "peer IP address must not be unspecified",
            ));
        }
        let key = load_epoch_key(secret_root, device_id.get(), key_epoch.get())
            .map_err(|source| RouteError::secret(peer, device_id, key_epoch, source))?;
        Ok(Self { peer, device_id, key_epoch, key, limits, decoded })
    }

    /// Returns the post-authentication identity and capability route.
    #[must_use]
    pub const fn decoded(&self) -> &DecodedRoute {
        &self.decoded
    }

    fn semantic_rejection(&self, message: &Message) -> Option<RejectReason> {
        match message {
            Message::Capabilities(capability)
                if capability.capability_digest() != self.decoded.capability().into_bytes()
                    || capability.descriptor().firmware_build_digest()
                        != self.decoded.firmware_build().into_bytes()
                    || usize::from(capability.descriptor().datagram_budget_bytes())
                        > self.limits.datagram_bytes.get() =>
            {
                Some(RejectReason::CapabilityConflict)
            }
            Message::CsiData(data)
                if data.capability_digest() != self.decoded.capability().into_bytes() =>
            {
                Some(RejectReason::CapabilityConflict)
            }
            Message::CsiData(data)
                if data.source_mac() != self.decoded.source_mac().into_bytes() =>
            {
                Some(RejectReason::SourceConflict)
            }
            Message::CsiData(data) if !self.decoded.admits_radio(data.radio()) => {
                Some(RejectReason::RadioConflict)
            }
            Message::Health(health)
                if health.capability_digest() != self.decoded.capability().into_bytes() =>
            {
                Some(RejectReason::CapabilityConflict)
            }
            Message::Health(health)
                if health.callback_max_us() != 0 || health.encoder_max_us() != 0 =>
            {
                Some(RejectReason::UnsupportedHealthLatency)
            }
            _ => None,
        }
    }
}

/// Invalid construction of an authenticated native-frame route.
#[derive(Debug)]
pub struct RouteError {
    kind: RouteErrorKind,
    peer: IpAddr,
    device_id: DeviceId,
    key_epoch: KeyEpoch,
    backtrace: Box<Backtrace>,
}

impl RouteError {
    fn invalid(
        peer: IpAddr,
        device_id: DeviceId,
        key_epoch: KeyEpoch,
        reason: &'static str,
    ) -> Self {
        Self {
            kind: RouteErrorKind::Invalid(reason),
            peer,
            device_id,
            key_epoch,
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    fn secret(
        peer: IpAddr,
        device_id: DeviceId,
        key_epoch: KeyEpoch,
        source: SecretStoreError,
    ) -> Self {
        Self {
            kind: RouteErrorKind::Secret(source),
            peer,
            device_id,
            key_epoch,
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    /// Returns the route peer involved in construction.
    #[must_use]
    pub const fn peer(&self) -> IpAddr {
        self.peer
    }

    /// Returns the route device involved in construction.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the route key epoch involved in construction.
    #[must_use]
    pub const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
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
        write!(
            formatter,
            "native-frame route peer {} device {} epoch {}: {}",
            self.peer, self.device_id, self.key_epoch, self.kind
        )
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
            measurement_limits: AssemblyLimits::host_default(),
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
    measurement_limits: AssemblyLimits,
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
            .field("measurement_limits", &self.measurement_limits)
            .finish_non_exhaustive()
    }
}

impl HostBuilder {
    /// Adds one exact peer, epoch-key, and decoded-identity route.
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

    /// Sets fixed assembly count, byte, and wait ceilings for the sole writer.
    #[must_use]
    pub fn measurement_limits(mut self, limits: AssemblyLimits) -> Self {
        self.measurement_limits = limits;
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
        let query_routes = Arc::new(self.routes.clone());
        let database_path = self.store.database_path();
        let replay_snapshot = self.store.database_snapshot().map_err(|source| {
            HostError::io_during(
                "create read-only Store snapshot",
                Some(&database_path),
                None,
                None,
                source,
            )
        })?;
        let socket = self.network.bind(self.bind).map_err(|source| {
            HostError::io_during("bind UDP socket", None, Some(self.bind), None, source)
        })?;
        let local_addr = socket.local_addr().map_err(|source| {
            HostError::io_during("read bound UDP address", None, Some(self.bind), None, source)
        })?;
        socket.set_read_timeout(Some(SOCKET_POLL_INTERVAL)).map_err(|source| {
            HostError::io_during("set UDP read timeout", None, Some(local_addr), None, source)
        })?;
        let stop = Arc::new(AtomicBool::new(false));
        let completion = Arc::new((Mutex::new(Completion::default()), Condvar::new()));
        let rejections =
            Arc::new(Mutex::new(VecDeque::with_capacity(REJECTION_DIAGNOSTIC_CAPACITY)));
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (control_sender, control_receiver) = mpsc::sync_channel(CONTROL_QUEUE_CAPACITY);
        let control_bytes = Arc::new(AtomicU64::new(0));
        let supervisor_control_bytes = Arc::clone(&control_bytes);
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
                            local_addr,
                            threads: supervisor_threads,
                            replay_snapshot,
                            stop: supervisor_stop,
                            completion: supervisor_completion,
                            rejections: supervisor_rejections,
                            ready_sender,
                            control_receiver,
                            control_bytes: supervisor_control_bytes,
                        },
                    );
                }),
            )
            .map_err(|source| {
                HostError::io_during(
                    "spawn Host supervisor",
                    None,
                    Some(local_addr),
                    Some("whisper-host-supervisor"),
                    source,
                )
            })?;

        ready_receiver.recv().map_err(|_| {
            HostError::message_during("await Host startup", "Host supervisor exited during startup")
        })??;
        Ok(HostRuntime {
            local_addr,
            database_path,
            routes: query_routes,
            stop,
            completion,
            rejections,
            control_sender: Some(control_sender),
            control_bytes,
        })
    }
}

/// A running Host handle with the only raw query entry point.
#[derive(Debug)]
pub struct HostRuntime {
    local_addr: SocketAddr,
    database_path: PathBuf,
    routes: Arc<Vec<NativeFrameRoute>>,
    stop: Arc<AtomicBool>,
    completion: Arc<(Mutex<Completion>, Condvar)>,
    rejections: Arc<Mutex<VecDeque<RejectedDatagram>>>,
    control_sender: Option<mpsc::SyncSender<ControlCommand>>,
    control_bytes: Arc<AtomicU64>,
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
            return Err(HostError::message_during(
                "validate raw query",
                "raw query limit must be between 1 and 1024",
            ));
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
            return Err(HostError::message_during(
                "validate raw-loss query",
                "raw-loss query limit must be between 1 and 1024",
            ));
        }
        query_raw_losses(&self.database_path, limit)
    }

    /// Queries at most `limit` committed capability, CSI, and health facts.
    ///
    /// Facts are returned oldest first within the newest requested suffix. Each
    /// typed fact carries the digest of the exact raw datagram from which it was
    /// derived.
    ///
    /// # Errors
    ///
    /// The limit must be between one and 1,024, and the Store must remain readable.
    pub fn query_native_facts(&self, limit: usize) -> Result<Vec<NativeFact>, HostError> {
        validate_native_query_limit(limit)?;
        query_native_facts(&self.database_path, &self.routes, limit)
    }

    /// Queries at most `limit` capability-qualified native CSI observations.
    ///
    /// Facts are returned oldest first within the newest requested suffix.
    ///
    /// # Errors
    ///
    /// The limit must be between one and 1,024, and the Store must remain readable.
    pub fn query_native_csi(&self, limit: usize) -> Result<Vec<NativeCsiFact>, HostError> {
        validate_native_query_limit(limit)?;
        query_native_csi(&self.database_path, &self.routes, limit)
    }

    /// Queries at most `limit` persisted native capability declarations.
    ///
    /// Facts are returned oldest first within the newest requested suffix.
    ///
    /// # Errors
    ///
    /// The limit must be between one and 1,024, and the Store must remain readable.
    pub fn query_native_capabilities(
        &self,
        limit: usize,
    ) -> Result<Vec<NativeCapabilityFact>, HostError> {
        validate_native_query_limit(limit)?;
        query_native_capabilities(&self.database_path, &self.routes, limit)
    }

    /// Queries at most `limit` persisted native health reports.
    ///
    /// Facts are returned oldest first within the newest requested suffix.
    ///
    /// # Errors
    ///
    /// The limit must be between one and 1,024, and the Store must remain readable.
    pub fn query_native_health(&self, limit: usize) -> Result<Vec<NativeHealthFact>, HostError> {
        validate_native_query_limit(limit)?;
        query_native_health(&self.database_path, &self.routes, limit)
    }

    /// Persists one independently established physical-input qualification.
    ///
    /// # Errors
    ///
    /// Returns an error when the sole Store writer is unavailable or persistence fails.
    pub fn persist_qualification(&self, relation: QualificationRelation) -> Result<(), HostError> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        let bytes = relation_command_bytes(&relation)?;
        self.enqueue_control(
            ControlCommand::Qualification { relation, reply: reply_sender, queued_bytes: 0 },
            bytes,
            "persist qualification",
        )?;
        reply_receiver.recv_timeout(CONTROL_RESPONSE_DEADLINE).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => HostError::message_during(
                "persist qualification",
                "Store writer response deadline elapsed",
            ),
            mpsc::RecvTimeoutError::Disconnected => {
                HostError::message_during("persist qualification", "Store writer exited")
            }
        })?
    }

    /// Persists and assembles one heterogeneous measurement fragment through the sole writer.
    ///
    /// # Errors
    ///
    /// Returns an error when finite queue limits or response deadlines elapse, or persistence fails.
    pub fn persist_measurement_fragment(
        &self,
        fragment: MeasurementFragment,
        arrival: SourceTick,
    ) -> Result<Vec<AssemblyClose>, HostError> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        let bytes = u64::from(fragment.fact().bytes().get()).saturating_add(512);
        self.enqueue_control(
            ControlCommand::Fragment { fragment, arrival, reply: reply_sender, queued_bytes: 0 },
            bytes,
            "persist measurement fragment",
        )?;
        reply_receiver.recv_timeout(CONTROL_RESPONSE_DEADLINE).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => HostError::message_during(
                "persist measurement fragment",
                "Store writer response deadline elapsed",
            ),
            mpsc::RecvTimeoutError::Disconnected => {
                HostError::message_during("persist measurement fragment", "Store writer exited")
            }
        })?
    }

    /// Persists wait-limit closes for one source at an explicit source-native tick.
    ///
    /// # Errors
    ///
    /// Returns an error when finite queue limits or response deadlines elapse, or persistence fails.
    pub fn expire_measurements(
        &self,
        source: SourceInstance,
        now: SourceTick,
    ) -> Result<Vec<AssemblyClose>, HostError> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        self.enqueue_control(
            ControlCommand::Expire { source, now, reply: reply_sender, queued_bytes: 0 },
            512,
            "expire measurements",
        )?;
        reply_receiver.recv_timeout(CONTROL_RESPONSE_DEADLINE).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => HostError::message_during(
                "expire measurements",
                "Store writer response deadline elapsed",
            ),
            mpsc::RecvTimeoutError::Disconnected => {
                HostError::message_during("expire measurements", "Store writer exited")
            }
        })?
    }

    fn enqueue_control(
        &self,
        mut command: ControlCommand,
        bytes: u64,
        operation: &'static str,
    ) -> Result<(), HostError> {
        if bytes > CONTROL_QUEUE_BYTES {
            return Err(HostError::message_during(
                operation,
                "command exceeds the control byte ceiling",
            ));
        }
        let sender = self
            .control_sender
            .as_ref()
            .ok_or_else(|| HostError::message_during(operation, "Host is shutting down"))?;
        let deadline = Instant::now() + CONTROL_ENQUEUE_DEADLINE;
        loop {
            let current = self.control_bytes.load(Ordering::Acquire);
            if current <= CONTROL_QUEUE_BYTES - bytes
                && self
                    .control_bytes
                    .compare_exchange_weak(
                        current,
                        current + bytes,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(HostError::message_during(
                    operation,
                    "control queue byte deadline elapsed",
                ));
            }
            thread::yield_now();
        }
        command.set_queued_bytes(bytes);
        loop {
            match sender.try_send(command) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) if Instant::now() < deadline => {
                    command = returned;
                    thread::yield_now();
                }
                Err(mpsc::TrySendError::Full(_)) => {
                    self.control_bytes.fetch_sub(bytes, Ordering::AcqRel);
                    return Err(HostError::message_during(
                        operation,
                        "control queue count deadline elapsed",
                    ));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.control_bytes.fetch_sub(bytes, Ordering::AcqRel);
                    return Err(HostError::message_during(
                        operation,
                        "Store writer is unavailable",
                    ));
                }
            }
        }
    }

    /// Queries a bounded newest suffix of immutable assembly closes.
    ///
    /// # Errors
    ///
    /// The limit must be between one and 1,024, and the Store must remain readable.
    pub fn query_measurement_closes(&self, limit: usize) -> Result<Vec<AssemblyClose>, HostError> {
        validate_native_query_limit(limit)?;
        query_measurement_closes(&self.database_path, limit)
    }

    /// Queries a bounded newest suffix of persisted qualification relations.
    ///
    /// # Errors
    ///
    /// The limit must be between one and 1,024, and the Store must remain readable.
    pub fn query_qualifications(
        &self,
        limit: usize,
    ) -> Result<Vec<QualificationRelation>, HostError> {
        validate_native_query_limit(limit)?;
        query_qualifications(&self.database_path, limit)
    }

    /// Returns a bounded newest suffix of non-authoritative rejection diagnostics.
    ///
    /// # Errors
    ///
    /// The limit must be between one and the diagnostic capacity of 64.
    pub fn query_rejections(&self, limit: usize) -> Result<Vec<RejectedDatagram>, HostError> {
        if !(1..=REJECTION_DIAGNOSTIC_CAPACITY).contains(&limit) {
            return Err(HostError::message_during(
                "validate rejection query",
                "rejection query limit must be between 1 and 64",
            ));
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
    pub fn shutdown(mut self) -> Result<(), HostError> {
        self.stop.store(true, Ordering::Release);
        self.control_sender.take();
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

/// Classification emitted when ingress or semantic admission rejects a datagram.
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
    /// The authenticated kind byte is not a v1 body kind.
    UnknownKind,
    /// The authenticated body failed its selected v1 grammar.
    MalformedBody,
    /// A CSI body named no capability persisted earlier in its epoch.
    CapabilityUnavailable,
    /// The body capability identity conflicts with the epoch capability pin.
    CapabilityConflict,
    /// Health latency fields are not accepted by the current host contract.
    UnsupportedHealthLatency,
    /// The authenticated CSI source identity conflicts with the epoch source pin.
    SourceConflict,
    /// The authenticated CSI radio channel conflicts with the epoch radio pin.
    RadioConflict,
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

    /// Returns why this datagram was rejected; semantic rejects retain raw bytes.
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
    kind: Box<HostErrorKind>,
    operation: &'static str,
    path: Option<PathBuf>,
    address: Option<SocketAddr>,
    thread: Option<&'static str>,
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
    #[error("Host replay identity failed: {0}")]
    ReplayIdentity(#[source] ReplayIdentityError),
    #[error("Host replay state failed: {0}")]
    ReplayState(#[source] ReplayStateError),
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Host {}", self.operation)?;
        if let Some(path) = &self.path {
            write!(formatter, " at {}", path.display())?;
        }
        if let Some(address) = self.address {
            write!(formatter, " for {address}")?;
        }
        if let Some(thread) = self.thread {
            write!(formatter, " on thread {thread}")?;
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
        Self::message_during("validate or decode Host state", message)
    }

    fn message_during(operation: &'static str, message: &'static str) -> Self {
        Self::new(operation, None, None, None, HostErrorKind::Message(message))
    }

    fn message_at(operation: &'static str, path: &Path, message: &'static str) -> Self {
        Self::new(operation, Some(path.to_owned()), None, None, HostErrorKind::Message(message))
    }

    fn message_on_thread(
        operation: &'static str,
        thread: &'static str,
        message: &'static str,
    ) -> Self {
        Self::new(operation, None, None, Some(thread), HostErrorKind::Message(message))
    }

    fn io_during(
        operation: &'static str,
        path: Option<&Path>,
        address: Option<SocketAddr>,
        thread: Option<&'static str>,
        source: io::Error,
    ) -> Self {
        Self::new(operation, path.map(Path::to_owned), address, thread, HostErrorKind::Io(source))
    }

    fn database_at(path: &Path, source: rusqlite::Error) -> Self {
        Self::new(
            "access Store database",
            Some(path.to_owned()),
            None,
            None,
            HostErrorKind::Database(source),
        )
    }

    fn replay_identity(path: &Path, source: ReplayIdentityError) -> Self {
        Self::new(
            "derive replay identity",
            Some(path.to_owned()),
            None,
            None,
            HostErrorKind::ReplayIdentity(source),
        )
    }

    fn replay_state(path: &Path, source: ReplayStateError) -> Self {
        Self::new(
            "validate replay state",
            Some(path.to_owned()),
            None,
            None,
            HostErrorKind::ReplayState(source),
        )
    }

    fn new(
        operation: &'static str,
        path: Option<PathBuf>,
        address: Option<SocketAddr>,
        thread: Option<&'static str>,
        kind: HostErrorKind,
    ) -> Self {
        Self {
            kind: Box::new(kind),
            operation,
            path,
            address,
            thread,
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    /// Returns the filesystem path involved in the failed operation, when applicable.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns the operation that failed.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Returns the network address involved in the failed operation, when applicable.
    #[must_use]
    pub const fn address(&self) -> Option<SocketAddr> {
        self.address
    }

    /// Returns the named worker involved in the failed operation, when applicable.
    #[must_use]
    pub const fn thread(&self) -> Option<&'static str> {
        self.thread
    }

    /// Returns the captured failure backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        self.backtrace.as_ref()
    }
}

#[derive(Default, Debug)]
struct Completion {
    done: bool,
    failure: Option<HostError>,
}

#[derive(Debug)]
struct AdmittedDatagram {
    route_index: usize,
    header: Header,
    authenticated: AuthenticatedDatagram,
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
    measurement_limits: AssemblyLimits,
}

struct ReaderConfig {
    socket: Box<dyn DatagramSocket>,
    local_addr: SocketAddr,
    routes: Arc<Vec<NativeFrameRoute>>,
    clock: Arc<dyn Clock>,
}

struct SupervisorContext {
    socket: Box<dyn DatagramSocket>,
    local_addr: SocketAddr,
    threads: Arc<dyn Threads>,
    replay_snapshot: StoreSnapshot,
    stop: Arc<AtomicBool>,
    completion: Arc<(Mutex<Completion>, Condvar)>,
    rejections: Arc<Mutex<VecDeque<RejectedDatagram>>>,
    ready_sender: mpsc::SyncSender<Result<(), HostError>>,
    control_receiver: mpsc::Receiver<ControlCommand>,
    control_bytes: Arc<AtomicU64>,
}

#[derive(Debug)]
enum ControlCommand {
    Qualification {
        relation: QualificationRelation,
        reply: mpsc::SyncSender<Result<(), HostError>>,
        queued_bytes: u64,
    },
    Fragment {
        fragment: MeasurementFragment,
        arrival: SourceTick,
        reply: mpsc::SyncSender<Result<Vec<AssemblyClose>, HostError>>,
        queued_bytes: u64,
    },
    Expire {
        source: SourceInstance,
        now: SourceTick,
        reply: mpsc::SyncSender<Result<Vec<AssemblyClose>, HostError>>,
        queued_bytes: u64,
    },
}

fn relation_command_bytes(relation: &QualificationRelation) -> Result<u64, HostError> {
    let details = match relation {
        QualificationRelation::Time(value) => {
            value.source_clock().len() + value.target_clock().len() + 32
        }
        QualificationRelation::Phase(_) => 48,
        QualificationRelation::Port(value) => value.entries().len().saturating_mul(9),
        QualificationRelation::Geometry(value) => {
            value.source_frame().len() + value.target_frame().len() + 56
        }
    };
    u64::try_from(relation.common().provenance().len().saturating_add(details).saturating_add(512))
        .map_err(|_| {
            HostError::message_during("persist qualification", "qualification size overflowed")
        })
}

impl ControlCommand {
    fn set_queued_bytes(&mut self, bytes: u64) {
        match self {
            Self::Qualification { queued_bytes, .. }
            | Self::Fragment { queued_bytes, .. }
            | Self::Expire { queued_bytes, .. } => *queued_bytes = bytes,
        }
    }
    const fn queued_bytes(&self) -> u64 {
        match self {
            Self::Qualification { queued_bytes, .. }
            | Self::Fragment { queued_bytes, .. }
            | Self::Expire { queued_bytes, .. } => *queued_bytes,
        }
    }
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
    sender: mpsc::Sender<(&'static str, Result<(), HostError>)>,
    result: Option<Result<(), HostError>>,
}

impl WorkerExitNotifier {
    fn new(
        worker: &'static str,
        sender: mpsc::Sender<(&'static str, Result<(), HostError>)>,
    ) -> Self {
        Self { worker, sender, result: None }
    }

    fn complete(&mut self, result: Result<(), HostError>) {
        self.result = Some(result);
    }
}

impl Drop for WorkerExitNotifier {
    fn drop(&mut self) {
        let result = self.result.take().unwrap_or_else(|| {
            Err(HostError::message_on_thread("run Host worker", self.worker, "worker panicked"))
        });
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
use persistence::{validate_native_route_pins, writer_loop};
mod query;
use query::{
    query_measurement_closes, query_native_capabilities, query_native_csi, query_native_facts,
    query_native_health, query_qualifications, query_raw, query_raw_losses,
};

fn validate_native_query_limit(limit: usize) -> Result<(), HostError> {
    if !(1..=MAXIMUM_RAW_QUERY_FACTS).contains(&limit) {
        return Err(HostError::message_during(
            "validate native-fact query",
            "native-fact query limit must be between 1 and 1024",
        ));
    }
    Ok(())
}
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
    let mut state = changed
        .wait_while(state, |state| !state.done)
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.failure.take().map_or(Ok(()), Err)
}

fn finish_completion(completion: &(Mutex<Completion>, Condvar), failure: Option<HostError>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{
        AuthenticatedBytesPerSecond, DatagramBytes, PacketsPerSecond, ReplayWindowPackets,
    };
    use std::fs;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    const KEY: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    fn limits() -> AdmissionLimits {
        AdmissionLimits::new(
            DatagramBytes::try_from(1_200).unwrap(),
            PacketsPerSecond::try_from(1_000).unwrap(),
            AuthenticatedBytesPerSecond::try_from(1_200_000).unwrap(),
            ReplayWindowPackets::try_from(64).unwrap(),
        )
    }

    fn route() -> NativeFrameRoute {
        let radio = RadioRxS3::try_new(
            1,
            S3SecondaryKind::None,
            S3PhyKind::NonHt,
            S3BandwidthKind::TwentyMhz,
            false,
            -42,
            -95,
            6,
            0,
            0,
        )
        .unwrap();
        NativeFrameRoute {
            peer: "127.0.0.1".parse().unwrap(),
            device_id: DeviceId::new(0x0102_0304_0506_0708),
            key_epoch: KeyEpoch::try_from(7).unwrap(),
            key: EpochKey::try_from(KEY.as_slice()).unwrap(),
            limits: limits(),
            decoded: DecodedRoute::new(
                SensorId::try_from("sensor-a").unwrap(),
                DecodedRouteLink::new(
                    SourceMac::try_from([2, 0, 0, 0, 0, 10]).unwrap(),
                    ChannelPolicy::try_from(1).unwrap(),
                    RadioRouteFacts::from_radio(radio),
                ),
                FirmwareBuildIdentity::from([0x11; 32]),
                CapabilityIdentity::from([0x34; 32]),
            ),
        }
    }

    fn store_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-host-system-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    struct FailedNetwork;

    impl Network for FailedNetwork {
        fn bind(&self, _address: SocketAddr) -> io::Result<Box<dyn DatagramSocket>> {
            Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "injected bind failure"))
        }
    }

    struct FailedThreads;

    impl Threads for FailedThreads {
        fn spawn(
            &self,
            _name: &'static str,
            _task: Box<dyn FnOnce() + Send>,
        ) -> io::Result<thread::JoinHandle<()>> {
            Err(io::Error::other("injected spawn failure"))
        }
    }

    struct TimeoutFailedNetwork;

    impl Network for TimeoutFailedNetwork {
        fn bind(&self, _address: SocketAddr) -> io::Result<Box<dyn DatagramSocket>> {
            Ok(Box::new(TimeoutFailedSocket))
        }
    }

    struct TimeoutFailedSocket;

    impl DatagramSocket for TimeoutFailedSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:4321".parse().unwrap())
        }

        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Err(io::Error::other("injected timeout failure"))
        }

        fn recv_from(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            unreachable!("timeout setup fails before receive")
        }
    }

    #[test]
    fn injected_network_failure_retains_bind_address_and_source() {
        let root = store_root("network");
        let store = Store::initialize(&root).unwrap();
        let bind = "127.0.0.1:0".parse().unwrap();
        let mut builder = Host::builder(store, DeploymentId::try_from("lab").unwrap(), bind);
        builder.routes.push(route());
        builder.network = Arc::new(FailedNetwork);

        let error = builder.start().unwrap_err();
        assert_eq!(error.operation(), "bind UDP socket");
        assert_eq!(error.address(), Some(bind));
        assert!(std::error::Error::source(&error).is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn injected_timeout_failure_retains_bound_address_and_source() {
        let root = store_root("timeout");
        let store = Store::initialize(&root).unwrap();
        let mut builder = Host::builder(
            store,
            DeploymentId::try_from("lab").unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        );
        builder.routes.push(route());
        builder.network = Arc::new(TimeoutFailedNetwork);

        let error = builder.start().unwrap_err();
        assert_eq!(error.operation(), "set UDP read timeout");
        assert_eq!(error.address(), Some("127.0.0.1:4321".parse().unwrap()));
        assert!(std::error::Error::source(&error).is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn injected_thread_failure_retains_thread_name_and_source() {
        let root = store_root("threads");
        let store = Store::initialize(&root).unwrap();
        let mut builder = Host::builder(
            store,
            DeploymentId::try_from("lab").unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        );
        builder.routes.push(route());
        builder.threads = Arc::new(FailedThreads);

        let error = builder.start().unwrap_err();
        assert_eq!(error.operation(), "spawn Host supervisor");
        assert_eq!(error.thread(), Some("whisper-host-supervisor"));
        assert!(std::error::Error::source(&error).is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn database_failure_retains_store_path_and_source() {
        let path = Path::new("/test/store/facts.sqlite3");
        let error = HostError::database_at(path, rusqlite::Error::InvalidQuery);
        assert_eq!(error.path(), Some(path));
        assert!(std::error::Error::source(&error).is_some());
    }

    struct OrderedClock {
        events: Arc<Mutex<Vec<&'static str>>>,
        monotonic: Instant,
    }

    impl Clock for OrderedClock {
        fn monotonic_now(&self) -> Instant {
            self.events.lock().unwrap().push("monotonic");
            self.monotonic
        }

        fn wall_now(&self) -> SystemTime {
            self.events.lock().unwrap().push("wall");
            UNIX_EPOCH + Duration::from_nanos(123)
        }
    }

    struct OneDatagram {
        bytes: Box<[u8]>,
        delivered: AtomicBool,
        stop: Arc<AtomicBool>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl DatagramSocket for OneDatagram {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:9000".parse().unwrap())
        }

        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            if !self.delivered.swap(true, Ordering::AcqRel) {
                self.events.lock().unwrap().push("receive");
                buffer[..self.bytes.len()].copy_from_slice(&self.bytes);
                return Ok((self.bytes.len(), "127.0.0.1:7000".parse().unwrap()));
            }
            self.stop.store(true, Ordering::Release);
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    fn hex_fixture(text: &str) -> Box<[u8]> {
        text.bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap() as u8;
                let low = (pair[1] as char).to_digit(16).unwrap() as u8;
                (high << 4) | low
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    #[test]
    fn injected_clock_samples_receive_time_before_admission_work() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let socket = OneDatagram {
            bytes: hex_fixture(include_str!(
                "../tests/fixtures/native-frame/csi-non-ht-3-pairs.hex"
            )),
            delivered: AtomicBool::new(false),
            stop: Arc::clone(&stop),
            events: Arc::clone(&events),
        };
        let config = ReaderConfig {
            socket: Box::new(socket),
            local_addr: "127.0.0.1:9000".parse().unwrap(),
            routes: Arc::new(vec![route()]),
            clock: Arc::new(OrderedClock {
                events: Arc::clone(&events),
                monotonic: Instant::now(),
            }),
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let overflow = OverflowSummary { count: AtomicU64::new(0) };
        let rejections = Mutex::new(VecDeque::new());

        reader_loop(config, sender, &overflow, &rejections, &stop).unwrap();

        assert_eq!(receiver.recv().unwrap().received_utc_ns, 123);
        assert_eq!(&*events.lock().unwrap(), &["monotonic", "receive", "wall", "monotonic"]);
    }
}
