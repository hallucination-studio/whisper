//! Supervised authenticated UDP admission and restricted local raw-fact queries.

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
use crate::artifact::{
    Artifact, ArtifactDigest, ArtifactImportError, ArtifactKind, ArtifactLimits, ArtifactOrigin,
    ArtifactRejectReason, ImportedArtifact, SealedArtifact,
};
use crate::companion::{
    ClockChallengeMeasurement, ClockSampleChallenge, CompanionChunk, CompanionEntropy,
    CompanionError, CompanionHandshakeRequest, CompanionHandshakeResponse, CompanionRejectReason,
    CompanionServerIdentity, CompanionState, PairingCode, PairingId, PairingOffer,
    SystemCompanionEntropy, UploadProgress,
};
use crate::key::{EpochKey, SecretStoreError, load_epoch_key};
use crate::native_frame::{Header, authenticate_datagram, parse_header};
use crate::replay::{
    ReplayAdmission, ReplayDecision, ReplayIdentityError, ReplayStateError,
    derive_replay_window_identity,
};
use crate::store::{Store, StoreSnapshot};
use crate::{BootGeneration, DeploymentId, DeviceId, KeyEpoch, MessageSequence, NativeFrameKind};

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
/// Worker stop/error polling period in milliseconds. The value keeps shutdown
/// latency interactive while avoiding a busy loop; changing it affects both
/// idle wakeups and worst-case cooperative shutdown latency.
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Packet and authenticated-byte budgets reset over one-second wall-independent
/// periods because the configured units are per second. Changing it changes
/// admission semantics and requires renaming those units.
const RATE_PERIOD: Duration = Duration::from_secs(1);
/// Maximum lifetime of a displayed one-time pairing offer.
const MAX_PAIRING_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Maximum time an import caller waits for the sole writer response. This
/// bounds API latency without claiming that an interrupted transaction committed.
const ARTIFACT_IMPORT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

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
        Ok(Self { peer, device_id, key_epoch, key, limits })
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
            artifact_limits: ArtifactLimits::default(),
            known_rf_identities: BTreeSet::new(),
            network: Arc::new(SystemNetwork),
            threads: Arc::new(SystemThreads),
            clock: Arc::new(SystemClock),
            companion_entropy: Arc::new(SystemCompanionEntropy),
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
    artifact_limits: ArtifactLimits,
    known_rf_identities: BTreeSet<String>,
    network: Arc<dyn Network>,
    threads: Arc<dyn Threads>,
    clock: Arc<dyn Clock>,
    companion_entropy: Arc<dyn CompanionEntropy>,
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
            .field("artifact_limits", &self.artifact_limits)
            .field("known_rf_identities", &self.known_rf_identities)
            .field("companion_entropy", &"cryptographic entropy capability")
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

    /// Sets bounded artifact validation and Store-capacity limits.
    #[must_use]
    pub fn artifact_limits(mut self, limits: ArtifactLimits) -> Self {
        self.artifact_limits = limits;
        self
    }

    /// Registers one RF identity that calibration artifacts may reference.
    #[must_use]
    pub fn known_rf_identity(mut self, identity: impl Into<String>) -> Self {
        self.known_rf_identities.insert(identity.into());
        self
    }

    /// Replaces the companion cryptographic entropy capability.
    #[must_use]
    pub fn companion_entropy(mut self, entropy: impl CompanionEntropy + 'static) -> Self {
        self.companion_entropy = Arc::new(entropy);
        self
    }

    /// Starts the UDP reader, sole writer, and independent lifecycle supervisor.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, duplicate or missing routes, socket
    /// startup failure, or failure to open the Store writer.
    pub fn start(mut self) -> Result<HostRuntime, HostError> {
        validate_builder(&self)?;
        let companion_signing_seed = self.store.take_companion_signing_seed();
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
        let (artifact_sender, artifact_receiver) = mpsc::sync_channel(8);
        let artifact_limits = self.artifact_limits;
        let known_rf_identities = self.known_rf_identities.clone();
        let runtime_clock = Arc::clone(&self.clock);
        let companion_entropy = Arc::clone(&self.companion_entropy);
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
                            artifact_receiver,
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
            stop,
            completion,
            rejections,
            artifact_sender,
            artifact_limits,
            known_rf_identities,
            clock: runtime_clock,
            companion: Arc::new(Mutex::new(CompanionState::new(companion_signing_seed))),
            companion_entropy,
            companion_monotonic_origin: Mutex::new(None),
        })
    }
}

/// A running Host handle with the only raw query entry point.
pub struct HostRuntime {
    local_addr: SocketAddr,
    database_path: PathBuf,
    stop: Arc<AtomicBool>,
    completion: Arc<(Mutex<Completion>, Condvar)>,
    rejections: Arc<Mutex<VecDeque<RejectedDatagram>>>,
    artifact_sender: mpsc::SyncSender<ArtifactCommand>,
    artifact_limits: ArtifactLimits,
    known_rf_identities: BTreeSet<String>,
    clock: Arc<dyn Clock>,
    companion: Arc<Mutex<CompanionState>>,
    companion_entropy: Arc<dyn CompanionEntropy>,
    companion_monotonic_origin: Mutex<Option<Instant>>,
}

impl fmt::Debug for HostRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRuntime")
            .field("local_addr", &self.local_addr)
            .field("database_path", &self.database_path)
            .field("artifact_limits", &self.artifact_limits)
            .field("known_rf_identities", &self.known_rf_identities)
            .field("companion", &"paired encrypted artifact entry")
            .finish_non_exhaustive()
    }
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

    /// Validates and commits a sealed artifact through the sole Store writer.
    ///
    /// Exact retries return the original receipt. This entry can create only
    /// immutable candidate artifacts; it has no activation or world-state authority.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for invalid, unsupported, oversized,
    /// incompatible, expired, conflicting, or unpersistable content.
    pub fn import_artifact(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<ImportedArtifact, ArtifactImportError> {
        self.import_artifact_from(bytes.as_ref(), ArtifactOrigin::Local)
    }

    fn import_artifact_from(
        &self,
        bytes: &[u8],
        origin: ArtifactOrigin,
    ) -> Result<ImportedArtifact, ArtifactImportError> {
        if bytes.len() > self.artifact_limits.max_artifact_bytes() {
            return Err(ArtifactImportError::new(
                ArtifactRejectReason::LimitExceeded,
                "sealed artifact byte limit exceeded",
            ));
        }
        let sealed = SealedArtifact::parse(bytes).map_err(ArtifactImportError::invalid_artifact)?;
        if let Some(receipt) = query_artifact_receipt(&self.database_path, sealed.digest())? {
            return Ok(receipt);
        }
        let artifact = sealed.decode().map_err(ArtifactImportError::invalid_artifact)?;
        let imported_utc_ns = utc_now_ns(self.clock.as_ref()).map_err(|_| {
            ArtifactImportError::new(
                ArtifactRejectReason::Persistence,
                "Host clock cannot represent artifact import time",
            )
        })?;
        artifact.validate_import(
            self.artifact_limits,
            &self.known_rf_identities,
            imported_utc_ns,
        )?;
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        self.artifact_sender
            .try_send(ArtifactCommand {
                sealed,
                artifact,
                imported_utc_ns,
                origin,
                limits: self.artifact_limits,
                reply: reply_sender,
            })
            .map_err(|_| {
                ArtifactImportError::new(
                    ArtifactRejectReason::Persistence,
                    "Store writer queue is unavailable or full",
                )
            })?;
        reply_receiver.recv_timeout(ARTIFACT_IMPORT_RESPONSE_TIMEOUT).map_err(|_| {
            ArtifactImportError::new(
                ArtifactRejectReason::Persistence,
                "Store writer did not complete artifact import before the response deadline",
            )
        })?
    }

    /// Queries one committed candidate artifact by its content digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the Store cannot be read or retained bytes are invalid.
    pub fn query_artifact(
        &self,
        digest: ArtifactDigest,
    ) -> Result<Option<SealedArtifact>, HostError> {
        query_artifact(&self.database_path, digest)
    }

    /// Exports exact sealed bytes for one committed candidate artifact.
    ///
    /// # Errors
    ///
    /// Returns an error if the Store cannot be read or retained bytes are invalid.
    pub fn export_artifact(&self, digest: ArtifactDigest) -> Result<Option<Box<[u8]>>, HostError> {
        Ok(self.query_artifact(digest)?.map(|artifact| artifact.bytes().into()))
    }

    /// Creates finite-lived one-time pairing information for the companion entry.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or greater-than-ten-minute lifetime, an
    /// unrepresentable clock value, or failure to obtain secure random bytes.
    pub fn begin_companion_pairing(
        &self,
        valid_for: Duration,
    ) -> Result<PairingOffer, CompanionError> {
        if valid_for.is_zero() || valid_for > MAX_PAIRING_LIFETIME {
            return Err(CompanionError::new(
                CompanionRejectReason::LimitExceeded,
                "pairing lifetime must be between one nanosecond and ten minutes",
            ));
        }
        let now = utc_now_ns(self.clock.as_ref()).map_err(|_| companion_clock_error())?;
        let duration = u64::try_from(valid_for.as_nanos()).map_err(|_| companion_clock_error())?;
        let expires = now.checked_add(duration).ok_or_else(companion_clock_error)?;
        let id = secure_random::<16>(self.companion_entropy.as_ref())?;
        let code = PairingCode::from_bytes(secure_random::<16>(self.companion_entropy.as_ref())?);
        let server_ephemeral_secret = secure_random::<32>(self.companion_entropy.as_ref())?;
        let mut companion = self.companion.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        companion.offer(now.into(), id, code, server_ephemeral_secret, expires.into())
    }

    /// Returns the Store-stable public identity companion clients must pin.
    #[must_use]
    pub fn companion_server_identity(&self) -> CompanionServerIdentity {
        self.companion.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).server_identity()
    }

    /// Measures and signs one Host-owned half of a two-way clock sample.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong pin, expired offer, or unrepresentable Host time.
    pub fn begin_companion_clock_sample(
        &self,
        pairing_id: PairingId,
        pinned_server_identity: CompanionServerIdentity,
        client_nonce: crate::companion::ClientNonce,
        client_send: crate::artifact::PhoneNanoseconds,
    ) -> Result<ClockSampleChallenge, CompanionError> {
        let host_receive = self.companion_monotonic_now()?;
        let now = utc_now_ns(self.clock.as_ref()).map_err(|_| companion_clock_error())?;
        let host_send = self.companion_monotonic_now()?;
        self.companion.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clock_challenge(
            pairing_id,
            pinned_server_identity,
            client_nonce,
            ClockChallengeMeasurement { now_utc: now.into(), client_send, host_receive, host_send },
        )
    }

    /// Consumes one wire-reconstructable request after signed clock validation.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong pin or code, expired/reused offer, forged or
    /// invalid clock samples, or failure to obtain a fresh session identity.
    pub fn connect_companion(
        &self,
        request: CompanionHandshakeRequest,
    ) -> Result<CompanionHandshakeResponse, CompanionError> {
        let now = utc_now_ns(self.clock.as_ref()).map_err(|_| companion_clock_error())?;
        let session_id = secure_random::<16>(self.companion_entropy.as_ref())?;
        self.companion.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).connect(
            request,
            now.into(),
            session_id,
        )
    }

    fn companion_monotonic_now(&self) -> Result<crate::artifact::HostNanoseconds, CompanionError> {
        let now = self.clock.monotonic_now();
        let mut origin =
            self.companion_monotonic_origin.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let origin = *origin.get_or_insert(now);
        let nanos = u64::try_from(now.saturating_duration_since(origin).as_nanos())
            .map_err(|_| companion_clock_error())?;
        Ok(nanos.into())
    }

    /// Accepts one authenticated companion chunk and imports completed bytes.
    ///
    /// Exact duplicate chunks are idempotent. Incomplete uploads remain bounded
    /// in the paired session so a caller can resume after an interrupted send.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown/expired session, authentication failure,
    /// conflicting chunk, exceeded limit, or shared artifact import rejection.
    pub fn upload_companion_chunk(
        &self,
        chunk: CompanionChunk,
    ) -> Result<UploadProgress, CompanionError> {
        let now = utc_now_ns(self.clock.as_ref()).map_err(|_| companion_clock_error())?;
        let assembled = self
            .companion
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accept_chunk(chunk, now.into(), self.artifact_limits.max_artifact_bytes())?;
        if let Some(receipt) = &assembled.completed_receipt {
            return Ok(UploadProgress::Imported(receipt.clone()));
        }
        if assembled.bytes.is_empty() {
            return Ok(UploadProgress::Pending {
                received_chunks: assembled.received_chunks,
                total_chunks: assembled.total_chunks,
            });
        }
        let uploaded = SealedArtifact::parse(&assembled.bytes)
            .and_then(|sealed| sealed.decode())
            .map_err(ArtifactImportError::invalid_artifact)
            .map_err(CompanionError::from_artifact)?;
        if let Artifact::Supervision(segment) = uploaded
            && segment.time_relation != assembled.clock_relation
        {
            return Err(CompanionError::from_artifact(ArtifactImportError::new(
                ArtifactRejectReason::InvalidRelation,
                "supervision clock relation differs from its authenticated companion session",
            )));
        }
        let receipt = self
            .import_artifact_from(&assembled.bytes, ArtifactOrigin::Companion)
            .map_err(CompanionError::from_artifact)?;
        self.companion
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_completed(&assembled, receipt.clone())?;
        Ok(UploadProgress::Imported(receipt))
    }

    /// Parses and accepts one encrypted companion transport frame.
    ///
    /// # Errors
    ///
    /// Returns the same bounded protocol and shared-import failures as
    /// [`Self::upload_companion_chunk`], plus malformed frame rejection.
    pub fn upload_companion_bytes(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<UploadProgress, CompanionError> {
        let chunk =
            CompanionChunk::parse(bytes.as_ref(), self.artifact_limits.max_artifact_bytes())?;
        self.upload_companion_chunk(chunk)
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
    artifact_receiver: mpsc::Receiver<ArtifactCommand>,
}

#[derive(Debug)]
struct ArtifactCommand {
    sealed: SealedArtifact,
    artifact: Artifact,
    imported_utc_ns: u64,
    origin: ArtifactOrigin,
    limits: ArtifactLimits,
    reply: mpsc::SyncSender<Result<ImportedArtifact, ArtifactImportError>>,
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
use persistence::writer_loop;
mod query;
use query::{query_artifact, query_artifact_receipt, query_raw, query_raw_losses};
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

fn secure_random<const N: usize>(
    entropy: &dyn CompanionEntropy,
) -> Result<[u8; N], CompanionError> {
    let mut bytes = [0_u8; N];
    entropy.fill(&mut bytes).map_err(CompanionError::entropy)?;
    Ok(bytes)
}

fn companion_clock_error() -> CompanionError {
    CompanionError::new(
        CompanionRejectReason::InvalidClockRelation,
        "Host clock cannot represent companion pairing time",
    )
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
        NativeFrameRoute {
            peer: "127.0.0.1".parse().unwrap(),
            device_id: DeviceId::new(0x0102_0304_0506_0708),
            key_epoch: KeyEpoch::try_from(7).unwrap(),
            key: EpochKey::try_from(KEY.as_slice()).unwrap(),
            limits: limits(),
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
