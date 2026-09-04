//! Application-owned lifecycle coordination for managed host persistence.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "external lifecycle wiring is implemented in a later work package")
)]

#[cfg(unix)]
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
#[cfg(all(unix, feature = "ingest-test-hooks"))]
use std::sync::Weak;
#[cfg(unix)]
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering},
    mpsc::{self, Receiver, SyncSender},
};
#[cfg(unix)]
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use tokio::sync::Notify;

use crate::Config;
use crate::config::RouteConfig;
use crate::database::{Database, DatabaseError, EpochHandle, ReplayWindowIdentity};
#[cfg(unix)]
use crate::domain::csi::CaptureProfileId;
#[cfg(unix)]
use crate::domain::identity::RadioLinkId;
use crate::domain::identity::{DeploymentId, DeviceId, KeyEpoch};
#[cfg(unix)]
use crate::domain::world::{BaselineCommand, TargetedBaselineCommand};
use crate::key_material::{EpochKey, SecretStoreError, load_epoch_key};
#[cfg(unix)]
use crate::relationship::{
    CoordinatorError, RebuiltSession, RelationshipCoordinator, process_packet,
    rebuild as rebuild_relationship,
};
#[cfg(unix)]
use crate::session::{SessionRecordKind, encode_record_body};
#[cfg(all(unix, feature = "ingest-test-hooks"))]
use crate::store::RelationshipFailureStage;
#[cfg(unix)]
use crate::store::{
    AdmissionEpochSeed, CaptureSession, PreparedSession, QueryError, QueryStore, Store, StoreError,
    prepare_semantic_session,
};
#[cfg(unix)]
use crate::wire::{self, IngestError};
#[cfg(unix)]
use crate::{CapturedDatagram, CommitOutcome, ProjectionSequence};
use sha2::{Digest, Sha256};

const REPLAY_WINDOW_IDENTITY_DOMAIN: &[u8] = b"whisper.replay-window.identity";
const REPLAY_WINDOW_IDENTITY_PREIMAGE_VERSION: u8 = 1;

#[cfg(unix)]
#[derive(Clone, Debug)]
pub(crate) struct RuntimeClock {
    source: RuntimeClockSource,
}

#[cfg(unix)]
#[derive(Clone, Debug)]
enum RuntimeClockSource {
    System,
    #[cfg(feature = "ingest-test-hooks")]
    Manual(Arc<ManualClockState>),
}

#[cfg(all(unix, feature = "ingest-test-hooks"))]
#[derive(Debug)]
struct ManualClockState {
    monotonic_origin: Instant,
    utc_origin: SystemTime,
    elapsed_ns: AtomicU64,
    #[cfg(test)]
    sample_count: AtomicUsize,
    writer: Mutex<Option<Weak<WriterInbox>>>,
}

#[cfg(all(unix, feature = "ingest-test-hooks"))]
#[derive(Clone, Debug)]
pub(crate) struct ManualClockControl {
    state: Arc<ManualClockState>,
}

#[cfg(unix)]
impl RuntimeClock {
    pub(crate) const fn system() -> Self {
        Self { source: RuntimeClockSource::System }
    }

    pub(crate) fn sample(&self) -> (Instant, SystemTime) {
        match &self.source {
            RuntimeClockSource::System => (Instant::now(), SystemTime::now()),
            #[cfg(feature = "ingest-test-hooks")]
            RuntimeClockSource::Manual(state) => {
                let elapsed = Duration::from_nanos(state.elapsed_ns.load(AtomicOrdering::Acquire));
                let sample = (
                    state
                        .monotonic_origin
                        .checked_add(elapsed)
                        .expect("manual clock advance validates the monotonic range"),
                    state
                        .utc_origin
                        .checked_add(elapsed)
                        .expect("manual clock advance validates the UTC range"),
                );
                #[cfg(test)]
                state.sample_count.fetch_add(1, AtomicOrdering::Release);
                sample
            }
        }
    }

    #[cfg(feature = "ingest-test-hooks")]
    pub(crate) fn manual() -> (Self, ManualClockControl) {
        let state = Arc::new(ManualClockState {
            monotonic_origin: Instant::now(),
            utc_origin: SystemTime::now(),
            elapsed_ns: AtomicU64::new(0),
            #[cfg(test)]
            sample_count: AtomicUsize::new(0),
            writer: Mutex::new(None),
        });
        (
            Self { source: RuntimeClockSource::Manual(Arc::clone(&state)) },
            ManualClockControl { state },
        )
    }

    #[cfg(feature = "ingest-test-hooks")]
    fn attach_writer(&self, writer: &Arc<WriterInbox>) {
        if let RuntimeClockSource::Manual(state) = &self.source {
            *state.writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(Arc::downgrade(writer));
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct IngressOrder {
    capture_origin: Instant,
    capacity: usize,
    sampling: AtomicUsize,
    state: Mutex<IngressOrderState>,
    changed: Condvar,
    async_changed: Notify,
    #[cfg(test)]
    registration_transition_hold: Mutex<Option<Arc<IngressRegistrationTransitionHold>>>,
}

#[cfg(all(unix, test))]
#[derive(Debug)]
struct IngressRegistrationTransitionHold {
    arrived: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct IngressOrderState {
    pending: VecDeque<IngressEntry>,
    active: Option<u64>,
    boundary_deadline_ns: Option<u64>,
    next_id: u64,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct IngressEntry {
    id: u64,
    elapsed_ns: u64,
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct IngressReceipt {
    order: Arc<IngressOrder>,
    id: u64,
    received: (Instant, SystemTime),
}

#[cfg(unix)]
struct IngressSampling<'a>(&'a IngressOrder);

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct IngressReservation {
    receipt: IngressReceipt,
}

#[cfg(unix)]
#[derive(Debug)]
struct IngressBoundary {
    order: Arc<IngressOrder>,
}

#[cfg(unix)]
impl IngressOrder {
    fn new(capture_origin: Instant, capacity: usize) -> Self {
        Self {
            capture_origin,
            capacity,
            sampling: AtomicUsize::new(0),
            state: Mutex::new(IngressOrderState::default()),
            changed: Condvar::new(),
            async_changed: Notify::new(),
            #[cfg(test)]
            registration_transition_hold: Mutex::new(None),
        }
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        clock: &RuntimeClock,
    ) -> Result<IngressReceipt, HostError> {
        let sampling = self.start_sampling()?;
        let received = clock.sample();
        let elapsed_ns = self.elapsed_ns(received.0)?;
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let registered_and_sampling = state
            .pending
            .len()
            .checked_add(self.sampling.load(AtomicOrdering::Acquire))
            .ok_or(HostError::IngressSamplingOverflow)?;
        if registered_and_sampling > self.capacity {
            return Err(HostError::WriterQueueFull);
        }
        let id = state.next_id;
        state.next_id = state.next_id.checked_add(1).ok_or(HostError::CaptureTimeOverflow)?;
        state.pending.push_back(IngressEntry { id, elapsed_ns });
        state.pending.make_contiguous().sort_by_key(|entry| (entry.elapsed_ns, entry.id));
        drop(sampling);
        #[cfg(test)]
        self.wait_at_registration_transition();
        drop(state);
        self.changed.notify_all();
        self.async_changed.notify_waiters();
        Ok(IngressReceipt { order: Arc::clone(self), id, received })
    }

    fn hold_boundary(self: &Arc<Self>, deadline: Instant) -> Result<IngressBoundary, HostError> {
        let deadline_elapsed_ns = self.elapsed_ns(deadline)?;
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            state.boundary_deadline_ns.replace(deadline_elapsed_ns).is_none(),
            "the single capture writer must not overlap ingress deadline boundaries"
        );
        self.async_changed.notify_waiters();
        state = self
            .changed
            .wait_while(state, |state| {
                self.sampling.load(AtomicOrdering::Acquire) != 0
                    || state.pending.iter().any(|entry| entry.elapsed_ns < deadline_elapsed_ns)
            })
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(state);
        Ok(IngressBoundary { order: Arc::clone(self) })
    }

    fn elapsed_ns(&self, instant: Instant) -> Result<u64, HostError> {
        let elapsed = instant
            .checked_duration_since(self.capture_origin)
            .ok_or(HostError::ReceiveBeforeSession)?;
        let elapsed_ns =
            u64::try_from(elapsed.as_nanos()).map_err(|_| HostError::CaptureTimeOverflow)?;
        Ok(elapsed_ns)
    }

    fn start_sampling(&self) -> Result<IngressSampling<'_>, HostError> {
        self.sampling
            .fetch_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| HostError::IngressSamplingOverflow)?;
        Ok(IngressSampling(self))
    }

    #[cfg(test)]
    fn hold_next_registration_transition(&self) -> Arc<IngressRegistrationTransitionHold> {
        let hold = Arc::new(IngressRegistrationTransitionHold {
            arrived: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        let previous = self
            .registration_transition_hold
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replace(Arc::clone(&hold));
        assert!(previous.is_none(), "only one registration transition may be held");
        hold
    }

    #[cfg(test)]
    fn wait_at_registration_transition(&self) {
        let hold = self
            .registration_transition_hold
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(hold) = hold {
            hold.arrived.wait();
            hold.release.wait();
        }
    }
}

#[cfg(unix)]
impl Drop for IngressSampling<'_> {
    fn drop(&mut self) {
        let previous = self.0.sampling.fetch_sub(1, AtomicOrdering::AcqRel);
        assert!(previous != 0, "ingress sampling count must not underflow");
        self.0.changed.notify_all();
        self.0.async_changed.notify_waiters();
    }
}

#[cfg(unix)]
impl IngressReservation {
    pub(crate) const fn received(&self) -> (Instant, SystemTime) {
        self.receipt.received
    }
}

#[cfg(unix)]
impl IngressReceipt {
    pub(crate) async fn reserve(self) -> IngressReservation {
        let order = Arc::clone(&self.order);
        loop {
            let changed = order.async_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = order.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let is_front = state.pending.front().is_some_and(|entry| entry.id == self.id);
                let before_boundary = state.boundary_deadline_ns.is_none_or(|deadline| {
                    state
                        .pending
                        .front()
                        .is_some_and(|entry| entry.id == self.id && entry.elapsed_ns < deadline)
                });
                if order.sampling.load(AtomicOrdering::Acquire) == 0
                    && is_front
                    && state.active.is_none()
                    && before_boundary
                {
                    state.active = Some(self.id);
                    drop(state);
                    return IngressReservation { receipt: self };
                }
            }
            changed.await;
        }
    }
}

#[cfg(unix)]
impl Drop for IngressReceipt {
    fn drop(&mut self) {
        let mut state = self.order.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.active == Some(self.id) {
            state.active = None;
        }
        if let Some(position) = state.pending.iter().position(|entry| entry.id == self.id) {
            state.pending.remove(position);
        }
        drop(state);
        self.order.changed.notify_all();
        self.order.async_changed.notify_waiters();
    }
}

#[cfg(unix)]
impl Drop for IngressBoundary {
    fn drop(&mut self) {
        let mut state = self.order.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.boundary_deadline_ns = None;
        drop(state);
        self.order.changed.notify_all();
        self.order.async_changed.notify_waiters();
    }
}

#[cfg(all(unix, feature = "ingest-test-hooks"))]
impl ManualClockControl {
    pub(crate) fn advance(&self, elapsed: Duration) -> bool {
        let Ok(elapsed_ns) = u64::try_from(elapsed.as_nanos()) else {
            return false;
        };
        let mut current = self.state.elapsed_ns.load(AtomicOrdering::Acquire);
        loop {
            let Some(next) = current.checked_add(elapsed_ns) else {
                return false;
            };
            let elapsed = Duration::from_nanos(next);
            if self.state.monotonic_origin.checked_add(elapsed).is_none()
                || self.state.utc_origin.checked_add(elapsed).is_none()
            {
                return false;
            }
            match self.state.elapsed_ns.compare_exchange_weak(
                current,
                next,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            ) {
                Ok(_) => {
                    if let Some(writer) = self
                        .state
                        .writer
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .as_ref()
                        .and_then(Weak::upgrade)
                    {
                        writer.wake();
                    }
                    return true;
                }
                Err(actual) => current = actual,
            }
        }
    }
}
const NATIVE_FRAME_WIRE_VERSION: u8 = 1;
// Fixed by the persistence-v1 managed-database path contract. Changing this splits
// cross-process sidecar identity and requires a contract change.
const MANAGED_DATABASE_LOCK_SUFFIX: &str = ".whisper.lock";

#[derive(Clone, Copy, Debug)]
enum ManagedTarget {
    Existing,
    Provisioning,
}

#[derive(Debug)]
struct ManagedDatabaseLock {
    database_path: PathBuf,
    _sidecar: File,
}

impl ManagedDatabaseLock {
    fn acquire(config: &Config, target: ManagedTarget) -> Result<Self, HostError> {
        let configured_path = config.session().database_path();
        let database_path = match target {
            ManagedTarget::Existing => canonical_existing_database(configured_path)?,
            ManagedTarget::Provisioning => canonical_provisioning_database(configured_path)?,
        };
        let lock_path = managed_lock_path(&database_path)?;
        let sidecar = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| HostError::ManagedDatabaseLockIo {
                path: lock_path.clone(),
                source,
            })?;
        sidecar.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => {
                HostError::ManagedDatabaseLockConflict { path: lock_path.clone() }
            }
            fs::TryLockError::Error(source) => {
                HostError::ManagedDatabaseLockIo { path: lock_path.clone(), source }
            }
        })?;

        let checked_path = match target {
            ManagedTarget::Existing => canonical_existing_database(configured_path)?,
            ManagedTarget::Provisioning => canonical_provisioning_database(configured_path)?,
        };
        if checked_path != database_path {
            return Err(HostError::ManagedDatabasePathInvalid {
                path: configured_path.to_path_buf(),
            });
        }

        Ok(Self { database_path, _sidecar: sidecar })
    }

    fn database_path(&self) -> &Path {
        &self.database_path
    }
}

fn canonical_existing_database(path: &Path) -> Result<PathBuf, HostError> {
    let canonical = fs::canonicalize(path)
        .map_err(|source| HostError::ManagedDatabasePathIo { path: path.to_path_buf(), source })?;
    let metadata = fs::metadata(&canonical)
        .map_err(|source| HostError::ManagedDatabasePathIo { path: canonical.clone(), source })?;
    validate_existing_database(&canonical, &metadata)?;
    Ok(canonical)
}

fn canonical_provisioning_database(path: &Path) -> Result<PathBuf, HostError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| HostError::ManagedDatabasePathInvalid { path: path.to_path_buf() })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent).map_err(|source| {
        HostError::ManagedDatabasePathIo { path: parent.to_path_buf(), source }
    })?;
    let parent_metadata = fs::metadata(&canonical_parent).map_err(|source| {
        HostError::ManagedDatabasePathIo { path: canonical_parent.clone(), source }
    })?;
    if !parent_metadata.is_dir() {
        return Err(HostError::ManagedDatabasePathInvalid { path: canonical_parent });
    }

    let database_path = canonical_parent.join(file_name);
    match fs::symlink_metadata(&database_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(HostError::ManagedDatabaseSymlink { path: database_path })
        }
        Ok(_) => Err(HostError::ManagedDatabaseAlreadyExists { path: database_path }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(database_path),
        Err(source) => Err(HostError::ManagedDatabasePathIo { path: database_path, source }),
    }
}

fn validate_existing_database(path: &Path, metadata: &Metadata) -> Result<(), HostError> {
    if !metadata.is_file() {
        return Err(HostError::ManagedDatabasePathInvalid { path: path.to_path_buf() });
    }
    let links = metadata_link_count(metadata);
    if links > 1 {
        return Err(HostError::ManagedDatabaseHardLinked { path: path.to_path_buf(), links });
    }
    Ok(())
}

#[cfg(unix)]
fn metadata_link_count(metadata: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;

    metadata.nlink()
}

#[cfg(windows)]
fn metadata_link_count(metadata: &Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;

    metadata.number_of_links().map_or(1, u64::from)
}

#[cfg(not(any(unix, windows)))]
fn metadata_link_count(_metadata: &Metadata) -> u64 {
    1
}

fn managed_lock_path(database_path: &Path) -> Result<PathBuf, HostError> {
    let file_name = database_path.file_name().ok_or_else(|| {
        HostError::ManagedDatabasePathInvalid { path: database_path.to_path_buf() }
    })?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(MANAGED_DATABASE_LOCK_SUFFIX);
    Ok(database_path.with_file_name(lock_name))
}

fn checked_deployment_length(length: usize) -> Result<u32, HostError> {
    u32::try_from(length).map_err(|_| HostError::DeploymentIdTooLong { length })
}

fn replay_window_identity_preimage(
    deployment: &DeploymentId,
    device: DeviceId,
    key_epoch: KeyEpoch,
    epoch_key: &EpochKey,
) -> Result<Vec<u8>, HostError> {
    let deployment = deployment.as_str().as_bytes();
    let deployment_len = checked_deployment_length(deployment.len())?;
    let mut preimage = Vec::with_capacity(
        REPLAY_WINDOW_IDENTITY_DOMAIN.len() + 1 + 1 + 1 + 4 + deployment.len() + 8 + 2 + 32,
    );
    preimage.extend_from_slice(REPLAY_WINDOW_IDENTITY_DOMAIN);
    preimage.push(0);
    preimage.push(REPLAY_WINDOW_IDENTITY_PREIMAGE_VERSION);
    preimage.push(NATIVE_FRAME_WIRE_VERSION);
    preimage.extend_from_slice(&deployment_len.to_be_bytes());
    preimage.extend_from_slice(deployment);
    preimage.extend_from_slice(&device.get().to_be_bytes());
    preimage.extend_from_slice(&key_epoch.get().to_be_bytes());
    preimage.extend_from_slice(epoch_key.as_bytes());
    Ok(preimage)
}

fn replay_window_identity(
    deployment: &DeploymentId,
    device: DeviceId,
    key_epoch: KeyEpoch,
    epoch_key: &EpochKey,
) -> Result<ReplayWindowIdentity, HostError> {
    Ok(ReplayWindowIdentity::new(
        Sha256::digest(replay_window_identity_preimage(deployment, device, key_epoch, epoch_key)?)
            .into(),
    ))
}

fn replay_admission_config(
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<(&DeploymentId, u16), HostError> {
    let matches = config
        .registry()
        .routes()
        .iter()
        .filter(|route| route.device_id() == device && route.key_epoch() == key_epoch);
    let route = select_replay_admission_route(matches, device, key_epoch)?;
    Ok((config.deployment().id(), route.admission_limits().replay_window_packets()))
}

fn select_replay_admission_route<'a>(
    mut matches: impl Iterator<Item = &'a RouteConfig>,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<&'a RouteConfig, HostError> {
    let route = matches.next().ok_or(HostError::MissingAdmissionRoute { device, key_epoch })?;
    if matches.next().is_some() {
        return Err(HostError::AmbiguousAdmissionRoute { device, key_epoch });
    }
    Ok(route)
}

fn provision_admission_epoch(
    database: &mut Database,
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<(), HostError> {
    replay_admission_config(config, device, key_epoch)?;
    let epoch_key = load_epoch_key(config, device, key_epoch)?;
    provision_admission_epoch_with_key(database, config, device, key_epoch, &epoch_key)
}

fn provision_admission_epoch_with_key(
    database: &mut Database,
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
    epoch_key: &EpochKey,
) -> Result<(), HostError> {
    let (deployment, replay_window_size) = replay_admission_config(config, device, key_epoch)?;
    let identity = replay_window_identity(deployment, device, key_epoch, epoch_key)?;
    database.provision_epoch(device, key_epoch, &identity, replay_window_size)?;
    Ok(())
}

fn validate_capture_epoch(
    database: &Database,
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<EpochHandle, HostError> {
    replay_admission_config(config, device, key_epoch)?;
    let epoch_key = load_epoch_key(config, device, key_epoch)?;
    validate_capture_epoch_with_key(database, config, device, key_epoch, &epoch_key)
}

fn validate_capture_epoch_with_key(
    database: &Database,
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
    epoch_key: &EpochKey,
) -> Result<EpochHandle, HostError> {
    let (deployment, replay_window_size) = replay_admission_config(config, device, key_epoch)?;
    let identity = replay_window_identity(deployment, device, key_epoch, epoch_key)?;
    Ok(database.validate_epoch(device, key_epoch, identity, replay_window_size)?)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HostError {
    #[error("deployment ID is {length} bytes, exceeding the replay identity u32 length limit")]
    DeploymentIdTooLong { length: usize },
    #[error("no replay-admission route for device {device} and key epoch {key_epoch}")]
    MissingAdmissionRoute { device: DeviceId, key_epoch: KeyEpoch },
    #[error("multiple replay-admission routes for device {device} and key epoch {key_epoch}")]
    AmbiguousAdmissionRoute { device: DeviceId, key_epoch: KeyEpoch },
    #[error("managed database path {path} could not be resolved or inspected: {source}")]
    ManagedDatabasePathIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("managed database path {path} is not a supported database target")]
    ManagedDatabasePathInvalid { path: PathBuf },
    #[error("managed database path {path} has {links} hard links")]
    ManagedDatabaseHardLinked { path: PathBuf, links: u64 },
    #[error("managed database provisioning target {path} already exists")]
    ManagedDatabaseAlreadyExists { path: PathBuf },
    #[error("managed database provisioning target {path} is a symlink")]
    ManagedDatabaseSymlink { path: PathBuf },
    #[error("managed database lock {path} is already held")]
    ManagedDatabaseLockConflict { path: PathBuf },
    #[error("managed database lock {path} could not be opened or acquired: {source}")]
    ManagedDatabaseLockIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    SecretStore(#[from] SecretStoreError),
    #[cfg(unix)]
    #[error(transparent)]
    Store(#[from] StoreError),
    #[cfg(unix)]
    #[error("semantic coordinator failed: {0}")]
    Coordinator(#[from] CoordinatorError),
    #[cfg(unix)]
    #[error(transparent)]
    Ingest(#[from] IngestError),
    #[cfg(unix)]
    #[error(transparent)]
    ExecutableIdentity(#[from] crate::executable::ExecutableIdentityError),
    #[cfg(unix)]
    #[error("capture receive time precedes the Capture Session origin")]
    ReceiveBeforeSession,
    #[cfg(unix)]
    #[error("captured datagrams were submitted out of receive-monotonic order")]
    ReceiveOrder,
    #[cfg(unix)]
    #[error("capture receive time exceeds the capture u64 nanosecond range")]
    CaptureTimeOverflow,
    #[cfg(unix)]
    #[error("the concurrent ingress sampling count overflowed")]
    IngressSamplingOverflow,
    #[cfg(unix)]
    #[error("capture UTC time is outside the capture timestamp range")]
    CaptureClock,
    #[cfg(unix)]
    #[error("authenticated route rate limit was exceeded")]
    RateLimited,
    #[cfg(unix)]
    #[error("authenticated route rate accounting overflowed")]
    RateOverflow,
    #[cfg(unix)]
    #[error("authenticated route rate accounting is corrupt")]
    RateStateCorrupt,
    #[cfg(unix)]
    #[error("writer queue capacity cannot be represented on this platform")]
    WriterQueueCapacity,
    #[cfg(unix)]
    #[error("the bounded writer queue is full")]
    WriterQueueFull,
    #[cfg(unix)]
    #[error("the Capture runtime queue-drop counter overflowed")]
    QueueDropOverflow,
    #[cfg(unix)]
    #[error("the capture writer has stopped")]
    WriterStopped,
    #[cfg(unix)]
    #[error("the capture writer thread could not be started: {0}")]
    WriterSpawn(#[source] io::Error),
    #[cfg(unix)]
    #[error("the capture writer thread panicked")]
    WriterPanicked,
    #[cfg(not(unix))]
    #[error("this platform cannot enforce the Unix Managed-store contract")]
    UnsupportedManagedStorePlatform,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum SessionTimeMapping {
    CaptureSession,
    AwaitingContinuation {
        semantic_origin: crate::domain::time::SessionTime,
    },
    Continued {
        semantic_origin: crate::domain::time::SessionTime,
        capture_origin: crate::domain::time::SessionTime,
    },
}

#[cfg(unix)]
impl SessionTimeMapping {
    fn time_at(
        self,
        capture_time: crate::domain::time::SessionTime,
    ) -> Result<crate::domain::time::SessionTime, CoordinatorError> {
        match self {
            Self::CaptureSession => Ok(capture_time),
            Self::AwaitingContinuation { semantic_origin } => Ok(semantic_origin),
            Self::Continued { semantic_origin, capture_origin } => semantic_origin
                .checked_add(
                    capture_time
                        .checked_duration_since(capture_origin)
                        .ok_or(CoordinatorError::Incompatible)?,
                )
                .ok_or(CoordinatorError::Incompatible),
        }
    }

    const fn awaiting_continuation(self) -> bool {
        matches!(self, Self::AwaitingContinuation { .. })
    }

    fn continue_at(
        &mut self,
        capture_origin: crate::domain::time::SessionTime,
    ) -> Result<(), CoordinatorError> {
        let Self::AwaitingContinuation { semantic_origin } = *self else {
            return Err(CoordinatorError::Incompatible);
        };
        *self = Self::Continued { semantic_origin, capture_origin };
        Ok(())
    }

    fn capture_deadline(self, semantic_time: crate::domain::time::SessionTime) -> Option<Duration> {
        match self {
            Self::CaptureSession => Some(Duration::from_nanos(semantic_time.as_nanos())),
            Self::AwaitingContinuation { .. } => None,
            Self::Continued { semantic_origin, capture_origin } => semantic_time
                .checked_duration_since(semantic_origin)
                .and_then(|elapsed| capture_origin.checked_add(elapsed))
                .map(|time| Duration::from_nanos(time.as_nanos())),
        }
    }
}

#[cfg(unix)]
struct SemanticWriter {
    capture: CaptureSession,
    config: Config,
    executable_identity: crate::executable::ExecutableIdentity,
    semantic_session_id: Option<crate::SessionId>,
    coordinator: Option<RelationshipCoordinator>,
    capabilities: BTreeMap<(DeviceId, KeyEpoch, u32), crate::wire::CapabilitiesV1>,
    session_time: SessionTimeMapping,
    next_timeline_advance_ns: Option<u64>,
    #[cfg(feature = "development-fixture")]
    rebuild_evidence: Option<crate::store::EvidenceRebuildSnapshot>,
}

#[cfg(unix)]
impl SemanticWriter {
    fn new(
        mut capture: CaptureSession,
        config: Config,
        executable_identity: crate::executable::ExecutableIdentity,
        rebuilt: Option<RebuiltSession>,
    ) -> Self {
        let (
            semantic_session_id,
            coordinator,
            capabilities,
            session_time,
            next_timeline_advance_ns,
        ) = rebuilt.map_or(
            (None, None, BTreeMap::new(), SessionTimeMapping::CaptureSession, None),
            |rebuilt| {
                (
                    Some(rebuilt.semantic_id),
                    Some(rebuilt.coordinator),
                    rebuilt.capabilities,
                    SessionTimeMapping::AwaitingContinuation {
                        semantic_origin: rebuilt.last_session_time,
                    },
                    Some(rebuilt.next_timeline_advance_ns),
                )
            },
        );
        #[cfg(feature = "development-fixture")]
        let rebuild_evidence = capture.take_rebuild_evidence();
        Self {
            capture,
            config,
            executable_identity,
            semantic_session_id,
            coordinator,
            capabilities,
            session_time,
            next_timeline_advance_ns,
            #[cfg(feature = "development-fixture")]
            rebuild_evidence,
        }
    }

    fn store_id(&self) -> [u8; 32] {
        self.capture.store_id()
    }

    fn capture_session_id(&self) -> &str {
        self.capture.session_id()
    }

    fn monotonic_origin(&self) -> Instant {
        self.capture.monotonic_origin()
    }

    const fn physical_continuation_pending(&self) -> bool {
        self.session_time.awaiting_continuation()
    }

    #[cfg(feature = "development-fixture")]
    fn take_rebuild_evidence(&mut self) -> Option<crate::store::EvidenceRebuildSnapshot> {
        self.rebuild_evidence.take()
    }

    #[cfg(feature = "development-fixture")]
    fn transaction_b_audit(&self) -> Arc<Mutex<crate::store::EvidenceTransactionBAudit>> {
        self.capture.transaction_b_audit()
    }

    fn next_timeline_deadline(&self) -> Option<Instant> {
        self.next_timeline_advance_ns
            .map(crate::domain::time::SessionTime::from_nanos)
            .and_then(|at| self.session_time.capture_deadline(at))
            .and_then(|at| self.monotonic_origin().checked_add(at))
    }

    fn prepare_session(
        &self,
        started_utc_ns: i64,
    ) -> Result<Option<(PreparedSession, RelationshipCoordinator)>, HostError> {
        if self.semantic_session_id.is_some() {
            return Ok(None);
        }
        let (manifest, prepared) =
            prepare_semantic_session(&self.config, started_utc_ns, self.executable_identity)?;
        let coordinator = RelationshipCoordinator::new(&manifest, &self.config)?;
        Ok(Some((prepared, coordinator)))
    }

    fn install_prepared(&mut self, prepared: Option<(PreparedSession, RelationshipCoordinator)>) {
        if let Some((prepared, coordinator)) = prepared {
            self.semantic_session_id = Some(prepared.id().clone());
            self.coordinator = Some(coordinator);
        }
    }

    fn schedule_first_timeline_advance(
        &mut self,
        after: crate::domain::time::SessionTime,
    ) -> Result<(), HostError> {
        let step = self.config.window().step_ns();
        self.next_timeline_advance_ns = Some(
            after
                .as_nanos()
                .checked_div(step)
                .and_then(|index| index.checked_add(1))
                .and_then(|index| index.checked_mul(step))
                .ok_or(CoordinatorError::Incompatible)?,
        );
        Ok(())
    }

    fn commit_candidate(
        &mut self,
        candidate: crate::wire::WireCandidate,
    ) -> Result<CommitOutcome, HostError> {
        let continuation_pending = self.session_time.awaiting_continuation();
        let capture_session_time = candidate.session_time();
        let semantic_time = self.session_time.time_at(capture_session_time)?;
        let candidate = candidate.with_session_time(semantic_time);
        let started_utc_ns =
            i64::try_from(candidate.receive_utc_ns()).map_err(|_| HostError::CaptureClock)?;
        let prepared = self.prepare_session(started_utc_ns)?;
        let semantic_id = prepared
            .as_ref()
            .map(|(prepared, _)| prepared.id().clone())
            .or_else(|| self.semantic_session_id.clone())
            .ok_or(CoordinatorError::Incompatible)?;
        let fact = self.capture.append_packet_fact(
            &semantic_id,
            prepared.as_ref().map(|(prepared, _)| prepared),
            &candidate,
            capture_session_time,
        )?;
        if fact.replay_rejected() {
            return Ok(CommitOutcome::ReplayRejected);
        }
        let created = prepared.is_some();
        self.install_prepared(prepared);
        if created {
            self.schedule_first_timeline_advance(fact.at())?;
        }
        let processing = process_packet(
            &self.config,
            &semantic_id,
            fact.record_seq(),
            self.coordinator.as_ref().ok_or(CoordinatorError::Incompatible)?,
            &self.capabilities,
            &candidate,
        )?;
        let projection = self.capture.persist_projection(
            &fact,
            processing.kind,
            processing.observation.as_ref(),
            &processing.transition,
        )?;
        self.coordinator = Some(processing.coordinator);
        if let Some((key, capability)) = processing.capability {
            self.capabilities.insert(key, capability);
        }
        if continuation_pending {
            self.session_time.continue_at(capture_session_time)?;
            self.schedule_first_timeline_advance(fact.at())?;
        }
        Ok(CommitOutcome::Committed(crate::CommitReceipt::new(
            processing.disposition,
            fact.capture_record_seq().ok_or(CoordinatorError::Incompatible)?,
            projection,
        )))
    }

    fn commit_relationship_command(
        &mut self,
        command: TargetedBaselineCommand,
        (monotonic_now, utc_now): (Instant, SystemTime),
    ) -> Result<ProjectionSequence, HostError> {
        if self.session_time.awaiting_continuation() {
            return Err(CoordinatorError::Incompatible.into());
        }
        let now = utc_now.duration_since(UNIX_EPOCH).map_err(|_| HostError::CaptureClock)?;
        let started_utc_ns = i64::try_from(now.as_nanos()).map_err(|_| HostError::CaptureClock)?;
        let capture_time = u64::try_from(
            monotonic_now
                .checked_duration_since(self.monotonic_origin())
                .ok_or(HostError::CaptureClock)?
                .as_nanos(),
        )
        .map_err(|_| HostError::CaptureClock)?;
        let at = self
            .session_time
            .time_at(crate::domain::time::SessionTime::from_nanos(capture_time))?;
        let prepared = self.prepare_session(started_utc_ns)?;
        let semantic_id = prepared
            .as_ref()
            .map(|(prepared, _)| prepared.id().clone())
            .or_else(|| self.semantic_session_id.clone())
            .ok_or(CoordinatorError::Incompatible)?;
        let body = encode_record_body(&SessionRecordKind::BaselineCommand(command.clone()))
            .map_err(StoreError::from)?;
        let fact = self.capture.append_semantic_fact(
            &semantic_id,
            prepared.as_ref().map(|(prepared, _)| prepared),
            at,
            "baseline_command",
            &body,
        )?;
        let created = prepared.is_some();
        self.install_prepared(prepared);
        if created {
            self.schedule_first_timeline_advance(fact.at())?;
        }
        let (coordinator, transition) =
            self.coordinator.as_ref().ok_or(CoordinatorError::Incompatible)?.command(&command)?;
        let projection = self.capture.persist_projection(&fact, "semantic", None, &transition)?;
        self.coordinator = Some(coordinator);
        Ok(projection)
    }

    fn commit_timeline_advance(&mut self) -> Result<ProjectionSequence, HostError> {
        let at = crate::domain::time::SessionTime::from_nanos(
            self.next_timeline_advance_ns.ok_or(CoordinatorError::Incompatible)?,
        );
        let semantic_id = self.semantic_session_id.clone().ok_or(CoordinatorError::Incompatible)?;
        let body =
            encode_record_body(&SessionRecordKind::TimelineAdvance).map_err(StoreError::from)?;
        let fact =
            self.capture.append_semantic_fact(&semantic_id, None, at, "timeline_advance", &body)?;
        let (coordinator, transition) = self
            .coordinator
            .as_ref()
            .ok_or(CoordinatorError::Incompatible)?
            .advance(fact.record_seq(), at)?;
        let projection = self.capture.persist_projection(&fact, "semantic", None, &transition)?;
        self.coordinator = Some(coordinator);
        self.next_timeline_advance_ns = Some(
            at.as_nanos()
                .checked_add(self.config.window().step_ns())
                .ok_or(CoordinatorError::Incompatible)?,
        );
        Ok(projection)
    }

    #[cfg(feature = "ingest-test-hooks")]
    fn arm_relationship_failure(&mut self, stage: RelationshipFailureStage) {
        self.capture.arm_relationship_failure(stage);
    }
}

#[derive(Debug)]
pub(crate) struct CaptureRuntime {
    store_id: [u8; 32],
    session_id: String,
    monotonic_origin: Instant,
    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    clock: RuntimeClock,
    #[cfg(unix)]
    config: Config,
    #[cfg(unix)]
    writer_inbox: Arc<WriterInbox>,
    #[cfg(unix)]
    relationship_commands: RelationshipCommandIngress,
    #[cfg(unix)]
    writer: Option<JoinHandle<()>>,
    #[cfg(unix)]
    writer_stopped: Arc<AtomicBool>,
    #[cfg(unix)]
    rate_windows: BTreeMap<crate::domain::route::HeaderRoute, RouteRateWindow>,
    #[cfg(unix)]
    last_receive: Option<Instant>,
    #[cfg(unix)]
    queue_drop_count: u64,
    #[cfg(unix)]
    store: Store,
    #[cfg(feature = "development-fixture")]
    rebuild_evidence: Option<crate::store::EvidenceRebuildSnapshot>,
    #[cfg(feature = "development-fixture")]
    transaction_b_audit: Arc<Mutex<crate::store::EvidenceTransactionBAudit>>,
}

impl CaptureRuntime {
    #[cfg(unix)]
    fn new(
        store: Store,
        config: Config,
        mut writer_state: SemanticWriter,
        clock: RuntimeClock,
    ) -> Result<Self, HostError> {
        let store_id = writer_state.store_id();
        let session_id = writer_state.capture_session_id().to_owned();
        let monotonic_origin = writer_state.monotonic_origin();
        #[cfg(feature = "development-fixture")]
        let rebuild_evidence = writer_state.take_rebuild_evidence();
        #[cfg(feature = "development-fixture")]
        let transaction_b_audit = writer_state.transaction_b_audit();
        let capacity = usize::try_from(config.server().command_queue_capacity())
            .map_err(|_| HostError::WriterQueueCapacity)?;
        let writer_stopped = Arc::new(AtomicBool::new(false));
        let writer_panicked = Arc::new(AtomicBool::new(false));
        let physical_continuation_pending =
            Arc::new(AtomicBool::new(writer_state.physical_continuation_pending()));
        let ingress_order = Arc::new(IngressOrder::new(monotonic_origin, capacity));
        let writer_inbox = Arc::new(WriterInbox::new(
            capacity,
            Arc::clone(&writer_stopped),
            Arc::clone(&writer_panicked),
            Arc::clone(&ingress_order),
        ));
        #[cfg(feature = "ingest-test-hooks")]
        clock.attach_writer(&writer_inbox);
        let writer_inbox_for_thread = Arc::clone(&writer_inbox);
        let writer_clock = clock.clone();
        let relationship_commands = RelationshipCommandIngress {
            writer_inbox: Arc::clone(&writer_inbox),
            configured_links: config.registry().links().keys().cloned().collect(),
            next_correlation: Arc::new(AtomicU64::new(0)),
            clock: clock.clone(),
            ingress_order,
            physical_continuation_pending: Arc::clone(&physical_continuation_pending),
        };
        let writer = thread::Builder::new()
            .name("whisper-capture-writer".to_owned())
            .spawn(move || {
                writer_loop(
                    writer_state,
                    writer_inbox_for_thread,
                    writer_clock,
                    physical_continuation_pending,
                )
            })
            .map_err(HostError::WriterSpawn)?;
        Ok(Self {
            store_id,
            session_id,
            monotonic_origin,
            #[cfg(feature = "ingest-test-hooks")]
            clock,
            config,
            writer_inbox,
            relationship_commands,
            writer: Some(writer),
            writer_stopped,
            rate_windows: BTreeMap::new(),
            last_receive: None,
            queue_drop_count: 0,
            store,
            #[cfg(feature = "development-fixture")]
            rebuild_evidence,
            #[cfg(feature = "development-fixture")]
            transaction_b_audit,
        })
    }

    #[cfg(unix)]
    pub(crate) fn query_store(&self) -> Result<QueryStore, QueryError> {
        self.store.query_store()
    }

    #[cfg(feature = "development-fixture")]
    pub(crate) fn take_rebuild_evidence(
        &mut self,
    ) -> Option<crate::store::EvidenceRebuildSnapshot> {
        self.rebuild_evidence.take()
    }

    #[cfg(feature = "development-fixture")]
    pub(crate) fn transaction_b_audit(
        &self,
    ) -> Arc<Mutex<crate::store::EvidenceTransactionBAudit>> {
        Arc::clone(&self.transaction_b_audit)
    }

    pub(crate) const fn store_id(&self) -> [u8; 32] {
        self.store_id
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    #[cfg(feature = "ingest-test-hooks")]
    pub(crate) fn elapsed(&self) -> Duration {
        self.clock
            .sample()
            .0
            .checked_duration_since(self.monotonic_origin)
            .expect("runtime clock cannot precede its capture origin")
    }

    #[cfg(unix)]
    pub(crate) fn try_submit(
        &mut self,
        datagram: CapturedDatagram,
    ) -> Result<CommitTicket, HostError> {
        if self.writer_stopped.load(AtomicOrdering::Acquire) {
            return Err(HostError::WriterStopped);
        }
        let peer = datagram.peer();
        let received_monotonic = datagram.received_monotonic();
        if self.last_receive.is_some_and(|last| received_monotonic < last) {
            return Err(HostError::ReceiveOrder);
        }
        let session_time = received_monotonic
            .checked_duration_since(self.monotonic_origin)
            .ok_or(HostError::ReceiveBeforeSession)?;
        let session_time_ns =
            u64::try_from(session_time.as_nanos()).map_err(|_| HostError::CaptureTimeOverflow)?;
        let session_time = crate::domain::time::SessionTime::from_nanos(session_time_ns);
        let receive_utc_ns = datagram
            .received_utc()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HostError::CaptureClock)?;
        let receive_utc_ns =
            u64::try_from(receive_utc_ns.as_nanos()).map_err(|_| HostError::CaptureClock)?;
        let header_route = wire::select_header_route(
            peer,
            datagram.bytes(),
            self.config.capture().max_datagram_bytes(),
            self.config.registry(),
        )?;
        let key = load_epoch_key(&self.config, header_route.device(), header_route.key_epoch())?;
        let authenticated = wire::admit_datagram(
            peer,
            crate::capture::WireFormat::NativeFrameUdp,
            datagram.into_bytes(),
            self.config.capture().max_datagram_bytes(),
            self.config.registry(),
            key.as_bytes(),
        )?;
        self.rate_windows.entry(header_route).or_default().admit(
            received_monotonic,
            authenticated.bytes().len(),
            header_route,
        )?;
        self.last_receive = Some(received_monotonic);
        let candidate = authenticated.into_candidate(session_time, receive_utc_ns);
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        let pending = PendingCandidate { candidate, response: response_tx };
        match self.writer_inbox.try_push(PendingWork::Candidate(pending)) {
            Ok(()) => Ok(CommitTicket { response: response_rx }),
            Err(PushError::Full) => {
                self.queue_drop_count =
                    self.queue_drop_count.checked_add(1).ok_or(HostError::QueueDropOverflow)?;
                Err(HostError::WriterQueueFull)
            }
            Err(PushError::Stopped) => Err(HostError::WriterStopped),
        }
    }

    pub(crate) fn observe_writer(&self, observer: WriterObserver) -> Result<(), HostError> {
        self.writer_inbox.observe(observer);
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn relationship_commands(&self) -> RelationshipCommandIngress {
        self.relationship_commands.clone()
    }

    #[cfg(unix)]
    pub(crate) fn ingress_order(&self) -> Arc<IngressOrder> {
        Arc::clone(&self.writer_inbox.ingress_order)
    }

    #[cfg(unix)]
    pub(crate) fn shutdown(mut self) -> Result<(), HostError> {
        self.stop_writer()
    }

    #[cfg(unix)]
    pub(crate) const fn queue_drop_count(&self) -> u64 {
        self.queue_drop_count
    }

    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    pub(crate) fn hold_writer(&mut self) -> Result<WriterHold, HostError> {
        self.writer_inbox.hold()?;
        Ok(WriterHold { inbox: Arc::clone(&self.writer_inbox), active: true })
    }

    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    pub(crate) fn panic_writer_for_test(&self) -> Result<(), HostError> {
        self.writer_inbox.request_panic()
    }

    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    pub(crate) fn arm_relationship_failure(
        &self,
        stage: RelationshipFailureStage,
    ) -> Result<(), HostError> {
        let (response, received) = mpsc::sync_channel(1);
        self.writer_inbox
            .try_push(PendingWork::ArmRelationshipFailure { stage, response })
            .map_err(|error| match error {
                PushError::Full => HostError::WriterQueueFull,
                PushError::Stopped => HostError::WriterStopped,
            })?;
        received.recv().map_err(|_| HostError::WriterStopped)
    }

    #[cfg(unix)]
    fn stop_writer(&mut self) -> Result<(), HostError> {
        self.writer_inbox.close();
        if let Some(writer) = self.writer.take() {
            writer.join().map_err(|_| HostError::WriterPanicked)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for CaptureRuntime {
    fn drop(&mut self) {
        let _ = self.stop_writer();
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct CommitTicket {
    #[cfg_attr(
        not(feature = "ingest-test-hooks"),
        expect(
            dead_code,
            reason = "production capture drops the outcome ticket after enqueue; test support waits for it"
        )
    )]
    response: Receiver<Result<CommitOutcome, Arc<HostError>>>,
}

#[cfg(unix)]
impl CommitTicket {
    #[cfg(feature = "ingest-test-hooks")]
    pub(crate) fn wait(self) -> Result<CommitOutcome, Arc<HostError>> {
        self.response.recv().map_err(|_| HostError::WriterStopped)?
    }
}

#[cfg(unix)]
pub(crate) type WriterObserver = Arc<dyn Fn(WriterEvent) + Send + Sync>;

#[cfg(unix)]
#[derive(Clone, Debug)]
pub(crate) enum WriterEvent {
    Committed(ProjectionSequence),
    Fatal(Arc<HostError>),
    Stopped { panicked: bool },
}

#[cfg(unix)]
struct PendingCandidate {
    candidate: crate::wire::WireCandidate,
    response: SyncSender<Result<CommitOutcome, Arc<HostError>>>,
}

#[cfg(unix)]
#[derive(Clone, Debug)]
pub(crate) struct RelationshipCommandIngress {
    writer_inbox: Arc<WriterInbox>,
    configured_links: BTreeSet<RadioLinkId>,
    next_correlation: Arc<AtomicU64>,
    clock: RuntimeClock,
    ingress_order: Arc<IngressOrder>,
    physical_continuation_pending: Arc<AtomicBool>,
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum RelationshipCommandAdmissionError {
    InvalidTarget,
    ContinuationPending,
    QueueFull,
    WriterStopped,
    CorrelationOverflow,
    Clock(HostError),
}

#[cfg(unix)]
impl RelationshipCommandIngress {
    pub(crate) async fn try_command(
        &self,
        link: RadioLinkId,
        profile: CaptureProfileId,
        command: BaselineCommand,
    ) -> Result<String, RelationshipCommandAdmissionError> {
        if self.physical_continuation_pending.load(AtomicOrdering::Acquire) {
            return Err(RelationshipCommandAdmissionError::ContinuationPending);
        }
        if !self.configured_links.contains(&link) {
            return Err(RelationshipCommandAdmissionError::InvalidTarget);
        }
        let correlation = self
            .next_correlation
            .fetch_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| RelationshipCommandAdmissionError::CorrelationOverflow)?
            .checked_add(1)
            .ok_or(RelationshipCommandAdmissionError::CorrelationOverflow)?;
        let command = TargetedBaselineCommand::new(
            crate::domain::identity::LinkProfileKey::new(link, profile),
            command,
        );
        let receipt = self.ingress_order.begin(&self.clock).map_err(|error| {
            if error.is_writer_queue_full() {
                RelationshipCommandAdmissionError::QueueFull
            } else {
                RelationshipCommandAdmissionError::Clock(error)
            }
        })?;
        let reservation = receipt.reserve().await;
        let received = reservation.received();
        self.writer_inbox
            .try_push(PendingWork::RelationshipCommand { command, received })
            .map_err(|error| match error {
                PushError::Full => RelationshipCommandAdmissionError::QueueFull,
                PushError::Stopped => RelationshipCommandAdmissionError::WriterStopped,
            })?;
        drop(reservation);
        Ok(format!("relationship-command-{correlation}"))
    }
}

#[cfg(unix)]
enum PendingWork {
    Candidate(PendingCandidate),
    RelationshipCommand {
        command: TargetedBaselineCommand,
        received: (Instant, SystemTime),
    },
    #[cfg(feature = "ingest-test-hooks")]
    ArmRelationshipFailure {
        stage: RelationshipFailureStage,
        response: SyncSender<()>,
    },
}

#[cfg(unix)]
impl PendingWork {
    fn precedes_timeline_deadline(&self, deadline: Instant, capture_origin: Instant) -> bool {
        let received = match self {
            Self::Candidate(pending) => capture_origin
                .checked_add(Duration::from_nanos(pending.candidate.session_time().as_nanos())),
            Self::RelationshipCommand { received, .. } => Some(received.0),
            #[cfg(feature = "ingest-test-hooks")]
            Self::ArmRelationshipFailure { .. } => return true,
        };
        received.is_some_and(|received| received < deadline)
    }
}

#[cfg(unix)]
#[expect(
    clippy::large_enum_variant,
    reason = "the writer handoff moves one queued item and avoids a heap allocation per input"
)]
enum WriterAction {
    Work(PendingWork),
    TimelineAdvance,
    Closed,
    Fatal(HostError),
}

#[cfg(unix)]
enum PushError {
    Full,
    Stopped,
}

#[cfg(unix)]
struct WriterInbox {
    capacity: usize,
    state: Mutex<WriterInboxState>,
    changed: Condvar,
    stopped: Arc<AtomicBool>,
    panicked: Arc<AtomicBool>,
    ingress_order: Arc<IngressOrder>,
}

#[cfg(unix)]
impl std::fmt::Debug for WriterInbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WriterInbox")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
#[derive(Default)]
struct WriterInboxState {
    work: VecDeque<PendingWork>,
    observer: Option<WriterObserver>,
    closed: bool,
    #[cfg(feature = "ingest-test-hooks")]
    hold_requested: bool,
    #[cfg(feature = "ingest-test-hooks")]
    held: bool,
    #[cfg(feature = "ingest-test-hooks")]
    panic_requested: bool,
}

#[cfg(unix)]
impl WriterInbox {
    fn new(
        capacity: usize,
        stopped: Arc<AtomicBool>,
        panicked: Arc<AtomicBool>,
        ingress_order: Arc<IngressOrder>,
    ) -> Self {
        Self {
            capacity,
            state: Mutex::new(WriterInboxState::default()),
            changed: Condvar::new(),
            stopped,
            panicked,
            ingress_order,
        }
    }

    fn try_push(&self, work: PendingWork) -> Result<(), PushError> {
        if self.stopped.load(AtomicOrdering::Acquire) {
            return Err(PushError::Stopped);
        }
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return Err(PushError::Stopped);
        }
        if state.work.len() >= self.capacity {
            return Err(PushError::Full);
        }
        state.work.push_back(work);
        drop(state);
        self.changed.notify_one();
        Ok(())
    }

    #[cfg(feature = "ingest-test-hooks")]
    fn wake(&self) {
        self.changed.notify_all();
    }

    fn next(
        &self,
        timeline_deadline: Option<Instant>,
        capture_origin: Instant,
        clock: &RuntimeClock,
    ) -> WriterAction {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            #[cfg(feature = "ingest-test-hooks")]
            if state.panic_requested {
                panic!("test-only writer panic requested through the guarded test seam");
            }
            #[cfg(feature = "ingest-test-hooks")]
            if state.hold_requested {
                state.held = true;
                self.changed.notify_all();
                state = self
                    .changed
                    .wait_while(state, |state| state.hold_requested && !state.closed)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.held = false;
                continue;
            }
            if state.closed {
                return state.work.pop_front().map_or(WriterAction::Closed, WriterAction::Work);
            }
            if let Some(deadline) = timeline_deadline
                && clock.sample().0 >= deadline
            {
                drop(state);
                let _boundary = match self.ingress_order.hold_boundary(deadline) {
                    Ok(boundary) => boundary,
                    Err(error) => return WriterAction::Fatal(error),
                };
                state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                #[cfg(feature = "ingest-test-hooks")]
                if state.panic_requested || state.hold_requested {
                    continue;
                }
                if state.closed {
                    return state.work.pop_front().map_or(WriterAction::Closed, WriterAction::Work);
                }
                if state
                    .work
                    .front()
                    .is_some_and(|work| work.precedes_timeline_deadline(deadline, capture_origin))
                {
                    return WriterAction::Work(
                        state.work.pop_front().expect("the checked writer work item must exist"),
                    );
                }
                return WriterAction::TimelineAdvance;
            }
            if let Some(work) = state.work.pop_front() {
                return WriterAction::Work(work);
            }
            state = if let Some(deadline) = timeline_deadline {
                let timeout = deadline.saturating_duration_since(clock.sample().0);
                self.changed
                    .wait_timeout(state, timeout)
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .0
            } else {
                self.changed.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner())
            };
        }
    }

    fn observe(&self, observer: WriterObserver) {
        let (stopped, panicked) = {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            state.observer = Some(Arc::clone(&observer));
            (
                self.stopped.load(AtomicOrdering::Acquire),
                self.panicked.load(AtomicOrdering::Acquire),
            )
        };
        if stopped {
            observer(WriterEvent::Stopped { panicked });
        }
    }

    fn notify(&self, event: WriterEvent) {
        let observer =
            self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).observer.clone();
        if let Some(observer) = observer {
            observer(event);
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        #[cfg(feature = "ingest-test-hooks")]
        {
            state.hold_requested = false;
        }
        drop(state);
        self.changed.notify_all();
    }

    #[cfg(feature = "ingest-test-hooks")]
    fn hold(&self) -> Result<(), HostError> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed || self.stopped.load(AtomicOrdering::Acquire) {
            return Err(HostError::WriterStopped);
        }
        state.hold_requested = true;
        self.changed.notify_all();
        state = self
            .changed
            .wait_while(state, |state| {
                !state.held && !state.closed && !self.stopped.load(AtomicOrdering::Acquire)
            })
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.held { Ok(()) } else { Err(HostError::WriterStopped) }
    }

    #[cfg(feature = "ingest-test-hooks")]
    fn release_hold(&self) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.hold_requested = false;
        drop(state);
        self.changed.notify_all();
    }

    #[cfg(feature = "ingest-test-hooks")]
    fn request_panic(&self) -> Result<(), HostError> {
        if self.stopped.load(AtomicOrdering::Acquire) {
            return Err(HostError::WriterStopped);
        }
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return Err(HostError::WriterStopped);
        }
        state.panic_requested = true;
        drop(state);
        self.changed.notify_all();
        Ok(())
    }
}

#[cfg(all(unix, feature = "ingest-test-hooks"))]
#[derive(Debug)]
pub(crate) struct WriterHold {
    inbox: Arc<WriterInbox>,
    active: bool,
}

#[cfg(all(unix, feature = "ingest-test-hooks"))]
impl Drop for WriterHold {
    fn drop(&mut self) {
        if self.active {
            self.inbox.release_hold();
            self.active = false;
        }
    }
}

#[cfg(unix)]
fn writer_loop(
    mut writer: SemanticWriter,
    inbox: Arc<WriterInbox>,
    clock: RuntimeClock,
    physical_continuation_pending: Arc<AtomicBool>,
) {
    let _stopped = WriterStoppedGuard(Arc::clone(&inbox));
    loop {
        match inbox.next(writer.next_timeline_deadline(), writer.monotonic_origin(), &clock) {
            WriterAction::Closed => break,
            WriterAction::Fatal(error) => {
                inbox.stopped.store(true, AtomicOrdering::Release);
                inbox.notify(WriterEvent::Fatal(Arc::new(error)));
                break;
            }
            WriterAction::TimelineAdvance => match writer.commit_timeline_advance() {
                Ok(projection) => inbox.notify(WriterEvent::Committed(projection)),
                Err(error) => {
                    inbox.stopped.store(true, AtomicOrdering::Release);
                    inbox.notify(WriterEvent::Fatal(Arc::new(error)));
                    break;
                }
            },
            WriterAction::Work(work) => match work {
                PendingWork::Candidate(PendingCandidate { candidate, response }) => {
                    let outcome = writer.commit_candidate(candidate);
                    match outcome {
                        Ok(outcome) => {
                            let _ = response.send(Ok(outcome));
                            if let CommitOutcome::Committed(receipt) = outcome {
                                physical_continuation_pending.store(false, AtomicOrdering::Release);
                                inbox.notify(WriterEvent::Committed(receipt.projection_sequence()));
                            }
                        }
                        Err(error) => {
                            inbox.stopped.store(true, AtomicOrdering::Release);
                            let error = Arc::new(error);
                            let _ = response.send(Err(Arc::clone(&error)));
                            inbox.notify(WriterEvent::Fatal(error));
                            break;
                        }
                    }
                }
                PendingWork::RelationshipCommand { command, received } => {
                    match writer.commit_relationship_command(command, received) {
                        Ok(projection) => inbox.notify(WriterEvent::Committed(projection)),
                        Err(error) => {
                            inbox.stopped.store(true, AtomicOrdering::Release);
                            inbox.notify(WriterEvent::Fatal(Arc::new(error)));
                            break;
                        }
                    }
                }
                #[cfg(feature = "ingest-test-hooks")]
                PendingWork::ArmRelationshipFailure { stage, response } => {
                    writer.arm_relationship_failure(stage);
                    let _ = response.send(());
                }
            },
        }
    }
}

#[cfg(unix)]
struct WriterStoppedGuard(Arc<WriterInbox>);

#[cfg(unix)]
impl Drop for WriterStoppedGuard {
    fn drop(&mut self) {
        let panicked = std::thread::panicking();
        let observer = {
            let state = self.0.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            self.0.panicked.store(panicked, AtomicOrdering::Release);
            self.0.stopped.store(true, AtomicOrdering::Release);
            state.observer.clone()
        };
        self.0.changed.notify_all();
        if panicked && let Some(observer) = observer {
            observer(WriterEvent::Stopped { panicked: true });
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct RouteRateWindow {
    entries: VecDeque<(Instant, u64)>,
    authenticated_bytes: u64,
}

#[cfg(unix)]
impl RouteRateWindow {
    fn admit(
        &mut self,
        received: Instant,
        bytes: usize,
        route: crate::domain::route::HeaderRoute,
    ) -> Result<(), HostError> {
        while self.entries.front().is_some_and(|(at, _)| {
            received.checked_duration_since(*at).is_some_and(|age| age >= Duration::from_secs(1))
        }) {
            let (_, expired) = self.entries.pop_front().ok_or(HostError::RateStateCorrupt)?;
            self.authenticated_bytes =
                self.authenticated_bytes.checked_sub(expired).ok_or(HostError::RateStateCorrupt)?;
        }
        let bytes = u64::try_from(bytes).map_err(|_| HostError::RateOverflow)?;
        let next_bytes =
            self.authenticated_bytes.checked_add(bytes).ok_or(HostError::RateOverflow)?;
        let limits = route.admission_limits();
        if self.entries.len() >= limits.peak_packets_per_second() as usize
            || next_bytes > limits.maximum_authenticated_bytes_per_second()
        {
            return Err(HostError::RateLimited);
        }
        self.entries.push_back((received, bytes));
        self.authenticated_bytes = next_bytes;
        Ok(())
    }
}

impl HostError {
    pub(crate) const fn is_lease_conflict(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Self::Store(error) if error.is_lease_conflict())
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    #[cfg(feature = "ingest-test-hooks")]
    pub(crate) const fn is_rate_limited(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Self::RateLimited)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    pub(crate) const fn is_writer_queue_full(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Self::WriterQueueFull)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    pub(crate) const fn is_writer_stopped(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Self::WriterStopped)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

#[cfg(unix)]
pub(crate) fn init_admission(config: &Config) -> Result<(), HostError> {
    let store = Store::acquire_for_initialization(config)?;
    let admissions = admission_seeds(config)?;
    store.initialize(config, admissions).map_err(Into::into)
}

#[cfg(not(unix))]
pub(crate) fn init_admission(_config: &Config) -> Result<(), HostError> {
    Err(HostError::UnsupportedManagedStorePlatform)
}

#[cfg(unix)]
pub(crate) fn serve(config: &Config) -> Result<CaptureRuntime, HostError> {
    serve_with_clock(config, RuntimeClock::system())
}

#[cfg(unix)]
pub(crate) fn serve_with_clock(
    config: &Config,
    clock: RuntimeClock,
) -> Result<CaptureRuntime, HostError> {
    let executable_identity = crate::executable::ExecutableIdentity::running()?;
    let store = Store::acquire_existing(config)?;
    let admissions = admission_seeds(config)?;
    let mut recovery = store.recover_capture(config, admissions.clone(), executable_identity)?;
    let rebuilt =
        recovery.take_input().map(|input| rebuild_relationship(config, input)).transpose()?;
    let recovered = recovery.finish(rebuilt.as_ref())?;
    let capture = store.create_capture_session(config, admissions, || clock.sample(), recovered)?;
    let writer = SemanticWriter::new(capture, config.clone(), executable_identity, rebuilt);
    CaptureRuntime::new(store, config.clone(), writer, clock)
}

#[cfg(not(unix))]
pub(crate) fn serve(_config: &Config) -> Result<CaptureRuntime, HostError> {
    Err(HostError::UnsupportedManagedStorePlatform)
}

#[cfg(unix)]
fn admission_seeds(config: &Config) -> Result<Vec<AdmissionEpochSeed>, HostError> {
    let mut identities = BTreeSet::new();
    let mut admissions = Vec::with_capacity(config.registry().routes().len());
    for route in config.registry().routes() {
        let device = route.device_id();
        let key_epoch = route.key_epoch();
        if !identities.insert((device, key_epoch)) {
            return Err(HostError::AmbiguousAdmissionRoute { device, key_epoch });
        }
        let (_, replay_window_size) = replay_admission_config(config, device, key_epoch)?;
        let epoch_key = load_epoch_key(config, device, key_epoch)?;
        let identity =
            replay_window_identity(config.deployment().id(), device, key_epoch, &epoch_key)?;
        admissions.push(AdmissionEpochSeed {
            device,
            key_epoch,
            replay_window_identity: identity,
            replay_window_size,
            epoch_key: Arc::new(epoch_key),
        });
    }
    admissions.sort_by_key(|admission| (admission.device, admission.key_epoch));
    Ok(admissions)
}

pub(crate) fn open_capture_database(config: &Config) -> Result<Database, HostError> {
    Ok(Database::open_writer_existing(config.session().database_path())?)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(unix)]
    use std::time::Duration;

    use rusqlite::Connection;

    use super::{
        EpochKey, HostError, ManagedDatabaseLock, ManagedTarget, ReplayWindowIdentity,
        checked_deployment_length, open_capture_database, provision_admission_epoch,
        replay_admission_config, replay_window_identity, replay_window_identity_preimage,
        select_replay_admission_route, validate_capture_epoch,
    };
    #[cfg(unix)]
    use super::{IngressOrder, RuntimeClock};
    use crate::database::{Database, DatabaseError};
    use crate::domain::identity::{DeploymentId, DeviceId, KeyEpoch};
    use crate::{Config, parse_config};

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn ingress_reservation_waits_without_blocking_and_releases_after_cancellation() {
        let clock = RuntimeClock::system();
        let capture_origin = clock.sample().0;
        let order = Arc::new(IngressOrder::new(capture_origin, 2));
        let first = order.begin(&clock).expect("first receipt").reserve().await;

        let cancelled = tokio::spawn({
            let order = Arc::clone(&order);
            let clock = clock.clone();
            async move { order.begin(&clock).expect("cancelled receipt").reserve().await }
        });
        tokio::task::yield_now().await;
        assert!(!cancelled.is_finished());
        cancelled.abort();
        assert!(cancelled.await.expect_err("cancelled reservation waiter").is_cancelled());

        let waiting = tokio::spawn({
            let order = Arc::clone(&order);
            let clock = clock.clone();
            async move { order.begin(&clock).expect("waiting receipt").reserve().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(first);

        let second = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("next reservation must not block the executor")
            .expect("reservation task");
        drop(second);
    }

    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    #[tokio::test(flavor = "current_thread")]
    async fn ingress_receipt_keeps_the_sample_taken_before_waiting() {
        let (clock, control) = RuntimeClock::manual();
        let capture_origin = clock.sample().0;
        let order = Arc::new(IngressOrder::new(capture_origin, 2));
        let first = order.begin(&clock).expect("first receipt").reserve().await;

        assert!(control.advance(Duration::from_secs(1)));
        let waiting = order.begin(&clock).expect("queued receipt");
        assert!(control.advance(Duration::from_secs(1)));
        drop(first);

        let reservation = waiting.reserve().await;
        assert_eq!(
            reservation
                .received()
                .0
                .checked_duration_since(capture_origin)
                .expect("receipt follows capture origin"),
            Duration::from_secs(1)
        );
    }

    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    #[tokio::test(flavor = "current_thread")]
    async fn ingress_reserves_by_sample_time_when_registration_order_inverts() {
        let (clock, control) = RuntimeClock::manual();
        let capture_origin = clock.sample().0;
        let order = Arc::new(IngressOrder::new(capture_origin, 2));
        let state = order.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);

        let earlier_thread = std::thread::spawn({
            let order = Arc::clone(&order);
            let clock = clock.clone();
            let sender = sender.clone();
            move || sender.send((true, order.begin(&clock))).expect("return earlier receipt")
        });
        while control.state.sample_count.load(Ordering::Acquire) != 2 {
            std::thread::yield_now();
        }
        assert!(control.advance(Duration::from_secs(1)));
        let later_thread = std::thread::spawn({
            let order = Arc::clone(&order);
            let clock = clock.clone();
            move || sender.send((false, order.begin(&clock))).expect("return later receipt")
        });
        while control.state.sample_count.load(Ordering::Acquire) != 3 {
            std::thread::yield_now();
        }
        drop(state);

        let mut earlier = None;
        let mut later = None;
        for _ in 0..2 {
            let (is_earlier, receipt) = receiver.recv().expect("receive ingress receipt");
            let receipt = receipt.expect("register ingress receipt");
            if is_earlier {
                earlier = Some(receipt);
            } else {
                later = Some(receipt);
            }
        }
        earlier_thread.join().expect("join earlier sampler");
        later_thread.join().expect("join later sampler");

        let first = earlier.expect("earlier receipt").reserve().await;
        let mut later = tokio::spawn(later.expect("later receipt").reserve());
        assert!(tokio::time::timeout(Duration::from_millis(25), &mut later).await.is_err());
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(1), later)
            .await
            .expect("later receipt must become reservable")
            .expect("later reservation task");
        assert_eq!(
            second
                .received()
                .0
                .checked_duration_since(capture_origin)
                .expect("later receipt follows capture origin"),
            Duration::from_secs(1)
        );
    }

    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    #[test]
    fn ingress_does_not_double_count_a_published_sampler() {
        let (clock, control) = RuntimeClock::manual();
        let capture_origin = clock.sample().0;
        let order = Arc::new(IngressOrder::new(capture_origin, 2));
        let hold = order.hold_next_registration_transition();
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);

        let first_thread = std::thread::spawn({
            let order = Arc::clone(&order);
            let clock = clock.clone();
            let sender = sender.clone();
            move || sender.send(order.begin(&clock)).expect("return first receipt")
        });
        hold.arrived.wait();
        assert!(control.advance(Duration::from_secs(1)));
        let second_thread = std::thread::spawn({
            let order = Arc::clone(&order);
            let clock = clock.clone();
            move || sender.send(order.begin(&clock)).expect("return second receipt")
        });
        while control.state.sample_count.load(Ordering::Acquire) != 3 {
            std::thread::yield_now();
        }
        hold.release.wait();

        let receipts =
            (0..2).map(|_| receiver.recv().expect("receive ingress receipt")).collect::<Vec<_>>();
        first_thread.join().expect("join first sampler");
        second_thread.join().expect("join second sampler");
        assert!(receipts.iter().all(Result::is_ok));
    }

    #[cfg(all(unix, feature = "ingest-test-hooks"))]
    #[tokio::test(flavor = "current_thread")]
    async fn ingress_boundary_waits_only_for_reservations_before_the_deadline() {
        let (clock, control) = RuntimeClock::manual();
        let capture_origin = clock.sample().0;
        let deadline = capture_origin.checked_add(Duration::from_secs(1)).expect("deadline");
        let order = Arc::new(IngressOrder::new(capture_origin, 2));

        let before = order.begin(&clock).expect("pre-deadline receipt").reserve().await;
        let mut waiting = tokio::task::spawn_blocking({
            let order = Arc::clone(&order);
            move || drop(order.hold_boundary(deadline).expect("pre-deadline boundary"))
        });
        assert!(tokio::time::timeout(Duration::from_millis(25), &mut waiting).await.is_err());
        drop(before);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("boundary must follow the released reservation")
            .expect("boundary task");

        assert!(control.advance(Duration::from_secs(1)));
        let at_deadline = order.begin(&clock).expect("at-deadline receipt").reserve().await;
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::task::spawn_blocking({
                let order = Arc::clone(&order);
                move || drop(order.hold_boundary(deadline).expect("at-deadline boundary"))
            }),
        )
        .await
        .expect("boundary must not wait for an at-deadline reservation")
        .expect("boundary task");
        drop(at_deadline);
    }

    fn database_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-application-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config_with_database_path(path: &Path) -> Config {
        let source = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
        parse_config(&source.replace(
            "database_path = \"./data/whisper.sqlite3\"",
            &format!("database_path = \"{}\"", path.display()),
        ))
        .expect("config with temporary database path")
    }

    #[cfg(unix)]
    fn config_with_database_and_secret_root(database: &Path, secret_root: &Path) -> Config {
        let source = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
        parse_config(
            &source
                .replace(
                    "database_path = \"./data/whisper.sqlite3\"",
                    &format!("database_path = \"{}\"", database.display()),
                )
                .replace(
                    "secret_root = \"./data/secrets\"",
                    &format!("secret_root = \"{}\"", secret_root.display()),
                ),
        )
        .expect("config with temporary database and secret root")
    }

    #[cfg(unix)]
    fn relative_to_current(path: &Path) -> PathBuf {
        let current = std::env::current_dir().expect("current directory");
        let common = current
            .components()
            .zip(path.components())
            .take_while(|(left, right)| left == right)
            .count();
        let mut relative = PathBuf::new();
        relative.extend(current.components().skip(common).map(|_| ".."));
        relative.extend(path.components().skip(common));
        relative
    }

    #[cfg(unix)]
    #[test]
    fn existing_database_spellings_share_one_canonical_lock_identity() {
        use std::os::unix::fs::symlink;

        let root = database_path().with_extension("paths");
        let real_directory = root.join("real");
        let database = real_directory.join("whisper.sqlite3");
        std::fs::create_dir_all(&real_directory).expect("create real directory");
        std::fs::write(&database, b"database identity").expect("create database target");

        let directory_alias = root.join("directory-alias");
        symlink(&real_directory, &directory_alias).expect("create directory symlink");
        let final_alias = root.join("database-alias");
        symlink(&database, &final_alias).expect("create final symlink");
        let spellings = [
            real_directory.join("nested").join("..").join("whisper.sqlite3"),
            directory_alias.join("whisper.sqlite3"),
            final_alias,
        ];
        std::fs::create_dir(real_directory.join("nested")).expect("create nested directory");

        let relative = relative_to_current(&database);
        let owner = ManagedDatabaseLock::acquire(
            &config_with_database_path(&relative),
            ManagedTarget::Existing,
        )
        .expect("acquire canonical owner");
        assert_eq!(
            owner.database_path(),
            std::fs::canonicalize(&database).expect("canonical database")
        );

        for spelling in spellings {
            assert!(matches!(
                ManagedDatabaseLock::acquire(
                    &config_with_database_path(&spelling),
                    ManagedTarget::Existing,
                ),
                Err(HostError::ManagedDatabaseLockConflict { .. })
            ));
        }

        drop(owner);
        std::fs::remove_dir_all(root).expect("cleanup path fixtures");
    }

    #[cfg(unix)]
    #[test]
    fn provisioning_requires_an_existing_parent_and_absent_non_symlink_target() {
        use std::os::unix::fs::symlink;

        let root = database_path().with_extension("provisioning");
        std::fs::create_dir(&root).expect("create provisioning parent");
        let canonical_root = std::fs::canonicalize(&root).expect("canonical parent");

        let available = root.join("new.sqlite3");
        let lock = ManagedDatabaseLock::acquire(
            &config_with_database_path(&available),
            ManagedTarget::Provisioning,
        )
        .expect("lock absent provisioning target");
        assert_eq!(lock.database_path(), canonical_root.join("new.sqlite3"));
        assert!(!available.exists());
        drop(lock);

        let existing = root.join("existing.sqlite3");
        std::fs::write(&existing, b"existing").expect("create existing target");
        assert!(matches!(
            ManagedDatabaseLock::acquire(
                &config_with_database_path(&existing),
                ManagedTarget::Provisioning,
            ),
            Err(HostError::ManagedDatabaseAlreadyExists { .. })
        ));

        let final_symlink = root.join("final-symlink.sqlite3");
        symlink(&existing, &final_symlink).expect("create final symlink");
        let dangling_symlink = root.join("dangling-symlink.sqlite3");
        symlink(root.join("absent.sqlite3"), &dangling_symlink).expect("create dangling symlink");
        for path in [&final_symlink, &dangling_symlink] {
            assert!(matches!(
                ManagedDatabaseLock::acquire(
                    &config_with_database_path(path),
                    ManagedTarget::Provisioning,
                ),
                Err(HostError::ManagedDatabaseSymlink { .. })
            ));
        }

        let missing_parent = root.join("missing").join("database.sqlite3");
        assert!(matches!(
            ManagedDatabaseLock::acquire(
                &config_with_database_path(&missing_parent),
                ManagedTarget::Provisioning,
            ),
            Err(HostError::ManagedDatabasePathIo { .. })
        ));

        std::fs::remove_dir_all(root).expect("cleanup provisioning fixtures");
    }

    #[test]
    fn managed_lock_sidecar_names_are_injective() {
        let root = database_path().with_extension("injective");
        std::fs::create_dir(&root).expect("create injective fixture directory");
        let first_path = root.join("foo");
        let second_path = root.join("foo.whisper.lock");
        std::fs::write(&first_path, b"first database").expect("create first database");
        std::fs::write(&second_path, b"second database").expect("create second database");

        let first = ManagedDatabaseLock::acquire(
            &config_with_database_path(&first_path),
            ManagedTarget::Existing,
        )
        .expect("lock first database");
        let second = ManagedDatabaseLock::acquire(
            &config_with_database_path(&second_path),
            ManagedTarget::Existing,
        )
        .expect("lock suffix-named database independently");
        assert!(matches!(
            ManagedDatabaseLock::acquire(
                &config_with_database_path(&first_path),
                ManagedTarget::Existing,
            ),
            Err(HostError::ManagedDatabaseLockConflict { .. })
        ));
        assert!(matches!(
            ManagedDatabaseLock::acquire(
                &config_with_database_path(&second_path),
                ManagedTarget::Existing,
            ),
            Err(HostError::ManagedDatabaseLockConflict { .. })
        ));

        drop((first, second));
        std::fs::remove_dir_all(root).expect("cleanup injective fixtures");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn existing_database_hard_links_are_rejected_explicitly() {
        let root = database_path().with_extension("hard-links");
        std::fs::create_dir(&root).expect("create hard-link fixture directory");
        let database = root.join("database.sqlite3");
        let alias = root.join("alias.sqlite3");
        std::fs::write(&database, b"database").expect("create database");
        std::fs::hard_link(&database, &alias).expect("create hard link");

        for path in [&database, &alias] {
            assert!(matches!(
                ManagedDatabaseLock::acquire(
                    &config_with_database_path(path),
                    ManagedTarget::Existing,
                ),
                Err(HostError::ManagedDatabaseHardLinked { links: 2, .. })
            ));
        }

        std::fs::remove_dir_all(root).expect("cleanup hard-link fixtures");
    }

    #[test]
    fn stale_sidecar_content_is_preserved_and_dropped_locks_are_reusable() {
        let root = database_path().with_extension("stale-sidecar");
        std::fs::create_dir(&root).expect("create stale-sidecar fixture directory");
        let database = root.join("database.sqlite3");
        let sidecar = root.join("database.sqlite3.whisper.lock");
        let stale = b"stale sidecar content must survive";
        std::fs::write(&database, b"database").expect("create database");
        std::fs::write(&sidecar, stale).expect("create stale sidecar");
        let config = config_with_database_path(&database);

        let first = ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing)
            .expect("lock through stale sidecar");
        assert_eq!(std::fs::read(&sidecar).expect("read held sidecar"), stale);
        assert!(matches!(
            ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing),
            Err(HostError::ManagedDatabaseLockConflict { .. })
        ));
        drop(first);

        drop(
            ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing)
                .expect("reuse dropped lock"),
        );
        assert_eq!(std::fs::read(&sidecar).expect("read reused sidecar"), stale);
        assert!(sidecar.exists());

        std::fs::remove_dir_all(root).expect("cleanup stale-sidecar fixtures");
    }

    #[cfg(unix)]
    #[test]
    fn managed_database_permission_failures_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let root = database_path().with_extension("permissions");
        let blocked = root.join("blocked");
        std::fs::create_dir_all(&blocked).expect("create permission fixture directory");
        let inaccessible_database = blocked.join("database.sqlite3");
        std::fs::write(&inaccessible_database, b"database").expect("create inaccessible database");

        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))
            .expect("remove path permissions");
        let path_error = ManagedDatabaseLock::acquire(
            &config_with_database_path(&inaccessible_database),
            ManagedTarget::Existing,
        )
        .expect_err("inaccessible database path must fail");
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700))
            .expect("restore path permissions");
        assert!(matches!(
            path_error,
            HostError::ManagedDatabasePathIo { source, .. }
                if source.kind() == std::io::ErrorKind::PermissionDenied
        ));

        let unwritable_database = root.join("unwritable.sqlite3");
        std::fs::write(&unwritable_database, b"database").expect("create unwritable database");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500))
            .expect("remove directory write permission");
        let lock_error = ManagedDatabaseLock::acquire(
            &config_with_database_path(&unwritable_database),
            ManagedTarget::Existing,
        )
        .expect_err("unwritable sidecar directory must fail");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("restore directory permissions");
        assert!(matches!(
            lock_error,
            HostError::ManagedDatabaseLockIo { source, .. }
                if source.kind() == std::io::ErrorKind::PermissionDenied
        ));

        std::fs::remove_dir_all(root).expect("cleanup permission fixtures");
    }

    #[test]
    fn managed_database_lock_conflicts_across_processes_and_reuses_after_release() {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};

        let root = database_path().with_extension("cross-process");
        std::fs::create_dir(&root).expect("create cross-process fixture directory");
        let database = root.join("database.sqlite3");
        std::fs::write(&database, b"database").expect("create database");
        let config = config_with_database_path(&database);

        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--ignored",
                "--exact",
                "application::tests::managed_database_lock_child_process",
                "--nocapture",
            ])
            .env("WHISPER_MANAGED_LOCK_CHILD_PATH", &database)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn lock child");
        let mut child_stdout =
            BufReader::new(child.stdout.take().expect("capture lock child stdout"));
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = child_stdout.read_line(&mut line).expect("read lock child output");
            assert_ne!(bytes, 0, "lock child exited before acquiring the lock");
            if line.contains("WHISPER_MANAGED_LOCK_ACQUIRED") {
                break;
            }
        }

        assert!(matches!(
            ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing),
            Err(HostError::ManagedDatabaseLockConflict { .. })
        ));
        child
            .stdin
            .as_mut()
            .expect("lock child stdin")
            .write_all(b"release\n")
            .expect("release lock child");
        assert!(child.wait().expect("wait for lock child").success());

        drop(
            ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing)
                .expect("reuse child lock after release"),
        );
        std::fs::remove_dir_all(root).expect("cleanup cross-process fixtures");
    }

    #[test]
    #[ignore = "invoked as an exact child process by the cross-process lock test"]
    fn managed_database_lock_child_process() {
        use std::io::{Read, Write};

        let Some(path) = std::env::var_os("WHISPER_MANAGED_LOCK_CHILD_PATH") else {
            return;
        };
        let config = config_with_database_path(Path::new(&path));
        let lock = ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing)
            .expect("child acquires managed database lock");
        println!("WHISPER_MANAGED_LOCK_ACQUIRED");
        std::io::stdout().flush().expect("flush lock child readiness");
        let mut release = [0_u8; 1];
        std::io::stdin().read_exact(&mut release).expect("wait for parent release signal");
        drop(lock);
    }

    fn vector_value(name: &str) -> &'static str {
        include_str!("../tests/fixtures/replay-window-identity/vector-v1.txt")
            .lines()
            .find_map(|line| line.strip_prefix(name).and_then(|value| value.strip_prefix('=')))
            .expect("fixture field")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    fn epoch_key(name: &str) -> EpochKey {
        EpochKey::from_test_bytes(
            decode_hex(vector_value(name)).try_into().expect("32-byte epoch key"),
        )
    }

    fn fixture_identity(name: &str) -> ReplayWindowIdentity {
        ReplayWindowIdentity::new(
            decode_hex(vector_value(name)).try_into().expect("32-byte replay identity"),
        )
    }

    fn config_identity(
        config: &Config,
        device: DeviceId,
        key_epoch: KeyEpoch,
        epoch_key: &EpochKey,
    ) -> ReplayWindowIdentity {
        let (deployment, _) =
            replay_admission_config(config, device, key_epoch).expect("matching route");
        replay_window_identity(deployment, device, key_epoch, epoch_key).expect("identity")
    }

    fn replace_first_setting(source: &str, name: &str, from: &str, to: &str) -> String {
        let from = format!("{name} = {from}");
        let to = format!("{name} = {to}");
        assert!(source.contains(&from), "missing fixture setting: {from}");
        source.replacen(&from, &to, 1)
    }

    #[test]
    fn epoch_key_debug_redacts_secret_bytes() {
        let debug = format!("{:?}", EpochKey::from_test_bytes([0xa5; 32]));

        assert_eq!(debug, "EpochKey([REDACTED])");
        assert!(!debug.contains("a5"));
    }

    #[test]
    fn replay_window_identity_rejects_deployment_lengths_above_u32() {
        let length = u32::MAX as usize + 1;

        assert!(matches!(
            checked_deployment_length(length),
            Err(HostError::DeploymentIdTooLong { length: actual }) if actual == length
        ));
    }

    #[test]
    fn replay_window_identity_matches_the_canonical_v1_vector() {
        let deployment = DeploymentId::new(vector_value("deployment_id")).expect("deployment");
        let device = DeviceId::new(vector_value("device_id").parse().expect("device"));
        let key_epoch = KeyEpoch::try_new(vector_value("key_epoch").parse().expect("key epoch"))
            .expect("nonzero key epoch");
        let epoch_key = epoch_key("epoch_key_hex");
        let config_source = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
        let config = parse_config(config_source).expect("valid config");
        let (configured_deployment, configured_window) =
            replay_admission_config(&config, device, key_epoch).expect("fixture route");
        let raw: toml::Value = toml::from_str(config_source).expect("fixture TOML");
        let route = &raw["routes"].as_array().expect("routes")[0];

        assert_eq!(configured_deployment, &deployment);
        assert_eq!(configured_window.to_string(), vector_value("replay_window_packets"));
        assert_eq!(route["peer"].as_str().expect("peer"), vector_value("peer"));
        assert_eq!(route["link"].as_str().expect("link"), vector_value("link_id"));
        assert_eq!(
            route["peak_packets_per_second"].as_integer().expect("packet rate").to_string(),
            vector_value("peak_packets_per_second")
        );
        assert_eq!(
            route["maximum_authenticated_bytes_per_second"]
                .as_integer()
                .expect("byte rate")
                .to_string(),
            vector_value("maximum_authenticated_bytes_per_second")
        );
        assert_eq!(
            route["maximum_valid_datagram_bytes"].as_integer().expect("datagram limit").to_string(),
            vector_value("maximum_valid_datagram_bytes")
        );

        assert_eq!(
            replay_window_identity_preimage(&deployment, device, key_epoch, &epoch_key)
                .expect("preimage"),
            decode_hex(vector_value("preimage_hex"))
        );
        assert_eq!(
            replay_window_identity(&deployment, device, key_epoch, &epoch_key).expect("identity"),
            fixture_identity("identity_sha256")
        );
    }

    #[test]
    fn included_epoch_key_mutation_changes_the_replay_window_identity() {
        let deployment = DeploymentId::new(vector_value("deployment_id")).expect("deployment");
        let device = DeviceId::new(vector_value("device_id").parse().expect("device"));
        let key_epoch = KeyEpoch::try_new(vector_value("key_epoch").parse().expect("key epoch"))
            .expect("nonzero key epoch");
        let canonical =
            replay_window_identity(&deployment, device, key_epoch, &epoch_key("epoch_key_hex"))
                .expect("canonical identity");
        let mutated = replay_window_identity(
            &deployment,
            device,
            key_epoch,
            &epoch_key("included_epoch_key_hex"),
        )
        .expect("mutated identity");

        assert_eq!(canonical, fixture_identity("identity_sha256"));
        assert_eq!(mutated, fixture_identity("included_identity_sha256"));
        assert_ne!(mutated, canonical);
    }

    #[test]
    fn excluded_route_mutations_do_not_change_the_replay_window_identity() {
        let source = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
        let device = DeviceId::new(vector_value("device_id").parse().expect("device"));
        let key_epoch = KeyEpoch::try_new(vector_value("key_epoch").parse().expect("key epoch"))
            .expect("nonzero key epoch");
        let epoch_key = epoch_key("epoch_key_hex");
        let canonical = fixture_identity("identity_sha256");
        let peer_source = source.replace(vector_value("peer"), vector_value("mutated_peer"));
        let link_source = source.replace(vector_value("link_id"), vector_value("mutated_link_id"));
        let numeric_mutations = [
            ("replay_window_packets", "replay_window_packets", "mutated_replay_window_packets"),
            (
                "peak_packets_per_second",
                "peak_packets_per_second",
                "mutated_peak_packets_per_second",
            ),
            (
                "maximum_authenticated_bytes_per_second",
                "maximum_authenticated_bytes_per_second",
                "mutated_maximum_authenticated_bytes_per_second",
            ),
            (
                "maximum_valid_datagram_bytes",
                "maximum_valid_datagram_bytes",
                "mutated_maximum_valid_datagram_bytes",
            ),
        ];
        let mut mutated_sources = vec![peer_source, link_source];
        mutated_sources.extend(numeric_mutations.map(|(setting, from, to)| {
            replace_first_setting(source, setting, vector_value(from), vector_value(to))
        }));

        for mutated_source in mutated_sources {
            let config = parse_config(&mutated_source).expect("valid excluded-field mutation");
            assert_eq!(config_identity(&config, device, key_epoch, &epoch_key), canonical);
        }
    }

    #[cfg(unix)]
    #[test]
    fn application_derives_identity_for_provisioning_and_capture_validation() {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let path = database_path();
        let secret_root = path.with_extension("secrets");
        let device_directory = secret_root.join("device-1");
        std::fs::create_dir(&secret_root).expect("create secret root");
        std::fs::set_permissions(&secret_root, std::fs::Permissions::from_mode(0o700))
            .expect("set secret root mode");
        std::fs::create_dir(&device_directory).expect("create device key directory");
        std::fs::set_permissions(&device_directory, std::fs::Permissions::from_mode(0o700))
            .expect("set device key directory mode");
        let key_path = device_directory.join("key-1.bin");
        let mut key_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .expect("create epoch key");
        key_file.write_all(&[0x11; 32]).expect("write epoch key");
        drop(key_file);

        let mut database = Database::create_new(&path).expect("create database");
        let config = config_with_database_and_secret_root(&path, &secret_root);
        let device = DeviceId::new(1);
        let key_epoch = KeyEpoch::try_new(1).expect("key epoch");

        provision_admission_epoch(&mut database, &config, device, key_epoch).expect("provision");
        validate_capture_epoch(&database, &config, device, key_epoch).expect("capture validation");
        std::fs::write(&key_path, [0x12; 32]).expect("replace epoch key bytes");
        assert!(validate_capture_epoch(&database, &config, device, key_epoch).is_err());
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
        std::fs::remove_dir_all(secret_root).expect("cleanup secret store");
    }

    #[test]
    fn admission_helpers_reject_a_missing_device_epoch_route() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let config = config_with_database_path(&path);
        let device = DeviceId::new(99);
        let key_epoch = KeyEpoch::try_new(1).expect("key epoch");

        assert!(matches!(
            provision_admission_epoch(
                &mut database,
                &config,
                device,
                key_epoch,
            ),
            Err(HostError::MissingAdmissionRoute {
                device: actual_device,
                key_epoch: actual_epoch,
            }) if actual_device == device && actual_epoch == key_epoch
        ));
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn admission_helpers_reject_ambiguous_device_epoch_routes() {
        let config = parse_config(include_str!("../tests/fixtures/config/valid-two-esp32.toml"))
            .expect("valid config");
        let device = DeviceId::new(1);
        let key_epoch = KeyEpoch::try_new(1).expect("key epoch");
        let route = &config.registry().routes()[0];

        assert!(matches!(
            select_replay_admission_route(
                [route, route].into_iter(),
                device,
                key_epoch,
            ),
            Err(HostError::AmbiguousAdmissionRoute {
                device: actual_device,
                key_epoch: actual_epoch,
            }) if actual_device == device && actual_epoch == key_epoch
        ));
    }

    #[test]
    fn capture_open_missing_store_is_non_creating() {
        let path = database_path();
        drop(Connection::open(&path).expect("create setup SQLite database"));
        std::fs::remove_file(&path).expect("remove setup SQLite database");
        let config = config_with_database_path(&path);

        assert!(matches!(
            open_capture_database(&config),
            Err(HostError::Database(DatabaseError::Missing))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn capture_open_rejects_non_sqlite_bytes_without_mutation_or_sidecars() {
        let path = database_path();
        let original = b"whisper-not-a-sqlite-database";
        std::fs::write(&path, original).expect("write non-SQLite fixture");
        let config = config_with_database_path(&path);
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));

        assert!(matches!(
            open_capture_database(&config),
            Err(HostError::Database(DatabaseError::Sql(_)))
        ));
        assert_eq!(std::fs::read(&path).expect("read fixture after failed open"), original);
        assert!(!wal.exists());
        assert!(!shm.exists());

        std::fs::remove_file(path).expect("cleanup");
    }
}
