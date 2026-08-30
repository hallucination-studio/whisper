//! Read-only Demo Store snapshots and canonical query DTOs.

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io::Cursor;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use ciborium::{de::from_reader, ser::into_writer};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::demo_store::{DemoStoreError, open_query_reader};
use crate::domain::identity::{
    DeploymentId, RadioLinkId, SensorId, SessionId, SpaceId, TransmitterId,
};
use crate::domain::time::SessionTime;
use crate::hex;
use crate::managed_store::{Identity, ManagedRoot, validate_existing_for_reader};

const TOPOLOGY_MANIFEST_SCHEMA: u8 = 1;

/// A failure to open or derive one complete read-only Demo query response.
#[derive(Debug)]
pub struct QueryError {
    source: QueryErrorKind,
    backtrace: Backtrace,
}

#[derive(Debug, thiserror::Error)]
enum QueryErrorKind {
    #[error("Demo query Store validation failed: {0}")]
    Store(#[source] DemoStoreError),
    #[error("Demo query SQLite operation failed: {0}")]
    Sql(#[source] rusqlite::Error),
    #[error("invalid Demo query: {0}")]
    InvalidRequest(&'static str),
    #[error("Demo query Store contents are incompatible")]
    Incompatible,
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for QueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl QueryError {
    /// Returns the backtrace captured at the query interface.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    /// Returns whether typed query construction rejected caller input.
    #[must_use]
    pub const fn is_invalid_request(&self) -> bool {
        matches!(self.source, QueryErrorKind::InvalidRequest(_))
    }

    /// Converts an unexpected read failure into the canonical projection error body.
    #[must_use]
    pub fn into_projection_failed(self) -> ErrorEnvelope {
        let _ = self;
        ErrorEnvelope::projection_failed()
    }

    fn new(source: QueryErrorKind) -> Self {
        Self { source, backtrace: Backtrace::capture() }
    }
}

impl From<DemoStoreError> for QueryError {
    fn from(source: DemoStoreError) -> Self {
        Self::new(QueryErrorKind::Store(source))
    }
}

impl From<rusqlite::Error> for QueryError {
    fn from(source: rusqlite::Error) -> Self {
        Self::new(QueryErrorKind::Sql(source))
    }
}

/// A non-creating handle that serializes snapshots through one pinned reader connection.
#[derive(Clone)]
pub struct QueryStore {
    inner: Arc<Mutex<PinnedReader>>,
}

struct PinnedReader {
    connection: Option<rusqlite::Connection>,
    managed: Option<Arc<ManagedRoot>>,
    database_path: PathBuf,
    file_identity: Identity,
    store_id: [u8; 32],
    replay_digest: [u8; 32],
}

impl Drop for PinnedReader {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            let _ = connection.close();
        }
        let _ = self.managed.take();
    }
}

impl fmt::Debug for QueryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("QueryStore").finish_non_exhaustive()
    }
}

impl QueryStore {
    pub(crate) fn from_managed(managed: Arc<ManagedRoot>) -> Result<Self, QueryError> {
        let database_path = managed.database_path();
        let (database_path, file_identity) =
            validate_existing_for_reader(database_path).map_err(DemoStoreError::from)?;
        let connection = open_query_reader(&database_path)?;
        let (store_id, replay_digest) = read_store_identity(&connection)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(PinnedReader {
                connection: Some(connection),
                managed: Some(managed),
                database_path,
                file_identity,
                store_id,
                replay_digest,
            })),
        })
    }

    /// Derives canonical provisioned and committed topology from one read snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error without a partial DTO when the Store cannot be read or validated.
    pub fn topology(&self) -> Result<TopologyOk, QueryError> {
        let mut reader = self.reader()?;
        validate_pinned_path(&reader)?;
        let store_id = reader.store_id;
        let connection = reader
            .connection
            .as_mut()
            .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let response = topology_snapshot(&transaction, store_id)?;
        transaction.commit()?;
        validate_pinned_path(&reader)?;
        Ok(response)
    }

    /// Derives one canonical native-coordinate signal response from a read snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error without a partial DTO when committed projection state is corrupt.
    pub fn signals(
        &self,
        query: &SignalQuery,
        limits: QueryLimits,
    ) -> Result<SignalsResponse, QueryError> {
        let mut reader = self.reader()?;
        validate_pinned_path(&reader)?;
        let store_id = reader.store_id;
        let replay_digest = reader.replay_digest;
        let connection = reader
            .connection
            .as_mut()
            .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let response = signals_snapshot(&transaction, query, limits, store_id, replay_digest)?;
        transaction.commit()?;
        validate_pinned_path(&reader)?;
        Ok(response)
    }

    fn reader(&self) -> Result<MutexGuard<'_, PinnedReader>, QueryError> {
        self.inner.lock().map_err(|_| QueryError::new(QueryErrorKind::Incompatible))
    }
}

fn validate_pinned_path(reader: &PinnedReader) -> Result<(), QueryError> {
    let (path, identity) =
        validate_existing_for_reader(&reader.database_path).map_err(DemoStoreError::from)?;
    if path != reader.database_path || identity != reader.file_identity {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    Ok(())
}

fn read_store_identity(
    connection: &rusqlite::Connection,
) -> Result<([u8; 32], [u8; 32]), QueryError> {
    let (store_id, replay, replay_digest): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT store_id, replay_config_cbor, replay_config_digest
             FROM store_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
    let store_id = store_id
        .as_slice()
        .try_into()
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    let replay_digest: [u8; 32] = replay_digest
        .as_slice()
        .try_into()
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    if <[u8; 32]>::from(Sha256::digest(&replay)) != replay_digest {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    Ok((store_id, replay_digest))
}

/// A half-open session-time range used by one signal query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalRange {
    from: SessionTime,
    to: SessionTime,
}

impl SignalRange {
    /// Validates a non-reversed half-open range. Equal bounds name an empty interval.
    pub fn try_new(from: SessionTime, to: SessionTime) -> Result<Self, QueryError> {
        if from.as_nanos() > to.as_nanos() {
            return Err(QueryError::new(QueryErrorKind::InvalidRequest("reversed signal range")));
        }
        Ok(Self { from, to })
    }
}

/// The exact scalar projection requested from native I/Q samples.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    /// Signed in-phase sample value.
    I,
    /// Signed quadrature sample value.
    Q,
    /// Euclidean magnitude of the I/Q pair.
    Amplitude,
    /// Wrapped `atan2(q, i)` phase in radians.
    Phase,
}

/// Validated runtime-only shaping limits for signal queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryLimits {
    max_signal_points: NonZeroU64,
    max_time_buckets: NonZeroU32,
}

impl QueryLimits {
    /// Validates positive point and bucket limits.
    pub fn try_new(max_signal_points: u64, max_time_buckets: u32) -> Result<Self, QueryError> {
        let max_signal_points = NonZeroU64::new(max_signal_points)
            .ok_or_else(|| QueryError::new(QueryErrorKind::InvalidRequest("zero point limit")))?;
        let max_time_buckets = NonZeroU32::new(max_time_buckets)
            .ok_or_else(|| QueryError::new(QueryErrorKind::InvalidRequest("zero bucket limit")))?;
        Ok(Self { max_signal_points, max_time_buckets })
    }
}

/// A validated typed signal selection independent of URL parsing.
#[derive(Clone, Debug)]
pub struct SignalQuery {
    session: SessionId,
    sensor: SensorId,
    link: RadioLinkId,
    range: SignalRange,
    metric: Metric,
    max_time_buckets: NonZeroU32,
    profile: Option<[u8; 32]>,
    path: Option<SignalPath>,
}

/// Validated required Capture Session, Sensor, and Link selectors.
#[derive(Clone, Debug)]
pub struct SignalSelection {
    session: SessionId,
    sensor: SensorId,
    link: RadioLinkId,
}

impl SignalSelection {
    /// Validates the three related signal identity selectors.
    pub fn try_new(session: &str, sensor: &str, link: &str) -> Result<Self, QueryError> {
        let session = SessionId::new(session)
            .map_err(|_| QueryError::new(QueryErrorKind::InvalidRequest("invalid session")))?;
        let sensor = SensorId::new(sensor)
            .map_err(|_| QueryError::new(QueryErrorKind::InvalidRequest("invalid sensor")))?;
        let link = RadioLinkId::new(link)
            .map_err(|_| QueryError::new(QueryErrorKind::InvalidRequest("invalid link")))?;
        Ok(Self { session, sensor, link })
    }
}

/// Builder for required query shaping and optional Profile/path selectors.
#[derive(Clone, Debug)]
pub struct SignalQueryBuilder {
    selection: SignalSelection,
    range: SignalRange,
    metric: Metric,
    max_time_buckets: Option<u32>,
    profile: Option<String>,
    path: Option<SignalPath>,
}

impl SignalQuery {
    /// Starts a query builder from validated identity, range, and metric values.
    #[must_use]
    pub fn builder(
        selection: SignalSelection,
        range: SignalRange,
        metric: Metric,
    ) -> SignalQueryBuilder {
        SignalQueryBuilder {
            selection,
            range,
            metric,
            max_time_buckets: None,
            profile: None,
            path: None,
        }
    }
}

impl SignalQueryBuilder {
    /// Sets the requested positive aggregation bucket bound.
    #[must_use]
    pub const fn max_time_buckets(mut self, max_time_buckets: u32) -> Self {
        self.max_time_buckets = Some(max_time_buckets);
        self
    }

    /// Restricts the query to one lowercase hexadecimal Profile identity.
    #[must_use]
    pub fn profile(mut self, profile: &str) -> Self {
        self.profile = Some(profile.to_owned());
        self
    }

    /// Restricts the query to one native CSI path.
    #[must_use]
    pub fn path(mut self, path: SignalPath) -> Self {
        self.path = Some(path);
        self
    }

    /// Validates all required and optional query shaping values.
    pub fn build(self) -> Result<SignalQuery, QueryError> {
        let max_time_buckets =
            self.max_time_buckets.and_then(NonZeroU32::new).ok_or_else(|| {
                QueryError::new(QueryErrorKind::InvalidRequest("zero or missing buckets"))
            })?;
        let profile = self.profile.as_deref().map(decode_hex_32).transpose()?;
        Ok(SignalQuery {
            session: self.selection.session,
            sensor: self.selection.sensor,
            link: self.selection.link,
            range: self.range,
            metric: self.metric,
            max_time_buckets,
            profile,
            path: self.path,
        })
    }
}

/// One exact native path selector and signal-axis value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalPath {
    /// A transmitter-stream and receiver-chain pair.
    TxRx {
        /// Transmit stream ordinal.
        tx_stream: u16,
        /// Receive chain ordinal.
        rx_chain: u16,
    },
    /// An opaque receive path ordinal.
    RawPathOrdinal {
        /// Opaque path ordinal.
        ordinal: u16,
    },
}

/// One canonical successful, empty, or typed-error signal envelope.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum SignalsResponse {
    /// A nonempty signal tile response.
    Ok(SignalsOk),
    /// The visible session contained no matching observation.
    Empty(EmptyEnvelope),
    /// A request or range could not produce a signal response.
    Error(ErrorEnvelope),
}

/// Canonical nonempty `SignalsOk` body imported by Demo Slice v1.
#[derive(Clone, Debug, Serialize)]
pub struct SignalsOk {
    http_schema_version: u8,
    kind: &'static str,
    resource: &'static str,
    data: SignalsData,
    receipt: ViewReceipt,
}

#[derive(Clone, Debug, Serialize)]
struct SignalsData {
    metric: Metric,
    tiles: Vec<SignalTile>,
}

#[derive(Clone, Debug, Serialize)]
struct SignalTile {
    stream: StreamInstance,
    profile: String,
    time_axis: Vec<String>,
    path_axis: Vec<SignalPath>,
    sample_axis: CsiSampleAxisDto,
    order: &'static str,
    cells: Vec<Option<SignalBucket>>,
    aggregation: &'static str,
    missing_spans: Vec<TimeIntervalDto>,
    receipt: ViewReceipt,
}

#[derive(Clone, Debug, Serialize)]
struct StreamInstance {
    key: StreamKey,
    device_epoch: DeviceEpochDto,
}

#[derive(Clone, Debug, Serialize)]
struct StreamKey {
    sensor: String,
    link: String,
    profile: String,
}

#[derive(Clone, Debug, Serialize)]
struct DeviceEpochDto {
    device_id: String,
    boot_generation: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CsiSampleAxisDto {
    OpaqueSampleOrdinal { count: u16 },
    IeeeToneIndex { values: Vec<i16> },
    FrequencyHz { values: Vec<String> },
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SignalBucket {
    Raw { value: f64 },
    MinMaxMeanRmsCount { minimum: f64, maximum: f64, mean: f64, rms: f64, count: u32 },
}

#[derive(Clone, Debug, Serialize)]
struct TimeIntervalDto {
    start: String,
    end: String,
}

#[derive(Clone, Debug, Serialize)]
struct ViewReceipt {
    projection_commit: ProjectionWatermark,
    session_id: String,
    first_record_seq: String,
    last_record_seq: String,
    decoder_version: String,
    conditioning_version: String,
    algorithm_version: String,
}

/// Canonical visible-session empty response imported by Demo Slice v1.
#[derive(Clone, Debug, Serialize)]
pub struct EmptyEnvelope {
    http_schema_version: u8,
    kind: &'static str,
    resource: &'static str,
    receipt: ViewReceipt,
}

/// Canonical typed query error response imported by Demo Slice v1.
#[derive(Clone, Debug, Serialize)]
pub struct ErrorEnvelope {
    http_schema_version: u8,
    kind: &'static str,
    error: ApiError,
}

impl ErrorEnvelope {
    /// Creates the canonical no-partial-body projection failure envelope.
    #[must_use]
    pub fn projection_failed() -> Self {
        Self {
            http_schema_version: 1,
            kind: "error",
            error: ApiError::Projection(ProjectionFailedError {
                code: "projection_failed",
                message: "committed projection could not be read".to_owned(),
            }),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
enum ApiError {
    Invalid(InvalidRequestError),
    Range(RangeUnavailableError),
    Phase(PhaseOverBudgetError),
    Projection(ProjectionFailedError),
}

#[derive(Clone, Debug, Serialize)]
struct InvalidRequestError {
    code: &'static str,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
struct RangeUnavailableError {
    code: &'static str,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
struct PhaseOverBudgetError {
    code: &'static str,
    message: String,
    max_signal_points: String,
}

#[derive(Clone, Debug, Serialize)]
struct ProjectionFailedError {
    code: &'static str,
    message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredObservationRoot {
    schema_version: u8,
    #[serde(serialize_with = "serialize_bytes")]
    config_digest: Vec<u8>,
    conditioning_version: String,
    observation: StoredObservation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredObservation {
    input: StoredInput,
    sensor: String,
    hardware: String,
    link: String,
    device_epoch: StoredDeviceEpoch,
    capture_sequence: u64,
    callback_tick_us: u64,
    timing: StoredTiming,
    radio: StoredRadio,
    #[serde(serialize_with = "serialize_bytes")]
    profile: Vec<u8>,
    csi: StoredCsi,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredDeviceEpoch {
    device: u64,
    boot_generation: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredTiming {
    received_ns: u64,
    device: StoredDeviceTimestamp,
    event_ns: u64,
    source: String,
    mapping_version: Option<String>,
    uncertainty_ns: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredDeviceTimestamp {
    ticks: u64,
    clock_domain: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRadio {
    channel: Option<u16>,
    centre_frequency_hz: Option<u64>,
    bandwidth_hz: Option<u64>,
    ppdu: Option<String>,
    rssi_dbm: i16,
    noise_floor_dbm: i16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredInput {
    session: String,
    record_seq: u64,
    decoder_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCsi {
    layout: StoredLayout,
    samples: Vec<StoredIqSample>,
    encoding: StoredEncoding,
    phase_state: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredLayout {
    paths: Vec<StoredPath>,
    samples: StoredSampleAxis,
    order: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredPath {
    TxRx { tx_stream: u16, rx_chain: u16 },
    RawPathOrdinal { ordinal: u16 },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredSampleAxis {
    OpaqueSampleOrdinal { count: u16 },
    IeeeToneIndex { values: Vec<i16> },
    FrequencyHz { values: Vec<u64> },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredIqSample {
    i: i64,
    q: i64,
    valid: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEncoding {
    signed_bits: u8,
    scale_numerator: i64,
    scale_denominator: i64,
    complex_order: String,
}

#[derive(Debug)]
struct SignalRow {
    session_time: u64,
    observation: StoredObservationRoot,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TileKey {
    profile: [u8; 32],
    device_id: u64,
    boot_generation: u32,
}

#[derive(Debug)]
struct TileRows {
    paths: Vec<SignalPath>,
    path_indices: Vec<usize>,
    sample_axis: CsiSampleAxisDto,
    rows: Vec<SignalRow>,
}

struct ObservationAuthority<'a> {
    query: &'a SignalQuery,
    record_sequence: u64,
    profile: [u8; 32],
    replay_digest: [u8; 32],
    decoder: &'a str,
    conditioning: &'a str,
    session_time: u64,
    device_id: u64,
    boot_generation: u32,
}

/// Canonical `TopologyOk` body imported by Demo Slice v1.
#[derive(Clone, Debug, Serialize)]
pub struct TopologyOk {
    http_schema_version: u8,
    kind: &'static str,
    resource: &'static str,
    data: TopologyData,
    receipt: StoreViewReceipt,
}

#[derive(Clone, Debug, Serialize)]
struct TopologyData {
    deployment: String,
    sessions: Vec<String>,
    spaces: Vec<TopologySpace>,
    sensors: Vec<TopologySensor>,
    links: Vec<TopologyLink>,
}

#[derive(Clone, Debug, Serialize)]
struct TopologySpace {
    id: String,
}

#[derive(Clone, Debug, Serialize)]
struct TopologySensor {
    id: String,
    hardware_kind: String,
    device_id: String,
}

#[derive(Clone, Debug, Serialize)]
struct TopologyLink {
    id: String,
    space: String,
    transmitter: String,
    receiver: String,
    profiles: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct StoreViewReceipt {
    projection_commit: ProjectionWatermark,
}

#[derive(Clone, Debug, Serialize)]
struct ProjectionWatermark {
    store_id: String,
    sequence: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredTopology {
    schema: u8,
    deployment: String,
    spaces: Vec<String>,
    transmitters: Vec<String>,
    sensors: Vec<StoredSensor>,
    links: Vec<StoredLink>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSensor {
    id: String,
    hardware_kind: String,
    device_id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredLink {
    id: String,
    space: String,
    transmitter: String,
    receiver: String,
}

fn signals_snapshot(
    transaction: &Transaction<'_>,
    query: &SignalQuery,
    limits: QueryLimits,
    expected_store_id: [u8; 32],
    expected_replay_digest: [u8; 32],
) -> Result<SignalsResponse, QueryError> {
    if query.max_time_buckets > limits.max_time_buckets {
        return Ok(invalid_request("max_time_buckets exceeds the configured limit"));
    }
    let (store_id, watermark, store_replay, store_replay_digest): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = transaction
        .query_row(
            "SELECT store_id, projection_commit_seq, replay_config_cbor, replay_config_digest
             FROM store_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
    let store_id: [u8; 32] = store_id
        .as_slice()
        .try_into()
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    if store_id != expected_store_id {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let store_replay_digest: [u8; 32] = store_replay_digest
        .as_slice()
        .try_into()
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    if store_replay_digest != expected_replay_digest
        || <[u8; 32]>::from(Sha256::digest(&store_replay)) != store_replay_digest
    {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let watermark = decode_u64(&watermark)?;
    let session = transaction
        .query_row(
            "SELECT committed_through_record_seq, replay_config_digest, decoder_version,
                    conditioning_version, algorithm_version, projection_commit_seq
             FROM capture_sessions WHERE session_id = ?1
               AND projection_commit_seq IS NOT NULL",
            [query.session.as_str()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((cursor, replay_digest, decoder, conditioning, algorithm, session_projection)) =
        session
    else {
        return Ok(range_unavailable("Capture Session is not query-visible"));
    };
    let cursor = decode_u64(&cursor)?;
    let session_projection = decode_u64(&session_projection)?;
    if watermark == 0 || session_projection == 0 || session_projection > watermark {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let replay_digest: [u8; 32] = replay_digest
        .as_slice()
        .try_into()
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    if replay_digest != store_replay_digest {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let receipt = ViewReceipt {
        projection_commit: ProjectionWatermark {
            store_id: hex::encode(&store_id),
            sequence: watermark.to_string(),
        },
        session_id: query.session.as_str().to_owned(),
        first_record_seq: "0".to_owned(),
        last_record_seq: cursor.to_string(),
        decoder_version: decoder.clone(),
        conditioning_version: conditioning.clone(),
        algorithm_version: algorithm,
    };
    if query.range.from == query.range.to {
        return Ok(empty_signals(receipt));
    }

    let rows = transaction
        .prepare(
            "SELECT observation.session_time_ns, observation.record_seq,
                    observation.profile_id, observation.observation_cbor,
                    observation.decoder_version, observation.conditioning_version,
                    observation.replay_config_digest, packet.session_time_ns,
                    packet.device_id, packet.boot_generation, packet.disposition
             FROM csi_observations AS observation
             JOIN packet_records AS packet USING(session_id, record_seq)
             WHERE observation.session_id = ?1
               AND observation.sensor_id = ?2 AND observation.link_id = ?3
               AND observation.record_seq <= ?4
               AND observation.session_time_ns >= ?5 AND observation.session_time_ns < ?6
             ORDER BY observation.profile_id, packet.device_id, packet.boot_generation,
                      observation.session_time_ns, observation.record_seq",
        )?
        .query_map(
            params![
                query.session.as_str(),
                query.sensor.as_str(),
                query.link.as_str(),
                cursor.to_be_bytes(),
                query.range.from.as_nanos().to_be_bytes(),
                query.range.to.as_nanos().to_be_bytes(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Ok(empty_signals(receipt));
    }
    let mut groups: BTreeMap<TileKey, TileRows> = BTreeMap::new();
    for (
        time,
        record,
        profile,
        observation_bytes,
        row_decoder,
        row_conditioning,
        row_replay_digest,
        packet_time,
        device,
        boot,
        disposition,
    ) in rows
    {
        let session_time = decode_u64(&time)?;
        let packet_time = decode_u64(&packet_time)?;
        let record_sequence = decode_u64(&record)?;
        let profile: [u8; 32] = profile
            .as_slice()
            .try_into()
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
        if query.profile.is_some_and(|selected| selected != profile) {
            continue;
        }
        let device_id = decode_u64(&device)?;
        let boot_generation = decode_u32(&boot)?;
        if boot_generation == 0
            || packet_time != session_time
            || row_decoder != decoder
            || row_conditioning != conditioning
            || row_replay_digest.as_slice() != replay_digest
            || disposition != "csi_committed"
        {
            return Err(QueryError::new(QueryErrorKind::Incompatible));
        }
        let mut observation_cursor = Cursor::new(observation_bytes.as_slice());
        let observation: StoredObservationRoot = from_reader(&mut observation_cursor)
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
        if observation_cursor.position()
            != u64::try_from(observation_bytes.len())
                .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?
        {
            return Err(QueryError::new(QueryErrorKind::Incompatible));
        }
        let mut canonical_observation = Vec::new();
        into_writer(&observation, &mut canonical_observation)
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
        if canonical_observation != observation_bytes {
            return Err(QueryError::new(QueryErrorKind::Incompatible));
        }
        validate_observation(
            &observation,
            ObservationAuthority {
                query,
                record_sequence,
                profile,
                replay_digest,
                decoder: &decoder,
                conditioning: &conditioning,
                session_time,
                device_id,
                boot_generation,
            },
        )?;
        let all_paths = decode_paths(&observation.observation.csi.layout.paths)?;
        let sample_axis = decode_sample_axis(&observation.observation.csi.layout.samples)?;
        validate_csi_shape(
            &observation.observation.csi,
            all_paths.len(),
            sample_count(&sample_axis)?,
        )?;
        let (paths, path_indices) = select_paths(&all_paths, query.path.as_ref());
        if paths.is_empty() {
            continue;
        }
        let key = TileKey { profile, device_id, boot_generation };
        let group = groups.entry(key).or_insert_with(|| TileRows {
            paths: paths.clone(),
            path_indices: path_indices.clone(),
            sample_axis: sample_axis.clone(),
            rows: Vec::new(),
        });
        if group.paths != paths
            || group.path_indices != path_indices
            || group.sample_axis != sample_axis
        {
            return Err(QueryError::new(QueryErrorKind::Incompatible));
        }
        group.rows.push(SignalRow { session_time, observation });
    }
    if groups.is_empty() {
        return Ok(empty_signals(receipt));
    }
    let raw_points = groups.values().try_fold(0_u64, |total, group| {
        let rows = u64::try_from(group.rows.len())
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
        let paths = u64::try_from(group.paths.len())
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
        let samples = u64::from(sample_count(&group.sample_axis)?);
        rows.checked_mul(paths)
            .and_then(|points| points.checked_mul(samples))
            .and_then(|points| total.checked_add(points))
            .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))
    })?;
    if raw_points > limits.max_signal_points.get() {
        if query.metric == Metric::Phase {
            return Ok(phase_over_budget(limits.max_signal_points));
        }
        return aggregate_signals(groups, query, limits, receipt);
    }
    let mut tiles = Vec::with_capacity(groups.len());
    for (key, group) in groups {
        let mut time_axis = Vec::with_capacity(group.rows.len());
        let mut cells = Vec::new();
        for row in group.rows {
            time_axis.push(row.session_time.to_string());
            let samples_per_path = usize::from(sample_count(&group.sample_axis)?);
            for path_index in &group.path_indices {
                let start = path_index
                    .checked_mul(samples_per_path)
                    .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
                let end = start
                    .checked_add(samples_per_path)
                    .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
                let samples = row
                    .observation
                    .observation
                    .csi
                    .samples
                    .get(start..end)
                    .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
                for sample in samples {
                    cells.push(raw_cell(query.metric, sample)?);
                }
            }
        }
        let profile = hex::encode(&key.profile);
        tiles.push(SignalTile {
            stream: StreamInstance {
                key: StreamKey {
                    sensor: query.sensor.as_str().to_owned(),
                    link: query.link.as_str().to_owned(),
                    profile: profile.clone(),
                },
                device_epoch: DeviceEpochDto {
                    device_id: key.device_id.to_string(),
                    boot_generation: key.boot_generation,
                },
            },
            profile,
            time_axis,
            path_axis: group.paths,
            sample_axis: group.sample_axis,
            order: "time_path_coordinate",
            cells,
            aggregation: "raw",
            missing_spans: Vec::new(),
            receipt: receipt.clone(),
        });
    }
    Ok(SignalsResponse::Ok(SignalsOk {
        http_schema_version: 1,
        kind: "ok",
        resource: "signals",
        data: SignalsData { metric: query.metric, tiles },
        receipt,
    }))
}

fn validate_observation(
    root: &StoredObservationRoot,
    authority: ObservationAuthority<'_>,
) -> Result<(), QueryError> {
    let observation = &root.observation;
    if root.schema_version != 1
        || root.config_digest.as_slice() != authority.replay_digest
        || root.conditioning_version != authority.conditioning
        || observation.input.session != authority.query.session.as_str()
        || observation.input.record_seq != authority.record_sequence
        || observation.input.decoder_version != authority.decoder
        || observation.sensor != authority.query.sensor.as_str()
        || observation.link != authority.query.link.as_str()
        || observation.profile.as_slice() != authority.profile
        || observation.hardware != "esp32-s3"
        || observation.device_epoch.device != authority.device_id
        || observation.device_epoch.boot_generation != authority.boot_generation
        || observation.capture_sequence == 0
        || observation.timing.received_ns != authority.session_time
        || observation.timing.event_ns != authority.session_time
        || observation.timing.source != "receive_only"
        || observation.timing.mapping_version.is_some()
        || observation.timing.uncertainty_ns != 0
        || observation.timing.device.clock_domain != "esp32s3-driver-ticks"
        || observation.radio.channel.is_none_or(|channel| channel == 0)
        || observation.radio.centre_frequency_hz.is_some()
        || !matches!(observation.radio.bandwidth_hz, Some(20_000_000 | 40_000_000))
        || !matches!(observation.radio.ppdu.as_deref(), Some("legacy" | "ht"))
        || i8::try_from(observation.radio.rssi_dbm).is_err()
        || i8::try_from(observation.radio.noise_floor_dbm).is_err()
    {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let _ = (observation.callback_tick_us, observation.timing.device.ticks);
    Ok(())
}

fn decode_paths(paths: &[StoredPath]) -> Result<Vec<SignalPath>, QueryError> {
    if paths.is_empty() {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let decoded: Vec<_> = paths
        .iter()
        .map(|path| match *path {
            StoredPath::TxRx { tx_stream, rx_chain } => SignalPath::TxRx { tx_stream, rx_chain },
            StoredPath::RawPathOrdinal { ordinal } => SignalPath::RawPathOrdinal { ordinal },
        })
        .collect();
    if decoded.iter().enumerate().any(|(index, path)| decoded[..index].contains(path)) {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    Ok(decoded)
}

fn select_paths(
    paths: &[SignalPath],
    selected: Option<&SignalPath>,
) -> (Vec<SignalPath>, Vec<usize>) {
    paths
        .iter()
        .enumerate()
        .filter(|(_, path)| selected.is_none_or(|selected| selected == *path))
        .map(|(index, path)| (path.clone(), index))
        .unzip()
}

fn decode_sample_axis(axis: &StoredSampleAxis) -> Result<CsiSampleAxisDto, QueryError> {
    match axis {
        StoredSampleAxis::OpaqueSampleOrdinal { count } if *count != 0 => {
            Ok(CsiSampleAxisDto::OpaqueSampleOrdinal { count: *count })
        }
        StoredSampleAxis::IeeeToneIndex { values }
            if !values.is_empty()
                && !values
                    .iter()
                    .enumerate()
                    .any(|(index, value)| values[..index].contains(value)) =>
        {
            Ok(CsiSampleAxisDto::IeeeToneIndex { values: values.clone() })
        }
        StoredSampleAxis::FrequencyHz { values }
            if !values.is_empty()
                && !values
                    .iter()
                    .enumerate()
                    .any(|(index, value)| values[..index].contains(value)) =>
        {
            Ok(CsiSampleAxisDto::FrequencyHz {
                values: values.iter().map(u64::to_string).collect(),
            })
        }
        _ => Err(QueryError::new(QueryErrorKind::Incompatible)),
    }
}

fn sample_count(axis: &CsiSampleAxisDto) -> Result<u16, QueryError> {
    match axis {
        CsiSampleAxisDto::OpaqueSampleOrdinal { count } => Ok(*count),
        CsiSampleAxisDto::IeeeToneIndex { values } => {
            u16::try_from(values.len()).map_err(|_| QueryError::new(QueryErrorKind::Incompatible))
        }
        CsiSampleAxisDto::FrequencyHz { values } => {
            u16::try_from(values.len()).map_err(|_| QueryError::new(QueryErrorKind::Incompatible))
        }
    }
}

fn validate_csi_shape(
    csi: &StoredCsi,
    path_count: usize,
    sample_count: u16,
) -> Result<(), QueryError> {
    let expected = path_count
        .checked_mul(usize::from(sample_count))
        .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
    if csi.layout.order != "path_then_sample"
        || csi.samples.len() != expected
        || csi.encoding.signed_bits != 8
        || csi.encoding.scale_numerator != 1
        || csi.encoding.scale_denominator != 1
        || csi.encoding.complex_order != "imaginary_real"
        || csi.phase_state != "raw"
        || csi
            .samples
            .iter()
            .any(|sample| i8::try_from(sample.i).is_err() || i8::try_from(sample.q).is_err())
    {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    Ok(())
}

fn raw_cell(metric: Metric, sample: &StoredIqSample) -> Result<Option<SignalBucket>, QueryError> {
    let Some(value) = sample_value(metric, sample)? else {
        return Ok(None);
    };
    Ok(Some(SignalBucket::Raw { value }))
}

fn sample_value(metric: Metric, sample: &StoredIqSample) -> Result<Option<f64>, QueryError> {
    if !sample.valid || metric == Metric::Phase && sample.i == 0 && sample.q == 0 {
        return Ok(None);
    }
    let i = sample.i as f64;
    let q = sample.q as f64;
    let value = match metric {
        Metric::I => i,
        Metric::Q => q,
        Metric::Amplitude => i.hypot(q),
        Metric::Phase => q.atan2(i),
    };
    if !value.is_finite() {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    Ok(Some(if value == 0.0 { 0.0 } else { value }))
}

fn empty_signals(receipt: ViewReceipt) -> SignalsResponse {
    SignalsResponse::Empty(EmptyEnvelope {
        http_schema_version: 1,
        kind: "empty",
        resource: "signals",
        receipt,
    })
}

fn invalid_request(message: &str) -> SignalsResponse {
    SignalsResponse::Error(ErrorEnvelope {
        http_schema_version: 1,
        kind: "error",
        error: ApiError::Invalid(InvalidRequestError {
            code: "invalid_request",
            message: message.to_owned(),
        }),
    })
}

fn range_unavailable(message: &str) -> SignalsResponse {
    SignalsResponse::Error(ErrorEnvelope {
        http_schema_version: 1,
        kind: "error",
        error: ApiError::Range(RangeUnavailableError {
            code: "range_unavailable",
            message: message.to_owned(),
        }),
    })
}

fn phase_over_budget(limit: NonZeroU64) -> SignalsResponse {
    SignalsResponse::Error(ErrorEnvelope {
        http_schema_version: 1,
        kind: "error",
        error: ApiError::Phase(PhaseOverBudgetError {
            code: "phase_over_budget",
            message: "phase requires a smaller raw interval".to_owned(),
            max_signal_points: limit.get().to_string(),
        }),
    })
}

fn aggregate_signals(
    groups: BTreeMap<TileKey, TileRows>,
    query: &SignalQuery,
    _limits: QueryLimits,
    receipt: ViewReceipt,
) -> Result<SignalsResponse, QueryError> {
    let from = query.range.from.as_nanos();
    let to = query.range.to.as_nanos();
    let duration = to
        .checked_sub(from)
        .filter(|duration| *duration != 0)
        .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
    let requested_buckets = u64::from(query.max_time_buckets.get());
    let width = duration / requested_buckets + u64::from(duration % requested_buckets != 0);
    let mut bucket_starts = Vec::new();
    let mut start = from;
    while start < to {
        bucket_starts.push(start);
        let remaining =
            to.checked_sub(start).ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
        start = start
            .checked_add(width.min(remaining))
            .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
    }
    if bucket_starts.len() > query.max_time_buckets.get() as usize {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }

    let mut tiles = Vec::with_capacity(groups.len());
    for (key, group) in groups {
        let samples_per_path = usize::from(sample_count(&group.sample_axis)?);
        let mut cells = Vec::new();
        for bucket_start in &bucket_starts {
            let remaining = to
                .checked_sub(*bucket_start)
                .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
            let bucket_end = bucket_start
                .checked_add(width.min(remaining))
                .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
            for path_index in &group.path_indices {
                for sample_index in 0..samples_per_path {
                    let flattened = path_index
                        .checked_mul(samples_per_path)
                        .and_then(|start| start.checked_add(sample_index))
                        .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
                    let mut values = Vec::new();
                    for row in &group.rows {
                        if row.session_time >= *bucket_start && row.session_time < bucket_end {
                            let sample = row
                                .observation
                                .observation
                                .csi
                                .samples
                                .get(flattened)
                                .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
                            if let Some(value) = sample_value(query.metric, sample)? {
                                values.push(value);
                            }
                        }
                    }
                    cells.push(aggregate_cell(&values)?);
                }
            }
        }
        let profile = hex::encode(&key.profile);
        tiles.push(SignalTile {
            stream: StreamInstance {
                key: StreamKey {
                    sensor: query.sensor.as_str().to_owned(),
                    link: query.link.as_str().to_owned(),
                    profile: profile.clone(),
                },
                device_epoch: DeviceEpochDto {
                    device_id: key.device_id.to_string(),
                    boot_generation: key.boot_generation,
                },
            },
            profile,
            time_axis: bucket_starts.iter().map(u64::to_string).collect(),
            path_axis: group.paths,
            sample_axis: group.sample_axis,
            order: "time_path_coordinate",
            cells,
            aggregation: "min_max_mean_rms_count",
            missing_spans: Vec::new(),
            receipt: receipt.clone(),
        });
    }
    Ok(SignalsResponse::Ok(SignalsOk {
        http_schema_version: 1,
        kind: "ok",
        resource: "signals",
        data: SignalsData { metric: query.metric, tiles },
        receipt,
    }))
}

fn aggregate_cell(values: &[f64]) -> Result<Option<SignalBucket>, QueryError> {
    let Some((&first, rest)) = values.split_first() else {
        return Ok(None);
    };
    let mut minimum = first;
    let mut maximum = first;
    let mut sum = first;
    let mut sum_squares = first * first;
    for value in rest {
        minimum = minimum.min(*value);
        maximum = maximum.max(*value);
        sum += *value;
        sum_squares += *value * *value;
    }
    let count =
        u32::try_from(values.len()).map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    let divisor = f64::from(count);
    let mean = sum / divisor;
    let rms = (sum_squares / divisor).sqrt();
    if [minimum, maximum, mean, rms].iter().any(|value| !value.is_finite()) {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    Ok(Some(SignalBucket::MinMaxMeanRmsCount {
        minimum: canonical_zero(minimum),
        maximum: canonical_zero(maximum),
        mean: canonical_zero(mean),
        rms: canonical_zero(rms),
        count,
    }))
}

fn canonical_zero(value: f64) -> f64 {
    if value == 0.0 { 0.0 } else { value }
}

fn topology_snapshot(
    transaction: &Transaction<'_>,
    expected_store_id: [u8; 32],
) -> Result<TopologyOk, QueryError> {
    let (store_id, topology_bytes, topology_digest, watermark): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = transaction
        .query_row(
            "SELECT store_id, topology_manifest_cbor, topology_manifest_digest,
                    projection_commit_seq FROM store_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .ok_or_else(|| QueryError::new(QueryErrorKind::Incompatible))?;
    let store_id: [u8; 32] = store_id
        .as_slice()
        .try_into()
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    if store_id != expected_store_id {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let expected_digest: [u8; 32] = topology_digest
        .as_slice()
        .try_into()
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    if <[u8; 32]>::from(Sha256::digest(&topology_bytes)) != expected_digest {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let watermark = decode_u64(&watermark)?;
    let mut topology_cursor = Cursor::new(topology_bytes.as_slice());
    let topology: StoredTopology = from_reader(&mut topology_cursor)
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    if topology_cursor.position()
        != u64::try_from(topology_bytes.len())
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?
        || topology.schema != TOPOLOGY_MANIFEST_SCHEMA
    {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    let mut canonical_topology = Vec::new();
    into_writer(&topology, &mut canonical_topology)
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    if canonical_topology != topology_bytes {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    ensure_strictly_ordered(topology.spaces.iter().map(String::as_bytes))?;
    ensure_strictly_ordered(topology.transmitters.iter().map(String::as_bytes))?;
    ensure_strictly_ordered(topology.sensors.iter().map(|sensor| sensor.id.as_bytes()))?;
    ensure_strictly_ordered(topology.links.iter().map(|link| link.id.as_bytes()))?;
    validate_topology_identities(&topology)?;

    let sessions = transaction
        .prepare(
            "SELECT session_id FROM capture_sessions
             WHERE projection_commit_seq IS NOT NULL ORDER BY session_id",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    ensure_strictly_ordered(sessions.iter().map(String::as_bytes))?;
    for session in &sessions {
        SessionId::new(session.as_str())
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    }

    let mut links = Vec::with_capacity(topology.links.len());
    for link in topology.links {
        let mut profiles = transaction
            .prepare(
                "SELECT DISTINCT lower(hex(observation.profile_id))
                 FROM csi_observations AS observation
                 JOIN capture_sessions AS session USING(session_id)
                 WHERE observation.sensor_id = ?1 AND observation.link_id = ?2
                   AND session.projection_commit_seq IS NOT NULL
                   AND observation.record_seq <= session.committed_through_record_seq
                 ORDER BY observation.profile_id",
            )?
            .query_map(params![&link.receiver, &link.id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        sort_unique(&mut profiles)?;
        links.push(TopologyLink {
            id: link.id,
            space: link.space,
            transmitter: link.transmitter,
            receiver: link.receiver,
            profiles,
        });
    }
    if watermark == 0
        && (!sessions.is_empty() || links.iter().any(|link| !link.profiles.is_empty()))
    {
        return Err(QueryError::new(QueryErrorKind::Incompatible));
    }
    Ok(TopologyOk {
        http_schema_version: 1,
        kind: "ok",
        resource: "topology",
        data: TopologyData {
            deployment: topology.deployment,
            sessions,
            spaces: topology.spaces.into_iter().map(|id| TopologySpace { id }).collect(),
            sensors: topology
                .sensors
                .into_iter()
                .map(|sensor| TopologySensor {
                    id: sensor.id,
                    hardware_kind: sensor.hardware_kind,
                    device_id: sensor.device_id.to_string(),
                })
                .collect(),
            links,
        },
        receipt: StoreViewReceipt {
            projection_commit: ProjectionWatermark {
                store_id: hex::encode(&store_id),
                sequence: watermark.to_string(),
            },
        },
    })
}

fn validate_topology_identities(topology: &StoredTopology) -> Result<(), QueryError> {
    DeploymentId::new(topology.deployment.as_str())
        .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    let spaces: BTreeSet<_> = topology.spaces.iter().map(String::as_str).collect();
    let transmitters: BTreeSet<_> = topology.transmitters.iter().map(String::as_str).collect();
    let sensors: BTreeSet<_> = topology.sensors.iter().map(|sensor| sensor.id.as_str()).collect();
    for space in &topology.spaces {
        SpaceId::new(space.as_str()).map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    }
    for transmitter in &topology.transmitters {
        TransmitterId::new(transmitter.as_str())
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    }
    let mut devices = BTreeSet::new();
    for sensor in &topology.sensors {
        SensorId::new(sensor.id.as_str())
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
        if sensor.hardware_kind != "esp32-s3" || !devices.insert(sensor.device_id) {
            return Err(QueryError::new(QueryErrorKind::Incompatible));
        }
    }
    for link in &topology.links {
        RadioLinkId::new(link.id.as_str())
            .map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
        if !spaces.contains(link.space.as_str())
            || !transmitters.contains(link.transmitter.as_str())
            || !sensors.contains(link.receiver.as_str())
        {
            return Err(QueryError::new(QueryErrorKind::Incompatible));
        }
    }
    Ok(())
}

fn decode_u64(bytes: &[u8]) -> Result<u64, QueryError> {
    let bytes: [u8; 8] =
        bytes.try_into().map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    Ok(u64::from_be_bytes(bytes))
}

fn serialize_bytes<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_bytes(bytes)
}

fn decode_u32(bytes: &[u8]) -> Result<u32, QueryError> {
    let bytes: [u8; 4] =
        bytes.try_into().map_err(|_| QueryError::new(QueryErrorKind::Incompatible))?;
    Ok(u32::from_be_bytes(bytes))
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], QueryError> {
    if value.len() != 64
        || value.bytes().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(QueryError::new(QueryErrorKind::InvalidRequest("invalid Profile identity")));
    }
    let mut decoded = [0_u8; 32];
    for (target, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = char::from(pair[0]).to_digit(16).ok_or_else(|| {
            QueryError::new(QueryErrorKind::InvalidRequest("invalid Profile identity"))
        })?;
        let low = char::from(pair[1]).to_digit(16).ok_or_else(|| {
            QueryError::new(QueryErrorKind::InvalidRequest("invalid Profile identity"))
        })?;
        *target = u8::try_from((high << 4) | low).map_err(|_| {
            QueryError::new(QueryErrorKind::InvalidRequest("invalid Profile identity"))
        })?;
    }
    Ok(decoded)
}

fn sort_unique(values: &mut [String]) -> Result<(), QueryError> {
    values.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    ensure_unique(values.iter().map(String::as_bytes))
}

fn ensure_unique<'a>(values: impl Iterator<Item = &'a [u8]>) -> Result<(), QueryError> {
    let mut previous: Option<&[u8]> = None;
    for value in values {
        if previous == Some(value) {
            return Err(QueryError::new(QueryErrorKind::Incompatible));
        }
        previous = Some(value);
    }
    Ok(())
}

fn ensure_strictly_ordered<'a>(values: impl Iterator<Item = &'a [u8]>) -> Result<(), QueryError> {
    let mut previous: Option<&[u8]> = None;
    for value in values {
        if previous.is_some_and(|previous| previous >= value) {
            return Err(QueryError::new(QueryErrorKind::Incompatible));
        }
        previous = Some(value);
    }
    Ok(())
}
