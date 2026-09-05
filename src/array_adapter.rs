//! Lossless locally coherent array capture records and qualified path adaptation.

use std::backtrace::Backtrace;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::artifact::{
    Artifact, ArtifactDigest, CalibrationBundle, CoherenceScope, SealedArtifact, SignalDirection,
};
use crate::measurement::{
    Eligibility, EventIdentity, MeasurementContext, ModelRequirements, NativeEventIdentity,
    PhaseReferenceIdentity, PhysicalOperator, Qualification, QualificationEpoch, QualificationGap,
    RetransmissionIdentity, SignalPath, SourceInstance, SourceTick, TickRange, TransmitterIdentity,
};
use crate::{BootGeneration, DeviceId, KeyEpoch, SensorId};

/// Canonical locally coherent array-capture envelope magic (`WAC1`).
const CAPTURE_MAGIC: &[u8; 4] = b"WAC1";
/// Exact canonical array-capture schema version.
const CAPTURE_SCHEMA_VERSION: u16 = 1;
/// Magic, schema, reserved field, and payload length.
const HEADER_BYTES: usize = 12;
/// SHA-256 digest appended to the canonical envelope.
const DIGEST_BYTES: usize = 32;
/// Maximum text identity width accepted from an array source.
const MAX_TEXT_BYTES: usize = 256;
/// Maximum native frequency samples in one bounded capture.
const MAX_FREQUENCIES: usize = 4_096;
/// Maximum logical signal paths in one bounded capture.
const MAX_SIGNAL_PATHS: usize = 256;
/// Maximum complex samples retained by one capture (16 MiB at four bytes each
/// leaves ample headroom for identities and masks).
const MAX_IQ_SAMPLES: usize = 4 * 1024 * 1024;
/// Maximum encoded capture size, including the digest.
const MAX_CAPTURE_BYTES: usize = 20 * 1024 * 1024;
/// Exact number of independently qualified local-array views in the RF-08
/// coverage contract. Changing it changes the downstream view topology.
const REQUIRED_ARRAY_VIEWS: usize = 3;

/// Opaque native LTF identity retained without assigning unsupported meaning.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LtfIdentity([u8; 32]);

impl LtfIdentity {
    /// Preserves the source-native LTF identity.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact opaque identity bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Opaque source-native path identity for one Tx/Rx CSI stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NativeArrayPathIdentity([u8; 32]);

impl NativeArrayPathIdentity {
    /// Preserves the source-native path identity.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact opaque identity bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// SHA-256 identity of exact local per-element phase corrections.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArrayPhaseCalibrationDigest([u8; 32]);

impl ArrayPhaseCalibrationDigest {
    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ArrayPhaseCalibrationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ArrayPhaseCalibrationDigest({self})")
    }
}

impl fmt::Display for ArrayPhaseCalibrationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Immutable path-major phase corrections for one local coherent array.
#[derive(Clone, Debug, PartialEq)]
pub struct ArrayPhaseCalibration {
    array_identity: Box<str>,
    reference: PhaseReferenceIdentity,
    epoch: QualificationEpoch,
    frequencies_hz: Box<[u64]>,
    paths: Box<[NativeArrayPathIdentity]>,
    correction_radians: Box<[f64]>,
    digest: ArrayPhaseCalibrationDigest,
}

impl ArrayPhaseCalibration {
    /// Constructs exact per-path, per-frequency phase corrections in path-major order.
    ///
    /// A correction is the finite rotation in radians applied to the native IQ sample
    /// before either delay or angle estimation. The frequency axis and native paths
    /// are immutable scope, rather than hints that may be reused on another capture.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, duplicate, unordered, non-finite, mismatched, or
    /// over-limit inputs. Each iterator is consumed through at most its limit plus one.
    pub fn new(
        array_identity: impl Into<Box<str>>,
        reference: PhaseReferenceIdentity,
        epoch: QualificationEpoch,
        frequencies_hz: impl IntoIterator<Item = u64>,
        paths: impl IntoIterator<Item = NativeArrayPathIdentity>,
        correction_radians: impl IntoIterator<Item = f64>,
    ) -> Result<Self, ArrayAdapterError> {
        let array_identity = array_identity.into();
        require_text(&array_identity)?;
        let frequencies_hz = collect_bounded(
            frequencies_hz,
            MAX_FREQUENCIES,
            "array phase calibration frequency axis exceeds its limit",
        )?;
        let paths = collect_bounded(
            paths,
            MAX_SIGNAL_PATHS,
            "array phase calibration paths exceed their limit",
        )?;
        if frequencies_hz.is_empty()
            || frequencies_hz.contains(&0)
            || frequencies_hz.windows(2).any(|pair| pair[0] >= pair[1])
            || paths.is_empty()
            || paths.iter().enumerate().any(|(index, path)| paths[..index].contains(path))
        {
            return Err(ArrayAdapterError::new("array phase calibration scope is invalid"));
        }
        let sample_count = frequencies_hz
            .len()
            .checked_mul(paths.len())
            .filter(|count| *count <= MAX_IQ_SAMPLES)
            .ok_or_else(|| {
                ArrayAdapterError::new("array phase calibration shape exceeds its limit")
            })?;
        let correction_radians = collect_bounded(
            correction_radians,
            sample_count,
            "array phase corrections exceed their declared shape",
        )?;
        if correction_radians.len() != sample_count
            || correction_radians.iter().any(|correction| !correction.is_finite())
        {
            return Err(ArrayAdapterError::new("array phase corrections are invalid"));
        }

        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"WPC1");
        put_text(&mut canonical, &array_identity)?;
        canonical.extend_from_slice(&reference.bytes());
        canonical.extend_from_slice(&epoch.get().to_le_bytes());
        put_count_u16(&mut canonical, frequencies_hz.len())?;
        for frequency in &frequencies_hz {
            canonical.extend_from_slice(&frequency.to_le_bytes());
        }
        put_count_u16(&mut canonical, paths.len())?;
        for path in &paths {
            canonical.extend_from_slice(&path.bytes());
        }
        for correction in &correction_radians {
            canonical.extend_from_slice(&correction.to_bits().to_le_bytes());
        }
        let digest = ArrayPhaseCalibrationDigest(Sha256::digest(canonical).into());
        Ok(Self {
            array_identity,
            reference,
            epoch,
            frequencies_hz: frequencies_hz.into_boxed_slice(),
            paths: paths.into_boxed_slice(),
            correction_radians: correction_radians.into_boxed_slice(),
            digest,
        })
    }

    /// Returns the immutable calibration digest.
    #[must_use]
    pub const fn digest(&self) -> ArrayPhaseCalibrationDigest {
        self.digest
    }

    /// Returns the exact local array identity.
    #[must_use]
    pub fn array_identity(&self) -> &str {
        &self.array_identity
    }

    /// Returns the independently qualified phase-reference identity.
    #[must_use]
    pub const fn reference(&self) -> PhaseReferenceIdentity {
        self.reference
    }

    /// Returns the phase-continuity epoch.
    #[must_use]
    pub const fn epoch(&self) -> QualificationEpoch {
        self.epoch
    }

    /// Returns the exact frequency axis to which corrections apply.
    #[must_use]
    pub fn frequencies_hz(&self) -> &[u64] {
        &self.frequencies_hz
    }

    /// Returns native paths in correction-major order.
    #[must_use]
    pub fn paths(&self) -> &[NativeArrayPathIdentity] {
        &self.paths
    }

    /// Returns the finite path-major rotations applied before estimation.
    #[must_use]
    pub fn correction_radians(&self) -> &[f64] {
        &self.correction_radians
    }
}

/// One native signed in-phase and quadrature sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComplexI16 {
    in_phase: i16,
    quadrature: i16,
}

impl ComplexI16 {
    /// Preserves an exact native integer IQ pair.
    #[must_use]
    pub const fn new(in_phase: i16, quadrature: i16) -> Self {
        Self { in_phase, quadrature }
    }

    /// Returns the native in-phase component.
    #[must_use]
    pub const fn in_phase(self) -> i16 {
        self.in_phase
    }

    /// Returns the native quadrature component.
    #[must_use]
    pub const fn quadrature(self) -> i16 {
        self.quadrature
    }
}

/// Per-sample acquisition state kept separate from the raw IQ value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleState {
    /// The source captured this exact native IQ value.
    Captured,
    /// No capture was attempted for this sample.
    NotCaptured,
    /// An expected sample was lost.
    Lost,
    /// Bytes were captured but failed source validation.
    Invalid,
    /// The sample value was interpolated and is not native evidence.
    Interpolated,
    /// Training selected this sample out without changing its acquisition fact.
    TrainingMasked,
}

impl SampleState {
    const fn code(self) -> u8 {
        match self {
            Self::Captured => 0,
            Self::NotCaptured => 1,
            Self::Lost => 2,
            Self::Invalid => 3,
            Self::Interpolated => 4,
            Self::TrainingMasked => 5,
        }
    }

    const fn from_code(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Captured),
            1 => Some(Self::NotCaptured),
            2 => Some(Self::Lost),
            3 => Some(Self::Invalid),
            4 => Some(Self::Interpolated),
            5 => Some(Self::TrainingMasked),
            _ => None,
        }
    }
}

/// Source-native radio and gain facts for one logical array path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArrayPathRadioFacts {
    native_antenna: u16,
    rssi_dbm_hundredths: i16,
    noise_dbm_hundredths: i16,
    gain_db_hundredths: Option<i16>,
}

impl ArrayPathRadioFacts {
    /// Preserves exact source-reported antenna, RSSI, noise, and actual gain fields.
    #[must_use]
    pub const fn new(
        native_antenna: u16,
        rssi_dbm_hundredths: i16,
        noise_dbm_hundredths: i16,
        gain_db_hundredths: Option<i16>,
    ) -> Self {
        Self { native_antenna, rssi_dbm_hundredths, noise_dbm_hundredths, gain_db_hundredths }
    }

    /// Returns the source-native antenna field without interpreting physical geometry.
    #[must_use]
    pub const fn native_antenna(self) -> u16 {
        self.native_antenna
    }

    /// Returns source-reported RSSI in hundredths of a decibel-milliwatt.
    #[must_use]
    pub const fn rssi_dbm_hundredths(self) -> i16 {
        self.rssi_dbm_hundredths
    }

    /// Returns source-reported noise floor in hundredths of a decibel-milliwatt.
    #[must_use]
    pub const fn noise_dbm_hundredths(self) -> i16 {
        self.noise_dbm_hundredths
    }

    /// Returns source-reported actual gain in hundredths of a decibel, when known.
    #[must_use]
    pub const fn gain_db_hundredths(self) -> Option<i16> {
        self.gain_db_hundredths
    }
}

/// Source-native PHY and receive facts shared by one array capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayNativeMetadata {
    bandwidth_hz: u32,
    rate_code: u32,
    mcs: Option<u16>,
    received_host_monotonic_ns: u64,
    path_facts: Box<[ArrayPathRadioFacts]>,
}

impl ArrayNativeMetadata {
    /// Constructs bounded native PHY, receive-time, and per-path radio facts.
    ///
    /// # Errors
    ///
    /// Returns an error for zero bandwidth or an empty/over-limit path fact set.
    pub fn new(
        bandwidth_hz: u32,
        rate_code: u32,
        mcs: Option<u16>,
        received_host_monotonic_ns: u64,
        path_facts: impl IntoIterator<Item = ArrayPathRadioFacts>,
    ) -> Result<Self, ArrayAdapterError> {
        let path_facts = collect_bounded(
            path_facts,
            MAX_SIGNAL_PATHS,
            "array native metadata exceeds its path limit",
        )?;
        if bandwidth_hz == 0 || path_facts.is_empty() || path_facts.len() > MAX_SIGNAL_PATHS {
            return Err(ArrayAdapterError::new("array native metadata is invalid"));
        }
        Ok(Self {
            bandwidth_hz,
            rate_code,
            mcs,
            received_host_monotonic_ns,
            path_facts: path_facts.into_boxed_slice(),
        })
    }

    /// Returns the source-reported RF bandwidth in hertz.
    #[must_use]
    pub const fn bandwidth_hz(&self) -> u32 {
        self.bandwidth_hz
    }

    /// Returns the opaque source-native rate code.
    #[must_use]
    pub const fn rate_code(&self) -> u32 {
        self.rate_code
    }

    /// Returns the source-native MCS value, when the profile defines one.
    #[must_use]
    pub const fn mcs(&self) -> Option<u16> {
        self.mcs
    }

    /// Returns the Host monotonic timestamp captured at receive admission.
    #[must_use]
    pub const fn received_host_monotonic_ns(&self) -> u64 {
        self.received_host_monotonic_ns
    }

    /// Returns one native radio-fact set per logical signal path.
    #[must_use]
    pub fn path_facts(&self) -> &[ArrayPathRadioFacts] {
        &self.path_facts
    }
}

/// Exact source, RF event, capture context, array, and device identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayCaptureIdentity {
    source: SourceInstance,
    event: EventIdentity,
    context: MeasurementContext,
    array_identity: Box<str>,
    rf_device_identity: Box<str>,
}

impl ArrayCaptureIdentity {
    /// Constructs the full native identity without inferring an array or RF device.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or overlong source identity.
    pub fn new(
        source: SourceInstance,
        event: EventIdentity,
        context: MeasurementContext,
        array_identity: impl Into<Box<str>>,
        rf_device_identity: impl Into<Box<str>>,
    ) -> Result<Self, ArrayAdapterError> {
        let array_identity = array_identity.into();
        let rf_device_identity = rf_device_identity.into();
        require_text(&array_identity)?;
        require_text(&rf_device_identity)?;
        Ok(Self { source, event, context, array_identity, rf_device_identity })
    }

    /// Returns the authenticated source instance.
    #[must_use]
    pub const fn source(&self) -> &SourceInstance {
        &self.source
    }

    /// Returns the source-native RF event identity.
    #[must_use]
    pub const fn event(&self) -> EventIdentity {
        self.event
    }

    /// Returns the exact capture profile, radio, and channel context.
    #[must_use]
    pub const fn context(&self) -> MeasurementContext {
        self.context
    }

    /// Returns the local coherent-array identity.
    #[must_use]
    pub fn array_identity(&self) -> &str {
        &self.array_identity
    }

    /// Returns the RF device identity named by calibration artifacts.
    #[must_use]
    pub fn rf_device_identity(&self) -> &str {
        &self.rf_device_identity
    }
}

/// One source-native Tx/Rx path and its logical calibration names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArraySignalPath {
    signal_path: SignalPath,
    native_path: NativeArrayPathIdentity,
    tx_logical_path: Box<str>,
    rx_logical_path: Box<str>,
}

impl ArraySignalPath {
    /// Constructs one exact native path without assigning physical antennas.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or overlong logical path name.
    pub fn new(
        signal_path: SignalPath,
        native_path: NativeArrayPathIdentity,
        tx_logical_path: impl Into<Box<str>>,
        rx_logical_path: impl Into<Box<str>>,
    ) -> Result<Self, ArrayAdapterError> {
        let tx_logical_path = tx_logical_path.into();
        let rx_logical_path = rx_logical_path.into();
        require_text(&tx_logical_path)?;
        require_text(&rx_logical_path)?;
        Ok(Self { signal_path, native_path, tx_logical_path, rx_logical_path })
    }

    /// Returns the protocol Tx stream and Rx chain.
    #[must_use]
    pub const fn signal_path(&self) -> SignalPath {
        self.signal_path
    }

    /// Returns the exact source-native path identity.
    #[must_use]
    pub const fn native_path(&self) -> NativeArrayPathIdentity {
        self.native_path
    }

    /// Returns the calibration name of the logical Tx stream.
    #[must_use]
    pub fn tx_logical_path(&self) -> &str {
        &self.tx_logical_path
    }

    /// Returns the calibration name of the logical Rx chain.
    #[must_use]
    pub fn rx_logical_path(&self) -> &str {
        &self.rx_logical_path
    }
}

/// One bounded lossless array capture with a path-major sample grid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayCapture {
    identity: ArrayCaptureIdentity,
    ltf: LtfIdentity,
    window: TickRange,
    observed_utc_ns: u64,
    native_metadata: ArrayNativeMetadata,
    frequencies_hz: Box<[u64]>,
    signal_paths: Box<[ArraySignalPath]>,
    raw_iq: Box<[ComplexI16]>,
    sample_states: Box<[SampleState]>,
}

impl ArrayCapture {
    /// Constructs a bounded path-major capture while preserving every native value.
    ///
    /// # Errors
    ///
    /// Returns an error for unordered frequency axes, duplicate paths, empty shapes,
    /// inconsistent sample counts, or any configured format limit violation.
    #[expect(
        clippy::too_many_arguments,
        reason = "the capture boundary names identity, timing, axes, payload, and acquisition state explicitly"
    )]
    pub fn new(
        identity: ArrayCaptureIdentity,
        ltf: LtfIdentity,
        window: TickRange,
        observed_utc_ns: u64,
        native_metadata: ArrayNativeMetadata,
        frequencies_hz: impl IntoIterator<Item = u64>,
        signal_paths: impl IntoIterator<Item = ArraySignalPath>,
        raw_iq: impl IntoIterator<Item = ComplexI16>,
        sample_states: impl IntoIterator<Item = SampleState>,
    ) -> Result<Self, ArrayAdapterError> {
        let frequencies_hz = collect_bounded(
            frequencies_hz,
            MAX_FREQUENCIES,
            "array frequency axis exceeds its limit",
        )?;
        let signal_paths = collect_bounded(
            signal_paths,
            MAX_SIGNAL_PATHS,
            "array signal paths exceed their limit",
        )?;
        if frequencies_hz.is_empty()
            || frequencies_hz.len() > MAX_FREQUENCIES
            || frequencies_hz.contains(&0)
            || frequencies_hz.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ArrayAdapterError::new("array frequency axis is invalid"));
        }
        if signal_paths.is_empty()
            || signal_paths.len() > MAX_SIGNAL_PATHS
            || signal_paths.iter().enumerate().any(|(index, path)| {
                signal_paths[..index].iter().any(|earlier| {
                    earlier.signal_path == path.signal_path
                        || earlier.native_path == path.native_path
                })
            })
        {
            return Err(ArrayAdapterError::new("array signal paths are invalid"));
        }
        let samples = frequencies_hz
            .len()
            .checked_mul(signal_paths.len())
            .ok_or_else(|| ArrayAdapterError::new("array sample shape overflows"))?;
        if samples > MAX_IQ_SAMPLES {
            return Err(ArrayAdapterError::new("array sample shape exceeds its limit"));
        }
        let raw_iq = collect_bounded(raw_iq, samples, "array IQ exceeds its declared shape")?;
        let sample_states = collect_bounded(
            sample_states,
            samples,
            "array sample state exceeds its declared shape",
        )?;
        if raw_iq.len() != samples
            || sample_states.len() != samples
            || native_metadata.path_facts.len() != signal_paths.len()
        {
            return Err(ArrayAdapterError::new("array IQ and sample-state shape is invalid"));
        }
        Ok(Self {
            identity,
            ltf,
            window,
            observed_utc_ns,
            native_metadata,
            frequencies_hz: frequencies_hz.into_boxed_slice(),
            signal_paths: signal_paths.into_boxed_slice(),
            raw_iq: raw_iq.into_boxed_slice(),
            sample_states: sample_states.into_boxed_slice(),
        })
    }

    /// Returns the complete source and RF identity.
    #[must_use]
    pub const fn identity(&self) -> &ArrayCaptureIdentity {
        &self.identity
    }

    /// Returns the opaque native LTF identity.
    #[must_use]
    pub const fn ltf(&self) -> LtfIdentity {
        self.ltf
    }

    /// Returns the source-native capture window.
    #[must_use]
    pub const fn window(&self) -> TickRange {
        self.window
    }

    /// Returns the independently associated UTC nanosecond timestamp.
    #[must_use]
    pub const fn observed_utc_ns(&self) -> u64 {
        self.observed_utc_ns
    }

    /// Returns exact source-native PHY, gain, and receive-time facts.
    #[must_use]
    pub const fn native_metadata(&self) -> &ArrayNativeMetadata {
        &self.native_metadata
    }

    /// Returns the exact native frequency axis in hertz.
    #[must_use]
    pub fn frequencies_hz(&self) -> &[u64] {
        &self.frequencies_hz
    }

    /// Returns the source-native paths in path-major sample order.
    #[must_use]
    pub fn signal_paths(&self) -> &[ArraySignalPath] {
        &self.signal_paths
    }

    /// Returns every native IQ sample without calibration or normalization.
    #[must_use]
    pub fn raw_iq(&self) -> &[ComplexI16] {
        &self.raw_iq
    }

    /// Returns acquisition state separately for every native IQ sample.
    #[must_use]
    pub fn sample_states(&self) -> &[SampleState] {
        &self.sample_states
    }
}

/// SHA-256 identity of one exact canonical array capture.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArrayCaptureDigest([u8; 32]);

impl ArrayCaptureDigest {
    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ArrayCaptureDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ArrayCaptureDigest({self})")
    }
}

impl fmt::Display for ArrayCaptureDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Canonical immutable bytes for one lossless native array capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedArrayCapture {
    bytes: Box<[u8]>,
    digest: ArrayCaptureDigest,
}

impl SealedArrayCapture {
    /// Validates and seals one capture in its canonical format.
    ///
    /// # Errors
    ///
    /// Returns an error if encoded fields exceed their finite format bounds.
    pub fn seal(capture: ArrayCapture) -> Result<Self, ArrayAdapterError> {
        let mut payload = Vec::new();
        encode_capture(&mut payload, &capture)?;
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| ArrayAdapterError::new("array capture payload exceeds its format"))?;
        let total = HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|value| value.checked_add(DIGEST_BYTES))
            .ok_or_else(|| ArrayAdapterError::new("array capture envelope size overflows"))?;
        if total > MAX_CAPTURE_BYTES {
            return Err(ArrayAdapterError::new("array capture exceeds its byte limit"));
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(CAPTURE_MAGIC);
        bytes.extend_from_slice(&CAPTURE_SCHEMA_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&payload);
        let digest = ArrayCaptureDigest(Sha256::digest(&bytes).into());
        bytes.extend_from_slice(digest.as_bytes());
        Ok(Self { bytes: bytes.into_boxed_slice(), digest })
    }

    /// Parses a canonical array-capture envelope and validates its digest and shape.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unsupported, non-canonical, or digest-mismatched bytes.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, ArrayAdapterError> {
        let bytes = bytes.as_ref();
        if bytes.len() > MAX_CAPTURE_BYTES
            || bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || &bytes[..4] != CAPTURE_MAGIC
            || u16::from_le_bytes(bytes[4..6].try_into().expect("fixed schema width"))
                != CAPTURE_SCHEMA_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(ArrayAdapterError::new("array capture envelope is unsupported"));
        }
        let payload_len = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed length width"));
        let expected = HEADER_BYTES
            .checked_add(payload_len as usize)
            .and_then(|value| value.checked_add(DIGEST_BYTES))
            .ok_or_else(|| ArrayAdapterError::new("array capture envelope size overflows"))?;
        if expected != bytes.len() {
            return Err(ArrayAdapterError::new("array capture envelope length is invalid"));
        }
        let digest_offset = bytes.len() - DIGEST_BYTES;
        let computed = ArrayCaptureDigest(Sha256::digest(&bytes[..digest_offset]).into());
        if bytes[digest_offset..] != computed.0 {
            return Err(ArrayAdapterError::new("array capture digest does not match its bytes"));
        }
        let sealed = Self { bytes: bytes.to_vec().into_boxed_slice(), digest: computed };
        let canonical = Self::seal(sealed.decode()?)?;
        if canonical.bytes != sealed.bytes {
            return Err(ArrayAdapterError::new("array capture encoding is not canonical"));
        }
        Ok(sealed)
    }

    /// Returns the exact sealed bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the digest of the envelope before its appended digest field.
    #[must_use]
    pub const fn digest(&self) -> ArrayCaptureDigest {
        self.digest
    }

    /// Decodes the validated canonical capture.
    ///
    /// # Errors
    ///
    /// Returns an error if retained bytes no longer form a valid capture.
    pub fn decode(&self) -> Result<ArrayCapture, ArrayAdapterError> {
        let mut reader = Reader::new(&self.bytes[HEADER_BYTES..self.bytes.len() - DIGEST_BYTES]);
        let capture = decode_capture(&mut reader)?;
        if !reader.is_empty() {
            return Err(ArrayAdapterError::new("array capture has trailing payload bytes"));
        }
        Ok(capture)
    }
}

/// Whether a failed window may retry or must start a new qualification epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArrayAdaptDisposition {
    /// Reject only this window while preserving the current physical epoch.
    RejectWindow,
    /// End continuity because a physical identity or calibration relation changed.
    EndEpoch,
}

/// Fail-closed reason a locally coherent array capture produced no paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArrayAdaptReason {
    /// The capture is not bound exactly to the supplied evidence block.
    InputBinding,
    /// The requested operator is not coherent angle-delay estimation.
    WrongOperator,
    /// One or more independently established physical relations is ineligible.
    PhysicalQualification,
    /// The artifact is not the exact calibration for this source and array.
    CalibrationIdentity,
    /// Calibration, geometry, phase, or time validity does not cover the capture.
    CalibrationValidity,
    /// The adapter input is not one locally coherent two-by-four receive array.
    UnsupportedShape,
    /// Logical paths do not map exactly to calibrated physical elements.
    PortMapping,
    /// Frequency samples lie outside the calibrated array range.
    FrequencyValidity,
    /// Local per-element phase corrections do not match the qualified capture scope.
    PhaseCalibration,
    /// The physical array geometry cannot constrain a two-dimensional arrival angle.
    DegenerateGeometry,
    /// Missing, invalid, interpolated, or training-masked samples prevent estimation.
    SampleQuality,
    /// Captured IQ contains no finite nonzero signal energy.
    InsufficientSignal,
    /// A supplied static reference does not share the exact source interpretation shape.
    StaticReferenceMismatch,
}

/// A rejected array-adapter invocation with explicit qualification gaps.
#[derive(Debug)]
pub struct ArrayAdaptFailure {
    reason: ArrayAdaptReason,
    disposition: ArrayAdaptDisposition,
    gaps: Box<[QualificationGap]>,
    context: &'static str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    backtrace: Box<Backtrace>,
}

impl ArrayAdaptFailure {
    fn new(reason: ArrayAdaptReason, disposition: ArrayAdaptDisposition) -> Self {
        Self {
            reason,
            disposition,
            gaps: Box::new([]),
            context: "array adaptation rejected",
            source: None,
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    fn with_source(
        reason: ArrayAdaptReason,
        disposition: ArrayAdaptDisposition,
        context: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            reason,
            disposition,
            gaps: Box::new([]),
            context,
            source: Some(Box::new(source)),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    fn qualification(eligibility: &Eligibility) -> Self {
        let disposition = if eligibility.gaps().iter().any(ends_epoch) {
            ArrayAdaptDisposition::EndEpoch
        } else {
            ArrayAdaptDisposition::RejectWindow
        };
        Self {
            reason: ArrayAdaptReason::PhysicalQualification,
            disposition,
            gaps: eligibility.gaps().into(),
            context: "array physical qualification rejected",
            source: None,
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    /// Returns the fail-closed classification.
    #[must_use]
    pub const fn reason(&self) -> ArrayAdaptReason {
        self.reason
    }

    /// Returns whether the window or entire physical epoch must end.
    #[must_use]
    pub const fn disposition(&self) -> ArrayAdaptDisposition {
        self.disposition
    }

    /// Returns all independently detected qualification gaps.
    #[must_use]
    pub fn qualification_gaps(&self) -> &[QualificationGap] {
        &self.gaps
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for ArrayAdaptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {:?}", self.context, self.reason)
    }
}

impl std::error::Error for ArrayAdaptFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Map-safe interpretation of one RF path hypothesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathKind {
    /// The earliest qualified peak remains a possible fixed-Tx direct path.
    DirectPathPossible,
    /// A peak agrees with an explicitly supplied immutable static reference spectrum.
    StableStatic,
    /// A qualified residual path is a dynamic candidate, not a person position.
    DynamicCandidate,
    /// A qualified RF path has no accepted map or reference explanation.
    Unexplained,
}

/// One bounded angle-delay hypothesis in the local array frame.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArrayPathCandidate {
    azimuth_radians: f64,
    elevation_radians: f64,
    world_direction: [f64; 3],
    delay_seconds: f64,
    normalized_power: f64,
    angular_error_radians: f64,
    delay_error_seconds: f64,
    kind: PathKind,
}

impl ArrayPathCandidate {
    /// Returns azimuth in the local array coordinate frame.
    #[must_use]
    pub const fn azimuth_radians(self) -> f64 {
        self.azimuth_radians
    }

    /// Returns elevation in the local array coordinate frame.
    #[must_use]
    pub const fn elevation_radians(self) -> f64 {
        self.elevation_radians
    }

    /// Returns the unit arrival direction in the calibration artifact's world frame.
    #[must_use]
    pub const fn world_direction(self) -> [f64; 3] {
        self.world_direction
    }

    /// Returns propagation delay in seconds relative to the capture clock.
    #[must_use]
    pub const fn delay_seconds(self) -> f64 {
        self.delay_seconds
    }

    /// Returns coherent beam power normalized to the strongest retained hypothesis.
    #[must_use]
    pub const fn normalized_power(self) -> f64 {
        self.normalized_power
    }

    /// Returns conservative scan-grid plus geometry angular error in radians.
    #[must_use]
    pub const fn angular_error_radians(self) -> f64 {
        self.angular_error_radians
    }

    /// Returns half-bin delay error in seconds.
    #[must_use]
    pub const fn delay_error_seconds(self) -> f64 {
        self.delay_error_seconds
    }

    /// Returns the bounded map-safe path interpretation.
    #[must_use]
    pub const fn kind(self) -> PathKind {
        self.kind
    }
}

/// Per-array coverage and geometry reported without cross-array phase fusion.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArrayCoverage {
    qualified_sample_fraction: f64,
    non_degenerate: bool,
    effective_aperture_m: f64,
    view_origin_world_m: [f64; 3],
}

impl ArrayCoverage {
    /// Returns the fraction of source-native samples admitted to estimation.
    #[must_use]
    pub const fn qualified_sample_fraction(self) -> f64 {
        self.qualified_sample_fraction
    }

    /// Reports whether local geometry spans two independent arrival-angle axes.
    #[must_use]
    pub const fn non_degenerate(self) -> bool {
        self.non_degenerate
    }

    /// Returns the largest calibrated phase-centre separation in metres.
    #[must_use]
    pub const fn effective_aperture_m(self) -> f64 {
        self.effective_aperture_m
    }

    /// Returns the array origin in the calibration artifact's world frame.
    #[must_use]
    pub const fn view_origin_world_m(self) -> [f64; 3] {
        self.view_origin_world_m
    }
}

/// Immutable qualified paths from exactly one local coherent array view.
#[derive(Clone, Debug, PartialEq)]
pub struct ArrayPathRecord {
    source: SourceInstance,
    array_identity: Box<str>,
    capture_digest: ArrayCaptureDigest,
    calibration_digest: ArtifactDigest,
    phase_calibration_digest: ArrayPhaseCalibrationDigest,
    static_reference_digest: Option<ArrayCaptureDigest>,
    window: TickRange,
    geometry_error_m: f64,
    coverage: ArrayCoverage,
    candidates: Box<[ArrayPathCandidate]>,
}

impl ArrayPathRecord {
    /// Returns the exact source instance of this view.
    #[must_use]
    pub const fn source(&self) -> &SourceInstance {
        &self.source
    }

    /// Returns the local array identity; records from different arrays never phase-fuse here.
    #[must_use]
    pub fn array_identity(&self) -> &str {
        &self.array_identity
    }

    /// Returns the immutable native capture digest.
    #[must_use]
    pub const fn capture_digest(&self) -> ArrayCaptureDigest {
        self.capture_digest
    }

    /// Returns the immutable spatial calibration digest.
    #[must_use]
    pub const fn calibration_digest(&self) -> ArtifactDigest {
        self.calibration_digest
    }

    /// Returns the exact local per-element phase-calibration identity.
    #[must_use]
    pub const fn phase_calibration_digest(&self) -> ArrayPhaseCalibrationDigest {
        self.phase_calibration_digest
    }

    /// Returns the immutable static-reference capture digest, when supplied.
    #[must_use]
    pub const fn static_reference_digest(&self) -> Option<ArrayCaptureDigest> {
        self.static_reference_digest
    }

    /// Returns the exact qualified source-native window.
    #[must_use]
    pub const fn window(&self) -> TickRange {
        self.window
    }

    /// Returns the conservative combined calibration geometry error in metres.
    #[must_use]
    pub const fn geometry_error_m(&self) -> f64 {
        self.geometry_error_m
    }

    /// Returns this array's independent coverage report.
    #[must_use]
    pub const fn coverage(&self) -> ArrayCoverage {
        self.coverage
    }

    /// Returns bounded local angle-delay hypotheses, never person positions.
    #[must_use]
    pub fn candidates(&self) -> &[ArrayPathCandidate] {
        &self.candidates
    }
}

/// An immutable spectrum whose source window and calibration were physically qualified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticArrayReference {
    capture: SealedArrayCapture,
    calibration_digest: ArtifactDigest,
    phase_calibration_digest: ArrayPhaseCalibrationDigest,
    array_identity: Box<str>,
}

impl StaticArrayReference {
    /// Binds exact capture bytes to the qualified record that produced them.
    ///
    /// This proves only that the spectrum passed array qualification. Promotion to
    /// a formal background condition remains the later scene-maintenance boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the capture digest or array identity differs from the record.
    pub fn new(
        record: &ArrayPathRecord,
        capture: &SealedArrayCapture,
    ) -> Result<Self, ArrayAdaptFailure> {
        let decoded = capture.decode().map_err(|source| {
            ArrayAdaptFailure::with_source(
                ArrayAdaptReason::StaticReferenceMismatch,
                ArrayAdaptDisposition::RejectWindow,
                "could not decode the static-reference capture",
                source,
            )
        })?;
        if capture.digest() != record.capture_digest
            || decoded.identity().array_identity() != record.array_identity()
        {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::StaticReferenceMismatch,
                ArrayAdaptDisposition::EndEpoch,
            ));
        }
        Ok(Self {
            capture: capture.clone(),
            calibration_digest: record.calibration_digest,
            phase_calibration_digest: record.phase_calibration_digest,
            array_identity: record.array_identity.clone(),
        })
    }

    /// Returns the exact immutable source spectrum digest.
    #[must_use]
    pub const fn capture_digest(&self) -> ArrayCaptureDigest {
        self.capture.digest()
    }

    /// Returns the calibration under which the reference was qualified.
    #[must_use]
    pub const fn calibration_digest(&self) -> ArtifactDigest {
        self.calibration_digest
    }

    /// Returns the local phase calibration under which the reference was qualified.
    #[must_use]
    pub const fn phase_calibration_digest(&self) -> ArrayPhaseCalibrationDigest {
        self.phase_calibration_digest
    }

    /// Returns the local array identity.
    #[must_use]
    pub fn array_identity(&self) -> &str {
        &self.array_identity
    }
}

/// Independent qualification summary for one array view.
#[derive(Clone, Debug, PartialEq)]
pub struct ArrayViewQualification {
    array_identity: Box<str>,
    source: SourceInstance,
    world_origin_m: [f64; 3],
    geometry_error_m: f64,
    candidate_count: usize,
    non_degenerate: bool,
}

impl ArrayViewQualification {
    /// Returns the independently calibrated array identity.
    #[must_use]
    pub fn array_identity(&self) -> &str {
        &self.array_identity
    }

    /// Returns the authenticated source instance for this view.
    #[must_use]
    pub const fn source(&self) -> &SourceInstance {
        &self.source
    }

    /// Returns the calibrated array origin in world-coordinate metres.
    #[must_use]
    pub const fn world_origin_m(&self) -> [f64; 3] {
        self.world_origin_m
    }

    /// Returns the conservative geometry error in metres.
    #[must_use]
    pub const fn geometry_error_m(&self) -> f64 {
        self.geometry_error_m
    }

    /// Returns the bounded local path count for this view.
    #[must_use]
    pub const fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    /// Reports whether this local array constrains two arrival-angle axes.
    #[must_use]
    pub const fn non_degenerate(&self) -> bool {
        self.non_degenerate
    }
}

/// Three independently qualified array views without cross-array carrier-phase state.
#[derive(Clone, Debug, PartialEq)]
pub struct ThreeArrayCoverage {
    views: Box<[ArrayViewQualification]>,
}

impl ThreeArrayCoverage {
    /// Summarizes exactly three distinct local-array path records.
    ///
    /// This summary reports coverage only. It neither phase-combines records nor
    /// intersects their rays into a person or world-state position.
    ///
    /// # Errors
    ///
    /// Returns an error unless there are exactly three distinct source, array,
    /// capture, calibration, and world-origin identities.
    pub fn new<'a>(
        records: impl IntoIterator<Item = &'a ArrayPathRecord>,
    ) -> Result<Self, ArrayCoverageError> {
        let records = records.into_iter().take(REQUIRED_ARRAY_VIEWS + 1).collect::<Vec<_>>();
        if records.len() != REQUIRED_ARRAY_VIEWS {
            return Err(ArrayCoverageError::new(
                "three-array coverage requires exactly three records",
            ));
        }
        for (index, record) in records.iter().enumerate() {
            let duplicate = records[..index].iter().any(|earlier| {
                earlier.array_identity == record.array_identity
                    || earlier.source == record.source
                    || earlier.capture_digest == record.capture_digest
                    || earlier.calibration_digest == record.calibration_digest
                    || earlier.coverage.view_origin_world_m == record.coverage.view_origin_world_m
            });
            if duplicate {
                return Err(ArrayCoverageError::new(
                    "three-array coverage records are not independent views",
                ));
            }
        }
        let views = records
            .into_iter()
            .map(|record| ArrayViewQualification {
                array_identity: record.array_identity.clone(),
                source: record.source.clone(),
                world_origin_m: record.coverage.view_origin_world_m,
                geometry_error_m: record.geometry_error_m,
                candidate_count: record.candidates.len(),
                non_degenerate: record.coverage.non_degenerate,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self { views })
    }

    /// Returns each array's independent qualification report in input order.
    #[must_use]
    pub fn views(&self) -> &[ArrayViewQualification] {
        &self.views
    }

    /// Returns the number of locally non-degenerate qualified views.
    #[must_use]
    pub fn non_degenerate_view_count(&self) -> usize {
        self.views.iter().filter(|view| view.non_degenerate).count()
    }

    /// Reports the accepted minimum of two non-degenerate local views.
    #[must_use]
    pub fn has_required_non_degenerate_views(&self) -> bool {
        self.non_degenerate_view_count() >= 2
    }
}

/// Invalid three-array coverage composition.
#[derive(Debug)]
pub struct ArrayCoverageError {
    message: &'static str,
    backtrace: Box<Backtrace>,
}

impl ArrayCoverageError {
    fn new(message: &'static str) -> Self {
        Self { message, backtrace: Box::new(Backtrace::capture()) }
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for ArrayCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ArrayCoverageError {}

/// Fixed first-version adapter for one ESPARGOS-class coherent two-by-four array.
#[derive(Clone, Copy, Debug, Default)]
pub struct EspargosSourceAdapter;

/// Exact immutable spatial and local-phase calibrations for one adaptation.
#[derive(Clone, Copy, Debug)]
pub struct ArrayCalibrationInput<'a> {
    spatial_bytes: &'a [u8],
    phase: &'a ArrayPhaseCalibration,
}

impl<'a> ArrayCalibrationInput<'a> {
    /// Groups sealed spatial-artifact bytes with exact local phase corrections.
    #[must_use]
    pub const fn new(spatial_bytes: &'a [u8], phase: &'a ArrayPhaseCalibration) -> Self {
        Self { spatial_bytes, phase }
    }

    /// Groups a validated sealed spatial artifact with exact local phase corrections.
    #[must_use]
    pub fn from_sealed(spatial: &'a SealedArtifact, phase: &'a ArrayPhaseCalibration) -> Self {
        Self::new(spatial.bytes(), phase)
    }
}

impl EspargosSourceAdapter {
    /// Creates the fixed bounded first-version array adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Produces local angle-delay hypotheses only after exact physical qualification.
    ///
    /// The output is one-array-local. It never combines carrier phase across arrays,
    /// constructs a person position, or promotes a ray intersection to a body landmark.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed reason when the capture, evidence block, calibration,
    /// static reference, sample quality, or independent physical relations disagree.
    pub fn adapt(
        &self,
        sealed_capture: &SealedArrayCapture,
        calibrations: ArrayCalibrationInput<'_>,
        block: &crate::measurement::EvidenceBlock,
        requirements: &ModelRequirements,
        qualification: &Qualification,
        static_reference: Option<&StaticArrayReference>,
    ) -> Result<ArrayPathRecord, ArrayAdaptFailure> {
        if requirements.operator() != PhysicalOperator::AngleDelay {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::WrongOperator,
                ArrayAdaptDisposition::RejectWindow,
            ));
        }
        let capture = sealed_capture.decode().map_err(|source| {
            ArrayAdaptFailure::with_source(
                ArrayAdaptReason::InputBinding,
                ArrayAdaptDisposition::RejectWindow,
                "could not decode the input array capture",
                source,
            )
        })?;
        validate_block_binding(&capture, sealed_capture.digest(), block)?;
        if !is_two_by_four_capture(&capture) {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::UnsupportedShape,
                ArrayAdaptDisposition::EndEpoch,
            ));
        }
        let eligibility = qualification.eligibility(block, requirements);
        if !eligibility.is_eligible() {
            return Err(ArrayAdaptFailure::qualification(&eligibility));
        }
        if capture.sample_states().iter().any(|state| *state != SampleState::Captured) {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::SampleQuality,
                ArrayAdaptDisposition::RejectWindow,
            ));
        }
        let sealed_calibration =
            SealedArtifact::parse(calibrations.spatial_bytes).map_err(|source| {
                ArrayAdaptFailure::with_source(
                    ArrayAdaptReason::CalibrationIdentity,
                    ArrayAdaptDisposition::EndEpoch,
                    "could not parse the sealed spatial calibration bytes",
                    source,
                )
            })?;
        let phase_calibration = calibrations.phase;
        let calibration = decode_calibration(&sealed_calibration)?;
        let ordered_elements = validate_calibration(&capture, &calibration, block, requirements)?;
        validate_phase_calibration(&capture, phase_calibration, block, requirements)?;
        let static_capture = static_reference
            .map(|reference| {
                validate_static_reference(
                    &capture,
                    reference,
                    sealed_calibration.digest(),
                    phase_calibration.digest(),
                )
            })
            .transpose()?;
        let geometry = geometry_metrics(&ordered_elements);
        if !geometry.non_degenerate {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::DegenerateGeometry,
                ArrayAdaptDisposition::EndEpoch,
            ));
        }
        let mut candidates = estimate_angle_delay(
            &capture,
            phase_calibration,
            &ordered_elements,
            geometry.aperture,
        )?;
        if candidates.is_empty() {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::InsufficientSignal,
                ArrayAdaptDisposition::RejectWindow,
            ));
        }
        candidates.sort_by(|left, right| left.delay_seconds.total_cmp(&right.delay_seconds));
        candidates[0].kind = PathKind::DirectPathPossible;
        let static_candidates = static_capture
            .as_ref()
            .map(|reference| {
                estimate_angle_delay(
                    reference,
                    phase_calibration,
                    &ordered_elements,
                    geometry.aperture,
                )
            })
            .transpose()?
            .unwrap_or_default();
        for candidate in candidates.iter_mut().skip(1) {
            let stable = static_candidates.iter().any(|reference| {
                (candidate.delay_seconds - reference.delay_seconds).abs()
                    <= candidate.delay_error_seconds + reference.delay_error_seconds
                    && (candidate.azimuth_radians - reference.azimuth_radians).abs()
                        <= ANGLE_STEP_RADIANS
                    && (candidate.elevation_radians - reference.elevation_radians).abs()
                        <= ANGLE_STEP_RADIANS
                    && (candidate.normalized_power - reference.normalized_power).abs()
                        <= STATIC_POWER_MATCH_TOLERANCE
            });
            candidate.kind = if stable {
                PathKind::StableStatic
            } else if candidate.normalized_power >= DYNAMIC_CANDIDATE_MINIMUM_POWER {
                PathKind::DynamicCandidate
            } else {
                PathKind::Unexplained
            };
        }
        let matrix = calibration.world_transform.matrix;
        for candidate in &mut candidates {
            candidate.world_direction = transform_direction(matrix, candidate.world_direction);
        }
        let geometry_error_m = calibration.max_error_m
            + calibration.world_transform.max_error_m
            + calibration.array_geometry.device_to_array.max_error_m
            + calibration.array_geometry.maximum_position_error_m;
        Ok(ArrayPathRecord {
            source: capture.identity().source().clone(),
            array_identity: capture.identity().array_identity().into(),
            capture_digest: sealed_capture.digest(),
            calibration_digest: sealed_calibration.digest(),
            phase_calibration_digest: phase_calibration.digest(),
            static_reference_digest: static_reference.map(StaticArrayReference::capture_digest),
            window: capture.window(),
            geometry_error_m,
            coverage: ArrayCoverage {
                qualified_sample_fraction: 1.0,
                non_degenerate: true,
                effective_aperture_m: geometry.aperture,
                view_origin_world_m: [matrix[3], matrix[7], matrix[11]],
            },
            candidates: candidates.into_boxed_slice(),
        })
    }
}

fn is_two_by_four_capture(capture: &ArrayCapture) -> bool {
    if capture.signal_paths().len() != 8 || capture.frequencies_hz().len() < 2 {
        return false;
    }
    let transmitters = capture
        .signal_paths()
        .iter()
        .map(|path| path.signal_path().tx_stream())
        .collect::<std::collections::BTreeSet<_>>();
    let receivers = capture
        .signal_paths()
        .iter()
        .map(|path| path.signal_path().rx_chain())
        .collect::<std::collections::BTreeSet<_>>();
    let frequency_span = capture.frequencies_hz().last().expect("nonempty frequency axis")
        - capture.frequencies_hz()[0];
    transmitters.len() == 1
        && receivers.len() == 8
        && frequency_span <= u64::from(capture.native_metadata().bandwidth_hz())
}

fn ends_epoch(gap: &QualificationGap) -> bool {
    matches!(
        gap,
        QualificationGap::MeasurementContext
            | QualificationGap::ArtifactActivation
            | QualificationGap::TimeScope
            | QualificationGap::TimeClockDomains
            | QualificationGap::TimeFit
            | QualificationGap::PhaseScope
            | QualificationGap::PhaseReference
            | QualificationGap::PhaseCoherence
            | QualificationGap::PortScope
            | QualificationGap::SignalPathMapping
            | QualificationGap::GeometryScope
            | QualificationGap::GeometryFrames
            | QualificationGap::GeometryPose
    )
}

fn validate_block_binding(
    capture: &ArrayCapture,
    digest: ArrayCaptureDigest,
    block: &crate::measurement::EvidenceBlock,
) -> Result<(), ArrayAdaptFailure> {
    let identity = block.identity();
    let scope = identity.scope();
    let paths_match = identity.signal_paths().len() == capture.signal_paths().len()
        && identity
            .signal_paths()
            .iter()
            .zip(capture.signal_paths())
            .all(|(block, capture)| *block == capture.signal_path());
    let member = crate::measurement::EvidenceMemberIdentity::new(*digest.as_bytes());
    if scope.source() != capture.identity().source()
        || scope.context() != capture.identity().context()
        || scope.window() != capture.window()
        || identity.members() != [member]
        || !paths_match
    {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::InputBinding,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    Ok(())
}

fn decode_calibration(sealed: &SealedArtifact) -> Result<CalibrationBundle, ArrayAdaptFailure> {
    match sealed.decode() {
        Ok(Artifact::Calibration(calibration)) => Ok(*calibration),
        Ok(Artifact::Scene(_) | Artifact::Supervision(_)) => Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::CalibrationIdentity,
            ArrayAdaptDisposition::EndEpoch,
        )),
        Err(source) => Err(ArrayAdaptFailure::with_source(
            ArrayAdaptReason::CalibrationIdentity,
            ArrayAdaptDisposition::EndEpoch,
            "could not decode the sealed spatial calibration",
            source,
        )),
    }
}

fn validate_calibration(
    capture: &ArrayCapture,
    calibration: &CalibrationBundle,
    block: &crate::measurement::EvidenceBlock,
    requirements: &ModelRequirements,
) -> Result<Vec<[f64; 3]>, ArrayAdaptFailure> {
    if calibration.rf_device_identity != capture.identity().rf_device_identity()
        || calibration.array_condition.array_identity != capture.identity().array_identity()
    {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::CalibrationIdentity,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    if calibration.array_condition.physical_element_count != 8
        || calibration.array_geometry.elements.len() != 8
    {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::UnsupportedShape,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    let utc = capture.observed_utc_ns();
    let valid = |start: crate::artifact::UtcNanoseconds, end: crate::artifact::UtcNanoseconds| {
        utc >= start.get() && utc <= end.get()
    };
    let epoch = block.identity().scope().epoch().get();
    if !valid(calibration.valid_from_utc, calibration.valid_until_utc)
        || !valid(
            calibration.array_geometry.valid_from_utc,
            calibration.array_geometry.valid_until_utc,
        )
        || !valid(
            calibration.phase_relation.valid_from_utc,
            calibration.phase_relation.valid_until_utc,
        )
        || !valid(
            calibration.time_relation.valid_from_utc,
            calibration.time_relation.valid_until_utc,
        )
        || calibration.phase_relation.scope != CoherenceScope::CaptureInterval
        || u64::from(calibration.array_geometry.epoch.get()) != epoch
        || u64::from(calibration.phase_relation.epoch.get()) != epoch
        || u64::from(calibration.time_relation.epoch.get()) != epoch
    {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::CalibrationValidity,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    if capture.frequencies_hz().iter().any(|frequency| {
        *frequency < calibration.array_geometry.minimum_frequency_hz
            || *frequency > calibration.array_geometry.maximum_frequency_hz
    }) {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::FrequencyValidity,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    let Some(geometry_requirement) = requirements.geometry_requirement() else {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::WrongOperator,
            ArrayAdaptDisposition::RejectWindow,
        ));
    };
    let Some(phase_requirement) = requirements.phase_requirement() else {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::WrongOperator,
            ArrayAdaptDisposition::RejectWindow,
        ));
    };
    let geometry_error_m = calibration.max_error_m
        + calibration.world_transform.max_error_m
        + calibration.array_geometry.device_to_array.max_error_m
        + calibration.array_geometry.maximum_position_error_m;
    if calibration.world_transform.source_coordinate_system != geometry_requirement.source_frame()
        || calibration.world_transform.target_coordinate_system
            != geometry_requirement.target_frame()
        || rigid_pose(calibration.world_transform.matrix) != Some(geometry_requirement.pose())
        || rigid_pose(calibration.array_geometry.device_to_array.matrix).is_none()
        || !error_within(
            geometry_error_m,
            ErrorUnitKind::Metres,
            geometry_requirement.maximum_error(),
        )
        || !error_within(
            calibration.phase_relation.maximum_error_radians,
            ErrorUnitKind::Radians,
            phase_requirement.maximum_error(),
        )
        || !error_within(
            calibration.time_relation.maximum_error.get() as f64,
            ErrorUnitKind::Nanoseconds,
            requirements.time_requirement().maximum_error(),
        )
    {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::CalibrationValidity,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    let transmit_names = capture
        .signal_paths()
        .iter()
        .map(ArraySignalPath::tx_logical_path)
        .collect::<std::collections::BTreeSet<_>>();
    let transmit_count = calibration
        .signal_paths
        .iter()
        .filter(|path| path.direction == SignalDirection::Transmit)
        .count();
    let receive_count = calibration
        .signal_paths
        .iter()
        .filter(|path| path.direction == SignalDirection::Receive)
        .count();
    if transmit_names.len() != 1
        || transmit_count != 1
        || receive_count != 8
        || calibration
            .signal_paths
            .iter()
            .filter(|path| path.direction == SignalDirection::Transmit)
            .filter(|path| transmit_names.contains(path.logical_path.as_str()))
            .count()
            != 1
    {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::PortMapping,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    let transmit_mapping = calibration
        .signal_paths
        .iter()
        .find(|path| path.direction == SignalDirection::Transmit)
        .expect("exactly one transmit mapping was established");
    let Some(transmit_antenna) = calibration
        .array_geometry
        .elements
        .iter()
        .position(|element| element.antenna_identity == transmit_mapping.antenna_identity)
    else {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::PortMapping,
            ArrayAdaptDisposition::EndEpoch,
        ));
    };
    let mut ordered = Vec::with_capacity(8);
    for capture_path in capture.signal_paths() {
        let Some(mapping) = calibration.signal_paths.iter().find(|candidate| {
            candidate.direction == SignalDirection::Receive
                && candidate.logical_path == capture_path.rx_logical_path()
        }) else {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::PortMapping,
                ArrayAdaptDisposition::EndEpoch,
            ));
        };
        let Some(element) = calibration
            .array_geometry
            .elements
            .iter()
            .find(|element| element.antenna_identity == mapping.antenna_identity)
        else {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::PortMapping,
                ArrayAdaptDisposition::EndEpoch,
            ));
        };
        let element_index = calibration
            .array_geometry
            .elements
            .iter()
            .position(|candidate| candidate.antenna_identity == element.antenna_identity)
            .expect("mapped element came from this collection");
        let Some(required) = requirements
            .port_requirements()
            .iter()
            .find(|required| required.path() == capture_path.signal_path())
        else {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::PortMapping,
                ArrayAdaptDisposition::EndEpoch,
            ));
        };
        if usize::from(required.tx_antenna()) != transmit_antenna
            || usize::from(required.rx_antenna()) != element_index
        {
            return Err(ArrayAdaptFailure::new(
                ArrayAdaptReason::PortMapping,
                ArrayAdaptDisposition::EndEpoch,
            ));
        }
        ordered.push(element.position_m);
    }
    if ordered.iter().enumerate().any(|(index, position)| ordered[..index].contains(position)) {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::DegenerateGeometry,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    Ok(ordered)
}

fn validate_static_reference(
    capture: &ArrayCapture,
    reference: &StaticArrayReference,
    calibration_digest: ArtifactDigest,
    phase_calibration_digest: ArrayPhaseCalibrationDigest,
) -> Result<ArrayCapture, ArrayAdaptFailure> {
    let decoded = reference.capture.decode().map_err(|source| {
        ArrayAdaptFailure::with_source(
            ArrayAdaptReason::StaticReferenceMismatch,
            ArrayAdaptDisposition::RejectWindow,
            "could not decode the validated static-reference capture",
            source,
        )
    })?;
    let same_paths = capture.signal_paths().len() == decoded.signal_paths().len()
        && capture.signal_paths().iter().zip(decoded.signal_paths()).all(|(left, right)| {
            left.signal_path() == right.signal_path()
                && left.native_path() == right.native_path()
                && left.tx_logical_path() == right.tx_logical_path()
                && left.rx_logical_path() == right.rx_logical_path()
        });
    if reference.calibration_digest != calibration_digest
        || reference.phase_calibration_digest != phase_calibration_digest
        || capture.identity().array_identity() != decoded.identity().array_identity()
        || capture.identity().rf_device_identity() != decoded.identity().rf_device_identity()
        || capture.identity().context() != decoded.identity().context()
        || capture.ltf() != decoded.ltf()
        || capture.frequencies_hz() != decoded.frequencies_hz()
        || decoded.sample_states().iter().any(|state| *state != SampleState::Captured)
        || !same_paths
    {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::StaticReferenceMismatch,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    Ok(decoded)
}

fn validate_phase_calibration(
    capture: &ArrayCapture,
    calibration: &ArrayPhaseCalibration,
    block: &crate::measurement::EvidenceBlock,
    requirements: &ModelRequirements,
) -> Result<(), ArrayAdaptFailure> {
    let expected_paths =
        capture.signal_paths().iter().map(ArraySignalPath::native_path).collect::<Vec<_>>();
    let Some(phase_requirement) = requirements.phase_requirement() else {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::WrongOperator,
            ArrayAdaptDisposition::RejectWindow,
        ));
    };
    if calibration.array_identity.as_ref() != capture.identity().array_identity()
        || calibration.reference != phase_requirement.reference()
        || calibration.epoch != block.identity().scope().epoch()
        || calibration.frequencies_hz.as_ref() != capture.frequencies_hz()
        || calibration.paths.as_ref() != expected_paths
    {
        return Err(ArrayAdaptFailure::new(
            ArrayAdaptReason::PhaseCalibration,
            ArrayAdaptDisposition::EndEpoch,
        ));
    }
    Ok(())
}

struct GeometryMetrics {
    non_degenerate: bool,
    aperture: f64,
}

fn geometry_metrics(elements: &[[f64; 3]]) -> GeometryMetrics {
    let mut aperture = 0.0_f64;
    for (index, left) in elements.iter().enumerate() {
        for right in &elements[index + 1..] {
            aperture = aperture.max(distance(*left, *right));
        }
    }
    let origin = elements[0];
    let non_degenerate = elements[1..].iter().enumerate().any(|(index, first)| {
        elements[index + 2..].iter().any(|second| {
            let a = subtract(*first, origin);
            let b = subtract(*second, origin);
            norm(cross(a, b)) > MINIMUM_GEOMETRY_CROSS_PRODUCT_M2
        })
    });
    GeometryMetrics { non_degenerate, aperture }
}

enum ErrorUnitKind {
    Metres,
    Radians,
    Nanoseconds,
}

fn error_within(
    actual: f64,
    actual_unit: ErrorUnitKind,
    maximum: crate::measurement::ErrorBound,
) -> bool {
    if !actual.is_finite() || actual < 0.0 || maximum.value() == u64::MAX {
        return false;
    }
    let scaled = match (actual_unit, maximum.unit()) {
        (ErrorUnitKind::Metres, crate::measurement::ErrorUnit::Millimetres)
        | (ErrorUnitKind::Radians, crate::measurement::ErrorUnit::Milliradians) => actual * 1_000.0,
        (ErrorUnitKind::Nanoseconds, crate::measurement::ErrorUnit::Nanoseconds) => actual,
        _ => return false,
    };
    scaled.ceil() <= maximum.value() as f64
}

fn rigid_pose(matrix: [f64; 16]) -> Option<crate::measurement::Pose> {
    let row_x = [matrix[0], matrix[1], matrix[2]];
    let row_y = [matrix[4], matrix[5], matrix[6]];
    let row_z = [matrix[8], matrix[9], matrix[10]];
    let orthonormal = [row_x, row_y, row_z].iter().all(|row| (norm(*row) - 1.0).abs() <= 1.0e-9)
        && dot(row_x, row_y).abs() <= 1.0e-9
        && dot(row_x, row_z).abs() <= 1.0e-9
        && dot(row_y, row_z).abs() <= 1.0e-9
        && (dot(row_x, cross(row_y, row_z)) - 1.0).abs() <= 1.0e-9;
    if !orthonormal {
        return None;
    }
    let trace = matrix[0] + matrix[5] + matrix[10];
    let (mut qx, mut qy, mut qz, mut qw) = if trace > 0.0 {
        let scale = (trace + 1.0).sqrt() * 2.0;
        (
            (matrix[9] - matrix[6]) / scale,
            (matrix[2] - matrix[8]) / scale,
            (matrix[4] - matrix[1]) / scale,
            scale / 4.0,
        )
    } else if matrix[0] > matrix[5] && matrix[0] > matrix[10] {
        let scale = (1.0 + matrix[0] - matrix[5] - matrix[10]).sqrt() * 2.0;
        (
            scale / 4.0,
            (matrix[1] + matrix[4]) / scale,
            (matrix[2] + matrix[8]) / scale,
            (matrix[9] - matrix[6]) / scale,
        )
    } else if matrix[5] > matrix[10] {
        let scale = (1.0 + matrix[5] - matrix[0] - matrix[10]).sqrt() * 2.0;
        (
            (matrix[1] + matrix[4]) / scale,
            scale / 4.0,
            (matrix[6] + matrix[9]) / scale,
            (matrix[2] - matrix[8]) / scale,
        )
    } else {
        let scale = (1.0 + matrix[10] - matrix[0] - matrix[5]).sqrt() * 2.0;
        (
            (matrix[2] + matrix[8]) / scale,
            (matrix[6] + matrix[9]) / scale,
            scale / 4.0,
            (matrix[4] - matrix[1]) / scale,
        )
    };
    if qw < 0.0 {
        qx = -qx;
        qy = -qy;
        qz = -qz;
        qw = -qw;
    }
    let scaled = [
        matrix[3] * 1_000.0,
        matrix[7] * 1_000.0,
        matrix[11] * 1_000.0,
        qx * 1_000_000.0,
        qy * 1_000_000.0,
        qz * 1_000_000.0,
        qw * 1_000_000.0,
    ];
    if scaled.iter().any(|value| !value.is_finite() || value.abs() > i64::MAX as f64) {
        return None;
    }
    Some(crate::measurement::Pose::new(scaled.map(|value| value.round() as i64)))
}

const SPEED_OF_LIGHT_MPS: f64 = 299_792_458.0;
/// Minimum cross-product magnitude in square metres used to reject numerically
/// collinear phase centres. This v1 numerical guard is below the documented
/// millimetre geometry-error budget; changing it changes which arrays qualify.
const MINIMUM_GEOMETRY_CROSS_PRODUCT_M2: f64 = 1.0e-8;
/// Maximum unitless normalized-power difference for matching a qualified static
/// path. The v1 value is an explicit classification policy, not measured RF
/// accuracy; changing it changes `StableStatic` membership.
const STATIC_POWER_MATCH_TOLERANCE: f64 = 0.15;
/// Minimum unitless normalized power for an unmatched path to remain a dynamic
/// candidate. The v1 midpoint is a conservative policy threshold; changing it
/// changes downstream dynamic-candidate volume.
const DYNAMIC_CANDIDATE_MINIMUM_POWER: f64 = 0.5;
/// Fixed 15-degree angular grid. This is an explicit first-version numerical
/// resolution, not evidence of physical accuracy.
const ANGLE_STEP_RADIANS: f64 = std::f64::consts::PI / 12.0;
/// The bounded adapter retains at most eight distinct local hypotheses.
const MAX_PATH_CANDIDATES: usize = 8;
/// Delay processing is capped independently of native sample count.
const MAX_DELAY_BINS: usize = 64;

#[derive(Clone, Copy)]
struct ComplexF64 {
    re: f64,
    im: f64,
}

impl ComplexF64 {
    fn add_rotated(&mut self, sample: ComplexI16, phase: f64) {
        let (sin, cos) = phase.sin_cos();
        let re = f64::from(sample.in_phase());
        let im = f64::from(sample.quadrature());
        self.re += re * cos - im * sin;
        self.im += re * sin + im * cos;
    }

    fn add_complex_rotated(&mut self, sample: Self, phase: f64) {
        let (sin, cos) = phase.sin_cos();
        self.re += sample.re * cos - sample.im * sin;
        self.im += sample.re * sin + sample.im * cos;
    }

    const fn power(self) -> f64 {
        self.re * self.re + self.im * self.im
    }
}

fn estimate_angle_delay(
    capture: &ArrayCapture,
    phase_calibration: &ArrayPhaseCalibration,
    elements: &[[f64; 3]],
    aperture: f64,
) -> Result<Vec<ArrayPathCandidate>, ArrayAdaptFailure> {
    let frequencies = capture.frequencies_hz();
    let spacing = frequencies
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .min()
        .expect("capture has at least two frequencies for a two-by-four adapter");
    let delay_bins = frequencies.len().min(MAX_DELAY_BINS);
    let delay_step = 1.0 / (spacing as f64 * delay_bins as f64);
    let center_frequency = frequencies[frequencies.len() / 2] as f64;
    let mut delayed = vec![vec![ComplexF64 { re: 0.0, im: 0.0 }; elements.len()]; delay_bins];
    for (bin, by_path) in delayed.iter_mut().enumerate() {
        let delay = bin as f64 * delay_step;
        for (path, accumulator) in by_path.iter_mut().enumerate() {
            for (frequency_index, (sample, frequency)) in capture.raw_iq()
                [path * frequencies.len()..(path + 1) * frequencies.len()]
                .iter()
                .zip(frequencies)
                .enumerate()
            {
                let relative_frequency = (*frequency - frequencies[0]) as f64;
                let calibration_index = path * frequencies.len() + frequency_index;
                accumulator.add_rotated(
                    *sample,
                    phase_calibration.correction_radians[calibration_index]
                        + 2.0 * std::f64::consts::PI * relative_frequency * delay,
                );
            }
        }
    }
    let total_energy = capture
        .raw_iq()
        .iter()
        .map(|sample| {
            let re = f64::from(sample.in_phase());
            let im = f64::from(sample.quadrature());
            re * re + im * im
        })
        .sum::<f64>();
    if !total_energy.is_finite() || total_energy == 0.0 {
        return Ok(Vec::new());
    }
    let azimuths = -6_i32..=6;
    let elevations = -2_i32..=2;
    let mut hypotheses = Vec::with_capacity(delay_bins * 65);
    for (bin, by_path) in delayed.iter().enumerate() {
        for azimuth_index in azimuths.clone() {
            let azimuth = f64::from(azimuth_index) * ANGLE_STEP_RADIANS;
            for elevation_index in elevations.clone() {
                let elevation = f64::from(elevation_index) * ANGLE_STEP_RADIANS;
                let direction = [
                    elevation.cos() * azimuth.cos(),
                    elevation.cos() * azimuth.sin(),
                    elevation.sin(),
                ];
                let mut beam = ComplexF64 { re: 0.0, im: 0.0 };
                for (sample, position) in by_path.iter().zip(elements) {
                    let phase =
                        2.0 * std::f64::consts::PI * center_frequency * dot(*position, direction)
                            / SPEED_OF_LIGHT_MPS;
                    beam.add_complex_rotated(*sample, phase);
                }
                hypotheses.push(ArrayPathCandidate {
                    azimuth_radians: azimuth,
                    elevation_radians: elevation,
                    world_direction: direction,
                    delay_seconds: bin as f64 * delay_step,
                    normalized_power: beam.power(),
                    angular_error_radians: ANGLE_STEP_RADIANS / 2.0
                        + (calibrated_wavelength(center_frequency) / aperture).atan(),
                    delay_error_seconds: delay_step / 2.0,
                    kind: PathKind::Unexplained,
                });
            }
        }
    }
    hypotheses.sort_by(|left, right| right.normalized_power.total_cmp(&left.normalized_power));
    let maximum = hypotheses.first().map_or(0.0, |candidate| candidate.normalized_power);
    if maximum == 0.0 || !maximum.is_finite() {
        return Ok(Vec::new());
    }
    let mut retained: Vec<ArrayPathCandidate> = Vec::with_capacity(MAX_PATH_CANDIDATES);
    for mut candidate in hypotheses {
        let separated = retained.iter().all(|existing| {
            (existing.delay_seconds - candidate.delay_seconds).abs() >= delay_step
                || (existing.azimuth_radians - candidate.azimuth_radians).abs()
                    >= 2.0 * ANGLE_STEP_RADIANS
                || (existing.elevation_radians - candidate.elevation_radians).abs()
                    >= 2.0 * ANGLE_STEP_RADIANS
        });
        if separated {
            candidate.normalized_power /= maximum;
            retained.push(candidate);
            if retained.len() == MAX_PATH_CANDIDATES {
                break;
            }
        }
    }
    Ok(retained)
}

fn calibrated_wavelength(frequency_hz: f64) -> f64 {
    SPEED_OF_LIGHT_MPS / frequency_hz
}

fn subtract(left: [f64; 3], right: [f64; 3]) -> [f64; 3] {
    [left[0] - right[0], left[1] - right[1], left[2] - right[2]]
}

fn cross(left: [f64; 3], right: [f64; 3]) -> [f64; 3] {
    [
        left[1] * right[2] - left[2] * right[1],
        left[2] * right[0] - left[0] * right[2],
        left[0] * right[1] - left[1] * right[0],
    ]
}

fn dot(left: [f64; 3], right: [f64; 3]) -> f64 {
    left[0] * right[0] + left[1] * right[1] + left[2] * right[2]
}

fn norm(value: [f64; 3]) -> f64 {
    dot(value, value).sqrt()
}

fn distance(left: [f64; 3], right: [f64; 3]) -> f64 {
    norm(subtract(left, right))
}

fn transform_direction(matrix: [f64; 16], direction: [f64; 3]) -> [f64; 3] {
    let transformed = [
        matrix[0] * direction[0] + matrix[1] * direction[1] + matrix[2] * direction[2],
        matrix[4] * direction[0] + matrix[5] * direction[1] + matrix[6] * direction[2],
        matrix[8] * direction[0] + matrix[9] * direction[1] + matrix[10] * direction[2],
    ];
    let length = norm(transformed);
    [transformed[0] / length, transformed[1] / length, transformed[2] / length]
}

/// Invalid array bytes, shape, calibration, or physical qualification.
#[derive(Debug)]
pub struct ArrayAdapterError {
    kind: Box<ArrayAdapterErrorKind>,
    backtrace: Box<Backtrace>,
}

#[derive(Debug)]
enum ArrayAdapterErrorKind {
    Invalid(&'static str),
    Measurement { context: &'static str, source: crate::measurement::MeasurementError },
}

impl ArrayAdapterError {
    fn new(message: &'static str) -> Self {
        Self {
            kind: Box::new(ArrayAdapterErrorKind::Invalid(message)),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    fn measurement(context: &'static str, source: crate::measurement::MeasurementError) -> Self {
        Self {
            kind: Box::new(ArrayAdapterErrorKind::Measurement { context, source }),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for ArrayAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind.as_ref() {
            ArrayAdapterErrorKind::Invalid(message) => formatter.write_str(message),
            ArrayAdapterErrorKind::Measurement { context, source } => {
                write!(formatter, "{context}: {source}")
            }
        }
    }
}

impl std::error::Error for ArrayAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.kind.as_ref() {
            ArrayAdapterErrorKind::Invalid(_) => None,
            ArrayAdapterErrorKind::Measurement { source, .. } => Some(source),
        }
    }
}

fn encode_capture(output: &mut Vec<u8>, capture: &ArrayCapture) -> Result<(), ArrayAdapterError> {
    let identity = capture.identity();
    put_text(output, identity.source().sensor().as_str())?;
    output.extend_from_slice(&identity.source().device().get().to_le_bytes());
    output.extend_from_slice(&identity.source().key_epoch().get().to_le_bytes());
    output.extend_from_slice(&identity.source().boot().get().to_le_bytes());
    output.extend_from_slice(&identity.event().transmitter().bytes());
    output.extend_from_slice(&identity.event().native_event().bytes());
    match identity.event().retransmission() {
        Some(retransmission) => {
            output.push(1);
            output.extend_from_slice(&retransmission.bytes());
        }
        None => output.push(0),
    }
    output.extend_from_slice(&identity.context().profile().bytes());
    output.extend_from_slice(&identity.context().radio().bytes());
    output.extend_from_slice(&identity.context().channel().bytes());
    put_text(output, identity.array_identity())?;
    put_text(output, identity.rf_device_identity())?;
    output.extend_from_slice(&capture.ltf().bytes());
    output.extend_from_slice(&capture.window().start().get().to_le_bytes());
    output.extend_from_slice(&capture.window().end().get().to_le_bytes());
    output.extend_from_slice(&capture.observed_utc_ns().to_le_bytes());
    let metadata = capture.native_metadata();
    output.extend_from_slice(&metadata.bandwidth_hz().to_le_bytes());
    output.extend_from_slice(&metadata.rate_code().to_le_bytes());
    match metadata.mcs() {
        Some(mcs) => {
            output.push(1);
            output.extend_from_slice(&mcs.to_le_bytes());
        }
        None => output.push(0),
    }
    output.extend_from_slice(&metadata.received_host_monotonic_ns().to_le_bytes());
    put_count_u16(output, metadata.path_facts().len())?;
    for facts in metadata.path_facts() {
        output.extend_from_slice(&facts.native_antenna().to_le_bytes());
        output.extend_from_slice(&facts.rssi_dbm_hundredths().to_le_bytes());
        output.extend_from_slice(&facts.noise_dbm_hundredths().to_le_bytes());
        match facts.gain_db_hundredths() {
            Some(gain) => {
                output.push(1);
                output.extend_from_slice(&gain.to_le_bytes());
            }
            None => output.push(0),
        }
    }
    put_count_u16(output, capture.frequencies_hz().len())?;
    for frequency in capture.frequencies_hz() {
        output.extend_from_slice(&frequency.to_le_bytes());
    }
    put_count_u16(output, capture.signal_paths().len())?;
    for path in capture.signal_paths() {
        // SignalPath is intentionally opaque to callers; its canonical debug-free
        // numeric accessors are added at the qualification boundary below.
        output.extend_from_slice(&path.signal_path().tx_stream().to_le_bytes());
        output.extend_from_slice(&path.signal_path().rx_chain().to_le_bytes());
        output.extend_from_slice(&path.native_path().bytes());
        put_text(output, path.tx_logical_path())?;
        put_text(output, path.rx_logical_path())?;
    }
    let sample_count = u32::try_from(capture.raw_iq().len())
        .map_err(|_| ArrayAdapterError::new("array sample count exceeds its format"))?;
    output.extend_from_slice(&sample_count.to_le_bytes());
    for (sample, state) in capture.raw_iq().iter().zip(capture.sample_states()) {
        output.extend_from_slice(&sample.in_phase().to_le_bytes());
        output.extend_from_slice(&sample.quadrature().to_le_bytes());
        output.push(state.code());
    }
    Ok(())
}

fn decode_capture(reader: &mut Reader<'_>) -> Result<ArrayCapture, ArrayAdapterError> {
    let sensor = reader.text()?;
    let source = SourceInstance::new(
        SensorId::try_from(sensor.as_str())
            .map_err(|_| ArrayAdapterError::new("array sensor identity is invalid"))?,
        DeviceId::new(reader.u64()?),
        KeyEpoch::new(reader.u16()?)
            .ok_or_else(|| ArrayAdapterError::new("array key epoch is invalid"))?,
        BootGeneration::new(reader.u32()?)
            .ok_or_else(|| ArrayAdapterError::new("array boot generation is invalid"))?,
    );
    let transmitter = TransmitterIdentity::new(reader.fixed()?);
    let native_event = NativeEventIdentity::new(reader.fixed()?);
    let retransmission = match reader.u8()? {
        0 => None,
        1 => Some(RetransmissionIdentity::new(reader.fixed()?)),
        _ => return Err(ArrayAdapterError::new("array retransmission marker is invalid")),
    };
    let context = MeasurementContext::new(
        crate::measurement::ProfileIdentity::new(reader.fixed()?),
        crate::measurement::RadioIdentity::new(reader.fixed()?),
        crate::measurement::ChannelIdentity::new(reader.fixed()?),
    );
    let identity = ArrayCaptureIdentity::new(
        source,
        EventIdentity::new(transmitter, native_event, retransmission),
        context,
        reader.text()?,
        reader.text()?,
    )?;
    let ltf = LtfIdentity::new(reader.fixed()?);
    let window = TickRange::new(SourceTick::new(reader.u64()?), SourceTick::new(reader.u64()?))?;
    let observed_utc_ns = reader.u64()?;
    let bandwidth_hz = reader.u32()?;
    let rate_code = reader.u32()?;
    let mcs = match reader.u8()? {
        0 => None,
        1 => Some(reader.u16()?),
        _ => return Err(ArrayAdapterError::new("array MCS marker is invalid")),
    };
    let received_host_monotonic_ns = reader.u64()?;
    let path_fact_count = reader.count(MAX_SIGNAL_PATHS)?;
    let mut path_facts = Vec::with_capacity(path_fact_count);
    for _ in 0..path_fact_count {
        let native_antenna = reader.u16()?;
        let rssi = reader.i16()?;
        let noise = reader.i16()?;
        let gain = match reader.u8()? {
            0 => None,
            1 => Some(reader.i16()?),
            _ => return Err(ArrayAdapterError::new("array gain marker is invalid")),
        };
        path_facts.push(ArrayPathRadioFacts::new(native_antenna, rssi, noise, gain));
    }
    let native_metadata = ArrayNativeMetadata::new(
        bandwidth_hz,
        rate_code,
        mcs,
        received_host_monotonic_ns,
        path_facts,
    )?;
    let frequency_count = reader.count(MAX_FREQUENCIES)?;
    let mut frequencies = Vec::with_capacity(frequency_count);
    for _ in 0..frequency_count {
        frequencies.push(reader.u64()?);
    }
    let path_count = reader.count(MAX_SIGNAL_PATHS)?;
    let mut paths = Vec::with_capacity(path_count);
    for _ in 0..path_count {
        paths.push(ArraySignalPath::new(
            SignalPath::new(reader.u16()?, reader.u16()?),
            NativeArrayPathIdentity::new(reader.fixed()?),
            reader.text()?,
            reader.text()?,
        )?);
    }
    let sample_count = reader.u32()? as usize;
    if sample_count > MAX_IQ_SAMPLES {
        return Err(ArrayAdapterError::new("array sample count exceeds its limit"));
    }
    let mut iq = Vec::with_capacity(sample_count);
    let mut states = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        iq.push(ComplexI16::new(reader.i16()?, reader.i16()?));
        states.push(
            SampleState::from_code(reader.u8()?)
                .ok_or_else(|| ArrayAdapterError::new("array sample state is invalid"))?,
        );
    }
    ArrayCapture::new(
        identity,
        ltf,
        window,
        observed_utc_ns,
        native_metadata,
        frequencies,
        paths,
        iq,
        states,
    )
}

fn require_text(value: &str) -> Result<(), ArrayAdapterError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(ArrayAdapterError::new("array text identity is invalid"));
    }
    Ok(())
}

fn collect_bounded<T>(
    values: impl IntoIterator<Item = T>,
    maximum: usize,
    message: &'static str,
) -> Result<Vec<T>, ArrayAdapterError> {
    let values = values.into_iter().take(maximum.saturating_add(1)).collect::<Vec<_>>();
    if values.len() > maximum {
        return Err(ArrayAdapterError::new(message));
    }
    Ok(values)
}

fn put_text(output: &mut Vec<u8>, value: &str) -> Result<(), ArrayAdapterError> {
    require_text(value)?;
    put_count_u16(output, value.len())?;
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_count_u16(output: &mut Vec<u8>, value: usize) -> Result<(), ArrayAdapterError> {
    let value = u16::try_from(value)
        .map_err(|_| ArrayAdapterError::new("array collection exceeds its format"))?;
    output.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ArrayAdapterError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| ArrayAdapterError::new("array capture offset overflows"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ArrayAdapterError::new("array capture is truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ArrayAdapterError> {
        self.take(N)?.try_into().map_err(|_| ArrayAdapterError::new("array fixed field is invalid"))
    }

    fn u8(&mut self) -> Result<u8, ArrayAdapterError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ArrayAdapterError> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, ArrayAdapterError> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, ArrayAdapterError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    fn i16(&mut self) -> Result<i16, ArrayAdapterError> {
        Ok(i16::from_le_bytes(self.fixed()?))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, ArrayAdapterError> {
        let value = self.u16()? as usize;
        if value == 0 || value > maximum {
            return Err(ArrayAdapterError::new("array collection count is invalid"));
        }
        Ok(value)
    }

    fn text(&mut self) -> Result<String, ArrayAdapterError> {
        let length = self.count(MAX_TEXT_BYTES)?;
        let bytes = self.take(length)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| ArrayAdapterError::new("array text identity is not UTF-8"))?;
        Ok(value.to_owned())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

impl From<crate::measurement::MeasurementError> for ArrayAdapterError {
    fn from(source: crate::measurement::MeasurementError) -> Self {
        Self::measurement("could not reconstruct the array capture time window", source)
    }
}
