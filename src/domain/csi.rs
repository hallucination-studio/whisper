//! Dynamic native-coordinate CSI values and profile identity.

use std::collections::BTreeMap;
use std::fmt;

use ciborium::ser::into_writer;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::identity::{DecoderVersion, HardwareKind, RadioLinkId, SensorId, SessionId};
use super::time::{FrameTiming, TimeQuality};

/// An error found while constructing a native CSI layout.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LayoutError {
    /// No path was supplied.
    #[error("CSI layout requires at least one path")]
    EmptyPaths,
    /// No sample coordinate was supplied.
    #[error("CSI layout requires at least one sample coordinate")]
    EmptySamples,
    /// A path appeared more than once.
    #[error("CSI layout contains duplicate path {0:?}")]
    DuplicatePath(CsiPath),
    /// A physical sample coordinate appeared more than once.
    #[error("CSI layout contains duplicate sample coordinate {0:?}")]
    DuplicateCoordinate(CsiSampleCoordinate),
    /// The sample order is not supported by this first slice.
    #[error("CSI sample order {0:?} is unsupported")]
    UnsupportedOrder(SampleOrder),
    /// The path/sample product could not be represented by `usize`.
    #[error("CSI path/sample count overflows usize")]
    CountOverflow,
}

/// A physical or protocol-native path coordinate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CsiPath {
    /// A protocol-provided transmit-stream/receive-chain coordinate.
    TxRx {
        /// Transmit stream ordinal.
        tx_stream: u16,
        /// Receive-chain ordinal.
        rx_chain: u16,
    },
    /// A protocol path whose physical meaning is intentionally opaque.
    RawPathOrdinal(u16),
}

/// The ordering of flattened complex samples in a capture.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SampleOrder {
    /// All samples for one path, followed by all samples for the next path.
    #[default]
    PathThenSample,
}

/// A sample-coordinate value with explicit native semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CsiSampleCoordinate {
    /// A protocol ordinal without a physical tone interpretation.
    OpaqueSampleOrdinal(u16),
    /// An IEEE tone index supplied by the protocol.
    IeeeToneIndex(i16),
    /// A protocol-provided absolute frequency in hertz.
    FrequencyHz(u64),
}

/// The native sample axis carried by a capture profile.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum CsiSampleAxis {
    /// Opaque ordinal coordinates from zero up to `count - 1`.
    OpaqueSampleOrdinal {
        /// Number of opaque coordinates in the axis.
        count: u16,
    },
    /// Explicit IEEE tone indices in protocol order.
    IeeeToneIndex(Box<[i16]>),
    /// Explicit absolute frequencies in hertz in protocol order.
    FrequencyHz(Box<[u64]>),
}

impl CsiSampleAxis {
    /// Creates an opaque ordinal axis.
    pub const fn try_opaque(count: u16) -> Result<Self, LayoutError> {
        if count == 0 {
            return Err(LayoutError::EmptySamples);
        }
        Ok(Self::OpaqueSampleOrdinal { count })
    }

    /// Creates an IEEE tone axis after checking for emptiness and duplicates.
    pub fn try_ieee_tones(values: impl Into<Box<[i16]>>) -> Result<Self, LayoutError> {
        let values = values.into();
        if values.is_empty() {
            return Err(LayoutError::EmptySamples);
        }
        for (index, value) in values.iter().enumerate() {
            if values[..index].contains(value) {
                return Err(LayoutError::DuplicateCoordinate(CsiSampleCoordinate::IeeeToneIndex(
                    *value,
                )));
            }
        }
        Ok(Self::IeeeToneIndex(values))
    }

    /// Creates a frequency axis after checking for emptiness and duplicates.
    pub fn try_frequencies_hz(values: impl Into<Box<[u64]>>) -> Result<Self, LayoutError> {
        let values = values.into();
        if values.is_empty() {
            return Err(LayoutError::EmptySamples);
        }
        for (index, value) in values.iter().enumerate() {
            if values[..index].contains(value) {
                return Err(LayoutError::DuplicateCoordinate(CsiSampleCoordinate::FrequencyHz(
                    *value,
                )));
            }
        }
        Ok(Self::FrequencyHz(values))
    }

    /// Returns the number of native sample coordinates.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::OpaqueSampleOrdinal { count } => *count as usize,
            Self::IeeeToneIndex(values) => values.len(),
            Self::FrequencyHz(values) => values.len(),
        }
    }

    /// Reports whether the axis contains no coordinates.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a coordinate by native ordinal.
    #[must_use]
    pub fn coordinate_at(&self, index: usize) -> Option<CsiSampleCoordinate> {
        match self {
            Self::OpaqueSampleOrdinal { count } => (*count as usize > index)
                .then_some(CsiSampleCoordinate::OpaqueSampleOrdinal(index as u16)),
            Self::IeeeToneIndex(values) => {
                values.get(index).copied().map(CsiSampleCoordinate::IeeeToneIndex)
            }
            Self::FrequencyHz(values) => {
                values.get(index).copied().map(CsiSampleCoordinate::FrequencyHz)
            }
        }
    }

    /// Returns all native coordinates in protocol order.
    #[must_use]
    pub fn coordinates(&self) -> Vec<CsiSampleCoordinate> {
        match self {
            Self::OpaqueSampleOrdinal { count } => {
                (0..*count).map(CsiSampleCoordinate::OpaqueSampleOrdinal).collect()
            }
            Self::IeeeToneIndex(values) => {
                values.iter().copied().map(CsiSampleCoordinate::IeeeToneIndex).collect()
            }
            Self::FrequencyHz(values) => {
                values.iter().copied().map(CsiSampleCoordinate::FrequencyHz).collect()
            }
        }
    }
}

/// A validated dynamic path × sample layout.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct CsiLayout {
    paths: Box<[CsiPath]>,
    samples: CsiSampleAxis,
    order: SampleOrder,
}

impl CsiLayout {
    /// Creates a layout and validates all coordinate invariants.
    pub fn try_new(
        paths: impl Into<Box<[CsiPath]>>,
        samples: CsiSampleAxis,
        order: SampleOrder,
    ) -> Result<Self, LayoutError> {
        let paths = paths.into();
        if paths.is_empty() {
            return Err(LayoutError::EmptyPaths);
        }
        for (index, path) in paths.iter().enumerate() {
            if paths[..index].contains(path) {
                return Err(LayoutError::DuplicatePath(*path));
            }
        }
        validate_axis(&samples)?;
        if !matches!(order, SampleOrder::PathThenSample) {
            return Err(LayoutError::UnsupportedOrder(order));
        }
        checked_coordinate_count(paths.len(), samples.len())?;
        Ok(Self { paths, samples, order })
    }

    /// Returns paths in native order.
    #[must_use]
    pub fn paths(&self) -> &[CsiPath] {
        &self.paths
    }

    /// Returns the native sample axis.
    #[must_use]
    pub const fn samples(&self) -> &CsiSampleAxis {
        &self.samples
    }

    /// Returns the flattening order.
    #[must_use]
    pub const fn order(&self) -> SampleOrder {
        self.order
    }

    /// Returns the checked path/sample product.
    pub fn sample_count(&self) -> Result<usize, LayoutError> {
        checked_coordinate_count(self.paths.len(), self.samples.len())
    }

    /// Returns native path/coordinate pairs in flattened sample order.
    #[must_use]
    pub fn coordinates(&self) -> Vec<(CsiPath, CsiSampleCoordinate)> {
        self.paths
            .iter()
            .flat_map(|path| {
                self.samples.coordinates().into_iter().map(move |coordinate| (*path, coordinate))
            })
            .collect()
    }
}

/// The explicit ordering convention for integer complex samples.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ComplexOrder {
    /// Samples are encoded real then imaginary.
    RealImaginary,
    /// Samples are encoded imaginary then real.
    ImaginaryReal,
}

/// Integer sample encoding and its reduced positive scale convention.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SampleEncoding {
    signed_bits: u8,
    scale_numerator: u32,
    scale_denominator: u32,
    complex_order: ComplexOrder,
}

impl SampleEncoding {
    /// Creates a checked sample encoding.
    pub const fn try_new(
        signed_bits: u8,
        scale_numerator: u32,
        scale_denominator: u32,
        complex_order: ComplexOrder,
    ) -> Result<Self, ProfileError> {
        if signed_bits == 0 || signed_bits > 32 {
            return Err(ProfileError::InvalidEncodingBits(signed_bits));
        }
        if scale_numerator == 0 || scale_denominator == 0 {
            return Err(ProfileError::InvalidScale);
        }
        let divisor = gcd(scale_numerator, scale_denominator);
        Ok(Self {
            signed_bits,
            scale_numerator: scale_numerator / divisor,
            scale_denominator: scale_denominator / divisor,
            complex_order,
        })
    }

    /// Returns the signed integer width.
    #[must_use]
    pub const fn signed_bits(self) -> u8 {
        self.signed_bits
    }

    /// Returns the reduced scale numerator.
    #[must_use]
    pub const fn scale_numerator(self) -> u32 {
        self.scale_numerator
    }

    /// Returns the reduced scale denominator.
    #[must_use]
    pub const fn scale_denominator(self) -> u32 {
        self.scale_denominator
    }

    /// Returns the complex byte ordering convention.
    #[must_use]
    pub const fn complex_order(self) -> ComplexOrder {
        self.complex_order
    }
}

const fn gcd(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn checked_coordinate_count(path_count: usize, sample_count: usize) -> Result<usize, LayoutError> {
    path_count.checked_mul(sample_count).ok_or(LayoutError::CountOverflow)
}

fn validate_axis(axis: &CsiSampleAxis) -> Result<(), LayoutError> {
    if axis.is_empty() {
        return Err(LayoutError::EmptySamples);
    }
    match axis {
        CsiSampleAxis::OpaqueSampleOrdinal { .. } => Ok(()),
        CsiSampleAxis::IeeeToneIndex(values) => {
            for (index, value) in values.iter().enumerate() {
                if values[..index].contains(value) {
                    return Err(LayoutError::DuplicateCoordinate(
                        CsiSampleCoordinate::IeeeToneIndex(*value),
                    ));
                }
            }
            Ok(())
        }
        CsiSampleAxis::FrequencyHz(values) => {
            for (index, value) in values.iter().enumerate() {
                if values[..index].contains(value) {
                    return Err(LayoutError::DuplicateCoordinate(
                        CsiSampleCoordinate::FrequencyHz(*value),
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Protocol-level phase capability/state.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PhaseState {
    /// No phase values are available.
    #[default]
    Unavailable,
    /// Raw phase can be displayed but is not calibrated for inference.
    Raw,
    /// Calibrated phase is available to a compatible algorithm.
    Calibrated,
}

/// One integer I/Q sample with an explicit validity bit.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize)]
pub struct IqSample {
    /// Real component.
    pub i: i32,
    /// Imaginary component.
    pub q: i32,
    /// Whether this pair is eligible for conditioning.
    pub valid: bool,
}

impl IqSample {
    /// Creates a valid sample.
    #[must_use]
    pub const fn new(i: i32, q: i32) -> Self {
        Self { i, q, valid: true }
    }

    /// Creates an explicitly invalid sample while preserving its raw values.
    #[must_use]
    pub const fn invalid(i: i32, q: i32) -> Self {
        Self { i, q, valid: false }
    }
}

/// A capture profile descriptor whose hash defines the compatibility boundary.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct ProfileDescriptor {
    /// Hardware family.
    pub hardware: HardwareKind,
    /// Firmware identity.
    pub firmware: Box<str>,
    /// Decoder identity.
    pub decoder_version: Box<str>,
    /// Wire-layout/acquisition capability identity.
    pub capability_id: Box<str>,
    /// Explicit acquisition and validity semantics.
    pub acquisition: AcquisitionCapabilities,
    /// Measured channel, if the protocol supplied one.
    pub channel: Option<u16>,
    /// Measured centre frequency in hertz, if known.
    pub centre_frequency_hz: Option<u64>,
    /// Measured bandwidth in hertz, if known.
    pub bandwidth_hz: Option<u64>,
    /// PPDU/PHY metadata, if known.
    pub ppdu: Option<PpduKind>,
    /// Native path/sample layout.
    pub layout: CsiLayout,
    /// Integer encoding and scale convention.
    pub encoding: SampleEncoding,
    /// Phase capability/state.
    pub phase_state: PhaseState,
    /// Event-time quality supported by this profile.
    pub time_quality: TimeQuality,
    /// Clock domain when corrected timestamps are supported.
    pub clock_domain: Option<Box<str>>,
}

/// Known PPDU/PHY categories supplied by a capture protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PpduKind {
    /// Legacy/non-HT frame.
    Legacy,
    /// HT frame.
    Ht,
    /// HE frame.
    He,
}

/// Concrete acquisition choices that affect profile compatibility.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AcquisitionCapabilities {
    /// Capture-driver acquisition mode.
    pub mode: AcquisitionMode,
    /// LTF selection made by firmware/driver.
    pub ltf_selection: LtfSelection,
    /// How multiple LTF blocks are merged.
    pub ltf_merge: LtfMerge,
    /// Frame-validity dialect available to the decoder.
    pub validity_dialect: ValidityDialect,
}

/// Capture-driver acquisition modes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AcquisitionMode {
    /// The legacy Wi-Fi CSI acquisition path.
    WifiCsi,
}

/// LTF selection semantics included in a profile identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum LtfSelection {
    /// Legacy LTF.
    Legacy,
    /// HT LTF.
    Ht,
    /// HE LTF.
    He,
    /// The protocol did not identify its LTF selection.
    Unknown,
}

/// LTF merge semantics included in a profile identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum LtfMerge {
    /// No merge occurred.
    None,
    /// Blocks were merged in the firmware-defined order.
    FirmwareDefined,
    /// Merge semantics were not supplied.
    Unknown,
}

/// Frame-validity semantics included in a profile identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ValidityDialect {
    /// An explicit per-frame validity flag is available.
    ExplicitFlag,
    /// The first raw words are conservatively invalidated.
    FirstWordInvalid,
    /// The required validity flag is absent.
    MissingFrameValidity,
    /// The protocol did not identify validity semantics.
    Unknown,
}

/// An error found in a capture profile descriptor or its canonical encoding.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProfileError {
    /// A required descriptor string was empty.
    #[error("capture profile field {0} must not be empty")]
    EmptyField(&'static str),
    /// Integer sample width was outside the representable range.
    #[error("sample encoding signed width {0} is outside 1..=32")]
    InvalidEncodingBits(u8),
    /// Scale numerator or denominator was zero.
    #[error("sample scale numerator and denominator must be positive")]
    InvalidScale,
    /// A corrected timestamp profile omitted its clock domain.
    #[error("clock-corrected profile requires a clock domain")]
    MissingClockDomain,
    /// A receive-only profile supplied a clock domain.
    #[error("receive-only profile must not supply a clock domain")]
    UnexpectedClockDomain,
    /// The layout was invalid.
    #[error(transparent)]
    Layout(#[from] LayoutError),
    /// Canonical CBOR serialization failed.
    #[error("canonical profile encoding failed: {0}")]
    CanonicalEncoding(String),
    /// A profile ID was already associated with a different descriptor.
    #[error("capture profile id {id} is already associated with a different descriptor")]
    DescriptorConflict {
        /// Digest already associated with a different descriptor.
        id: CaptureProfileId,
    },
}

/// A validated capture profile and its canonical ID.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CaptureProfile {
    descriptor: ProfileDescriptor,
    id: CaptureProfileId,
}

impl CaptureProfile {
    /// Validates a descriptor and derives its canonical SHA-256 identity.
    pub fn try_new(descriptor: ProfileDescriptor) -> Result<Self, ProfileError> {
        validate_profile_descriptor(&descriptor)?;
        let canonical = canonical_profile_bytes(&descriptor)?;
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        Ok(Self { descriptor, id: CaptureProfileId::from_bytes(digest) })
    }

    /// Returns the immutable descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ProfileDescriptor {
        &self.descriptor
    }

    /// Returns the canonical profile ID.
    #[must_use]
    pub const fn id(&self) -> CaptureProfileId {
        self.id
    }

    /// Returns the exact canonical bytes used for hashing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProfileError> {
        canonical_profile_bytes(&self.descriptor)
    }
}

/// An opaque profile digest represented as 32 bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CaptureProfileId([u8; 32]);

impl CaptureProfileId {
    /// Creates an ID from a SHA-256 digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CaptureProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A runtime catalog that interns validated profile descriptors by digest.
#[derive(Clone, Debug, Default)]
pub struct ProfileCatalog {
    profiles: BTreeMap<CaptureProfileId, CaptureProfile>,
}

impl ProfileCatalog {
    /// Interns a descriptor, rejecting an ID collision with different bytes.
    pub fn intern(&mut self, profile: CaptureProfile) -> Result<CaptureProfileId, ProfileError> {
        let id = profile.id();
        if let Some(existing) = self.profiles.get(&id) {
            if existing != &profile {
                return Err(ProfileError::DescriptorConflict { id });
            }
            return Ok(id);
        }
        self.profiles.insert(id, profile);
        Ok(id)
    }

    /// Looks up a profile by its canonical ID.
    #[must_use]
    pub fn get(&self, id: &CaptureProfileId) -> Option<&CaptureProfile> {
        self.profiles.get(id)
    }

    /// Returns an immutable catalog snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ProfileCatalogSnapshot {
        ProfileCatalogSnapshot { profiles: self.profiles.clone() }
    }
}

/// An immutable profile catalog view suitable for read-side consumers.
#[derive(Clone, Debug, Default)]
pub struct ProfileCatalogSnapshot {
    profiles: BTreeMap<CaptureProfileId, CaptureProfile>,
}

impl ProfileCatalogSnapshot {
    /// Looks up a profile by ID.
    #[must_use]
    pub fn get(&self, id: &CaptureProfileId) -> Option<&CaptureProfile> {
        self.profiles.get(id)
    }

    /// Iterates profiles in canonical digest order.
    pub fn iter(&self) -> impl Iterator<Item = (&CaptureProfileId, &CaptureProfile)> {
        self.profiles.iter()
    }
}

/// Dynamic path × native-coordinate integer CSI samples.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CsiCapture {
    layout: CsiLayout,
    samples: Box<[IqSample]>,
    encoding: SampleEncoding,
    phase_state: PhaseState,
}

impl CsiCapture {
    /// Constructs a capture after checking its exact path/sample cardinality.
    pub fn try_new(
        layout: CsiLayout,
        samples: impl Into<Box<[IqSample]>>,
        encoding: SampleEncoding,
        phase_state: PhaseState,
    ) -> Result<Self, CsiCaptureError> {
        let samples = samples.into();
        let expected = layout.sample_count()?;
        if samples.len() != expected {
            return Err(CsiCaptureError::SampleLength { expected, actual: samples.len() });
        }
        Ok(Self { layout, samples, encoding, phase_state })
    }

    /// Returns the native layout.
    #[must_use]
    pub const fn layout(&self) -> &CsiLayout {
        &self.layout
    }

    /// Returns samples in the layout's path-major order.
    #[must_use]
    pub fn samples(&self) -> &[IqSample] {
        &self.samples
    }

    /// Returns the encoding convention.
    #[must_use]
    pub const fn encoding(&self) -> SampleEncoding {
        self.encoding
    }

    /// Returns the phase capability/state.
    #[must_use]
    pub const fn phase_state(&self) -> PhaseState {
        self.phase_state
    }

    /// Returns native coordinate pairs in the same order as `samples`.
    #[must_use]
    pub fn coordinates(&self) -> Vec<(CsiPath, CsiSampleCoordinate)> {
        self.layout.coordinates()
    }
}

/// An error found while constructing a CSI capture.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CsiCaptureError {
    /// The layout's path/sample product overflowed.
    #[error(transparent)]
    Layout(#[from] LayoutError),
    /// The sample count did not match the layout.
    #[error("CSI sample length mismatch: expected {expected}, received {actual}")]
    SampleLength {
        /// Number of samples implied by the layout.
        expected: usize,
        /// Number of samples supplied by the capture.
        actual: usize,
    },
}

/// The session ordering and decoder identity attached to a decoded observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct InputReceipt {
    session: SessionId,
    record_seq: u64,
    decoder_version: DecoderVersion,
}

impl InputReceipt {
    /// Combines validated session and decoder identities with the session order.
    #[must_use]
    pub(crate) fn new(
        session: SessionId,
        record_seq: u64,
        decoder_version: DecoderVersion,
    ) -> Self {
        Self { session, record_seq, decoder_version }
    }

    /// Returns the source session.
    #[must_use]
    pub(crate) const fn session(&self) -> &SessionId {
        &self.session
    }

    /// Returns the total session record sequence.
    #[must_use]
    pub(crate) const fn record_seq(&self) -> u64 {
        self.record_seq
    }

    /// Returns the decoder version.
    #[must_use]
    pub(crate) const fn decoder_version(&self) -> &DecoderVersion {
        &self.decoder_version
    }
}

/// Typed radio facts shared by Wi-Fi CSI decoders.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RadioMetadata {
    channel: Option<u16>,
    centre_frequency_hz: Option<u64>,
    bandwidth_hz: Option<u64>,
    ppdu: Option<PpduKind>,
    rssi_dbm: i8,
    noise_floor_dbm: i8,
}

/// An error found while constructing typed radio metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[expect(
    clippy::enum_variant_names,
    reason = "Each variant names the known radio quantity that was rejected"
)]
pub(crate) enum RadioMetadataError {
    /// A known channel was zero.
    #[error("known radio channel must be non-zero")]
    ZeroChannel,
    /// A known centre frequency was zero.
    #[error("known radio centre frequency must be non-zero")]
    ZeroCentreFrequency,
    /// A known bandwidth was zero.
    #[error("known radio bandwidth must be non-zero")]
    ZeroBandwidth,
}

impl RadioMetadata {
    /// Constructs metadata after rejecting zero-valued known quantities.
    pub(crate) const fn try_new(
        channel: Option<u16>,
        centre_frequency_hz: Option<u64>,
        bandwidth_hz: Option<u64>,
        ppdu: Option<PpduKind>,
        rssi_dbm: i8,
        noise_floor_dbm: i8,
    ) -> Result<Self, RadioMetadataError> {
        if matches!(channel, Some(0)) {
            return Err(RadioMetadataError::ZeroChannel);
        }
        if matches!(centre_frequency_hz, Some(0)) {
            return Err(RadioMetadataError::ZeroCentreFrequency);
        }
        if matches!(bandwidth_hz, Some(0)) {
            return Err(RadioMetadataError::ZeroBandwidth);
        }
        Ok(Self { channel, centre_frequency_hz, bandwidth_hz, ppdu, rssi_dbm, noise_floor_dbm })
    }

    /// Returns the configured channel when known.
    #[must_use]
    pub(crate) const fn channel(self) -> Option<u16> {
        self.channel
    }

    /// Returns the centre frequency in hertz when known.
    #[must_use]
    pub(crate) const fn centre_frequency_hz(self) -> Option<u64> {
        self.centre_frequency_hz
    }

    /// Returns the bandwidth in hertz when known.
    #[must_use]
    pub(crate) const fn bandwidth_hz(self) -> Option<u64> {
        self.bandwidth_hz
    }

    /// Returns the PPDU kind when known.
    #[must_use]
    pub(crate) const fn ppdu(self) -> Option<PpduKind> {
        self.ppdu
    }

    /// Returns the received signal strength in dBm.
    #[must_use]
    pub(crate) const fn rssi_dbm(self) -> i8 {
        self.rssi_dbm
    }

    /// Returns the noise floor in dBm.
    #[must_use]
    pub(crate) const fn noise_floor_dbm(self) -> i8 {
        self.noise_floor_dbm
    }
}

/// A typed dynamic CSI observation after route/profile resolution.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct CsiObservation {
    input: InputReceipt,
    sensor: SensorId,
    hardware: HardwareKind,
    link: RadioLinkId,
    device_sequence: u32,
    timing: FrameTiming,
    radio: RadioMetadata,
    profile: CaptureProfileId,
    csi: CsiCapture,
}

impl CsiObservation {
    /// Combines validated identity, timing, radio, profile, and CSI values.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "The envelope constructor mirrors its nine architecture-defined fields"
    )]
    pub(crate) fn new(
        input: InputReceipt,
        sensor: SensorId,
        hardware: HardwareKind,
        link: RadioLinkId,
        device_sequence: u32,
        timing: FrameTiming,
        radio: RadioMetadata,
        profile: CaptureProfileId,
        csi: CsiCapture,
    ) -> Self {
        Self { input, sensor, hardware, link, device_sequence, timing, radio, profile, csi }
    }

    /// Returns the input receipt.
    #[must_use]
    pub(crate) const fn input(&self) -> &InputReceipt {
        &self.input
    }

    /// Returns the resolved receiving sensor.
    #[must_use]
    pub(crate) const fn sensor(&self) -> &SensorId {
        &self.sensor
    }

    /// Returns the resolved hardware family.
    #[must_use]
    pub(crate) const fn hardware(&self) -> HardwareKind {
        self.hardware
    }

    /// Returns the resolved radio link.
    #[must_use]
    pub(crate) const fn link(&self) -> &RadioLinkId {
        &self.link
    }

    /// Returns the device sequence number.
    #[must_use]
    pub(crate) const fn device_sequence(&self) -> u32 {
        self.device_sequence
    }

    /// Returns the frame timing and provenance.
    #[must_use]
    pub(crate) const fn timing(&self) -> &FrameTiming {
        &self.timing
    }

    /// Returns typed radio metadata.
    #[must_use]
    pub(crate) const fn radio(&self) -> RadioMetadata {
        self.radio
    }

    /// Returns the resolved capture profile identity.
    #[must_use]
    pub(crate) const fn profile(&self) -> CaptureProfileId {
        self.profile
    }

    /// Returns the dynamic CSI capture.
    #[must_use]
    pub(crate) const fn csi(&self) -> &CsiCapture {
        &self.csi
    }
}

fn validate_profile_descriptor(descriptor: &ProfileDescriptor) -> Result<(), ProfileError> {
    if descriptor.firmware.trim().is_empty() {
        return Err(ProfileError::EmptyField("firmware"));
    }
    if descriptor.decoder_version.trim().is_empty() {
        return Err(ProfileError::EmptyField("decoder_version"));
    }
    if descriptor.capability_id.trim().is_empty() {
        return Err(ProfileError::EmptyField("capability_id"));
    }
    let _ = descriptor.layout.sample_count()?;
    match descriptor.time_quality {
        TimeQuality::ClockCorrected => match descriptor.clock_domain.as_deref() {
            None => Err(ProfileError::MissingClockDomain),
            Some(clock_domain) if clock_domain.trim().is_empty() => {
                Err(ProfileError::EmptyField("clock_domain"))
            }
            Some(_) => Ok(()),
        },
        TimeQuality::ReceiveOnly | TimeQuality::Unknown => {
            if descriptor.clock_domain.is_some() {
                Err(ProfileError::UnexpectedClockDomain)
            } else {
                Ok(())
            }
        }
    }
}

const PROFILE_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
struct CanonicalProfile<'a> {
    schema_version: u16,
    hardware: &'a HardwareKind,
    firmware: &'a str,
    decoder_version: &'a str,
    capability_id: &'a str,
    acquisition: &'a AcquisitionCapabilities,
    channel: &'a Option<u16>,
    centre_frequency_hz: &'a Option<u64>,
    bandwidth_hz: &'a Option<u64>,
    ppdu: &'a Option<PpduKind>,
    layout: &'a CsiLayout,
    encoding: &'a SampleEncoding,
    phase_state: &'a PhaseState,
    time_quality: &'a TimeQuality,
    clock_domain: &'a Option<Box<str>>,
}

fn canonical_profile_bytes(descriptor: &ProfileDescriptor) -> Result<Vec<u8>, ProfileError> {
    let value = CanonicalProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        hardware: &descriptor.hardware,
        firmware: &descriptor.firmware,
        decoder_version: &descriptor.decoder_version,
        capability_id: &descriptor.capability_id,
        acquisition: &descriptor.acquisition,
        channel: &descriptor.channel,
        centre_frequency_hz: &descriptor.centre_frequency_hz,
        bandwidth_hz: &descriptor.bandwidth_hz,
        ppdu: &descriptor.ppdu,
        layout: &descriptor.layout,
        encoding: &descriptor.encoding,
        phase_state: &descriptor.phase_state,
        time_quality: &descriptor.time_quality,
        clock_domain: &descriptor.clock_domain,
    };
    let mut bytes = Vec::new();
    into_writer(&value, &mut bytes)
        .map_err(|error| ProfileError::CanonicalEncoding(error.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> CaptureProfile {
        let layout = CsiLayout::try_new(
            vec![CsiPath::RawPathOrdinal(0)],
            CsiSampleAxis::try_opaque(1).expect("non-empty axis"),
            SampleOrder::PathThenSample,
        )
        .expect("valid layout");
        CaptureProfile::try_new(ProfileDescriptor {
            hardware: HardwareKind::Esp32S3,
            firmware: "test-firmware".into(),
            decoder_version: "test-decoder".into(),
            capability_id: "test-capability".into(),
            acquisition: AcquisitionCapabilities {
                mode: AcquisitionMode::WifiCsi,
                ltf_selection: LtfSelection::Legacy,
                ltf_merge: LtfMerge::None,
                validity_dialect: ValidityDialect::FirstWordInvalid,
            },
            channel: None,
            centre_frequency_hz: None,
            bandwidth_hz: None,
            ppdu: None,
            layout,
            encoding: SampleEncoding::try_new(8, 1, 1, ComplexOrder::RealImaginary)
                .expect("valid encoding"),
            phase_state: PhaseState::Unavailable,
            time_quality: TimeQuality::ReceiveOnly,
            clock_domain: None,
        })
        .expect("valid profile")
    }

    #[test]
    fn checked_coordinate_count_reports_overflow() {
        assert_eq!(checked_coordinate_count(usize::MAX, 2), Err(LayoutError::CountOverflow));
    }

    #[test]
    fn profile_catalog_rejects_same_id_with_different_descriptor() {
        let first = test_profile();
        let mut conflicting = first.clone();
        conflicting.descriptor.capability_id = "different-capability".into();

        let mut catalog = ProfileCatalog::default();
        catalog.intern(first.clone()).expect("first profile");
        assert!(matches!(
            catalog.intern(conflicting),
            Err(ProfileError::DescriptorConflict { id }) if id == first.id()
        ));
    }
}
