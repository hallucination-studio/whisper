//! Lossless native-coordinate facts derived from authenticated source bytes.

use std::backtrace::Backtrace;
use std::fmt;
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::identity::{BootGeneration, DeviceId, KeyEpoch, MessageSequence, SensorId};
use crate::native_frame::{CapabilitiesV1, CsiDataV1};

#[doc(inline)]
pub use crate::native_frame::{
    CapabilityDescriptor, HealthV1, IqSample, LtfBlock, LtfKind, RadioRxS3, S3BandwidthKind,
    S3PhyKind, S3SecondaryKind,
};

/// The authenticated source MAC admitted for one native route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceMac([u8; 6]);

impl SourceMac {
    /// Creates an admitted source MAC, rejecting the all-zero sentinel.
    pub fn try_new(bytes: [u8; 6]) -> Result<Self, SourceMacError> {
        if bytes == [0; 6] {
            return Err(SourceMacError::all_zero());
        }
        Ok(Self(bytes))
    }

    /// Borrows the six source-MAC octets in wire order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Returns the six source-MAC octets in wire order.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 6] {
        self.0
    }
}

impl TryFrom<[u8; 6]> for SourceMac {
    type Error = SourceMacError;

    fn try_from(bytes: [u8; 6]) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

impl TryFrom<&[u8]> for SourceMac {
    type Error = SourceMacError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 6] = bytes.try_into().map_err(|_| SourceMacError::width(bytes.len()))?;
        Self::try_new(bytes)
    }
}

impl fmt::Display for SourceMac {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Invalid authenticated source-MAC configuration or persistence.
#[derive(Debug)]
pub struct SourceMacError {
    actual_width: usize,
    all_zero: bool,
    backtrace: Box<Backtrace>,
}

impl SourceMacError {
    fn width(actual_width: usize) -> Self {
        Self { actual_width, all_zero: false, backtrace: Box::new(Backtrace::capture()) }
    }

    fn all_zero() -> Self {
        Self { actual_width: 6, all_zero: true, backtrace: Box::new(Backtrace::capture()) }
    }

    /// Returns the rejected source-MAC width in bytes.
    #[must_use]
    pub const fn actual_width(&self) -> usize {
        self.actual_width
    }

    /// Returns the captured validation backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for SourceMacError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.all_zero {
            write!(formatter, "native source MAC must not be all zero")
        } else {
            write!(formatter, "native source MAC must be 6 bytes (got {})", self.actual_width)
        }
    }
}

impl std::error::Error for SourceMacError {}

/// The exact primary channel policy admitted for one native route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelPolicy(u8);

impl ChannelPolicy {
    /// Creates a route channel policy for the supported 2.4 GHz primary channels.
    pub fn try_new(channel: u8) -> Result<Self, ChannelPolicyError> {
        if !(1..=14).contains(&channel) {
            return Err(ChannelPolicyError::new(channel));
        }
        Ok(Self(channel))
    }

    /// Returns the admitted primary channel number.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for ChannelPolicy {
    type Error = ChannelPolicyError;

    fn try_from(channel: u8) -> Result<Self, Self::Error> {
        Self::try_new(channel)
    }
}

impl fmt::Display for ChannelPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "channel {}", self.0)
    }
}

/// Invalid native primary-channel policy.
#[derive(Debug)]
pub struct ChannelPolicyError {
    channel: u8,
    backtrace: Box<Backtrace>,
}

impl ChannelPolicyError {
    fn new(channel: u8) -> Self {
        Self { channel, backtrace: Box::new(Backtrace::capture()) }
    }

    /// Returns the rejected primary channel number.
    #[must_use]
    pub const fn channel(&self) -> u8 {
        self.channel
    }

    /// Returns the captured validation backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for ChannelPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native primary channel must be between 1 and 14 (got {})", self.channel)
    }
}

impl std::error::Error for ChannelPolicyError {}

/// The fixed-width identity of the firmware build admitted for one route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FirmwareBuildIdentity([u8; 32]);

impl FirmwareBuildIdentity {
    /// Borrows the non-secret firmware build digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the firmware build digest.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for FirmwareBuildIdentity {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for FirmwareBuildIdentity {
    type Error = DigestIdentityError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            DigestIdentityError::new(DigestIdentityKind::FirmwareBuild, bytes.len())
        })?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for FirmwareBuildIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

/// The fixed-width capability identity admitted for one route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityIdentity([u8; 32]);

impl CapabilityIdentity {
    /// Borrows the non-secret capability digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the capability digest.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for CapabilityIdentity {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for CapabilityIdentity {
    type Error = DigestIdentityError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DigestIdentityError::new(DigestIdentityKind::Capability, bytes.len()))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for CapabilityIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

fn write_digest(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum DigestIdentityKind {
    FirmwareBuild,
    Capability,
}

impl fmt::Display for DigestIdentityKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirmwareBuild => formatter.write_str("firmware-build"),
            Self::Capability => formatter.write_str("capability"),
        }
    }
}

/// Invalid persisted or byte-slice native digest identity.
#[derive(Debug)]
pub struct DigestIdentityError {
    kind: DigestIdentityKind,
    actual_width: usize,
    backtrace: Box<Backtrace>,
}

impl DigestIdentityError {
    fn new(kind: DigestIdentityKind, actual_width: usize) -> Self {
        Self { kind, actual_width, backtrace: Box::new(Backtrace::capture()) }
    }

    /// Returns the rejected digest width in bytes.
    #[must_use]
    pub const fn actual_width(&self) -> usize {
        self.actual_width
    }

    /// Returns the captured validation backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for DigestIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native {} digest must be 32 bytes (got {})",
            self.kind, self.actual_width
        )
    }
}

impl std::error::Error for DigestIdentityError {}

/// A physical or protocol-native RF path coordinate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CsiPath {
    /// A protocol-provided transmit-stream and receive-chain coordinate.
    TxRx {
        /// Transmit-stream ordinal.
        tx_stream: u16,
        /// Receive-chain ordinal.
        rx_chain: u16,
    },
    /// A protocol path whose physical meaning is intentionally opaque.
    RawPathOrdinal(u16),
}

/// A protocol-native sample axis that does not invent unavailable coordinates.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SampleAxis {
    /// Opaque ordinals from zero through `count - 1`.
    OpaqueOrdinal {
        /// Number of sample coordinates.
        count: u16,
    },
}

/// The immutable provenance shared by every typed native fact.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NativeFactProvenance {
    provenance_digest: [u8; 32],
    sensor: SensorId,
    peer: SocketAddr,
    received_at: SystemTime,
    device_id: DeviceId,
    key_epoch: KeyEpoch,
    boot_generation: BootGeneration,
    message_sequence: MessageSequence,
}

impl NativeFactProvenance {
    /// Returns the SHA-256 digest of the exact authenticated raw datagram.
    #[must_use]
    pub const fn provenance_digest(&self) -> &[u8; 32] {
        &self.provenance_digest
    }

    /// Returns the configured sensor identity that admitted this fact.
    #[must_use]
    pub const fn sensor(&self) -> &SensorId {
        &self.sensor
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

    /// Returns the authenticated device boot generation.
    #[must_use]
    pub const fn boot_generation(&self) -> BootGeneration {
        self.boot_generation
    }

    /// Returns the authenticated transport sequence.
    #[must_use]
    pub const fn message_sequence(&self) -> MessageSequence {
        self.message_sequence
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "These are the fixed native-fact provenance fields"
    )]
    pub(crate) const fn new(
        provenance_digest: [u8; 32],
        sensor: SensorId,
        peer: SocketAddr,
        received_at: SystemTime,
        device_id: DeviceId,
        key_epoch: KeyEpoch,
        boot_generation: BootGeneration,
        message_sequence: MessageSequence,
    ) -> Self {
        Self {
            provenance_digest,
            sensor,
            peer,
            received_at,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
        }
    }
}

/// One lossless CSI capture in its native path and sample coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCsi {
    path: CsiPath,
    sample_axis: SampleAxis,
    samples: Box<[IqSample]>,
}

impl NativeCsi {
    /// Returns the protocol-native RF path.
    #[must_use]
    pub const fn path(&self) -> CsiPath {
        self.path
    }

    /// Returns the protocol-native sample axis.
    #[must_use]
    pub const fn sample_axis(&self) -> SampleAxis {
        self.sample_axis
    }

    /// Returns I/Q pairs in exact protocol order with source validity preserved.
    #[must_use]
    pub fn samples(&self) -> &[IqSample] {
        &self.samples
    }
}

/// One authenticated, capability-qualified native CSI observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCsiFact {
    provenance: NativeFactProvenance,
    capability_digest: [u8; 32],
    capture_sequence: u64,
    driver_rx_timestamp_us: u32,
    callback_tick_us: u64,
    source_mac: [u8; 6],
    radio: RadioRxS3,
    first_invalid_bytes: u8,
    trailing_invalid_bytes: u8,
    complex_sample_count: u16,
    blocks: Box<[LtfBlock]>,
    raw_csi: Box<[u8]>,
    csi: NativeCsi,
}

impl NativeCsiFact {
    /// Returns the raw-fact provenance for this observation.
    #[must_use]
    pub const fn provenance(&self) -> &NativeFactProvenance {
        &self.provenance
    }

    /// Returns the capability identity required by this observation.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }

    /// Returns the capture-side sequence, including gaps caused by dropped callbacks.
    #[must_use]
    pub const fn capture_sequence(&self) -> u64 {
        self.capture_sequence
    }

    /// Returns the exact driver receive timestamp.
    #[must_use]
    pub const fn driver_rx_timestamp_us(&self) -> u32 {
        self.driver_rx_timestamp_us
    }

    /// Returns the callback delivery tick in the boot clock.
    #[must_use]
    pub const fn callback_tick_us(&self) -> u64 {
        self.callback_tick_us
    }

    /// Returns the driver-reported source MAC.
    #[must_use]
    pub const fn source_mac(&self) -> [u8; 6] {
        self.source_mac
    }

    /// Returns all authenticated radio receive facts.
    #[must_use]
    pub const fn radio(&self) -> RadioRxS3 {
        self.radio
    }

    /// Returns the explicit leading invalid byte count.
    #[must_use]
    pub const fn first_invalid_bytes(&self) -> u8 {
        self.first_invalid_bytes
    }

    /// Returns trailing raw alignment bytes excluded from logical pairs.
    #[must_use]
    pub const fn trailing_invalid_bytes(&self) -> u8 {
        self.trailing_invalid_bytes
    }

    /// Returns the number of complete logical complex pairs.
    #[must_use]
    pub const fn complex_sample_count(&self) -> u16 {
        self.complex_sample_count
    }

    /// Returns LTF blocks in the driver-reported order.
    #[must_use]
    pub fn blocks(&self) -> &[LtfBlock] {
        &self.blocks
    }

    /// Returns the exact ESP-IDF CSI bytes, including any trailing alignment bytes.
    #[must_use]
    pub fn raw_csi(&self) -> &[u8] {
        &self.raw_csi
    }

    /// Returns the native path and opaque sample-axis observation.
    #[must_use]
    pub const fn csi(&self) -> &NativeCsi {
        &self.csi
    }

    /// Returns the native path coordinate.
    #[must_use]
    pub const fn path(&self) -> CsiPath {
        self.csi.path()
    }

    /// Returns the native sample axis.
    #[must_use]
    pub const fn sample_axis(&self) -> SampleAxis {
        self.csi.sample_axis()
    }

    /// Returns I/Q pairs in exact protocol order with source validity preserved.
    #[must_use]
    pub fn samples(&self) -> &[IqSample] {
        self.csi.samples()
    }

    pub(crate) fn from_body(provenance: NativeFactProvenance, data: &CsiDataV1) -> Self {
        Self {
            provenance,
            capability_digest: data.capability_digest(),
            capture_sequence: data.capture_sequence(),
            driver_rx_timestamp_us: data.driver_rx_timestamp_us(),
            callback_tick_us: data.callback_tick_us(),
            source_mac: data.source_mac(),
            radio: data.radio(),
            first_invalid_bytes: data.first_invalid_bytes(),
            trailing_invalid_bytes: data.trailing_invalid_bytes(),
            complex_sample_count: data.complex_sample_count(),
            blocks: data.blocks().into(),
            raw_csi: data.raw_csi().into(),
            csi: data.native_csi(),
        }
    }
}

/// One authenticated capability declaration retained for an epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCapabilityFact {
    provenance: NativeFactProvenance,
    capability_digest: [u8; 32],
    descriptor: CapabilityDescriptor,
}

impl NativeCapabilityFact {
    /// Returns the raw-fact provenance for this capability.
    #[must_use]
    pub const fn provenance(&self) -> &NativeFactProvenance {
        &self.provenance
    }

    /// Returns the SHA-256 capability identity.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }

    /// Returns the immutable firmware and ABI capability descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &CapabilityDescriptor {
        &self.descriptor
    }

    pub(crate) fn from_body(provenance: NativeFactProvenance, body: &CapabilitiesV1) -> Self {
        Self {
            provenance,
            capability_digest: body.capability_digest(),
            descriptor: body.descriptor().clone(),
        }
    }
}

/// One authenticated health-counter report retained with its source provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHealthFact {
    provenance: NativeFactProvenance,
    health: HealthV1,
}

impl NativeHealthFact {
    /// Returns the raw-fact provenance for this health report.
    #[must_use]
    pub const fn provenance(&self) -> &NativeFactProvenance {
        &self.provenance
    }

    /// Returns the capability identity named by this health report.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.health.capability_digest()
    }

    /// Returns the complete decoded health body.
    #[must_use]
    pub const fn health(&self) -> &HealthV1 {
        &self.health
    }

    /// Returns the health callback tick.
    #[must_use]
    pub const fn callback_tick_us(&self) -> u64 {
        self.health.callback_tick_us()
    }

    /// Returns the number of eligible callbacks seen.
    #[must_use]
    pub const fn capture_seen(&self) -> u64 {
        self.health.capture_seen()
    }

    /// Returns callbacks dropped because no slot was available.
    #[must_use]
    pub const fn queue_drop_no_slot(&self) -> u64 {
        self.health.queue_drop_no_slot()
    }

    /// Returns callbacks dropped because the queue was full.
    #[must_use]
    pub const fn queue_drop_full(&self) -> u64 {
        self.health.queue_drop_full()
    }

    /// Returns oversize callback rejects.
    #[must_use]
    pub const fn oversize_reject(&self) -> u64 {
        self.health.oversize_reject()
    }

    /// Returns encoder rejects.
    #[must_use]
    pub const fn encode_reject(&self) -> u64 {
        self.health.encode_reject()
    }

    /// Returns send failures.
    #[must_use]
    pub const fn send_failure(&self) -> u64 {
        self.health.send_failure()
    }

    /// Returns the slot-pool high-water mark.
    #[must_use]
    pub const fn pool_high_water_slots(&self) -> u16 {
        self.health.pool_high_water_slots()
    }

    /// Returns the callback maximum duration.
    #[must_use]
    pub const fn callback_max_us(&self) -> u32 {
        self.health.callback_max_us()
    }

    /// Returns the encoder maximum duration.
    #[must_use]
    pub const fn encoder_max_us(&self) -> u32 {
        self.health.encoder_max_us()
    }

    pub(crate) fn from_body(provenance: NativeFactProvenance, health: &HealthV1) -> Self {
        Self { provenance, health: health.clone() }
    }
}

/// A typed native fact that survived authentication, replay admission, and semantic checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeFact {
    /// A capability declaration.
    Capabilities(NativeCapabilityFact),
    /// A capability-qualified CSI observation.
    Csi(NativeCsiFact),
    /// A health-counter report.
    Health(NativeHealthFact),
}

impl NativeFact {
    /// Returns the immutable raw-fact provenance for this typed fact.
    #[must_use]
    pub const fn provenance(&self) -> &NativeFactProvenance {
        match self {
            Self::Capabilities(fact) => fact.provenance(),
            Self::Csi(fact) => fact.provenance(),
            Self::Health(fact) => fact.provenance(),
        }
    }
}

impl CsiDataV1 {
    /// Projects the authenticated ESP32-S3 body into its lossless native CSI facts.
    #[must_use]
    pub fn native_csi(&self) -> NativeCsi {
        NativeCsi {
            path: CsiPath::RawPathOrdinal(0),
            sample_axis: SampleAxis::OpaqueOrdinal { count: self.complex_sample_count() },
            samples: self.iq_samples().into_boxed_slice(),
        }
    }
}
