//! Lossless native-coordinate facts derived from authenticated source bytes.

use std::net::SocketAddr;
use std::time::SystemTime;

use crate::identity::{BootGeneration, DeviceId, KeyEpoch, MessageSequence};
use crate::native_frame::{CapabilitiesV1, CsiDataV1};

#[doc(inline)]
pub use crate::native_frame::{
    CapabilityDescriptor, HealthV1, IqSample, LtfBlock, LtfKind, RadioRxS3, S3BandwidthKind,
    S3PhyKind, S3SecondaryKind,
};

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

    pub(crate) const fn new(
        provenance_digest: [u8; 32],
        peer: SocketAddr,
        received_at: SystemTime,
        device_id: DeviceId,
        key_epoch: KeyEpoch,
        boot_generation: BootGeneration,
        message_sequence: MessageSequence,
    ) -> Self {
        Self {
            provenance_digest,
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
