//! Strongly typed identities used to keep independent RF sources separate.

use std::fmt;
use std::num::{NonZeroU16, NonZeroU32};
use std::str::FromStr;

use serde::Serialize;

use super::csi::CaptureProfileId;

/// Hardware families understood by the configuration and profile contracts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum HardwareKind {
    /// ESP32-S3 capture hardware.
    Esp32S3,
    /// ESP32-C6 capture hardware.
    Esp32C6,
    /// Intel 5300 CSI hardware; live transport is not in the first slice.
    Intel5300,
}

impl fmt::Display for HardwareKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Esp32S3 => "esp32-s3",
            Self::Esp32C6 => "esp32-c6",
            Self::Intel5300 => "intel-5300",
        };
        formatter.write_str(value)
    }
}

/// Error returned when an identity is empty or contains only whitespace.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdError {
    /// The supplied value was not a usable identifier.
    #[error("{kind} must not be empty or whitespace-only")]
    Invalid {
        /// Human-readable identity category.
        kind: &'static str,
    },
    /// A generation or key epoch was zero even though zero is reserved.
    #[error("{kind} must be non-zero")]
    Zero {
        /// Human-readable identity category.
        kind: &'static str,
    },
}

macro_rules! string_id {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[doc = concat!("A validated ", $kind, " identity.")]
        pub struct $name(Box<str>);

        impl $name {
            /// Creates an identity after checking that it is non-empty.
            pub fn new(value: impl Into<Box<str>>) -> Result<Self, IdError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(IdError::Invalid { kind: $kind });
                }
                Ok(Self(value))
            }

            /// Returns the stable textual representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value.into_boxed_str())
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_id!(DeploymentId, "deployment id");
string_id!(SpaceId, "space id");
string_id!(SensorId, "sensor id");
string_id!(TransmitterId, "transmitter id");
string_id!(RadioLinkId, "radio link id");
string_id!(SessionId, "session id");
string_id!(ConditioningVersion, "conditioning version");
string_id!(DecoderVersion, "decoder version");
string_id!(AlgorithmVersion, "algorithm version");

/// A provisioned opaque device identity, never derived from a MAC address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DeviceId(u64);

impl DeviceId {
    /// Creates a device identity from its provisioned value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the provisioned numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A non-zero enrolled key generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct KeyEpoch(NonZeroU16);

impl KeyEpoch {
    /// Creates a key epoch, rejecting the reserved zero value.
    pub const fn try_new(value: u16) -> Result<Self, IdError> {
        match NonZeroU16::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(IdError::Zero { kind: "key epoch" }),
        }
    }

    /// Returns the enrolled key generation.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl fmt::Display for KeyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// A non-zero persistent device boot generation used for nonce separation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BootGeneration(NonZeroU32);

impl BootGeneration {
    /// Creates a boot generation, rejecting the reserved zero value.
    pub const fn try_new(value: u32) -> Result<Self, IdError> {
        match NonZeroU32::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(IdError::Zero { kind: "boot generation" }),
        }
    }

    /// Returns the persistent boot generation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for BootGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// A device identity qualified by its authenticated boot generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DeviceEpoch {
    device: DeviceId,
    boot_generation: BootGeneration,
}

impl DeviceEpoch {
    /// Combines a device identity with an already validated boot generation.
    #[must_use]
    pub const fn new(device: DeviceId, boot_generation: BootGeneration) -> Self {
        Self { device, boot_generation }
    }

    /// Returns the device identity.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the authenticated boot generation.
    #[must_use]
    pub const fn boot_generation(self) -> BootGeneration {
        self.boot_generation
    }
}

impl fmt::Display for DeviceEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.device, self.boot_generation)
    }
}

/// A physical transmitter-to-receiver CSI link.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RadioLink {
    id: RadioLinkId,
    space: SpaceId,
    transmitter: TransmitterId,
    receiver: SensorId,
}

#[expect(dead_code, reason = "consumed by work-package 4.1 topology")]
impl RadioLink {
    /// Creates a link with explicit space, transmitter, and receiver identities.
    #[must_use]
    pub fn new(
        id: RadioLinkId,
        space: SpaceId,
        transmitter: TransmitterId,
        receiver: SensorId,
    ) -> Self {
        Self { id, space, transmitter, receiver }
    }

    /// Returns the link identity.
    #[must_use]
    pub const fn id(&self) -> &RadioLinkId {
        &self.id
    }

    /// Returns the containing space.
    #[must_use]
    pub const fn space(&self) -> &SpaceId {
        &self.space
    }

    /// Returns the transmitter identity.
    #[must_use]
    pub const fn transmitter(&self) -> &TransmitterId {
        &self.transmitter
    }

    /// Returns the receiving sensor identity.
    #[must_use]
    pub const fn receiver(&self) -> &SensorId {
        &self.receiver
    }
}

/// A build identity recorded with derived facts.
pub type BuildFingerprint = [u8; 32];

/// A baseline residual contract identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BaselineContractId([u8; 32]);

impl BaselineContractId {
    /// Creates an ID from its digest bytes.
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

/// A persisted baseline revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BaselineRevision(u64);

impl BaselineRevision {
    /// Creates a revision number.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the revision number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A mutable state sequence within one immutable baseline revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BaselineStateSequence(u64);

impl BaselineStateSequence {
    /// Creates a state sequence.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A digest of a windowing contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WindowContractId([u8; 32]);

impl WindowContractId {
    /// Creates an ID from its digest bytes.
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

/// A deterministic window identity within a session.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WindowId(u64);

impl WindowId {
    /// Creates a window identity.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The physical link and capture profile that share a baseline key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LinkProfileKey {
    link: RadioLinkId,
    profile: CaptureProfileId,
}

impl LinkProfileKey {
    /// Creates a link/profile key.
    #[must_use]
    pub fn new(link: RadioLinkId, profile: CaptureProfileId) -> Self {
        Self { link, profile }
    }

    /// Returns the physical link identity.
    #[must_use]
    pub const fn link(&self) -> &RadioLinkId {
        &self.link
    }

    /// Returns the capture profile identity.
    #[must_use]
    pub const fn profile(&self) -> &CaptureProfileId {
        &self.profile
    }
}

/// A stream key before an authenticated device epoch is applied.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StreamKey {
    sensor: SensorId,
    link: RadioLinkId,
    profile: CaptureProfileId,
}

impl StreamKey {
    /// Creates a stream key.
    #[must_use]
    pub fn new(sensor: SensorId, link: RadioLinkId, profile: CaptureProfileId) -> Self {
        Self { sensor, link, profile }
    }

    /// Returns the sensor identity.
    #[must_use]
    pub const fn sensor(&self) -> &SensorId {
        &self.sensor
    }

    /// Returns the link identity.
    #[must_use]
    pub const fn link(&self) -> &RadioLinkId {
        &self.link
    }

    /// Returns the profile identity.
    #[must_use]
    pub const fn profile(&self) -> &CaptureProfileId {
        &self.profile
    }
}

/// A stream key qualified by an authenticated device epoch.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StreamInstanceId {
    key: StreamKey,
    device_epoch: DeviceEpoch,
}

impl StreamInstanceId {
    /// Creates a stream identity.
    #[must_use]
    pub fn new(key: StreamKey, device_epoch: DeviceEpoch) -> Self {
        Self { key, device_epoch }
    }

    /// Returns the unqualified stream key.
    #[must_use]
    pub const fn key(&self) -> &StreamKey {
        &self.key
    }

    /// Returns the authenticated device epoch.
    #[must_use]
    pub const fn device_epoch(&self) -> DeviceEpoch {
        self.device_epoch
    }
}

/// A stable snapshot identity, derived without randomness.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SnapshotId {
    session: SessionId,
    window: WindowId,
}

impl SnapshotId {
    /// Creates a snapshot identity.
    #[must_use]
    pub fn new(session: SessionId, window: WindowId) -> Self {
        Self { session, window }
    }

    /// Returns the source session.
    #[must_use]
    pub const fn session(&self) -> &SessionId {
        &self.session
    }

    /// Returns the window identity.
    #[must_use]
    pub const fn window(&self) -> WindowId {
        self.window
    }
}
