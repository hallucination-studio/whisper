//! Strongly typed identities used to keep independent RF sources separate.

use std::fmt;
use std::str::FromStr;

use serde::Serialize;

use super::csi::CaptureProfileId;
use super::time::HostEpoch;

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

#[expect(dead_code, reason = "consumed by work-package 3.1 timeline")]
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

/// A stream key before host-inferred restart epochs are applied.
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

/// A stream key qualified by a host-inferred restart epoch.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StreamId {
    key: StreamKey,
    epoch: HostEpoch,
}

impl StreamId {
    /// Creates a stream identity.
    #[must_use]
    pub fn new(key: StreamKey, epoch: HostEpoch) -> Self {
        Self { key, epoch }
    }

    /// Returns the unqualified stream key.
    #[must_use]
    pub const fn key(&self) -> &StreamKey {
        &self.key
    }

    /// Returns the host epoch.
    #[must_use]
    pub const fn epoch(&self) -> HostEpoch {
        self.epoch
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
