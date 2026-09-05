//! Strong identities carried by authenticated native-frame facts.

use std::fmt;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

/// A nonempty sensing-deployment identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeploymentId(Box<str>);

impl DeploymentId {
    /// Borrows the exact deployment identifier.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for DeploymentId {
    type Error = DeploymentIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(DeploymentIdError);
        }
        Ok(Self(value.into()))
    }
}

impl fmt::Display for DeploymentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// An empty deployment identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("deployment identity must not be empty")]
pub struct DeploymentIdError;

/// A deployment-unique opaque sensing-device identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(u64);

impl DeviceId {
    /// Wraps the complete opaque native-frame device value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the wire-level unsigned value.
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

/// A nonzero native-frame authentication-key epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyEpoch(NonZeroU16);

impl KeyEpoch {
    /// Constructs a key epoch, rejecting the wire-reserved zero value.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        match NonZeroU16::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the wire-level unsigned value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl fmt::Display for KeyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A nonzero persistent firmware boot generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BootGeneration(NonZeroU32);

impl BootGeneration {
    /// Constructs a boot generation, rejecting the wire-reserved zero value.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the wire-level unsigned value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for BootGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A nonzero native-frame transport sequence within one boot generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageSequence(NonZeroU64);

impl MessageSequence {
    /// Constructs a sequence, rejecting the wire-reserved zero value.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the wire-level unsigned value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for MessageSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// An authenticated native-frame v1 kind byte, including unknown kinds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NativeFrameKind(u8);

impl NativeFrameKind {
    /// Wraps the complete authenticated kind-byte domain.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the wire-level byte.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Display for NativeFrameKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
