//! Strong identities carried by authenticated native-frame facts.

use std::backtrace::Backtrace;
use std::fmt;
use std::num::ParseIntError;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::str::FromStr;

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
            return Err(DeploymentIdError {
                input_length: 0,
                backtrace: Box::new(Backtrace::capture()),
            });
        }
        Ok(Self(value.into()))
    }
}

impl fmt::Display for DeploymentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for DeploymentId {
    type Err = DeploymentIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

/// An empty deployment identity.
#[derive(Debug)]
pub struct DeploymentIdError {
    input_length: usize,
    backtrace: Box<Backtrace>,
}

impl DeploymentIdError {
    /// Returns the rejected UTF-8 byte length.
    #[must_use]
    pub const fn input_length(&self) -> usize {
        self.input_length
    }

    /// Returns the captured validation backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for DeploymentIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "deployment identity must not be empty (input was {} bytes)",
            self.input_length
        )
    }
}

impl std::error::Error for DeploymentIdError {}

/// Invalid numeric text or a wire-reserved zero identity value.
#[derive(Debug)]
pub struct IdentityValueError {
    field: &'static str,
    value: Box<str>,
    source: Option<ParseIntError>,
    backtrace: Box<Backtrace>,
}

impl IdentityValueError {
    fn zero(field: &'static str) -> Self {
        Self { field, value: "0".into(), source: None, backtrace: Box::new(Backtrace::capture()) }
    }

    fn parse(field: &'static str, value: &str, source: ParseIntError) -> Self {
        Self {
            field,
            value: value.into(),
            source: Some(source),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    /// Returns the identity field whose value was rejected.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for IdentityValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} value {:?}: expected a nonzero unsigned integer",
            self.field, self.value
        )
    }
}

impl std::error::Error for IdentityValueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| source as _)
    }
}

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

impl TryFrom<u16> for KeyEpoch {
    type Error = IdentityValueError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value).ok_or_else(|| IdentityValueError::zero("key epoch"))
    }
}

impl FromStr for KeyEpoch {
    type Err = IdentityValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse::<u16>()
            .map_err(|source| IdentityValueError::parse("key epoch", value, source))?
            .try_into()
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

impl TryFrom<u32> for BootGeneration {
    type Error = IdentityValueError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or_else(|| IdentityValueError::zero("boot generation"))
    }
}

impl FromStr for BootGeneration {
    type Err = IdentityValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse::<u32>()
            .map_err(|source| IdentityValueError::parse("boot generation", value, source))?
            .try_into()
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

impl TryFrom<u64> for MessageSequence {
    type Error = IdentityValueError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or_else(|| IdentityValueError::zero("message sequence"))
    }
}

impl FromStr for MessageSequence {
    type Err = IdentityValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse::<u64>()
            .map_err(|source| IdentityValueError::parse("message sequence", value, source))?
            .try_into()
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
