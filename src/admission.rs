//! Strong units and coherent construction for one native-frame admission route.

use std::backtrace::Backtrace;
use std::fmt;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use crate::native_frame::MINIMUM_NATIVE_FRAME_V1_DATAGRAM_BYTES;

/// Smallest route datagram budget in bytes, derived from native-frame v1's
/// 32-byte header + 705-byte maximum body + 16-byte GCM tag. Raising it rejects
/// conforming route budgets; lowering it permits routes that cannot carry v1.
const MINIMUM_DATAGRAM_BYTES: usize = MINIMUM_NATIVE_FRAME_V1_DATAGRAM_BYTES as usize;
/// IPv4's maximum UDP payload in bytes. This bounds each reader allocation;
/// changing it alters accepted routes and worst-case ingress memory use.
const MAXIMUM_DATAGRAM_BYTES: usize = 65_507;

/// A native-frame route datagram budget measured in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramBytes(usize);

impl DatagramBytes {
    /// Returns the route's complete UDP datagram budget in bytes.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl fmt::Display for DatagramBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} bytes", self.0)
    }
}

impl TryFrom<usize> for DatagramBytes {
    type Error = LimitValueError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if !(MINIMUM_DATAGRAM_BYTES..=MAXIMUM_DATAGRAM_BYTES).contains(&value) {
            return Err(LimitValueError::new(
                "datagram bytes",
                value as u64,
                MINIMUM_DATAGRAM_BYTES as u64,
                MAXIMUM_DATAGRAM_BYTES as u64,
            ));
        }
        Ok(Self(value))
    }
}

/// An authenticated packet budget measured in packets per second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketsPerSecond(NonZeroU32);

impl PacketsPerSecond {
    /// Returns the authenticated packet budget per second.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for PacketsPerSecond {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} packets/s", self.0)
    }
}

impl TryFrom<u32> for PacketsPerSecond {
    type Error = LimitValueError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or_else(|| LimitValueError::new("packets per second", 0, 1, u32::MAX.into()))
    }
}

/// An authenticated byte budget measured in bytes per second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedBytesPerSecond(NonZeroU64);

impl AuthenticatedBytesPerSecond {
    /// Returns the authenticated byte budget per second.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for AuthenticatedBytesPerSecond {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} bytes/s", self.0)
    }
}

impl TryFrom<u64> for AuthenticatedBytesPerSecond {
    type Error = LimitValueError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| LimitValueError::new("authenticated bytes per second", 0, 1, u64::MAX))
    }
}

/// A durable replay window measured in packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayWindowPackets(NonZeroU16);

impl ReplayWindowPackets {
    /// Returns the durable replay-window width in packets.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl fmt::Display for ReplayWindowPackets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} packets", self.0)
    }
}

impl TryFrom<u16> for ReplayWindowPackets {
    type Error = LimitValueError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or_else(|| LimitValueError::new("replay window packets", 0, 1, u16::MAX.into()))
    }
}

/// Invalid numeric admission-limit value with its expected unit range.
#[derive(Debug)]
pub struct LimitValueError {
    unit: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
    backtrace: Box<Backtrace>,
}

impl LimitValueError {
    fn new(unit: &'static str, value: u64, minimum: u64, maximum: u64) -> Self {
        Self { unit, value, minimum, maximum, backtrace: Box::new(Backtrace::capture()) }
    }

    /// Returns the unit-bearing field whose value was rejected.
    #[must_use]
    pub const fn unit(&self) -> &'static str {
        self.unit
    }

    /// Returns the captured validation backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for LimitValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} value {}: expected {}..={}",
            self.unit, self.value, self.minimum, self.maximum
        )
    }
}

impl std::error::Error for LimitValueError {}

/// Exact per-route native-frame admission limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimits {
    pub(crate) datagram_bytes: DatagramBytes,
    pub(crate) packets_per_second: PacketsPerSecond,
    pub(crate) authenticated_bytes_per_second: AuthenticatedBytesPerSecond,
    pub(crate) replay_window_packets: ReplayWindowPackets,
}

impl AdmissionLimits {
    /// Creates a complete route limit set from validated semantic units.
    #[must_use]
    pub const fn new(
        datagram_bytes: DatagramBytes,
        packets_per_second: PacketsPerSecond,
        authenticated_bytes_per_second: AuthenticatedBytesPerSecond,
        replay_window_packets: ReplayWindowPackets,
    ) -> Self {
        Self {
            datagram_bytes,
            packets_per_second,
            authenticated_bytes_per_second,
            replay_window_packets,
        }
    }

    /// Returns the complete route datagram budget.
    #[must_use]
    pub const fn datagram_bytes(self) -> DatagramBytes {
        self.datagram_bytes
    }

    /// Returns the authenticated packet-rate limit.
    #[must_use]
    pub const fn packets_per_second(self) -> PacketsPerSecond {
        self.packets_per_second
    }

    /// Returns the authenticated byte-rate limit.
    #[must_use]
    pub const fn authenticated_bytes_per_second(self) -> AuthenticatedBytesPerSecond {
        self.authenticated_bytes_per_second
    }

    /// Returns the durable replay-window width.
    #[must_use]
    pub const fn replay_window_packets(self) -> ReplayWindowPackets {
        self.replay_window_packets
    }
}
