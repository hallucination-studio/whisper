//! Typed route facts split at the authentication boundary.

use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

use super::csi::CaptureProfileId;
use super::identity::{DeviceEpoch, DeviceId, KeyEpoch, RadioLinkId, SensorId};

/// Errors produced while constructing route values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RouteValueError {
    /// A configured admission limit was zero.
    #[error("route admission limit {field} must be non-zero")]
    ZeroAdmissionLimit {
        /// Limit field that was zero.
        field: &'static str,
    },
    /// The authenticated radio channel was zero.
    #[error("authenticated radio channel must be non-zero")]
    ZeroChannel,
    /// The authenticated channel is outside the ESP32 2.4 GHz range.
    #[error("authenticated S3 channel {0} is outside 1..=14")]
    InvalidS3Channel(u8),
    /// The authenticated S3 PHY facts were not a supported combination.
    #[error("authenticated S3 PHY, bandwidth, secondary, STBC, and LTF facts are incompatible")]
    UnsupportedS3RadioCombination,
    /// The authenticated source address contained no usable address bits.
    #[error("authenticated source MAC must not be all zero")]
    ZeroSourceMac,
}

/// The two S3 PHY encodings admitted by the native-frame route boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum S3Phy {
    /// Non-HT PHY.
    NonHt,
    /// HT PHY.
    Ht,
}

/// The two S3 channel bandwidth encodings admitted by the route boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum S3Bandwidth {
    /// Twenty megahertz channel bandwidth.
    TwentyMhz,
    /// Forty megahertz channel bandwidth.
    FortyMhz,
}

/// The S3 secondary-channel placement encoded in an authenticated frame.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum S3Secondary {
    /// No secondary channel is present.
    None,
    /// Secondary channel is above the primary channel.
    Above,
    /// Secondary channel is below the primary channel.
    Below,
}

/// The S3 LTF block kinds understood by the route boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum S3Ltf {
    /// Legacy LTF block.
    Lltf,
    /// HT LTF block.
    HtLtf,
    /// STBC HT LTF block.
    StbcHtLtf,
}

/// Complete ordered S3 LTF block sequence implied by PHY and STBC facts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum S3LtfSequence {
    /// Non-HT frames contain one LLTF block.
    NonHt,
    /// HT frames without STBC contain LLTF then HTLTF.
    Ht,
    /// HT frames with STBC contain LLTF, HTLTF, then STBC HTLTF.
    HtStbc,
}

impl S3LtfSequence {
    /// Returns the exact ordered blocks expected on the native-frame wire.
    #[must_use]
    pub const fn blocks(self) -> &'static [S3Ltf] {
        match self {
            Self::NonHt => &[S3Ltf::Lltf],
            Self::Ht => &[S3Ltf::Lltf, S3Ltf::HtLtf],
            Self::HtStbc => &[S3Ltf::Lltf, S3Ltf::HtLtf, S3Ltf::StbcHtLtf],
        }
    }
}

/// Bounded pre-authentication limits supplied by the route configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AdmissionLimits {
    maximum_datagram_bytes: u16,
    peak_packets_per_second: u32,
    maximum_authenticated_bytes_per_second: u64,
    replay_window_packets: u16,
}

impl AdmissionLimits {
    /// Creates bounded limits after rejecting zero budgets.
    pub const fn try_new(
        maximum_datagram_bytes: u16,
        peak_packets_per_second: u32,
        maximum_authenticated_bytes_per_second: u64,
        replay_window_packets: u16,
    ) -> Result<Self, RouteValueError> {
        if maximum_datagram_bytes == 0 {
            return Err(RouteValueError::ZeroAdmissionLimit { field: "maximum_datagram_bytes" });
        }
        if peak_packets_per_second == 0 {
            return Err(RouteValueError::ZeroAdmissionLimit { field: "peak_packets_per_second" });
        }
        if maximum_authenticated_bytes_per_second == 0 {
            return Err(RouteValueError::ZeroAdmissionLimit {
                field: "maximum_authenticated_bytes_per_second",
            });
        }
        if replay_window_packets == 0 {
            return Err(RouteValueError::ZeroAdmissionLimit { field: "replay_window_packets" });
        }
        Ok(Self {
            maximum_datagram_bytes,
            peak_packets_per_second,
            maximum_authenticated_bytes_per_second,
            replay_window_packets,
        })
    }

    /// Returns the maximum admitted datagram size in bytes.
    #[must_use]
    pub const fn maximum_datagram_bytes(self) -> u16 {
        self.maximum_datagram_bytes
    }

    /// Returns the peak admitted packet rate.
    #[must_use]
    pub const fn peak_packets_per_second(self) -> u32 {
        self.peak_packets_per_second
    }

    /// Returns the maximum authenticated byte rate.
    #[must_use]
    pub const fn maximum_authenticated_bytes_per_second(self) -> u64 {
        self.maximum_authenticated_bytes_per_second
    }

    /// Returns the bounded replay window size in packets.
    #[must_use]
    pub const fn replay_window_packets(self) -> u16 {
        self.replay_window_packets
    }
}

/// Pre-authentication admission facts selected from the datagram and config.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct HeaderRoute {
    peer: IpAddr,
    device: DeviceId,
    key_epoch: KeyEpoch,
    admission_limits: AdmissionLimits,
}

impl HeaderRoute {
    /// Creates a route containing only peer, device, key, and admission-limit facts.
    #[must_use]
    pub const fn new(
        peer: IpAddr,
        device: DeviceId,
        key_epoch: KeyEpoch,
        admission_limits: AdmissionLimits,
    ) -> Self {
        Self { peer, device, key_epoch, admission_limits }
    }

    /// Returns the configured peer IP address.
    #[must_use]
    pub const fn peer(self) -> IpAddr {
        self.peer
    }

    /// Returns the provisioned device identity.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the enrolled key epoch.
    #[must_use]
    pub const fn key_epoch(self) -> KeyEpoch {
        self.key_epoch
    }

    /// Returns the bounded admission limits.
    #[must_use]
    pub const fn admission_limits(self) -> AdmissionLimits {
        self.admission_limits
    }
}

impl fmt::Display for HeaderRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "peer={} device={} key_epoch={} limit={}",
            self.peer, self.device, self.key_epoch, self.admission_limits.maximum_datagram_bytes
        )
    }
}

/// Authenticated S3 radio facts required to resolve a decoded route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct S3RadioFacts {
    channel: u8,
    secondary: S3Secondary,
    phy: S3Phy,
    bandwidth: S3Bandwidth,
    stbc: bool,
    ltf_sequence: S3LtfSequence,
}

impl S3RadioFacts {
    /// Creates S3 radio facts after rejecting unsupported combinations.
    pub const fn try_new(
        channel: u8,
        secondary: S3Secondary,
        phy: S3Phy,
        bandwidth: S3Bandwidth,
        stbc: bool,
    ) -> Result<Self, RouteValueError> {
        if channel == 0 {
            return Err(RouteValueError::ZeroChannel);
        }
        if channel > 14 {
            return Err(RouteValueError::InvalidS3Channel(channel));
        }
        let ltf_sequence = match (phy, stbc) {
            (S3Phy::NonHt, false) => S3LtfSequence::NonHt,
            (S3Phy::NonHt, true) => return Err(RouteValueError::UnsupportedS3RadioCombination),
            (S3Phy::Ht, false) => S3LtfSequence::Ht,
            (S3Phy::Ht, true) => S3LtfSequence::HtStbc,
        };
        let secondary_valid = match phy {
            S3Phy::NonHt => {
                matches!(bandwidth, S3Bandwidth::TwentyMhz)
                    && matches!(secondary, S3Secondary::None)
            }
            S3Phy::Ht => match bandwidth {
                S3Bandwidth::TwentyMhz => matches!(secondary, S3Secondary::None),
                S3Bandwidth::FortyMhz => {
                    matches!(secondary, S3Secondary::Above | S3Secondary::Below)
                }
            },
        };
        if !secondary_valid {
            return Err(RouteValueError::UnsupportedS3RadioCombination);
        }
        Ok(Self { channel, secondary, phy, bandwidth, stbc, ltf_sequence })
    }

    /// Returns the authenticated channel.
    #[must_use]
    pub const fn channel(self) -> u8 {
        self.channel
    }

    /// Returns the authenticated secondary-channel placement.
    #[must_use]
    pub const fn secondary(self) -> S3Secondary {
        self.secondary
    }

    /// Returns the authenticated PHY category.
    #[must_use]
    pub const fn phy(self) -> S3Phy {
        self.phy
    }

    /// Returns the authenticated channel bandwidth.
    #[must_use]
    pub const fn bandwidth(self) -> S3Bandwidth {
        self.bandwidth
    }

    /// Returns whether the frame uses STBC.
    #[must_use]
    pub const fn stbc(self) -> bool {
        self.stbc
    }

    /// Returns the complete authenticated LTF block sequence.
    #[must_use]
    pub const fn ltf_sequence(self) -> S3LtfSequence {
        self.ltf_sequence
    }
}

/// Post-authentication route facts resolved from authenticated body metadata.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DecodedRoute {
    device_epoch: DeviceEpoch,
    sensor: SensorId,
    link: RadioLinkId,
    profile: CaptureProfileId,
    source_mac: [u8; 6],
    radio: S3RadioFacts,
}

impl DecodedRoute {
    /// Resolves a route only after authenticated source-MAC, profile, and radio facts exist.
    pub fn try_new(
        device_epoch: DeviceEpoch,
        sensor: SensorId,
        link: RadioLinkId,
        profile: CaptureProfileId,
        source_mac: [u8; 6],
        radio: S3RadioFacts,
    ) -> Result<Self, RouteValueError> {
        if source_mac.iter().all(|byte| *byte == 0) {
            return Err(RouteValueError::ZeroSourceMac);
        }
        Ok(Self { device_epoch, sensor, link, profile, source_mac, radio })
    }

    /// Returns the authenticated device epoch.
    #[must_use]
    pub const fn device_epoch(&self) -> DeviceEpoch {
        self.device_epoch
    }

    /// Returns the resolved receiving sensor.
    #[must_use]
    pub const fn sensor(&self) -> &SensorId {
        &self.sensor
    }

    /// Returns the resolved physical radio link.
    #[must_use]
    pub const fn link(&self) -> &RadioLinkId {
        &self.link
    }

    /// Returns the resolved capture profile identity.
    #[must_use]
    pub const fn profile(&self) -> CaptureProfileId {
        self.profile
    }

    /// Returns the driver-reported source MAC.
    #[must_use]
    pub const fn source_mac(&self) -> [u8; 6] {
        self.source_mac
    }

    /// Returns the authenticated radio facts.
    #[must_use]
    pub const fn radio(&self) -> S3RadioFacts {
        self.radio
    }
}
