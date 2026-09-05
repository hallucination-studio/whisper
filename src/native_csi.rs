//! Lossless native-coordinate CSI facts derived from authenticated source bytes.

use crate::native_frame::{CsiDataV1, IqSample};

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
