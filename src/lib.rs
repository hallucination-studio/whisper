//! Preserved native RF input contracts for the RF world-model rebuild.

#![forbid(unsafe_code)]

mod host;
mod identity;
pub(crate) mod key;
#[expect(dead_code, reason = "retained for the next lossless native-CSI fact slice")]
pub(crate) mod native_csi;
/// Native-frame v1 authentication, parsing, and lossless body values.
#[expect(dead_code, reason = "retained as the fixed deployed-device input contract")]
#[path = "wire.rs"]
pub(crate) mod native_frame;
pub(crate) mod replay;
mod store;

#[doc(inline)]
pub use host::{
    AdmissionLimits, AdmissionLimitsError, Host, HostBuilder, HostError, HostRuntime,
    NativeFrameRoute, RawFact, RawLoss, RawLossKind, RejectReason, RejectedDatagram, RouteError,
};
#[doc(inline)]
pub use identity::{
    BootGeneration, DeploymentId, DeploymentIdError, DeviceId, KeyEpoch, MessageSequence,
    NativeFrameKind,
};
#[doc(inline)]
pub use store::{Store, StoreId, StoreInitError, StoreOpenError};

#[cfg(test)]
mod conformance;
