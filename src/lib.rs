//! Preserved native RF input contracts for the RF world-model rebuild.

#![forbid(unsafe_code)]

mod admission;
pub mod artifact;
pub mod companion;
mod host;
mod identity;
pub(crate) mod key;
pub mod measurement;
pub mod native_csi;
/// Native-frame v1 authentication, parsing, and lossless body values.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "retained as the fixed deployed-device input contract")
)]
#[path = "wire.rs"]
pub(crate) mod native_frame;
pub(crate) mod replay;
mod store;

#[doc(inline)]
pub use admission::{
    AdmissionLimits, AuthenticatedBytesPerSecond, DatagramBytes, LimitValueError, PacketsPerSecond,
    ReplayWindowPackets,
};
#[doc(inline)]
pub use host::{
    DecodedRoute, DecodedRouteLink, Host, HostBuilder, HostError, HostRuntime, NativeFrameRoute,
    RadioRouteFacts, RawFact, RawLoss, RawLossKind, RejectReason, RejectedDatagram, RouteError,
};
#[doc(inline)]
pub use identity::{
    BootGeneration, DeploymentId, DeploymentIdError, DeviceId, IdentityValueError, KeyEpoch,
    MessageSequence, NativeFrameKind, SensorId, SensorIdError,
};
#[doc(inline)]
pub use store::{Store, StoreId, StoreInitError, StoreOpenError};

#[cfg(test)]
mod conformance;
