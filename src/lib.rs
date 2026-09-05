//! Preserved native RF input contracts for the RF world-model rebuild.

#![forbid(unsafe_code)]

mod admission;
mod artifact;
mod companion;
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
pub use admission::{
    AdmissionLimits, AuthenticatedBytesPerSecond, DatagramBytes, LimitValueError, PacketsPerSecond,
    ReplayWindowPackets,
};
#[doc(inline)]
pub use artifact::{
    ArrayCondition, Artifact, ArtifactDigest, ArtifactError, ArtifactImportError, ArtifactKind,
    ArtifactLimits, ArtifactLimitsBuilder, ArtifactMetadata, ArtifactOrigin, ArtifactRejectReason,
    CalibrationBundle, CalibrationEpoch, ClockErrorNanoseconds, ClockOffsetNanoseconds,
    CoherenceScope, CoordinateTransform, CoverageCell, DepthQuality, GeometryElement, GeometryKind,
    HostNanoseconds, ImportedArtifact, JointLabel, LabelScope, MetersPerSecond, PersonLabel,
    PhoneNanoseconds, PhoneTimeRelation, PortCondition, SceneSnapshot, SealedArtifact,
    SourceIdentity, SupervisionSample, SupervisionSegment, TrackingEpoch, TrackingQuality,
    UtcNanoseconds,
};
#[doc(inline)]
pub use companion::{
    ClientNonce, ClockExchange, CompanionChunk, CompanionClockRelation, CompanionConnection,
    CompanionEntropy, CompanionError, CompanionRejectReason, CompanionServerIdentity, PairingCode,
    PairingId, PairingOffer, SystemCompanionEntropy, UploadId, UploadProgress,
};
#[doc(inline)]
pub use host::{
    Host, HostBuilder, HostError, HostRuntime, NativeFrameRoute, RawFact, RawLoss, RawLossKind,
    RejectReason, RejectedDatagram, RouteError,
};
#[doc(inline)]
pub use identity::{
    BootGeneration, DeploymentId, DeploymentIdError, DeviceId, IdentityValueError, KeyEpoch,
    MessageSequence, NativeFrameKind,
};
#[doc(inline)]
pub use store::{Store, StoreId, StoreInitError, StoreOpenError};

#[cfg(test)]
mod conformance;
