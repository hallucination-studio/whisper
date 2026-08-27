//! Stable, transport-neutral values shared by the RF processing pipeline.

#[expect(dead_code, reason = "CSI domain values are consumed by the work-package 1.2 decoder")]
pub(crate) mod csi;
#[expect(dead_code, reason = "identity values are consumed by the work-packages 1.2 through 4.1")]
pub(crate) mod identity;
#[expect(dead_code, reason = "route values are consumed by the work-package 1.2 decoder")]
pub(crate) mod route;
#[expect(dead_code, reason = "time values are consumed by the work-packages 1.2 through 3.1")]
pub(crate) mod time;
#[expect(dead_code, reason = "world values are consumed by the work-package 3.3 estimator")]
pub(crate) mod world;

#[cfg(test)]
mod tests;

#[expect(unused_imports, reason = "new identity values are consumed by the 1.2 decoder")]
pub(crate) use identity::{
    BootGeneration, ConditioningVersion, DeploymentId, DeviceEpoch, DeviceId, HardwareKind,
    IdError, KeyEpoch, RadioLinkId, SensorId, SpaceId, TransmitterId,
};
#[expect(unused_imports, reason = "route values are consumed by the 1.2 decoder")]
pub(crate) use route::{
    AdmissionLimits, DecodedRoute, HeaderRoute, RouteValueError, S3Bandwidth, S3Ltf, S3LtfSequence,
    S3Phy, S3RadioFacts, S3Secondary,
};
