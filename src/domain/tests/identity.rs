//! Typed identity validation tests.

use std::str::FromStr;

use crate::domain::identity::{
    DeploymentId, RadioLinkId, SensorId, SessionId, SpaceId, TransmitterId,
};

#[test]
fn identity_newtypes_reject_empty_and_whitespace() {
    assert!(DeploymentId::new("").is_err());
    assert!(SpaceId::new(" \t\n").is_err());
    assert!(SensorId::from_str("").is_err());

    let deployment = DeploymentId::new("same").expect("id");
    let sensor = SensorId::new("same").expect("id");
    assert_eq!(deployment.as_str(), sensor.as_str());
    let _link = RadioLinkId::new("same").expect("distinct typed id");
    let _session = SessionId::new("same").expect("distinct typed id");
    let _transmitter = TransmitterId::new("same").expect("distinct typed id");
}
