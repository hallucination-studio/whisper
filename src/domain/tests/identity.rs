//! Typed identity validation tests.

use std::str::FromStr;

use crate::domain::identity::{
    BootGeneration, DeploymentId, DeviceEpoch, DeviceId, KeyEpoch, RadioLinkId, SensorId,
    SessionId, SpaceId, TransmitterId,
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

#[test]
fn device_epoch_requires_non_zero_key_and_boot_values() {
    assert!(KeyEpoch::try_new(0).is_err());
    assert!(BootGeneration::try_new(0).is_err());

    let device = DeviceId::new(7);
    let key_epoch = KeyEpoch::try_new(3).expect("key epoch");
    let boot_generation = BootGeneration::try_new(11).expect("boot generation");
    let epoch = DeviceEpoch::new(device, boot_generation);
    assert_eq!(epoch.device(), device);
    assert_eq!(epoch.boot_generation(), boot_generation);
    assert_eq!(key_epoch.get(), 3);
}
