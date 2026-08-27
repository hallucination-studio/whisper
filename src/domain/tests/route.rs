//! Pre-authentication and post-authentication route value tests.

use std::net::IpAddr;

use crate::domain::csi::CaptureProfileId;
use crate::domain::identity::{
    BootGeneration, DeviceEpoch, DeviceId, KeyEpoch, RadioLinkId, SensorId,
};
use crate::domain::route::{
    AdmissionLimits, DecodedRoute, HeaderRoute, RouteValueError, S3Bandwidth, S3Ltf, S3LtfSequence,
    S3Phy, S3RadioFacts, S3Secondary,
};

#[test]
fn header_route_contains_only_admission_facts() {
    let peer: IpAddr = "192.0.2.10".parse().expect("peer");
    let device = DeviceId::new(9);
    let key_epoch = KeyEpoch::try_new(2).expect("key epoch");
    let limits = AdmissionLimits::try_new(1_200, 100, 50_000, 64).expect("limits");
    let route = HeaderRoute::new(peer, device, key_epoch, limits);

    assert_eq!(route.peer(), peer);
    assert_eq!(route.device(), device);
    assert_eq!(route.key_epoch(), key_epoch);
    assert_eq!(route.admission_limits(), limits);
    assert_eq!(limits.maximum_datagram_bytes(), 1_200);
    assert_eq!(limits.peak_packets_per_second(), 100);
    assert_eq!(limits.maximum_authenticated_bytes_per_second(), 50_000);
    assert_eq!(limits.replay_window_packets(), 64);
    assert!(AdmissionLimits::try_new(0, 100, 50_000, 64).is_err());
    assert!(AdmissionLimits::try_new(1_200, 0, 50_000, 64).is_err());
    assert!(AdmissionLimits::try_new(1_200, 100, 0, 64).is_err());
    assert!(AdmissionLimits::try_new(1_200, 100, 50_000, 0).is_err());
}

#[test]
fn decoded_route_requires_authenticated_source_and_radio_facts() {
    let device_epoch =
        DeviceEpoch::new(DeviceId::new(9), BootGeneration::try_new(4).expect("boot generation"));
    let radio =
        S3RadioFacts::try_new(6, S3Secondary::None, S3Phy::Ht, S3Bandwidth::TwentyMhz, false)
            .expect("radio facts");
    let profile = CaptureProfileId::from_bytes([0xA5; 32]);
    let route = DecodedRoute::try_new(
        device_epoch,
        SensorId::new("sensor").expect("sensor"),
        RadioLinkId::new("link").expect("link"),
        profile,
        [1, 2, 3, 4, 5, 6],
        radio,
    )
    .expect("decoded route");

    assert_eq!(route.device_epoch(), device_epoch);
    assert_eq!(route.profile(), profile);
    assert_eq!(route.source_mac(), [1, 2, 3, 4, 5, 6]);
    assert_eq!(route.radio(), radio);
    assert_eq!(radio.ltf_sequence(), S3LtfSequence::Ht);
    assert_eq!(radio.ltf_sequence().blocks(), &[S3Ltf::Lltf, S3Ltf::HtLtf]);
    let non_ht =
        S3RadioFacts::try_new(1, S3Secondary::None, S3Phy::NonHt, S3Bandwidth::TwentyMhz, false)
            .expect("non-HT radio facts");
    assert_eq!(non_ht.ltf_sequence(), S3LtfSequence::NonHt);
    assert_eq!(non_ht.ltf_sequence().blocks(), &[S3Ltf::Lltf]);
    let ht_stbc =
        S3RadioFacts::try_new(11, S3Secondary::Above, S3Phy::Ht, S3Bandwidth::FortyMhz, true)
            .expect("STBC radio facts");
    assert_eq!(ht_stbc.ltf_sequence(), S3LtfSequence::HtStbc);
    assert_eq!(ht_stbc.ltf_sequence().blocks(), &[S3Ltf::Lltf, S3Ltf::HtLtf, S3Ltf::StbcHtLtf]);
    assert!(
        S3RadioFacts::try_new(0, S3Secondary::None, S3Phy::Ht, S3Bandwidth::TwentyMhz, false,)
            .is_err()
    );
    assert_eq!(
        S3RadioFacts::try_new(36, S3Secondary::None, S3Phy::Ht, S3Bandwidth::TwentyMhz, false,),
        Err(RouteValueError::InvalidS3Channel(36))
    );
    assert_eq!(
        S3RadioFacts::try_new(6, S3Secondary::Above, S3Phy::NonHt, S3Bandwidth::FortyMhz, false,),
        Err(RouteValueError::UnsupportedS3RadioCombination)
    );
    assert_eq!(
        S3RadioFacts::try_new(6, S3Secondary::None, S3Phy::NonHt, S3Bandwidth::FortyMhz, false),
        Err(RouteValueError::UnsupportedS3RadioCombination)
    );
    assert_eq!(
        S3RadioFacts::try_new(6, S3Secondary::None, S3Phy::NonHt, S3Bandwidth::TwentyMhz, true),
        Err(RouteValueError::UnsupportedS3RadioCombination)
    );
    assert_eq!(
        S3RadioFacts::try_new(6, S3Secondary::Above, S3Phy::Ht, S3Bandwidth::TwentyMhz, false),
        Err(RouteValueError::UnsupportedS3RadioCombination)
    );
    assert_eq!(
        S3RadioFacts::try_new(6, S3Secondary::None, S3Phy::Ht, S3Bandwidth::FortyMhz, false),
        Err(RouteValueError::UnsupportedS3RadioCombination)
    );
    assert_eq!(
        DecodedRoute::try_new(
            device_epoch,
            SensorId::new("sensor").expect("sensor"),
            RadioLinkId::new("link").expect("link"),
            profile,
            [0; 6],
            radio,
        ),
        Err(RouteValueError::ZeroSourceMac)
    );
}
