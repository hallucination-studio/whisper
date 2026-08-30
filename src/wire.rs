//! Fixed native-frame envelope, ESP32-S3 body grammar, and authenticated decoding.

use std::net::SocketAddr;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};

use crate::CaptureRecordSequence;
use crate::capture::{CapturedPacket, WireFormat};
use crate::config::{Registry, RouteError};
use crate::domain::csi::{
    AcquisitionCapabilities, AcquisitionMode, CaptureProfile, CsiCapture, CsiLayout,
    CsiObservation, CsiPath, CsiSampleAxis, IqSample, LtfMerge, LtfSelection, PhaseState, PpduKind,
    ProfileCatalog, ProfileDescriptor, ProfileError, RadioMetadata, SampleEncoding, SampleOrder,
    ValidityDialect,
};
use crate::domain::identity::{
    BootGeneration, DecoderVersion, DeviceEpoch, DeviceId, HardwareKind, KeyEpoch, SessionId,
};
use crate::domain::route::{
    DecodedRoute, HeaderRoute, S3Bandwidth, S3Phy, S3RadioFacts, S3Secondary,
};
use crate::domain::time::{DeviceTimestamp, EventTimeSource, FrameTiming, SessionTime, TimeError};

/// The fixed native-frame header size in bytes.
pub const HEADER_BYTES: usize = 32;
/// The AES-256-GCM authentication tag size in bytes.
pub const TAG_BYTES: usize = 16;
/// The maximum ESP32-S3 raw CSI byte count.
pub const MAX_RAW_CSI_BYTES: usize = 612;
/// The maximum native-frame cleartext body size.
pub const MAX_CSI_PLAINTEXT_BYTES: usize = 705;
/// The fixed capability descriptor size in bytes.
pub const CAPABILITY_DESCRIPTOR_BYTES: usize = 79;
/// The native-frame wire schema version.
pub const WIRE_SCHEMA_VERSION: u8 = 1;

const CAPABILITIES_BODY_BYTES: usize = 32 + 2 + CAPABILITY_DESCRIPTOR_BYTES;
const HEALTH_BODY_BYTES: usize = 98;
pub(crate) const CSI_FIXED_BODY_BYTES: usize = 75;
pub(crate) const LTF_BLOCK_BYTES: usize = 6;

/// The authenticated message kinds defined by native-frame version one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MessageKind {
    /// Capability descriptor and build binding.
    Capabilities,
    /// One complete ESP32-S3 CSI capture.
    CsiData,
    /// Monotonic capture and encoder health counters.
    Health,
}

#[cfg(test)]
mod golden_tests {
    use super::*;
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    const KEY: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const DEVICE_ID: u64 = 0x0102_0304_0506_0708;
    const KEY_EPOCH: u16 = 7;
    const BOOT_GENERATION: u32 = 9;

    fn fixture(name: &str) -> Vec<u8> {
        let text = match name {
            "capabilities" => include_str!("../tests/fixtures/native-frame/capabilities-v1.hex"),
            "non-ht" => include_str!("../tests/fixtures/native-frame/csi-non-ht-3-pairs.hex"),
            "ht" => include_str!("../tests/fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex"),
            "ht-stbc" => include_str!("../tests/fixtures/native-frame/csi-ht-stbc-7-pairs.hex"),
            "health" => include_str!("../tests/fixtures/native-frame/health-v1.hex"),
            _ => panic!("unknown native-frame fixture {name}"),
        };
        let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
        assert_eq!(digits.len() % 2, 0, "fixture has an odd number of hex digits");
        digits
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("fixture hex") as u8;
                let low = (pair[1] as char).to_digit(16).expect("fixture hex") as u8;
                (high << 4) | low
            })
            .collect()
    }

    fn descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::try_new([0x11; 32], [0x22; 32], 1024).expect("valid descriptor")
    }

    fn capability_digest() -> [u8; 32] {
        CapabilitiesV1::new(descriptor()).capability_digest()
    }

    fn non_ht() -> CsiDataV1 {
        CsiDataV1::try_new(
            capability_digest(),
            21,
            22,
            23,
            [2, 0, 0, 0, 0, 10],
            RadioRxS3::try_new(
                1,
                S3SecondaryKind::None,
                S3PhyKind::NonHt,
                S3BandwidthKind::TwentyMhz,
                false,
                -42,
                -95,
                6,
                0,
                0,
            )
            .expect("valid non-HT radio"),
            0,
            0,
            vec![LtfBlock::new(LtfKind::Lltf, 3, 0)],
            vec![1, 2, 0x80, 0x7f, 0xff, 0],
        )
        .expect("valid non-HT body")
    }

    fn ht() -> CsiDataV1 {
        CsiDataV1::try_new(
            capability_digest(),
            31,
            32,
            33,
            [2, 0, 0, 0, 0, 10],
            RadioRxS3::try_new(
                6,
                S3SecondaryKind::Above,
                S3PhyKind::Ht,
                S3BandwidthKind::FortyMhz,
                false,
                -50,
                -96,
                0,
                7,
                1,
            )
            .expect("valid HT radio"),
            4,
            2,
            vec![LtfBlock::new(LtfKind::Lltf, 2, 0), LtfBlock::new(LtfKind::HtLtf, 3, 4)],
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa5, 0x5a],
        )
        .expect("valid HT body")
    }

    fn ht_stbc() -> CsiDataV1 {
        CsiDataV1::try_new(
            capability_digest(),
            41,
            42,
            43,
            [2, 0, 0, 0, 0, 10],
            RadioRxS3::try_new(
                11,
                S3SecondaryKind::Below,
                S3PhyKind::Ht,
                S3BandwidthKind::FortyMhz,
                true,
                -55,
                -97,
                0,
                3,
                0,
            )
            .expect("valid HT STBC radio"),
            0,
            0,
            vec![
                LtfBlock::new(LtfKind::Lltf, 2, 0),
                LtfBlock::new(LtfKind::HtLtf, 2, 4),
                LtfBlock::new(LtfKind::StbcHtLtf, 3, 8),
            ],
            vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
        )
        .expect("valid HT STBC body")
    }

    fn health() -> HealthV1 {
        HealthV1::new(capability_digest(), 51, 52, 53, 54, 55, 56, 57, 3, 58, 59)
    }

    fn seal(kind: MessageKind, sequence: u64, body: &[u8]) -> Vec<u8> {
        seal_datagram(&KEY, kind, DEVICE_ID, KEY_EPOCH, BOOT_GENERATION, sequence, body)
            .expect("valid native-frame body")
            .into_vec()
    }

    fn seal_raw(kind: u8, sequence: u64, body: &[u8]) -> Vec<u8> {
        let mut header = [0_u8; HEADER_BYTES];
        header[0] = WIRE_SCHEMA_VERSION;
        header[1] = kind;
        header[2..4].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        header[4..12].copy_from_slice(&DEVICE_ID.to_le_bytes());
        header[12..14].copy_from_slice(&KEY_EPOCH.to_le_bytes());
        header[16..20].copy_from_slice(&BOOT_GENERATION.to_le_bytes());
        header[20..28].copy_from_slice(&sequence.to_le_bytes());
        header[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());
        let mut nonce = [0_u8; 12];
        nonce[..4].copy_from_slice(&BOOT_GENERATION.to_le_bytes());
        nonce[4..].copy_from_slice(&sequence.to_le_bytes());
        let ciphertext = Aes256Gcm::new_from_slice(&KEY)
            .expect("test key")
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &header })
            .expect("test encryption");
        header.into_iter().chain(ciphertext).collect()
    }

    #[test]
    fn golden_capability_seals_and_decodes_exactly() {
        let body = encode_capabilities(&descriptor());
        let expected = fixture("capabilities");
        assert_eq!(seal(MessageKind::Capabilities, 11, &body), expected);
        let decoded = open_datagram(&KEY, &expected).expect("capability fixture opens");
        assert_eq!(decoded.header().kind(), Some(MessageKind::Capabilities));
        assert_eq!(decoded.header().device_id(), DEVICE_ID);
        assert_eq!(decoded.header().key_epoch(), KEY_EPOCH);
        assert_eq!(decoded.header().boot_generation(), BOOT_GENERATION);
        assert_eq!(decoded.header().message_seq(), 11);
        assert_eq!(decoded.header().ciphertext_bytes() as usize, body.len());
        let Message::Capabilities(capability) = decoded.message() else {
            panic!("expected capabilities")
        };
        assert_eq!(capability.descriptor(), &descriptor());
        assert_eq!(capability.capability_digest(), capability_digest());
    }

    #[test]
    fn golden_csi_vectors_preserve_shape_and_raw_bytes() {
        let cases = [
            ("non-ht", 12, non_ht(), 3_u16, 1_u8, 0_u8),
            ("ht", 13, ht(), 5_u16, 2_u8, 2_u8),
            ("ht-stbc", 14, ht_stbc(), 7_u16, 3_u8, 0_u8),
        ];
        for (name, sequence, expected_data, samples, block_count, trailing) in cases {
            let body = encode_csi_data(&expected_data);
            let expected = fixture(name);
            assert_eq!(seal(MessageKind::CsiData, sequence, &body), expected);
            let decoded = open_datagram(&KEY, &expected).expect("CSI fixture opens");
            assert_eq!(decoded.header().kind(), Some(MessageKind::CsiData));
            let Message::CsiData(data) = decoded.message() else { panic!("expected CSI data") };
            assert_eq!(data.complex_sample_count(), samples);
            assert_eq!(data.blocks().len(), usize::from(block_count));
            assert_eq!(data.trailing_invalid_bytes(), trailing);
            assert_eq!(data.raw_csi(), expected_data.raw_csi());
        }
        let decoded = open_datagram(&KEY, &fixture("non-ht")).unwrap();
        let Message::CsiData(non_ht) = decoded.message() else { panic!("expected non-HT CSI") };
        assert_eq!(non_ht.raw_csi(), &[1, 2, 0x80, 0x7f, 0xff, 0]);
        assert_eq!(non_ht.radio().channel(), 1);
        assert_eq!(non_ht.radio().rssi_dbm(), -42);
        assert_eq!(non_ht.blocks()[0].kind(), LtfKind::Lltf);
        let decoded = open_datagram(&KEY, &fixture("ht")).unwrap();
        let Message::CsiData(ht) = decoded.message() else { panic!("expected HT CSI") };
        assert_eq!(ht.first_invalid_bytes(), 4);
        assert_eq!(ht.raw_csi().last(), Some(&0x5a));
        assert_eq!(ht.iq_samples().len(), 5);
        let decoded = open_datagram(&KEY, &fixture("ht-stbc")).unwrap();
        let Message::CsiData(stbc) = decoded.message() else { panic!("expected STBC CSI") };
        assert!(stbc.radio().stbc());
        assert_eq!(stbc.blocks()[2].kind(), LtfKind::StbcHtLtf);
    }

    #[test]
    fn golden_health_seals_and_decodes_fixed_counters() {
        let body = encode_health(&health());
        let expected = fixture("health");
        assert_eq!(body.len(), 98);
        assert_eq!(seal(MessageKind::Health, 15, &body), expected);
        let decoded = open_datagram(&KEY, &expected).expect("health fixture opens");
        let Message::Health(health) = decoded.message() else { panic!("expected health") };
        assert_eq!(health.capture_seen(), 52);
        assert_eq!(health.queue_drop_full(), 54);
        assert_eq!(health.encoder_max_us(), 59);
    }

    #[test]
    fn every_valid_datagram_prefix_is_rejected_without_panic() {
        for name in ["capabilities", "non-ht", "ht", "ht-stbc", "health"] {
            let datagram = fixture(name);
            for length in 0..datagram.len() {
                assert!(
                    open_datagram(&KEY, &datagram[..length]).is_err(),
                    "accepted {name} prefix {length}"
                );
            }
        }
    }

    #[test]
    fn header_length_tag_and_version_fail_before_body_decode() {
        let valid = fixture("non-ht");

        let mut version = valid.clone();
        version[0] = 2;
        assert!(matches!(
            open_datagram(&KEY, &version),
            Err(WireError::UnknownVersion { version: 2 })
        ));

        let mut header_length = valid.clone();
        header_length[2] = 31;
        assert!(matches!(open_datagram(&KEY, &header_length), Err(WireError::HeaderLength { .. })));

        let mut reserved_a = valid.clone();
        reserved_a[14] = 1;
        assert!(matches!(
            open_datagram(&KEY, &reserved_a),
            Err(WireError::ReservedHeader { offset: 14, .. })
        ));

        let mut reserved_b = valid.clone();
        reserved_b[30] = 1;
        assert!(matches!(
            open_datagram(&KEY, &reserved_b),
            Err(WireError::ReservedHeader { offset: 30, .. })
        ));

        let mut tag = valid.clone();
        *tag.last_mut().expect("tag byte") ^= 1;
        assert!(matches!(open_datagram(&KEY, &tag), Err(WireError::AuthenticationFailed)));

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(matches!(open_datagram(&KEY, &trailing), Err(WireError::Trailing { .. })));

        let mut declared_longer = valid.clone();
        let declared = u16::from_le_bytes([declared_longer[28], declared_longer[29]]);
        declared_longer[28..30].copy_from_slice(&(declared + 1).to_le_bytes());
        assert!(matches!(open_datagram(&KEY, &declared_longer), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn header_zero_values_are_reserved_and_seal_reports_them() {
        let body = encode_csi_data(&non_ht());
        assert!(matches!(
            seal_datagram(&KEY, MessageKind::CsiData, DEVICE_ID, 0, BOOT_GENERATION, 1, &body),
            Err(SealError::ZeroKeyEpoch)
        ));
        assert!(matches!(
            seal_datagram(&KEY, MessageKind::CsiData, DEVICE_ID, KEY_EPOCH, 0, 1, &body),
            Err(SealError::ZeroBootGeneration)
        ));
        let valid = fixture("non-ht");
        for (offset, expected) in [(12, "key"), (16, "boot"), (20, "sequence")] {
            let mut bytes = valid.clone();
            match offset {
                12 => bytes[12..14].fill(0),
                16 => bytes[16..20].fill(0),
                20 => bytes[20..28].fill(0),
                _ => unreachable!("fixed test offset"),
            }
            let error = open_datagram(&KEY, &bytes).expect_err("zero header field accepted");
            assert!(
                matches!(
                    (expected, error),
                    ("key", WireError::ZeroKeyEpoch)
                        | ("boot", WireError::ZeroBootGeneration)
                        | ("sequence", WireError::ZeroMessageSequence)
                ),
                "wrong zero-field error for {expected}"
            );
        }
    }

    #[test]
    fn authenticated_unknown_kind_and_malformed_body_are_distinct() {
        let body = encode_csi_data(&non_ht());
        let unknown = seal_raw(0x7f, 71, &body);
        assert!(matches!(
            open_datagram(&KEY, &unknown),
            Err(WireError::UnknownKind { kind: 0x7f })
        ));

        let malformed = seal_raw(2, 72, &[0; 75]);
        assert!(matches!(
            open_datagram(&KEY, &malformed),
            Err(WireError::MalformedBody { kind: "csi-data", .. })
        ));

        let mut invalid_stbc = encode_csi_data(&non_ht()).into_vec();
        invalid_stbc[62] = 2;
        let invalid_stbc = seal_raw(2, 73, &invalid_stbc);
        assert!(matches!(
            open_datagram(&KEY, &invalid_stbc),
            Err(WireError::MalformedBody {
                error: BodyError::UnknownEnum { field: "stbc", value: 2 },
                ..
            })
        ));
    }

    #[test]
    fn authenticated_csi_body_rejects_each_structural_accounting_violation() {
        let base = encode_csi_data(&non_ht()).into_vec();
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                {
                    let mut body = base.clone();
                    body[70] = 0;
                    body
                },
                "block count",
            ),
            (
                {
                    let mut body = base.clone();
                    body[75] = 9;
                    body
                },
                "unknown LTF",
            ),
            (
                {
                    let mut body = base.clone();
                    body[75] = 2;
                    body
                },
                "LTF order",
            ),
            (
                {
                    let mut body = base.clone();
                    body[76] = 1;
                    body
                },
                "block reserved",
            ),
            (
                {
                    let mut body = base.clone();
                    body[77..79].fill(0);
                    body
                },
                "block sample count",
            ),
            (
                {
                    let mut body = base.clone();
                    body[79] = 2;
                    body
                },
                "block offset",
            ),
            (
                {
                    let mut body = base.clone();
                    body[73..75].copy_from_slice(&2_u16.to_le_bytes());
                    body
                },
                "complex sample count",
            ),
            (
                {
                    let mut body = base.clone();
                    body[68] = 1;
                    body
                },
                "first invalid",
            ),
            (
                {
                    let mut body = base.clone();
                    body[69] = 1;
                    body
                },
                "trailing invalid",
            ),
        ];
        for (body, label) in cases {
            let datagram = seal_raw(2, 80, &body);
            assert!(
                matches!(open_datagram(&KEY, &datagram), Err(WireError::MalformedBody { .. })),
                "accepted {label}"
            );
        }

        let mut odd_raw = base.clone();
        odd_raw.truncate(86);
        odd_raw[71..73].copy_from_slice(&5_u16.to_le_bytes());
        assert!(matches!(
            open_datagram(&KEY, &seal_raw(2, 81, &odd_raw)),
            Err(WireError::MalformedBody { error: BodyError::RawLengthMismatch, .. })
        ));

        let mut too_short = base;
        too_short.truncate(83);
        too_short[68] = 4;
        too_short[71..73].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            open_datagram(&KEY, &seal_raw(2, 82, &too_short)),
            Err(WireError::MalformedBody { error: BodyError::FirstInvalidOutOfBounds, .. })
        ));
    }

    #[test]
    fn authenticated_capability_rejects_digest_and_descriptor_mismatch() {
        let mut digest_mismatch = encode_capabilities(&descriptor()).into_vec();
        digest_mismatch[0] ^= 1;
        assert!(matches!(
            open_datagram(&KEY, &seal_raw(1, 83, &digest_mismatch)),
            Err(WireError::MalformedBody {
                kind: "capabilities",
                error: BodyError::CapabilityDigestMismatch,
            })
        ));

        let mut descriptor_mismatch = encode_capabilities(&descriptor()).into_vec();
        descriptor_mismatch[34] = 2;
        assert!(matches!(
            open_datagram(&KEY, &seal_raw(1, 84, &descriptor_mismatch)),
            Err(WireError::MalformedBody {
                kind: "capabilities",
                error: BodyError::DescriptorMismatch { field: "descriptor_version", value: 2 },
            })
        ));
    }

    #[test]
    fn authenticated_capability_rejects_each_fixed_descriptor_bit() {
        let cases = [
            (35, "target_kind", 2),
            (36, "source_iq_order", 2),
            (37, "output_encoding", 2),
            (38, "sample_axis", 2),
            (39, "sample_order", 2),
            (40, "phase_state", 2),
            (41, "driver_rx_timestamp_bits", 64),
            (42, "capture_config", 0),
        ];
        for (sequence, (offset, field, value)) in (90_u64..).zip(cases) {
            let mut body = encode_capabilities(&descriptor()).into_vec();
            body[offset] = value;
            assert!(
                matches!(
                    open_datagram(&KEY, &seal_raw(1, sequence, &body)),
                    Err(WireError::MalformedBody {
                        kind: "capabilities",
                        error: BodyError::DescriptorMismatch { field: actual, value: received },
                    }) if actual == field && received == value
                ),
                "accepted capability descriptor field {field}"
            );
        }
    }

    #[test]
    fn authenticated_csi_rejects_radio_and_ltf_contract_mismatches() {
        let base = encode_csi_data(&non_ht()).into_vec();
        let mut unknown_secondary = base.clone();
        unknown_secondary[59] = 3;
        let mut unknown_phy = base.clone();
        unknown_phy[60] = 3;
        let mut unknown_bandwidth = base.clone();
        unknown_bandwidth[61] = 3;
        let mut unknown_stbc = base.clone();
        unknown_stbc[62] = 2;
        let mut invalid_secondary = base.clone();
        invalid_secondary[59] = 1;
        let mut invalid_bandwidth = base.clone();
        invalid_bandwidth[61] = 2;
        let mut invalid_stbc = base.clone();
        invalid_stbc[62] = 1;
        let mut phy_ltf_mismatch = base.clone();
        phy_ltf_mismatch[60] = 2;
        phy_ltf_mismatch[65] = 0;
        let mut ltf_mismatch = base;
        ltf_mismatch[75] = 2;

        let cases = [
            (unknown_secondary, BodyError::UnknownEnum { field: "secondary", value: 3 }),
            (unknown_phy, BodyError::UnknownEnum { field: "phy", value: 3 }),
            (unknown_bandwidth, BodyError::UnknownEnum { field: "bandwidth", value: 3 }),
            (unknown_stbc, BodyError::UnknownEnum { field: "stbc", value: 2 }),
            (invalid_secondary, BodyError::InvalidRadioCombination),
            (invalid_bandwidth, BodyError::InvalidRadioCombination),
            (invalid_stbc, BodyError::InvalidRadioCombination),
            (phy_ltf_mismatch, BodyError::InvalidBlockCount(1)),
            (ltf_mismatch, BodyError::InvalidLtfOrder { block: 0 }),
        ];
        for (sequence, (body, expected)) in (100_u64..).zip(cases) {
            assert_eq!(
                open_datagram(&KEY, &seal_raw(2, sequence, &body)),
                Err(WireError::MalformedBody { kind: "csi-data", error: expected })
            );
        }
    }

    #[test]
    fn body_constructor_enforces_s3_capacity_and_exact_accounting() {
        assert_eq!(MAX_RAW_CSI_BYTES, 612);
        assert_eq!(MAX_CSI_PLAINTEXT_BYTES, 705);
        assert_eq!(TAG_BYTES, 16);
        let radio = RadioRxS3::try_new(
            1,
            S3SecondaryKind::None,
            S3PhyKind::NonHt,
            S3BandwidthKind::TwentyMhz,
            false,
            -40,
            -95,
            1,
            0,
            0,
        )
        .expect("valid radio");
        assert!(matches!(
            CsiDataV1::try_new(
                [0; 32],
                0,
                0,
                0,
                [1, 2, 3, 4, 5, 6],
                radio,
                0,
                0,
                vec![LtfBlock::new(LtfKind::Lltf, 1, 0)],
                vec![0, 1],
            ),
            Err(BodyError::ZeroCaptureSequence)
        ));
        assert!(matches!(
            RadioRxS3::try_new(
                1,
                S3SecondaryKind::None,
                S3PhyKind::NonHt,
                S3BandwidthKind::TwentyMhz,
                false,
                -40,
                -95,
                0,
                1,
                0,
            ),
            Err(BodyError::RadioRateEncodingMismatch)
        ));
        assert!(matches!(
            CsiDataV1::try_new(
                [0; 32],
                1,
                0,
                0,
                [0; 6],
                radio,
                0,
                0,
                vec![LtfBlock::new(LtfKind::Lltf, 1, 0)],
                vec![0, 1],
            ),
            Err(BodyError::ZeroSourceMac)
        ));
        assert!(matches!(
            CsiDataV1::try_new(
                [0; 32],
                1,
                0,
                0,
                [1, 2, 3, 4, 5, 6],
                radio,
                0,
                0,
                vec![
                    LtfBlock::new(LtfKind::Lltf, 1, 0),
                    LtfBlock::new(LtfKind::Lltf, 1, 2),
                    LtfBlock::new(LtfKind::Lltf, 1, 4),
                    LtfBlock::new(LtfKind::Lltf, 1, 6),
                ],
                vec![0, 1, 2, 3, 4, 5, 6, 7],
            ),
            Err(BodyError::InvalidBlockCount(4))
        ));
        assert!(matches!(
            CapabilityDescriptor::try_new(
                [0; 32],
                [0; 32],
                (HEADER_BYTES + TAG_BYTES + MAX_CSI_PLAINTEXT_BYTES - 1) as u16
            ),
            Err(BodyError::InvalidDatagramBudget { .. })
        ));
        assert!(matches!(
            seal_datagram(
                &KEY,
                MessageKind::Health,
                DEVICE_ID,
                KEY_EPOCH,
                BOOT_GENERATION,
                85,
                &vec![0; MAX_CSI_PLAINTEXT_BYTES + 1],
            ),
            Err(SealError::BodyTooLarge { .. })
        ));
        assert!(matches!(
            open_datagram(&KEY, &seal_raw(2, 86, &vec![0; MAX_CSI_PLAINTEXT_BYTES + 1])),
            Err(WireError::CiphertextTooLarge { .. })
        ));
    }

    #[test]
    fn body_constructor_rejects_raw_csi_above_s3_ceiling() {
        let radio = RadioRxS3::try_new(
            1,
            S3SecondaryKind::None,
            S3PhyKind::NonHt,
            S3BandwidthKind::TwentyMhz,
            false,
            -40,
            -95,
            1,
            0,
            0,
        )
        .expect("valid radio");
        assert!(matches!(
            CsiDataV1::try_new(
                [0; 32],
                1,
                0,
                0,
                [1, 2, 3, 4, 5, 6],
                radio,
                0,
                0,
                vec![LtfBlock::new(LtfKind::Lltf, 1, 0)],
                vec![0; MAX_RAW_CSI_BYTES + 2],
            ),
            Err(BodyError::RawCsiTooLarge { actual: 614, maximum: 612 })
        ));
    }
}

impl MessageKind {
    const fn byte(self) -> u8 {
        match self {
            Self::Capabilities => 1,
            Self::CsiData => 2,
            Self::Health => 3,
        }
    }

    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Capabilities),
            2 => Some(Self::CsiData),
            3 => Some(Self::Health),
            _ => None,
        }
    }
}

/// Header values decoded without interpreting the encrypted body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Header {
    kind: u8,
    device_id: u64,
    key_epoch: u16,
    boot_generation: u32,
    message_seq: u64,
    ciphertext_bytes: u16,
}

impl Header {
    /// Returns the authenticated message kind, if it is one of the v1 kinds.
    #[must_use]
    pub const fn kind(self) -> Option<MessageKind> {
        MessageKind::from_byte(self.kind)
    }

    /// Returns the raw kind byte, including an unknown authenticated value.
    #[must_use]
    pub const fn kind_byte(self) -> u8 {
        self.kind
    }

    /// Returns the provisioned opaque device identity.
    #[must_use]
    pub const fn device_id(self) -> u64 {
        self.device_id
    }

    /// Returns the enrolled key epoch.
    #[must_use]
    pub const fn key_epoch(self) -> u16 {
        self.key_epoch
    }

    /// Returns the persistent device boot generation.
    #[must_use]
    pub const fn boot_generation(self) -> u32 {
        self.boot_generation
    }

    /// Returns the transport sequence number.
    #[must_use]
    pub const fn message_seq(self) -> u64 {
        self.message_seq
    }

    /// Returns the declared encrypted body length.
    #[must_use]
    pub const fn ciphertext_bytes(self) -> u16 {
        self.ciphertext_bytes
    }
}

/// Errors raised by fixed-header parsing, authentication, or body decoding.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WireError {
    /// The datagram ended before a required fixed or variable section.
    #[error("native-frame datagram is truncated: needed {needed} bytes, received {actual}")]
    Truncated {
        /// Minimum bytes required by the current section.
        needed: usize,
        /// Bytes supplied by the caller.
        actual: usize,
    },
    /// The datagram contained bytes outside its exact declared length.
    #[error("native-frame datagram has trailing bytes: expected {expected}, received {actual}")]
    Trailing {
        /// Exact bytes declared by the header.
        expected: usize,
        /// Bytes supplied by the caller.
        actual: usize,
    },
    /// A version other than the sole supported schema was observed.
    #[error("unknown native-frame wire version {version}")]
    UnknownVersion {
        /// Version byte found in the datagram.
        version: u8,
    },
    /// The header length field did not equal the fixed header size.
    #[error("native-frame header_bytes must be {expected}, received {actual}")]
    HeaderLength {
        /// Required fixed header length.
        expected: u16,
        /// Header length found in the datagram.
        actual: u16,
    },
    /// A reserved header field was non-zero.
    #[error("native-frame reserved header field at offset {offset} is {value:#06x}")]
    ReservedHeader {
        /// Byte offset of the reserved field.
        offset: usize,
        /// Value found in the reserved field.
        value: u16,
    },
    /// The header used the reserved zero key epoch.
    #[error("native-frame key_epoch must be non-zero")]
    ZeroKeyEpoch,
    /// The header used the reserved zero boot generation.
    #[error("native-frame boot_generation must be non-zero")]
    ZeroBootGeneration,
    /// The header used the reserved zero transport sequence.
    #[error("native-frame message_seq must be non-zero")]
    ZeroMessageSequence,
    /// The encrypted body exceeds the native-frame cleartext ceiling.
    #[error("native-frame ciphertext length {actual} exceeds {maximum}")]
    CiphertextTooLarge {
        /// Declared encrypted body bytes.
        actual: usize,
        /// Maximum allowed cleartext body bytes.
        maximum: usize,
    },
    /// AES-GCM authentication failed.
    #[error("native-frame authentication failed")]
    AuthenticationFailed,
    /// A validly authenticated v1 header named no known body kind.
    #[error("authenticated native-frame kind {kind} is unknown")]
    UnknownKind {
        /// Authenticated raw kind byte.
        kind: u8,
    },
    /// The authenticated body violated the selected exact grammar.
    #[error("malformed native-frame {kind} body: {error}")]
    MalformedBody {
        /// Body kind selected by the header.
        kind: &'static str,
        /// Structural or semantic body error.
        error: BodyError,
    },
}

/// Structural and semantic failures in one native-frame body.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BodyError {
    /// The body length was not the exact fixed or computed length.
    #[error("expected {expected} bytes, received {actual}")]
    ExactLength {
        /// Required body length.
        expected: usize,
        /// Supplied body length.
        actual: usize,
    },
    /// A body exceeded the cleartext ceiling.
    #[error("body length {actual} exceeds {maximum}")]
    PlaintextTooLarge {
        /// Supplied body length.
        actual: usize,
        /// Maximum allowed body length.
        maximum: usize,
    },
    /// The capability digest did not hash the descriptor bytes.
    #[error("capability digest does not match descriptor bytes")]
    CapabilityDigestMismatch,
    /// A body field had an unsupported enumeration value.
    #[error("field {field} has unknown value {value:#04x}")]
    UnknownEnum {
        /// Field whose value was rejected.
        field: &'static str,
        /// Raw value found on the wire.
        value: u8,
    },
    /// A fixed descriptor field differed from the v1 contract.
    #[error("capability descriptor field {field} has value {value:#04x}")]
    DescriptorMismatch {
        /// Fixed descriptor field name.
        field: &'static str,
        /// Raw value found on the wire.
        value: u8,
    },
    /// A fixed descriptor budget was zero or below its envelope overhead.
    #[error("capability datagram budget must be at least {minimum} bytes")]
    InvalidDatagramBudget {
        /// Minimum header plus tag bytes.
        minimum: u16,
    },
    /// The capture sequence is reserved from zero.
    #[error("capture_seq must be non-zero")]
    ZeroCaptureSequence,
    /// The body did not contain one to three LTF blocks.
    #[error("ltf_block_count must be in 1..=3, received {0}")]
    InvalidBlockCount(u8),
    /// A block reserved byte was non-zero.
    #[error("ltf block {block} reserved byte must be zero")]
    NonZeroBlockReserved {
        /// Block index.
        block: usize,
    },
    /// A block had no logical pairs.
    #[error("ltf block {block} sample_count must be non-zero")]
    ZeroBlockSampleCount {
        /// Block index.
        block: usize,
    },
    /// A block did not use the exact implied LTF order.
    #[error("ltf block {block} kind is not the expected ordered kind")]
    InvalidLtfOrder {
        /// Block index.
        block: usize,
    },
    /// A block did not begin at the contiguous raw offset.
    #[error("ltf block {block} raw offset is not contiguous")]
    InvalidBlockOffset {
        /// Block index.
        block: usize,
    },
    /// Block sample counts did not equal the complete raw pair count.
    #[error("ltf block sample counts do not equal complex_sample_count")]
    BlockSampleCountMismatch,
    /// Raw byte accounting did not match complete pairs and trailing bytes.
    #[error("raw_csi_bytes does not equal 2 * complex_sample_count + trailing_invalid_bytes")]
    RawLengthMismatch,
    /// Only zero or four leading invalid bytes are supported.
    #[error("first_invalid_bytes must be zero or four")]
    InvalidFirstInvalidBytes,
    /// Only zero or two trailing alignment bytes are supported.
    #[error("trailing_invalid_bytes must be zero or two")]
    InvalidTrailingInvalidBytes,
    /// The leading invalid marker did not fit in the raw buffer.
    #[error("first_invalid_bytes exceeds raw_csi_bytes")]
    FirstInvalidOutOfBounds,
    /// A raw CSI buffer exceeded the target maximum.
    #[error("raw_csi_bytes {actual} exceeds {maximum}")]
    RawCsiTooLarge {
        /// Supplied raw CSI byte count.
        actual: usize,
        /// Maximum raw CSI byte count.
        maximum: usize,
    },
    /// The source radio facts are not a valid S3 combination.
    #[error("S3 radio facts are an unsupported PHY/bandwidth/secondary/STBC combination")]
    InvalidRadioCombination,
    /// A rate or MCS field was populated for the wrong PHY.
    #[error("rate and mcs fields do not match the selected PHY")]
    RadioRateEncodingMismatch,
    /// The receive antenna is outside the two S3 antenna values.
    #[error("rx_antenna must be zero or one")]
    InvalidRxAntenna,
    /// The source MAC was all zero.
    #[error("source_mac must not be all zero")]
    ZeroSourceMac,
}

/// The S3 PHY values represented by the native-frame body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum S3PhyKind {
    /// Non-HT PHY.
    NonHt,
    /// HT PHY.
    Ht,
}

impl S3PhyKind {
    const fn byte(self) -> u8 {
        match self {
            Self::NonHt => 1,
            Self::Ht => 2,
        }
    }

    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::NonHt),
            2 => Some(Self::Ht),
            _ => None,
        }
    }
}

/// The S3 channel bandwidth values represented by the body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum S3BandwidthKind {
    /// Twenty megahertz.
    TwentyMhz,
    /// Forty megahertz.
    FortyMhz,
}

impl S3BandwidthKind {
    const fn byte(self) -> u8 {
        match self {
            Self::TwentyMhz => 1,
            Self::FortyMhz => 2,
        }
    }

    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::TwentyMhz),
            2 => Some(Self::FortyMhz),
            _ => None,
        }
    }
}

/// The S3 secondary-channel placement represented by the body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum S3SecondaryKind {
    /// No secondary channel.
    None,
    /// Secondary channel above the primary channel.
    Above,
    /// Secondary channel below the primary channel.
    Below,
}

impl S3SecondaryKind {
    const fn byte(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Above => 1,
            Self::Below => 2,
        }
    }

    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Above),
            2 => Some(Self::Below),
            _ => None,
        }
    }
}

/// The ordered LTF block kinds represented by the body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LtfKind {
    /// Legacy LTF.
    Lltf,
    /// HT LTF.
    HtLtf,
    /// STBC HT LTF.
    StbcHtLtf,
}

impl LtfKind {
    const fn byte(self) -> u8 {
        match self {
            Self::Lltf => 1,
            Self::HtLtf => 2,
            Self::StbcHtLtf => 3,
        }
    }

    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Lltf),
            2 => Some(Self::HtLtf),
            3 => Some(Self::StbcHtLtf),
            _ => None,
        }
    }
}

/// Complete S3 radio receive metadata carried by a CSI body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RadioRxS3 {
    channel: u8,
    secondary: S3SecondaryKind,
    phy: S3PhyKind,
    bandwidth: S3BandwidthKind,
    stbc: bool,
    rssi_dbm: i8,
    noise_floor_dbm: i8,
    rate: u8,
    mcs: u8,
    rx_antenna: u8,
}

impl RadioRxS3 {
    /// Constructs radio facts after applying every v1 S3 combination rule.
    #[expect(clippy::too_many_arguments, reason = "These are the fixed native-frame radio fields")]
    pub fn try_new(
        channel: u8,
        secondary: S3SecondaryKind,
        phy: S3PhyKind,
        bandwidth: S3BandwidthKind,
        stbc: bool,
        rssi_dbm: i8,
        noise_floor_dbm: i8,
        rate: u8,
        mcs: u8,
        rx_antenna: u8,
    ) -> Result<Self, BodyError> {
        if !(1..=14).contains(&channel) {
            return Err(BodyError::InvalidRadioCombination);
        }
        if rx_antenna > 1 {
            return Err(BodyError::InvalidRxAntenna);
        }
        let valid_combination = matches!(
            (phy, bandwidth, secondary, stbc),
            (S3PhyKind::NonHt, S3BandwidthKind::TwentyMhz, S3SecondaryKind::None, false)
                | (S3PhyKind::Ht, S3BandwidthKind::TwentyMhz, S3SecondaryKind::None, _)
                | (
                    S3PhyKind::Ht,
                    S3BandwidthKind::FortyMhz,
                    S3SecondaryKind::Above | S3SecondaryKind::Below,
                    _,
                )
        );
        if !valid_combination {
            return Err(BodyError::InvalidRadioCombination);
        }
        if (matches!(phy, S3PhyKind::NonHt) && mcs != 0)
            || (matches!(phy, S3PhyKind::Ht) && rate != 0)
        {
            return Err(BodyError::RadioRateEncodingMismatch);
        }
        Ok(Self {
            channel,
            secondary,
            phy,
            bandwidth,
            stbc,
            rssi_dbm,
            noise_floor_dbm,
            rate,
            mcs,
            rx_antenna,
        })
    }

    /// Returns the primary channel.
    #[must_use]
    pub const fn channel(self) -> u8 {
        self.channel
    }

    /// Returns the secondary-channel placement.
    #[must_use]
    pub const fn secondary(self) -> S3SecondaryKind {
        self.secondary
    }

    /// Returns the PHY category.
    #[must_use]
    pub const fn phy(self) -> S3PhyKind {
        self.phy
    }

    /// Returns the channel bandwidth.
    #[must_use]
    pub const fn bandwidth(self) -> S3BandwidthKind {
        self.bandwidth
    }

    /// Returns whether STBC is active.
    #[must_use]
    pub const fn stbc(self) -> bool {
        self.stbc
    }

    /// Returns received signal strength in dBm.
    #[must_use]
    pub const fn rssi_dbm(self) -> i8 {
        self.rssi_dbm
    }

    /// Returns the reported noise floor in dBm.
    #[must_use]
    pub const fn noise_floor_dbm(self) -> i8 {
        self.noise_floor_dbm
    }

    /// Returns the non-HT rate field.
    #[must_use]
    pub const fn rate(self) -> u8 {
        self.rate
    }

    /// Returns the HT MCS field.
    #[must_use]
    pub const fn mcs(self) -> u8 {
        self.mcs
    }

    /// Returns the receive antenna ordinal.
    #[must_use]
    pub const fn rx_antenna(self) -> u8 {
        self.rx_antenna
    }
}

/// One contiguous LTF block descriptor in native driver order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LtfBlock {
    kind: LtfKind,
    sample_count: u16,
    raw_offset_bytes: u16,
}

impl LtfBlock {
    /// Creates a block descriptor; full order and accounting are checked by the CSI body.
    #[must_use]
    pub const fn new(kind: LtfKind, sample_count: u16, raw_offset_bytes: u16) -> Self {
        Self { kind, sample_count, raw_offset_bytes }
    }

    /// Returns the block kind.
    #[must_use]
    pub const fn kind(self) -> LtfKind {
        self.kind
    }

    /// Returns the number of complete complex pairs in this block.
    #[must_use]
    pub const fn sample_count(self) -> u16 {
        self.sample_count
    }

    /// Returns the raw byte offset at which this block begins.
    #[must_use]
    pub const fn raw_offset_bytes(self) -> u16 {
        self.raw_offset_bytes
    }
}

/// The fixed capability descriptor bound to one firmware build and ABI.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityDescriptor {
    firmware_build_digest: [u8; 32],
    idf_wifi_abi_digest: [u8; 32],
    datagram_budget_bytes: u16,
}

impl CapabilityDescriptor {
    /// Creates the only supported S3 v1 descriptor shape.
    pub fn try_new(
        firmware_build_digest: [u8; 32],
        idf_wifi_abi_digest: [u8; 32],
        datagram_budget_bytes: u16,
    ) -> Result<Self, BodyError> {
        if datagram_budget_bytes < minimum_datagram_budget_bytes() {
            return Err(BodyError::InvalidDatagramBudget {
                minimum: minimum_datagram_budget_bytes(),
            });
        }
        Ok(Self { firmware_build_digest, idf_wifi_abi_digest, datagram_budget_bytes })
    }

    /// Returns the immutable firmware build digest.
    #[must_use]
    pub const fn firmware_build_digest(&self) -> [u8; 32] {
        self.firmware_build_digest
    }

    /// Returns the ESP-IDF Wi-Fi ABI digest.
    #[must_use]
    pub const fn idf_wifi_abi_digest(&self) -> [u8; 32] {
        self.idf_wifi_abi_digest
    }

    /// Returns the configured transport datagram budget.
    #[must_use]
    pub const fn datagram_budget_bytes(&self) -> u16 {
        self.datagram_budget_bytes
    }

    pub(crate) fn to_bytes(&self) -> [u8; CAPABILITY_DESCRIPTOR_BYTES] {
        let mut bytes = [0_u8; CAPABILITY_DESCRIPTOR_BYTES];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 1;
        bytes[3] = 1;
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[7] = 32;
        bytes[8] = 0x07;
        bytes[9..11].copy_from_slice(&(MAX_RAW_CSI_BYTES as u16).to_le_bytes());
        bytes[11..13].copy_from_slice(&(MAX_CSI_PLAINTEXT_BYTES as u16).to_le_bytes());
        bytes[13..15].copy_from_slice(&self.datagram_budget_bytes.to_le_bytes());
        bytes[15..47].copy_from_slice(&self.firmware_build_digest);
        bytes[47..79].copy_from_slice(&self.idf_wifi_abi_digest);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, BodyError> {
        if bytes.len() != CAPABILITY_DESCRIPTOR_BYTES {
            return Err(BodyError::ExactLength {
                expected: CAPABILITY_DESCRIPTOR_BYTES,
                actual: bytes.len(),
            });
        }
        let fixed = [
            (0, 1, "descriptor_version"),
            (1, 1, "target_kind"),
            (2, 1, "source_iq_order"),
            (3, 1, "output_encoding"),
            (4, 1, "sample_axis"),
            (5, 1, "sample_order"),
            (6, 1, "phase_state"),
            (7, 32, "driver_rx_timestamp_bits"),
            (8, 0x07, "capture_config"),
        ];
        for (offset, expected, field) in fixed {
            if bytes[offset] != expected {
                return Err(BodyError::DescriptorMismatch { field, value: bytes[offset] });
            }
        }
        let raw_max = u16::from_le_bytes([bytes[9], bytes[10]]);
        if raw_max != MAX_RAW_CSI_BYTES as u16 {
            return Err(BodyError::DescriptorMismatch {
                field: "max_raw_csi_bytes",
                value: bytes[9],
            });
        }
        let plaintext_max = u16::from_le_bytes([bytes[11], bytes[12]]);
        if plaintext_max != MAX_CSI_PLAINTEXT_BYTES as u16 {
            return Err(BodyError::DescriptorMismatch {
                field: "max_csi_plaintext_bytes",
                value: bytes[11],
            });
        }
        let budget = u16::from_le_bytes([bytes[13], bytes[14]]);
        Self::try_new(
            bytes[15..47].try_into().expect("checked capability descriptor length"),
            bytes[47..79].try_into().expect("checked capability descriptor length"),
            budget,
        )
    }
}

/// A decoded and authenticated capability body.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilitiesV1 {
    capability_digest: [u8; 32],
    descriptor: CapabilityDescriptor,
}

impl CapabilitiesV1 {
    /// Creates a capability body from a fixed descriptor.
    #[must_use]
    pub fn new(descriptor: CapabilityDescriptor) -> Self {
        let digest: [u8; 32] = Sha256::digest(descriptor.to_bytes()).into();
        Self { capability_digest: digest, descriptor }
    }

    /// Returns the SHA-256 descriptor digest.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }

    /// Returns the immutable descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &CapabilityDescriptor {
        &self.descriptor
    }

    pub(crate) fn from_persisted(digest: &[u8], descriptor: &[u8]) -> Result<Self, BodyError> {
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| BodyError::ExactLength { expected: 32, actual: digest.len() })?;
        let expected_digest: [u8; 32] = Sha256::digest(descriptor).into();
        if digest != expected_digest {
            return Err(BodyError::CapabilityDigestMismatch);
        }
        Ok(Self {
            capability_digest: digest,
            descriptor: CapabilityDescriptor::from_bytes(descriptor)?,
        })
    }
}

/// CSI data body preserving exact driver metadata and raw bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CsiDataV1 {
    capability_digest: [u8; 32],
    capture_sequence: u64,
    driver_rx_timestamp_us: u32,
    callback_tick_us: u64,
    source_mac: [u8; 6],
    radio: RadioRxS3,
    first_invalid_bytes: u8,
    trailing_invalid_bytes: u8,
    complex_sample_count: u16,
    blocks: Box<[LtfBlock]>,
    raw_csi: Box<[u8]>,
}

impl CsiDataV1 {
    /// Constructs and validates one complete S3 CSI body.
    #[expect(clippy::too_many_arguments, reason = "These are the fixed native-frame body fields")]
    pub fn try_new(
        capability_digest: [u8; 32],
        capture_sequence: u64,
        driver_rx_timestamp_us: u32,
        callback_tick_us: u64,
        source_mac: [u8; 6],
        radio: RadioRxS3,
        first_invalid_bytes: u8,
        trailing_invalid_bytes: u8,
        blocks: impl Into<Box<[LtfBlock]>>,
        raw_csi: impl Into<Box<[u8]>>,
    ) -> Result<Self, BodyError> {
        let blocks = blocks.into();
        let raw_csi = raw_csi.into();
        if source_mac == [0; 6] {
            return Err(BodyError::ZeroSourceMac);
        }
        let complex_sample_count = validate_csi_parts(
            capture_sequence,
            radio,
            first_invalid_bytes,
            trailing_invalid_bytes,
            &blocks,
            &raw_csi,
        )?;
        Ok(Self {
            capability_digest,
            capture_sequence,
            driver_rx_timestamp_us,
            callback_tick_us,
            source_mac,
            radio,
            first_invalid_bytes,
            trailing_invalid_bytes,
            complex_sample_count,
            blocks,
            raw_csi,
        })
    }

    /// Returns the capability descriptor digest required for this body.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }

    /// Returns the capture-side sequence, including gaps caused by dropped callbacks.
    #[must_use]
    pub const fn capture_sequence(&self) -> u64 {
        self.capture_sequence
    }

    /// Returns the exact driver receive timestamp.
    #[must_use]
    pub const fn driver_rx_timestamp_us(&self) -> u32 {
        self.driver_rx_timestamp_us
    }

    /// Returns the callback delivery tick in the boot clock.
    #[must_use]
    pub const fn callback_tick_us(&self) -> u64 {
        self.callback_tick_us
    }

    /// Returns the driver-reported source MAC.
    #[must_use]
    pub const fn source_mac(&self) -> [u8; 6] {
        self.source_mac
    }

    /// Returns all authenticated radio receive facts.
    #[must_use]
    pub const fn radio(&self) -> RadioRxS3 {
        self.radio
    }

    /// Returns the explicit leading invalid byte count.
    #[must_use]
    pub const fn first_invalid_bytes(&self) -> u8 {
        self.first_invalid_bytes
    }

    /// Returns trailing raw alignment bytes excluded from logical pairs.
    #[must_use]
    pub const fn trailing_invalid_bytes(&self) -> u8 {
        self.trailing_invalid_bytes
    }

    /// Returns the number of complete logical complex pairs.
    #[must_use]
    pub const fn complex_sample_count(&self) -> u16 {
        self.complex_sample_count
    }

    /// Returns LTF blocks in the driver-reported order.
    #[must_use]
    pub fn blocks(&self) -> &[LtfBlock] {
        &self.blocks
    }

    /// Returns exact ESP-IDF raw CSI bytes in `[imaginary, real]` order.
    #[must_use]
    pub fn raw_csi(&self) -> &[u8] {
        &self.raw_csi
    }

    /// Maps raw signed `[imaginary, real]` pairs to domain `IqSample` values.
    #[must_use]
    pub fn iq_samples(&self) -> Vec<IqSample> {
        self.raw_csi[..usize::from(self.complex_sample_count) * 2]
            .chunks_exact(2)
            .enumerate()
            .map(|(index, pair)| {
                let imaginary = i8::from_ne_bytes([pair[0]]) as i32;
                let real = i8::from_ne_bytes([pair[1]]) as i32;
                if self.first_invalid_bytes == 4 && index < 2 {
                    IqSample::invalid(real, imaginary)
                } else {
                    IqSample::new(real, imaginary)
                }
            })
            .collect()
    }
}

/// Health counters carried by the native-frame control body.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HealthV1 {
    capability_digest: [u8; 32],
    callback_tick_us: u64,
    capture_seen: u64,
    queue_drop_no_slot: u64,
    queue_drop_full: u64,
    oversize_reject: u64,
    encode_reject: u64,
    send_failure: u64,
    pool_high_water_slots: u16,
    callback_max_us: u32,
    encoder_max_us: u32,
}

impl HealthV1 {
    /// Creates a health body with monotonic counters supplied by the application.
    #[expect(clippy::too_many_arguments, reason = "These are the fixed native-frame health fields")]
    #[must_use]
    pub const fn new(
        capability_digest: [u8; 32],
        callback_tick_us: u64,
        capture_seen: u64,
        queue_drop_no_slot: u64,
        queue_drop_full: u64,
        oversize_reject: u64,
        encode_reject: u64,
        send_failure: u64,
        pool_high_water_slots: u16,
        callback_max_us: u32,
        encoder_max_us: u32,
    ) -> Self {
        Self {
            capability_digest,
            callback_tick_us,
            capture_seen,
            queue_drop_no_slot,
            queue_drop_full,
            oversize_reject,
            encode_reject,
            send_failure,
            pool_high_water_slots,
            callback_max_us,
            encoder_max_us,
        }
    }

    /// Returns the capability digest.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }

    /// Returns the callback tick.
    #[must_use]
    pub const fn callback_tick_us(&self) -> u64 {
        self.callback_tick_us
    }

    /// Returns the number of eligible callbacks seen.
    #[must_use]
    pub const fn capture_seen(&self) -> u64 {
        self.capture_seen
    }

    /// Returns callbacks dropped because no slot was available.
    #[must_use]
    pub const fn queue_drop_no_slot(&self) -> u64 {
        self.queue_drop_no_slot
    }

    /// Returns callbacks dropped because the queue was full.
    #[must_use]
    pub const fn queue_drop_full(&self) -> u64 {
        self.queue_drop_full
    }

    /// Returns oversize callback rejects.
    #[must_use]
    pub const fn oversize_reject(&self) -> u64 {
        self.oversize_reject
    }

    /// Returns encoder rejects.
    #[must_use]
    pub const fn encode_reject(&self) -> u64 {
        self.encode_reject
    }

    /// Returns send failures.
    #[must_use]
    pub const fn send_failure(&self) -> u64 {
        self.send_failure
    }

    /// Returns the slot-pool high-water mark.
    #[must_use]
    pub const fn pool_high_water_slots(&self) -> u16 {
        self.pool_high_water_slots
    }

    /// Returns the callback maximum duration.
    #[must_use]
    pub const fn callback_max_us(&self) -> u32 {
        self.callback_max_us
    }

    /// Returns the encoder maximum duration.
    #[must_use]
    pub const fn encoder_max_us(&self) -> u32 {
        self.encoder_max_us
    }
}

/// One decoded native-frame message after exact authentication and grammar checks.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Message {
    /// Capability message.
    Capabilities(CapabilitiesV1),
    /// CSI data message.
    CsiData(CsiDataV1),
    /// Health message.
    Health(HealthV1),
}

/// An authenticated body before message-kind and grammar decoding.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct AuthenticatedDatagram {
    header: Header,
    plaintext: Box<[u8]>,
}

impl AuthenticatedDatagram {
    /// Returns the fixed header authenticated as GCM additional data.
    #[must_use]
    pub(crate) const fn header(&self) -> Header {
        self.header
    }

    /// Returns the authenticated cleartext body for the later decoder stage.
    #[must_use]
    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

/// A packet that passed fixed-header, route-budget, and AEAD admission.
///
/// The encrypted bytes remain owned here until the caller has appended them to
/// the session record and consumes this value into a recorded packet.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct AdmittedDatagram {
    peer: SocketAddr,
    wire_format: WireFormat,
    bytes: Box<[u8]>,
    authenticated: AuthenticatedDatagram,
    header_route: HeaderRoute,
}

impl AdmittedDatagram {
    /// Returns the exact encrypted datagram bytes that must be appended.
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the authenticated fixed header.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the work-package 2 capture/session owner")
    )]
    pub(crate) const fn header(&self) -> Header {
        self.authenticated.header()
    }

    /// Converts authenticated bytes into a pure, bounded Demo candidate.
    #[must_use]
    pub(crate) fn into_candidate(
        self,
        session_time: SessionTime,
        receive_utc_ns: u64,
    ) -> WireCandidate {
        let Self { peer, wire_format: _, bytes, authenticated, header_route } = self;
        let header = authenticated.header();
        let body = match header.kind() {
            None => CandidateBody::UnknownKind { kind: header.kind_byte() },
            Some(kind) => match decode_body(kind, authenticated.plaintext()) {
                Ok(Message::Capabilities(capabilities)) => {
                    CandidateBody::Capabilities(capabilities)
                }
                Ok(Message::CsiData(data)) => CandidateBody::CsiData(data),
                Ok(Message::Health(health)) => CandidateBody::Health(health),
                Err(_) => CandidateBody::MalformedKnownBody,
            },
        };
        WireCandidate { peer, bytes, header_route, header, session_time, receive_utc_ns, body }
    }

    /// Moves one successfully appended admission into its session record.
    ///
    /// The caller must invoke this only after the bytes returned by [`Self::bytes`]
    /// have been durably appended. The exact bytes are moved without copying.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the work-package 2 capture/session owner")
    )]
    pub(crate) fn into_recorded(
        self,
        session_id: SessionId,
        record_seq: u64,
        receive_monotonic_ns: u64,
        receive_utc_ns: i64,
    ) -> RecordedDatagram {
        let Self { peer, wire_format, bytes, authenticated, header_route } = self;
        RecordedDatagram {
            packet: CapturedPacket::new(
                session_id,
                record_seq,
                receive_monotonic_ns,
                receive_utc_ns,
                peer,
                wire_format,
                bytes,
            ),
            authenticated,
            header_route,
        }
    }
}

/// A syntactically bounded authenticated body with no durable authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CandidateBody {
    /// An authenticated kind outside the native-frame v1 message set.
    UnknownKind { kind: u8 },
    /// A known kind whose body did not satisfy its exact grammar.
    MalformedKnownBody,
    /// A syntactically valid capability body.
    Capabilities(CapabilitiesV1),
    /// A syntactically valid CSI body.
    CsiData(CsiDataV1),
    /// A syntactically valid health body.
    Health(HealthV1),
}

/// A pure authenticated candidate awaiting Store-scoped admission and disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireCandidate {
    peer: SocketAddr,
    bytes: Box<[u8]>,
    header_route: HeaderRoute,
    header: Header,
    session_time: SessionTime,
    receive_utc_ns: u64,
    body: CandidateBody,
}

impl WireCandidate {
    #[must_use]
    pub(crate) const fn peer(&self) -> SocketAddr {
        self.peer
    }

    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub(crate) const fn header_route(&self) -> HeaderRoute {
        self.header_route
    }

    #[must_use]
    pub(crate) const fn header(&self) -> Header {
        self.header
    }

    #[must_use]
    pub(crate) const fn session_time(&self) -> SessionTime {
        self.session_time
    }

    #[must_use]
    pub(crate) const fn receive_utc_ns(&self) -> u64 {
        self.receive_utc_ns
    }

    #[must_use]
    pub(crate) const fn body(&self) -> &CandidateBody {
        &self.body
    }
}

/// An admitted datagram paired with its durable session record context.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct RecordedDatagram {
    packet: CapturedPacket,
    authenticated: AuthenticatedDatagram,
    header_route: HeaderRoute,
}

/// A decoded message paired with its authenticated header.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DecodedDatagram {
    header: Header,
    message: Message,
}

impl DecodedDatagram {
    /// Returns the authenticated fixed header.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// Returns the decoded message body.
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }
}

/// Errors returned while sealing a fixed native-frame datagram.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SealError {
    /// The key epoch is reserved from zero.
    #[error("key_epoch must be non-zero")]
    ZeroKeyEpoch,
    /// The boot generation is reserved from zero.
    #[error("boot_generation must be non-zero")]
    ZeroBootGeneration,
    /// The transport sequence is reserved from zero.
    #[error("message_seq must be non-zero")]
    ZeroMessageSequence,
    /// The body exceeded the u16 length field or the v1 cleartext ceiling.
    #[error("body length {actual} exceeds {maximum}")]
    BodyTooLarge {
        /// Supplied body bytes.
        actual: usize,
        /// Maximum body bytes.
        maximum: usize,
    },
    /// The body did not satisfy its selected exact grammar.
    #[error("invalid {kind} body: {error}")]
    InvalidBody {
        /// Selected body kind.
        kind: &'static str,
        /// Body validation failure.
        error: BodyError,
    },
}

/// Seals one exact native-frame body with AES-256-GCM.
///
/// `key` is supplied by the application; this function does not load or retain
/// secrets. The header is authenticated as GCM additional authenticated data.
pub fn seal_datagram(
    key: &[u8; 32],
    kind: MessageKind,
    device_id: u64,
    key_epoch: u16,
    boot_generation: u32,
    message_seq: u64,
    body: &[u8],
) -> Result<Box<[u8]>, SealError> {
    if key_epoch == 0 {
        return Err(SealError::ZeroKeyEpoch);
    }
    if boot_generation == 0 {
        return Err(SealError::ZeroBootGeneration);
    }
    if message_seq == 0 {
        return Err(SealError::ZeroMessageSequence);
    }
    if body.len() > u16::MAX as usize || body.len() > MAX_CSI_PLAINTEXT_BYTES {
        return Err(SealError::BodyTooLarge {
            actual: body.len(),
            maximum: MAX_CSI_PLAINTEXT_BYTES,
        });
    }
    validate_body(kind, body)
        .map_err(|error| SealError::InvalidBody { kind: kind_name(kind), error })?;

    let mut header = [0_u8; HEADER_BYTES];
    header[0] = WIRE_SCHEMA_VERSION;
    header[1] = kind.byte();
    header[2..4].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    header[4..12].copy_from_slice(&device_id.to_le_bytes());
    header[12..14].copy_from_slice(&key_epoch.to_le_bytes());
    header[16..20].copy_from_slice(&boot_generation.to_le_bytes());
    header[20..28].copy_from_slice(&message_seq.to_le_bytes());
    header[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());

    let nonce_bytes = nonce_bytes(boot_generation, message_seq);
    let cipher =
        Aes256Gcm::new_from_slice(key).expect("a 32-byte key always constructs AES-256-GCM");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: body, aad: &header })
        .map_err(|_| SealError::BodyTooLarge {
            actual: body.len(),
            maximum: MAX_CSI_PLAINTEXT_BYTES,
        })?;
    let mut datagram = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
    datagram.extend_from_slice(&header);
    datagram.extend_from_slice(&ciphertext);
    Ok(datagram.into_boxed_slice())
}

/// Authenticates one complete native-frame datagram without interpreting its body.
pub(crate) fn authenticate_datagram(
    key: &[u8; 32],
    bytes: &[u8],
) -> Result<AuthenticatedDatagram, WireError> {
    let header = parse_header(bytes)?;
    let expected = HEADER_BYTES
        .checked_add(usize::from(header.ciphertext_bytes))
        .and_then(|length| length.checked_add(TAG_BYTES))
        .expect("u16 ciphertext length cannot overflow native-frame length");
    if bytes.len() < expected {
        return Err(WireError::Truncated { needed: expected, actual: bytes.len() });
    }
    if bytes.len() > expected {
        return Err(WireError::Trailing { expected, actual: bytes.len() });
    }
    if usize::from(header.ciphertext_bytes) > MAX_CSI_PLAINTEXT_BYTES {
        return Err(WireError::CiphertextTooLarge {
            actual: usize::from(header.ciphertext_bytes),
            maximum: MAX_CSI_PLAINTEXT_BYTES,
        });
    }
    let nonce_bytes = nonce_bytes(header.boot_generation, header.message_seq);
    let cipher =
        Aes256Gcm::new_from_slice(key).expect("a 32-byte key always constructs AES-256-GCM");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: &bytes[HEADER_BYTES..], aad: &bytes[..HEADER_BYTES] },
        )
        .map_err(|_| WireError::AuthenticationFailed)?;
    Ok(AuthenticatedDatagram { header, plaintext: plaintext.into_boxed_slice() })
}

/// Decodes the kind and exact body grammar after datagram authentication.
pub(crate) fn decode_authenticated(
    authenticated: &AuthenticatedDatagram,
) -> Result<DecodedDatagram, WireError> {
    let header = authenticated.header;
    let kind = header.kind().ok_or(WireError::UnknownKind { kind: header.kind })?;
    let message = decode_body(kind, authenticated.plaintext())
        .map_err(|error| WireError::MalformedBody { kind: kind_name(kind), error })?;
    Ok(DecodedDatagram { header, message })
}

/// Authenticates and decodes one complete native-frame datagram.
pub fn open_datagram(key: &[u8; 32], bytes: &[u8]) -> Result<DecodedDatagram, WireError> {
    decode_authenticated(&authenticate_datagram(key, bytes)?)
}

/// Encodes a capability descriptor body with its descriptor digest.
#[must_use]
pub fn encode_capabilities(descriptor: &CapabilityDescriptor) -> Box<[u8]> {
    let descriptor_bytes = descriptor.to_bytes();
    let digest: [u8; 32] = Sha256::digest(descriptor_bytes).into();
    let mut body = Vec::with_capacity(CAPABILITIES_BODY_BYTES);
    body.extend_from_slice(&digest);
    body.extend_from_slice(&(CAPABILITY_DESCRIPTOR_BYTES as u16).to_le_bytes());
    body.extend_from_slice(&descriptor_bytes);
    body.into_boxed_slice()
}

/// Encodes a validated CSI data body.
#[must_use]
pub fn encode_csi_data(data: &CsiDataV1) -> Box<[u8]> {
    let mut body = Vec::with_capacity(csi_body_len(data.blocks.len(), data.raw_csi.len()));
    body.extend_from_slice(&data.capability_digest);
    body.extend_from_slice(&data.capture_sequence.to_le_bytes());
    body.extend_from_slice(&data.driver_rx_timestamp_us.to_le_bytes());
    body.extend_from_slice(&data.callback_tick_us.to_le_bytes());
    body.extend_from_slice(&data.source_mac);
    body.push(data.radio.channel);
    body.push(data.radio.secondary.byte());
    body.push(data.radio.phy.byte());
    body.push(data.radio.bandwidth.byte());
    body.push(u8::from(data.radio.stbc));
    body.push(data.radio.rssi_dbm as u8);
    body.push(data.radio.noise_floor_dbm as u8);
    body.push(data.radio.rate);
    body.push(data.radio.mcs);
    body.push(data.radio.rx_antenna);
    body.push(data.first_invalid_bytes);
    body.push(data.trailing_invalid_bytes);
    body.push(data.blocks.len() as u8);
    body.extend_from_slice(&(data.raw_csi.len() as u16).to_le_bytes());
    body.extend_from_slice(&data.complex_sample_count.to_le_bytes());
    for block in &data.blocks {
        body.push(block.kind.byte());
        body.push(0);
        body.extend_from_slice(&block.sample_count.to_le_bytes());
        body.extend_from_slice(&block.raw_offset_bytes.to_le_bytes());
    }
    body.extend_from_slice(&data.raw_csi);
    body.into_boxed_slice()
}

/// Encodes a health body with its fixed field order.
#[must_use]
pub fn encode_health(health: &HealthV1) -> Box<[u8]> {
    let mut body = Vec::with_capacity(HEALTH_BODY_BYTES);
    body.extend_from_slice(&health.capability_digest);
    body.extend_from_slice(&health.callback_tick_us.to_le_bytes());
    body.extend_from_slice(&health.capture_seen.to_le_bytes());
    body.extend_from_slice(&health.queue_drop_no_slot.to_le_bytes());
    body.extend_from_slice(&health.queue_drop_full.to_le_bytes());
    body.extend_from_slice(&health.oversize_reject.to_le_bytes());
    body.extend_from_slice(&health.encode_reject.to_le_bytes());
    body.extend_from_slice(&health.send_failure.to_le_bytes());
    body.extend_from_slice(&health.pool_high_water_slots.to_le_bytes());
    body.extend_from_slice(&health.callback_max_us.to_le_bytes());
    body.extend_from_slice(&health.encoder_max_us.to_le_bytes());
    body.into_boxed_slice()
}

pub(crate) fn parse_header(bytes: &[u8]) -> Result<Header, WireError> {
    if bytes.len() < HEADER_BYTES {
        return Err(WireError::Truncated { needed: HEADER_BYTES, actual: bytes.len() });
    }
    if bytes[0] != WIRE_SCHEMA_VERSION {
        return Err(WireError::UnknownVersion { version: bytes[0] });
    }
    let header_length = u16::from_le_bytes([bytes[2], bytes[3]]);
    if header_length != HEADER_BYTES as u16 {
        return Err(WireError::HeaderLength {
            expected: HEADER_BYTES as u16,
            actual: header_length,
        });
    }
    let reserved_a = u16::from_le_bytes([bytes[14], bytes[15]]);
    if reserved_a != 0 {
        return Err(WireError::ReservedHeader { offset: 14, value: reserved_a });
    }
    let reserved_b = u16::from_le_bytes([bytes[30], bytes[31]]);
    if reserved_b != 0 {
        return Err(WireError::ReservedHeader { offset: 30, value: reserved_b });
    }
    let key_epoch = u16::from_le_bytes([bytes[12], bytes[13]]);
    if key_epoch == 0 {
        return Err(WireError::ZeroKeyEpoch);
    }
    let boot_generation =
        u32::from_le_bytes(bytes[16..20].try_into().expect("checked header length"));
    if boot_generation == 0 {
        return Err(WireError::ZeroBootGeneration);
    }
    let message_seq = u64::from_le_bytes(bytes[20..28].try_into().expect("checked header length"));
    if message_seq == 0 {
        return Err(WireError::ZeroMessageSequence);
    }
    Ok(Header {
        kind: bytes[1],
        device_id: u64::from_le_bytes(bytes[4..12].try_into().expect("checked header length")),
        key_epoch,
        boot_generation,
        message_seq,
        ciphertext_bytes: u16::from_le_bytes([bytes[28], bytes[29]]),
    })
}

fn decode_body(kind: MessageKind, bytes: &[u8]) -> Result<Message, BodyError> {
    match kind {
        MessageKind::Capabilities => decode_capabilities(bytes).map(Message::Capabilities),
        MessageKind::CsiData => decode_csi_data(bytes).map(Message::CsiData),
        MessageKind::Health => decode_health(bytes).map(Message::Health),
    }
}

fn validate_body(kind: MessageKind, bytes: &[u8]) -> Result<(), BodyError> {
    decode_body(kind, bytes).map(|_| ())
}

fn decode_capabilities(bytes: &[u8]) -> Result<CapabilitiesV1, BodyError> {
    if bytes.len() != CAPABILITIES_BODY_BYTES {
        return Err(BodyError::ExactLength {
            expected: CAPABILITIES_BODY_BYTES,
            actual: bytes.len(),
        });
    }
    let digest: [u8; 32] = bytes[..32].try_into().expect("checked capability body length");
    let descriptor_bytes = u16::from_le_bytes([bytes[32], bytes[33]]);
    if usize::from(descriptor_bytes) != CAPABILITY_DESCRIPTOR_BYTES {
        return Err(BodyError::ExactLength {
            expected: CAPABILITY_DESCRIPTOR_BYTES,
            actual: usize::from(descriptor_bytes),
        });
    }
    let descriptor = CapabilityDescriptor::from_bytes(&bytes[34..])?;
    let expected_digest: [u8; 32] = Sha256::digest(&bytes[34..]).into();
    if digest != expected_digest {
        return Err(BodyError::CapabilityDigestMismatch);
    }
    Ok(CapabilitiesV1 { capability_digest: digest, descriptor })
}

fn decode_csi_data(bytes: &[u8]) -> Result<CsiDataV1, BodyError> {
    if bytes.len() > MAX_CSI_PLAINTEXT_BYTES {
        return Err(BodyError::PlaintextTooLarge {
            actual: bytes.len(),
            maximum: MAX_CSI_PLAINTEXT_BYTES,
        });
    }
    if bytes.len() < CSI_FIXED_BODY_BYTES {
        return Err(BodyError::ExactLength { expected: CSI_FIXED_BODY_BYTES, actual: bytes.len() });
    }
    let capability_digest: [u8; 32] = bytes[..32].try_into().expect("checked CSI body length");
    let capture_sequence =
        u64::from_le_bytes(bytes[32..40].try_into().expect("checked CSI body length"));
    let driver_rx_timestamp_us =
        u32::from_le_bytes(bytes[40..44].try_into().expect("checked CSI body length"));
    let callback_tick_us =
        u64::from_le_bytes(bytes[44..52].try_into().expect("checked CSI body length"));
    let source_mac: [u8; 6] = bytes[52..58].try_into().expect("checked CSI body length");
    let radio = decode_radio(&bytes[58..68])?;
    let first_invalid_bytes = bytes[68];
    let trailing_invalid_bytes = bytes[69];
    let block_count = bytes[70];
    let raw_bytes = usize::from(u16::from_le_bytes([bytes[71], bytes[72]]));
    let complex_sample_count = u16::from_le_bytes([bytes[73], bytes[74]]);
    let block_count_usize = usize::from(block_count);
    if !(1..=3).contains(&block_count) {
        return Err(BodyError::InvalidBlockCount(block_count));
    }
    let blocks_end = CSI_FIXED_BODY_BYTES
        .checked_add(block_count_usize.checked_mul(LTF_BLOCK_BYTES).expect("block count is <= 3"))
        .expect("fixed CSI body plus three blocks cannot overflow");
    let expected_len = blocks_end.checked_add(raw_bytes).expect("u16 raw length cannot overflow");
    if bytes.len() < expected_len {
        return Err(BodyError::ExactLength { expected: expected_len, actual: bytes.len() });
    }
    if bytes.len() > expected_len {
        return Err(BodyError::ExactLength { expected: expected_len, actual: bytes.len() });
    }
    let mut blocks = Vec::with_capacity(block_count_usize);
    let mut cursor = CSI_FIXED_BODY_BYTES;
    for index in 0..block_count_usize {
        let kind = LtfKind::from_byte(bytes[cursor])
            .ok_or(BodyError::UnknownEnum { field: "ltf_kind", value: bytes[cursor] })?;
        let reserved = bytes[cursor + 1];
        if reserved != 0 {
            return Err(BodyError::NonZeroBlockReserved { block: index });
        }
        let sample_count = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
        let raw_offset_bytes = u16::from_le_bytes([bytes[cursor + 4], bytes[cursor + 5]]);
        blocks.push(LtfBlock::new(kind, sample_count, raw_offset_bytes));
        cursor += LTF_BLOCK_BYTES;
    }
    let raw_csi = bytes[cursor..].to_vec().into_boxed_slice();
    let data = CsiDataV1::try_new(
        capability_digest,
        capture_sequence,
        driver_rx_timestamp_us,
        callback_tick_us,
        source_mac,
        radio,
        first_invalid_bytes,
        trailing_invalid_bytes,
        blocks.into_boxed_slice(),
        raw_csi,
    )?;
    if data.complex_sample_count != complex_sample_count {
        return Err(BodyError::BlockSampleCountMismatch);
    }
    Ok(data)
}

fn decode_health(bytes: &[u8]) -> Result<HealthV1, BodyError> {
    if bytes.len() != HEALTH_BODY_BYTES {
        return Err(BodyError::ExactLength { expected: HEALTH_BODY_BYTES, actual: bytes.len() });
    }
    let digest: [u8; 32] = bytes[..32].try_into().expect("checked health body length");
    let mut cursor = 32;
    let callback_tick_us = take_u64(bytes, &mut cursor);
    let capture_seen = take_u64(bytes, &mut cursor);
    let queue_drop_no_slot = take_u64(bytes, &mut cursor);
    let queue_drop_full = take_u64(bytes, &mut cursor);
    let oversize_reject = take_u64(bytes, &mut cursor);
    let encode_reject = take_u64(bytes, &mut cursor);
    let send_failure = take_u64(bytes, &mut cursor);
    let pool_high_water_slots = take_u16(bytes, &mut cursor);
    let callback_max_us = take_u32(bytes, &mut cursor);
    let encoder_max_us = take_u32(bytes, &mut cursor);
    Ok(HealthV1::new(
        digest,
        callback_tick_us,
        capture_seen,
        queue_drop_no_slot,
        queue_drop_full,
        oversize_reject,
        encode_reject,
        send_failure,
        pool_high_water_slots,
        callback_max_us,
        encoder_max_us,
    ))
}

fn decode_radio(bytes: &[u8]) -> Result<RadioRxS3, BodyError> {
    let secondary = S3SecondaryKind::from_byte(bytes[1])
        .ok_or(BodyError::UnknownEnum { field: "secondary", value: bytes[1] })?;
    let phy = S3PhyKind::from_byte(bytes[2])
        .ok_or(BodyError::UnknownEnum { field: "phy", value: bytes[2] })?;
    let bandwidth = S3BandwidthKind::from_byte(bytes[3])
        .ok_or(BodyError::UnknownEnum { field: "bandwidth", value: bytes[3] })?;
    let stbc = match bytes[4] {
        0 => false,
        1 => true,
        value => return Err(BodyError::UnknownEnum { field: "stbc", value }),
    };
    RadioRxS3::try_new(
        bytes[0],
        secondary,
        phy,
        bandwidth,
        stbc,
        bytes[5] as i8,
        bytes[6] as i8,
        bytes[7],
        bytes[8],
        bytes[9],
    )
}

fn validate_csi_parts(
    capture_sequence: u64,
    radio: RadioRxS3,
    first_invalid_bytes: u8,
    trailing_invalid_bytes: u8,
    blocks: &[LtfBlock],
    raw_csi: &[u8],
) -> Result<u16, BodyError> {
    if capture_sequence == 0 {
        return Err(BodyError::ZeroCaptureSequence);
    }
    if raw_csi.len() > MAX_RAW_CSI_BYTES {
        return Err(BodyError::RawCsiTooLarge {
            actual: raw_csi.len(),
            maximum: MAX_RAW_CSI_BYTES,
        });
    }
    if blocks.is_empty() || blocks.len() > 3 {
        return Err(BodyError::InvalidBlockCount(blocks.len() as u8));
    }
    if first_invalid_bytes != 0 && first_invalid_bytes != 4 {
        return Err(BodyError::InvalidFirstInvalidBytes);
    }
    if trailing_invalid_bytes != 0 && trailing_invalid_bytes != 2 {
        return Err(BodyError::InvalidTrailingInvalidBytes);
    }
    if raw_csi.len() < usize::from(trailing_invalid_bytes) {
        return Err(BodyError::RawLengthMismatch);
    }
    let logical_bytes = raw_csi.len() - usize::from(trailing_invalid_bytes);
    if usize::from(first_invalid_bytes) > logical_bytes {
        return Err(BodyError::FirstInvalidOutOfBounds);
    }
    if !logical_bytes.is_multiple_of(2) {
        return Err(BodyError::RawLengthMismatch);
    }
    let complex_sample_count = logical_bytes / 2;
    if complex_sample_count == 0 || complex_sample_count > u16::MAX as usize {
        return Err(BodyError::RawLengthMismatch);
    }
    let expected_ltf = match (radio.phy, radio.stbc) {
        (S3PhyKind::NonHt, false) => &[LtfKind::Lltf][..],
        (S3PhyKind::Ht, false) => &[LtfKind::Lltf, LtfKind::HtLtf][..],
        (S3PhyKind::Ht, true) => &[LtfKind::Lltf, LtfKind::HtLtf, LtfKind::StbcHtLtf][..],
        (S3PhyKind::NonHt, true) => return Err(BodyError::InvalidRadioCombination),
    };
    if blocks.len() != expected_ltf.len() {
        return Err(BodyError::InvalidBlockCount(blocks.len() as u8));
    }
    let mut pair_sum = 0_usize;
    for (index, (block, expected_kind)) in blocks.iter().zip(expected_ltf).enumerate() {
        if block.kind != *expected_kind {
            return Err(BodyError::InvalidLtfOrder { block: index });
        }
        if block.sample_count == 0 {
            return Err(BodyError::ZeroBlockSampleCount { block: index });
        }
        let expected_offset = pair_sum.checked_mul(2).ok_or(BodyError::RawLengthMismatch)?;
        if usize::from(block.raw_offset_bytes) != expected_offset {
            return Err(BodyError::InvalidBlockOffset { block: index });
        }
        pair_sum = pair_sum
            .checked_add(usize::from(block.sample_count))
            .ok_or(BodyError::BlockSampleCountMismatch)?;
    }
    if pair_sum != complex_sample_count {
        return Err(BodyError::BlockSampleCountMismatch);
    }
    if csi_body_len(blocks.len(), raw_csi.len()) > MAX_CSI_PLAINTEXT_BYTES {
        return Err(BodyError::PlaintextTooLarge {
            actual: csi_body_len(blocks.len(), raw_csi.len()),
            maximum: MAX_CSI_PLAINTEXT_BYTES,
        });
    }
    Ok(complex_sample_count as u16)
}

fn csi_body_len(block_count: usize, raw_bytes: usize) -> usize {
    CSI_FIXED_BODY_BYTES + block_count * LTF_BLOCK_BYTES + raw_bytes
}

const fn minimum_datagram_budget_bytes() -> u16 {
    (HEADER_BYTES + TAG_BYTES + MAX_CSI_PLAINTEXT_BYTES) as u16
}

fn kind_name(kind: MessageKind) -> &'static str {
    match kind {
        MessageKind::Capabilities => "capabilities",
        MessageKind::CsiData => "csi-data",
        MessageKind::Health => "health",
    }
}

fn nonce_bytes(boot_generation: u32, message_seq: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&boot_generation.to_le_bytes());
    nonce[4..].copy_from_slice(&message_seq.to_le_bytes());
    nonce
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> u16 {
    let value = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    value
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> u32 {
    let value =
        u32::from_le_bytes(bytes[*cursor..*cursor + 4].try_into().expect("fixed health body"));
    *cursor += 4;
    value
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
    let value =
        u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().expect("fixed health body"));
    *cursor += 8;
    value
}

/// A previously accepted capability paired with the authenticated epoch that announced it.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CapabilityReceipt {
    session: SessionId,
    record_seq: u64,
    header: Header,
    capability: CapabilitiesV1,
}

impl CapabilityReceipt {
    fn new(
        session: SessionId,
        record_seq: u64,
        header: Header,
        capability: CapabilitiesV1,
    ) -> Self {
        Self { session, record_seq, header, capability }
    }
}

/// A route-resolved result used by the ingest task after durable packet admission.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DecodedInput {
    /// A capability announcement accepted for the configured device and epoch.
    Capabilities(CapabilityReceipt),
    /// A CSI observation with a profile and link identity.
    Csi(CsiObservation),
    /// A health report accepted for the configured device.
    Health(HealthV1),
    /// An authenticated v1 message kind that has no body decoder.
    UnknownKind { kind: u8 },
}

/// Errors produced after the encrypted datagram passes fixed-header admission.
#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum IngestError {
    /// The capture-wide datagram budget was exceeded.
    #[error("datagram length {actual} exceeds global limit {maximum}")]
    GlobalDatagramTooLarge {
        /// Captured datagram byte length.
        actual: usize,
        /// Configured global byte limit.
        maximum: usize,
    },
    /// The route-specific datagram budget was exceeded.
    #[error("datagram length {actual} exceeds route limit {maximum}")]
    RouteDatagramTooLarge {
        /// Captured datagram byte length.
        actual: usize,
        /// Configured route byte limit.
        maximum: usize,
    },
    /// The packet did not match an exact configured route.
    #[error(transparent)]
    Route(#[from] RouteError),
    /// The fixed envelope or body was invalid.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// No previously accepted capability was available for this CSI body.
    #[error("capability descriptor was not durably accepted before CSI data")]
    CapabilityUnavailable,
    /// The body or descriptor did not match the route's pinned capability.
    #[error("authenticated capability does not match the route pins")]
    UnsupportedCapability,
    /// A CSI body exceeded the receiver's configured raw or plaintext budget.
    #[error(
        "CSI body exceeds receiver budget: raw {raw_actual}/{raw_max}, plaintext {plaintext_actual}/{plaintext_max}"
    )]
    CsiBudgetExceeded {
        /// Raw CSI bytes carried by the authenticated body.
        raw_actual: usize,
        /// Maximum raw CSI bytes configured for the receiver.
        raw_max: usize,
        /// Cleartext body bytes carried by the authenticated body.
        plaintext_actual: usize,
        /// Maximum cleartext body bytes configured for the receiver.
        plaintext_max: usize,
    },
    /// The body source MAC was not the link's exact transmitter MAC.
    #[error("authenticated source MAC does not match the link")]
    UnknownSourceMac,
    /// Authenticated radio facts were outside the link channel policy.
    #[error("authenticated radio facts do not match the link policy")]
    RouteRadioMismatch,
    /// The resolved source/link/profile facts could not be represented by the domain route.
    #[error("decoded route is invalid: {0}")]
    DecodedRoute(String),
    /// The profile descriptor could not be validated or interned.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// The dynamic CSI capture violated a domain cardinality invariant.
    #[error("invalid CSI capture: {0}")]
    CsiCapture(String),
    /// The receive-only timing value could not be built.
    #[error(transparent)]
    Time(#[from] TimeError),
}

/// Admits one raw receive fact through the pre-decode route and AEAD boundary.
///
/// This stage owns no sockets, secret storage, replay state, session metadata,
/// or body interpretation. The owned bytes remain in the returned admission.
#[allow(dead_code)]
pub(crate) fn admit_datagram(
    peer: SocketAddr,
    wire_format: WireFormat,
    bytes: Box<[u8]>,
    maximum_live_datagram_bytes: u32,
    registry: &Registry,
    key: &[u8; 32],
) -> Result<AdmittedDatagram, IngestError> {
    if wire_format != WireFormat::NativeFrameUdp {
        return Err(IngestError::Wire(WireError::UnknownVersion { version: 0 }));
    }
    let header_route = select_header_route(peer, &bytes, maximum_live_datagram_bytes, registry)?;
    let authenticated = authenticate_datagram(key, &bytes)?;
    debug_assert_eq!(header_route.device().get(), authenticated.header().device_id);
    Ok(AdmittedDatagram { peer, wire_format, bytes, authenticated, header_route })
}

/// Selects the exact configured route after validating the bounded fixed header.
pub(crate) fn select_header_route(
    peer: SocketAddr,
    bytes: &[u8],
    maximum_live_datagram_bytes: u32,
    registry: &Registry,
) -> Result<HeaderRoute, IngestError> {
    let actual = bytes.len();
    let global_maximum = maximum_live_datagram_bytes as usize;
    if actual > global_maximum {
        return Err(IngestError::GlobalDatagramTooLarge { actual, maximum: global_maximum });
    }
    let header = parse_header(bytes)?;
    let device_id = DeviceId::new(header.device_id);
    let key_epoch = KeyEpoch::try_new(header.key_epoch).map_err(|_| WireError::ZeroKeyEpoch)?;
    let header_route = registry.resolve_header_route(peer.ip(), device_id, key_epoch)?;
    let route_maximum = usize::from(header_route.admission_limits().maximum_datagram_bytes());
    if actual > route_maximum {
        return Err(IngestError::RouteDatagramTooLarge { actual, maximum: route_maximum });
    }
    Ok(header_route)
}

/// Resolves one recorded and authenticated datagram through the body boundary.
///
/// The caller supplies the key-independent recorded admission and any
/// previously durable capability. This stage owns neither sockets nor replay
/// state and cannot run before [`AdmittedDatagram::into_recorded`].
#[allow(dead_code)]
pub(crate) fn decode_recorded(
    recorded: &RecordedDatagram,
    registry: &Registry,
    profiles: &mut ProfileCatalog,
    accepted_capability: Option<&CapabilityReceipt>,
) -> Result<DecodedInput, IngestError> {
    let header = recorded.authenticated.header();
    if header.kind().is_none() {
        return Ok(DecodedInput::UnknownKind { kind: header.kind_byte() });
    }
    debug_assert_eq!(recorded.header_route.device().get(), header.device_id);
    let resolved = registry.resolve_authenticated_route(recorded.header_route)?;
    let decoded = decode_authenticated(&recorded.authenticated)?;
    match decoded.message {
        Message::Capabilities(capability) => {
            validate_pinned_capability(resolved.sensor, resolved.route, &capability)?;
            Ok(DecodedInput::Capabilities(CapabilityReceipt::new(
                recorded.packet.session_id().clone(),
                recorded.packet.record_seq(),
                header,
                capability,
            )))
        }
        Message::Health(health) => {
            if health.capability_digest() != resolved.sensor.capability_digest() {
                return Err(IngestError::UnsupportedCapability);
            }
            Ok(DecodedInput::Health(health))
        }
        Message::CsiData(data) => resolve_csi(
            &recorded.packet,
            header,
            resolved.sensor,
            resolved.link,
            resolved.route,
            data,
            accepted_capability,
            profiles,
        ),
    }
}

#[allow(dead_code)]
fn validate_pinned_capability(
    sensor: &crate::config::SensorConfig,
    route: &crate::config::RouteConfig,
    capability: &CapabilitiesV1,
) -> Result<(), IngestError> {
    if capability.capability_digest() != sensor.capability_digest()
        || capability.descriptor().firmware_build_digest() != sensor.firmware_build_digest()
        || capability.descriptor().datagram_budget_bytes()
            > route.admission_limits().maximum_datagram_bytes()
    {
        return Err(IngestError::UnsupportedCapability);
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "The ingest boundary carries explicit external context"
)]
#[allow(dead_code)]
fn resolve_csi(
    packet: &CapturedPacket,
    header: Header,
    sensor: &crate::config::SensorConfig,
    link: &crate::config::LinkConfig,
    route: &crate::config::RouteConfig,
    data: CsiDataV1,
    accepted_capability: Option<&CapabilityReceipt>,
    profiles: &mut ProfileCatalog,
) -> Result<DecodedInput, IngestError> {
    let accepted = accepted_capability.ok_or(IngestError::CapabilityUnavailable)?;
    if accepted.session != *packet.session_id()
        || accepted.record_seq >= packet.record_seq()
        || accepted.header.device_id != header.device_id
        || accepted.header.key_epoch != header.key_epoch
        || accepted.header.boot_generation != header.boot_generation
    {
        return Err(IngestError::CapabilityUnavailable);
    }
    let input = ObservationInput::from_packet(packet);
    let (profile, observation) =
        build_csi(&input, header, sensor, link, route, data, &accepted.capability)?;
    profiles.intern(profile)?;
    Ok(DecodedInput::Csi(observation))
}

#[derive(Clone, Debug)]
pub(crate) struct DemoObservationInput(ObservationInput);

impl DemoObservationInput {
    pub(crate) fn try_new(
        session_id: &str,
        record_sequence: CaptureRecordSequence,
        session_time: SessionTime,
    ) -> Result<Self, IngestError> {
        let session = SessionId::new(session_id)
            .map_err(|error| IngestError::DecodedRoute(error.to_string()))?;
        Ok(Self(ObservationInput { session, record_sequence, session_time }))
    }
}

pub(crate) fn resolve_demo_csi(
    input: DemoObservationInput,
    header_route: HeaderRoute,
    header: Header,
    registry: &Registry,
    data: CsiDataV1,
    capability: &CapabilitiesV1,
) -> Result<(CaptureProfile, CsiObservation), IngestError> {
    let resolved = registry.resolve_authenticated_route(header_route)?;
    build_csi(&input.0, header, resolved.sensor, resolved.link, resolved.route, data, capability)
}

#[derive(Clone, Debug)]
struct ObservationInput {
    session: SessionId,
    record_sequence: CaptureRecordSequence,
    session_time: SessionTime,
}

impl ObservationInput {
    fn from_packet(packet: &CapturedPacket) -> Self {
        Self {
            session: packet.session_id().clone(),
            record_sequence: CaptureRecordSequence::new(packet.record_seq()),
            session_time: SessionTime::from_nanos(packet.receive_monotonic_ns()),
        }
    }
}

fn build_csi(
    input: &ObservationInput,
    header: Header,
    sensor: &crate::config::SensorConfig,
    link: &crate::config::LinkConfig,
    route: &crate::config::RouteConfig,
    data: CsiDataV1,
    capability: &CapabilitiesV1,
) -> Result<(CaptureProfile, CsiObservation), IngestError> {
    if data.capability_digest() != capability.capability_digest() {
        return Err(IngestError::UnsupportedCapability);
    }
    validate_pinned_capability(sensor, route, capability)?;
    let raw_actual = data.raw_csi().len();
    let plaintext_actual = csi_body_len(data.blocks().len(), raw_actual);
    let raw_max = usize::from(sensor.maximum_raw_csi_bytes());
    let plaintext_max = usize::from(sensor.maximum_plaintext_bytes());
    if raw_actual > raw_max || plaintext_actual > plaintext_max {
        return Err(IngestError::CsiBudgetExceeded {
            raw_actual,
            raw_max,
            plaintext_actual,
            plaintext_max,
        });
    }
    if data.source_mac() != link.expected_transmitter_mac() || data.source_mac() == [0; 6] {
        return Err(IngestError::UnknownSourceMac);
    }
    let radio = data.radio();
    if !link.channel_policy().allowed().contains(&radio.channel())
        || link.channel_policy().expected().is_some_and(|expected| expected != radio.channel())
    {
        return Err(IngestError::RouteRadioMismatch);
    }
    let domain_radio = S3RadioFacts::try_new(
        radio.channel(),
        match radio.secondary() {
            S3SecondaryKind::None => S3Secondary::None,
            S3SecondaryKind::Above => S3Secondary::Above,
            S3SecondaryKind::Below => S3Secondary::Below,
        },
        match radio.phy() {
            S3PhyKind::NonHt => S3Phy::NonHt,
            S3PhyKind::Ht => S3Phy::Ht,
        },
        match radio.bandwidth() {
            S3BandwidthKind::TwentyMhz => S3Bandwidth::TwentyMhz,
            S3BandwidthKind::FortyMhz => S3Bandwidth::FortyMhz,
        },
        radio.stbc(),
    )
    .map_err(|error| IngestError::DecodedRoute(error.to_string()))?;
    let device_epoch = DeviceEpoch::new(
        DeviceId::new(header.device_id),
        BootGeneration::try_new(header.boot_generation)
            .map_err(|_| IngestError::Wire(WireError::ZeroBootGeneration))?,
    );
    let layout = CsiLayout::try_new(
        vec![CsiPath::RawPathOrdinal(0)],
        CsiSampleAxis::try_opaque(data.complex_sample_count())
            .map_err(|error| IngestError::CsiCapture(error.to_string()))?,
        SampleOrder::PathThenSample,
    )
    .map_err(|error| IngestError::CsiCapture(error.to_string()))?;
    let profile = CaptureProfile::try_new(ProfileDescriptor {
        hardware: HardwareKind::Esp32S3,
        firmware: digest_hex(sensor.firmware_build_digest()).into_boxed_str(),
        decoder_version: "native-frame-v1".into(),
        capability_id: digest_hex(capability.capability_digest()).into_boxed_str(),
        acquisition: AcquisitionCapabilities {
            mode: AcquisitionMode::WifiCsi,
            ltf_selection: match radio.phy() {
                S3PhyKind::NonHt => LtfSelection::Legacy,
                S3PhyKind::Ht => LtfSelection::Ht,
            },
            ltf_merge: LtfMerge::None,
            validity_dialect: ValidityDialect::FirstWordInvalid,
        },
        channel: Some(u16::from(radio.channel())),
        centre_frequency_hz: None,
        bandwidth_hz: Some(match radio.bandwidth() {
            S3BandwidthKind::TwentyMhz => 20_000_000,
            S3BandwidthKind::FortyMhz => 40_000_000,
        }),
        ppdu: Some(match radio.phy() {
            S3PhyKind::NonHt => PpduKind::Legacy,
            S3PhyKind::Ht => PpduKind::Ht,
        }),
        secondary_channel: Some(radio.secondary().byte()),
        stbc: Some(radio.stbc()),
        layout: layout.clone(),
        encoding: SampleEncoding::try_new(8, 1, 1, crate::domain::csi::ComplexOrder::ImaginaryReal)
            .expect("fixed signed-i8 imaginary-real encoding is valid"),
        phase_state: PhaseState::Raw,
        time_quality: crate::domain::time::TimeQuality::ReceiveOnly,
        clock_domain: None,
    })?;
    let profile_id = profile.id();
    let decoded_route = DecodedRoute::try_new(
        device_epoch,
        sensor.id().clone(),
        link.id().clone(),
        profile_id,
        data.source_mac(),
        domain_radio,
    )
    .map_err(|error| IngestError::DecodedRoute(error.to_string()))?;
    debug_assert_eq!(decoded_route.profile(), profile_id);
    let csi = CsiCapture::try_new(
        layout,
        data.iq_samples(),
        SampleEncoding::try_new(8, 1, 1, crate::domain::csi::ComplexOrder::ImaginaryReal)
            .expect("fixed signed-i8 imaginary-real encoding is valid"),
        PhaseState::Raw,
    )
    .map_err(|error| IngestError::CsiCapture(error.to_string()))?;
    let received = input.session_time;
    let device_timestamp =
        DeviceTimestamp::try_new(u64::from(data.driver_rx_timestamp_us()), "esp32s3-driver-ticks")?;
    let timing = FrameTiming::try_new(
        received,
        Some(device_timestamp),
        received,
        EventTimeSource::ReceiveOnly,
        None,
        0,
    )?;
    let radio_metadata = RadioMetadata::try_new(
        Some(u16::from(radio.channel())),
        None,
        Some(match radio.bandwidth() {
            S3BandwidthKind::TwentyMhz => 20_000_000,
            S3BandwidthKind::FortyMhz => 40_000_000,
        }),
        Some(match radio.phy() {
            S3PhyKind::NonHt => PpduKind::Legacy,
            S3PhyKind::Ht => PpduKind::Ht,
        }),
        radio.rssi_dbm(),
        radio.noise_floor_dbm(),
    )
    .map_err(|error| IngestError::DecodedRoute(error.to_string()))?;
    let input = crate::domain::csi::InputReceipt::new(
        input.session.clone(),
        input.record_sequence,
        DecoderVersion::new("native-frame-v1")
            .map_err(|error| IngestError::DecodedRoute(error.to_string()))?,
    );
    Ok((
        profile,
        CsiObservation::new(
            input,
            sensor.id().clone(),
            HardwareKind::Esp32S3,
            link.id().clone(),
            device_epoch,
            data.capture_sequence(),
            data.callback_tick_us(),
            timing,
            radio_metadata,
            profile_id,
            csi,
        ),
    ))
}

#[allow(dead_code)]
fn digest_hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::WireFormat;
    use crate::config::parse_config;
    use crate::domain::csi::ProfileCatalog;
    use crate::domain::identity::SessionId;
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };

    const KEY: [u8; 32] = [0x5a; 32];
    const DEVICE_ID: u64 = 1;
    const KEY_EPOCH: u16 = 1;
    const BOOT_GENERATION: u32 = 4;
    const PEER: &str = "192.0.2.10:5000";
    const FIRMWARE_DIGEST: [u8; 32] = [0x11; 32];
    const ABI_DIGEST: [u8; 32] = [0x22; 32];

    fn descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::try_new(FIRMWARE_DIGEST, ABI_DIGEST, 1024)
            .expect("valid route-test descriptor")
    }

    fn capability() -> CapabilitiesV1 {
        CapabilitiesV1::new(descriptor())
    }

    fn csi(source_mac: [u8; 6], channel: u8) -> CsiDataV1 {
        CsiDataV1::try_new(
            capability().capability_digest(),
            2,
            3,
            4,
            source_mac,
            RadioRxS3::try_new(
                channel,
                S3SecondaryKind::None,
                S3PhyKind::NonHt,
                S3BandwidthKind::TwentyMhz,
                false,
                -40,
                -95,
                1,
                0,
                0,
            )
            .expect("valid route-test radio"),
            0,
            0,
            vec![LtfBlock::new(LtfKind::Lltf, 3, 0)],
            vec![1, 2, 3, 4, 5, 6],
        )
        .expect("valid route-test CSI")
    }

    fn csi_ht(source_mac: [u8; 6], channel: u8) -> CsiDataV1 {
        CsiDataV1::try_new(
            capability().capability_digest(),
            3,
            30,
            31,
            source_mac,
            RadioRxS3::try_new(
                channel,
                S3SecondaryKind::None,
                S3PhyKind::Ht,
                S3BandwidthKind::TwentyMhz,
                false,
                -40,
                -95,
                0,
                7,
                0,
            )
            .expect("valid route-test HT radio"),
            0,
            0,
            vec![LtfBlock::new(LtfKind::Lltf, 1, 0), LtfBlock::new(LtfKind::HtLtf, 2, 2)],
            vec![1, 2, 3, 4, 5, 6],
        )
        .expect("valid route-test HT CSI")
    }

    fn config_source() -> String {
        let capability_hex = digest_hex(capability().capability_digest());
        let firmware_hex = digest_hex(FIRMWARE_DIGEST);
        include_str!("../tests/fixtures/config/valid-two-esp32.toml")
            .replacen(
                "firmware_build_digest = \"0101010101010101010101010101010101010101010101010101010101010101\"",
                &format!("firmware_build_digest = \"{firmware_hex}\""),
                1,
            )
            .replacen(
                "capability_digest = \"0202020202020202020202020202020202020202020202020202020202020202\"",
                &format!("capability_digest = \"{capability_hex}\""),
                1,
            )
    }

    fn config() -> crate::config::Config {
        parse_config(&config_source()).expect("valid route-test config")
    }

    fn recorded(
        config: &crate::config::Config,
        peer: &str,
        record_seq: u64,
        bytes: Box<[u8]>,
    ) -> RecordedDatagram {
        admit_datagram(
            peer.parse().expect("valid peer"),
            WireFormat::NativeFrameUdp,
            bytes,
            config.capture().max_datagram_bytes(),
            config.registry(),
            &KEY,
        )
        .expect("admitted test datagram")
        .into_recorded(
            SessionId::new("route-test").expect("valid session"),
            record_seq,
            100,
            200,
        )
    }

    fn sealed_capability(sequence: u64, boot_generation: u32) -> Box<[u8]> {
        seal_datagram(
            &KEY,
            MessageKind::Capabilities,
            DEVICE_ID,
            KEY_EPOCH,
            boot_generation,
            sequence,
            &encode_capabilities(&descriptor()),
        )
        .expect("sealed capability")
    }

    fn sealed_csi(
        sequence: u64,
        boot_generation: u32,
        source_mac: [u8; 6],
        channel: u8,
    ) -> Box<[u8]> {
        let body = encode_csi_data(&csi(source_mac, channel));
        seal_datagram(
            &KEY,
            MessageKind::CsiData,
            DEVICE_ID,
            KEY_EPOCH,
            boot_generation,
            sequence,
            &body,
        )
        .expect("sealed CSI")
    }

    fn sealed_csi_ht(
        sequence: u64,
        boot_generation: u32,
        source_mac: [u8; 6],
        channel: u8,
    ) -> Box<[u8]> {
        let body = encode_csi_data(&csi_ht(source_mac, channel));
        seal_datagram(
            &KEY,
            MessageKind::CsiData,
            DEVICE_ID,
            KEY_EPOCH,
            boot_generation,
            sequence,
            &body,
        )
        .expect("sealed HT CSI")
    }

    fn sealed_raw(kind: u8, sequence: u64, body: &[u8]) -> Box<[u8]> {
        let mut header = [0_u8; HEADER_BYTES];
        header[0] = WIRE_SCHEMA_VERSION;
        header[1] = kind;
        header[2..4].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        header[4..12].copy_from_slice(&DEVICE_ID.to_le_bytes());
        header[12..14].copy_from_slice(&KEY_EPOCH.to_le_bytes());
        header[16..20].copy_from_slice(&BOOT_GENERATION.to_le_bytes());
        header[20..28].copy_from_slice(&sequence.to_le_bytes());
        header[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());
        let nonce = nonce_bytes(BOOT_GENERATION, sequence);
        let ciphertext = Aes256Gcm::new_from_slice(&KEY)
            .expect("test key")
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &header })
            .expect("test encryption");
        header.into_iter().chain(ciphertext).collect::<Vec<_>>().into_boxed_slice()
    }

    fn accepted_capability(
        config: &crate::config::Config,
        profiles: &mut ProfileCatalog,
    ) -> CapabilityReceipt {
        accepted_capability_for(config, profiles, BOOT_GENERATION)
    }

    fn accepted_capability_for(
        config: &crate::config::Config,
        profiles: &mut ProfileCatalog,
        boot_generation: u32,
    ) -> CapabilityReceipt {
        let packet = recorded(config, PEER, 1, sealed_capability(1, boot_generation));
        match decode_recorded(&packet, config.registry(), profiles, None).expect("capability route")
        {
            DecodedInput::Capabilities(capability) => capability,
            other => panic!("expected capability, got {other:?}"),
        }
    }

    #[test]
    fn route_resolves_only_after_capability_and_authenticated_link_facts() {
        let config = config();
        let mut profiles = ProfileCatalog::default();
        let capability = accepted_capability(&config, &mut profiles);
        let packet =
            recorded(&config, PEER, 2, sealed_csi(2, BOOT_GENERATION, [2, 0, 0, 0, 0, 10], 1));
        let decoded = decode_recorded(&packet, config.registry(), &mut profiles, Some(&capability))
            .expect("CSI route");
        let DecodedInput::Csi(observation) = decoded else { panic!("expected CSI observation") };
        assert_eq!(observation.device_epoch().boot_generation().get(), BOOT_GENERATION);
        assert_eq!(observation.capture_sequence(), 2);
        assert_eq!(observation.timing().device().expect("driver timestamp").ticks(), 3);
        assert_eq!(observation.callback_tick_us(), 4);
        assert_eq!(observation.link().to_string(), "link-a");
    }

    #[test]
    fn route_assigns_distinct_profiles_to_same_count_native_descriptors() {
        let config = config();
        let mut profiles = ProfileCatalog::default();
        let capability = accepted_capability(&config, &mut profiles);
        let non_ht_packet =
            recorded(&config, PEER, 2, sealed_csi(2, BOOT_GENERATION, [2, 0, 0, 0, 0, 10], 1));
        let ht_packet =
            recorded(&config, PEER, 3, sealed_csi_ht(3, BOOT_GENERATION, [2, 0, 0, 0, 0, 10], 1));
        let DecodedInput::Csi(non_ht) =
            decode_recorded(&non_ht_packet, config.registry(), &mut profiles, Some(&capability))
                .expect("Non-HT route")
        else {
            panic!("expected Non-HT CSI observation")
        };
        let DecodedInput::Csi(ht) =
            decode_recorded(&ht_packet, config.registry(), &mut profiles, Some(&capability))
                .expect("HT route")
        else {
            panic!("expected HT CSI observation")
        };
        assert_eq!(non_ht.csi().samples().len(), ht.csi().samples().len());
        assert_ne!(non_ht.profile(), ht.profile());
    }

    #[test]
    fn route_records_authenticated_unknown_kind_without_interpreting_body() {
        let config = config();
        let mut profiles = ProfileCatalog::default();
        let datagram = sealed_raw(0x7f, 1, &[0xa5]);
        let admitted = admit_datagram(
            PEER.parse().expect("valid peer"),
            WireFormat::NativeFrameUdp,
            datagram.clone(),
            config.capture().max_datagram_bytes(),
            config.registry(),
            &KEY,
        )
        .expect("authenticated unknown kind");
        assert_eq!(admitted.bytes(), datagram.as_ref());
        assert_eq!(admitted.header().message_seq(), 1);
        let recorded = admitted.into_recorded(
            SessionId::new("route-test").expect("valid session"),
            1,
            100,
            200,
        );

        assert_eq!(
            decode_recorded(&recorded, config.registry(), &mut profiles, None)
                .expect("unknown kind route"),
            DecodedInput::UnknownKind { kind: 0x7f }
        );

        let mut tampered = datagram.into_vec();
        *tampered.last_mut().expect("authentication tag byte") ^= 1;
        assert!(matches!(
            admit_datagram(
                PEER.parse().expect("valid peer"),
                WireFormat::NativeFrameUdp,
                tampered.into_boxed_slice(),
                config.capture().max_datagram_bytes(),
                config.registry(),
                &KEY,
            ),
            Err(IngestError::Wire(WireError::AuthenticationFailed))
        ));
    }

    #[test]
    fn demo_candidate_preserves_authenticated_unknown_kind_without_store_authority() {
        let config = config();
        let datagram = sealed_raw(0x7f, 1, &[0xa5]);
        let candidate = admit_datagram(
            PEER.parse().expect("valid peer"),
            WireFormat::NativeFrameUdp,
            datagram.clone(),
            config.capture().max_datagram_bytes(),
            config.registry(),
            &KEY,
        )
        .expect("authenticated unknown kind")
        .into_candidate(SessionTime::from_nanos(100), 200);

        assert_eq!(candidate.bytes(), datagram.as_ref());
        assert_eq!(candidate.header().message_seq(), 1);
        assert_eq!(candidate.session_time().as_nanos(), 100);
        assert_eq!(candidate.receive_utc_ns(), 200);
        assert_eq!(candidate.body(), &CandidateBody::UnknownKind { kind: 0x7f });
    }

    #[test]
    fn route_rejects_unknown_peer_before_aead_and_requires_previous_capability() {
        let config = config();
        let mut profiles = ProfileCatalog::default();
        assert!(matches!(
            admit_datagram(
                "192.0.2.99:5000".parse().expect("valid peer"),
                WireFormat::NativeFrameUdp,
                sealed_csi(2, BOOT_GENERATION, [2, 0, 0, 0, 0, 10], 1),
                config.capture().max_datagram_bytes(),
                config.registry(),
                &KEY,
            ),
            Err(IngestError::Route(RouteError::Unknown { .. }))
        ));
        assert!(matches!(
            admit_datagram(
                "192.0.2.11:5000".parse().expect("valid peer"),
                WireFormat::NativeFrameUdp,
                sealed_csi(2, BOOT_GENERATION, [2, 0, 0, 0, 0, 10], 1),
                config.capture().max_datagram_bytes(),
                config.registry(),
                &KEY,
            ),
            Err(IngestError::Route(RouteError::Unknown { .. }))
        ));

        let no_capability =
            recorded(&config, PEER, 2, sealed_csi(2, BOOT_GENERATION, [2, 0, 0, 0, 0, 10], 1));
        assert!(matches!(
            decode_recorded(&no_capability, config.registry(), &mut profiles, None),
            Err(IngestError::CapabilityUnavailable)
        ));
    }

    #[test]
    fn route_rejects_authenticated_capability_not_pinned_by_config() {
        let mismatched_source = config_source().replacen(
            &format!("firmware_build_digest = \"{}\"", digest_hex(FIRMWARE_DIGEST)),
            "firmware_build_digest = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"",
            1,
        );
        let config = parse_config(&mismatched_source).expect("valid mismatched pin config");
        let mut profiles = ProfileCatalog::default();
        let capability_packet = recorded(&config, PEER, 1, sealed_capability(1, BOOT_GENERATION));
        assert!(matches!(
            decode_recorded(&capability_packet, config.registry(), &mut profiles, None),
            Err(IngestError::UnsupportedCapability)
        ));
    }

    #[test]
    fn route_rejects_source_and_channel_mismatch_after_authentication() {
        let config = config();
        let mut profiles = ProfileCatalog::default();
        let capability = accepted_capability(&config, &mut profiles);
        for (source_mac, channel, expected) in [
            ([2, 0, 0, 0, 0, 11], 1, IngestError::UnknownSourceMac),
            ([2, 0, 0, 0, 0, 0x63], 1, IngestError::UnknownSourceMac),
            ([2, 0, 0, 0, 0, 10], 6, IngestError::RouteRadioMismatch),
        ] {
            let packet =
                recorded(&config, PEER, 2, sealed_csi(2, BOOT_GENERATION, source_mac, channel));
            let error =
                decode_recorded(&packet, config.registry(), &mut profiles, Some(&capability))
                    .expect_err("mismatched route facts accepted");
            assert_eq!(error, expected);
        }
    }

    #[test]
    fn route_applies_receiver_raw_budget_and_preserves_boot_epoch() {
        let limited_source =
            config_source().replace("maximum_raw_csi_bytes = 612", "maximum_raw_csi_bytes = 4");
        let limited_config = parse_config(&limited_source).expect("valid limited route config");
        let mut profiles = ProfileCatalog::default();
        let capability = accepted_capability(&limited_config, &mut profiles);
        let limited_packet = recorded(
            &limited_config,
            PEER,
            2,
            sealed_csi(2, BOOT_GENERATION, [2, 0, 0, 0, 0, 10], 1),
        );
        assert!(matches!(
            decode_recorded(
                &limited_packet,
                limited_config.registry(),
                &mut profiles,
                Some(&capability)
            ),
            Err(IngestError::CsiBudgetExceeded { raw_actual: 6, raw_max: 4, .. })
        ));

        let config = config();
        let next_packet =
            recorded(&config, PEER, 2, sealed_csi(3, BOOT_GENERATION + 1, [2, 0, 0, 0, 0, 10], 1));
        let stale_capability = accepted_capability(&config, &mut profiles);
        assert!(matches!(
            decode_recorded(
                &next_packet,
                config.registry(),
                &mut profiles,
                Some(&stale_capability)
            ),
            Err(IngestError::CapabilityUnavailable)
        ));
        let capability = accepted_capability_for(&config, &mut profiles, BOOT_GENERATION + 1);
        let DecodedInput::Csi(observation) =
            decode_recorded(&next_packet, config.registry(), &mut profiles, Some(&capability))
                .expect("next device epoch route")
        else {
            panic!("expected CSI observation")
        };
        assert_eq!(observation.device_epoch().boot_generation().get(), BOOT_GENERATION + 1);
    }
}
