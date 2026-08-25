//! CSI layouts, captures, and profile identity regression tests.

use std::fs;

use sha2::{Digest, Sha256};

use crate::domain::csi::{
    AcquisitionCapabilities, AcquisitionMode, CaptureProfile, ComplexOrder, CsiCapture, CsiLayout,
    CsiPath, CsiSampleAxis, IqSample, LtfMerge, LtfSelection, PhaseState, ProfileCatalog,
    ProfileDescriptor, ProfileError, SampleEncoding, SampleOrder, ValidityDialect,
};
use crate::domain::identity::HardwareKind;
use crate::domain::time::TimeQuality;

fn profile_descriptor() -> ProfileDescriptor {
    let layout = CsiLayout::try_new(
        vec![CsiPath::RawPathOrdinal(0)],
        CsiSampleAxis::try_opaque(3).expect("non-empty axis"),
        SampleOrder::PathThenSample,
    )
    .expect("valid layout");
    ProfileDescriptor {
        hardware: HardwareKind::Esp32S3,
        firmware: "esp32-s3-fw".into(),
        decoder_version: "adr018-v1".into(),
        capability_id: "capture-v1".into(),
        acquisition: AcquisitionCapabilities {
            mode: AcquisitionMode::WifiCsi,
            ltf_selection: LtfSelection::Legacy,
            ltf_merge: LtfMerge::None,
            validity_dialect: ValidityDialect::FirstWordInvalid,
        },
        channel: Some(1),
        centre_frequency_hz: Some(2_412_000_000),
        bandwidth_hz: Some(20_000_000),
        ppdu: None,
        layout,
        encoding: SampleEncoding::try_new(16, 2, 4, ComplexOrder::RealImaginary)
            .expect("valid reduced scale"),
        phase_state: PhaseState::Raw,
        time_quality: TimeQuality::ReceiveOnly,
        clock_domain: None,
    }
}

#[test]
fn csi_layout_rejects_empty_duplicate_and_directly_constructed_duplicate_axes() {
    assert!(
        CsiLayout::try_new(
            Vec::<CsiPath>::new(),
            CsiSampleAxis::OpaqueSampleOrdinal { count: 1 },
            SampleOrder::PathThenSample,
        )
        .is_err()
    );

    assert!(
        CsiLayout::try_new(
            vec![CsiPath::RawPathOrdinal(0), CsiPath::RawPathOrdinal(0)],
            CsiSampleAxis::OpaqueSampleOrdinal { count: 1 },
            SampleOrder::PathThenSample,
        )
        .is_err()
    );

    assert!(
        CsiLayout::try_new(
            vec![CsiPath::RawPathOrdinal(0)],
            CsiSampleAxis::IeeeToneIndex(vec![1, 1].into_boxed_slice()),
            SampleOrder::PathThenSample,
        )
        .is_err()
    );
    assert!(
        CsiLayout::try_new(
            vec![CsiPath::RawPathOrdinal(0)],
            CsiSampleAxis::FrequencyHz(vec![2, 2].into_boxed_slice()),
            SampleOrder::PathThenSample,
        )
        .is_err()
    );
}

#[test]
fn csi_capture_requires_exact_sample_length() {
    let layout = CsiLayout::try_new(
        vec![CsiPath::RawPathOrdinal(0), CsiPath::RawPathOrdinal(1)],
        CsiSampleAxis::try_opaque(3).expect("axis"),
        SampleOrder::PathThenSample,
    )
    .expect("layout");
    let encoding =
        SampleEncoding::try_new(16, 1, 1, ComplexOrder::ImaginaryReal).expect("encoding");
    assert!(
        CsiCapture::try_new(
            layout.clone(),
            vec![IqSample::new(1, 2); 5],
            encoding,
            PhaseState::Unavailable
        )
        .is_err()
    );
    let capture = CsiCapture::try_new(
        layout,
        vec![IqSample::new(1, 2); 6],
        encoding,
        PhaseState::Unavailable,
    )
    .expect("exact length");
    assert_eq!(capture.coordinates().len(), 6);
}

#[test]
fn intel_three_by_three_by_thirty_has_270_distinct_native_coordinates() {
    let paths: Vec<_> = (0..3)
        .flat_map(|tx| (0..3).map(move |rx| CsiPath::TxRx { tx_stream: tx, rx_chain: rx }))
        .collect();
    let layout = CsiLayout::try_new(
        paths,
        CsiSampleAxis::try_ieee_tones((0..30).map(|index| index as i16).collect::<Vec<_>>())
            .expect("tones"),
        SampleOrder::PathThenSample,
    )
    .expect("layout");
    let encoding =
        SampleEncoding::try_new(16, 1, 1, ComplexOrder::RealImaginary).expect("encoding");
    let capture = CsiCapture::try_new(
        layout,
        vec![IqSample::new(1, 1); 270],
        encoding,
        PhaseState::Unavailable,
    )
    .expect("capture");
    let coordinates = capture.coordinates();
    let unique: std::collections::BTreeSet<_> = coordinates.iter().copied().collect();
    assert_eq!(coordinates.len(), 270);
    assert_eq!(unique.len(), 270);
}

#[test]
fn sample_scale_is_reduced_and_profile_digest_covers_compatibility_fields() {
    let profile = CaptureProfile::try_new(profile_descriptor()).expect("profile");
    assert_eq!(profile.descriptor().encoding.scale_numerator(), 1);
    assert_eq!(profile.descriptor().encoding.scale_denominator(), 2);

    let mut catalog = ProfileCatalog::default();
    let first = catalog.intern(profile.clone()).expect("intern");
    assert_eq!(catalog.intern(profile).expect("same descriptor"), first);

    let mut changed = profile_descriptor();
    changed.acquisition.ltf_selection = LtfSelection::He;
    assert_ne!(CaptureProfile::try_new(changed).expect("changed profile").id(), first);
    let mut changed = profile_descriptor();
    changed.acquisition.ltf_merge = LtfMerge::FirmwareDefined;
    assert_ne!(CaptureProfile::try_new(changed).expect("changed profile").id(), first);
    let mut changed = profile_descriptor();
    changed.acquisition.validity_dialect = ValidityDialect::ExplicitFlag;
    assert_ne!(CaptureProfile::try_new(changed).expect("changed profile").id(), first);
    let mut changed = profile_descriptor();
    changed.capability_id = "capture-v2".into();
    assert_ne!(CaptureProfile::try_new(changed).expect("changed profile").id(), first);
    let mut changed = profile_descriptor();
    changed.time_quality = TimeQuality::ClockCorrected;
    changed.clock_domain = Some("host-clock".into());
    assert_ne!(CaptureProfile::try_new(changed).expect("changed profile").id(), first);
}

#[test]
fn profile_fixture_bytes_and_digest_are_stable() {
    let profile = CaptureProfile::try_new(profile_descriptor()).expect("profile");
    let bytes = profile.canonical_bytes().expect("canonical bytes");
    let encoded = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let digest_hex = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let fixture_dir = format!("{}/tests/fixtures/config", env!("CARGO_MANIFEST_DIR"));
    let expected_bytes = fs::read_to_string(format!("{fixture_dir}/profile-canonical.hex"))
        .expect("profile byte fixture")
        .trim()
        .to_owned();
    let expected_digest = fs::read_to_string(format!("{fixture_dir}/profile-canonical.sha256"))
        .expect("profile digest fixture")
        .trim()
        .to_owned();
    assert_eq!(encoded, expected_bytes);
    assert_eq!(digest_hex, expected_digest);
    assert_eq!(profile.id().as_bytes(), digest);
}

#[test]
fn profile_clock_domain_has_explicit_empty_value_validation() {
    let mut descriptor = profile_descriptor();
    descriptor.time_quality = TimeQuality::ClockCorrected;
    descriptor.clock_domain = Some(" \t".into());
    assert!(matches!(
        CaptureProfile::try_new(descriptor),
        Err(ProfileError::EmptyField("clock_domain"))
    ));

    let mut descriptor = profile_descriptor();
    descriptor.clock_domain = Some(" \t".into());
    assert!(matches!(
        CaptureProfile::try_new(descriptor),
        Err(ProfileError::UnexpectedClockDomain)
    ));

    let mut descriptor = profile_descriptor();
    descriptor.time_quality = TimeQuality::Unknown;
    descriptor.clock_domain = Some("".into());
    assert!(matches!(
        CaptureProfile::try_new(descriptor),
        Err(ProfileError::UnexpectedClockDomain)
    ));
}
