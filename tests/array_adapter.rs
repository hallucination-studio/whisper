//! Public locally coherent array-adapter behavior.

use sha2::{Digest, Sha256};
use whisper::array_adapter::{
    ArrayAdaptDisposition, ArrayAdaptReason, ArrayCapture, ArrayCaptureIdentity,
    ArrayNativeMetadata, ArrayPathRadioFacts, ArrayPathRecord, ArraySignalPath, ComplexI16,
    EspargosSourceAdapter, LtfIdentity, NativeArrayPathIdentity, PathKind, SampleState,
    SealedArrayCapture, StaticArrayReference, ThreeArrayCoverage,
};
use whisper::artifact::{
    ArrayCondition, ArrayElementGeometry, Artifact, ArtifactMetadata, CalibrationBundle,
    CalibrationEpoch, ClockErrorNanoseconds, ClockOffsetNanoseconds, CoherenceScope,
    CoordinateTransform, DeviceArrayGeometry, PhaseRelation as ArtifactPhaseRelation,
    RfTimeRelation, SealedArtifact, SignalDirection, SignalPathCondition, SourceIdentity,
    UtcNanoseconds,
};
use whisper::measurement::{
    ArtifactScope, ChannelIdentity, ErrorBound, ErrorUnit, EventIdentity, EvidenceBlock,
    EvidenceBlockIdentity, EvidenceMemberIdentity, EvidenceQuality, EvidenceScope, FitIdentity,
    Geometry, GeometryRequirement, MeasurementContext, ModelRequirements, NativeEventIdentity,
    PhaseReferenceIdentity, PhaseRelation, PhaseRequirement, PhysicalOperator,
    PhysicalRequirements, PortMapEntry, PortMapping, PortRequirement, Pose, ProfileIdentity,
    Qualification, QualificationEpoch, QualificationGap, RadioIdentity, RelationValidity,
    SignalPath, SourceInstance, SourceTick, TickRange, TimeRelation, TimeRequirement,
    TransmitterIdentity,
};
use whisper::{BootGeneration, DeviceId, KeyEpoch, SensorId};

fn source() -> SourceInstance {
    SourceInstance::new(
        SensorId::try_from("array-west").unwrap(),
        DeviceId::new(41),
        KeyEpoch::new(3).unwrap(),
        BootGeneration::new(7).unwrap(),
    )
}

fn identity() -> ArrayCaptureIdentity {
    ArrayCaptureIdentity::new(
        source(),
        EventIdentity::new(
            TransmitterIdentity::new([11; 32]),
            NativeEventIdentity::new([12; 32]),
            None,
        ),
        MeasurementContext::new(
            ProfileIdentity::new([13; 32]),
            RadioIdentity::new([14; 32]),
            ChannelIdentity::new([15; 32]),
        ),
        "espargos-west",
        "rx-west",
    )
    .unwrap()
}

fn capture() -> ArrayCapture {
    let (iq, states) = fixture_samples();
    capture_with(iq, states)
}

fn fixture_samples() -> (Vec<ComplexI16>, Vec<SampleState>) {
    const FIXTURE: &str = include_str!("fixtures/array/espargos-2x4-v1.csv");
    let mut iq = Vec::new();
    let mut states = Vec::new();
    for line in FIXTURE.lines().filter(|line| !line.starts_with('#')) {
        let fields = line.split(',').collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].parse::<usize>().unwrap(), iq.len() / 4);
        assert_eq!(fields[1].parse::<usize>().unwrap(), iq.len() % 4);
        iq.push(ComplexI16::new(fields[2].parse().unwrap(), fields[3].parse().unwrap()));
        states.push(match fields[4] {
            "captured" => SampleState::Captured,
            other => panic!("unsupported fixture state: {other}"),
        });
    }
    (iq, states)
}

fn capture_with(
    iq: impl IntoIterator<Item = ComplexI16>,
    states: impl IntoIterator<Item = SampleState>,
) -> ArrayCapture {
    capture_shape(8, iq, states)
}

fn capture_shape(
    path_count: u16,
    iq: impl IntoIterator<Item = ComplexI16>,
    states: impl IntoIterator<Item = SampleState>,
) -> ArrayCapture {
    let paths = (0_u16..path_count).map(|rx| {
        ArraySignalPath::new(
            SignalPath::new(0, rx),
            NativeArrayPathIdentity::new([rx as u8 + 1; 32]),
            format!("tx/{0}", 0),
            format!("rx/{rx}"),
        )
        .unwrap()
    });
    let metadata = native_metadata(path_count);
    ArrayCapture::new(
        identity(),
        LtfIdentity::new([16; 32]),
        TickRange::new(SourceTick::new(100), SourceTick::new(103)).unwrap(),
        1_800_000_000_000_000_000,
        metadata,
        [5_180_000_000, 5_180_312_500, 5_180_625_000, 5_180_937_500],
        paths,
        iq,
        states,
    )
    .unwrap()
}

fn native_metadata(path_count: u16) -> ArrayNativeMetadata {
    ArrayNativeMetadata::new(
        20_000_000,
        0x0087,
        Some(7),
        4_200_000_000,
        (0..path_count)
            .map(|rx| ArrayPathRadioFacts::new(rx, -4_200 + rx as i16, -9_200, Some(1_800))),
    )
    .unwrap()
}

fn sealed_capture() -> SealedArrayCapture {
    SealedArrayCapture::seal(capture()).unwrap()
}

fn calibration() -> SealedArtifact {
    let scene = whisper::artifact::SceneSnapshot {
        metadata: ArtifactMetadata {
            artifact_id: "scene-a".into(),
            revision: 1,
            provenance: vec![SourceIdentity {
                namespace: "fixture".into(),
                identity: "room-survey".into(),
            }],
        },
        world_coordinate_system: "room".into(),
        geometry: vec![whisper::artifact::GeometryElement {
            kind: whisper::artifact::GeometryKind::Wall,
            vertices_m: vec![[0.0, 0.0, 0.0], [5.0, 0.0, 0.0]],
        }],
        geometry_validity_mask: vec![true],
        coverage_mask: vec![whisper::artifact::CoverageCell {
            position_m: [2.5, 2.0, 0.0],
            covered: true,
        }],
        scan_coverage: 1.0,
        map_error_m: 0.02,
        usdz_display_reference: None,
    };
    let scene_digest = SealedArtifact::seal(Artifact::Scene(scene)).unwrap().digest();
    let identity_matrix =
        [1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0];
    let mut signal_paths = vec![SignalPathCondition {
        logical_path: "tx/0".into(),
        direction: SignalDirection::Transmit,
        device_chain: "tx-chain-0".into(),
        antenna_identity: "element-0".into(),
    }];
    signal_paths.extend((0..8).map(|rx| SignalPathCondition {
        logical_path: format!("rx/{rx}"),
        direction: SignalDirection::Receive,
        device_chain: format!("rx-chain-{rx}"),
        antenna_identity: format!("element-{rx}"),
    }));
    let elements = (0..8)
        .map(|index| ArrayElementGeometry {
            antenna_identity: format!("element-{index}"),
            position_m: [f64::from(index % 4) * 0.03, f64::from(index / 4) * 0.03, 0.0],
        })
        .collect();
    SealedArtifact::seal(Artifact::Calibration(Box::new(CalibrationBundle {
        metadata: ArtifactMetadata {
            artifact_id: "calibration-west".into(),
            revision: 4,
            provenance: vec![SourceIdentity {
                namespace: "fixture".into(),
                identity: "array-survey".into(),
            }],
        },
        scene_digest,
        rf_device_identity: "rx-west".into(),
        antenna_reference: "array-origin".into(),
        world_transform: CoordinateTransform {
            source_coordinate_system: "array".into(),
            target_coordinate_system: "room".into(),
            matrix: identity_matrix,
            max_error_m: 0.02,
        },
        signal_paths,
        array_condition: ArrayCondition {
            array_identity: "espargos-west".into(),
            physical_element_count: 8,
        },
        array_geometry: DeviceArrayGeometry {
            source: SourceIdentity { namespace: "fixture".into(), identity: "calipers".into() },
            applicability: "espargos-ht20".into(),
            minimum_frequency_hz: 5_170_000_000,
            maximum_frequency_hz: 5_190_000_000,
            device_to_array: CoordinateTransform {
                source_coordinate_system: "device".into(),
                target_coordinate_system: "array".into(),
                matrix: identity_matrix,
                max_error_m: 0.01,
            },
            elements,
            maximum_position_error_m: 0.002,
            valid_from_utc: UtcNanoseconds::from(1_700_000_000_000_000_000),
            valid_until_utc: UtcNanoseconds::from(1_900_000_000_000_000_000),
            epoch: CalibrationEpoch::new(4),
        },
        phase_relation: ArtifactPhaseRelation {
            source: SourceIdentity {
                namespace: "fixture".into(),
                identity: "phase-calibrator".into(),
            },
            scope: CoherenceScope::CaptureInterval,
            maximum_error_radians: 0.03,
            valid_from_utc: UtcNanoseconds::from(1_700_000_000_000_000_000),
            valid_until_utc: UtcNanoseconds::from(1_900_000_000_000_000_000),
            epoch: CalibrationEpoch::new(4),
        },
        time_relation: RfTimeRelation {
            source: SourceIdentity {
                namespace: "fixture".into(),
                identity: "time-calibrator".into(),
            },
            offset: ClockOffsetNanoseconds::from(0),
            maximum_error: ClockErrorNanoseconds::from(3),
            valid_from_utc: UtcNanoseconds::from(1_700_000_000_000_000_000),
            valid_until_utc: UtcNanoseconds::from(1_900_000_000_000_000_000),
            epoch: CalibrationEpoch::new(4),
        },
        max_error_m: 0.04,
        valid_from_utc: UtcNanoseconds::from(1_700_000_000_000_000_000),
        valid_until_utc: UtcNanoseconds::from(1_900_000_000_000_000_000),
    })))
    .unwrap()
}

fn calibration_with(change: impl FnOnce(&mut CalibrationBundle)) -> SealedArtifact {
    let Artifact::Calibration(mut value) = calibration().decode().unwrap() else {
        unreachable!("fixture is a calibration")
    };
    change(&mut value);
    SealedArtifact::seal(Artifact::Calibration(value)).unwrap()
}

fn range(start: u64, end: u64) -> TickRange {
    TickRange::new(SourceTick::new(start), SourceTick::new(end)).unwrap()
}

fn pose(origin: [f64; 3]) -> Pose {
    Pose::new([
        (origin[0] * 1_000.0).round() as i64,
        (origin[1] * 1_000.0).round() as i64,
        (origin[2] * 1_000.0).round() as i64,
        0,
        0,
        0,
        1_000_000,
    ])
}

fn relation_validity() -> RelationValidity {
    RelationValidity::new(
        "fixture",
        source(),
        ErrorBound::new(3, ErrorUnit::Nanoseconds),
        range(90, 110),
        QualificationEpoch::new(4),
    )
    .unwrap()
}

fn time_relation() -> TimeRelation {
    TimeRelation::new(relation_validity(), "array-clock", "host-clock", FitIdentity::new([21; 32]))
        .unwrap()
}

fn phase_relation(
    error_milliradians: u64,
    reference: PhaseReferenceIdentity,
    coherence: TickRange,
) -> PhaseRelation {
    PhaseRelation::new(
        RelationValidity::new(
            "fixture",
            source(),
            ErrorBound::new(error_milliradians, ErrorUnit::Milliradians),
            range(90, 110),
            QualificationEpoch::new(4),
        )
        .unwrap(),
        reference,
        coherence,
    )
    .unwrap()
}

fn port_mapping(path_count: u16, changed_last_antenna: bool) -> PortMapping {
    PortMapping::new(
        relation_validity(),
        (0..path_count).map(|rx| {
            let antenna = if changed_last_antenna && rx + 1 == path_count { 99 } else { rx };
            PortMapEntry::new(0, rx, Some(0), antenna)
        }),
    )
    .unwrap()
}

fn geometry_relation(pose: Pose) -> Geometry {
    Geometry::new(
        RelationValidity::new(
            "fixture",
            source(),
            ErrorBound::new(40, ErrorUnit::Millimetres),
            range(90, 110),
            QualificationEpoch::new(4),
        )
        .unwrap(),
        "array",
        "room",
        pose,
    )
    .unwrap()
}

fn evidence(capture: &SealedArrayCapture) -> EvidenceBlock {
    let decoded = capture.decode().unwrap();
    EvidenceBlock::new(
        EvidenceBlockIdentity::new(
            EvidenceScope::new(
                decoded.identity().source().clone(),
                decoded.identity().context(),
                decoded.window(),
                QualificationEpoch::new(4),
            ),
            [EvidenceMemberIdentity::new(*capture.digest().as_bytes())],
            decoded.signal_paths().iter().map(ArraySignalPath::signal_path),
        )
        .unwrap(),
        [EvidenceQuality::Captured],
    )
    .unwrap()
}

fn requirements() -> ModelRequirements {
    requirements_for(8)
}

fn requirements_for(path_count: u16) -> ModelRequirements {
    requirements_for_pose(path_count, pose([0.0; 3]))
}

fn requirements_for_pose(path_count: u16, geometry_pose: Pose) -> ModelRequirements {
    ModelRequirements::new(
        PhysicalOperator::AngleDelay,
        ArtifactScope::new(range(90, 110), QualificationEpoch::new(4), identity().context()),
        PhysicalRequirements::new(
            TimeRequirement::new(
                "array-clock",
                "host-clock",
                FitIdentity::new([21; 32]),
                ErrorBound::new(3, ErrorUnit::Nanoseconds),
            )
            .unwrap(),
            Some(PhaseRequirement::new(
                PhaseReferenceIdentity::new([22; 32]),
                range(90, 110),
                ErrorBound::new(30, ErrorUnit::Milliradians),
            )),
            (0..path_count).map(|rx| PortRequirement::new(SignalPath::new(0, rx), 0, rx)),
            Some(
                GeometryRequirement::new(
                    "array",
                    "room",
                    geometry_pose,
                    ErrorBound::new(80, ErrorUnit::Millimetres),
                )
                .unwrap(),
            ),
        )
        .unwrap(),
    )
    .unwrap()
}

fn qualification() -> Qualification {
    qualification_for(8)
}

fn qualification_for(path_count: u16) -> Qualification {
    Qualification::new(
        Some(time_relation()),
        Some(phase_relation(30, PhaseReferenceIdentity::new([22; 32]), range(90, 110))),
        Some(port_mapping(path_count, false)),
        Some(geometry_relation(pose([0.0; 3]))),
    )
}

fn record_for_view(index: u64, origin: [f64; 3]) -> ArrayPathRecord {
    let source = SourceInstance::new(
        SensorId::try_from(format!("array-{index}").as_str()).unwrap(),
        DeviceId::new(100 + index),
        KeyEpoch::new(3).unwrap(),
        BootGeneration::new(7).unwrap(),
    );
    let base = capture();
    let view_capture = ArrayCapture::new(
        ArrayCaptureIdentity::new(
            source.clone(),
            base.identity().event(),
            base.identity().context(),
            format!("espargos-{index}"),
            format!("rx-{index}"),
        )
        .unwrap(),
        base.ltf(),
        base.window(),
        base.observed_utc_ns(),
        base.native_metadata().clone(),
        base.frequencies_hz().iter().copied(),
        base.signal_paths().iter().cloned(),
        base.raw_iq().iter().copied(),
        base.sample_states().iter().copied(),
    )
    .unwrap();
    let view_capture = SealedArrayCapture::seal(view_capture).unwrap();
    let calibration = calibration_with(|value| {
        value.rf_device_identity = format!("rx-{index}");
        value.array_condition.array_identity = format!("espargos-{index}");
        value.world_transform.matrix[3] = origin[0];
        value.world_transform.matrix[7] = origin[1];
        value.world_transform.matrix[11] = origin[2];
    });
    let validity = |error| {
        RelationValidity::new(
            "fixture",
            source.clone(),
            error,
            range(90, 110),
            QualificationEpoch::new(4),
        )
        .unwrap()
    };
    let qualification = Qualification::new(
        Some(
            TimeRelation::new(
                validity(ErrorBound::new(3, ErrorUnit::Nanoseconds)),
                "array-clock",
                "host-clock",
                FitIdentity::new([21; 32]),
            )
            .unwrap(),
        ),
        Some(
            PhaseRelation::new(
                validity(ErrorBound::new(30, ErrorUnit::Milliradians)),
                PhaseReferenceIdentity::new([22; 32]),
                range(90, 110),
            )
            .unwrap(),
        ),
        Some(
            PortMapping::new(
                validity(ErrorBound::new(3, ErrorUnit::Nanoseconds)),
                (0..8).map(|rx| PortMapEntry::new(0, rx, Some(0), rx)),
            )
            .unwrap(),
        ),
        Some(
            Geometry::new(
                validity(ErrorBound::new(40, ErrorUnit::Millimetres)),
                "array",
                "room",
                pose(origin),
            )
            .unwrap(),
        ),
    );
    EspargosSourceAdapter::new()
        .adapt(
            &view_capture,
            &calibration,
            &evidence(&view_capture),
            &requirements_for_pose(8, pose(origin)),
            &qualification,
            None,
        )
        .unwrap()
}

#[test]
fn fixed_native_capture_round_trips_without_losing_axes_paths_or_iq() {
    const FIXTURE: &str = include_str!("fixtures/array/espargos-2x4-v1.csv");
    const FIXTURE_SHA256: [u8; 32] = [
        23, 252, 20, 5, 38, 179, 228, 63, 229, 184, 224, 217, 84, 225, 70, 160, 137, 158, 141, 225,
        17, 77, 232, 210, 28, 106, 120, 113, 91, 192, 211, 97,
    ];
    const CAPTURE_SHA256: [u8; 32] = [
        158, 15, 86, 241, 12, 198, 30, 33, 39, 182, 66, 166, 22, 163, 79, 123, 65, 20, 222, 152,
        164, 172, 67, 168, 140, 192, 215, 136, 37, 187, 237, 204,
    ];
    assert_eq!(<[u8; 32]>::from(Sha256::digest(FIXTURE.as_bytes())), FIXTURE_SHA256);
    let capture = capture();
    let sealed = SealedArrayCapture::seal(capture.clone()).unwrap();
    let parsed = SealedArrayCapture::parse(sealed.bytes()).unwrap();

    assert_eq!(parsed.decode().unwrap(), capture);
    assert_eq!(parsed.digest(), sealed.digest());
    assert_eq!(*parsed.digest().as_bytes(), CAPTURE_SHA256);
    assert_eq!(parsed.bytes(), sealed.bytes());
    assert_eq!(
        parsed.decode().unwrap().frequencies_hz(),
        [5_180_000_000, 5_180_312_500, 5_180_625_000, 5_180_937_500,]
    );
    assert_eq!(parsed.decode().unwrap().signal_paths().len(), 8);
    assert_eq!(parsed.decode().unwrap().raw_iq()[0], ComplexI16::new(-16, 16));
    assert_eq!(parsed.decode().unwrap().native_metadata().bandwidth_hz(), 20_000_000);
    assert_eq!(parsed.decode().unwrap().native_metadata().path_facts()[7].native_antenna(), 7);
}

#[test]
fn malformed_digest_shape_axis_and_duplicate_paths_are_rejected() {
    let sealed = sealed_capture();
    let mut tampered = sealed.bytes().to_vec();
    tampered[20] ^= 1;
    assert!(SealedArrayCapture::parse(&tampered).is_err());
    assert!(SealedArrayCapture::parse(&sealed.bytes()[..sealed.bytes().len() - 1]).is_err());

    let paths = (0_u16..8)
        .map(|rx| {
            ArraySignalPath::new(
                SignalPath::new(0, rx),
                NativeArrayPathIdentity::new([rx as u8 + 1; 32]),
                "tx/0",
                format!("rx/{rx}"),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(
        ArrayCapture::new(
            identity(),
            LtfIdentity::new([16; 32]),
            range(100, 103),
            1_800_000_000_000_000_000,
            native_metadata(8),
            [5_180_000_000, 5_179_000_000],
            paths.clone(),
            std::iter::repeat_n(ComplexI16::new(1, 1), 16),
            std::iter::repeat_n(SampleState::Captured, 16),
        )
        .is_err()
    );
    assert!(
        ArrayCapture::new(
            identity(),
            LtfIdentity::new([16; 32]),
            range(100, 103),
            1_800_000_000_000_000_000,
            native_metadata(2),
            [5_180_000_000, 5_181_000_000],
            [paths[0].clone(), paths[0].clone()],
            std::iter::repeat_n(ComplexI16::new(1, 1), 4),
            std::iter::repeat_n(SampleState::Captured, 4),
        )
        .is_err()
    );
    assert!(
        ArrayCapture::new(
            identity(),
            LtfIdentity::new([16; 32]),
            range(100, 103),
            1_800_000_000_000_000_000,
            native_metadata(8),
            [5_180_000_000, 5_181_000_000],
            paths,
            std::iter::repeat_n(ComplexI16::new(1, 1), 16),
            std::iter::repeat_n(SampleState::Captured, 15),
        )
        .is_err()
    );
}

#[test]
fn exact_local_calibration_and_relations_produce_a_qualified_path_record() {
    let capture = sealed_capture();
    let calibration = calibration();
    let record = EspargosSourceAdapter::new()
        .adapt(&capture, &calibration, &evidence(&capture), &requirements(), &qualification(), None)
        .unwrap();

    assert_eq!(record.capture_digest(), capture.digest());
    assert_eq!(record.calibration_digest(), calibration.digest());
    assert_eq!(record.array_identity(), "espargos-west");
    assert_eq!(record.geometry_error_m(), 0.072);
    assert!(!record.candidates().is_empty());
    let direction = record.candidates()[0].world_direction();
    let norm = direction.iter().map(|value| value * value).sum::<f64>().sqrt();
    assert!((norm - 1.0).abs() < 1.0e-12);
    assert!(record.coverage().qualified_sample_fraction() == 1.0);
    assert!(record.coverage().non_degenerate());
}

#[test]
fn immutable_static_spectrum_is_retained_and_never_erases_dynamic_path_evidence() {
    let capture = sealed_capture();
    let calibration = calibration();
    let seed_record = EspargosSourceAdapter::new()
        .adapt(&capture, &calibration, &evidence(&capture), &requirements(), &qualification(), None)
        .unwrap();
    let reference = StaticArrayReference::new(&seed_record, &capture).unwrap();
    let record = EspargosSourceAdapter::new()
        .adapt(
            &capture,
            &calibration,
            &evidence(&capture),
            &requirements(),
            &qualification(),
            Some(&reference),
        )
        .unwrap();

    assert_eq!(reference.capture_digest(), capture.digest());
    assert_eq!(record.static_reference_digest(), Some(reference.capture_digest()));
    assert_eq!(record.candidates()[0].kind(), PathKind::DirectPathPossible);
    assert!(record.candidates().iter().skip(1).all(|path| path.kind() == PathKind::StableStatic));

    let unrelated = SealedArrayCapture::seal(capture_with(
        std::iter::repeat_n(ComplexI16::new(1, 1), 32),
        std::iter::repeat_n(SampleState::Captured, 32),
    ))
    .unwrap();
    assert!(StaticArrayReference::new(&seed_record, &unrelated).is_err());

    let revised_calibration = calibration_with(|value| value.metadata.revision = 5);
    let failure = EspargosSourceAdapter::new()
        .adapt(
            &capture,
            &revised_calibration,
            &evidence(&capture),
            &requirements(),
            &qualification(),
            Some(&reference),
        )
        .unwrap_err();
    assert_eq!(failure.reason(), ArrayAdaptReason::StaticReferenceMismatch);
    assert_eq!(failure.disposition(), ArrayAdaptDisposition::EndEpoch);
}

#[test]
fn unmatched_paths_remain_dynamic_candidates_or_unexplained_rf_not_people() {
    let capture = sealed_capture();
    let quiet_reference = SealedArrayCapture::seal(capture_with(
        std::iter::repeat_n(ComplexI16::new(10, 10), 32),
        std::iter::repeat_n(SampleState::Captured, 32),
    ))
    .unwrap();
    let reference_record = EspargosSourceAdapter::new()
        .adapt(
            &quiet_reference,
            &calibration(),
            &evidence(&quiet_reference),
            &requirements(),
            &qualification(),
            None,
        )
        .unwrap();
    let quiet_reference = StaticArrayReference::new(&reference_record, &quiet_reference).unwrap();
    let record = EspargosSourceAdapter::new()
        .adapt(
            &capture,
            &calibration(),
            &evidence(&capture),
            &requirements(),
            &qualification(),
            Some(&quiet_reference),
        )
        .unwrap();

    assert!(record.candidates().iter().any(|path| path.kind() == PathKind::DynamicCandidate));
    assert!(record.candidates().iter().any(|path| path.kind() == PathKind::Unexplained));
}

#[test]
fn every_independent_relation_gap_blocks_angle_delay_without_an_aggregate_bypass() {
    let capture = sealed_capture();
    let calibration = calibration();
    let exact_phase = || phase_relation(30, PhaseReferenceIdentity::new([22; 32]), range(90, 110));
    let exact_geometry = || geometry_relation(pose([0.0; 3]));
    let cases = vec![
        (
            QualificationGap::TimeClockDomains,
            Qualification::new(
                Some(
                    TimeRelation::new(
                        relation_validity(),
                        "other-clock",
                        "host-clock",
                        FitIdentity::new([21; 32]),
                    )
                    .unwrap(),
                ),
                Some(exact_phase()),
                Some(port_mapping(8, false)),
                Some(exact_geometry()),
            ),
        ),
        (
            QualificationGap::TimeFit,
            Qualification::new(
                Some(
                    TimeRelation::new(
                        relation_validity(),
                        "array-clock",
                        "host-clock",
                        FitIdentity::new([99; 32]),
                    )
                    .unwrap(),
                ),
                Some(exact_phase()),
                Some(port_mapping(8, false)),
                Some(exact_geometry()),
            ),
        ),
        (
            QualificationGap::TimeError,
            Qualification::new(
                Some(
                    TimeRelation::new(
                        RelationValidity::new(
                            "fixture",
                            source(),
                            ErrorBound::new(4, ErrorUnit::Nanoseconds),
                            range(90, 110),
                            QualificationEpoch::new(4),
                        )
                        .unwrap(),
                        "array-clock",
                        "host-clock",
                        FitIdentity::new([21; 32]),
                    )
                    .unwrap(),
                ),
                Some(exact_phase()),
                Some(port_mapping(8, false)),
                Some(exact_geometry()),
            ),
        ),
        (
            QualificationGap::PhaseReference,
            Qualification::new(
                Some(time_relation()),
                Some(phase_relation(30, PhaseReferenceIdentity::new([99; 32]), range(90, 110))),
                Some(port_mapping(8, false)),
                Some(exact_geometry()),
            ),
        ),
        (
            QualificationGap::PhaseCoherence,
            Qualification::new(
                Some(time_relation()),
                Some(phase_relation(30, PhaseReferenceIdentity::new([22; 32]), range(95, 105))),
                Some(port_mapping(8, false)),
                Some(exact_geometry()),
            ),
        ),
        (
            QualificationGap::PhaseError,
            Qualification::new(
                Some(time_relation()),
                Some(phase_relation(31, PhaseReferenceIdentity::new([22; 32]), range(90, 110))),
                Some(port_mapping(8, false)),
                Some(exact_geometry()),
            ),
        ),
        (
            QualificationGap::SignalPathMapping,
            Qualification::new(
                Some(time_relation()),
                Some(exact_phase()),
                Some(port_mapping(8, true)),
                Some(exact_geometry()),
            ),
        ),
        (
            QualificationGap::GeometryPose,
            Qualification::new(
                Some(time_relation()),
                Some(exact_phase()),
                Some(port_mapping(8, false)),
                Some(geometry_relation(Pose::new([1; 7]))),
            ),
        ),
        (
            QualificationGap::GeometryError,
            Qualification::new(
                Some(time_relation()),
                Some(exact_phase()),
                Some(port_mapping(8, false)),
                Some(
                    Geometry::new(
                        RelationValidity::new(
                            "fixture",
                            source(),
                            ErrorBound::new(81, ErrorUnit::Millimetres),
                            range(90, 110),
                            QualificationEpoch::new(4),
                        )
                        .unwrap(),
                        "array",
                        "room",
                        pose([0.0; 3]),
                    )
                    .unwrap(),
                ),
            ),
        ),
    ];

    for (expected_gap, qualification) in cases {
        let failure = EspargosSourceAdapter::new()
            .adapt(
                &capture,
                &calibration,
                &evidence(&capture),
                &requirements(),
                &qualification,
                None,
            )
            .unwrap_err();
        assert_eq!(failure.reason(), ArrayAdaptReason::PhysicalQualification);
        assert!(failure.qualification_gaps().contains(&expected_gap), "missing {expected_gap:?}");
        let expected_disposition = match expected_gap {
            QualificationGap::TimeError
            | QualificationGap::PhaseError
            | QualificationGap::GeometryError => ArrayAdaptDisposition::RejectWindow,
            _ => ArrayAdaptDisposition::EndEpoch,
        };
        assert_eq!(failure.disposition(), expected_disposition, "gap={expected_gap:?}");
    }
}

#[test]
fn calibration_identity_validity_frequency_ports_and_geometry_fail_closed() {
    let capture = sealed_capture();
    let cases = vec![
        (
            ArrayAdaptReason::CalibrationIdentity,
            calibration_with(|value| value.rf_device_identity = "other-device".into()),
        ),
        (
            ArrayAdaptReason::CalibrationIdentity,
            calibration_with(|value| value.array_condition.array_identity = "other-array".into()),
        ),
        (
            ArrayAdaptReason::CalibrationValidity,
            calibration_with(|value| value.phase_relation.scope = CoherenceScope::Packet),
        ),
        (
            ArrayAdaptReason::CalibrationValidity,
            calibration_with(|value| {
                let end = UtcNanoseconds::from(1_750_000_000_000_000_000);
                value.valid_until_utc = end;
                value.array_geometry.valid_until_utc = end;
                value.phase_relation.valid_until_utc = end;
                value.time_relation.valid_until_utc = end;
            }),
        ),
        (
            ArrayAdaptReason::CalibrationValidity,
            calibration_with(|value| value.array_geometry.epoch = CalibrationEpoch::new(5)),
        ),
        (
            ArrayAdaptReason::CalibrationValidity,
            calibration_with(|value| {
                value.world_transform.target_coordinate_system = "other-room".into();
            }),
        ),
        (
            ArrayAdaptReason::CalibrationValidity,
            calibration_with(|value| value.world_transform.matrix[0] = 2.0),
        ),
        (
            ArrayAdaptReason::CalibrationValidity,
            calibration_with(|value| value.phase_relation.maximum_error_radians = 0.031),
        ),
        (
            ArrayAdaptReason::CalibrationValidity,
            calibration_with(|value| {
                value.time_relation.maximum_error = ClockErrorNanoseconds::from(4);
            }),
        ),
        (
            ArrayAdaptReason::FrequencyValidity,
            calibration_with(|value| {
                value.array_geometry.minimum_frequency_hz = 5_000_000_000;
                value.array_geometry.maximum_frequency_hz = 5_100_000_000;
            }),
        ),
        (
            ArrayAdaptReason::PortMapping,
            calibration_with(|value| {
                value.signal_paths.retain(|path| path.logical_path != "rx/7");
            }),
        ),
        (
            ArrayAdaptReason::PortMapping,
            calibration_with(|value| {
                value.signal_paths.push(SignalPathCondition {
                    logical_path: "rx/8".into(),
                    direction: SignalDirection::Receive,
                    device_chain: "rx-chain-8".into(),
                    antenna_identity: "element-0".into(),
                });
            }),
        ),
        (
            ArrayAdaptReason::PortMapping,
            calibration_with(|value| value.array_geometry.elements.swap(0, 1)),
        ),
        (
            ArrayAdaptReason::DegenerateGeometry,
            calibration_with(|value| {
                for (index, element) in value.array_geometry.elements.iter_mut().enumerate() {
                    element.position_m = [index as f64 * 0.03, 0.0, 0.0];
                }
            }),
        ),
        (
            ArrayAdaptReason::UnsupportedShape,
            calibration_with(|value| value.array_condition.physical_element_count = 7),
        ),
    ];

    for (expected, calibration) in cases {
        let failure = EspargosSourceAdapter::new()
            .adapt(
                &capture,
                &calibration,
                &evidence(&capture),
                &requirements(),
                &qualification(),
                None,
            )
            .unwrap_err();
        assert_eq!(failure.reason(), expected);
        assert_eq!(failure.disposition(), ArrayAdaptDisposition::EndEpoch);
    }
}

#[test]
fn every_non_native_sample_state_and_occluded_zero_energy_window_is_rejected() {
    for state in [
        SampleState::NotCaptured,
        SampleState::Lost,
        SampleState::Invalid,
        SampleState::Interpolated,
        SampleState::TrainingMasked,
    ] {
        let capture = SealedArrayCapture::seal(capture_with(
            std::iter::repeat_n(ComplexI16::new(1, -1), 32),
            std::iter::repeat_n(state, 32),
        ))
        .unwrap();
        let failure = EspargosSourceAdapter::new()
            .adapt(
                &capture,
                &calibration(),
                &evidence(&capture),
                &requirements(),
                &qualification(),
                None,
            )
            .unwrap_err();
        assert_eq!(failure.reason(), ArrayAdaptReason::SampleQuality, "state={state:?}");
        assert_eq!(failure.disposition(), ArrayAdaptDisposition::RejectWindow);
    }

    let occluded = SealedArrayCapture::seal(capture_with(
        std::iter::repeat_n(ComplexI16::new(0, 0), 32),
        std::iter::repeat_n(SampleState::Captured, 32),
    ))
    .unwrap();
    let failure = EspargosSourceAdapter::new()
        .adapt(
            &occluded,
            &calibration(),
            &evidence(&occluded),
            &requirements(),
            &qualification(),
            None,
        )
        .unwrap_err();
    assert_eq!(failure.reason(), ArrayAdaptReason::InsufficientSignal);
    assert_eq!(failure.disposition(), ArrayAdaptDisposition::RejectWindow);
}

#[test]
fn non_two_by_four_capture_shape_never_reaches_angle_delay_estimation() {
    let seven_path_capture = SealedArrayCapture::seal(capture_shape(
        7,
        std::iter::repeat_n(ComplexI16::new(1, -1), 28),
        std::iter::repeat_n(SampleState::Captured, 28),
    ))
    .unwrap();
    let failure = EspargosSourceAdapter::new()
        .adapt(
            &seven_path_capture,
            &calibration(),
            &evidence(&seven_path_capture),
            &requirements_for(7),
            &qualification_for(7),
            None,
        )
        .unwrap_err();
    assert_eq!(failure.reason(), ArrayAdaptReason::UnsupportedShape);
    assert_eq!(failure.disposition(), ArrayAdaptDisposition::EndEpoch);

    let base = capture();
    let mut paths = base.signal_paths().to_vec();
    paths[7] = ArraySignalPath::new(SignalPath::new(1, 7), paths[7].native_path(), "tx/1", "rx/7")
        .unwrap();
    let mixed_transmitters = SealedArrayCapture::seal(
        ArrayCapture::new(
            base.identity().clone(),
            base.ltf(),
            base.window(),
            base.observed_utc_ns(),
            base.native_metadata().clone(),
            base.frequencies_hz().iter().copied(),
            paths,
            base.raw_iq().iter().copied(),
            base.sample_states().iter().copied(),
        )
        .unwrap(),
    )
    .unwrap();
    let failure = EspargosSourceAdapter::new()
        .adapt(
            &mixed_transmitters,
            &calibration(),
            &evidence(&mixed_transmitters),
            &requirements(),
            &qualification(),
            None,
        )
        .unwrap_err();
    assert_eq!(failure.reason(), ArrayAdaptReason::UnsupportedShape);
}

#[test]
fn three_views_report_each_array_and_at_least_two_non_degenerate_qualifications() {
    let records = [
        record_for_view(1, [0.0, 0.0, 1.2]),
        record_for_view(2, [4.0, 0.0, 1.2]),
        record_for_view(3, [2.0, 4.0, 1.2]),
    ];
    let coverage = ThreeArrayCoverage::new(records.iter()).unwrap();

    assert_eq!(coverage.views().len(), 3);
    assert_eq!(coverage.non_degenerate_view_count(), 3);
    assert!(coverage.has_required_non_degenerate_views());
    assert_eq!(
        coverage.views().iter().map(|view| view.array_identity()).collect::<Vec<_>>(),
        ["espargos-1", "espargos-2", "espargos-3"]
    );
    assert!(ThreeArrayCoverage::new([&records[0], &records[0], &records[2]]).is_err());
}
