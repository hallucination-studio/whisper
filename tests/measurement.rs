//! Public measurement assembly and physical qualification behavior.

use sha2::{Digest, Sha256};
use whisper::measurement::{
    ArtifactScope, AssemblyCapacity, AssemblyCloseReason, AssemblyKey, AssemblyLimits,
    ChannelIdentity, ErrorBound, ErrorUnit, EventIdentity, EvidenceBlock, EvidenceBlockIdentity,
    EvidenceMemberIdentity, EvidenceQuality, EvidenceScope, FitIdentity, FragmentBytes,
    FragmentFact, FragmentPosition, Geometry, GeometryRequirement, MeasurementAssembler,
    MeasurementContext, MeasurementFragment, ModelRequirements, NativeEventIdentity,
    PhaseReferenceIdentity, PhaseRelation, PhaseRequirement, PhysicalOperator,
    PhysicalRequirements, PortMapEntry, PortMapping, PortRequirement, Pose, ProfileIdentity,
    Qualification, QualificationEpoch, QualificationGap, RadioIdentity, RelationValidity,
    SignalPath, SourceInstance, SourceTick, TickRange, TimeRelation, TimeRequirement,
    TransmitterIdentity, WaitTicks,
};
use whisper::{BootGeneration, DeviceId, KeyEpoch, SensorId};

fn source(boot: u32) -> SourceInstance {
    SourceInstance::new(
        SensorId::try_from("receiver-a").unwrap(),
        DeviceId::new(7),
        KeyEpoch::new(2).unwrap(),
        BootGeneration::new(boot).unwrap(),
    )
}

fn key(boot: u32, event: u8) -> AssemblyKey {
    AssemblyKey::new(
        source(boot),
        EventIdentity::new(
            TransmitterIdentity::new([3; 32]),
            NativeEventIdentity::new([event; 32]),
            None,
        ),
        MeasurementContext::new(
            ProfileIdentity::new([4; 32]),
            RadioIdentity::new([5; 32]),
            ChannelIdentity::new([6; 32]),
        ),
    )
}

fn fragment_with(
    boot: u32,
    event: u8,
    ordinal: u16,
    expected: u16,
    digest: u8,
    bytes: u32,
) -> MeasurementFragment {
    MeasurementFragment::new(
        key(boot, event),
        FragmentPosition::new(ordinal, expected).unwrap(),
        FragmentFact::new(
            [digest; 32],
            FragmentBytes::new(bytes).unwrap(),
            EvidenceQuality::Captured,
        ),
    )
}

fn fragment(boot: u32, event: u8, ordinal: u16, expected: u16) -> MeasurementFragment {
    fragment_with(boot, event, ordinal, expected, ordinal as u8 + 1, 12)
}

fn limits(open: usize, fragments: u16, bytes: u64, wait: u64) -> AssemblyLimits {
    AssemblyLimits::new(
        AssemblyCapacity::new(open, fragments, bytes).unwrap(),
        WaitTicks::new(wait).unwrap(),
    )
}

#[test]
fn assembly_reorders_and_records_exact_duplicates_without_mutating_membership() {
    const FIXTURE: &str = include_str!("fixtures/measurement/fragments-v1.txt");
    const FIXTURE_SHA256: [u8; 32] = [
        205, 38, 239, 195, 234, 42, 62, 253, 208, 219, 42, 62, 250, 124, 7, 23, 56, 77, 84, 86, 43,
        181, 180, 152, 157, 226, 125, 234, 3, 30, 89, 163,
    ];
    assert_eq!(<[u8; 32]>::from(Sha256::digest(FIXTURE.as_bytes())), FIXTURE_SHA256);
    let mut assembler = MeasurementAssembler::new(limits(4, 4, 64, 10));
    let mut closes = Vec::new();
    for line in FIXTURE.lines().filter(|line| !line.starts_with('#')) {
        let values = line.split(',').collect::<Vec<_>>();
        let arrival = values[0].parse().unwrap();
        closes.extend(
            assembler
                .ingest(
                    fragment_with(
                        values[1].parse().unwrap(),
                        values[2].parse().unwrap(),
                        values[3].parse().unwrap(),
                        values[4].parse().unwrap(),
                        values[5].parse().unwrap(),
                        values[6].parse().unwrap(),
                    ),
                    SourceTick::new(arrival),
                )
                .unwrap(),
        );
    }
    assert_eq!(
        closes.iter().map(|close| close.reason()).collect::<Vec<_>>(),
        [AssemblyCloseReason::DuplicateFragment, AssemblyCloseReason::Complete,]
    );
    assert_eq!(
        closes[1].members().iter().map(|member| member.ordinal()).collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(closes[1].expected_fragments(), 2);
    assert!(closes[1].missing_ordinals().is_empty());
}

#[test]
fn partial_timeout_and_late_data_are_separate_immutable_facts() {
    let mut assembler = MeasurementAssembler::new(limits(4, 4, 64, 5));
    assembler.ingest(fragment(1, 8, 0, 2), SourceTick::new(10)).unwrap();
    let original = assembler.expire(&source(1), SourceTick::new(15)).remove(0);
    assert_eq!(original.reason(), AssemblyCloseReason::WaitLimit);
    assert_eq!(original.missing_ordinals(), [1]);
    let late = assembler.late(fragment(1, 8, 1, 2), SourceTick::new(16));
    assert_eq!(late.reason(), AssemblyCloseReason::LateFragment);
    assert_eq!(original.missing_ordinals(), [1]);
}

#[test]
fn boot_profile_radio_and_channel_boundaries_never_mix() {
    let mut assembler = MeasurementAssembler::new(limits(8, 4, 64, 5));
    let first = fragment(1, 8, 0, 2);
    let base = first.key().clone();
    let contexts = [
        MeasurementContext::new(
            ProfileIdentity::new([9; 32]),
            base.context().radio(),
            base.context().channel(),
        ),
        MeasurementContext::new(
            base.context().profile(),
            RadioIdentity::new([9; 32]),
            base.context().channel(),
        ),
        MeasurementContext::new(
            base.context().profile(),
            base.context().radio(),
            ChannelIdentity::new([9; 32]),
        ),
    ];
    assembler.ingest(first, SourceTick::new(0)).unwrap();
    for context in contexts {
        assembler
            .ingest(
                MeasurementFragment::new(
                    AssemblyKey::new(base.source().clone(), base.event(), context),
                    FragmentPosition::new(1, 2).unwrap(),
                    FragmentFact::new(
                        [2; 32],
                        FragmentBytes::new(12).unwrap(),
                        EvidenceQuality::Captured,
                    ),
                ),
                SourceTick::new(1),
            )
            .unwrap();
    }
    assembler
        .ingest(
            MeasurementFragment::new(
                AssemblyKey::new(source(2), base.event(), base.context()),
                FragmentPosition::new(1, 2).unwrap(),
                FragmentFact::new(
                    [2; 32],
                    FragmentBytes::new(12).unwrap(),
                    EvidenceQuality::Captured,
                ),
            ),
            SourceTick::new(1),
        )
        .unwrap();
    let mut closes = assembler.expire(&source(1), SourceTick::new(6));
    closes.extend(assembler.expire(&source(2), SourceTick::new(6)));
    assert_eq!(closes.len(), 5);
    assert!(closes.iter().all(|close| close.members().len() == 1));
}

#[test]
fn every_resource_ceiling_has_an_explicit_close_reason() {
    let mut count = MeasurementAssembler::new(limits(2, 1, 64, 5));
    assert_eq!(
        count.ingest(fragment(1, 1, 0, 2), SourceTick::new(0)).unwrap()[0].reason(),
        AssemblyCloseReason::CountLimit
    );
    let mut bytes = MeasurementAssembler::new(limits(2, 4, 8, 5));
    assert_eq!(
        bytes.ingest(fragment(1, 2, 0, 2), SourceTick::new(0)).unwrap()[0].reason(),
        AssemblyCloseReason::ByteLimit
    );
    let mut open = MeasurementAssembler::new(limits(1, 4, 64, 5));
    open.ingest(fragment(1, 3, 0, 2), SourceTick::new(0)).unwrap();
    assert_eq!(
        open.ingest(fragment(1, 4, 0, 2), SourceTick::new(1)).unwrap()[0].reason(),
        AssemblyCloseReason::ResourceLimit
    );
}

fn range(start: u64, end: u64) -> TickRange {
    TickRange::new(SourceTick::new(start), SourceTick::new(end)).unwrap()
}

fn validity(end: u64) -> RelationValidity {
    validity_with_error(end, ErrorBound::new(3, ErrorUnit::Nanoseconds))
}

fn validity_with_error(end: u64, error: ErrorBound) -> RelationValidity {
    RelationValidity::new("survey", source(1), error, range(0, end), QualificationEpoch::new(4))
        .unwrap()
}

fn block(window: TickRange, quality: EvidenceQuality) -> EvidenceBlock {
    EvidenceBlock::new(
        EvidenceBlockIdentity::new(
            EvidenceScope::new(source(1), key(1, 1).context(), window, QualificationEpoch::new(4)),
            [EvidenceMemberIdentity::new([1; 32])],
            [SignalPath::new(0, 0)],
        )
        .unwrap(),
        [quality],
    )
    .unwrap()
}

fn requirements(operator: PhysicalOperator, activation: TickRange) -> ModelRequirements {
    let angle = operator == PhysicalOperator::AngleDelay;
    ModelRequirements::new(
        operator,
        ArtifactScope::new(activation, QualificationEpoch::new(4), key(1, 1).context()),
        PhysicalRequirements::new(
            TimeRequirement::new(
                "sensor-clock",
                "model-clock",
                FitIdentity::new([1; 32]),
                ErrorBound::new(3, ErrorUnit::Nanoseconds),
            )
            .unwrap(),
            angle.then_some(PhaseRequirement::new(
                PhaseReferenceIdentity::new([2; 32]),
                range(0, 10),
                ErrorBound::new(3, ErrorUnit::Nanoseconds),
            )),
            angle.then_some(PortRequirement::new(SignalPath::new(0, 0), 2, 1)),
            angle
                .then(|| {
                    GeometryRequirement::new(
                        "sensor",
                        "room",
                        Pose::new([0; 7]),
                        ErrorBound::new(3, ErrorUnit::Nanoseconds),
                    )
                })
                .transpose()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn model_requirements_reject_every_partial_operator_input_combination() {
    for operator in [
        PhysicalOperator::AbsoluteResponse,
        PhysicalOperator::FastChange,
        PhysicalOperator::AngleDelay,
    ] {
        for mask in 0_u8..8 {
            let physical = PhysicalRequirements::new(
                TimeRequirement::new(
                    "sensor-clock",
                    "model-clock",
                    FitIdentity::new([1; 32]),
                    ErrorBound::new(3, ErrorUnit::Nanoseconds),
                )
                .unwrap(),
                (mask & 1 != 0).then_some(PhaseRequirement::new(
                    PhaseReferenceIdentity::new([2; 32]),
                    range(0, 10),
                    ErrorBound::new(3, ErrorUnit::Milliradians),
                )),
                (mask & 2 != 0).then_some(PortRequirement::new(SignalPath::new(0, 0), 2, 1)),
                (mask & 4 != 0)
                    .then(|| {
                        GeometryRequirement::new(
                            "sensor",
                            "room",
                            Pose::new([0; 7]),
                            ErrorBound::new(3, ErrorUnit::Millimetres),
                        )
                    })
                    .transpose()
                    .unwrap(),
            )
            .unwrap();
            let result = ModelRequirements::new(
                operator,
                ArtifactScope::new(range(0, 10), QualificationEpoch::new(4), key(1, 1).context()),
                physical,
            );
            let accepted = match operator {
                PhysicalOperator::AngleDelay => mask == 7,
                PhysicalOperator::AbsoluteResponse | PhysicalOperator::FastChange => mask == 0,
            };
            assert_eq!(result.is_ok(), accepted, "operator={operator:?}, mask={mask:03b}");
        }
    }
}

#[test]
fn eligibility_checks_exact_relation_source_window_and_operator_requirements() {
    let qualification = Qualification::new(
        Some(
            TimeRelation::new(
                validity(10),
                "sensor-clock",
                "model-clock",
                FitIdentity::new([1; 32]),
            )
            .unwrap(),
        ),
        None,
        Some(PortMapping::new(validity(10), [PortMapEntry::new(0, 0, None, 1)]).unwrap()),
        Some(Geometry::new(validity(10), "sensor", "room", Pose::new([0; 7])).unwrap()),
    );
    let result = qualification.eligibility(
        &block(range(5, 6), EvidenceQuality::Captured),
        &requirements(PhysicalOperator::AngleDelay, range(0, 10)),
    );
    assert_eq!(
        result.gaps(),
        [QualificationGap::PhaseRelation, QualificationGap::SignalPathMapping]
    );
}

#[test]
fn activation_relation_and_quality_failures_remain_distinct() {
    let qualification = Qualification::new(
        Some(
            TimeRelation::new(
                validity(3),
                "sensor-clock",
                "model-clock",
                FitIdentity::new([1; 32]),
            )
            .unwrap(),
        ),
        Some(
            PhaseRelation::new(validity(3), PhaseReferenceIdentity::new([2; 32]), range(0, 3))
                .unwrap(),
        ),
        None,
        None,
    );
    let result = qualification.eligibility(
        &block(range(5, 5), EvidenceQuality::Interpolated),
        &requirements(PhysicalOperator::AbsoluteResponse, range(0, 4)),
    );
    assert!(result.gaps().contains(&QualificationGap::Interpolated));
    assert!(result.gaps().contains(&QualificationGap::ArtifactActivation));
    assert!(result.gaps().contains(&QualificationGap::TimeScope));
}

#[test]
fn eligibility_reports_exact_physical_mismatches_without_accepting_unrelated_inputs() {
    let evidence = block(range(5, 6), EvidenceQuality::Captured);
    let required = requirements(PhysicalOperator::AngleDelay, range(0, 10));

    let bad_time = Qualification::new(
        Some(
            TimeRelation::new(
                validity_with_error(10, ErrorBound::new(u64::MAX, ErrorUnit::Nanoseconds)),
                "sensor-clock",
                "model-clock",
                FitIdentity::new([1; 32]),
            )
            .unwrap(),
        ),
        Some(
            PhaseRelation::new(
                validity_with_error(10, ErrorBound::new(u64::MAX, ErrorUnit::Nanoseconds)),
                PhaseReferenceIdentity::new([9; 32]),
                range(0, 10),
            )
            .unwrap(),
        ),
        Some(
            PortMapping::new(
                validity(10),
                [PortMapEntry::new(0, 0, Some(2), 1), PortMapEntry::new(8, 8, Some(8), 8)],
            )
            .unwrap(),
        ),
        Some(
            Geometry::new(
                validity_with_error(10, ErrorBound::new(u64::MAX, ErrorUnit::Nanoseconds)),
                "sensor",
                "other-room",
                Pose::new([0; 7]),
            )
            .unwrap(),
        ),
    );

    let gaps = bad_time.eligibility(&evidence, &required);
    assert!(gaps.gaps().contains(&QualificationGap::TimeError));
    assert!(gaps.gaps().contains(&QualificationGap::PhaseReference));
    assert!(gaps.gaps().contains(&QualificationGap::PhaseError));
    assert!(gaps.gaps().contains(&QualificationGap::SignalPathMapping));
    assert!(gaps.gaps().contains(&QualificationGap::GeometryFrames));
    assert!(gaps.gaps().contains(&QualificationGap::GeometryError));
    assert!(!gaps.is_eligible());

    let exact = Qualification::new(
        Some(
            TimeRelation::new(
                validity(10),
                "sensor-clock",
                "model-clock",
                FitIdentity::new([1; 32]),
            )
            .unwrap(),
        ),
        Some(
            PhaseRelation::new(validity(10), PhaseReferenceIdentity::new([2; 32]), range(0, 10))
                .unwrap(),
        ),
        Some(PortMapping::new(validity(10), [PortMapEntry::new(0, 0, Some(2), 1)]).unwrap()),
        Some(Geometry::new(validity(10), "sensor", "room", Pose::new([0; 7])).unwrap()),
    );
    assert!(exact.eligibility(&evidence, &required).is_eligible());
}

#[test]
fn eligibility_rejects_profile_radio_or_channel_crossing() {
    let qualification = Qualification::new(
        Some(
            TimeRelation::new(
                validity(10),
                "sensor-clock",
                "model-clock",
                FitIdentity::new([1; 32]),
            )
            .unwrap(),
        ),
        None,
        None,
        None,
    );
    for context in [
        MeasurementContext::new(
            ProfileIdentity::new([99; 32]),
            RadioIdentity::new([5; 32]),
            ChannelIdentity::new([6; 32]),
        ),
        MeasurementContext::new(
            ProfileIdentity::new([4; 32]),
            RadioIdentity::new([99; 32]),
            ChannelIdentity::new([6; 32]),
        ),
        MeasurementContext::new(
            ProfileIdentity::new([4; 32]),
            RadioIdentity::new([5; 32]),
            ChannelIdentity::new([99; 32]),
        ),
    ] {
        let identity = EvidenceBlockIdentity::new(
            EvidenceScope::new(source(1), context, range(5, 6), QualificationEpoch::new(4)),
            [EvidenceMemberIdentity::new([1; 32])],
            [],
        )
        .unwrap();
        let evidence = EvidenceBlock::new(identity, [EvidenceQuality::Captured]).unwrap();
        let gaps = qualification.eligibility(
            &evidence,
            &requirements(PhysicalOperator::AbsoluteResponse, range(0, 10)),
        );
        assert!(gaps.gaps().contains(&QualificationGap::MeasurementContext));
    }
}

#[test]
fn eligibility_reports_each_relation_identity_validity_and_mapping_gap() {
    let evidence = block(range(5, 6), EvidenceQuality::Captured);
    let required = requirements(PhysicalOperator::AngleDelay, range(0, 10));
    let exact_time =
        TimeRelation::new(validity(10), "sensor-clock", "model-clock", FitIdentity::new([1; 32]))
            .unwrap();
    let exact_phase =
        PhaseRelation::new(validity(10), PhaseReferenceIdentity::new([2; 32]), range(0, 10))
            .unwrap();
    let exact_port = PortMapping::new(validity(10), [PortMapEntry::new(0, 0, Some(2), 1)]).unwrap();
    let exact_geometry = Geometry::new(validity(10), "sensor", "room", Pose::new([0; 7])).unwrap();
    let cases = [
        (
            QualificationGap::TimeClockDomains,
            Qualification::new(
                Some(
                    TimeRelation::new(
                        validity(10),
                        "other-clock",
                        "model-clock",
                        FitIdentity::new([1; 32]),
                    )
                    .unwrap(),
                ),
                Some(exact_phase.clone()),
                Some(exact_port.clone()),
                Some(exact_geometry.clone()),
            ),
        ),
        (
            QualificationGap::TimeFit,
            Qualification::new(
                Some(
                    TimeRelation::new(
                        validity(10),
                        "sensor-clock",
                        "model-clock",
                        FitIdentity::new([9; 32]),
                    )
                    .unwrap(),
                ),
                Some(exact_phase.clone()),
                Some(exact_port.clone()),
                Some(exact_geometry.clone()),
            ),
        ),
        (
            QualificationGap::TimeScope,
            Qualification::new(
                Some(
                    TimeRelation::new(
                        validity(4),
                        "sensor-clock",
                        "model-clock",
                        FitIdentity::new([1; 32]),
                    )
                    .unwrap(),
                ),
                Some(exact_phase.clone()),
                Some(exact_port.clone()),
                Some(exact_geometry.clone()),
            ),
        ),
        (
            QualificationGap::PhaseCoherence,
            Qualification::new(
                Some(exact_time.clone()),
                Some(
                    PhaseRelation::new(
                        validity(10),
                        PhaseReferenceIdentity::new([2; 32]),
                        range(0, 4),
                    )
                    .unwrap(),
                ),
                Some(exact_port.clone()),
                Some(exact_geometry.clone()),
            ),
        ),
        (
            QualificationGap::PortMapping,
            Qualification::new(
                Some(exact_time.clone()),
                Some(exact_phase.clone()),
                None,
                Some(exact_geometry.clone()),
            ),
        ),
        (
            QualificationGap::GeometryPose,
            Qualification::new(
                Some(exact_time.clone()),
                Some(exact_phase.clone()),
                Some(exact_port.clone()),
                Some(Geometry::new(validity(10), "sensor", "room", Pose::new([1; 7])).unwrap()),
            ),
        ),
        (
            QualificationGap::TimeError,
            Qualification::new(
                Some(
                    TimeRelation::new(
                        validity_with_error(10, ErrorBound::new(3, ErrorUnit::Millimetres)),
                        "sensor-clock",
                        "model-clock",
                        FitIdentity::new([1; 32]),
                    )
                    .unwrap(),
                ),
                Some(exact_phase),
                Some(exact_port),
                Some(exact_geometry),
            ),
        ),
    ];
    for (expected, qualification) in cases {
        let gaps = qualification.eligibility(&evidence, &required);
        assert!(gaps.gaps().contains(&expected), "missing {expected:?}: {:?}", gaps.gaps());
    }

    let expired_epoch_identity = EvidenceBlockIdentity::new(
        EvidenceScope::new(source(1), key(1, 1).context(), range(5, 6), QualificationEpoch::new(5)),
        [EvidenceMemberIdentity::new([1; 32])],
        [SignalPath::new(0, 0)],
    )
    .unwrap();
    let expired_epoch =
        EvidenceBlock::new(expired_epoch_identity, [EvidenceQuality::Captured]).unwrap();
    let gaps = Qualification::new(Some(exact_time), None, None, None).eligibility(
        &expired_epoch,
        &requirements(PhysicalOperator::AbsoluteResponse, range(0, 10)),
    );
    assert!(gaps.gaps().contains(&QualificationGap::ArtifactActivation));
}
