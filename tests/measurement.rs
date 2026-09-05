//! Public measurement assembly and physical qualification behavior.

use sha2::{Digest, Sha256};
use whisper::measurement::{
    AssemblyCapacity, AssemblyCloseReason, AssemblyKey, AssemblyLimits, ChannelIdentity,
    ErrorBound, ErrorUnit, EventIdentity, EvidenceBlock, EvidenceBlockIdentity,
    EvidenceMemberIdentity, EvidenceQuality, FitIdentity, FragmentBytes, FragmentFact,
    FragmentPosition, Geometry, MeasurementAssembler, MeasurementContext, MeasurementFragment,
    ModelRequirements, NativeEventIdentity, PhaseReferenceIdentity, PhaseRelation,
    PhysicalOperator, PortMapEntry, PortMapping, Pose, ProfileIdentity, Qualification,
    QualificationEpoch, QualificationGap, RadioIdentity, RelationValidity, SourceInstance,
    SourceTick, TickRange, TimeRelation, TransmitterIdentity, WaitTicks,
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
    let late = MeasurementAssembler::late(fragment(1, 8, 1, 2));
    assert_eq!(late.reason(), AssemblyCloseReason::LateFragment);
    assert_eq!(original.missing_ordinals(), [1]);
}

#[test]
fn source_profile_radio_and_channel_boundaries_never_mix() {
    let mut assembler = MeasurementAssembler::new(limits(8, 4, 64, 5));
    let first = fragment(1, 8, 0, 2);
    let mut different = first.key().clone();
    different = AssemblyKey::new(
        different.source().clone(),
        different.event(),
        MeasurementContext::new(
            ProfileIdentity::new([9; 32]),
            different.context().radio(),
            different.context().channel(),
        ),
    );
    assembler.ingest(first, SourceTick::new(0)).unwrap();
    assembler
        .ingest(
            MeasurementFragment::new(
                different,
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
    let closes = assembler.expire(&source(1), SourceTick::new(6));
    assert_eq!(closes.len(), 2);
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
    RelationValidity::new(
        "survey",
        source(1),
        ErrorBound::new(3, ErrorUnit::Nanoseconds),
        range(0, end),
        QualificationEpoch::new(4),
    )
    .unwrap()
}

fn block(window: TickRange, quality: EvidenceQuality) -> EvidenceBlock {
    EvidenceBlock::new(
        EvidenceBlockIdentity::new(
            source(1),
            [EvidenceMemberIdentity::new([1; 32])],
            window,
            QualificationEpoch::new(4),
        )
        .unwrap(),
        [quality],
    )
    .unwrap()
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
        PhysicalOperator::AngleDelay,
        &block(range(5, 6), EvidenceQuality::Captured),
        ModelRequirements::new(range(0, 10), QualificationEpoch::new(4)),
    );
    assert_eq!(result.gaps(), [QualificationGap::PhaseRelation, QualificationGap::TxGeometry]);
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
        PhysicalOperator::AbsoluteResponse,
        &block(range(5, 5), EvidenceQuality::Interpolated),
        ModelRequirements::new(range(0, 4), QualificationEpoch::new(4)),
    );
    assert!(result.gaps().contains(&QualificationGap::Interpolated));
    assert!(result.gaps().contains(&QualificationGap::ArtifactActivation));
    assert!(result.gaps().contains(&QualificationGap::TimeRelation));
}
