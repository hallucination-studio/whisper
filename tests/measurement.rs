//! Public measurement assembly and physical qualification behavior.

use sha2::{Digest, Sha256};
use whisper::measurement::{
    AssemblyCloseReason, AssemblyKey, AssemblyLimits, EvidenceBlock, EvidenceQuality, Geometry,
    MeasurementAssembler, MeasurementFragment, ModelRequirements, PhaseRelation, PhysicalOperator,
    PortMapping, QualificationGap, RelationValidity, TimeRelation,
};
use whisper::{BootGeneration, DeviceId};

fn key(boot: u32, event: u64) -> AssemblyKey {
    AssemblyKey::new(
        DeviceId::new(7),
        BootGeneration::new(boot).unwrap(),
        [2, 0, 0, 0, 0, 1],
        event,
        Some(91),
    )
}

fn fragment(boot: u32, event: u64, ordinal: u16, expected: u16) -> MeasurementFragment {
    MeasurementFragment::new(
        key(boot, event),
        ordinal,
        expected,
        [ordinal as u8 + 1; 32],
        12,
        EvidenceQuality::Captured,
    )
    .unwrap()
}

#[test]
fn assembly_is_deterministic_across_reordering_and_exact_duplicates() {
    const FIXTURE: &str = include_str!("fixtures/measurement/fragments-v1.txt");
    const FIXTURE_SHA256: [u8; 32] = [
        205, 38, 239, 195, 234, 42, 62, 253, 208, 219, 42, 62, 250, 124, 7, 23, 56, 77, 84, 86, 43,
        181, 180, 152, 157, 226, 125, 234, 3, 30, 89, 163,
    ];
    assert_eq!(<[u8; 32]>::from(Sha256::digest(FIXTURE.as_bytes())), FIXTURE_SHA256);
    let mut assembler = MeasurementAssembler::new(AssemblyLimits::new(4, 4, 64, 10).unwrap());
    let mut close = None;
    for line in FIXTURE.lines().filter(|line| !line.starts_with('#')) {
        let fields = line.split(',').collect::<Vec<_>>();
        let arrival = fields[0].parse().unwrap();
        let boot = fields[1].parse().unwrap();
        let event = fields[2].parse().unwrap();
        let ordinal = fields[3].parse().unwrap();
        let expected = fields[4].parse().unwrap();
        let digest_byte = fields[5].parse().unwrap();
        let payload_bytes = fields[6].parse().unwrap();
        assert_eq!(fields[7], "captured");
        close = assembler
            .ingest(
                MeasurementFragment::new(
                    key(boot, event),
                    ordinal,
                    expected,
                    [digest_byte; 32],
                    payload_bytes,
                    EvidenceQuality::Captured,
                )
                .unwrap(),
                arrival,
            )
            .unwrap()
            .or(close);
    }
    let close = close.unwrap();

    assert_eq!(close.reason(), AssemblyCloseReason::Complete);
    assert_eq!(close.members().iter().map(|member| member.ordinal()).collect::<Vec<_>>(), [0, 1]);
    assert!(close.missing_ordinals().is_empty());
    assert_eq!(close.total_bytes(), 24);
}

#[test]
fn timeout_fixes_missing_members_and_late_data_never_mutates_the_close() {
    let mut assembler = MeasurementAssembler::new(AssemblyLimits::new(4, 4, 64, 5).unwrap());
    assembler.ingest(fragment(1, 8, 0, 2), 10).unwrap();
    let original = assembler.expire(15);
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].reason(), AssemblyCloseReason::WaitLimit);
    assert_eq!(original[0].missing_ordinals(), [1]);

    let late = assembler.ingest(fragment(1, 8, 1, 2), 16).unwrap().unwrap();
    assert_eq!(late.reason(), AssemblyCloseReason::LateFragment);
    assert_eq!(late.members().len(), 1);
    assert_eq!(original[0].missing_ordinals(), [1]);
}

#[test]
fn identical_event_numbers_from_different_boots_do_not_join() {
    let mut assembler = MeasurementAssembler::new(AssemblyLimits::new(4, 4, 64, 5).unwrap());
    assembler.ingest(fragment(1, 8, 0, 2), 0).unwrap();
    assembler.ingest(fragment(2, 8, 1, 2), 1).unwrap();
    let closes = assembler.expire(6);

    assert_eq!(closes.len(), 2);
    assert_ne!(closes[0].key().boot_generation(), closes[1].key().boot_generation());
    assert!(closes.iter().all(|close| close.members().len() == 1));
}

fn validity(epoch: u64, until: u64) -> RelationValidity {
    RelationValidity::new("survey", 3, 0, until, epoch).unwrap()
}

#[test]
fn time_alignment_does_not_grant_phase_or_unknown_tx_geometry() {
    let block = EvidenceBlock::new(5, 4, [EvidenceQuality::Captured]);
    let qualification = whisper::measurement::Qualification::new(
        Some(TimeRelation::new(validity(4, 10))),
        None,
        Some(PortMapping::new(validity(4, 10), false)),
        Some(Geometry::new(validity(4, 10))),
    );
    let result = qualification.eligibility(
        PhysicalOperator::AngleDelay,
        &block,
        ModelRequirements::angle_delay(),
    );

    assert!(!result.is_eligible());
    assert_eq!(result.gaps(), [QualificationGap::PhaseRelation, QualificationGap::TxGeometry]);
}

#[test]
fn expired_relations_and_distinct_quality_states_are_explicit_gaps() {
    let qualification = whisper::measurement::Qualification::new(
        Some(TimeRelation::new(validity(4, 3))),
        Some(PhaseRelation::new(validity(4, 3))),
        Some(PortMapping::new(validity(4, 3), true)),
        Some(Geometry::new(validity(4, 3))),
    );
    for (quality, expected_gap) in [
        (EvidenceQuality::NotCaptured, QualificationGap::NotCaptured),
        (EvidenceQuality::Lost, QualificationGap::Lost),
        (EvidenceQuality::Invalid, QualificationGap::Invalid),
        (EvidenceQuality::Interpolated, QualificationGap::Interpolated),
        (EvidenceQuality::TrainingMasked, QualificationGap::TrainingMasked),
    ] {
        let result = qualification.eligibility(
            PhysicalOperator::AbsoluteResponse,
            &EvidenceBlock::new(5, 4, [quality]),
            ModelRequirements::absolute_response(),
        );
        assert!(result.gaps().contains(&expected_gap));
        assert!(result.gaps().contains(&QualificationGap::TimeRelation));
    }
}
