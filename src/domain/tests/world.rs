//! Baseline, evidence, and world-snapshot invariant tests.

use std::collections::BTreeMap;

use crate::domain::csi::{CaptureProfileId, CsiPath, CsiSampleCoordinate};
use crate::domain::identity::{
    AlgorithmVersion, BaselineContractId, BaselineRevision, BaselineStateSequence,
    ConditioningVersion, DecoderVersion, DeploymentId, LinkProfileKey, RadioLinkId, SensorId,
    SessionId, SnapshotId, SpaceId, StreamId, StreamKey, WindowId,
};
use crate::domain::time::{HostEpoch, SessionTime, TimeInterval, TimeQuality};
use crate::domain::world::{
    BaselineCoordinate, BaselineDecision, BaselineSnapshot, BaselineStatus, CoordinateEvidence,
    DerivationReceipt, EvidenceReceipt, Knowledge, LinkBelief, LinkContribution, LinkDiagnostics,
    LinkQuality, LinkStepEvidence, ResidualSummary, SensorHealth, SpaceBelief, StableOrChanging,
    WorldSnapshot, WorldValueError,
};

fn baseline_coordinate(path: CsiPath, coordinate: CsiSampleCoordinate) -> BaselineCoordinate {
    BaselineCoordinate::try_new(path, coordinate, 2, 1.0, 0.25, 10)
        .expect("valid baseline coordinate")
}

fn profile(seed: u8) -> CaptureProfileId {
    CaptureProfileId::from_bytes([seed; 32])
}

fn evidence_receipt(
    first_record_seq: u64,
    last_record_seq: u64,
    baseline_revision: Option<BaselineRevision>,
    scored: Option<BaselineStateSequence>,
    resulting: Option<BaselineStateSequence>,
) -> Result<EvidenceReceipt, WorldValueError> {
    EvidenceReceipt::try_new(
        SessionId::new("session").expect("session"),
        first_record_seq,
        last_record_seq,
        RadioLinkId::new("link").expect("link"),
        profile(1),
        ConditioningVersion::new("conditioning").expect("conditioning"),
        BaselineContractId::from_bytes([2; 32]),
        baseline_revision,
        scored,
        resulting,
        None,
        0,
        BTreeMap::new(),
    )
}

fn quality() -> LinkQuality {
    LinkQuality::try_new(1, 1.0, 0.0, 0, true, TimeQuality::ReceiveOnly, true, []).expect("quality")
}

fn coordinate_evidence(path: CsiPath, coordinate: CsiSampleCoordinate) -> CoordinateEvidence {
    CoordinateEvidence::try_new(path, coordinate, Some(1.0), None, None, None, None)
        .expect("coordinate evidence")
}

#[test]
fn baseline_snapshot_exposes_its_full_compatibility_identity() {
    let deployment = DeploymentId::new("deployment").expect("deployment");
    let space = SpaceId::new("space").expect("space");
    let key = LinkProfileKey::new(
        RadioLinkId::new("link").expect("link"),
        CaptureProfileId::from_bytes([7; 32]),
    );
    let conditioning = ConditioningVersion::new("conditioning-v1").expect("conditioning");
    let snapshot = BaselineSnapshot::try_new(
        deployment.clone(),
        space.clone(),
        key.clone(),
        conditioning.clone(),
        BaselineRevision::new(3),
        BaselineContractId::from_bytes([8; 32]),
        vec![baseline_coordinate(
            CsiPath::RawPathOrdinal(0),
            CsiSampleCoordinate::OpaqueSampleOrdinal(0),
        )],
    )
    .expect("baseline snapshot");

    assert_eq!(snapshot.deployment(), &deployment);
    assert_eq!(snapshot.space(), &space);
    assert_eq!(snapshot.key(), &key);
    assert_eq!(snapshot.conditioning_version(), &conditioning);
}

#[test]
fn baseline_snapshot_rejects_empty_and_duplicate_coordinates() {
    let deployment = DeploymentId::new("deployment").expect("deployment");
    let space = SpaceId::new("space").expect("space");
    let key = LinkProfileKey::new(
        RadioLinkId::new("link").expect("link"),
        CaptureProfileId::from_bytes([7; 32]),
    );
    let conditioning = ConditioningVersion::new("conditioning-v1").expect("conditioning");
    let coordinate = baseline_coordinate(
        CsiPath::RawPathOrdinal(0),
        CsiSampleCoordinate::OpaqueSampleOrdinal(0),
    );
    let make_snapshot = |coordinates| {
        BaselineSnapshot::try_new(
            deployment.clone(),
            space.clone(),
            key.clone(),
            conditioning.clone(),
            BaselineRevision::new(1),
            BaselineContractId::from_bytes([9; 32]),
            coordinates,
        )
    };

    assert!(matches!(
        make_snapshot(Vec::<BaselineCoordinate>::new()),
        Err(WorldValueError::EmptyBaselineSnapshot)
    ));
    assert!(matches!(
        make_snapshot(vec![coordinate.clone(), coordinate]),
        Err(WorldValueError::UnorderedCoordinates)
    ));
}

#[test]
fn stable_value_constructors_reject_non_finite_or_out_of_range_values() {
    assert!(matches!(
        BaselineCoordinate::try_new(
            CsiPath::RawPathOrdinal(0),
            CsiSampleCoordinate::OpaqueSampleOrdinal(0),
            1,
            f64::NAN,
            0.0,
            1,
        ),
        Err(WorldValueError::NonFiniteStatistic { .. })
    ));
    assert!(matches!(
        BaselineCoordinate::try_new(
            CsiPath::RawPathOrdinal(0),
            CsiSampleCoordinate::OpaqueSampleOrdinal(0),
            1,
            0.0,
            -1.0,
            1,
        ),
        Err(WorldValueError::NegativeVariance { .. })
    ));
    assert!(matches!(
        ResidualSummary::try_new(1, f64::NAN, 0.0),
        Err(WorldValueError::InvalidResidual { .. })
    ));
    assert!(matches!(
        LinkQuality::try_new(1, 1.1, 0.0, 0, true, TimeQuality::ReceiveOnly, true, []),
        Err(WorldValueError::InvalidFraction { .. })
    ));
}

#[test]
fn coordinate_evidence_rejects_non_finite_optional_values() {
    let invalid_values = [
        (Some(f64::NAN), None, None, None),
        (None, Some(f64::INFINITY), None, None),
        (None, None, Some(f64::NEG_INFINITY), None),
        (None, None, None, Some(f64::NAN)),
    ];
    for (observed, predicted, signed_residual, standardized) in invalid_values {
        assert!(matches!(
            CoordinateEvidence::try_new(
                CsiPath::RawPathOrdinal(0),
                CsiSampleCoordinate::OpaqueSampleOrdinal(0),
                observed,
                predicted,
                signed_residual,
                standardized,
                None,
            ),
            Err(WorldValueError::NonFiniteEvidence { .. })
        ));
    }
}

#[test]
fn evidence_receipt_rejects_record_and_baseline_sequence_invariants() {
    assert!(matches!(
        evidence_receipt(2, 1, None, None, None),
        Err(WorldValueError::InvalidEvidenceReceiptOrder)
    ));
    assert!(matches!(
        evidence_receipt(1, 1, None, Some(BaselineStateSequence::new(1)), None,),
        Err(WorldValueError::BaselineSequenceRequiresRevision)
    ));
    assert!(matches!(
        evidence_receipt(
            1,
            1,
            Some(BaselineRevision::new(1)),
            None,
            Some(BaselineStateSequence::new(1)),
        ),
        Err(WorldValueError::ResultingSequenceRequiresScored)
    ));
    assert!(matches!(
        evidence_receipt(
            1,
            1,
            Some(BaselineRevision::new(1)),
            Some(BaselineStateSequence::new(2)),
            Some(BaselineStateSequence::new(1)),
        ),
        Err(WorldValueError::BaselineSequenceReversed { .. })
    ));
}

#[test]
fn link_diagnostics_reject_non_finite_and_negative_scores() {
    let summary = ResidualSummary::try_new(1, 0.0, 0.0).expect("summary");
    assert!(matches!(
        LinkDiagnostics::try_new(f64::NAN, 0.0, summary),
        Err(WorldValueError::InvalidDiagnostic { .. })
    ));
    assert!(matches!(
        LinkDiagnostics::try_new(0.0, -1.0, summary),
        Err(WorldValueError::InvalidDiagnostic { .. })
    ));
}

#[test]
fn link_step_evidence_rejects_identity_coordinates_and_sequence_mismatches() {
    let link = RadioLinkId::new("link").expect("link");
    let other_link = RadioLinkId::new("other-link").expect("other link");
    let profile_id = profile(1);
    let link_profile = LinkProfileKey::new(link.clone(), profile_id);
    let stream = StreamId::new(
        StreamKey::new(SensorId::new("sensor").expect("sensor"), link.clone(), profile_id),
        HostEpoch::new(0),
    );
    let base = |stream, link_profile, coordinates, scored, resulting| {
        LinkStepEvidence::try_new(
            stream,
            link_profile,
            BaselineContractId::from_bytes([2; 32]),
            Some(BaselineRevision::new(1)),
            scored,
            resulting,
            BaselineDecision::BootstrapAccepted,
            Knowledge::known(StableOrChanging::Stable),
            quality(),
            coordinates,
        )
    };

    let mismatched_stream = StreamId::new(
        StreamKey::new(SensorId::new("sensor").expect("sensor"), other_link, profile_id),
        HostEpoch::new(0),
    );
    assert!(matches!(
        base(mismatched_stream, link_profile.clone(), Vec::new(), None, None),
        Err(WorldValueError::StreamLinkProfileMismatch)
    ));

    let duplicate = coordinate_evidence(
        CsiPath::RawPathOrdinal(0),
        CsiSampleCoordinate::OpaqueSampleOrdinal(0),
    );
    assert!(matches!(
        base(stream.clone(), link_profile.clone(), vec![duplicate.clone(), duplicate], None, None,),
        Err(WorldValueError::UnorderedEvidenceCoordinates)
    ));
    assert!(matches!(
        base(
            stream,
            link_profile,
            Vec::new(),
            Some(BaselineStateSequence::new(2)),
            Some(BaselineStateSequence::new(1)),
        ),
        Err(WorldValueError::BaselineSequenceReversed { .. })
    ));
}

#[test]
fn link_and_space_contributions_reject_empty_or_unordered_collections() {
    let link = RadioLinkId::new("link").expect("link");
    let status = Knowledge::known(StableOrChanging::Stable);
    assert!(matches!(
        LinkContribution::try_new(link.clone(), Vec::<CaptureProfileId>::new(), status.clone(), []),
        Err(WorldValueError::EmptyProfiles)
    ));
    assert!(matches!(
        LinkContribution::try_new(link.clone(), vec![profile(2), profile(1)], status.clone(), []),
        Err(WorldValueError::UnorderedProfiles)
    ));

    let first = LinkContribution::try_new(link.clone(), vec![profile(1)], status.clone(), [])
        .expect("first contribution");
    let duplicate = LinkContribution::try_new(link, vec![profile(2)], status.clone(), [])
        .expect("duplicate contribution");
    assert!(matches!(
        SpaceBelief::try_new(status, vec![first, duplicate]),
        Err(WorldValueError::UnorderedContributions)
    ));
}

#[test]
fn sensor_health_and_link_belief_combine_validated_values() {
    let health = SensorHealth::new(true, TimeQuality::ReceiveOnly, 0);
    assert_eq!(health, SensorHealth::new(true, TimeQuality::ReceiveOnly, 0));
    let evidence = evidence_receipt(1, 1, None, None, None).expect("evidence");
    let belief = LinkBelief::new(
        Knowledge::known(StableOrChanging::Stable),
        None,
        quality(),
        BaselineStatus::Missing,
        evidence,
    );
    assert_eq!(
        belief,
        LinkBelief::new(
            Knowledge::known(StableOrChanging::Stable),
            None,
            quality(),
            BaselineStatus::Missing,
            evidence_receipt(1, 1, None, None, None).expect("evidence"),
        )
    );
}

#[test]
fn receipt_and_world_snapshot_reject_inconsistent_record_or_identity_bounds() {
    let session = SessionId::new("session").expect("session");
    assert!(matches!(
        DerivationReceipt::try_new(
            session.clone(),
            2,
            1,
            1,
            [0; 32],
            [0; 32],
            DecoderVersion::new("decoder").expect("decoder"),
            ConditioningVersion::new("conditioning").expect("conditioning"),
            AlgorithmVersion::new("algorithm").expect("algorithm"),
        ),
        Err(WorldValueError::InvalidReceiptOrder)
    ));

    let receipt = DerivationReceipt::try_new(
        session.clone(),
        1,
        1,
        1,
        [0; 32],
        [0; 32],
        DecoderVersion::new("decoder").expect("decoder"),
        ConditioningVersion::new("conditioning").expect("conditioning"),
        AlgorithmVersion::new("algorithm").expect("algorithm"),
    )
    .expect("receipt");
    let window = WindowId::new(1);
    let wrong_id = SnapshotId::new(SessionId::new("other").expect("other session"), window);
    let interval = TimeInterval::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(1))
        .expect("interval");
    assert!(matches!(
        WorldSnapshot::try_new(
            wrong_id,
            None,
            DeploymentId::new("deployment").expect("deployment"),
            window,
            interval,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            receipt,
        ),
        Err(WorldValueError::InvalidSnapshotIdentity)
    ));

    for previous_id in [
        SnapshotId::new(SessionId::new("other").expect("other session"), WindowId::new(0)),
        SnapshotId::new(session.clone(), WindowId::new(2)),
    ] {
        let receipt = DerivationReceipt::try_new(
            session.clone(),
            1,
            1,
            1,
            [0; 32],
            [0; 32],
            DecoderVersion::new("decoder").expect("decoder"),
            ConditioningVersion::new("conditioning").expect("conditioning"),
            AlgorithmVersion::new("algorithm").expect("algorithm"),
        )
        .expect("receipt");
        assert!(matches!(
            WorldSnapshot::try_new(
                SnapshotId::new(session.clone(), window),
                Some(previous_id),
                DeploymentId::new("deployment").expect("deployment"),
                window,
                interval,
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                receipt,
            ),
            Err(WorldValueError::InvalidPreviousSnapshotIdentity)
        ));
    }
}
