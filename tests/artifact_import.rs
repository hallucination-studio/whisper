//! Spatial artifact import, persistence, query, and export behavior.

use std::fs;
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use whisper::artifact::{
    ArrayCondition, ArrayElementGeometry, Artifact, ArtifactDigest, ArtifactKind, ArtifactLimits,
    ArtifactMetadata, ArtifactOrigin, ArtifactRejectReason, CalibrationBundle, CalibrationEpoch,
    CoherenceScope, CoordinateTransform, CoverageCell, DepthQuality, DeviceArrayGeometry,
    GeometryElement, GeometryKind, JointLabel, LabelScope, MetersPerSecond, PersonLabel,
    PhaseRelation, PhoneTimeRelation, RfTimeRelation, SceneSnapshot, SealedArtifact,
    SignalDirection, SignalPathCondition, SourceIdentity, SupervisionSample, SupervisionSegment,
    TrackingQuality,
};
use whisper::companion::{
    ClientEphemeralSecret, ClientNonce, ClockSampleChallenge, ClockSampleResponse,
    CompanionConnection, CompanionEntropy, CompanionHandshakeRequest, CompanionHandshakeResponse,
    CompanionRejectReason, CompanionServerIdentity, PairingInvitation, UploadId, UploadProgress,
};
use whisper::native_csi::{
    CapabilityIdentity, ChannelPolicy, FirmwareBuildIdentity, RadioRxS3, S3BandwidthKind,
    S3PhyKind, S3SecondaryKind, SourceMac,
};
use whisper::{
    AdmissionLimits, AuthenticatedBytesPerSecond, DatagramBytes, DecodedRoute, DecodedRouteLink,
    DeploymentId, DeviceId, Host, KeyEpoch, NativeFrameRoute, PacketsPerSecond, RadioRouteFacts,
    ReplayWindowPackets, SensorId, Store,
};

const KEY: [u8; 32] = [7; 32];

#[derive(Debug)]
struct FailingEntropy;

impl CompanionEntropy for FailingEntropy {
    fn fill(&self, _output: &mut [u8]) -> std::io::Result<()> {
        Err(std::io::Error::other("injected entropy failure"))
    }
}

#[test]
fn scene_sealed_bytes_round_trip_without_losing_geometry_or_uncertainty() {
    let scene = SceneSnapshot {
        metadata: metadata("room-a", 3),
        world_coordinate_system: "arkit-world-42".into(),
        geometry: vec![GeometryElement {
            kind: GeometryKind::Door,
            vertices_m: vec![[1.0, 0.0, 0.0], [1.0, 2.1, 0.0]],
        }],
        geometry_validity_mask: vec![true],
        coverage_mask: vec![CoverageCell { position_m: [1.0, 1.0, 0.0], covered: true }],
        scan_coverage: 0.96,
        map_error_m: 0.12,
        usdz_display_reference: Some("room-a.usdz#sha256=0123".into()),
    };

    let sealed = SealedArtifact::seal(Artifact::Scene(scene.clone())).unwrap();
    let second = SealedArtifact::seal(Artifact::Scene(scene.clone())).unwrap();

    assert_eq!(sealed.bytes(), second.bytes());
    assert_eq!(sealed.digest(), second.digest());
    assert_eq!(sealed.decode().unwrap(), Artifact::Scene(scene));
}

#[test]
fn companion_entropy_failure_is_reported_with_its_source() {
    use std::error::Error as _;

    let parent = temporary_directory("companion-entropy-failure");
    let root = parent.join("world-store");
    let host =
        configured_builder(&parent, Store::initialize(&root).unwrap(), ArtifactLimits::default())
            .companion_entropy(FailingEntropy)
            .start()
            .unwrap();
    let error = host.begin_companion_pairing(std::time::Duration::from_secs(1)).unwrap_err();
    assert_eq!(error.reason(), CompanionRejectReason::AuthenticationFailed);
    assert!(error.source().and_then(std::error::Error::source).is_some());
    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[cfg(unix)]
#[test]
fn companion_signing_seed_is_owner_only_and_redacted() {
    let parent = temporary_directory("companion-signing-seed");
    let root = parent.join("world-store");
    let store = Store::initialize(&root).unwrap();
    let seed_path = root.join(".whisper.companion-signing-seed");
    let seed = fs::read(&seed_path).unwrap();
    assert_eq!(fs::metadata(&seed_path).unwrap().permissions().mode() & 0o7777, 0o600);
    assert!(!format!("{store:?}").contains(&format!("{seed:?}")));
    drop(store);
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Store::open(&root).is_err());
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn artifact_database_failure_retains_operation_path_and_source() {
    use std::error::Error as _;

    let parent = temporary_directory("artifact-database-context");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let database = root.join("facts.sqlite3");
    let moved = root.join("facts.sqlite3.hidden");
    fs::rename(&database, &moved).unwrap();
    let sealed = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();
    let error = host.import_artifact(sealed.bytes()).unwrap_err();
    assert!(error.to_string().contains("open artifact receipt query"));
    assert!(error.to_string().contains(database.to_str().unwrap()));
    assert!(error.source().and_then(std::error::Error::source).is_some());
    fs::rename(moved, database).unwrap();
    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn calibration_and_supervision_round_trip_with_conditions_masks_and_joint_uncertainty() {
    let scene_digest = SealedArtifact::seal(Artifact::Scene(scene())).unwrap().digest();
    let calibration_bundle = calibration(scene_digest);
    let supervision = supervision(scene_digest);

    for artifact in
        [Artifact::Calibration(Box::new(calibration_bundle)), Artifact::Supervision(supervision)]
    {
        let sealed = SealedArtifact::seal(artifact.clone()).unwrap();
        assert_eq!(sealed.decode().unwrap(), artifact);
    }

    let mut invalid_geometry = calibration(scene_digest);
    invalid_geometry.array_geometry.minimum_frequency_hz =
        invalid_geometry.array_geometry.maximum_frequency_hz + 1;
    assert!(SealedArtifact::seal(Artifact::Calibration(Box::new(invalid_geometry))).is_err());

    let mut empty_geometry_frame = calibration(scene_digest);
    empty_geometry_frame.array_geometry.device_to_array.source_coordinate_system.clear();
    assert!(SealedArtifact::seal(Artifact::Calibration(Box::new(empty_geometry_frame))).is_err());

    let mut non_finite_geometry = calibration(scene_digest);
    non_finite_geometry.array_geometry.device_to_array.matrix[3] = f64::NAN;
    assert!(SealedArtifact::seal(Artifact::Calibration(Box::new(non_finite_geometry))).is_err());

    let mut overflow_singular_geometry = calibration(scene_digest);
    overflow_singular_geometry.array_geometry.device_to_array.matrix[..12].copy_from_slice(&[
        1.0e308, 1.0e308, 0.0, 0.0, 1.0e308, 1.0e308, 0.0, 0.0, 0.0, 0.0, 1.0e308, 0.0,
    ]);
    assert!(
        SealedArtifact::seal(Artifact::Calibration(Box::new(overflow_singular_geometry))).is_err()
    );
}

#[test]
fn explicit_local_import_is_immutable_queryable_and_byte_exact_on_export() {
    let parent = temporary_directory("artifact-local-import");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let server_identity = host.companion_server_identity();
    let sealed = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();

    let first = host.import_artifact(sealed.bytes()).expect("valid scene imports");
    let duplicate = host.import_artifact(sealed.bytes()).expect("exact retry is idempotent");

    assert_eq!(first, duplicate);
    assert_eq!(
        host.query_artifact(sealed.digest()).unwrap().unwrap().decode().unwrap(),
        Artifact::Scene(scene())
    );
    assert_eq!(host.export_artifact(sealed.digest()).unwrap().unwrap().as_ref(), sealed.bytes());

    host.shutdown().unwrap();
    let reopened =
        start_host_from_store(&parent, Store::open(&root).unwrap(), ArtifactLimits::default());
    assert_eq!(reopened.companion_server_identity(), server_identity);
    assert_eq!(
        reopened.export_artifact(sealed.digest()).unwrap().unwrap().as_ref(),
        sealed.bytes(),
        "artifact remains queryable after Host restart"
    );
    reopened.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn exact_committed_retry_returns_original_receipt_after_calibration_expires() {
    let parent = temporary_directory("artifact-expired-retry");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let scene = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();
    host.import_artifact(scene.bytes()).unwrap();
    let now =
        u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()).unwrap();
    let expires = now + 50_000_000;
    let mut value = calibration(scene.digest());
    value.valid_from_utc = (now - 1_000_000).into();
    value.valid_until_utc = expires.into();
    let sealed = SealedArtifact::seal(Artifact::Calibration(Box::new(value))).unwrap();
    let original = host.import_artifact(sealed.bytes()).unwrap();
    while u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()).unwrap()
        <= expires
    {
        std::hint::spin_loop();
    }
    assert_eq!(host.import_artifact(sealed.bytes()).unwrap(), original);
    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn local_import_commits_scene_calibration_and_supervision_as_separate_candidates() {
    let parent = temporary_directory("artifact-three-kinds");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let scene_sealed = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();
    host.import_artifact(scene_sealed.bytes()).unwrap();
    let calibration =
        SealedArtifact::seal(Artifact::Calibration(Box::new(calibration(scene_sealed.digest()))))
            .unwrap();
    let supervision =
        SealedArtifact::seal(Artifact::Supervision(supervision(scene_sealed.digest()))).unwrap();

    let calibration_receipt = host.import_artifact(calibration.bytes()).unwrap();
    let supervision_receipt = host.import_artifact(supervision.bytes()).unwrap();

    assert_eq!(calibration_receipt.kind(), ArtifactKind::Calibration);
    assert_eq!(supervision_receipt.kind(), ArtifactKind::Supervision);
    assert_eq!(host.query_artifact(calibration.digest()).unwrap().unwrap(), calibration);
    assert_eq!(host.query_artifact(supervision.digest()).unwrap().unwrap(), supervision);

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn invalid_incompatible_and_conflicting_artifacts_fail_closed() {
    let parent = temporary_directory("artifact-fail-closed");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let scene_sealed = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();
    host.import_artifact(scene_sealed.bytes()).unwrap();

    let mut corrupt = scene_sealed.bytes().to_vec();
    corrupt[12] ^= 1;
    assert_eq!(
        host.import_artifact(&corrupt).unwrap_err().reason(),
        ArtifactRejectReason::InvalidArtifact
    );

    let mut conflicting_scene = scene();
    conflicting_scene.scan_coverage = 0.95;
    let conflict = SealedArtifact::seal(Artifact::Scene(conflicting_scene)).unwrap();
    assert_eq!(
        host.import_artifact(conflict.bytes()).unwrap_err().reason(),
        ArtifactRejectReason::IdentityConflict
    );

    let mut unknown = calibration(scene_sealed.digest());
    unknown.rf_device_identity = "unregistered-rx".into();
    let unknown = SealedArtifact::seal(Artifact::Calibration(Box::new(unknown))).unwrap();
    assert_eq!(
        host.import_artifact(unknown.bytes()).unwrap_err().reason(),
        ArtifactRejectReason::UnknownRfIdentity
    );

    let mut expired = calibration(scene_sealed.digest());
    expired.valid_until_utc = 2_000.into();
    let expired = SealedArtifact::seal(Artifact::Calibration(Box::new(expired))).unwrap();
    assert_eq!(
        host.import_artifact(expired.bytes()).unwrap_err().reason(),
        ArtifactRejectReason::Expired
    );

    let missing_scene = SealedArtifact::seal(Artifact::Calibration(Box::new(calibration(
        SealedArtifact::seal(Artifact::Scene(SceneSnapshot {
            metadata: metadata("other", 3),
            ..scene()
        }))
        .unwrap()
        .digest(),
    ))))
    .unwrap();
    assert_eq!(
        host.import_artifact(missing_scene.bytes()).unwrap_err().reason(),
        ArtifactRejectReason::MissingScene
    );

    let mut reset_segment = supervision(scene_sealed.digest());
    let mut reset = reset_segment.samples[0].clone();
    reset.pose_time = (reset.pose_time.get() + 10).into();
    reset.rgb_time = (reset.rgb_time.get() + 10).into();
    reset.depth_time = (reset.depth_time.get() + 10).into();
    reset.tracking_epoch = (reset.tracking_epoch.get() + 1).into();
    reset.relocalized = false;
    reset_segment.samples.push(reset);
    let reset = SealedArtifact::seal(Artifact::Supervision(reset_segment)).unwrap();
    assert_eq!(
        host.import_artifact(reset.bytes()).unwrap_err().reason(),
        ArtifactRejectReason::TrackingNotRelocalized
    );

    let mut unseen_empty = supervision(scene_sealed.digest());
    unseen_empty.samples[0].person_visibility.clear();
    unseen_empty.samples[0].label = JointLabel::WholeRoomEmpty;
    assert!(
        SealedArtifact::seal(Artifact::Supervision(unseen_empty)).is_err(),
        "a locally visible region cannot encode an unseen room as empty"
    );

    let mut zero_velocity = supervision(scene_sealed.digest());
    zero_velocity.metadata.artifact_id = "zero-velocity".into();
    zero_velocity.maximum_person_velocity = MetersPerSecond::new(0.0).unwrap();
    let zero_velocity = SealedArtifact::seal(Artifact::Supervision(zero_velocity)).unwrap();
    assert_eq!(
        host.import_artifact(zero_velocity.bytes()).unwrap_err().reason(),
        ArtifactRejectReason::InvalidRelation,
    );

    let mut singular_camera = supervision(scene_sealed.digest());
    singular_camera.samples[0].camera_to_world.matrix[0] = 0.0;
    assert!(SealedArtifact::seal(Artifact::Supervision(singular_camera)).is_err());

    let mut outside_relation = supervision(scene_sealed.digest());
    outside_relation.samples[0].rgb_time = 999.into();
    outside_relation.samples[0].maximum_time_error = 2_000.into();
    assert!(SealedArtifact::seal(Artifact::Supervision(outside_relation)).is_err());

    assert_eq!(host.query_artifact(scene_sealed.digest()).unwrap().unwrap(), scene_sealed);
    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn artifact_byte_limit_rejects_before_store_write() {
    let parent = temporary_directory("artifact-size-limit");
    let root = parent.join("world-store");
    let limits = ArtifactLimits::builder().max_artifact_bytes(64).build().unwrap();
    let host = start_host_with_limits(&parent, &root, limits);
    let sealed = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();

    assert_eq!(
        host.import_artifact(sealed.bytes()).unwrap_err().reason(),
        ArtifactRejectReason::LimitExceeded
    );
    assert!(host.query_artifact(sealed.digest()).unwrap().is_none());

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn artifact_and_companion_chunk_counts_are_bounded() {
    let parent = temporary_directory("artifact-count-limit");
    let root = parent.join("world-store");
    let limits = ArtifactLimits::builder().max_artifacts(1).build().unwrap();
    let host = start_host_with_limits(&parent, &root, limits);
    let first = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();
    host.import_artifact(first.bytes()).unwrap();
    let second = SealedArtifact::seal(Artifact::Scene(SceneSnapshot {
        metadata: metadata("room-b", 3),
        ..scene()
    }))
    .unwrap();
    assert_eq!(
        host.import_artifact(second.bytes()).unwrap_err().reason(),
        ArtifactRejectReason::LimitExceeded
    );

    let offer = host.begin_companion_pairing(std::time::Duration::from_secs(30)).unwrap();
    assert!(!offer.pairing_id().as_bytes().iter().all(|byte| *byte == 0));
    assert_eq!(offer.display_code().to_string(), "[REDACTED]");
    assert_eq!(offer.display_code().format_for_display().len(), 39);
    offer.verify_server_proof(offer.server_identity()).unwrap();
    let connection = pair_companion(&host, &offer, ClientNonce::from_bytes([1; 32]));
    assert_eq!(
        connection
            .seal_upload(UploadId::from_bytes([3; 16]), &vec![0; 1_025], 1)
            .unwrap_err()
            .reason(),
        CompanionRejectReason::LimitExceeded
    );
    assert_eq!(
        connection
            .seal_upload(UploadId::from_bytes([4; 16]), &[1], 64 * 1024 + 1)
            .unwrap_err()
            .reason(),
        CompanionRejectReason::LimitExceeded
    );

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn paired_encrypted_companion_upload_resumes_and_uses_shared_candidate_import() {
    let parent = temporary_directory("artifact-companion-upload");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let offer = host.begin_companion_pairing(std::time::Duration::from_secs(30)).unwrap();
    let wrong_pin = CompanionServerIdentity::from_bytes([0; 32]);
    assert_eq!(
        host.begin_companion_clock_sample(
            offer.pairing_id(),
            wrong_pin,
            ClientNonce::from_bytes([10; 32]),
            1.into(),
        )
        .unwrap_err()
        .reason(),
        CompanionRejectReason::ServerIdentityMismatch
    );
    let connection = pair_companion(&host, &offer, ClientNonce::from_bytes([11; 32]));
    connection.verify_server_proof().unwrap();
    assert_eq!(
        host.begin_companion_clock_sample(
            offer.pairing_id(),
            offer.server_identity(),
            ClientNonce::from_bytes([12; 32]),
            1.into(),
        )
        .unwrap_err()
        .reason(),
        CompanionRejectReason::PairingUnavailable
    );

    let sealed = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();
    let chunks = connection.seal_upload(UploadId::from_bytes([9; 16]), sealed.bytes(), 64).unwrap();
    let first = host.upload_companion_bytes(chunks[0].bytes()).unwrap();
    assert!(matches!(first, UploadProgress::Pending { received_chunks: 1, .. }));
    let duplicate = host.upload_companion_bytes(chunks[0].bytes()).unwrap();
    assert_eq!(duplicate, first, "duplicate chunk is idempotent");

    let mut final_progress = None;
    for chunk in chunks.iter().skip(1) {
        final_progress = Some(host.upload_companion_bytes(chunk.bytes()).unwrap());
    }
    let UploadProgress::Imported(receipt) = final_progress.unwrap() else {
        panic!("resumed upload did not import its completed artifact");
    };
    assert_eq!(receipt.digest(), sealed.digest());
    assert_eq!(receipt.origin(), ArtifactOrigin::Companion);
    assert_eq!(host.export_artifact(sealed.digest()).unwrap().unwrap().as_ref(), sealed.bytes());
    assert_eq!(
        host.upload_companion_bytes(chunks.last().unwrap().bytes()).unwrap(),
        UploadProgress::Imported(receipt.clone()),
        "a lost final response can be recovered by retrying the authenticated final chunk",
    );

    let mut invalid_calibration = calibration(sealed.digest());
    invalid_calibration.rf_device_identity = "unknown-rx".into();
    let invalid_calibration =
        SealedArtifact::seal(Artifact::Calibration(Box::new(invalid_calibration))).unwrap();
    let invalid_chunks = connection
        .seal_upload(
            UploadId::from_bytes([10; 16]),
            invalid_calibration.bytes(),
            invalid_calibration.bytes().len(),
        )
        .unwrap();
    let error = host.upload_companion_bytes(invalid_chunks[0].bytes()).unwrap_err();
    assert_eq!(error.reason(), CompanionRejectReason::ArtifactRejected);
    assert_eq!(error.artifact_reason(), Some(ArtifactRejectReason::UnknownRfIdentity));

    let mismatched =
        SealedArtifact::seal(Artifact::Supervision(supervision(sealed.digest()))).unwrap();
    let mismatched_chunk = connection
        .seal_upload(UploadId::from_bytes([11; 16]), mismatched.bytes(), mismatched.bytes().len())
        .unwrap()
        .remove(0);
    let error = host.upload_companion_bytes(mismatched_chunk.bytes()).unwrap_err();
    assert_eq!(error.artifact_reason(), Some(ArtifactRejectReason::InvalidRelation));

    let first_content = SealedArtifact::seal(Artifact::Scene(SceneSnapshot {
        metadata: metadata("nonce-domain-a", 1),
        ..scene()
    }))
    .unwrap();
    let second_content = SealedArtifact::seal(Artifact::Scene(SceneSnapshot {
        metadata: metadata("nonce-domain-b", 1),
        ..scene()
    }))
    .unwrap();
    let reused_id = UploadId::from_bytes([12; 16]);
    let first_chunk =
        connection.seal_upload(reused_id, first_content.bytes(), 64).unwrap().remove(0);
    let conflicting_chunk =
        connection.seal_upload(reused_id, second_content.bytes(), 64).unwrap().remove(0);
    assert_ne!(
        &first_chunk.bytes()[92..],
        &conflicting_chunk.bytes()[92..],
        "reusing an upload id for different content must not reuse the AES-GCM key/nonce pair",
    );
    assert!(matches!(
        host.upload_companion_bytes(first_chunk.bytes()).unwrap(),
        UploadProgress::Pending { .. }
    ));
    assert_eq!(
        host.upload_companion_bytes(conflicting_chunk.bytes()).unwrap_err().reason(),
        CompanionRejectReason::UploadConflict,
    );

    let layout_content = vec![7_u8; 1_000];
    let layout_id = UploadId::from_bytes([13; 16]);
    let chunks_100 = connection.seal_upload(layout_id, &layout_content, 100).unwrap();
    let chunks_101 = connection.seal_upload(layout_id, &layout_content, 101).unwrap();
    assert_eq!(chunks_100.len(), chunks_101.len());
    assert_ne!(
        &chunks_100[0].bytes()[92..],
        &chunks_101[0].bytes()[92..],
        "the canonical layout must change the AES-GCM key/nonce domain",
    );
    assert!(matches!(
        host.upload_companion_bytes(chunks_100[0].bytes()).unwrap(),
        UploadProgress::Pending { .. }
    ));
    assert_eq!(
        host.upload_companion_bytes(chunks_101[0].bytes()).unwrap_err().reason(),
        CompanionRejectReason::UploadConflict,
    );

    let mut forged_layout =
        connection.seal_upload(UploadId::from_bytes([14; 16]), &layout_content, 100).unwrap()[0]
            .bytes()
            .into_vec();
    forged_layout[44..48].copy_from_slice(&101_u32.to_le_bytes());
    let forged_layout_error = host.upload_companion_bytes(&forged_layout).unwrap_err();
    assert_eq!(forged_layout_error.reason(), CompanionRejectReason::AuthenticationFailed);
    assert!(
        forged_layout_error.to_string().contains("authenticate and decrypt companion upload chunk")
    );

    let mut noncanonical_layout =
        connection.seal_upload(UploadId::from_bytes([15; 16]), &layout_content, 100).unwrap()[0]
            .bytes()
            .into_vec();
    noncanonical_layout[44..48].copy_from_slice(&99_u32.to_le_bytes());
    assert_eq!(
        host.upload_companion_bytes(&noncanonical_layout).unwrap_err().reason(),
        CompanionRejectReason::LimitExceeded,
    );

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn companion_transport_rejects_tampered_ciphertext_without_importing() {
    use std::error::Error as _;

    let parent = temporary_directory("artifact-companion-tamper");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let offer = host.begin_companion_pairing(std::time::Duration::from_secs(30)).unwrap();
    let connection = pair_companion(&host, &offer, ClientNonce::from_bytes([20; 32]));
    let sealed = SealedArtifact::seal(Artifact::Scene(scene())).unwrap();
    let chunk = connection
        .seal_upload(UploadId::from_bytes([4; 16]), sealed.bytes(), sealed.bytes().len())
        .unwrap()
        .remove(0);
    let mut tampered = chunk.bytes().into_vec();
    *tampered.last_mut().unwrap() ^= 1;

    let error = host.upload_companion_bytes(&tampered).unwrap_err();
    assert_eq!(error.reason(), CompanionRejectReason::AuthenticationFailed);
    assert!(error.to_string().contains("authenticate and decrypt companion upload chunk"));
    assert!(error.source().and_then(std::error::Error::source).is_some());
    assert!(host.query_artifact(sealed.digest()).unwrap().is_none());

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn companion_pairing_expires_and_clock_round_trip_is_bounded() {
    let parent = temporary_directory("artifact-companion-expiry");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let offer = host.begin_companion_pairing(std::time::Duration::from_secs(30)).unwrap();
    let challenge = host
        .begin_companion_clock_sample(
            offer.pairing_id(),
            offer.server_identity(),
            ClientNonce::from_bytes([30; 32]),
            1.into(),
        )
        .unwrap();
    let mut forged_host_time = challenge.to_wire().into_vec();
    forged_host_time[60] ^= 1;
    assert_eq!(
        ClockSampleChallenge::from_wire(&forged_host_time, offer.server_identity())
            .unwrap_err()
            .reason(),
        CompanionRejectReason::AuthenticationFailed
    );

    let expired = host.begin_companion_pairing(std::time::Duration::from_nanos(1)).unwrap();
    while SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        <= u128::from(expired.expires_at_utc().get())
    {
        std::hint::spin_loop();
    }
    assert_eq!(
        host.begin_companion_clock_sample(
            expired.pairing_id(),
            expired.server_identity(),
            ClientNonce::from_bytes([31; 32]),
            1.into(),
        )
        .unwrap_err()
        .reason(),
        CompanionRejectReason::PairingUnavailable
    );

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn pairing_secret_is_absent_from_wire_and_wrong_tampered_or_replayed_proofs_fail() {
    use std::error::Error as _;

    let parent = temporary_directory("companion-secret-establishment");
    let root = parent.join("world-store");
    let host = start_host(&parent, &root);
    let offer = host.begin_companion_pairing(std::time::Duration::from_secs(30)).unwrap();
    let invitation_wire = offer.to_wire();
    assert!(
        !invitation_wire.windows(16).any(|window| window == offer.display_code().expose_bytes())
    );
    let mut tampered_invitation = invitation_wire.clone().into_vec();
    tampered_invitation[60] ^= 1;
    assert_eq!(
        PairingInvitation::from_wire(&tampered_invitation, offer.server_identity())
            .unwrap_err()
            .reason(),
        CompanionRejectReason::AuthenticationFailed,
    );
    let invitation =
        PairingInvitation::from_wire(&invitation_wire, offer.server_identity()).unwrap();
    let nonce = ClientNonce::from_bytes([61; 32]);
    let responses = collect_clock_responses(&host, &invitation, nonce);

    let mut wrong_code = *offer.display_code().expose_bytes();
    wrong_code[0] ^= 1;
    let (wrong_request, _) = invitation
        .begin_handshake(
            whisper::companion::PairingCode::from_bytes(wrong_code),
            nonce,
            ClientEphemeralSecret::from_bytes([62; 32]).unwrap(),
            responses.clone(),
        )
        .unwrap();
    let wrong_code_error = host.connect_companion(wrong_request).unwrap_err();
    assert_eq!(wrong_code_error.reason(), CompanionRejectReason::AuthenticationFailed);
    assert!(wrong_code_error.to_string().contains("verify companion pairing-code proof"));
    assert!(wrong_code_error.source().and_then(std::error::Error::source).is_some());

    let (request, pending) = invitation
        .begin_handshake(
            offer.display_code().clone(),
            nonce,
            ClientEphemeralSecret::from_bytes([63; 32]).unwrap(),
            responses,
        )
        .unwrap();
    let request_wire = request.to_wire();
    let mut tampered = request_wire.clone().into_vec();
    tampered[116] ^= 1;
    assert_eq!(
        host.connect_companion(CompanionHandshakeRequest::from_wire(&tampered).unwrap())
            .unwrap_err()
            .reason(),
        CompanionRejectReason::AuthenticationFailed,
    );
    let request = CompanionHandshakeRequest::from_wire(&request_wire).unwrap();
    let replay = request.clone();
    let response = host.connect_companion(request).unwrap();
    pending.complete(CompanionHandshakeResponse::from_wire(&response.to_wire()).unwrap()).unwrap();
    assert_eq!(
        host.connect_companion(replay).unwrap_err().reason(),
        CompanionRejectReason::PairingUnavailable,
    );
    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

fn scene() -> SceneSnapshot {
    SceneSnapshot {
        metadata: metadata("room-a", 3),
        world_coordinate_system: "arkit-world-42".into(),
        geometry: vec![GeometryElement {
            kind: GeometryKind::Wall,
            vertices_m: vec![[0.0, 0.0, 0.0], [4.0, 0.0, 0.0]],
        }],
        geometry_validity_mask: vec![true],
        coverage_mask: vec![CoverageCell { position_m: [2.0, 0.0, 0.0], covered: true }],
        scan_coverage: 0.96,
        map_error_m: 0.12,
        usdz_display_reference: None,
    }
}

#[test]
fn rust_and_swift_scene_fixtures_round_trip_through_rust_wsa1_codec() {
    for (fixture, artifact_id) in [
        (include_str!("fixtures/phone-client-171/rust-scene-wsa1.hex"), "room-a"),
        (include_str!("fixtures/phone-client-171/swift-scene-wsa1.hex"), "swift-room-b"),
    ] {
        let bytes = decode_hex_fixture(fixture);
        let sealed = SealedArtifact::parse(&bytes).unwrap();
        let artifact = sealed.decode().unwrap();
        assert!(
            matches!(&artifact, Artifact::Scene(scene) if scene.metadata.artifact_id == artifact_id)
        );
        assert_eq!(SealedArtifact::seal(artifact).unwrap().bytes(), bytes.as_slice());
    }
}

fn decode_hex_fixture(hex: &str) -> Vec<u8> {
    let compact: String = hex.chars().filter(|character| !character.is_whitespace()).collect();
    assert_eq!(compact.len() % 2, 0, "fixture hex has odd length");
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("fixture high nibble");
            let low = (pair[1] as char).to_digit(16).expect("fixture low nibble");
            ((high << 4) | low) as u8
        })
        .collect()
}

fn pair_companion(
    host: &whisper::HostRuntime,
    displayed_offer: &whisper::companion::PairingOffer,
    nonce: ClientNonce,
) -> CompanionConnection {
    let invitation =
        PairingInvitation::from_wire(&displayed_offer.to_wire(), displayed_offer.server_identity())
            .unwrap();
    let responses = collect_clock_responses(host, &invitation, nonce);
    let (request, pending) = invitation
        .begin_handshake(
            displayed_offer.display_code().clone(),
            nonce,
            ClientEphemeralSecret::from_bytes([42; 32]).unwrap(),
            responses.clone(),
        )
        .unwrap();
    let (_, forged_pending) = invitation
        .begin_handshake(
            displayed_offer.display_code().clone(),
            nonce,
            ClientEphemeralSecret::from_bytes([42; 32]).unwrap(),
            responses,
        )
        .unwrap();
    let request = CompanionHandshakeRequest::from_wire(&request.to_wire()).unwrap();
    let response = host.connect_companion(request).unwrap();
    let response_wire = response.to_wire();
    let mut forged_valid_from = response_wire.clone().into_vec();
    forged_valid_from[68] ^= 1;
    let forged = CompanionHandshakeResponse::from_wire(&forged_valid_from).unwrap();
    assert_eq!(
        forged_pending.complete(forged).unwrap_err().reason(),
        CompanionRejectReason::AuthenticationFailed,
    );
    let response = CompanionHandshakeResponse::from_wire(&response_wire).unwrap();
    pending.complete(response).unwrap()
}

fn collect_clock_responses(
    host: &whisper::HostRuntime,
    invitation: &PairingInvitation,
    nonce: ClientNonce,
) -> Vec<ClockSampleResponse> {
    let phone_origin = std::time::Instant::now();
    let phone_base = 1_000_000_000_u64;
    let mut responses = Vec::new();
    for sample in 0..3 {
        if sample != 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let client_send = phone_base + u64::try_from(phone_origin.elapsed().as_nanos()).unwrap();
        let challenge = host
            .begin_companion_clock_sample(
                invitation.pairing_id(),
                invitation.server_identity(),
                nonce,
                client_send.into(),
            )
            .unwrap();
        let challenge =
            ClockSampleChallenge::from_wire(&challenge.to_wire(), invitation.server_identity())
                .unwrap();
        let client_receive = phone_base + u64::try_from(phone_origin.elapsed().as_nanos()).unwrap();
        let response = ClockSampleResponse::new(challenge, client_receive.into());
        responses.push(
            ClockSampleResponse::from_wire(&response.to_wire(), invitation.server_identity())
                .unwrap(),
        );
    }
    responses
}

fn calibration(scene_digest: ArtifactDigest) -> CalibrationBundle {
    CalibrationBundle {
        metadata: metadata("calibration-a", 2),
        scene_digest,
        rf_device_identity: "rx-array-1".into(),
        antenna_reference: "fiducial-11-to-array-origin".into(),
        world_transform: CoordinateTransform {
            source_coordinate_system: "array-1".into(),
            target_coordinate_system: "arkit-world-42".into(),
            matrix: [
                1.0, 0.0, 0.0, 2.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.5, 0.0, 0.0, 0.0, 1.0,
            ],
            max_error_m: 0.08,
        },
        signal_paths: vec![SignalPathCondition {
            logical_path: "rx-stream-0".into(),
            direction: SignalDirection::Receive,
            device_chain: "rx-chain-0".into(),
            antenna_identity: "element-0".into(),
        }],
        array_condition: ArrayCondition {
            array_identity: "array-1".into(),
            physical_element_count: 1,
        },
        array_geometry: DeviceArrayGeometry {
            source: SourceIdentity {
                namespace: "rf-metrology".into(),
                identity: "geometry-run-3".into(),
            },
            applicability: "rx-array-1 5.15-5.85 GHz factory configuration".into(),
            minimum_frequency_hz: 5_150_000_000,
            maximum_frequency_hz: 5_850_000_000,
            device_to_array: CoordinateTransform {
                source_coordinate_system: "rx-device-1".into(),
                target_coordinate_system: "array-1".into(),
                matrix: [
                    1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
                ],
                max_error_m: 0.01,
            },
            elements: vec![ArrayElementGeometry {
                antenna_identity: "element-0".into(),
                position_m: [0.0, 0.0, 0.0],
            }],
            maximum_position_error_m: 0.005,
            valid_from_utc: 1_000.into(),
            valid_until_utc: 9_000_000_000_000_000_000.into(),
            epoch: CalibrationEpoch::new(3),
        },
        phase_relation: PhaseRelation {
            source: SourceIdentity {
                namespace: "rf-calibrator".into(),
                identity: "phase-run-9".into(),
            },
            scope: CoherenceScope::Packet,
            maximum_error_radians: 0.05,
            valid_from_utc: 1_000.into(),
            valid_until_utc: 9_000_000_000_000_000_000.into(),
            epoch: CalibrationEpoch::new(9),
        },
        time_relation: RfTimeRelation {
            source: SourceIdentity {
                namespace: "rf-calibrator".into(),
                identity: "time-run-4".into(),
            },
            offset: 12_i64.into(),
            maximum_error: 20_u64.into(),
            valid_from_utc: 1_000.into(),
            valid_until_utc: 9_000_000_000_000_000_000.into(),
            epoch: CalibrationEpoch::new(4),
        },
        max_error_m: 0.14,
        valid_from_utc: 1_000.into(),
        valid_until_utc: 9_000_000_000_000_000_000.into(),
    }
}

fn supervision(scene_digest: ArtifactDigest) -> SupervisionSegment {
    SupervisionSegment {
        metadata: metadata("labels-a", 4),
        scene_digest,
        camera_intrinsics: [800.0, 0.0, 320.0, 0.0, 800.0, 240.0, 0.0, 0.0, 1.0],
        samples: vec![SupervisionSample {
            rgb_reference: "rgb:2000".into(),
            depth_reference: Some("depth:2002".into()),
            pose_reference: "pose:2001".into(),
            rgb_time: 2_000.into(),
            depth_time: 2_002.into(),
            pose_time: 2_001.into(),
            maximum_time_error: 5.into(),
            tracking_epoch: 7.into(),
            relocalized: true,
            tracking_quality: TrackingQuality::Normal,
            depth_quality: DepthQuality::Measured,
            scope: LabelScope::LocallyVisible,
            person_visibility: vec![0.9],
            label: JointLabel::VisibleSet(vec![PersonLabel {
                station: "station-3".into(),
                pose: "standing".into(),
                position_m: [1.2, 0.0, 2.0],
                max_error_m: 0.16,
            }]),
            camera_to_world: CoordinateTransform {
                source_coordinate_system: "camera".into(),
                target_coordinate_system: "arkit-world-42".into(),
                matrix: [
                    1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
                ],
                max_error_m: 0.02,
            },
            sample_source: SourceIdentity {
                namespace: "phone-frame".into(),
                identity: "frame-2001".into(),
            },
            joint_error_m: 0.04,
        }],
        shared_position_error_m: 0.1,
        time_relation: PhoneTimeRelation::new(
            [1; 16],
            10_i64.into(),
            0,
            2_001.into(),
            10_u64.into(),
            1_000.into(),
            3_000.into(),
        )
        .unwrap(),
        maximum_person_velocity: MetersPerSecond::new(12.0).unwrap(),
    }
}

fn metadata(artifact_id: &str, revision: u32) -> ArtifactMetadata {
    ArtifactMetadata { artifact_id: artifact_id.into(), revision, provenance: sources() }
}

fn sources() -> Vec<SourceIdentity> {
    vec![SourceIdentity { namespace: "phone-capture".into(), identity: "capture-7".into() }]
}

fn start_host(parent: &std::path::Path, root: &std::path::Path) -> whisper::HostRuntime {
    start_host_with_limits(parent, root, ArtifactLimits::default())
}

fn start_host_with_limits(
    parent: &std::path::Path,
    root: &std::path::Path,
    artifact_limits: ArtifactLimits,
) -> whisper::HostRuntime {
    start_host_from_store(parent, Store::initialize(root).unwrap(), artifact_limits)
}

fn start_host_from_store(
    parent: &std::path::Path,
    store: Store,
    artifact_limits: ArtifactLimits,
) -> whisper::HostRuntime {
    configured_builder(parent, store, artifact_limits).start().unwrap()
}

fn configured_builder(
    parent: &std::path::Path,
    store: Store,
    artifact_limits: ArtifactLimits,
) -> whisper::HostBuilder {
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let secret_root = parent.join("secrets");
    let device_root = secret_root.join("device-1");
    fs::create_dir_all(&device_root).unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&device_root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key_path = device_root.join("key-1.bin");
    fs::write(&key_path, KEY).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    let limits = AdmissionLimits::new(
        DatagramBytes::try_from(753).unwrap(),
        PacketsPerSecond::try_from(10).unwrap(),
        AuthenticatedBytesPerSecond::try_from(10_000).unwrap(),
        ReplayWindowPackets::try_from(64).unwrap(),
    );
    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        DeviceId::new(1),
        KeyEpoch::new(1).unwrap(),
        limits,
        DecodedRoute::new(
            SensorId::try_from("artifact-test-sensor").unwrap(),
            DecodedRouteLink::new(
                SourceMac::try_from([2, 0, 0, 0, 0, 10]).unwrap(),
                ChannelPolicy::try_from(1).unwrap(),
                RadioRouteFacts::from_radio(
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
                    .unwrap(),
                ),
            ),
            FirmwareBuildIdentity::from([0x11; 32]),
            CapabilityIdentity::from([0x22; 32]),
        ),
        &secret_root,
    )
    .unwrap();
    Host::builder(store, DeploymentId::try_from("lab").unwrap(), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .artifact_limits(artifact_limits)
        .known_rf_identity("rx-array-1")
}

fn temporary_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("whisper-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}
