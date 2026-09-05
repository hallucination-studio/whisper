//! Production UDP admission through raw fact A and the restricted local query.

use std::fs;
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use whisper::measurement::{
    AssemblyCapacity, AssemblyCloseReason, AssemblyKey, AssemblyLimits, ChannelIdentity,
    ErrorBound, ErrorUnit, EventIdentity, EvidenceQuality, FitIdentity, FragmentBytes,
    FragmentFact, FragmentPosition, MeasurementContext, MeasurementFragment, NativeEventIdentity,
    PhaseReferenceIdentity, PhaseRelation, PortMapEntry, PortMapping, Pose, ProfileIdentity,
    QualificationEpoch, QualificationRelation, RadioIdentity, RelationValidity, SourceInstance,
    SourceTick, TickRange, TimeRelation, TransmitterIdentity, WaitTicks,
};
use whisper::native_csi::{
    CapabilityIdentity, ChannelPolicy, CsiPath, FirmwareBuildIdentity, NativeFact, RadioRxS3,
    S3BandwidthKind, S3PhyKind, S3SecondaryKind, SampleAxis, SourceMac,
};
use whisper::{
    AdmissionLimits, AuthenticatedBytesPerSecond, BootGeneration, DatagramBytes, DecodedRoute,
    DecodedRouteLink, DeploymentId, DeviceId, Host, KeyEpoch, MessageSequence, NativeFrameKind,
    NativeFrameRoute, PacketsPerSecond, RadioRouteFacts, RawLossKind, RejectReason,
    ReplayWindowPackets, SensorId, Store,
};

const KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const DEVICE_ID: u64 = 0x0102_0304_0506_0708;
const KEY_EPOCH: u16 = 7;
const SOURCE_MAC: [u8; 6] = [2, 0, 0, 0, 0, 10];
const CAPABILITY_DIGEST: [u8; 32] = [
    0x34, 0x93, 0x9e, 0x35, 0xea, 0xbe, 0x30, 0x4c, 0xa5, 0x66, 0x14, 0x4f, 0x25, 0x8c, 0x1e, 0x52,
    0x2c, 0x88, 0x7f, 0x1e, 0xc5, 0x39, 0x5e, 0xdb, 0xbc, 0x22, 0x68, 0xe1, 0xfc, 0x54, 0x08, 0x43,
];

#[test]
fn native_csi_closes_one_persisted_measurement_and_relations_round_trip() {
    let parent = temporary_directory("host-measurement-close");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host =
        start_host(Store::initialize(parent.join("world-store")).unwrap(), &sender, &secret_root);
    sender
        .send_to(
            &hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex")),
            host.local_addr(),
        )
        .unwrap();
    sender
        .send_to(
            &hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex")),
            host.local_addr(),
        )
        .unwrap();
    wait_for_fact_count(&host, 2);

    let closes = host.query_measurement_closes(4).unwrap();
    assert_eq!(closes.len(), 1);
    assert_eq!(closes[0].reason(), AssemblyCloseReason::Complete);
    assert_eq!(closes[0].members().len(), 1);
    assert_eq!(
        closes[0].members()[0].fact_digest(),
        *host.query_native_csi(1).unwrap()[0].provenance().provenance_digest()
    );

    let relation_source = SourceInstance::new(
        SensorId::try_from("hall-west").unwrap(),
        DeviceId::new(DEVICE_ID),
        KeyEpoch::new(KEY_EPOCH).unwrap(),
        BootGeneration::new(1).unwrap(),
    );
    let validity = |unit| {
        RelationValidity::new(
            "survey-7",
            relation_source.clone(),
            ErrorBound::new(30, unit),
            TickRange::new(SourceTick::new(40), SourceTick::new(50)).unwrap(),
            QualificationEpoch::new(6),
        )
        .unwrap()
    };
    let relations = vec![
        QualificationRelation::Time(
            TimeRelation::new(
                validity(ErrorUnit::Nanoseconds),
                "esp-timer",
                "host-monotonic",
                FitIdentity::new([7; 32]),
            )
            .unwrap(),
        ),
        QualificationRelation::Phase(
            PhaseRelation::new(
                validity(ErrorUnit::Milliradians),
                PhaseReferenceIdentity::new([8; 32]),
                TickRange::new(SourceTick::new(42), SourceTick::new(48)).unwrap(),
            )
            .unwrap(),
        ),
        QualificationRelation::Port(
            PortMapping::new(
                validity(ErrorUnit::PartsPerMillion),
                [PortMapEntry::new(0, 1, Some(2), 3)],
            )
            .unwrap(),
        ),
        QualificationRelation::Geometry(
            whisper::measurement::Geometry::new(
                validity(ErrorUnit::Millimetres),
                "sensor-frame",
                "room-frame",
                Pose::new([1, 2, 3, 0, 0, 0, 1_000_000]),
            )
            .unwrap(),
        ),
    ];
    for relation in &relations {
        host.persist_qualification(relation.clone()).unwrap();
    }
    let persisted = host.query_qualifications(4).unwrap();
    assert_eq!(persisted, relations);

    host.shutdown().unwrap();
    let reopened =
        start_host(Store::open(parent.join("world-store")).unwrap(), &sender, &secret_root);
    assert_eq!(reopened.query_measurement_closes(4).unwrap().len(), 1);
    assert_eq!(reopened.query_qualifications(4).unwrap(), relations);
    reopened.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn heterogeneous_partial_assembly_survives_restart_and_late_data_cannot_reopen_it() {
    let parent = temporary_directory("host-general-measurement");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let store_root = parent.join("world-store");
    let source = SourceInstance::new(
        SensorId::try_from("heterogeneous-rx").unwrap(),
        DeviceId::new(91),
        KeyEpoch::new(3).unwrap(),
        BootGeneration::new(8).unwrap(),
    );
    let key = AssemblyKey::new(
        source.clone(),
        EventIdentity::new(
            TransmitterIdentity::new([1; 32]),
            NativeEventIdentity::new([2; 32]),
            None,
        ),
        MeasurementContext::new(
            ProfileIdentity::new([3; 32]),
            RadioIdentity::new([4; 32]),
            ChannelIdentity::new([5; 32]),
        ),
    );
    let make_fragment = |ordinal, digest| {
        MeasurementFragment::new(
            key.clone(),
            FragmentPosition::new(ordinal, 2).unwrap(),
            FragmentFact::new(
                [digest; 32],
                FragmentBytes::new(11).unwrap(),
                EvidenceQuality::Captured,
            ),
        )
    };

    let host = start_host(Store::initialize(&store_root).unwrap(), &sender, &secret_root);
    assert!(
        host.persist_measurement_fragment(make_fragment(1, 8), SourceTick::new(10))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        host.persist_measurement_fragment(make_fragment(1, 8), SourceTick::new(11)).unwrap()[0]
            .reason(),
        AssemblyCloseReason::DuplicateFragment,
    );
    host.shutdown().unwrap();

    let reopened = start_host(Store::open(&store_root).unwrap(), &sender, &secret_root);
    let completed =
        reopened.persist_measurement_fragment(make_fragment(0, 7), SourceTick::new(12)).unwrap();
    assert_eq!(completed[0].reason(), AssemblyCloseReason::Complete);
    assert_eq!(
        completed[0].members().iter().map(|member| member.ordinal()).collect::<Vec<_>>(),
        [0, 1]
    );
    reopened.shutdown().unwrap();

    let reopened = start_host(Store::open(&store_root).unwrap(), &sender, &secret_root);
    let late =
        reopened.persist_measurement_fragment(make_fragment(0, 9), SourceTick::new(13)).unwrap();
    assert_eq!(late[0].reason(), AssemblyCloseReason::LateFragment);
    let closes = reopened.query_measurement_closes(8).unwrap();
    let complete =
        closes.iter().find(|close| close.reason() == AssemblyCloseReason::Complete).unwrap();
    assert_eq!(
        complete.members().iter().map(|member| member.fact_digest()).collect::<Vec<_>>(),
        [[7; 32], [8; 32]]
    );
    let timeout_key = AssemblyKey::new(
        source.clone(),
        EventIdentity::new(
            TransmitterIdentity::new([1; 32]),
            NativeEventIdentity::new([6; 32]),
            None,
        ),
        MeasurementContext::new(
            ProfileIdentity::new([3; 32]),
            RadioIdentity::new([4; 32]),
            ChannelIdentity::new([5; 32]),
        ),
    );
    reopened
        .persist_measurement_fragment(
            MeasurementFragment::new(
                timeout_key,
                FragmentPosition::new(0, 2).unwrap(),
                FragmentFact::new(
                    [6; 32],
                    FragmentBytes::new(10).unwrap(),
                    EvidenceQuality::Captured,
                ),
            ),
            SourceTick::new(1),
        )
        .unwrap();
    let expired = reopened.expire_measurements(source.clone(), SourceTick::new(1_000_001)).unwrap();
    assert_eq!(expired[0].reason(), AssemblyCloseReason::WaitLimit);
    assert_eq!(expired[0].missing_ordinals(), [1]);
    let key_for_event = |event| {
        AssemblyKey::new(
            source.clone(),
            EventIdentity::new(
                TransmitterIdentity::new([1; 32]),
                NativeEventIdentity::new([event; 32]),
                None,
            ),
            MeasurementContext::new(
                ProfileIdentity::new([3; 32]),
                RadioIdentity::new([4; 32]),
                ChannelIdentity::new([5; 32]),
            ),
        )
    };
    let count = reopened
        .persist_measurement_fragment(
            MeasurementFragment::new(
                key_for_event(7),
                FragmentPosition::new(0, 1_025).unwrap(),
                FragmentFact::new(
                    [7; 32],
                    FragmentBytes::new(1).unwrap(),
                    EvidenceQuality::Captured,
                ),
            ),
            SourceTick::new(2),
        )
        .unwrap();
    assert_eq!(count[0].reason(), AssemblyCloseReason::CountLimit);
    let large = FragmentBytes::new(9 * 1024 * 1024).unwrap();
    assert!(
        reopened
            .persist_measurement_fragment(
                MeasurementFragment::new(
                    key_for_event(8),
                    FragmentPosition::new(0, 2).unwrap(),
                    FragmentFact::new([8; 32], large, EvidenceQuality::Captured),
                ),
                SourceTick::new(2),
            )
            .unwrap()
            .is_empty()
    );
    let bytes = reopened
        .persist_measurement_fragment(
            MeasurementFragment::new(
                key_for_event(8),
                FragmentPosition::new(1, 2).unwrap(),
                FragmentFact::new([9; 32], large, EvidenceQuality::Captured),
            ),
            SourceTick::new(3),
        )
        .unwrap();
    assert_eq!(bytes[0].reason(), AssemblyCloseReason::ByteLimit);
    reopened
        .persist_measurement_fragment(
            MeasurementFragment::new(
                key_for_event(9),
                FragmentPosition::new(0, 2).unwrap(),
                FragmentFact::new(
                    [10; 32],
                    FragmentBytes::new(1).unwrap(),
                    EvidenceQuality::Captured,
                ),
            ),
            SourceTick::new(4),
        )
        .unwrap();
    let conflict = reopened
        .persist_measurement_fragment(
            MeasurementFragment::new(
                key_for_event(9),
                FragmentPosition::new(0, 2).unwrap(),
                FragmentFact::new(
                    [11; 32],
                    FragmentBytes::new(1).unwrap(),
                    EvidenceQuality::Captured,
                ),
            ),
            SourceTick::new(5),
        )
        .unwrap();
    assert_eq!(conflict[0].reason(), AssemblyCloseReason::ConflictingDuplicate);
    let waited_key = key_for_event(10);
    reopened
        .persist_measurement_fragment(
            MeasurementFragment::new(
                waited_key.clone(),
                FragmentPosition::new(0, 2).unwrap(),
                FragmentFact::new(
                    [12; 32],
                    FragmentBytes::new(1).unwrap(),
                    EvidenceQuality::Captured,
                ),
            ),
            SourceTick::new(20),
        )
        .unwrap();
    let after_deadline = reopened
        .persist_measurement_fragment(
            MeasurementFragment::new(
                waited_key,
                FragmentPosition::new(1, 2).unwrap(),
                FragmentFact::new(
                    [13; 32],
                    FragmentBytes::new(1).unwrap(),
                    EvidenceQuality::Captured,
                ),
            ),
            SourceTick::new(1_000_020),
        )
        .unwrap();
    assert_eq!(
        after_deadline.iter().map(|close| close.reason()).collect::<Vec<_>>(),
        [AssemblyCloseReason::WaitLimit, AssemblyCloseReason::LateFragment]
    );
    assert!(!after_deadline.iter().any(|close| close.reason() == AssemblyCloseReason::Complete));
    let reasons = reopened
        .query_measurement_closes(16)
        .unwrap()
        .into_iter()
        .map(|close| close.reason())
        .collect::<Vec<_>>();
    for reason in [
        AssemblyCloseReason::WaitLimit,
        AssemblyCloseReason::CountLimit,
        AssemblyCloseReason::ByteLimit,
        AssemblyCloseReason::ConflictingDuplicate,
    ] {
        assert!(reasons.contains(&reason));
    }
    reopened.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn measurement_query_rejects_same_width_tampering_for_every_close_reason() {
    let parent = temporary_directory("host-measurement-tamper");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let store_root = parent.join("world-store");
    let source = SourceInstance::new(
        SensorId::try_from("tamper-rx").unwrap(),
        DeviceId::new(92),
        KeyEpoch::new(3).unwrap(),
        BootGeneration::new(8).unwrap(),
    );
    let key_for_event = |event| {
        AssemblyKey::new(
            source.clone(),
            EventIdentity::new(
                TransmitterIdentity::new([1; 32]),
                NativeEventIdentity::new([event; 32]),
                None,
            ),
            MeasurementContext::new(
                ProfileIdentity::new([3; 32]),
                RadioIdentity::new([4; 32]),
                ChannelIdentity::new([5; 32]),
            ),
        )
    };
    let fragment = |event, ordinal, expected, digest, bytes| {
        MeasurementFragment::new(
            key_for_event(event),
            FragmentPosition::new(ordinal, expected).unwrap(),
            FragmentFact::new(
                [digest; 32],
                FragmentBytes::new(bytes).unwrap(),
                EvidenceQuality::Captured,
            ),
        )
    };
    let limits =
        AssemblyLimits::new(AssemblyCapacity::new(2, 2, 8).unwrap(), WaitTicks::new(5).unwrap());
    let host = start_host_with_measurement_limits(
        Store::initialize(&store_root).unwrap(),
        &sender,
        &secret_root,
        limits,
    );
    host.persist_measurement_fragment(fragment(1, 0, 1, 1, 1), SourceTick::new(0)).unwrap();
    host.persist_measurement_fragment(fragment(2, 0, 2, 2, 1), SourceTick::new(0)).unwrap();
    host.expire_measurements(source.clone(), SourceTick::new(5)).unwrap();
    host.persist_measurement_fragment(fragment(3, 0, 3, 3, 1), SourceTick::new(5)).unwrap();
    host.persist_measurement_fragment(fragment(4, 0, 2, 4, 5), SourceTick::new(5)).unwrap();
    host.persist_measurement_fragment(fragment(4, 1, 2, 5, 5), SourceTick::new(6)).unwrap();
    host.persist_measurement_fragment(fragment(5, 0, 2, 6, 1), SourceTick::new(6)).unwrap();
    host.persist_measurement_fragment(fragment(6, 0, 2, 7, 1), SourceTick::new(6)).unwrap();
    host.persist_measurement_fragment(fragment(7, 0, 2, 8, 1), SourceTick::new(6)).unwrap();
    host.persist_measurement_fragment(fragment(5, 1, 2, 9, 1), SourceTick::new(7)).unwrap();
    host.persist_measurement_fragment(fragment(6, 1, 2, 10, 1), SourceTick::new(7)).unwrap();
    host.persist_measurement_fragment(fragment(8, 0, 2, 11, 1), SourceTick::new(7)).unwrap();
    host.persist_measurement_fragment(fragment(8, 0, 2, 11, 1), SourceTick::new(8)).unwrap();
    host.persist_measurement_fragment(fragment(9, 0, 2, 12, 1), SourceTick::new(8)).unwrap();
    host.persist_measurement_fragment(fragment(9, 0, 2, 13, 1), SourceTick::new(9)).unwrap();
    host.persist_measurement_fragment(fragment(1, 0, 1, 14, 1), SourceTick::new(9)).unwrap();
    assert_eq!(host.query_measurement_closes(32).unwrap().len(), 10);
    host.shutdown().unwrap();

    let mutations = [
        ("complete", "attempted_fragments", "attempted_fragments + 1"),
        ("wait_limit", "close_tick", "first_tick"),
        ("count_limit", "attempted_fragments", "attempted_fragments + 1"),
        ("byte_limit", "attempted_bytes", "limit_bytes"),
        ("resource_limit", "open_assemblies", "open_assemblies - 1"),
        ("late_fragment", "attempted_fragments", "attempted_fragments + 1"),
        ("duplicate_fragment", "attempted_fragments", "1"),
        ("conflicting_duplicate", "attempted_bytes", "total_bytes"),
    ];
    let database_path = store_root.join("facts.sqlite3");
    for (reason, column, expression) in mutations {
        let database = rusqlite::Connection::open(&database_path).unwrap();
        let id: i64 = database
            .query_row(
                "SELECT assembly_id FROM measurement_assemblies WHERE close_reason=?1 LIMIT 1",
                [reason],
                |row| row.get(0),
            )
            .unwrap();
        let original: rusqlite::types::Value = database
            .query_row(
                &format!("SELECT {column} FROM measurement_assemblies WHERE assembly_id=?1"),
                [id],
                |row| row.get(0),
            )
            .unwrap();
        database
            .execute(
                &format!(
                    "UPDATE measurement_assemblies SET {column}={expression} WHERE assembly_id=?1"
                ),
                [id],
            )
            .unwrap();
        drop(database);
        let reopened = start_host_with_measurement_limits(
            Store::open(&store_root).unwrap(),
            &sender,
            &secret_root,
            limits,
        );
        assert!(reopened.query_measurement_closes(32).is_err(), "accepted {reason} tamper");
        reopened.shutdown().unwrap();
        let database = rusqlite::Connection::open(&database_path).unwrap();
        database
            .execute(
                &format!("UPDATE measurement_assemblies SET {column}=?1 WHERE assembly_id=?2"),
                rusqlite::params![original, id],
            )
            .unwrap();
    }
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn resource_limit_close_remains_closed_across_restart() {
    let parent = temporary_directory("host-measurement-resource-restart");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let store_root = parent.join("world-store");
    let source = SourceInstance::new(
        SensorId::try_from("resource-rx").unwrap(),
        DeviceId::new(93),
        KeyEpoch::new(3).unwrap(),
        BootGeneration::new(8).unwrap(),
    );
    let key_for_event = |event: u16| {
        let mut identity = [0_u8; 32];
        identity[..2].copy_from_slice(&event.to_be_bytes());
        AssemblyKey::new(
            source.clone(),
            EventIdentity::new(
                TransmitterIdentity::new([1; 32]),
                NativeEventIdentity::new(identity),
                None,
            ),
            MeasurementContext::new(
                ProfileIdentity::new([3; 32]),
                RadioIdentity::new([4; 32]),
                ChannelIdentity::new([5; 32]),
            ),
        )
    };
    let fragment_for = |event| {
        MeasurementFragment::new(
            key_for_event(event),
            FragmentPosition::new(0, 2).unwrap(),
            FragmentFact::new(
                [event as u8; 32],
                FragmentBytes::new(1).unwrap(),
                EvidenceQuality::Captured,
            ),
        )
    };

    let limits = AssemblyLimits::new(
        AssemblyCapacity::new(4, 1_024, 16 * 1024 * 1024).unwrap(),
        WaitTicks::new(1_000_000).unwrap(),
    );
    let host = start_host_with_measurement_limits(
        Store::initialize(&store_root).unwrap(),
        &sender,
        &secret_root,
        limits,
    );
    for event in 0..4 {
        assert!(
            host.persist_measurement_fragment(
                fragment_for(event),
                SourceTick::new(u64::from(event))
            )
            .unwrap()
            .is_empty()
        );
    }
    let resource = host.persist_measurement_fragment(fragment_for(4), SourceTick::new(4)).unwrap();
    assert_eq!(resource[0].reason(), AssemblyCloseReason::ResourceLimit);
    host.shutdown().unwrap();

    let reopened = start_host_with_measurement_limits(
        Store::open(&store_root).unwrap(),
        &sender,
        &secret_root,
        limits,
    );
    let late = reopened.persist_measurement_fragment(fragment_for(4), SourceTick::new(5)).unwrap();
    assert_eq!(late[0].reason(), AssemblyCloseReason::LateFragment);
    let closes = reopened.query_measurement_closes(4).unwrap();
    assert!(closes.iter().any(|close| close.reason() == AssemblyCloseReason::ResourceLimit));
    assert!(closes.iter().any(|close| close.reason() == AssemblyCloseReason::LateFragment));
    reopened.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn saturated_control_refill_rotates_to_udp_ingress() {
    const CONCURRENT_COMMANDS: usize = 96;
    let parent = temporary_directory("host-writer-fairness");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host = Arc::new(start_host(
        Store::initialize(parent.join("world-store")).unwrap(),
        &sender,
        &secret_root,
    ));
    let barrier = Arc::new(Barrier::new(CONCURRENT_COMMANDS + 1));
    let mut workers = Vec::new();
    for worker in 0..CONCURRENT_COMMANDS {
        let host = Arc::clone(&host);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            let source = SourceInstance::new(
                SensorId::try_from("fairness-rx").unwrap(),
                DeviceId::new(120),
                KeyEpoch::new(4).unwrap(),
                BootGeneration::new(9).unwrap(),
            );
            let common = RelationValidity::new(
                "fairness-fit",
                source,
                ErrorBound::new(1, ErrorUnit::Nanoseconds),
                TickRange::new(SourceTick::new(0), SourceTick::new(100)).unwrap(),
                QualificationEpoch::new(worker as u64),
            )
            .unwrap();
            host.persist_qualification(QualificationRelation::Time(
                TimeRelation::new(common, "source", "target", FitIdentity::new([worker as u8; 32]))
                    .unwrap(),
            ))
        }));
    }
    barrier.wait();
    let ingress_started = Instant::now();
    sender
        .send_to(
            &hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex")),
            host.local_addr(),
        )
        .unwrap();
    wait_for_fact_count(&host, 1);
    assert!(ingress_started.elapsed() < Duration::from_secs(3));
    for worker in workers {
        if let Err(error) = worker.join().unwrap() {
            assert!(
                error.to_string().contains("control queue count deadline elapsed"),
                "unexpected saturated-control result: {error}"
            );
        }
    }
    Arc::try_unwrap(host).expect("workers released host").shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn route_budget_carries_every_supported_native_frame_v1_message() {
    assert!(DatagramBytes::try_from(752).is_err());
    let minimum = DatagramBytes::try_from(753).expect("specified v1 minimum is accepted");
    for fixture in [
        include_str!("fixtures/native-frame/capabilities-v1.hex"),
        include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"),
        include_str!("fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex"),
        include_str!("fixtures/native-frame/csi-ht-stbc-7-pairs.hex"),
        include_str!("fixtures/native-frame/health-v1.hex"),
        include_str!("fixtures/native-frame/csi-production-non-ht-64-pairs.hex"),
        include_str!("fixtures/native-frame/csi-production-ht20-128-pairs.hex"),
        include_str!("fixtures/native-frame/csi-production-ht20-stbc-192-pairs.hex"),
        include_str!("fixtures/native-frame/csi-production-ht40-above-192-pairs.hex"),
        include_str!("fixtures/native-frame/csi-production-ht40-below-192-pairs.hex"),
        include_str!("fixtures/native-frame/csi-production-ht40-above-stbc-306-pairs.hex"),
        include_str!("fixtures/native-frame/csi-production-ht40-below-stbc-306-pairs.hex"),
    ] {
        assert!(hex_fixture(fixture).len() <= minimum.get());
    }
}

#[test]
fn wire_identity_types_support_canonical_checked_conversions() {
    assert_eq!(KeyEpoch::try_from(7).unwrap().get(), 7);
    assert_eq!("7".parse::<KeyEpoch>().unwrap().get(), 7);
    assert_eq!(BootGeneration::try_from(9).unwrap().get(), 9);
    assert_eq!("9".parse::<BootGeneration>().unwrap().get(), 9);
    assert_eq!(MessageSequence::try_from(12).unwrap().get(), 12);
    assert_eq!("12".parse::<MessageSequence>().unwrap().get(), 12);
    assert!(KeyEpoch::try_from(0).is_err());
    let error = "not-a-sequence".parse::<MessageSequence>().unwrap_err();
    assert!(std::error::Error::source(&error).is_some());

    let source = SourceMac::try_from(SOURCE_MAC).unwrap();
    assert_eq!(source.to_string(), "02:00:00:00:00:0a");
    let source_error = SourceMac::try_from([0; 6]).unwrap_err();
    assert_eq!(source_error.actual_width(), 6);
    assert!(source_error.to_string().contains("all zero"));
    let channel = ChannelPolicy::try_from(11).unwrap();
    assert_eq!(channel.get(), 11);
    let channel_error = ChannelPolicy::try_from(0).unwrap_err();
    assert_eq!(channel_error.channel(), 0);
    let capability = CapabilityIdentity::try_from(CAPABILITY_DIGEST.as_slice()).unwrap();
    assert_eq!(capability.into_bytes(), CAPABILITY_DIGEST);
    let digest_error = CapabilityIdentity::try_from(&[0_u8; 31][..]).unwrap_err();
    assert_eq!(digest_error.actual_width(), 31);
    assert!(digest_error.to_string().contains("32 bytes"));
}

#[test]
fn public_validation_errors_retain_context_sources_and_backtraces() {
    let deployment_error = DeploymentId::try_from("").unwrap_err();
    assert_eq!(deployment_error.input_length(), 0);
    let _ = deployment_error.backtrace();

    let limit_error = DatagramBytes::try_from(752).unwrap_err();
    assert_eq!(limit_error.unit(), "datagram bytes");
    let _ = limit_error.backtrace();

    let parent = temporary_directory("route-error-context");
    let secret_root = parent.join("missing-secret-root");
    let route_error = NativeFrameRoute::load(
        "127.0.0.1".parse().unwrap(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .unwrap_err();
    assert_eq!(route_error.device_id(), device_id());
    assert_eq!(route_error.key_epoch(), key_epoch());
    let secret_text = secret_root.display().to_string();
    assert!(!route_error.to_string().contains(&secret_text));
    assert!(!format!("{route_error:?}").contains(&secret_text));
    assert!(std::error::Error::source(&route_error).is_some());
    let _ = route_error.backtrace();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn authenticated_production_udp_datagram_is_queryable_as_exact_raw_bytes() {
    let parent = temporary_directory("host-udp");
    let store = Store::initialize(parent.join("world-store")).expect("Store initializes");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .expect("exact route is valid");
    let host = Host::builder(store, deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .start()
        .expect("Host starts");
    let datagram = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));

    sender.send_to(&datagram, host.local_addr()).expect("fixed datagram sent");

    let deadline = Instant::now() + Duration::from_secs(2);
    let fact = loop {
        let mut facts = host.query_raw(1).expect("local raw query succeeds");
        if let Some(fact) = facts.pop() {
            break fact;
        }
        assert!(Instant::now() < deadline, "raw fact was not committed before the deadline");
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(fact.datagram(), datagram);
    assert_eq!(fact.digest(), &<[u8; 32]>::from(Sha256::digest(&datagram)));
    assert_eq!(fact.peer(), sender.local_addr().unwrap());
    assert_eq!(fact.device_id(), device_id());
    assert_eq!(fact.key_epoch(), key_epoch());
    assert_eq!(fact.boot_generation(), BootGeneration::new(9).unwrap());
    assert_eq!(fact.message_sequence(), MessageSequence::new(12).unwrap());
    assert_eq!(fact.kind(), NativeFrameKind::new(2));
    assert!(fact.received_at() <= SystemTime::now());

    host.shutdown().expect("Host shuts down");
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[test]
fn authenticated_native_messages_become_lossless_typed_facts_with_raw_provenance() {
    let parent = temporary_directory("host-native-facts");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host =
        start_host(Store::initialize(parent.join("world-store")).unwrap(), &sender, &secret_root);
    let datagrams = [
        hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex")),
        hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex")),
        hex_fixture(include_str!("fixtures/native-frame/health-zero-latency-v1.hex")),
    ];
    for datagram in &datagrams {
        sender.send_to(datagram, host.local_addr()).unwrap();
    }
    wait_for_fact_count(&host, datagrams.len());

    let raw = host.query_raw(16).unwrap();
    let typed = host.query_native_facts(16).unwrap();
    assert_eq!(typed.len(), datagrams.len());
    for fact in &typed {
        let raw_fact = raw
            .iter()
            .find(|candidate| candidate.digest() == fact.provenance().provenance_digest())
            .expect("typed provenance points at one raw fact");
        let expected_datagram = datagrams
            .iter()
            .find(|bytes| Sha256::digest(bytes).as_slice() == raw_fact.digest())
            .expect("typed provenance digest identifies one input datagram");
        assert_eq!(raw_fact.datagram(), expected_datagram);
    }

    let csi = typed
        .iter()
        .find_map(|fact| match fact {
            NativeFact::Csi(csi) => Some(csi),
            _ => None,
        })
        .expect("CSI fact is queryable");
    assert_eq!(csi.sample_axis(), SampleAxis::OpaqueOrdinal { count: 3 });
    assert_eq!(csi.samples().len(), 3);
    assert_eq!(csi.samples()[0].i, 2);
    assert_eq!(csi.samples()[0].q, 1);
    assert_eq!(csi.driver_rx_timestamp_us(), 22);
    assert_eq!(csi.callback_tick_us(), 23);
    assert_eq!(csi.radio().rssi_dbm(), -42);
    assert_eq!(csi.radio().noise_floor_dbm(), -95);
    assert_eq!(csi.radio().rate(), 6);
    assert_eq!(csi.radio().mcs(), 0);
    assert_eq!(host.query_native_capabilities(1).unwrap().len(), 1);
    let health = host.query_native_health(1).unwrap();
    assert_eq!(health.len(), 1);
    assert_eq!(health[0].callback_tick_us(), 51);
    assert_eq!(health[0].capture_seen(), 52);
    assert_eq!(health[0].callback_max_us(), 0);
    assert_eq!(health[0].encoder_max_us(), 0);

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn nonzero_health_latency_is_retained_raw_but_not_typed() {
    let parent = temporary_directory("host-health-latency");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host =
        start_host(Store::initialize(parent.join("world-store")).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    let health = hex_fixture(include_str!("fixtures/native-frame/health-v1.hex"));
    sender.send_to(&capabilities, host.local_addr()).unwrap();
    sender.send_to(&health, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 2);

    assert!(host.query_native_health(16).unwrap().is_empty());
    assert_eq!(host.query_native_facts(16).unwrap().len(), 1);
    wait_for_rejection(&host, RejectReason::UnsupportedHealthLatency);
    assert!(host.query_raw(16).unwrap().iter().any(|fact| fact.datagram() == health));

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn each_native_csi_layout_is_queryable_without_length_based_reinterpretation() {
    for (
        label,
        fixture,
        radio,
        expected_samples,
        expected_first_invalid,
        expected_trailing_invalid,
    ) in [
        (
            "host-native-layout-non-ht",
            hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex")),
            non_ht_radio(),
            3,
            0,
            0,
        ),
        (
            "host-native-layout-ht",
            hex_fixture(include_str!("fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex")),
            ht40_above_radio(),
            5,
            4,
            2,
        ),
        (
            "host-native-layout-ht-stbc",
            hex_fixture(include_str!("fixtures/native-frame/csi-ht-stbc-7-pairs.hex")),
            ht40_below_stbc_radio(),
            7,
            0,
            0,
        ),
    ] {
        let parent = temporary_directory(label);
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
        let secret_root = create_secret_root(&parent);
        let host = start_host_with_radio(
            Store::initialize(parent.join("world-store")).unwrap(),
            &sender,
            &secret_root,
            radio,
        );
        let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
        sender.send_to(&capabilities, host.local_addr()).unwrap();
        sender.send_to(&fixture, host.local_addr()).unwrap();
        wait_for_fact_count(&host, 2);

        let facts = host.query_native_csi(4).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].complex_sample_count(), expected_samples);
        assert_eq!(facts[0].first_invalid_bytes(), expected_first_invalid);
        assert_eq!(facts[0].trailing_invalid_bytes(), expected_trailing_invalid);
        assert_eq!(facts[0].samples().len(), usize::from(expected_samples));
        assert_eq!(facts[0].sample_axis(), SampleAxis::OpaqueOrdinal { count: expected_samples });
        assert_eq!(facts[0].raw_csi().len(), csi_body_raw_length(&fixture));
        if expected_first_invalid != 0 {
            assert!(facts[0].samples().iter().take(2).all(|sample| !sample.valid));
        }

        host.shutdown().unwrap();
        fs::remove_dir_all(parent).unwrap();
    }
}

#[test]
fn every_full_production_sender_layout_preserves_exact_native_bytes_and_samples() {
    let cases = [
        (
            "host-production-layout-non-ht",
            include_str!("fixtures/native-frame/csi-production-non-ht-64-pairs.hex"),
            non_ht_radio(),
            &[64_u16][..],
            128_usize,
            "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5",
        ),
        (
            "host-production-layout-ht20",
            include_str!("fixtures/native-frame/csi-production-ht20-128-pairs.hex"),
            ht20_radio(),
            &[64_u16, 64][..],
            256,
            "78694fa4f1c96155917a82d47c2d12598423e27420899d7ef28e983002b94056",
        ),
        (
            "host-production-layout-ht20-stbc",
            include_str!("fixtures/native-frame/csi-production-ht20-stbc-192-pairs.hex"),
            ht20_stbc_radio(),
            &[64_u16, 64, 64][..],
            384,
            "e14c4fb944c59050be0116db33c432e6ece16c82cfb71bee9784020d7e3dc07a",
        ),
        (
            "host-production-layout-ht40-above",
            include_str!("fixtures/native-frame/csi-production-ht40-above-192-pairs.hex"),
            ht40_above_radio(),
            &[64_u16, 128][..],
            384,
            "4d3d0303daa0c59f454c0613c6fa8804d82b7169c8b25085897557ed688c5684",
        ),
        (
            "host-production-layout-ht40-below",
            include_str!("fixtures/native-frame/csi-production-ht40-below-192-pairs.hex"),
            ht40_below_radio(),
            &[64_u16, 128][..],
            384,
            "1de36ef01b993d3a3046e8226dc213e7701591234d2a5865151b55c43d710176",
        ),
        (
            "host-production-layout-ht40-above-stbc",
            include_str!("fixtures/native-frame/csi-production-ht40-above-stbc-306-pairs.hex"),
            ht40_above_stbc_radio(),
            &[64_u16, 121, 121][..],
            612,
            "f105688edae1128f3435df735df6faa97c1e76cf7101461fdcad524d06e208bb",
        ),
        (
            "host-production-layout-ht40-below-stbc",
            include_str!("fixtures/native-frame/csi-production-ht40-below-stbc-306-pairs.hex"),
            ht40_below_stbc_radio(),
            &[64_u16, 121, 121][..],
            612,
            "7b6e9df2e8f39b38320a435ec050122b108275925adfba42d90c88db8304219c",
        ),
    ];
    for (label, fixture, radio, expected_blocks, expected_raw_len, expected_raw_digest) in cases {
        let parent = temporary_directory(label);
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
        let secret_root = create_secret_root(&parent);
        let host = start_host_with_radio(
            Store::initialize(parent.join("world-store")).unwrap(),
            &sender,
            &secret_root,
            radio,
        );
        let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
        let datagram = hex_fixture(fixture);
        sender.send_to(&capabilities, host.local_addr()).unwrap();
        sender.send_to(&datagram, host.local_addr()).unwrap();
        wait_for_fact_count(&host, 2);

        let facts = host.query_native_csi(1).unwrap();
        assert_eq!(facts.len(), 1);
        let fact = &facts[0];
        assert_eq!(
            fact.blocks().iter().map(|block| block.sample_count()).collect::<Vec<_>>(),
            expected_blocks
        );
        assert_eq!(fact.raw_csi().len(), expected_raw_len);
        assert_eq!(Sha256::digest(fact.raw_csi()).as_slice(), hex_fixture(expected_raw_digest));
        assert_eq!(fact.csi().path(), CsiPath::RawPathOrdinal(0));
        assert_eq!(
            fact.sample_axis(),
            SampleAxis::OpaqueOrdinal { count: expected_blocks.iter().sum() }
        );
        assert_eq!(fact.samples().len(), usize::from(expected_blocks.iter().sum::<u16>()));
        assert_eq!(fact.radio(), radio);
        let expected_provenance: [u8; 32] = Sha256::digest(&datagram).into();
        assert_eq!(fact.provenance().provenance_digest(), &expected_provenance);
        let raw = host.query_raw(4).unwrap();
        assert!(raw.iter().any(|candidate| candidate.datagram() == datagram.as_slice()));

        host.shutdown().unwrap();
        fs::remove_dir_all(parent).unwrap();
    }
}

#[test]
fn capability_conflict_is_retained_raw_and_excluded_from_typed_facts() {
    let parent = temporary_directory("host-capability-conflict");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host =
        start_host(Store::initialize(parent.join("world-store")).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    let mut changed_body = decrypt_fixture(&capabilities);
    changed_body[34 + 15] ^= 1;
    let changed_digest: [u8; 32] = Sha256::digest(&changed_body[34..]).into();
    changed_body[..32].copy_from_slice(&changed_digest);
    let changed = seal_native_datagram(1, 12, &changed_body);
    sender.send_to(&changed, host.local_addr()).unwrap();
    sender.send_to(&capabilities, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 2);

    assert_eq!(host.query_native_capabilities(16).unwrap().len(), 1);
    assert!(
        host.query_rejections(16)
            .unwrap()
            .iter()
            .any(|rejection| rejection.reason() == RejectReason::CapabilityConflict)
    );

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn source_and_radio_conflicts_are_retained_raw_and_excluded_independently() {
    for (label, offset, value, reason) in [
        ("host-source-conflict", 52, None, RejectReason::SourceConflict),
        ("host-radio-conflict", 58, Some(2), RejectReason::RadioConflict),
    ] {
        let parent = temporary_directory(label);
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
        let secret_root = create_secret_root(&parent);
        let host = start_host(
            Store::initialize(parent.join("world-store")).unwrap(),
            &sender,
            &secret_root,
        );
        let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
        let csi = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
        let mut changed_body = decrypt_fixture(&csi);
        changed_body[offset] = value.unwrap_or(changed_body[offset].wrapping_add(1));
        let changed = seal_native_datagram(2, 13, &changed_body);
        sender.send_to(&capabilities, host.local_addr()).unwrap();
        sender.send_to(&csi, host.local_addr()).unwrap();
        sender.send_to(&changed, host.local_addr()).unwrap();
        wait_for_fact_count(&host, 3);

        assert_eq!(host.query_native_csi(16).unwrap().len(), 1);
        assert!(
            host.query_rejections(16).unwrap().iter().any(|rejection| rejection.reason() == reason)
        );

        host.shutdown().unwrap();
        fs::remove_dir_all(parent).unwrap();
    }
}

#[test]
fn every_configured_radio_identity_field_is_admitted_only_when_pinned() {
    let cases = [
        (
            "host-radio-phy-conflict",
            non_ht_radio(),
            "fixtures/native-frame/csi-production-non-ht-64-pairs.hex",
            "fixtures/native-frame/csi-production-ht20-128-pairs.hex",
            None,
        ),
        (
            "host-radio-bandwidth-conflict",
            ht20_radio(),
            "fixtures/native-frame/csi-production-ht20-128-pairs.hex",
            "fixtures/native-frame/csi-production-ht40-above-192-pairs.hex",
            None,
        ),
        (
            "host-radio-secondary-conflict",
            ht40_above_radio(),
            "fixtures/native-frame/csi-production-ht40-above-192-pairs.hex",
            "fixtures/native-frame/csi-production-ht40-below-192-pairs.hex",
            None,
        ),
        (
            "host-radio-stbc-conflict",
            ht40_above_radio(),
            "fixtures/native-frame/csi-production-ht40-above-192-pairs.hex",
            "fixtures/native-frame/csi-production-ht40-above-stbc-306-pairs.hex",
            None,
        ),
        (
            "host-radio-rate-conflict",
            non_ht_radio(),
            "fixtures/native-frame/csi-production-non-ht-64-pairs.hex",
            "fixtures/native-frame/csi-production-non-ht-64-pairs.hex",
            Some(65_u8),
        ),
        (
            "host-radio-mcs-conflict",
            ht40_above_radio(),
            "fixtures/native-frame/csi-production-ht40-above-192-pairs.hex",
            "fixtures/native-frame/csi-production-ht40-above-192-pairs.hex",
            Some(66_u8),
        ),
        (
            "host-radio-antenna-conflict",
            ht40_above_radio(),
            "fixtures/native-frame/csi-production-ht40-above-192-pairs.hex",
            "fixtures/native-frame/csi-production-ht40-above-192-pairs.hex",
            Some(67_u8),
        ),
    ];
    for (label, radio, baseline_name, variant_name, mutate_offset) in cases {
        let parent = temporary_directory(label);
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
        let secret_root = create_secret_root(&parent);
        let host = start_host_with_radio(
            Store::initialize(parent.join("world-store")).unwrap(),
            &sender,
            &secret_root,
            radio,
        );
        let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
        let baseline = fixture_by_name(baseline_name);
        let mut variant = fixture_by_name(variant_name);
        if let Some(offset) = mutate_offset {
            let mut body = decrypt_fixture(&variant);
            body[usize::from(offset)] = body[usize::from(offset)].wrapping_sub(1);
            variant = seal_native_datagram(2, 31, &body);
        }
        sender.send_to(&capabilities, host.local_addr()).unwrap();
        sender.send_to(&baseline, host.local_addr()).unwrap();
        sender.send_to(&variant, host.local_addr()).unwrap();
        wait_for_fact_count(&host, 3);
        wait_for_rejection(&host, RejectReason::RadioConflict);
        assert_eq!(host.query_native_csi(16).unwrap().len(), 1);
        assert_eq!(host.query_raw(16).unwrap().len(), 3);

        host.shutdown().unwrap();
        fs::remove_dir_all(parent).unwrap();
    }
}

#[test]
fn authenticated_unknown_kind_and_malformed_body_remain_raw_only() {
    let parent = temporary_directory("host-semantic-rejections");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host =
        start_host(Store::initialize(parent.join("world-store")).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    let valid_body = decrypt_fixture(&capabilities);
    let unknown = seal_native_datagram(99, 12, &valid_body);
    let malformed = seal_native_datagram(2, 13, &[]);
    sender.send_to(&capabilities, host.local_addr()).unwrap();
    sender.send_to(&unknown, host.local_addr()).unwrap();
    sender.send_to(&malformed, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 3);

    assert_eq!(host.query_native_facts(16).unwrap().len(), 1);
    let rejections = host.query_rejections(16).unwrap();
    assert!(rejections.iter().any(|rejection| rejection.reason() == RejectReason::UnknownKind));
    assert!(rejections.iter().any(|rejection| rejection.reason() == RejectReason::MalformedBody));

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn csi_before_capability_is_retained_raw_but_never_backfilled_as_typed() {
    let parent = temporary_directory("host-csi-before-capability");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host =
        start_host(Store::initialize(parent.join("world-store")).unwrap(), &sender, &secret_root);
    let csi = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    sender.send_to(&csi, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 1);
    sender.send_to(&capabilities, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 2);

    assert!(host.query_native_csi(16).unwrap().is_empty());
    assert!(
        host.query_rejections(16)
            .unwrap()
            .iter()
            .any(|rejection| rejection.reason() == RejectReason::CapabilityUnavailable)
    );

    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn restart_preserves_raw_fact_and_replay_rejection_excludes_duplicate_bytes() {
    let parent = temporary_directory("host-restart-replay");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let datagram = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));

    let secret_root = create_secret_root(&parent);
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    sender.send_to(&datagram, first.local_addr()).unwrap();
    wait_for_fact_count(&first, 1);
    first.shutdown().expect("first Host shuts down");

    let restarted =
        start_host(Store::open(&root).expect("same Store reopens"), &sender, &secret_root);
    assert_eq!(restarted.query_raw(10).unwrap().len(), 1);
    sender.send_to(&datagram, restarted.local_addr()).unwrap();
    wait_for_rejection(&restarted, RejectReason::Replay);
    assert_eq!(restarted.query_raw(10).unwrap().len(), 1);

    let mut bad_tag = datagram;
    *bad_tag.last_mut().expect("datagram has authentication tag") ^= 1;
    sender.send_to(&bad_tag, restarted.local_addr()).unwrap();
    wait_for_rejection(&restarted, RejectReason::AuthenticationFailed);
    assert_eq!(restarted.query_raw(10).unwrap().len(), 1);

    restarted.shutdown().expect("restarted Host shuts down");
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[test]
fn restart_replays_capability_csi_and_health_queries_without_derivation_drift() {
    let parent = temporary_directory("host-native-query-restart");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    let datagrams = [
        hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex")),
        hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex")),
        hex_fixture(include_str!("fixtures/native-frame/health-zero-latency-v1.hex")),
    ];
    for datagram in &datagrams {
        sender.send_to(datagram, first.local_addr()).unwrap();
    }
    wait_for_fact_count(&first, datagrams.len());
    let before_capabilities = first.query_native_capabilities(16).unwrap();
    let before_csi = first.query_native_csi(16).unwrap();
    let before_health = first.query_native_health(16).unwrap();
    let before_facts = first.query_native_facts(16).unwrap();
    assert_eq!(before_capabilities.len(), 1);
    assert_eq!(before_csi.len(), 1);
    assert_eq!(before_health.len(), 1);
    assert_eq!(before_csi[0].raw_csi(), &[1, 2, 0x80, 0x7f, 0xff, 0]);
    assert_eq!(before_health[0].callback_max_us(), 0);
    assert_eq!(before_health[0].encoder_max_us(), 0);
    first.shutdown().unwrap();

    let restarted = start_host(Store::open(&root).unwrap(), &sender, &secret_root);
    assert_eq!(restarted.query_native_capabilities(16).unwrap(), before_capabilities);
    assert_eq!(restarted.query_native_csi(16).unwrap(), before_csi);
    assert_eq!(restarted.query_native_health(16).unwrap(), before_health);
    assert_eq!(restarted.query_native_facts(16).unwrap(), before_facts);
    let after_raw = restarted.query_raw(16).unwrap();
    for datagram in &datagrams {
        assert!(after_raw.iter().any(|fact| fact.datagram() == datagram.as_slice()));
    }

    restarted.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn restart_with_changed_sensor_identity_never_relabels_old_typed_facts() {
    let parent = temporary_directory("host-native-route-restart");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    let csi = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    sender.send_to(&capabilities, first.local_addr()).unwrap();
    sender.send_to(&csi, first.local_addr()).unwrap();
    wait_for_fact_count(&first, 2);
    first.shutdown().unwrap();

    let database_path = root.join("facts.sqlite3");
    let before = fs::read(&database_path).unwrap();
    let changed_sensor = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route_for_sensor(non_ht_radio(), "sensor-b"),
        &secret_root,
    )
    .unwrap();
    let error = Host::builder(
        Store::open(&root).unwrap(),
        deployment("lab"),
        "127.0.0.1:0".parse().unwrap(),
    )
    .route(changed_sensor)
    .start()
    .expect_err("changed sensor identity must not relabel retained typed facts");
    assert_eq!(error.operation(), "validate retained native route identity");
    assert_eq!(error.path(), Some(database_path.as_path()));
    assert_eq!(fs::read(&database_path).unwrap(), before);

    let reopened = wait_for_store(&root);
    drop(reopened);
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn typed_query_rejects_persisted_route_identity_tampering() {
    let parent = temporary_directory("host-native-route-pin-tamper");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    let csi = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    sender.send_to(&capabilities, host.local_addr()).unwrap();
    sender.send_to(&csi, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 2);
    let database = rusqlite::Connection::open(root.join("facts.sqlite3")).unwrap();
    database.execute("UPDATE native_route_pins SET sensor_id = 'sensor-b'", []).unwrap();
    drop(database);

    let error = host.query_native_csi(16).unwrap_err();
    assert_eq!(error.operation(), "validate retained native route identity");
    assert_eq!(host.query_raw(16).unwrap().len(), 2);
    host.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn same_width_typed_derivative_tampering_fails_closed_after_restart() {
    let parent = temporary_directory("host-native-derivative-tamper");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    let csi = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    sender.send_to(&capabilities, first.local_addr()).unwrap();
    sender.send_to(&csi, first.local_addr()).unwrap();
    wait_for_fact_count(&first, 2);
    first.shutdown().unwrap();

    let database_path = root.join("facts.sqlite3");
    let database = rusqlite::Connection::open(&database_path).unwrap();
    database.execute("UPDATE native_csi_facts SET rssi_dbm = -41 WHERE fact_id = 2", []).unwrap();
    drop(database);

    let restarted = start_host(Store::open(&root).unwrap(), &sender, &secret_root);
    let error = restarted.query_native_csi(16).unwrap_err();
    assert_eq!(error.operation(), "decode persisted native fact");
    assert_eq!(error.path(), Some(database_path.as_path()));
    assert_eq!(restarted.query_raw(16).unwrap().len(), 2);
    restarted.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn persisted_raw_digest_tampering_fails_before_typed_reconstruction() {
    let parent = temporary_directory("host-native-raw-tamper");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    let csi = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    sender.send_to(&capabilities, first.local_addr()).unwrap();
    sender.send_to(&csi, first.local_addr()).unwrap();
    wait_for_fact_count(&first, 2);
    first.shutdown().unwrap();

    let database_path = root.join("facts.sqlite3");
    let database = rusqlite::Connection::open(&database_path).unwrap();
    database
        .execute("UPDATE raw_facts SET datagram = substr(datagram, 1, length(datagram) - 1) WHERE fact_id = 2", [])
        .unwrap();
    drop(database);

    let restarted = start_host(Store::open(&root).unwrap(), &sender, &secret_root);
    let error = restarted.query_native_csi(16).unwrap_err();
    assert_eq!(error.operation(), "decode persisted native fact");
    assert_eq!(error.path(), Some(database_path.as_path()));
    restarted.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn malformed_persisted_capability_width_returns_contextual_host_error() {
    let parent = temporary_directory("host-native-capability-width");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    sender.send_to(&capabilities, first.local_addr()).unwrap();
    wait_for_fact_count(&first, 1);
    first.shutdown().unwrap();

    let database_path = root.join("facts.sqlite3");
    let database = rusqlite::Connection::open(&database_path).unwrap();
    database.execute_batch("PRAGMA ignore_check_constraints = ON;").unwrap();
    database
        .execute(
            "UPDATE native_capability_facts SET capability_digest = zeroblob(31) WHERE fact_id = 1",
            [],
        )
        .unwrap();
    drop(database);

    let restarted = start_host(Store::open(&root).unwrap(), &sender, &secret_root);
    let error = restarted.query_native_capabilities(16).unwrap_err();
    assert_eq!(error.operation(), "decode persisted native fact");
    assert_eq!(error.path(), Some(database_path.as_path()));
    assert!(error.to_string().contains("capability digest"));
    restarted.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn malformed_persisted_source_width_returns_contextual_host_error() {
    let parent = temporary_directory("host-native-source-width");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    let capabilities = hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex"));
    let csi = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    sender.send_to(&capabilities, first.local_addr()).unwrap();
    sender.send_to(&csi, first.local_addr()).unwrap();
    wait_for_fact_count(&first, 2);
    first.shutdown().unwrap();

    let database_path = root.join("facts.sqlite3");
    let database = rusqlite::Connection::open(&database_path).unwrap();
    database.execute_batch("PRAGMA ignore_check_constraints = ON;").unwrap();
    database
        .execute("UPDATE native_csi_facts SET source_mac = zeroblob(5) WHERE fact_id = 2", [])
        .unwrap();
    drop(database);

    let restarted = start_host(Store::open(&root).unwrap(), &sender, &secret_root);
    let error = restarted.query_native_csi(16).unwrap_err();
    assert_eq!(error.operation(), "decode persisted native fact");
    assert_eq!(error.path(), Some(database_path.as_path()));
    assert!(error.to_string().contains("source MAC"));
    restarted.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn restart_rejects_changed_replay_identity_or_window_without_touching_facts() {
    let parent = temporary_directory("host-replay-config-mismatch");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let secret_root = create_secret_root(&parent);
    let datagram = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    sender.send_to(&datagram, first.local_addr()).unwrap();
    wait_for_fact_count(&first, 1);
    first.shutdown().unwrap();
    let database_path = root.join("facts.sqlite3");
    let before = fs::read(&database_path).unwrap();

    let changed_deployment = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .unwrap();
    let mismatch = Host::builder(
        Store::open(&root).unwrap(),
        deployment("other"),
        "127.0.0.1:0".parse().unwrap(),
    )
    .route(changed_deployment)
    .start()
    .expect_err("changed deployment must not reset replay state");
    assert_eq!(mismatch.operation(), "validate retained replay state");
    assert_eq!(mismatch.path(), Some(database_path.as_path()));
    assert_eq!(fs::read(&database_path).unwrap(), before);

    let changed_window = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits_with(1_000, 32),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .unwrap();
    Host::builder(wait_for_store(&root), deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(changed_window)
        .start()
        .expect_err("changed replay window must not reset replay state");
    assert_eq!(fs::read(&database_path).unwrap(), before);

    let advanced_epoch = KeyEpoch::new(KEY_EPOCH + 1).unwrap();
    write_epoch_key(&secret_root, advanced_epoch);
    let advanced_route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        advanced_epoch,
        admission_limits(1_000),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .unwrap();
    Host::builder(wait_for_store(&root), deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(advanced_route)
        .start()
        .expect_err("an unprovisioned advanced epoch must not replace retained replay state");
    assert_eq!(fs::read(&database_path).unwrap(), before);

    drop(wait_for_store(&root));
    let database = rusqlite::Connection::open(&database_path).unwrap();
    database.execute("UPDATE replay_windows SET state = x'00'", []).unwrap();
    drop(database);
    let corrupt_before = fs::read(&database_path).unwrap();
    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .unwrap();
    Host::builder(Store::open(&root).unwrap(), deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .start()
        .expect_err("corrupt retained replay state must not be silently reset");
    assert_eq!(fs::read(&database_path).unwrap(), corrupt_before);

    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn restart_rejects_missing_replay_row_without_touching_database_bytes() {
    let parent = temporary_directory("host-replay-row-missing");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let secret_root = create_secret_root(&parent);
    let first = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);
    first.shutdown().unwrap();
    let database_path = root.join("facts.sqlite3");
    let database = rusqlite::Connection::open(&database_path).unwrap();
    database.execute("DELETE FROM replay_windows", []).unwrap();
    drop(database);
    let before = fs::read(&database_path).unwrap();

    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .unwrap();
    Host::builder(Store::open(&root).unwrap(), deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .start()
        .expect_err("missing persisted route must not be silently recreated");
    assert_eq!(fs::read(&database_path).unwrap(), before);

    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn authenticated_route_rate_limit_excludes_packet_before_replay_admission() {
    let parent = temporary_directory("host-route-rate");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let root = parent.join("world-store");
    let store = Store::initialize(&root).unwrap();
    let secret_root = create_secret_root(&parent);
    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .unwrap();
    let host = Host::builder(store, deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .start()
        .unwrap();
    let sequence_12 = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    let sequence_13 =
        hex_fixture(include_str!("fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex"));

    sender.send_to(&sequence_12, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 1);
    sender.send_to(&sequence_13, host.local_addr()).unwrap();
    wait_for_rejection(&host, RejectReason::AuthenticatedRateLimited);
    assert_eq!(host.query_raw(10).unwrap().len(), 1);

    host.shutdown().unwrap();
    let restarted = start_host(Store::open(&root).unwrap(), &sender, &secret_root);
    sender.send_to(&sequence_13, restarted.local_addr()).unwrap();
    wait_for_fact_count(&restarted, 2);
    restarted.shutdown().unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn missing_and_reordered_sequences_are_preserved_as_explicit_raw_losses() {
    let parent = temporary_directory("host-sequence-loss");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host =
        start_host(Store::initialize(parent.join("world-store")).unwrap(), &sender, &secret_root);
    let sequence_12 = hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex"));
    let sequence_13 =
        hex_fixture(include_str!("fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex"));
    let sequence_14 = hex_fixture(include_str!("fixtures/native-frame/csi-ht-stbc-7-pairs.hex"));
    let sequence_15 = hex_fixture(include_str!("fixtures/native-frame/health-v1.hex"));

    sender.send_to(&sequence_12, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 1);
    sender.send_to(&sequence_14, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 2);
    sender.send_to(&sequence_13, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 3);
    sender.send_to(&sequence_15, host.local_addr()).unwrap();
    wait_for_fact_count(&host, 4);

    let losses = host.query_raw_losses(10).expect("local raw-loss query succeeds");
    assert!(losses.iter().any(|loss| {
        loss.kind() == RawLossKind::SequenceGapObserved
            && loss.device_id() == Some(device_id())
            && loss.boot_generation() == BootGeneration::new(9)
            && loss.first_sequence() == MessageSequence::new(13)
            && loss.last_sequence() == MessageSequence::new(13)
    }));
    assert_eq!(
        losses.iter().filter(|loss| loss.kind() == RawLossKind::SequenceGapObserved).count(),
        1,
        "arrival 12,14,13,15 must not manufacture a second 14 gap from latest fact order"
    );
    assert!(losses.iter().any(|loss| {
        loss.kind() == RawLossKind::ReorderedArrival
            && loss.first_sequence() == MessageSequence::new(13)
            && loss.last_sequence() == MessageSequence::new(13)
    }));

    host.shutdown().expect("Host shuts down");
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[test]
fn authenticated_queue_pressure_is_preserved_as_bounded_raw_loss() {
    let parent = temporary_directory("host-queue-loss");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let store = Store::initialize(parent.join("world-store")).unwrap();
    let secret_root = create_secret_root(&parent);
    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route(non_ht_radio()),
        &secret_root,
    )
    .expect("exact route is valid");
    let host = Host::builder(store, deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .ingress_capacity(1)
        .start()
        .expect("Host starts");
    let datagrams = [
        hex_fixture(include_str!("fixtures/native-frame/capabilities-v1.hex")),
        hex_fixture(include_str!("fixtures/native-frame/csi-non-ht-3-pairs.hex")),
        hex_fixture(include_str!("fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex")),
        hex_fixture(include_str!("fixtures/native-frame/csi-ht-stbc-7-pairs.hex")),
        hex_fixture(include_str!("fixtures/native-frame/health-v1.hex")),
    ];

    for _ in 0..100 {
        for datagram in &datagrams {
            sender.send_to(datagram, host.local_addr()).unwrap();
        }
    }
    wait_for_rejection(&host, RejectReason::IngressQueueFull);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if host
            .query_raw_losses(16)
            .unwrap()
            .iter()
            .any(|loss| loss.kind() == RawLossKind::IngressQueueOverflow && loss.count() > 0)
        {
            break;
        }
        assert!(Instant::now() < deadline, "queue loss was not durably recorded");
        thread::sleep(Duration::from_millis(10));
    }

    host.shutdown().expect("Host shuts down");
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[test]
fn dropping_runtime_leaves_cleanup_and_lease_release_with_the_supervisor() {
    let parent = temporary_directory("host-drop-cleanup");
    let root = parent.join("world-store");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
    let secret_root = create_secret_root(&parent);
    let host = start_host(Store::initialize(&root).unwrap(), &sender, &secret_root);

    drop(host);

    let deadline = Instant::now() + Duration::from_secs(2);
    let reopened = loop {
        match Store::open(&root) {
            Ok(store) => break store,
            Err(error) if error.is_lease_conflict() => {
                assert!(Instant::now() < deadline, "supervisor did not release the Store lease");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("Store failed to reopen after runtime drop: {error}"),
        }
    };

    drop(reopened);
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

fn start_host(
    store: Store,
    sender: &UdpSocket,
    secret_root: &std::path::Path,
) -> whisper::HostRuntime {
    start_host_with_radio(store, sender, secret_root, non_ht_radio())
}

fn start_host_with_radio(
    store: Store,
    sender: &UdpSocket,
    secret_root: &std::path::Path,
    radio: RadioRxS3,
) -> whisper::HostRuntime {
    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route(radio),
        secret_root,
    )
    .expect("exact route is valid");
    Host::builder(store, deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .start()
        .expect("Host starts")
}

fn start_host_with_measurement_limits(
    store: Store,
    sender: &UdpSocket,
    secret_root: &std::path::Path,
    limits: AssemblyLimits,
) -> whisper::HostRuntime {
    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        decoded_route(non_ht_radio()),
        secret_root,
    )
    .expect("exact route is valid");
    Host::builder(store, deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .measurement_limits(limits)
        .start()
        .expect("Host starts")
}

fn decoded_route(radio: RadioRxS3) -> DecodedRoute {
    decoded_route_for_sensor(radio, "sensor-a")
}

fn decoded_route_for_sensor(radio: RadioRxS3, sensor: &str) -> DecodedRoute {
    DecodedRoute::new(
        SensorId::try_from(sensor).unwrap(),
        DecodedRouteLink::new(
            SourceMac::try_from(SOURCE_MAC).unwrap(),
            ChannelPolicy::try_from(radio.channel()).unwrap(),
            RadioRouteFacts::from_radio(radio),
        ),
        FirmwareBuildIdentity::from([0x11; 32]),
        CapabilityIdentity::from(CAPABILITY_DIGEST),
    )
}

fn non_ht_radio() -> RadioRxS3 {
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
    .unwrap()
}

fn ht20_radio() -> RadioRxS3 {
    RadioRxS3::try_new(
        6,
        S3SecondaryKind::None,
        S3PhyKind::Ht,
        S3BandwidthKind::TwentyMhz,
        false,
        -50,
        -96,
        0,
        7,
        1,
    )
    .unwrap()
}

fn ht20_stbc_radio() -> RadioRxS3 {
    RadioRxS3::try_new(
        11,
        S3SecondaryKind::None,
        S3PhyKind::Ht,
        S3BandwidthKind::TwentyMhz,
        true,
        -55,
        -97,
        0,
        3,
        0,
    )
    .unwrap()
}

fn ht40_above_radio() -> RadioRxS3 {
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
    .unwrap()
}

fn ht40_below_radio() -> RadioRxS3 {
    RadioRxS3::try_new(
        11,
        S3SecondaryKind::Below,
        S3PhyKind::Ht,
        S3BandwidthKind::FortyMhz,
        false,
        -50,
        -96,
        0,
        7,
        0,
    )
    .unwrap()
}

fn ht40_below_stbc_radio() -> RadioRxS3 {
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
    .unwrap()
}

fn ht40_above_stbc_radio() -> RadioRxS3 {
    RadioRxS3::try_new(
        6,
        S3SecondaryKind::Above,
        S3PhyKind::Ht,
        S3BandwidthKind::FortyMhz,
        true,
        -55,
        -97,
        0,
        3,
        1,
    )
    .unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::new(DEVICE_ID)
}

fn key_epoch() -> KeyEpoch {
    KeyEpoch::new(KEY_EPOCH).unwrap()
}

fn deployment(value: &str) -> DeploymentId {
    DeploymentId::try_from(value).unwrap()
}

fn admission_limits(packets_per_second: u32) -> AdmissionLimits {
    admission_limits_with(packets_per_second, 64)
}

fn admission_limits_with(packets_per_second: u32, replay_window_packets: u16) -> AdmissionLimits {
    AdmissionLimits::new(
        DatagramBytes::try_from(1_200).unwrap(),
        PacketsPerSecond::try_from(packets_per_second).unwrap(),
        AuthenticatedBytesPerSecond::try_from(1_200_000).unwrap(),
        ReplayWindowPackets::try_from(replay_window_packets).unwrap(),
    )
}

#[cfg(unix)]
fn create_secret_root(parent: &std::path::Path) -> PathBuf {
    let root = parent.join("secrets");
    let device = root.join(format!("device-{DEVICE_ID}"));
    fs::create_dir(&root).expect("secret root created");
    fs::create_dir(&device).expect("device key directory created");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&device, fs::Permissions::from_mode(0o700)).unwrap();
    let key = device.join(format!("key-{KEY_EPOCH}.bin"));
    fs::write(&key, KEY).expect("epoch key written");
    fs::set_permissions(key, fs::Permissions::from_mode(0o600)).unwrap();
    root
}

#[cfg(unix)]
fn write_epoch_key(secret_root: &std::path::Path, epoch: KeyEpoch) {
    let key =
        secret_root.join(format!("device-{DEVICE_ID}")).join(format!("key-{}.bin", epoch.get()));
    fs::write(&key, KEY).unwrap();
    fs::set_permissions(key, fs::Permissions::from_mode(0o600)).unwrap();
}

fn wait_for_fact_count(host: &whisper::HostRuntime, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if host.query_raw(10).expect("local raw query succeeds").len() == expected {
            return;
        }
        assert!(Instant::now() < deadline, "raw fact count did not reach {expected}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_store(root: &std::path::Path) -> Store {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match Store::open(root) {
            Ok(store) => return store,
            Err(error) if error.is_lease_conflict() => {
                assert!(Instant::now() < deadline, "failed Host did not release Store lease");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("Store failed to reopen: {error}"),
        }
    }
}

fn wait_for_rejection(host: &whisper::HostRuntime, expected: RejectReason) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if host
            .query_rejections(16)
            .expect("bounded rejection query succeeds")
            .iter()
            .any(|rejection| rejection.reason() == expected)
        {
            return;
        }
        assert!(Instant::now() < deadline, "rejection was not observed: {expected:?}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn decrypt_fixture(datagram: &[u8]) -> Vec<u8> {
    let body_length = usize::from(u16::from_le_bytes([datagram[28], datagram[29]]));
    assert_eq!(datagram.len(), 32 + body_length + 16);
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&datagram[16..20]);
    nonce[4..].copy_from_slice(&datagram[20..28]);
    Aes256Gcm::new_from_slice(&KEY)
        .expect("test key has the required length")
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &datagram[32..], aad: &datagram[..32] })
        .expect("fixture is authenticated")
}

fn fixture_by_name(name: &str) -> Vec<u8> {
    let fixture = match name {
        "fixtures/native-frame/csi-production-non-ht-64-pairs.hex" => {
            include_str!("fixtures/native-frame/csi-production-non-ht-64-pairs.hex")
        }
        "fixtures/native-frame/csi-production-ht20-128-pairs.hex" => {
            include_str!("fixtures/native-frame/csi-production-ht20-128-pairs.hex")
        }
        "fixtures/native-frame/csi-production-ht40-above-192-pairs.hex" => {
            include_str!("fixtures/native-frame/csi-production-ht40-above-192-pairs.hex")
        }
        "fixtures/native-frame/csi-production-ht40-below-192-pairs.hex" => {
            include_str!("fixtures/native-frame/csi-production-ht40-below-192-pairs.hex")
        }
        "fixtures/native-frame/csi-production-ht40-above-stbc-306-pairs.hex" => {
            include_str!("fixtures/native-frame/csi-production-ht40-above-stbc-306-pairs.hex")
        }
        _ => panic!("unknown production CSI fixture {name}"),
    };
    hex_fixture(fixture)
}

fn csi_body_raw_length(datagram: &[u8]) -> usize {
    let body = decrypt_fixture(datagram);
    let block_count = usize::from(body[70]);
    body.len() - (75 + block_count * 6)
}

fn seal_native_datagram(kind: u8, sequence: u64, body: &[u8]) -> Vec<u8> {
    assert!(body.len() <= u16::MAX as usize);
    let mut header = [0_u8; 32];
    header[0] = 1;
    header[1] = kind;
    header[2..4].copy_from_slice(&32_u16.to_le_bytes());
    header[4..12].copy_from_slice(&DEVICE_ID.to_le_bytes());
    header[12..14].copy_from_slice(&KEY_EPOCH.to_le_bytes());
    header[16..20].copy_from_slice(&9_u32.to_le_bytes());
    header[20..28].copy_from_slice(&sequence.to_le_bytes());
    header[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&9_u32.to_le_bytes());
    nonce[4..].copy_from_slice(&sequence.to_le_bytes());
    let ciphertext = Aes256Gcm::new_from_slice(&KEY)
        .expect("test key has the required length")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &header })
        .expect("test body fits the native-frame cipher");
    let mut datagram = Vec::with_capacity(header.len() + ciphertext.len());
    datagram.extend_from_slice(&header);
    datagram.extend_from_slice(&ciphertext);
    datagram
}

fn hex_fixture(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("fixture hex") as u8;
            let low = (pair[1] as char).to_digit(16).expect("fixture hex") as u8;
            (high << 4) | low
        })
        .collect()
}

fn temporary_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after the Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("whisper-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).expect("unique temporary directory created");
    path
}
