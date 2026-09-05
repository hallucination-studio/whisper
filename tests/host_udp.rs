//! Production UDP admission through raw fact A and the restricted local query.

use std::fs;
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use whisper::{
    AdmissionLimits, AuthenticatedBytesPerSecond, BootGeneration, DatagramBytes, DeploymentId,
    DeviceId, Host, KeyEpoch, MessageSequence, NativeFrameKind, NativeFrameRoute, PacketsPerSecond,
    RawLossKind, RejectReason, ReplayWindowPackets, Store,
};

const KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const DEVICE_ID: u64 = 0x0102_0304_0506_0708;
const KEY_EPOCH: u16 = 7;

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
    let route = NativeFrameRoute::load(
        sender.local_addr().unwrap().ip(),
        device_id(),
        key_epoch(),
        admission_limits(1_000),
        secret_root,
    )
    .expect("exact route is valid");
    Host::builder(store, deployment("lab"), "127.0.0.1:0".parse().unwrap())
        .route(route)
        .start()
        .expect("Host starts")
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
