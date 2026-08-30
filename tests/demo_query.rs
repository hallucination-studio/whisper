//! Read-only Demo topology and signal query behavior.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ciborium::{de::from_reader, ser::into_writer, value::Value};
use rusqlite::Connection;
use serde_json::json;
use sha2::{Digest, Sha256};
use whisper::{
    CapturedDatagram, ErrorEnvelope, Metric, QueryLimits, QueryStore, SessionTime, SignalPath,
    SignalQuery, SignalRange, SignalSelection, parse_config,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct DemoFixture {
    root: PathBuf,
    database: PathBuf,
    config: whisper::Config,
}

impl DemoFixture {
    fn new() -> Self {
        Self::build(false)
    }

    fn with_unpinned_first_channel() -> Self {
        Self::build(true)
    }

    fn build(unpin_first_channel: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "whisper-demo-query-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create fixture root");
        let managed_root = root.join("managed");
        create_directory(&managed_root, 0o700);
        let database = managed_root.join("demo.sqlite3");
        let secret_root = root.join("secrets");
        create_directory(&secret_root, 0o700);
        for (device, byte) in [(1, 0x11), (2, 0x22)] {
            let device_root = secret_root.join(format!("device-{device}"));
            create_directory(&device_root, 0o700);
            let key = device_root.join("key-1.bin");
            fs::write(&key, [byte; 32]).expect("write epoch key");
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
                .expect("protect epoch key");
        }
        let first_capability = capability_body([0x01; 32], [0x22; 32], 1024);
        let second_capability = capability_body([0x03; 32], [0x44; 32], 2048);
        let mut source = include_str!("fixtures/config/valid-two-esp32.toml").to_owned();
        if unpin_first_channel {
            source = source.replacen("expected = 1", "", 1);
        }
        let source = source
            .replace(
                "0202020202020202020202020202020202020202020202020202020202020202",
                &encode_hex(&first_capability[..32]),
            )
            .replace(
                "0404040404040404040404040404040404040404040404040404040404040404",
                &encode_hex(&second_capability[..32]),
            )
            .replace(
                "secret_root = \"./data/secrets\"",
                &format!("secret_root = \"{}\"", secret_root.display()),
            )
            .replace(
                "database_path = \"./data/whisper.sqlite3\"",
                &format!("database_path = \"{}\"", database.display()),
            );
        let config = parse_config(&source).expect("parse Demo configuration");
        Self { root, database, config }
    }
}

impl Drop for DemoFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_directory(path: &Path, mode: u32) {
    fs::create_dir(path).expect("create protected directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("set protected directory mode");
}

fn signal_selection(session: &str, sensor: &str, link: &str) -> SignalSelection {
    SignalSelection::try_new(session, sensor, link).expect("signal selection")
}

fn capability_body(
    firmware_digest: [u8; 32],
    abi_digest: [u8; 32],
    datagram_budget_bytes: u16,
) -> Vec<u8> {
    let mut descriptor = [0_u8; 79];
    descriptor[..9].copy_from_slice(&[1, 1, 1, 1, 1, 1, 1, 32, 0x07]);
    descriptor[9..11].copy_from_slice(&612_u16.to_le_bytes());
    descriptor[11..13].copy_from_slice(&705_u16.to_le_bytes());
    descriptor[13..15].copy_from_slice(&datagram_budget_bytes.to_le_bytes());
    descriptor[15..47].copy_from_slice(&firmware_digest);
    descriptor[47..].copy_from_slice(&abi_digest);
    let digest = Sha256::digest(descriptor);
    digest.into_iter().chain((descriptor.len() as u16).to_le_bytes()).chain(descriptor).collect()
}

fn csi_body(capability_digest: &[u8], source_mac: [u8; 6], channel: u8) -> Vec<u8> {
    csi_body_with_samples(capability_digest, source_mac, channel, 0, [1, 2, 3, 4, 5, 6])
}

fn csi_body_with_samples(
    capability_digest: &[u8],
    source_mac: [u8; 6],
    channel: u8,
    first_invalid_bytes: u8,
    raw: [u8; 6],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(capability_digest);
    body.extend_from_slice(&1_u64.to_le_bytes());
    body.extend_from_slice(&2_u32.to_le_bytes());
    body.extend_from_slice(&3_u64.to_le_bytes());
    body.extend_from_slice(&source_mac);
    body.extend_from_slice(&[channel, 0, 1, 1, 0, (-42_i8) as u8, (-95_i8) as u8, 6, 0, 0]);
    body.extend_from_slice(&[first_invalid_bytes, 0, 1]);
    body.extend_from_slice(&6_u16.to_le_bytes());
    body.extend_from_slice(&3_u16.to_le_bytes());
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&3_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&raw);
    body
}

#[derive(Clone, Copy)]
struct TestEpoch<'a> {
    key: &'a [u8; 32],
    device_id: u64,
    peer: &'a str,
    boot_generation: u32,
}

fn submit_packet(
    run: &mut whisper::CaptureRun,
    epoch: TestEpoch<'_>,
    kind: u8,
    message_sequence: u64,
    receive: Instant,
    body: &[u8],
) {
    let datagram = CapturedDatagram::new(
        epoch.peer.parse().expect("peer"),
        receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw_for_epoch(
            epoch.key,
            epoch.device_id,
            epoch.boot_generation,
            kind,
            message_sequence,
            body,
        ),
    );
    let _ =
        run.try_submit(datagram).expect("submit Demo packet").wait().expect("commit Demo packet");
}

fn seal_raw_for(
    key: &[u8; 32],
    device_id: u64,
    kind: u8,
    message_sequence: u64,
    body: &[u8],
) -> Box<[u8]> {
    seal_raw_for_epoch(key, device_id, 1, kind, message_sequence, body)
}

fn seal_raw_for_epoch(
    key: &[u8; 32],
    device_id: u64,
    boot_generation: u32,
    kind: u8,
    message_sequence: u64,
    body: &[u8],
) -> Box<[u8]> {
    const HEADER_BYTES: usize = 32;
    let mut header = [0_u8; HEADER_BYTES];
    header[0] = 1;
    header[1] = kind;
    header[2..4].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    header[4..12].copy_from_slice(&device_id.to_le_bytes());
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[16..20].copy_from_slice(&boot_generation.to_le_bytes());
    header[20..28].copy_from_slice(&message_sequence.to_le_bytes());
    header[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&boot_generation.to_le_bytes());
    nonce[4..].copy_from_slice(&message_sequence.to_le_bytes());
    let ciphertext = Aes256Gcm::new_from_slice(key)
        .expect("test key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &header })
        .expect("seal test datagram");
    header.into_iter().chain(ciphertext).collect::<Vec<_>>().into_boxed_slice()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn commit_one_observation(
    run: &mut whisper::CaptureRun,
    key: &[u8; 32],
    device_id: u64,
    peer: &str,
    capability: &[u8],
    source_mac: [u8; 6],
    channel: u8,
) {
    let first_receive = Instant::now();
    for (offset, (kind, body)) in
        [(1, capability.to_vec()), (2, csi_body(&capability[..32], source_mac, channel))]
            .into_iter()
            .enumerate()
    {
        let datagram = CapturedDatagram::new(
            peer.parse().expect("peer"),
            first_receive + Duration::from_nanos(offset as u64),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            seal_raw_for(key, device_id, kind, offset as u64 + 1, &body),
        );
        let _ = run
            .try_submit(datagram)
            .expect("submit Demo packet")
            .wait()
            .expect("commit Demo packet");
    }
}

#[test]
fn empty_store_topology_comes_only_from_the_persisted_manifest_snapshot() {
    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let topology = QueryStore::open(&fixture.database)
        .expect("open Query Store")
        .topology()
        .expect("read topology snapshot");
    let actual = serde_json::to_value(topology).expect("serialize topology DTO");
    let store_id =
        actual["receipt"]["projection_commit"]["store_id"].as_str().expect("hex Store ID");
    assert_eq!(store_id.len(), 64);
    assert!(store_id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(
        actual,
        json!({
            "http_schema_version": 1,
            "kind": "ok",
            "resource": "topology",
            "data": {
                "deployment": "lab",
                "sessions": [],
                "spaces": [{"id": "room"}],
                "sensors": [
                    {"id": "sensor-a", "hardware_kind": "esp32-s3", "device_id": "1"},
                    {"id": "sensor-b", "hardware_kind": "esp32-s3", "device_id": "2"}
                ],
                "links": [
                    {
                        "id": "link-a", "space": "room", "transmitter": "tx-a",
                        "receiver": "sensor-a", "profiles": []
                    },
                    {
                        "id": "link-b", "space": "room", "transmitter": "tx-b",
                        "receiver": "sensor-b", "profiles": []
                    }
                ]
            },
            "receipt": {"projection_commit": {"store_id": store_id, "sequence": "0"}}
        })
    );
}

#[test]
fn query_store_open_is_non_creating() {
    let root = std::env::temp_dir().join(format!(
        "whisper-missing-query-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("create query root");
    let database = root.join("missing.sqlite3");
    assert!(QueryStore::open(&database).is_err());
    assert!(!database.exists());
    fs::remove_dir(root).expect("remove query root");
}

#[test]
fn query_store_rejects_store_replacement_across_snapshots() {
    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize original Demo Store");
    let store = QueryStore::open(&fixture.database).expect("open original Query Store");
    let replaced = fixture.root.join("replaced.sqlite3");
    fs::rename(&fixture.database, &replaced).expect("move original Store aside");
    for (suffix, name) in [("-wal", "replaced.sqlite3-wal"), ("-shm", "replaced.sqlite3-shm")] {
        let mut companion = fixture.database.as_os_str().to_os_string();
        companion.push(suffix);
        let companion = PathBuf::from(companion);
        if companion.exists() {
            fs::rename(&companion, fixture.root.join(name)).expect("move original companion aside");
        }
    }
    whisper::init_admission(&fixture.config).expect("initialize replacement Demo Store");

    assert!(store.topology().is_err(), "a QueryStore must remain pinned to its opened Store");
}

#[test]
fn topology_orders_visible_sessions_and_profiles_across_dynamic_links() {
    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let first_capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let second_capability = capability_body([0x03; 32], [0x44; 32], 2048);

    let mut first = whisper::serve(&fixture.config).expect("start first Capture Run");
    let first_session = first.session_id().to_owned();
    commit_one_observation(
        &mut first,
        &[0x11; 32],
        1,
        "192.0.2.10:5000",
        &first_capability,
        [2, 0, 0, 0, 0, 10],
        1,
    );
    first.shutdown().expect("stop first Capture Run");

    let mut second = whisper::serve(&fixture.config).expect("start second Capture Run");
    let second_session = second.session_id().to_owned();
    commit_one_observation(
        &mut second,
        &[0x22; 32],
        2,
        "192.0.2.11:5000",
        &second_capability,
        [2, 0, 0, 0, 0, 11],
        6,
    );
    second.shutdown().expect("stop second Capture Run");

    let actual = serde_json::to_value(
        QueryStore::open(&fixture.database)
            .expect("open Query Store")
            .topology()
            .expect("read topology snapshot"),
    )
    .expect("serialize topology DTO");
    let mut expected_sessions = vec![first_session, second_session];
    expected_sessions.sort();
    assert_eq!(actual["data"]["sessions"], json!(expected_sessions));
    assert_eq!(actual["receipt"]["projection_commit"]["sequence"], "4");
    let links = actual["data"]["links"].as_array().expect("topology links");
    assert_eq!(
        (links[0]["id"].as_str(), links[1]["id"].as_str()),
        (Some("link-a"), Some("link-b"))
    );
    for link in links {
        let profiles = link["profiles"].as_array().expect("link profiles");
        assert_eq!(profiles.len(), 1);
        let profile = profiles[0].as_str().expect("hex profile");
        assert_eq!(profile.len(), 64);
        assert!(profile.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }
    assert_ne!(links[0]["profiles"], links[1]["profiles"]);
}

#[test]
fn raw_i_signals_preserve_native_axes_cells_and_same_snapshot_receipts() {
    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let mut run = whisper::serve(&fixture.config).expect("start Capture Run");
    let session = run.session_id().to_owned();
    commit_one_observation(
        &mut run,
        &[0x11; 32],
        1,
        "192.0.2.10:5000",
        &capability,
        [2, 0, 0, 0, 0, 10],
        1,
    );
    run.shutdown().expect("stop Capture Run");

    let query = SignalQuery::builder(
        signal_selection(&session, "sensor-a", "link-a"),
        SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(u64::MAX))
            .expect("query range"),
        Metric::I,
    )
    .max_time_buckets(16)
    .build()
    .expect("signal query");
    let response = QueryStore::open(&fixture.database)
        .expect("open Query Store")
        .signals(&query, QueryLimits::try_new(1024, 64).expect("query limits"))
        .expect("read signals snapshot");
    let actual = serde_json::to_value(response).expect("serialize signals DTO");

    assert_eq!(actual["kind"], "ok");
    assert_eq!(actual["resource"], "signals");
    assert_eq!(actual["data"]["metric"], "i");
    let tiles = actual["data"]["tiles"].as_array().expect("signal tiles");
    assert_eq!(tiles.len(), 1);
    let tile = &tiles[0];
    assert_eq!(tile["stream"]["key"]["sensor"], "sensor-a");
    assert_eq!(tile["stream"]["key"]["link"], "link-a");
    assert_eq!(tile["stream"]["device_epoch"]["device_id"], "1");
    assert_eq!(tile["stream"]["device_epoch"]["boot_generation"], 1);
    assert_eq!(tile["path_axis"], json!([{"kind": "raw_path_ordinal", "ordinal": 0}]));
    assert_eq!(tile["sample_axis"], json!({"kind": "opaque_sample_ordinal", "count": 3}));
    assert_eq!(tile["order"], "time_path_coordinate");
    assert_eq!(tile["aggregation"], "raw");
    assert_eq!(
        tile["cells"],
        json!([
            {"kind": "raw", "value": 2.0},
            {"kind": "raw", "value": 4.0},
            {"kind": "raw", "value": 6.0}
        ])
    );
    assert_eq!(tile["missing_spans"], json!([]));
    assert_eq!(tile["receipt"], actual["receipt"]);
    assert_eq!(actual["receipt"]["session_id"], session);
    assert_eq!(actual["receipt"]["first_record_seq"], "0");
    assert_eq!(actual["receipt"]["last_record_seq"], "1");
    assert_eq!(actual["receipt"]["projection_commit"]["sequence"], "2");
    assert_eq!(actual["receipt"]["decoder_version"], "native-frame-v1");
    assert_eq!(actual["receipt"]["conditioning_version"], "amplitude-v1");
    assert_eq!(actual["receipt"]["algorithm_version"], "demo-native-coordinate-v1");

    let store = QueryStore::open(&fixture.database).expect("reopen Query Store");
    let range = SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(u64::MAX))
        .expect("metric range");
    for (metric, expected) in
        [(Metric::Q, 1.0), (Metric::Amplitude, 5_f64.sqrt()), (Metric::Phase, 1_f64.atan2(2.0))]
    {
        let response = serde_json::to_value(
            store
                .signals(
                    &SignalQuery::builder(
                        signal_selection(&session, "sensor-a", "link-a"),
                        range,
                        metric,
                    )
                    .max_time_buckets(16)
                    .build()
                    .expect("metric query"),
                    QueryLimits::try_new(1024, 64).expect("metric limits"),
                )
                .expect("read metric signals"),
        )
        .expect("serialize metric signals");
        let value =
            response["data"]["tiles"][0]["cells"][0]["value"].as_f64().expect("raw metric value");
        assert!((value - expected).abs() < f64::EPSILON);
    }
}

#[test]
fn signals_apply_empty_selectors_aggregation_and_phase_budget_without_fabrication() {
    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let mut run = whisper::serve(&fixture.config).expect("start Capture Run");
    let session = run.session_id().to_owned();
    commit_one_observation(
        &mut run,
        &[0x11; 32],
        1,
        "192.0.2.10:5000",
        &capability,
        [2, 0, 0, 0, 0, 10],
        1,
    );
    run.shutdown().expect("stop Capture Run");
    let store = QueryStore::open(&fixture.database).expect("open Query Store");
    let range = SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(u64::MAX))
        .expect("query range");

    let empty = store
        .signals(
            &SignalQuery::builder(
                signal_selection(&session, "sensor-b", "link-b"),
                range,
                Metric::I,
            )
            .max_time_buckets(1)
            .build()
            .expect("empty query"),
            QueryLimits::try_new(1024, 64).expect("query limits"),
        )
        .expect("read empty result");
    let empty = serde_json::to_value(empty).expect("serialize empty result");
    assert_eq!(empty["kind"], "empty");
    assert_eq!(empty["resource"], "signals");
    assert_eq!(empty["receipt"]["session_id"], session);

    let missing_path =
        SignalQuery::builder(signal_selection(&session, "sensor-a", "link-a"), range, Metric::I)
            .max_time_buckets(1)
            .path(SignalPath::RawPathOrdinal { ordinal: 1 })
            .build()
            .expect("path query");
    let missing_path = serde_json::to_value(
        store
            .signals(&missing_path, QueryLimits::try_new(1024, 64).expect("query limits"))
            .expect("read missing path"),
    )
    .expect("serialize missing path");
    assert_eq!(missing_path["kind"], "empty");

    let aggregate = store
        .signals(
            &SignalQuery::builder(
                signal_selection(&session, "sensor-a", "link-a"),
                range,
                Metric::Amplitude,
            )
            .max_time_buckets(1)
            .build()
            .expect("aggregate query"),
            QueryLimits::try_new(2, 64).expect("query limits"),
        )
        .expect("read aggregate result");
    let aggregate = serde_json::to_value(aggregate).expect("serialize aggregate result");
    let tile = &aggregate["data"]["tiles"][0];
    assert_eq!(tile["aggregation"], "min_max_mean_rms_count");
    assert_eq!(tile["time_axis"], json!(["0"]));
    let cells = tile["cells"].as_array().expect("aggregate cells");
    assert_eq!(cells.len(), 3);
    for cell in cells {
        assert_eq!(cell["kind"], "min_max_mean_rms_count");
        assert_eq!(cell["count"], 1);
        assert_eq!(cell["minimum"], cell["maximum"]);
        assert_eq!(cell["minimum"], cell["mean"]);
        assert_eq!(cell["minimum"], cell["rms"]);
    }

    let phase = store
        .signals(
            &SignalQuery::builder(
                signal_selection(&session, "sensor-a", "link-a"),
                range,
                Metric::Phase,
            )
            .max_time_buckets(1)
            .build()
            .expect("phase query"),
            QueryLimits::try_new(2, 64).expect("query limits"),
        )
        .expect("read phase error");
    let phase = serde_json::to_value(phase).expect("serialize phase error");
    assert_eq!(phase["kind"], "error");
    assert_eq!(phase["error"]["code"], "phase_over_budget");
    assert_eq!(phase["error"]["max_signal_points"], "2");
}

#[test]
fn invalid_samples_and_valid_zero_remain_distinct_with_duplicate_timestamp_ordering() {
    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let mut run = whisper::serve(&fixture.config).expect("start Capture Run");
    let session = run.session_id().to_owned();
    commit_one_observation(
        &mut run,
        &[0x11; 32],
        1,
        "192.0.2.10:5000",
        &capability,
        [2, 0, 0, 0, 0, 10],
        1,
    );
    let equal_receive = Instant::now();
    submit_packet(
        &mut run,
        TestEpoch { key: &[0x11; 32], device_id: 1, peer: "192.0.2.10:5000", boot_generation: 1 },
        2,
        3,
        equal_receive,
        &csi_body_with_samples(&capability[..32], [2, 0, 0, 0, 0, 10], 1, 4, [7, 8, 9, 10, 11, 12]),
    );
    submit_packet(
        &mut run,
        TestEpoch { key: &[0x11; 32], device_id: 1, peer: "192.0.2.10:5000", boot_generation: 1 },
        2,
        4,
        equal_receive,
        &csi_body_with_samples(&capability[..32], [2, 0, 0, 0, 0, 10], 1, 0, [0, 0, 3, 4, 5, 6]),
    );
    run.shutdown().expect("stop Capture Run");
    let store = QueryStore::open(&fixture.database).expect("open Query Store");
    let range = SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(u64::MAX))
        .expect("query range");
    let limits = QueryLimits::try_new(1024, 64).expect("query limits");

    let i = serde_json::to_value(
        store
            .signals(
                &SignalQuery::builder(
                    signal_selection(&session, "sensor-a", "link-a"),
                    range,
                    Metric::I,
                )
                .max_time_buckets(8)
                .build()
                .expect("I query"),
                limits,
            )
            .expect("read I signals"),
    )
    .expect("serialize I signals");
    let i_tile = &i["data"]["tiles"][0];
    assert_eq!(i_tile["time_axis"][1], i_tile["time_axis"][2]);
    let i_cells = i_tile["cells"].as_array().expect("I cells");
    assert!(i_cells[3].is_null());
    assert!(i_cells[4].is_null());
    assert_eq!(i_cells[6], json!({"kind": "raw", "value": 0.0}));

    let phase = serde_json::to_value(
        store
            .signals(
                &SignalQuery::builder(
                    signal_selection(&session, "sensor-a", "link-a"),
                    range,
                    Metric::Phase,
                )
                .max_time_buckets(8)
                .build()
                .expect("phase query"),
                limits,
            )
            .expect("read phase signals"),
    )
    .expect("serialize phase signals");
    let phase_cells = phase["data"]["tiles"][0]["cells"].as_array().expect("phase cells");
    assert!(phase_cells[3].is_null());
    assert!(phase_cells[4].is_null());
    assert!(phase_cells[6].is_null(), "valid zero vector has no phase direction");

    let aggregate = serde_json::to_value(
        store
            .signals(
                &SignalQuery::builder(
                    signal_selection(&session, "sensor-a", "link-a"),
                    range,
                    Metric::I,
                )
                .max_time_buckets(1)
                .build()
                .expect("aggregate query"),
                QueryLimits::try_new(2, 64).expect("aggregate limits"),
            )
            .expect("read aggregate signals"),
    )
    .expect("serialize aggregate signals");
    let aggregate_cells =
        aggregate["data"]["tiles"][0]["cells"].as_array().expect("aggregate cells");
    assert_eq!(aggregate_cells[0]["count"], 2);
    assert_eq!(aggregate_cells[0]["mean"], 1.0);
    assert_eq!(aggregate_cells[1]["count"], 2);
    assert_eq!(aggregate_cells[2]["count"], 3);
}

#[test]
fn aggregation_uses_exact_half_open_buckets_and_ordered_valid_samples() {
    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let mut run = whisper::serve(&fixture.config).expect("start Capture Run");
    let session = run.session_id().to_owned();
    let base = Instant::now() + Duration::from_millis(1);
    let epoch =
        TestEpoch { key: &[0x11; 32], device_id: 1, peer: "192.0.2.10:5000", boot_generation: 1 };
    submit_packet(&mut run, epoch, 1, 1, base, &capability);
    for (index, raw) in [[1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], [13, 14, 15, 16, 17, 18]]
        .into_iter()
        .enumerate()
    {
        submit_packet(
            &mut run,
            epoch,
            2,
            index as u64 + 2,
            base + Duration::from_nanos(index as u64 * 10 + 1),
            &csi_body_with_samples(&capability[..32], [2, 0, 0, 0, 0, 10], 1, 0, raw),
        );
    }
    run.shutdown().expect("stop Capture Run");
    let store = QueryStore::open(&fixture.database).expect("open Query Store");
    let full_range =
        SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(u64::MAX))
            .expect("full range");
    let raw = serde_json::to_value(
        store
            .signals(
                &SignalQuery::builder(
                    signal_selection(&session, "sensor-a", "link-a"),
                    full_range,
                    Metric::I,
                )
                .max_time_buckets(8)
                .build()
                .expect("raw query"),
                QueryLimits::try_new(1024, 64).expect("raw limits"),
            )
            .expect("read raw signals"),
    )
    .expect("serialize raw signals");
    let raw_axis = raw["data"]["tiles"][0]["time_axis"].as_array().expect("raw time axis");
    let first: u64 = raw_axis[0].as_str().expect("first time").parse().expect("first u64");
    let last: u64 = raw_axis[2].as_str().expect("last time").parse().expect("last u64");
    assert_eq!(last - first, 20);
    let to = last.checked_add(1).expect("bounded query end");
    let range = SignalRange::try_new(SessionTime::from_nanos(first), SessionTime::from_nanos(to))
        .expect("aggregate range");

    let aggregate = serde_json::to_value(
        store
            .signals(
                &SignalQuery::builder(
                    signal_selection(&session, "sensor-a", "link-a"),
                    range,
                    Metric::I,
                )
                .max_time_buckets(2)
                .build()
                .expect("aggregate query"),
                QueryLimits::try_new(2, 64).expect("aggregate limits"),
            )
            .expect("read aggregate signals"),
    )
    .expect("serialize aggregate signals");
    let tile = &aggregate["data"]["tiles"][0];
    assert_eq!(tile["time_axis"], json!([first.to_string(), (first + 11).to_string()]));
    let cells = tile["cells"].as_array().expect("aggregate cells");
    assert_eq!(cells.len(), 6);
    assert_eq!(cells[0]["minimum"], 2.0);
    assert_eq!(cells[0]["maximum"], 8.0);
    assert_eq!(cells[0]["mean"], 5.0);
    assert_eq!(cells[0]["count"], 2);
    let rms = cells[0]["rms"].as_f64().expect("aggregate RMS");
    assert!((rms - 34_f64.sqrt()).abs() < f64::EPSILON);
    assert_eq!(cells[3]["minimum"], 14.0);
    assert_eq!(cells[3]["maximum"], 14.0);
    assert_eq!(cells[3]["count"], 1);
}

#[test]
fn omitted_and_explicit_profile_selectors_preserve_separate_ordered_tiles() {
    let fixture = DemoFixture::with_unpinned_first_channel();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let mut run = whisper::serve(&fixture.config).expect("start Capture Run");
    let session = run.session_id().to_owned();
    let base = Instant::now();
    let epoch =
        TestEpoch { key: &[0x11; 32], device_id: 1, peer: "192.0.2.10:5000", boot_generation: 1 };
    submit_packet(&mut run, epoch, 1, 1, base, &capability);
    for (offset, channel) in [1, 6].into_iter().enumerate() {
        submit_packet(
            &mut run,
            epoch,
            2,
            offset as u64 + 2,
            base + Duration::from_nanos(offset as u64 + 1),
            &csi_body(&capability[..32], [2, 0, 0, 0, 0, 10], channel),
        );
    }
    run.shutdown().expect("stop Capture Run");
    let store = QueryStore::open(&fixture.database).expect("open Query Store");
    let range = SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(u64::MAX))
        .expect("query range");
    let limits = QueryLimits::try_new(1024, 64).expect("query limits");
    let selection = signal_selection(&session, "sensor-a", "link-a");
    let query = SignalQuery::builder(selection.clone(), range, Metric::I)
        .max_time_buckets(8)
        .build()
        .expect("multi-profile query");
    let all = serde_json::to_value(store.signals(&query, limits).expect("read all profiles"))
        .expect("serialize all profiles");
    let tiles = all["data"]["tiles"].as_array().expect("profile tiles");
    assert_eq!(tiles.len(), 2);
    let first_profile = tiles[0]["profile"].as_str().expect("first profile");
    let second_profile = tiles[1]["profile"].as_str().expect("second profile");
    assert!(first_profile < second_profile);
    assert_ne!(first_profile, second_profile);

    let selected = SignalQuery::builder(selection.clone(), range, Metric::I)
        .max_time_buckets(8)
        .profile(second_profile)
        .build()
        .expect("profile selector");
    let selected =
        serde_json::to_value(store.signals(&selected, limits).expect("read selected profile"))
            .expect("serialize selected profile");
    let selected_tiles = selected["data"]["tiles"].as_array().expect("selected tiles");
    assert_eq!(selected_tiles.len(), 1);
    assert_eq!(selected_tiles[0]["profile"], second_profile);

    let absent = SignalQuery::builder(selection, range, Metric::I)
        .max_time_buckets(8)
        .profile("0000000000000000000000000000000000000000000000000000000000000000")
        .build()
        .expect("absent profile selector");
    let absent = serde_json::to_value(store.signals(&absent, limits).expect("read absent profile"))
        .expect("serialize absent profile");
    assert_eq!(absent["kind"], "empty");
}

#[test]
fn signals_keep_device_epochs_as_separate_strictly_ordered_tiles() {
    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let mut run = whisper::serve(&fixture.config).expect("start Capture Run");
    let session = run.session_id().to_owned();
    let base = Instant::now();
    for boot_generation in [1, 2] {
        let epoch =
            TestEpoch { key: &[0x11; 32], device_id: 1, peer: "192.0.2.10:5000", boot_generation };
        submit_packet(
            &mut run,
            epoch,
            1,
            1,
            base + Duration::from_nanos(u64::from(boot_generation) * 2),
            &capability,
        );
        submit_packet(
            &mut run,
            epoch,
            2,
            2,
            base + Duration::from_nanos(u64::from(boot_generation) * 2 + 1),
            &csi_body(&capability[..32], [2, 0, 0, 0, 0, 10], 1),
        );
    }
    run.shutdown().expect("stop Capture Run");
    let response = QueryStore::open(&fixture.database)
        .expect("open Query Store")
        .signals(
            &SignalQuery::builder(
                signal_selection(&session, "sensor-a", "link-a"),
                SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(u64::MAX))
                    .expect("query range"),
                Metric::I,
            )
            .max_time_buckets(8)
            .build()
            .expect("epoch query"),
            QueryLimits::try_new(1024, 64).expect("query limits"),
        )
        .expect("read epoch tiles");
    let response = serde_json::to_value(response).expect("serialize epoch tiles");
    let tiles = response["data"]["tiles"].as_array().expect("epoch tiles");
    assert_eq!(tiles.len(), 2);
    assert_eq!(tiles[0]["stream"]["device_epoch"]["boot_generation"], 1);
    assert_eq!(tiles[1]["stream"]["device_epoch"]["boot_generation"], 2);
    assert_eq!(tiles[0]["profile"], tiles[1]["profile"]);
}

#[test]
fn invalid_absent_and_projection_failures_have_canonical_error_shapes() {
    assert!(
        SignalRange::try_new(SessionTime::from_nanos(2), SessionTime::from_nanos(1))
            .expect_err("reversed range")
            .is_invalid_request()
    );
    assert!(QueryLimits::try_new(0, 1).expect_err("zero point limit").is_invalid_request());
    let range = SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(1))
        .expect("query range");
    assert!(
        SignalQuery::builder(signal_selection("session", "sensor", "link"), range, Metric::I)
            .max_time_buckets(1)
            .profile("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .build()
            .expect_err("uppercase Profile identity")
            .is_invalid_request()
    );

    let fixture = DemoFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Demo Store");
    let store = QueryStore::open(&fixture.database).expect("open Query Store");
    let absent = store
        .signals(
            &SignalQuery::builder(
                signal_selection("capture-00000000000000000000000000000000", "sensor-a", "link-a"),
                range,
                Metric::I,
            )
            .max_time_buckets(1)
            .build()
            .expect("absent session query"),
            QueryLimits::try_new(1, 1).expect("query limits"),
        )
        .expect("read absent session");
    let absent = serde_json::to_value(absent).expect("serialize absent session");
    assert_eq!(absent["kind"], "error");
    assert_eq!(absent["error"]["code"], "range_unavailable");
    assert!(absent["error"].get("available_from").is_none());

    assert_eq!(
        serde_json::to_value(ErrorEnvelope::projection_failed())
            .expect("serialize projection error"),
        json!({
            "http_schema_version": 1,
            "kind": "error",
            "error": {
                "code": "projection_failed",
                "message": "committed projection could not be read"
            }
        })
    );
}

#[test]
fn queries_fail_closed_on_noncanonical_manifest_and_projection_envelope_mismatch() {
    let topology_fixture = DemoFixture::new();
    whisper::init_admission(&topology_fixture.config).expect("initialize topology Store");
    let connection = Connection::open(&topology_fixture.database).expect("open topology Store");
    let topology: Vec<u8> = connection
        .query_row("SELECT topology_manifest_cbor FROM store_state", [], |row| row.get(0))
        .expect("read topology manifest");
    let mut value: Value = from_reader(topology.as_slice()).expect("decode topology manifest");
    let Value::Map(entries) = &mut value else { panic!("topology root must be a map") };
    let links = entries
        .iter_mut()
        .find_map(|(key, value)| (key == &Value::Text("links".to_owned())).then_some(value))
        .expect("topology links");
    let Value::Array(links) = links else { panic!("topology links must be an array") };
    links.reverse();
    let mut noncanonical = Vec::new();
    into_writer(&value, &mut noncanonical).expect("encode noncanonical topology");
    let digest: [u8; 32] = Sha256::digest(&noncanonical).into();
    connection
        .execute(
            "UPDATE store_state SET topology_manifest_cbor = ?1, topology_manifest_digest = ?2",
            rusqlite::params![noncanonical, digest],
        )
        .expect("install noncanonical topology");
    drop(connection);
    assert!(
        QueryStore::open(&topology_fixture.database).expect("open Query Store").topology().is_err()
    );

    let signal_fixture = DemoFixture::new();
    whisper::init_admission(&signal_fixture.config).expect("initialize signal Store");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let mut run = whisper::serve(&signal_fixture.config).expect("start Capture Run");
    let session = run.session_id().to_owned();
    commit_one_observation(
        &mut run,
        &[0x11; 32],
        1,
        "192.0.2.10:5000",
        &capability,
        [2, 0, 0, 0, 0, 10],
        1,
    );
    run.shutdown().expect("stop Capture Run");
    let connection = Connection::open(&signal_fixture.database).expect("open signal Store");
    connection
        .execute("UPDATE csi_observations SET decoder_version = 'mismatched-decoder'", [])
        .expect("corrupt projection envelope");
    let query = SignalQuery::builder(
        signal_selection(&session, "sensor-a", "link-a"),
        SignalRange::try_new(SessionTime::from_nanos(0), SessionTime::from_nanos(u64::MAX))
            .expect("query range"),
        Metric::I,
    )
    .max_time_buckets(8)
    .build()
    .expect("signal query");
    let store = QueryStore::open(&signal_fixture.database).expect("open Query Store");
    let limits = QueryLimits::try_new(1024, 64).expect("query limits");
    assert!(store.signals(&query, limits).is_err());

    connection
        .execute("UPDATE csi_observations SET decoder_version = 'native-frame-v1'", [])
        .expect("restore projection decoder");
    connection
        .execute(
            "UPDATE packet_records SET disposition = 'health_committed'
             WHERE record_seq = (SELECT record_seq FROM csi_observations)",
            [],
        )
        .expect("corrupt packet disposition");
    assert!(store.signals(&query, limits).is_err());

    connection
        .execute(
            "UPDATE packet_records SET disposition = 'csi_committed'
             WHERE record_seq = (SELECT record_seq FROM csi_observations)",
            [],
        )
        .expect("restore packet disposition");
    let observation: Vec<u8> = connection
        .query_row("SELECT observation_cbor FROM csi_observations", [], |row| row.get(0))
        .expect("read observation CBOR");
    let mut observation: Value = from_reader(observation.as_slice()).expect("decode observation");
    let Value::Map(entries) = &mut observation else { panic!("observation root must be a map") };
    entries.reverse();
    let mut noncanonical_observation = Vec::new();
    into_writer(&observation, &mut noncanonical_observation)
        .expect("encode noncanonical observation");
    connection
        .execute("UPDATE csi_observations SET observation_cbor = ?1", [noncanonical_observation])
        .expect("install noncanonical observation");
    assert!(store.signals(&query, limits).is_err());
}
