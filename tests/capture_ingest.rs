//! Bounded capture ingest behavior through the Capture runtime interface.

#![cfg(all(unix, feature = "ingest-test-hooks"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "ingest-test-hooks")]
use std::sync::mpsc;
#[cfg(feature = "ingest-test-hooks")]
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ciborium::{de::from_reader, ser::into_writer, value::Value};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use whisper::{
    CaptureRecordSequence, CapturedDatagram, CommitError, CommitOutcome, PacketDisposition,
    ProjectionSequence, SubmitError, parse_config,
};

const HEADER_BYTES: usize = 32;
const KEY: [u8; 32] = [0x11; 32];
const EXPECTED_PROFILE_ID: [u8; 32] = [
    0x61, 0x97, 0x1b, 0xc9, 0x47, 0x6b, 0xde, 0xac, 0xd7, 0x70, 0x3e, 0x35, 0x16, 0x45, 0x7d, 0xf6,
    0x20, 0x14, 0x7f, 0x73, 0x15, 0x7c, 0xd1, 0xd4, 0xad, 0x83, 0x6f, 0xb9, 0xc7, 0xb7, 0x4b, 0xe2,
];
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
type RejectedStoreEffects = (u64, Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>);

struct CaptureFixture {
    root: PathBuf,
    config: whisper::Config,
    database: PathBuf,
}

impl CaptureFixture {
    fn new() -> Self {
        Self::from_source(include_str!("fixtures/config/valid-two-esp32.toml").to_owned())
    }

    fn with_first_sensor_raw_limit(limit: u16) -> Self {
        let source = include_str!("fixtures/config/valid-two-esp32.toml").replacen(
            "maximum_raw_csi_bytes = 612",
            &format!("maximum_raw_csi_bytes = {limit}"),
            1,
        );
        Self::from_source(source)
    }

    fn with_first_capability_budget(budget: u16) -> Self {
        let capability = capability_body([0x01; 32], [0x22; 32], budget);
        let source = include_str!("fixtures/config/valid-two-esp32.toml").replace(
            "0202020202020202020202020202020202020202020202020202020202020202",
            &encode_hex(&capability[..32]),
        );
        Self::from_source(source)
    }

    fn with_first_route_packet_rate(limit: u32) -> Self {
        let source = include_str!("fixtures/config/valid-two-esp32.toml").replacen(
            "peak_packets_per_second = 100",
            &format!("peak_packets_per_second = {limit}"),
            1,
        );
        Self::from_source(source)
    }

    fn with_first_route_byte_rate(limit: u64) -> Self {
        let source = include_str!("fixtures/config/valid-two-esp32.toml").replacen(
            "maximum_authenticated_bytes_per_second = 204800",
            &format!("maximum_authenticated_bytes_per_second = {limit}"),
            1,
        );
        Self::from_source(source)
    }

    #[cfg(feature = "ingest-test-hooks")]
    fn with_writer_queue_capacity(capacity: u32) -> Self {
        let source = include_str!("fixtures/config/valid-two-esp32.toml").replace(
            "command_queue_capacity = 64",
            &format!("command_queue_capacity = {capacity}"),
        );
        Self::from_source(source)
    }

    fn from_source(source: String) -> Self {
        let root = std::env::temp_dir().join(format!(
            "whisper-ingest-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create fixture root");

        let managed_root = root.join("managed");
        create_directory(&managed_root, 0o700);
        let database = managed_root.join("host.sqlite3");

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

        let capability = capability_body([0x01; 32], [0x22; 32], 1024);
        let capability_digest = encode_hex(&capability[..32]);
        let second_capability = capability_body([0x03; 32], [0x44; 32], 2048);
        let second_capability_digest = encode_hex(&second_capability[..32]);
        let source = source
            .replace(
                "0202020202020202020202020202020202020202020202020202020202020202",
                &capability_digest,
            )
            .replace(
                "0404040404040404040404040404040404040404040404040404040404040404",
                &second_capability_digest,
            )
            .replace(
                "secret_root = \"./data/secrets\"",
                &format!("secret_root = \"{}\"", secret_root.display()),
            )
            .replace(
                "database_path = \"./data/whisper.sqlite3\"",
                &format!("database_path = \"{}\"", database.display()),
            );
        let config = parse_config(&source).expect("parse runtime configuration");
        Self { root, config, database }
    }
}

impl Drop for CaptureFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_directory(path: &Path, mode: u32) {
    fs::create_dir(path).expect("create protected directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("set protected directory mode");
}

fn seal_raw(kind: u8, boot_generation: u32, message_sequence: u64, body: &[u8]) -> Box<[u8]> {
    seal_raw_for(&KEY, 1, kind, boot_generation, message_sequence, body)
}

fn seal_raw_for(
    key: &[u8; 32],
    device_id: u64,
    kind: u8,
    boot_generation: u32,
    message_sequence: u64,
    body: &[u8],
) -> Box<[u8]> {
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

fn health_body(capability_digest: &[u8]) -> Vec<u8> {
    let mut body = vec![0_u8; 98];
    body[..32].copy_from_slice(capability_digest);
    body
}

fn csi_body(capability_digest: &[u8], source_mac: [u8; 6], channel: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(capability_digest);
    body.extend_from_slice(&1_u64.to_le_bytes());
    body.extend_from_slice(&2_u32.to_le_bytes());
    body.extend_from_slice(&3_u64.to_le_bytes());
    body.extend_from_slice(&source_mac);
    body.extend_from_slice(&[channel, 0, 1, 1, 0, (-42_i8) as u8, (-95_i8) as u8, 6, 0, 0]);
    body.extend_from_slice(&[0, 0, 1]);
    body.extend_from_slice(&6_u16.to_le_bytes());
    body.extend_from_slice(&3_u16.to_le_bytes());
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&3_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    body
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn map_value_mut<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
    let Value::Map(entries) = value else { panic!("expected CBOR map while locating {key}") };
    entries
        .iter_mut()
        .find_map(|(candidate, value)| (candidate == &Value::Text(key.to_owned())).then_some(value))
        .unwrap_or_else(|| panic!("missing CBOR key {key}"))
}

fn normalized_observation_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut root: Value = from_reader(bytes).expect("decode committed observation root");
    let observation = map_value_mut(&mut root, "observation");
    let input = map_value_mut(observation, "input");
    *map_value_mut(input, "session") =
        Value::Text("capture-00000000000000000000000000000000".to_owned());
    let timing = map_value_mut(observation, "timing");
    *map_value_mut(timing, "received_ns") = Value::Integer(42_u64.into());
    *map_value_mut(timing, "event_ns") = Value::Integer(42_u64.into());
    let mut normalized = Vec::new();
    into_writer(&root, &mut normalized).expect("encode normalized observation root");
    normalized
}

fn decode_hex_fixture(source: &str) -> Vec<u8> {
    let digits: Vec<_> = source.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    assert_eq!(digits.len() % 2, 0, "fixture hex must contain complete bytes");
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).expect("fixture high hex digit");
            let low = char::from(pair[1]).to_digit(16).expect("fixture low hex digit");
            u8::try_from((high << 4) | low).expect("decoded fixture byte")
        })
        .collect()
}

#[test]
fn authenticated_unknown_kind_commits_one_packet_cursor_and_watermark() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        Instant::now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 1, &[0xa5]),
    );

    let outcome = run.try_submit(datagram).expect("submit candidate").wait().expect("commit");
    let CommitOutcome::Committed(receipt) = outcome else {
        panic!("authenticated first packet was rejected as replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::UnknownKind);
    let record_sequence: CaptureRecordSequence = receipt.record_sequence();
    let projection_sequence: ProjectionSequence = receipt.projection_sequence();
    assert_eq!(record_sequence.get(), 0);
    assert_eq!(projection_sequence.get(), 1);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let packet: (Vec<u8>, Vec<u8>, String) = connection
        .query_row(
            "SELECT record_seq, session_time_ns, disposition FROM packet_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read packet");
    assert_eq!(packet.0, 0_u64.to_be_bytes());
    assert_eq!(packet.1.len(), 8);
    assert_eq!(packet.2, "unknown_kind");
    let (cursor, watermark): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT committed_through_record_seq,
                    (SELECT projection_commit_seq FROM store_state)
             FROM capture_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read committed cursor");
    assert_eq!(cursor, 0_u64.to_be_bytes());
    assert_eq!(watermark, 1_u64.to_be_bytes());
}

#[test]
fn replay_rejection_has_no_packet_cursor_or_watermark_effect() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let bytes = seal_raw(0x7f, 1, 1, &[0xa5]);
    let first = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        bytes.clone(),
    );
    let replay = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        bytes,
    );

    assert!(matches!(
        run.try_submit(first).expect("submit first").wait().expect("commit first"),
        CommitOutcome::Committed(_)
    ));
    assert_eq!(
        run.try_submit(replay).expect("submit replay").wait().expect("reject replay"),
        CommitOutcome::ReplayRejected
    );
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (packets, cursor, watermark): (u64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), committed_through_record_seq,
                    (SELECT projection_commit_seq FROM store_state)
             FROM capture_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read replay effects");
    assert_eq!(packets, 1);
    assert_eq!(cursor, 0_u64.to_be_bytes());
    assert_eq!(watermark, 1_u64.to_be_bytes());
}

#[test]
fn malformed_known_body_commits_before_capability_resolution() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        Instant::now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &[0xa5]),
    );

    let CommitOutcome::Committed(receipt) =
        run.try_submit(datagram).expect("submit malformed body").wait().expect("commit packet")
    else {
        panic!("first authenticated packet cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::MalformedKnownBody);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (disposition, capabilities, observations): (String, u64, u64) = connection
        .query_row(
            "SELECT disposition, (SELECT count(*) FROM capability_epochs),
                    (SELECT count(*) FROM csi_observations)
             FROM packet_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read malformed packet effects");
    assert_eq!(disposition, "malformed_known_body");
    assert_eq!(capabilities, 0);
    assert_eq!(observations, 0);
}

#[test]
fn first_conforming_capability_commits_exact_epoch_row() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let body = capability_body([0x01; 32], [0x22; 32], 1024);
    let datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        Instant::now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &body),
    );

    let CommitOutcome::Committed(receipt) =
        run.try_submit(datagram).expect("submit capability").wait().expect("commit capability")
    else {
        panic!("first authenticated packet cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::CapabilityCommitted);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (digest, descriptor, first_record): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT capability_digest, descriptor_bytes, first_record_seq FROM capability_epochs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read committed capability");
    assert_eq!(digest, body[..32]);
    assert_eq!(descriptor, body[34..]);
    assert_eq!(first_record, 0_u64.to_be_bytes());
}

#[test]
fn capability_pin_precedence_checks_build_before_digest() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let build_and_digest_mismatch = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability_body([0x09; 32], [0x33; 32], 1024)),
    );
    let digest_only_mismatch = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 2, &capability_body([0x01; 32], [0x33; 32], 1024)),
    );

    let CommitOutcome::Committed(build_receipt) = run
        .try_submit(build_and_digest_mismatch)
        .expect("submit build mismatch")
        .wait()
        .expect("commit build mismatch packet")
    else {
        panic!("new sequence cannot be a replay")
    };
    let CommitOutcome::Committed(digest_receipt) = run
        .try_submit(digest_only_mismatch)
        .expect("submit digest mismatch")
        .wait()
        .expect("commit digest mismatch packet")
    else {
        panic!("new sequence cannot be a replay")
    };
    assert_eq!(build_receipt.disposition(), PacketDisposition::BuildMismatch);
    assert_eq!(digest_receipt.disposition(), PacketDisposition::CapabilityPinMismatch);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let capabilities: u64 = connection
        .query_row("SELECT count(*) FROM capability_epochs", [], |row| row.get(0))
        .expect("read capability count");
    assert_eq!(capabilities, 0);
}

#[test]
fn capability_descriptor_budget_above_route_is_rejected_before_epoch_commit() {
    let fixture = CaptureFixture::with_first_capability_budget(2049);
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let capability = capability_body([0x01; 32], [0x22; 32], 2049);
    let datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        Instant::now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability),
    );

    let CommitOutcome::Committed(receipt) = run
        .try_submit(datagram)
        .expect("submit over-budget capability")
        .wait()
        .expect("commit classified capability packet")
    else {
        panic!("first authenticated packet cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::CapabilityPinMismatch);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (disposition, capabilities): (String, u64) = connection
        .query_row(
            "SELECT disposition, (SELECT count(*) FROM capability_epochs)
             FROM packet_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read over-budget capability effects");
    assert_eq!(disposition, "capability_pin_mismatch");
    assert_eq!(capabilities, 0);
}

#[test]
fn repeated_equal_capability_validates_one_durable_epoch_row() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let body = capability_body([0x01; 32], [0x22; 32], 1024);
    for (offset, message_sequence) in [1_u64, 2].into_iter().enumerate() {
        let datagram = CapturedDatagram::new(
            "192.0.2.10:5000".parse().expect("peer"),
            first_receive + Duration::from_nanos(offset as u64),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            seal_raw(1, 1, message_sequence, &body),
        );
        let CommitOutcome::Committed(receipt) = run
            .try_submit(datagram)
            .expect("submit repeated capability")
            .wait()
            .expect("commit repeated capability")
        else {
            panic!("increasing sequence cannot be a replay")
        };
        assert_eq!(receipt.disposition(), PacketDisposition::CapabilityCommitted);
    }
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (packets, capabilities, first_record, watermark): (u64, u64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), count(*), first_record_seq,
                    (SELECT projection_commit_seq FROM store_state)
             FROM capability_epochs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read repeated capability effects");
    assert_eq!((packets, capabilities), (2, 1));
    assert_eq!(first_record, 0_u64.to_be_bytes());
    assert_eq!(watermark, 2_u64.to_be_bytes());
}

#[test]
fn conforming_health_commits_without_capability_or_observation_rows() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        Instant::now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(3, 1, 1, &health_body(&capability[..32])),
    );

    let CommitOutcome::Committed(receipt) =
        run.try_submit(datagram).expect("submit health").wait().expect("commit health")
    else {
        panic!("first authenticated packet cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::HealthCommitted);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (disposition, capabilities, observations): (String, u64, u64) = connection
        .query_row(
            "SELECT disposition, (SELECT count(*) FROM capability_epochs),
                    (SELECT count(*) FROM csi_observations)
             FROM packet_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read health effects");
    assert_eq!(disposition, "health_committed");
    assert_eq!((capabilities, observations), (0, 0));
}

#[test]
fn csi_unavailable_precedes_source_and_radio_mismatches() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        Instant::now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(2, 1, 1, &csi_body(&capability[..32], [2, 0, 0, 0, 0, 99], 6)),
    );

    let CommitOutcome::Committed(receipt) =
        run.try_submit(datagram).expect("submit CSI").wait().expect("commit CSI packet")
    else {
        panic!("first authenticated packet cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::CapabilityUnavailable);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (disposition, observations, watermark): (String, u64, Vec<u8>) = connection
        .query_row(
            "SELECT disposition, (SELECT count(*) FROM csi_observations),
                    (SELECT projection_commit_seq FROM store_state)
             FROM packet_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read unavailable CSI effects");
    assert_eq!(disposition, "capability_unavailable");
    assert_eq!(observations, 0);
    assert_eq!(watermark, 1_u64.to_be_bytes());
}

#[test]
fn conforming_csi_commits_native_coordinate_observation() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let capability_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability),
    );
    let csi_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(10),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(2, 1, 2, &csi_body(&capability[..32], [2, 0, 0, 0, 0, 10], 1)),
    );

    let _ = run
        .try_submit(capability_datagram)
        .expect("submit capability")
        .wait()
        .expect("commit capability");
    let CommitOutcome::Committed(receipt) =
        run.try_submit(csi_datagram).expect("submit CSI").wait().expect("commit CSI")
    else {
        panic!("increasing sequence cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::CsiCommitted);
    assert_eq!(receipt.record_sequence().get(), 1);
    assert_eq!(receipt.projection_sequence().get(), 2);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (session_time, sensor, link, profile, observation, decoder): (
        Vec<u8>,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        String,
    ) = connection
        .query_row(
            "SELECT session_time_ns, sensor_id, link_id, profile_id, observation_cbor,
                    decoder_version
             FROM csi_observations",
            [],
            |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
            },
        )
        .expect("read CSI observation");
    assert_eq!(session_time.len(), 8);
    assert_eq!((sensor.as_str(), link.as_str()), ("sensor-a", "link-a"));
    assert_eq!(profile, EXPECTED_PROFILE_ID);
    assert_eq!(decoder, "native-frame-v1");
    assert_eq!(
        normalized_observation_bytes(&observation),
        decode_hex_fixture(include_str!("fixtures/demo/observation-v1.hex"))
    );
}

#[test]
fn csi_mismatch_precedence_runs_through_body_budget() {
    let fixture = CaptureFixture::with_first_sensor_raw_limit(4);
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let capability_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability),
    );
    let _ = run
        .try_submit(capability_datagram)
        .expect("submit capability")
        .wait()
        .expect("commit capability");

    let cases = [
        ([0x99; 32], [2, 0, 0, 0, 0, 99], 6, PacketDisposition::CapabilityMismatch),
        (
            capability[..32].try_into().expect("capability digest"),
            [2, 0, 0, 0, 0, 99],
            6,
            PacketDisposition::SourceMismatch,
        ),
        (
            capability[..32].try_into().expect("capability digest"),
            [2, 0, 0, 0, 0, 10],
            6,
            PacketDisposition::RadioMismatch,
        ),
    ];
    for (offset, (digest, source, channel, expected)) in cases.into_iter().enumerate() {
        let datagram = CapturedDatagram::new(
            "192.0.2.10:5000".parse().expect("peer"),
            first_receive + Duration::from_nanos(offset as u64 + 1),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            seal_raw(2, 1, offset as u64 + 2, &csi_body(&digest, source, channel)),
        );
        let CommitOutcome::Committed(receipt) = run
            .try_submit(datagram)
            .expect("submit mismatched CSI")
            .wait()
            .expect("commit mismatched CSI")
        else {
            panic!("increasing sequence cannot be a replay")
        };
        assert_eq!(receipt.disposition(), expected);
    }
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let dispositions = connection
        .prepare("SELECT disposition FROM packet_records ORDER BY record_seq")
        .expect("prepare disposition query")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query dispositions")
        .collect::<Result<Vec<_>, _>>()
        .expect("read dispositions");
    assert_eq!(
        dispositions,
        ["capability_committed", "capability_mismatch", "source_mismatch", "radio_mismatch",]
    );
    let observations: u64 = connection
        .query_row("SELECT count(*) FROM csi_observations", [], |row| row.get(0))
        .expect("read observation count");
    assert_eq!(observations, 0);
}

#[test]
fn csi_detects_durable_capability_build_mismatch_before_candidate_digest() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let capability_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability),
    );
    let _ = run
        .try_submit(capability_datagram)
        .expect("submit capability")
        .wait()
        .expect("commit capability");

    let mut mismatched_descriptor = capability[34..].to_vec();
    mismatched_descriptor[15] = 0x09;
    let mismatched_digest: [u8; 32] = Sha256::digest(&mismatched_descriptor).into();
    Connection::open(&fixture.database)
        .expect("open Store for private corruption fixture")
        .execute(
            "UPDATE capability_epochs SET capability_digest = ?1, descriptor_bytes = ?2",
            rusqlite::params![mismatched_digest, mismatched_descriptor],
        )
        .expect("install internally consistent mismatched capability row");
    let csi_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(2, 1, 2, &csi_body(&mismatched_digest, [2, 0, 0, 0, 0, 99], 6)),
    );

    let CommitOutcome::Committed(receipt) = run
        .try_submit(csi_datagram)
        .expect("submit CSI")
        .wait()
        .expect("commit build mismatch packet")
    else {
        panic!("increasing sequence cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::BuildMismatch);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (disposition, observations): (String, u64) = connection
        .query_row(
            "SELECT disposition, (SELECT count(*) FROM csi_observations)
             FROM packet_records WHERE record_seq = ?1",
            [1_u64.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read build mismatch effects");
    assert_eq!(disposition, "build_mismatch");
    assert_eq!(observations, 0);
}

#[test]
fn csi_body_budget_mismatch_commits_without_observation() {
    let fixture = CaptureFixture::with_first_sensor_raw_limit(4);
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let capability_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability),
    );
    let _ = run
        .try_submit(capability_datagram)
        .expect("submit capability")
        .wait()
        .expect("commit capability");
    let csi_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(2, 1, 2, &csi_body(&capability[..32], [2, 0, 0, 0, 0, 10], 1)),
    );

    let CommitOutcome::Committed(receipt) = run
        .try_submit(csi_datagram)
        .expect("submit CSI")
        .wait()
        .expect("commit body-budget mismatch")
    else {
        panic!("increasing sequence cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::BodyBudgetMismatch);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let observations: u64 = connection
        .query_row("SELECT count(*) FROM csi_observations", [], |row| row.get(0))
        .expect("read observation count");
    assert_eq!(observations, 0);
}

#[cfg(feature = "ingest-test-hooks")]
#[test]
fn decoded_domain_rejection_commits_packet_without_observation() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let capability_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability),
    );
    let _ = run
        .try_submit(capability_datagram)
        .expect("submit capability")
        .wait()
        .expect("commit capability");
    run.reject_next_csi_domain_for_test();
    let csi_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(2, 1, 2, &csi_body(&capability[..32], [2, 0, 0, 0, 0, 10], 1)),
    );

    let CommitOutcome::Committed(receipt) = run
        .try_submit(csi_datagram)
        .expect("submit CSI")
        .wait()
        .expect("commit decoded-domain rejection")
    else {
        panic!("increasing sequence cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::DecodedDomainRejected);
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (disposition, observations): (String, u64) = connection
        .query_row(
            "SELECT disposition, (SELECT count(*) FROM csi_observations)
             FROM packet_records WHERE record_seq = ?1",
            [1_u64.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read decoded-domain effects");
    assert_eq!(disposition, "decoded_domain_rejected");
    assert_eq!(observations, 0);
}

#[cfg(feature = "ingest-test-hooks")]
#[test]
fn csi_body_budget_precedes_decoded_domain_rejection() {
    let fixture = CaptureFixture::with_first_sensor_raw_limit(4);
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let capability_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability),
    );
    let _ = run
        .try_submit(capability_datagram)
        .expect("submit capability")
        .wait()
        .expect("commit capability");
    run.reject_next_csi_domain_for_test();
    let csi_datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(2, 1, 2, &csi_body(&capability[..32], [2, 0, 0, 0, 0, 10], 1)),
    );

    let CommitOutcome::Committed(receipt) = run
        .try_submit(csi_datagram)
        .expect("submit over-budget CSI")
        .wait()
        .expect("commit classified CSI")
    else {
        panic!("increasing sequence cannot be a replay")
    };
    assert_eq!(receipt.disposition(), PacketDisposition::BodyBudgetMismatch);
    run.shutdown().expect("stop Capture runtime");
}

#[test]
fn capability_conflict_rolls_back_complete_write_set_and_stops_writer() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let first = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 1, &capability),
    );
    let _ = run.try_submit(first).expect("submit capability").wait().expect("commit capability");

    let mut conflicting_descriptor = capability[34..].to_vec();
    conflicting_descriptor[47] ^= 0xff;
    let conflicting_digest: [u8; 32] = Sha256::digest(&conflicting_descriptor).into();
    Connection::open(&fixture.database)
        .expect("open Store for private conflict fixture")
        .execute(
            "UPDATE capability_epochs SET capability_digest = ?1, descriptor_bytes = ?2",
            rusqlite::params![conflicting_digest, conflicting_descriptor],
        )
        .expect("install conflicting capability row");
    let conflict = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(1, 1, 2, &capability),
    );
    let commit_error: CommitError = run
        .try_submit(conflict)
        .expect("queue conflict")
        .wait()
        .expect_err("capability conflict must stop the writer");
    assert!(!commit_error.is_writer_stopped());
    fs::remove_file(fixture.root.join("secrets/device-1/key-1.bin"))
        .expect("remove key after fatal writer failure");
    let after_fatal = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(2),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 3, &[0xa5]),
    );
    let submit_error: SubmitError =
        run.try_submit(after_fatal).expect_err("stopped writer must reject later input");
    assert!(submit_error.is_writer_stopped());
    run.shutdown().expect("join stopped writer");

    let connection = Connection::open(&fixture.database).expect("open rolled-back Store");
    let (packets, maximum_sequence, cursor, watermark): (u64, Vec<u8>, Vec<u8>, Vec<u8>) =
        connection
            .query_row(
                "SELECT (SELECT count(*) FROM packet_records),
                        (SELECT maximum_message_sequence FROM admission_epochs
                         WHERE device_id = ?1 AND key_epoch = ?2),
                        committed_through_record_seq,
                        (SELECT projection_commit_seq FROM store_state)
                 FROM capture_sessions",
                rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read rollback effects");
    assert_eq!(packets, 1);
    assert_eq!(maximum_sequence, 1_u64.to_be_bytes());
    assert_eq!(cursor, 0_u64.to_be_bytes());
    assert_eq!(watermark, 1_u64.to_be_bytes());
}

#[test]
fn record_and_watermark_overflow_fail_closed_before_publication() {
    for overflow in ["record", "watermark"] {
        let fixture = CaptureFixture::new();
        whisper::init_admission(&fixture.config).expect("initialize Store");
        let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
        let connection = Connection::open(&fixture.database).expect("open overflow fixture");
        match overflow {
            "record" => {
                connection
                    .execute(
                        "UPDATE capture_sessions
                         SET committed_through_record_seq = ?1, last_session_time_ns = ?2,
                             projection_commit_seq = ?3",
                        rusqlite::params![
                            u64::MAX.to_be_bytes(),
                            0_u64.to_be_bytes(),
                            0_u64.to_be_bytes(),
                        ],
                    )
                    .expect("install maximum record cursor");
            }
            "watermark" => {
                connection
                    .execute(
                        "UPDATE store_state SET projection_commit_seq = ?1",
                        [u64::MAX.to_be_bytes()],
                    )
                    .expect("install maximum watermark");
            }
            _ => unreachable!("fixed overflow fixture"),
        }
        drop(connection);
        let datagram = CapturedDatagram::new(
            "192.0.2.10:5000".parse().expect("peer"),
            Instant::now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            seal_raw(0x7f, 1, 1, &[0xa5]),
        );
        assert!(run.try_submit(datagram).expect("queue overflow candidate").wait().is_err());
        run.shutdown().expect("join stopped writer");

        let connection = Connection::open(&fixture.database).expect("open failed Store");
        let (packets, replay_boot): (u64, Option<Vec<u8>>) = connection
            .query_row(
                "SELECT (SELECT count(*) FROM packet_records), highest_boot_generation
                 FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
                rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read overflow rollback");
        assert_eq!(packets, 0, "{overflow} overflow inserted a packet");
        assert_eq!(replay_boot, None, "{overflow} overflow advanced replay");
    }
}

#[test]
fn nonmonotonic_session_time_and_corrupt_replay_bitmap_fail_closed() {
    let time_fixture = CaptureFixture::new();
    whisper::init_admission(&time_fixture.config).expect("initialize time Store");
    let mut time_run = whisper::serve(&time_fixture.config).expect("start time Capture runtime");
    let first_receive = Instant::now();
    let first = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 1, &[0xa5]),
    );
    let _ = time_run.try_submit(first).expect("submit first").wait().expect("commit first");
    Connection::open(&time_fixture.database)
        .expect("open time corruption fixture")
        .execute("UPDATE capture_sessions SET last_session_time_ns = ?1", [u64::MAX.to_be_bytes()])
        .expect("install reversed session time");
    let second = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 2, &[0xa5]),
    );
    assert!(time_run.try_submit(second).expect("queue reversed time").wait().is_err());
    time_run.shutdown().expect("join stopped time writer");
    let connection = Connection::open(&time_fixture.database).expect("open time Store");
    let (packets, maximum_sequence): (u64, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), maximum_message_sequence
             FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
            rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read time rollback");
    assert_eq!(packets, 1);
    assert_eq!(maximum_sequence, 1_u64.to_be_bytes());

    let replay_fixture = CaptureFixture::new();
    whisper::init_admission(&replay_fixture.config).expect("initialize replay Store");
    let mut replay_run =
        whisper::serve(&replay_fixture.config).expect("start replay Capture runtime");
    Connection::open(&replay_fixture.database)
        .expect("open replay corruption fixture")
        .execute(
            "UPDATE admission_epochs
             SET highest_boot_generation = ?1, maximum_message_sequence = ?2,
                 seen_bitmap = zeroblob(8)
             WHERE device_id = ?3 AND key_epoch = ?4",
            rusqlite::params![
                1_u32.to_be_bytes(),
                1_u64.to_be_bytes(),
                1_u64.to_be_bytes(),
                1_u16.to_be_bytes(),
            ],
        )
        .expect("install corrupt replay bitmap");
    let datagram = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        Instant::now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 2, &[0xa5]),
    );
    assert!(replay_run.try_submit(datagram).expect("queue corrupt replay").wait().is_err());
    replay_run.shutdown().expect("join stopped replay writer");
    let packets: u64 = Connection::open(&replay_fixture.database)
        .expect("open replay Store")
        .query_row("SELECT count(*) FROM packet_records", [], |row| row.get(0))
        .expect("read replay packet count");
    assert_eq!(packets, 0);
}

#[test]
fn multiple_routes_sessions_epochs_and_observations_remain_dynamic() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let first_capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let second_capability = capability_body([0x03; 32], [0x44; 32], 2048);
    let mut first_run = whisper::serve(&fixture.config).expect("start first Capture runtime");
    let first_receive = Instant::now();
    let first_run_packets = [
        ("192.0.2.10:5000", seal_raw_for(&[0x11; 32], 1, 1, 1, 1, &first_capability)),
        ("192.0.2.11:5000", seal_raw_for(&[0x22; 32], 2, 1, 1, 1, &second_capability)),
        (
            "192.0.2.10:5000",
            seal_raw_for(
                &[0x11; 32],
                1,
                2,
                1,
                2,
                &csi_body(&first_capability[..32], [2, 0, 0, 0, 0, 10], 1),
            ),
        ),
        (
            "192.0.2.11:5000",
            seal_raw_for(
                &[0x22; 32],
                2,
                2,
                1,
                2,
                &csi_body(&second_capability[..32], [2, 0, 0, 0, 0, 11], 6),
            ),
        ),
    ];
    for (offset, (peer, bytes)) in first_run_packets.into_iter().enumerate() {
        let datagram = CapturedDatagram::new(
            peer.parse().expect("peer"),
            first_receive + Duration::from_nanos(offset as u64),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            bytes,
        );
        let _ = first_run
            .try_submit(datagram)
            .expect("submit first-run packet")
            .wait()
            .expect("commit first-run packet");
    }
    first_run.shutdown().expect("stop first Capture runtime");

    let mut second_run = whisper::serve(&fixture.config).expect("start second Capture runtime");
    let second_receive = Instant::now();
    let second_run_packets = [
        (
            "192.0.2.10:5000",
            seal_raw_for(
                &[0x11; 32],
                1,
                2,
                1,
                3,
                &csi_body(&first_capability[..32], [2, 0, 0, 0, 0, 10], 1),
            ),
        ),
        ("192.0.2.11:5000", seal_raw_for(&[0x22; 32], 2, 1, 2, 1, &second_capability)),
        (
            "192.0.2.11:5000",
            seal_raw_for(
                &[0x22; 32],
                2,
                2,
                2,
                2,
                &csi_body(&second_capability[..32], [2, 0, 0, 0, 0, 11], 6),
            ),
        ),
    ];
    for (offset, (peer, bytes)) in second_run_packets.into_iter().enumerate() {
        let datagram = CapturedDatagram::new(
            peer.parse().expect("peer"),
            second_receive + Duration::from_nanos(offset as u64),
            SystemTime::UNIX_EPOCH + Duration::from_secs(2),
            bytes,
        );
        let _ = second_run
            .try_submit(datagram)
            .expect("submit second-run packet")
            .wait()
            .expect("commit second-run packet");
    }
    second_run.shutdown().expect("stop second Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open dynamic Store");
    let counts: (u64, u64, u64, u64, u64, u64) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM capture_sessions),
                    (SELECT count(*) FROM capability_epochs),
                    (SELECT count(*) FROM csi_observations),
                    (SELECT count(DISTINCT sensor_id) FROM csi_observations),
                    (SELECT count(DISTINCT link_id) FROM csi_observations),
                    (SELECT count(DISTINCT profile_id) FROM csi_observations)",
            [],
            |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
            },
        )
        .expect("read dynamic counts");
    assert_eq!(counts, (2, 3, 4, 2, 2, 2));
    let epochs: Vec<(Vec<u8>, Vec<u8>)> = connection
        .prepare(
            "SELECT device_id, boot_generation FROM capability_epochs
             ORDER BY device_id, boot_generation",
        )
        .expect("prepare epoch query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query epochs")
        .collect::<Result<_, _>>()
        .expect("read epochs");
    assert_eq!(
        epochs,
        [
            (1_u64.to_be_bytes().to_vec(), 1_u32.to_be_bytes().to_vec()),
            (2_u64.to_be_bytes().to_vec(), 1_u32.to_be_bytes().to_vec()),
            (2_u64.to_be_bytes().to_vec(), 2_u32.to_be_bytes().to_vec()),
        ]
    );
}

#[test]
fn pre_transaction_route_byte_and_auth_rejects_have_no_store_effect() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();

    let unknown_route = CapturedDatagram::new(
        "192.0.2.99:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 1, &[0xa5]),
    );
    assert!(run.try_submit(unknown_route).is_err());

    let oversized = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 1, &vec![0xa5; 2_001]),
    );
    assert!(run.try_submit(oversized).is_err());

    let mut unauthenticated = seal_raw(0x7f, 1, 1, &[0xa5]).into_vec();
    *unauthenticated.last_mut().expect("authentication tag") ^= 0xff;
    let unauthenticated = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(2),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        unauthenticated,
    );
    assert!(run.try_submit(unauthenticated).is_err());
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (packets, cursor, watermark, replay_boot): RejectedStoreEffects = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), committed_through_record_seq,
                    (SELECT projection_commit_seq FROM store_state),
                    (SELECT highest_boot_generation FROM admission_epochs
                     WHERE device_id = ?1 AND key_epoch = ?2)
             FROM capture_sessions",
            rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read rejected input effects");
    assert_eq!(packets, 0);
    assert_eq!(cursor, None);
    assert_eq!(watermark, 0_u64.to_be_bytes());
    assert_eq!(replay_boot, None);
}

#[test]
fn authenticated_rate_reject_does_not_advance_replay_or_session() {
    let fixture = CaptureFixture::with_first_route_packet_rate(1);
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let first = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 1, &[0xa5]),
    );
    let rate_rejected = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 2, &[0xa5]),
    );

    let _ = run.try_submit(first).expect("submit first").wait().expect("commit first");
    let error: SubmitError =
        run.try_submit(rate_rejected).expect_err("packet rate must reject the second datagram");
    assert!(error.is_rate_limited());
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (packets, maximum_sequence, watermark): (u64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), maximum_message_sequence,
                    (SELECT projection_commit_seq FROM store_state)
             FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
            rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read rate rejection effects");
    assert_eq!(packets, 1);
    assert_eq!(maximum_sequence, 1_u64.to_be_bytes());
    assert_eq!(watermark, 1_u64.to_be_bytes());
}

#[test]
fn authenticated_byte_rate_reject_does_not_advance_replay_or_session() {
    let first_bytes = seal_raw(0x7f, 1, 1, &[0xa5]);
    let byte_limit = u64::try_from(first_bytes.len()).expect("datagram length fits u64");
    let fixture = CaptureFixture::with_first_route_byte_rate(byte_limit);
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let first_receive = Instant::now();
    let first = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        first_bytes,
    );
    let byte_rate_rejected = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 2, &[0xa5]),
    );

    let _ = run.try_submit(first).expect("submit first").wait().expect("commit first");
    assert!(run.try_submit(byte_rate_rejected).is_err());
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (packets, maximum_sequence, watermark): (u64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), maximum_message_sequence,
                    (SELECT projection_commit_seq FROM store_state)
             FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
            rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read byte-rate rejection effects");
    assert_eq!(packets, 1);
    assert_eq!(maximum_sequence, 1_u64.to_be_bytes());
    assert_eq!(watermark, 1_u64.to_be_bytes());
}

#[test]
fn out_of_order_receive_time_is_rejected_before_store_admission() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let earlier_receive = Instant::now();
    let first = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        earlier_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 1, &[0xa5]),
    );
    let out_of_order = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        earlier_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 2, &[0xa5]),
    );

    let _ = run.try_submit(first).expect("submit first").wait().expect("commit first");
    assert!(run.try_submit(out_of_order).is_err());
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (packets, maximum_sequence, watermark): (u64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), maximum_message_sequence,
                    (SELECT projection_commit_seq FROM store_state)
             FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
            rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read receive-order rejection effects");
    assert_eq!(packets, 1);
    assert_eq!(maximum_sequence, 1_u64.to_be_bytes());
    assert_eq!(watermark, 1_u64.to_be_bytes());
}

#[test]
fn session_time_conversion_overflow_is_rejected_without_store_effect() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let overflow_receive = Instant::now()
        .checked_add(Duration::from_nanos(u64::MAX))
        .expect("platform Instant represents the capture overflow fixture");
    let overflow = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        overflow_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 1, &[0xa5]),
    );

    assert!(run.try_submit(overflow).is_err());
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (packets, cursor, watermark, replay_boot): RejectedStoreEffects = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), committed_through_record_seq,
                    (SELECT projection_commit_seq FROM store_state),
                    (SELECT highest_boot_generation FROM admission_epochs
                     WHERE device_id = ?1 AND key_epoch = ?2)
             FROM capture_sessions",
            rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read session-time overflow effects");
    assert_eq!(packets, 0);
    assert_eq!(cursor, None);
    assert_eq!(watermark, 0_u64.to_be_bytes());
    assert_eq!(replay_boot, None);
}

#[cfg(feature = "ingest-test-hooks")]
#[test]
fn full_writer_queue_drops_candidate_without_store_effect_and_counts_it() {
    let fixture = CaptureFixture::with_writer_queue_capacity(1);
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let hold = run.hold_writer_for_test().expect("pause writer");
    let first_receive = Instant::now();
    let queued = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 1, &[0xa5]),
    );
    let dropped = CapturedDatagram::new(
        "192.0.2.10:5000".parse().expect("peer"),
        first_receive + Duration::from_nanos(1),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        seal_raw(0x7f, 1, 2, &[0xa5]),
    );

    let ticket = run.try_submit(queued).expect("fill writer queue");
    let error: SubmitError = run.try_submit(dropped).expect_err("full queue must drop candidate");
    assert!(error.is_queue_full());
    assert_eq!(run.queue_drop_count(), 1);
    drop(hold);
    let _ = ticket.wait().expect("commit queued packet");
    run.shutdown().expect("stop Capture runtime");

    let connection = Connection::open(&fixture.database).expect("open committed Store");
    let (packets, maximum_sequence, watermark): (u64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM packet_records), maximum_message_sequence,
                    (SELECT projection_commit_seq FROM store_state)
             FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
            rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read queue drop effects");
    assert_eq!(packets, 1);
    assert_eq!(maximum_sequence, 1_u64.to_be_bytes());
    assert_eq!(watermark, 1_u64.to_be_bytes());
}

#[cfg(feature = "ingest-test-hooks")]
#[test]
fn shutdown_releases_an_active_writer_hold_before_joining() {
    let fixture = CaptureFixture::new();
    whisper::init_admission(&fixture.config).expect("initialize Store");
    let mut run = whisper::serve(&fixture.config).expect("start Capture runtime");
    let (finished_tx, finished_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let _hold = run.hold_writer_for_test().expect("pause writer");
        let stopped = run.shutdown().is_ok();
        let _ = finished_tx.send(stopped);
    });

    assert_eq!(
        finished_rx.recv_timeout(Duration::from_secs(1)),
        Ok(true),
        "shutdown must release the test hold before joining the writer",
    );
}
