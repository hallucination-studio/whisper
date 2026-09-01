//! Independent-process coverage for bounded RF relationship evidence.

#![cfg(all(feature = "development-fixture", unix))]

use std::error::Error as _;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ciborium::value::Value as CborValue;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(feature = "ingest-test-hooks")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "ingest-test-hooks")]
use tokio::net::TcpStream;
#[cfg(feature = "ingest-test-hooks")]
use whisper::test_support::{
    advance_host_clock, hold_evidence_snapshot, set_evidence_snapshot_row_limit,
    start_host_with_manual_clock,
};

static NEXT_PACKAGE: AtomicU64 = AtomicU64::new(0);

fn png_crc(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

fn push_png_chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&u32::try_from(data.len()).expect("PNG chunk length").to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(data);
    let mut crc_input = kind.to_vec();
    crc_input.extend_from_slice(data);
    output.extend_from_slice(&png_crc(&crc_input).to_be_bytes());
}

fn rewrite_png_dimensions(bytes: &mut [u8], width: u32, height: u32) {
    bytes[16..20].copy_from_slice(&width.to_be_bytes());
    bytes[20..24].copy_from_slice(&height.to_be_bytes());
    let crc = png_crc(&bytes[12..29]);
    bytes[29..33].copy_from_slice(&crc.to_be_bytes());
}

fn state_fixture(kind: &str) -> (Vec<String>, [u8; 4]) {
    let rows = match kind {
        "unknown" => [
            "10000001", "01000010", "00100100", "00011000", "00011000", "00100100", "01000010",
            "10000001",
        ],
        "stable" => [
            "11111111", "10000001", "10111101", "10100101", "10100101", "10111101", "10000001",
            "11111111",
        ],
        _ => panic!("unknown state fixture"),
    };
    (rows.into_iter().map(str::to_owned).collect(), [172, 75, 36, 255])
}

fn production_asset_sha256() -> String {
    let mut preimage = Vec::new();
    let page = include_str!("../src/host/assets/index.html").replace("__MAX_TIME_BUCKETS__", "512");
    for (path, bytes) in [
        ("/", page.as_bytes()),
        ("/assets/app.css", include_bytes!("../src/host/assets/app.css").as_slice()),
        ("/assets/app.js", include_bytes!("../src/host/assets/app.js").as_slice()),
    ] {
        preimage.extend_from_slice(&(path.len() as u64).to_be_bytes());
        preimage.extend_from_slice(path.as_bytes());
        preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        preimage.extend_from_slice(bytes);
    }
    sha256(&preimage)
}

fn screenshot_png(pattern: &[String], foreground: [u8; 4]) -> Vec<u8> {
    screenshot_png_with_background(pattern, foreground, [247, 249, 248, 255])
}

fn screenshot_png_with_background(
    pattern: &[String],
    foreground: [u8; 4],
    background: [u8; 4],
) -> Vec<u8> {
    let width = 160_u32;
    let height = 100_u32;
    let row_bytes = usize::try_from(width).expect("fixture width") * 4;
    let mut pixels =
        Vec::with_capacity(usize::try_from(height).expect("fixture height") * (row_bytes + 1));
    for y in 0..height {
        pixels.push(0);
        for x in 0..width {
            let on = x < 32
                && y < 32
                && pattern[usize::try_from(y / 4).expect("marker row")].as_bytes()
                    [usize::try_from(x / 4).expect("marker column")]
                    == b'1';
            pixels.extend_from_slice(if on { &foreground } else { &background });
        }
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&pixels).expect("compress PNG fixture pixels");
    let compressed = encoder.finish().expect("finish PNG fixture compression");
    let mut output = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut header = Vec::from(width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    push_png_chunk(&mut output, b"IHDR", &header);
    push_png_chunk(&mut output, b"IDAT", &compressed);
    push_png_chunk(&mut output, b"IEND", &[]);
    output
}

fn chrome_screenshot_png(pattern: &[String], foreground: [u8; 3]) -> Vec<u8> {
    let width = 160_u32;
    let height = 100_u32;
    let row_bytes = usize::try_from(width).expect("fixture width") * 3;
    let mut pixels =
        Vec::with_capacity(usize::try_from(height).expect("fixture height") * (row_bytes + 1));
    for y in 0..height {
        pixels.push(0);
        for x in 0..width {
            let on = x < 32
                && y < 32
                && pattern[usize::try_from(y / 4).expect("marker row")].as_bytes()
                    [usize::try_from(x / 4).expect("marker column")]
                    == b'1';
            pixels.extend_from_slice(if on { &foreground } else { &[247, 249, 248] });
        }
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&pixels).expect("compress Chrome PNG fixture pixels");
    let compressed = encoder.finish().expect("finish Chrome PNG fixture compression");
    let mut output = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut header = Vec::from(width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    push_png_chunk(&mut output, b"IHDR", &header);
    push_png_chunk(&mut output, b"IDAT", &compressed);
    push_png_chunk(&mut output, b"IEND", &[]);
    output
}

fn package_directory() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "whisper-rf-evidence-{}-{}",
        std::process::id(),
        NEXT_PACKAGE.fetch_add(1, Ordering::Relaxed)
    ));
    let receipts = root.join("docs/evidence/receipts");
    fs::create_dir_all(&receipts).expect("create evidence fixture receipt parent");
    receipts.join("rf-relationship-simulated-0001")
}

fn canonical_json(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serialize canonical ASCII JSON fixture")
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn host_executable_sha256() -> String {
    sha256(&fs::read(env!("CARGO_BIN_EXE_whisper")).expect("read Host executable fixture"))
}

fn host_source_sha256() -> String {
    env!("WHISPER_HOST_SOURCE_SHA256").to_owned()
}

fn accepted_host_source_sha256() -> &'static str {
    include_str!("fixtures/evidence-host-source-sha256.txt").trim()
}

fn host_identity() -> Value {
    json!({
        "executable_sha256": host_executable_sha256(),
        "source_clean": env!("WHISPER_HOST_SOURCE_CLEAN") == "true",
        "source_revision": env!("WHISPER_HOST_SOURCE_REVISION"),
        "source_sha256": accepted_host_source_sha256(),
        "target": env!("WHISPER_HOST_TARGET")
    })
}

#[test]
fn host_source_identity_matches_the_accepted_vector() {
    assert_eq!(host_source_sha256(), accepted_host_source_sha256());
}

#[derive(serde::Deserialize)]
struct PacketEvidenceVector {
    body_binding_sha256: String,
    body_sha256: String,
    ciphertext_sha256: String,
    received_utc_ns: i64,
}

fn packet_evidence_vector(
    receive_utc_ns: i64,
    bytes: &[u8],
    body_sha256: Option<&str>,
) -> (&'static str, &'static str) {
    static VECTORS: OnceLock<Vec<PacketEvidenceVector>> = OnceLock::new();
    let vectors = VECTORS.get_or_init(|| {
        serde_json::from_str(include_str!("fixtures/evidence/v1/packet-evidence-vectors.json"))
            .expect("parse accepted packet evidence vectors")
    });
    let ciphertext_sha256 = sha256(bytes);
    let vector = vectors
        .iter()
        .find(|vector| {
            vector.received_utc_ns == receive_utc_ns
                && vector.ciphertext_sha256 == ciphertext_sha256
                && body_sha256.is_none_or(|expected| vector.body_sha256 == expected)
        })
        .expect("accepted packet evidence vector");
    (&vector.body_sha256, &vector.body_binding_sha256)
}

fn fixture_receive_utc_ns(index: usize) -> i64 {
    if index < 11 {
        i64::try_from(index + 2).expect("pre-restart fixture receive time")
    } else {
        i64::try_from(index + 6).expect("post-restart fixture receive time")
    }
}

fn write_file(root: &Path, path: &str, bytes: &[u8]) {
    let target = root.join(path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).expect("create evidence fixture parent");
    }
    fs::write(target, bytes).expect("write evidence fixture artifact");
}

fn fixture_datagram(sequence: u64) -> Vec<u8> {
    fixture_datagram_for(sequence, 1, [2, 0, 0, 0, 0, 10])
}

fn fixture_datagram_for(sequence: u64, device_id: u64, source_mac: [u8; 6]) -> Vec<u8> {
    let capability = capability_body([1; 32], [3; 32], 1024);
    let mut body = Vec::new();
    body.extend_from_slice(&capability[..32]);
    body.extend_from_slice(&sequence.to_le_bytes());
    body.extend_from_slice(&2_u32.to_le_bytes());
    body.extend_from_slice(&3_u64.to_le_bytes());
    body.extend_from_slice(&source_mac);
    body.extend_from_slice(&[1, 0, 1, 1, 0, (-42_i8) as u8, (-95_i8) as u8, 6, 0, 0]);
    body.extend_from_slice(&[0, 0, 1]);
    body.extend_from_slice(&6_u16.to_le_bytes());
    body.extend_from_slice(&3_u16.to_le_bytes());
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&3_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&[1, 2, 3, 4, 5, 6]);

    seal_fixture_datagram_for(2, sequence, device_id, &body)
}

fn fixture_capability_datagram(sequence: u64) -> Vec<u8> {
    seal_fixture_datagram(1, sequence, &capability_body([1; 32], [3; 32], 1024))
}

fn seal_fixture_datagram(kind: u8, sequence: u64, body: &[u8]) -> Vec<u8> {
    seal_fixture_datagram_for(kind, sequence, 1, body)
}

fn seal_fixture_datagram_for(kind: u8, sequence: u64, device_id: u64, body: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 32];
    header[0] = 1;
    header[1] = kind;
    header[2..4].copy_from_slice(&32_u16.to_le_bytes());
    header[4..12].copy_from_slice(&device_id.to_le_bytes());
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[16..20].copy_from_slice(&1_u32.to_le_bytes());
    header[20..28].copy_from_slice(&sequence.to_le_bytes());
    header[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&1_u32.to_le_bytes());
    nonce[4..].copy_from_slice(&sequence.to_le_bytes());
    let ciphertext = Aes256Gcm::new_from_slice(&fixture_key("sensor-a", 1))
        .expect("fixture AES key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &header })
        .expect("seal fixture datagram");
    header.into_iter().chain(ciphertext).collect()
}

fn packet_evidence_digests(receive_utc_ns: i64, bytes: &[u8]) -> (String, String) {
    let mut body = Sha256::new();
    body.update(b"rf-relationship-packet-body-v1\0");
    body.update(receive_utc_ns.to_be_bytes());
    body.update(b"native_frame_v1\0");
    body.update(u64::try_from(bytes.len()).expect("packet length").to_be_bytes());
    body.update(bytes);
    let body_sha256: [u8; 32] = body.finalize().into();

    let mut binding = Sha256::new();
    binding.update(b"rf-relationship-packet-binding-v1\0");
    binding.update(body_sha256);
    binding.update(receive_utc_ns.to_be_bytes());
    binding.update(u64::try_from(bytes.len()).expect("packet length").to_be_bytes());
    binding.update(bytes);
    (encode_hex(&body_sha256), encode_hex(&binding.finalize()))
}

// Adversarial tests need to preserve canonical encoding while changing one semantic field. Positive
// package bytes come only from the checked-in golden vectors below.
fn canonical_cbor_mutation(value: &Value) -> Vec<u8> {
    let value = CborValue::serialized(value).expect("serialize canonical CBOR fixture value");
    let mut bytes = Vec::new();
    write_cbor(&value, &mut bytes);
    bytes
}

fn baseline_command_body(link: &str, profile: [u8; 32], command: &str) -> Vec<u8> {
    let value = CborValue::Map(vec![
        (CborValue::Text("link".to_owned()), CborValue::Text(link.to_owned())),
        (CborValue::Text("profile".to_owned()), CborValue::Bytes(profile.to_vec())),
        (CborValue::Text("command".to_owned()), CborValue::Text(command.to_owned())),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("encode command fixture body");
    bytes
}

fn write_cbor(value: &CborValue, output: &mut Vec<u8>) {
    match value {
        CborValue::Integer(integer) => {
            let value = i128::from(*integer);
            if value >= 0 {
                write_cbor_uint(0, u64::try_from(value).expect("fixture positive integer"), output);
            } else {
                write_cbor_uint(
                    1,
                    u64::try_from(-1_i128 - value).expect("fixture negative integer"),
                    output,
                );
            }
        }
        CborValue::Bytes(bytes) => {
            write_cbor_uint(2, bytes.len() as u64, output);
            output.extend_from_slice(bytes);
        }
        CborValue::Text(text) => {
            write_cbor_uint(3, text.len() as u64, output);
            output.extend_from_slice(text.as_bytes());
        }
        CborValue::Array(values) => {
            write_cbor_uint(4, values.len() as u64, output);
            for value in values {
                write_cbor(value, output);
            }
        }
        CborValue::Map(values) => {
            let mut encoded = values
                .iter()
                .map(|(key, value)| {
                    let mut key_bytes = Vec::new();
                    let mut value_bytes = Vec::new();
                    write_cbor(key, &mut key_bytes);
                    write_cbor(value, &mut value_bytes);
                    (key_bytes, value_bytes)
                })
                .collect::<Vec<_>>();
            encoded.sort_by(|left, right| {
                left.0.len().cmp(&right.0.len()).then_with(|| left.0.cmp(&right.0))
            });
            write_cbor_uint(5, encoded.len() as u64, output);
            for (key, value) in encoded {
                output.extend_from_slice(&key);
                output.extend_from_slice(&value);
            }
        }
        CborValue::Bool(false) => output.push(0xf4),
        CborValue::Bool(true) => output.push(0xf5),
        CborValue::Null => output.push(0xf6),
        _ => panic!("unsupported fixture CBOR value"),
    }
}

fn write_cbor_uint(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[cfg(feature = "ingest-test-hooks")]
struct RuntimeFixture {
    root: PathBuf,
    config: whisper::Config,
}

#[cfg(feature = "ingest-test-hooks")]
impl RuntimeFixture {
    fn new() -> Self {
        let root = package_directory().with_extension("runtime");
        fs::create_dir(&root).expect("create runtime fixture root");
        let managed = root.join("managed");
        create_directory(&managed, 0o700);
        let database = managed.join("host.sqlite3");
        let secrets = root.join("secrets");
        create_directory(&secrets, 0o700);
        for (device, sensor) in [(1, "sensor-a"), (2, "sensor-b")] {
            let device_root = secrets.join(format!("device-{device}"));
            create_directory(&device_root, 0o700);
            let key = device_root.join("key-1.bin");
            fs::write(&key, fixture_key(sensor, 1)).expect("write fixture epoch key");
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
                .expect("protect fixture epoch key");
        }
        let first_capability = capability_body([0x01; 32], [0x22; 32], 1024);
        let second_capability = capability_body([0x03; 32], [0x44; 32], 2048);
        let source = include_str!("fixtures/config/valid-two-esp32.toml")
            .replace(
                "0202020202020202020202020202020202020202020202020202020202020202",
                &encode_hex(&first_capability[..32]),
            )
            .replace(
                "0404040404040404040404040404040404040404040404040404040404040404",
                &encode_hex(&second_capability[..32]),
            )
            .replacen("expected_peer_ip = \"192.0.2.10\"", "expected_peer_ip = \"127.0.0.1\"", 1)
            .replacen("expected_peer_ip = \"192.0.2.11\"", "expected_peer_ip = \"127.0.0.1\"", 1)
            .replacen("peer = \"192.0.2.10\"", "peer = \"127.0.0.1\"", 1)
            .replacen("peer = \"192.0.2.11\"", "peer = \"127.0.0.1\"", 1)
            .replacen("bind = \"127.0.0.1:9000\"", "bind = \"0.0.0.0:0\"", 1)
            .replacen("bind = \"127.0.0.1:8080\"", "bind = \"127.0.0.1:0\"", 1)
            .replace(
                "secret_root = \"./data/secrets\"",
                &format!("secret_root = \"{}\"", secrets.display()),
            )
            .replace(
                "database_path = \"./data/whisper.sqlite3\"",
                &format!("database_path = \"{}\"", database.display()),
            );
        let config = whisper::parse_config(&source).expect("parse runtime fixture configuration");
        whisper::init_admission(&config).expect("initialize runtime fixture Store");
        Self { root, config }
    }
}

#[cfg(feature = "ingest-test-hooks")]
impl Drop for RuntimeFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(feature = "ingest-test-hooks")]
fn create_directory(path: &Path, mode: u32) {
    fs::create_dir(path).expect("create protected fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("protect fixture directory");
}

fn fixture_key(sensor_id: &str, key_epoch: u16) -> [u8; 32] {
    let mut preimage = b"whisper.development-fixture-key".to_vec();
    preimage.extend_from_slice(&[0, 1]);
    preimage.extend_from_slice(&33_u32.to_be_bytes());
    preimage.extend_from_slice(b"whisper-v1-public-e2e-fixture-key");
    preimage.extend_from_slice(&(sensor_id.len() as u32).to_be_bytes());
    preimage.extend_from_slice(sensor_id.as_bytes());
    preimage.extend_from_slice(&key_epoch.to_be_bytes());
    Sha256::digest(preimage).into()
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
    Sha256::digest(descriptor)
        .into_iter()
        .chain((descriptor.len() as u16).to_le_bytes())
        .chain(descriptor)
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(feature = "ingest-test-hooks")]
async fn http_request(address: std::net::SocketAddr, request: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("connect Host HTTP");
    stream.write_all(request.as_bytes()).await.expect("write Host HTTP request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read Host HTTP response");
    response
}

#[cfg(feature = "ingest-test-hooks")]
async fn wait_for_projection(address: std::net::SocketAddr, expected: &str) {
    for _ in 0..100 {
        let response = http_request(
            address,
            "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let separator =
            response.windows(4).position(|window| window == b"\r\n\r\n").expect("HTTP headers");
        let body: Value = serde_json::from_slice(&response[separator + 4..]).expect("HTTP JSON");
        if body["receipt"]["projection_commit"]["sequence"] == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("projection {expected} did not become visible");
}

#[cfg(feature = "ingest-test-hooks")]
fn response_json(response: &[u8]) -> Value {
    let separator =
        response.windows(4).position(|window| window == b"\r\n\r\n").expect("HTTP headers");
    serde_json::from_slice(&response[separator + 4..]).expect("HTTP JSON response")
}

#[cfg(feature = "ingest-test-hooks")]
async fn wait_for_projection_at_least(address: std::net::SocketAddr, minimum: u64) -> u64 {
    for _ in 0..200 {
        let sequence = projection_sequence(address).await;
        if sequence >= minimum {
            return sequence;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("projection did not reach {minimum}");
}

#[cfg(feature = "ingest-test-hooks")]
async fn projection_sequence(address: std::net::SocketAddr) -> u64 {
    let response = http_request(
        address,
        "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    response_json(&response)["receipt"]["projection_commit"]["sequence"]
        .as_str()
        .expect("projection sequence")
        .parse::<u64>()
        .expect("u64 projection sequence")
}

#[cfg(feature = "ingest-test-hooks")]
async fn latest_relationship(address: std::net::SocketAddr, profile: &str) -> Value {
    for _ in 0..100 {
        let subjects = response_json(
            &http_request(
                address,
                "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        if let Some(session) = subjects["data"]["subjects"]
            .as_array()
            .and_then(|subjects| subjects.first())
            .and_then(|subject| subject["session_id"].as_str())
        {
            let request = format!(
                "GET /api/relationships/latest?session={session}&link=link-a&profile={profile} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            );
            let latest = response_json(&http_request(address, &request).await);
            if latest["kind"] == "ok" {
                return latest;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("relationship did not become query-visible");
}

#[cfg(feature = "ingest-test-hooks")]
async fn relationship_observation(
    address: std::net::SocketAddr,
    profile: &str,
) -> (Vec<u8>, Value) {
    let subjects = response_json(
        &http_request(
            address,
            "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    let session = subjects["data"]["subjects"][0]["session_id"]
        .as_str()
        .expect("observable Semantic Session");
    let request = format!(
        "GET /api/relationships/latest?session={session}&link=link-a&profile={profile} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let response = http_request(address, &request).await;
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response headers");
    let body = response[separator + 4..].to_vec();
    let value = serde_json::from_slice(&body).expect("relationship response JSON");
    (body, value)
}

#[cfg(feature = "ingest-test-hooks")]
fn csi_body(capability_digest: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(capability_digest);
    body.extend_from_slice(&1_u64.to_le_bytes());
    body.extend_from_slice(&2_u32.to_le_bytes());
    body.extend_from_slice(&3_u64.to_le_bytes());
    body.extend_from_slice(&[2, 0, 0, 0, 0, 10]);
    body.extend_from_slice(&[1, 0, 1, 1, 0, (-42_i8) as u8, (-95_i8) as u8, 6, 0, 0]);
    body.extend_from_slice(&[0, 0, 1]);
    body.extend_from_slice(&6_u16.to_le_bytes());
    body.extend_from_slice(&3_u16.to_le_bytes());
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&3_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    body
}

#[cfg(feature = "ingest-test-hooks")]
fn seal_runtime_datagram(kind: u8, sequence: u64, body: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 32];
    header[0] = 1;
    header[1] = kind;
    header[2..4].copy_from_slice(&32_u16.to_le_bytes());
    header[4..12].copy_from_slice(&1_u64.to_le_bytes());
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[16..20].copy_from_slice(&1_u32.to_le_bytes());
    header[20..28].copy_from_slice(&sequence.to_le_bytes());
    header[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&1_u32.to_le_bytes());
    nonce[4..].copy_from_slice(&sequence.to_le_bytes());
    let ciphertext = Aes256Gcm::new_from_slice(&fixture_key("sensor-a", 1))
        .expect("runtime fixture key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &header })
        .expect("seal runtime fixture datagram");
    header.into_iter().chain(ciphertext).collect()
}

#[cfg(feature = "ingest-test-hooks")]
async fn send_csi_window(
    runtime: &whisper::HostRuntime,
    sender: &tokio::net::UdpSocket,
    destination: std::net::SocketAddr,
    capability_digest: &[u8],
    counters: &mut (u64, u64, u64),
) {
    for _ in 0..3 {
        advance_host_clock(runtime, Duration::from_millis(200));
        counters.0 += 1;
        counters.1 += 1;
        let mut csi = csi_body(capability_digest);
        csi[32..40].copy_from_slice(&counters.0.to_le_bytes());
        sender
            .send_to(&seal_runtime_datagram(2, counters.1, &csi), destination)
            .await
            .expect("send simulated CSI");
        counters.2 += 1;
        counters.2 = wait_for_projection_at_least(runtime.http_address(), counters.2).await;
    }
    advance_host_clock(runtime, Duration::from_millis(400));
    counters.0 += 1;
    counters.1 += 1;
    let mut csi = csi_body(capability_digest);
    csi[32..40].copy_from_slice(&counters.0.to_le_bytes());
    sender
        .send_to(&seal_runtime_datagram(2, counters.1, &csi), destination)
        .await
        .expect("send next-window carry CSI");
    counters.2 += 2;
    counters.2 = wait_for_projection_at_least(runtime.http_address(), counters.2).await;
}

#[cfg(feature = "ingest-test-hooks")]
fn relationship_command(profile: &str, command: &str) -> String {
    let body = format!(
        r#"{{"http_schema_version":1,"target":{{"link":"link-a","profile":"{profile}"}},"command":"{command}"}}"#
    );
    format!(
        "POST /api/relationships/commands HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
}

fn artifact(path: &str, media_type: &str, bytes: &[u8]) -> Value {
    json!({"media_type": media_type, "path": path, "sha256": sha256(bytes)})
}

fn live_payload(store_id: &str, watermark: &str, delivery_sequence: &str) -> Vec<u8> {
    format!(
        r#"{{"http_schema_version":1,"delivery_sequence":"{delivery_sequence}","projection_commit":{{"store_id":"{store_id}","sequence":"{watermark}"}},"payload":{{"kind":"projection_watermark"}}}}"#
    )
    .into_bytes()
}

fn complete_package(root: &Path) {
    fs::create_dir(root).expect("create complete package root");

    let mut datagrams = (1_u64..=13).map(fixture_datagram).collect::<Vec<_>>();
    datagrams.push(fixture_capability_datagram(14));
    let packet_records = [1_u64, 3, 5, 7, 9, 11, 13, 15, 17, 19, 22, 26, 27, 29];
    let capability = capability_body([1; 32], [3; 32], 1024);
    let physical = canonical_json(&json!({
        "datagrams": datagrams.iter().enumerate().map(|(index, datagram)| json!({
            "body_binding_sha256": packet_evidence_vector(
                fixture_receive_utc_ns(index), datagram, None,
            ).1,
            "context": {
                "capture_record_seq": if index < 11 { index } else { index - 11 }.to_string(),
                "capture_session_id": if index < 11 { "capture-1" } else { "capture-2" },
                "capture_session_time": (packet_records[index] + 1).to_string(),
                "semantic_record_seq": packet_records[index].to_string(),
                "semantic_session_time": (packet_records[index] + 1).to_string(),
                "transport": "udp",
                "wire_format": "native_frame_v1"
            },
            "device_id": "1",
            "key_epoch": "1",
            "path": format!("datagrams/{index:06}.bin"),
            "receive_order": index.to_string(),
            "received_monotonic_ns": (packet_records[index] + 1).to_string(),
            "received_utc_ns": fixture_receive_utc_ns(index).to_string(),
            "sha256": sha256(datagram)
        })).collect::<Vec<_>>(),
        "fixture": {
            "capability_sha256": encode_hex(&capability[..32]),
            "firmware_image_sha256": "01".repeat(32),
            "kind": "development_fixture",
            "provisioning_sha256": "dd".repeat(32),
            "sensor_id": "sensor-a"
        },
        "schema_version": 1
    }));
    let profile = "55".repeat(32);
    let host = host_identity();
    let active_baseline = include_bytes!("fixtures/session/v1/baseline-active.cbor");
    let digest = "22".repeat(32);
    let commit = |record_seq: u64| {
        json!({
            "commit_seq": record_seq + 1,
            "kind": "semantic",
            "record_seq": record_seq,
            "timeline_digest": format!("{:064x}", record_seq + 11)
        })
    };
    let first_capture = json!({
        "algorithm_version": "native-coordinate-ingest-v1",
        "capture_session_id": "capture-1",
        "conditioning_version": "conditioning-v1",
        "decoder_version": "native-frame-v1",
        "durable_tail": 10,
        "last_session_time": 23,
        "started_utc_ns": 1
    });
    let stable = |result_time: u64, source_record_seq: u64, creator_commit_seq: u64| {
        json!({
            "changed_at": 100,
            "change_current": {"kind": "known", "value": "stable"},
            "change_previous": {"kind": "unknown", "reason": "baseline_learning"},
            "creator_commit_seq": creator_commit_seq,
            "knowledge": {"kind": "known", "value": "stable"},
            "link": "link-a",
            "profile": profile,
            "result_time": result_time,
            "source_record_seq": source_record_seq
        })
    };
    let mut facts = Vec::new();
    let mut trace_facts = Vec::new();
    let mut commits = Vec::new();
    let mut datagram_index = 0_usize;
    let mut capture_record_seq = 0_u64;
    let decoded_csi = |sequence: usize| {
        json!({
            "kind": "csi_data",
            "callback_tick_us": "3",
            "capability_sha256": encode_hex(&capability[..32]),
            "capture_sequence": sequence.to_string(),
            "channel": "1",
            "complex_sample_count": "3",
            "driver_rx_timestamp_us": "2"
        })
    };
    {
        let mut push_fact = |kind: &str, command: Option<&str>, capture_session: Option<&str>| {
            let record_seq = facts.len() as u64;
            let command_value = command
                .map(|command| json!({"command": command, "link": "link-a", "profile": profile}));
            let (capture, trace_capture, datagram_sha256, body_sha256) = if let Some(session) =
                capture_session
            {
                let datagram = &datagrams[datagram_index];
                let digest = sha256(datagram);
                let body_digest =
                    packet_evidence_vector(fixture_receive_utc_ns(datagram_index), datagram, None)
                        .0
                        .to_owned();
                let capture = json!({
                    "capture_record_seq": capture_record_seq,
                    "capture_session_id": session,
                    "capture_session_time": record_seq + 1
                });
                let trace_capture = json!({
                    "capture_record_seq": capture_record_seq.to_string(),
                    "capture_session_id": session,
                    "capture_session_time": (record_seq + 1).to_string()
                });
                datagram_index += 1;
                capture_record_seq += 1;
                (capture, trace_capture, Value::String(digest), body_digest)
            } else {
                let body = command.map_or_else(
                    || vec![0xf6],
                    |value| baseline_command_body("link-a", [0x55; 32], value),
                );
                (Value::Null, Value::Null, Value::Null, sha256(&body))
            };
            facts.push(json!({
                "body_sha256": body_sha256.clone(),
                "capture": capture,
                "command": command_value.clone(),
                "datagram_sha256": datagram_sha256.clone(),
                "kind": kind,
                "record_seq": record_seq,
                "session_time": record_seq + 1
            }));
            commits.push(commit(record_seq));
            trace_facts.push(json!({
                "body_sha256": body_sha256,
                "capture": trace_capture,
                "command": command_value,
                "datagram_sha256": datagram_sha256,
                "decoded_message": if kind == "packet" {
                    decoded_csi(datagram_index)
                } else {
                    Value::Null
                },
                "kind": kind,
                "record_seq": record_seq.to_string(),
                "session_time": (record_seq + 1).to_string(),
                "transaction_a": {
                    "effects": if kind == "packet" {
                        json!(["ordered_fact", "replay_admission", "capture_membership"])
                    } else {
                        json!(["ordered_fact"])
                    },
                    "identity": format!("semantic-1:A:{record_seq}")
                },
                "transaction_b": {
                    "baseline_sha256": null,
                    "commit_seq": (record_seq + 1).to_string(),
                    "creator_commit_seq": null,
                    "effects": ["processed_cursor", "timeline_digest", "projection_watermark"],
                    "identity": format!("{}:B:{}", "55".repeat(32), record_seq + 1),
                    "processed_cursor": record_seq.to_string(),
                    "relationship_sha256": null,
                    "timeline_digest": format!("{:064x}", record_seq + 11),
                    "watermark": (record_seq + 1).to_string()
                }
            }));
        };
        push_fact("baseline_command", Some("begin_learning"), None);
        for _ in 0..10 {
            push_fact("packet", None, Some("capture-1"));
            push_fact("timeline_advance", None, None);
        }
        push_fact("baseline_command", Some("commit"), None);
        push_fact("packet", None, Some("capture-1"));
        push_fact("timeline_advance", None, None);
        push_fact("baseline_command", Some("begin_learning"), None);
        push_fact("baseline_command", Some("commit"), None);
    }
    for (record_seq, command) in [(24_usize, "begin_learning"), (25, "commit")] {
        let command_value =
            json!({"command": command, "link": "link-b", "profile": "66".repeat(32)});
        let body_sha256 = sha256(&baseline_command_body("link-b", [0x66; 32], command));
        facts[record_seq]["body_sha256"] = Value::String(body_sha256.clone());
        facts[record_seq]["command"] = command_value.clone();
        trace_facts[record_seq]["body_sha256"] = Value::String(body_sha256);
        trace_facts[record_seq]["command"] = command_value;
    }
    let unknown_relationship = json!({
        "changed_at": null,
        "change_current": null,
        "change_previous": null,
        "creator_commit_seq": 3,
        "knowledge": {"kind": "unknown", "reason": "baseline_learning"},
        "link": "link-a",
        "profile": profile,
        "result_time": 3,
        "source_record_seq": 2
    });
    trace_facts[0]["transaction_b"]["baseline_sha256"] = Value::String("01".repeat(32));
    trace_facts[0]["transaction_b"]["effects"] =
        json!(["processed_cursor", "timeline_digest", "projection_watermark", "complete_baseline"]);
    trace_facts[2]["transaction_b"]["creator_commit_seq"] = Value::String("3".to_owned());
    trace_facts[2]["transaction_b"]["effects"] = json!([
        "processed_cursor",
        "timeline_digest",
        "projection_watermark",
        "relationship_projection",
        "creator_commit"
    ]);
    trace_facts[2]["transaction_b"]["relationship_sha256"] =
        Value::String(sha256(&canonical_cbor_mutation(&json!([unknown_relationship]))));
    let observations = |facts: &[Value]| {
        facts
            .iter()
            .filter(|fact| fact["kind"] == "packet" && fact["record_seq"] != 29)
            .map(|fact| {
                json!({
                    "link": "link-a",
                    "profile": profile,
                    "record_seq": fact["record_seq"],
                    "session_time": fact["session_time"]
                })
            })
            .collect::<Vec<_>>()
    };
    let pre_facts = facts.clone();
    let pre_commits = commits.clone();
    let pre_value = json!({
        "active_session": {"manifest_sha256": digest, "session_id": "semantic-1"},
        "baselines": [{
            "deployment": "lab", "link": "link-a", "profile": profile,
            "source_record_seq": 23, "state_cbor": encode_hex(active_baseline),
            "state_sha256": sha256(active_baseline)
        }],
        "capture_sessions": [first_capture],
        "commits": pre_commits,
        "config_digest": "44".repeat(32),
        "durable_tail": 25,
        "facts": pre_facts,
        "observations": observations(&facts),
        "processed_cursor": 25,
        "replay_identities": [{
            "device_id": 1, "key_epoch": 1, "replay_window_sha256": "aa".repeat(32)
        }],
        "relationships": [stable(100, 23, 24)],
        "schema_version": 1,
        "selected_range": {"first_record_seq": 0, "last_record_seq": 25},
        "store_id": "55".repeat(32),
        "timeline_digest": format!("{:064x}", 36),
        "topology_digest": "77".repeat(32),
        "watermark": 26
    });
    capture_record_seq = 0;
    {
        let mut push_continuation = |kind: &str, capture_session: Option<&str>| {
            let record_seq = facts.len() as u64;
            let (capture, trace_capture, datagram_sha256, body_sha256) = if let Some(session) =
                capture_session
            {
                let datagram = &datagrams[datagram_index];
                let digest = sha256(datagram);
                let body_digest =
                    packet_evidence_vector(fixture_receive_utc_ns(datagram_index), datagram, None)
                        .0
                        .to_owned();
                let capture = json!({
                    "capture_record_seq": capture_record_seq,
                    "capture_session_id": session,
                    "capture_session_time": record_seq + 1
                });
                let trace_capture = json!({
                    "capture_record_seq": capture_record_seq.to_string(),
                    "capture_session_id": session,
                    "capture_session_time": (record_seq + 1).to_string()
                });
                datagram_index += 1;
                capture_record_seq += 1;
                (capture, trace_capture, Value::String(digest), body_digest)
            } else {
                (Value::Null, Value::Null, Value::Null, sha256(&[0xf6]))
            };
            facts.push(json!({
                "body_sha256": body_sha256.clone(),
                "capture": capture,
                "command": null,
                "datagram_sha256": datagram_sha256.clone(),
                "kind": kind,
                "record_seq": record_seq,
                "session_time": record_seq + 1
            }));
            commits.push(commit(record_seq));
            trace_facts.push(json!({
                "body_sha256": body_sha256,
                "capture": trace_capture,
                "command": null,
                "datagram_sha256": datagram_sha256,
                "decoded_message": if kind == "packet" {
                    decoded_csi(datagram_index)
                } else {
                    Value::Null
                },
                "kind": kind,
                "record_seq": record_seq.to_string(),
                "session_time": (record_seq + 1).to_string(),
                "transaction_a": {
                    "effects": if kind == "packet" {
                        json!(["ordered_fact", "replay_admission", "capture_membership"])
                    } else {
                        json!(["ordered_fact"])
                    },
                    "identity": format!("semantic-1:A:{record_seq}")
                },
                "transaction_b": {
                    "baseline_sha256": null,
                    "commit_seq": (record_seq + 1).to_string(),
                    "creator_commit_seq": null,
                    "effects": ["processed_cursor", "timeline_digest", "projection_watermark"],
                    "identity": format!("{}:B:{}", "55".repeat(32), record_seq + 1),
                    "processed_cursor": record_seq.to_string(),
                    "relationship_sha256": null,
                    "timeline_digest": format!("{:064x}", record_seq + 11),
                    "watermark": (record_seq + 1).to_string()
                }
            }));
        };
        push_continuation("packet", Some("capture-2"));
        push_continuation("packet", Some("capture-2"));
        push_continuation("timeline_advance", None);
        push_continuation("packet", Some("capture-2"));
    }
    trace_facts[29]["decoded_message"] = json!({
        "kind": "capabilities",
        "capability_sha256": encode_hex(&capability[..32]),
        "firmware_image_sha256": "01".repeat(32)
    });
    let continuation_value = json!({
        "active_session": {"manifest_sha256": digest, "session_id": "semantic-1"},
        "baselines": [{
            "deployment": "lab", "link": "link-a", "profile": profile,
            "source_record_seq": 28, "state_cbor": encode_hex(active_baseline),
            "state_sha256": sha256(active_baseline)
        }],
        "capture_sessions": [first_capture, {
            "algorithm_version": "native-coordinate-ingest-v1",
            "capture_session_id": "capture-2",
            "conditioning_version": "conditioning-v1",
            "decoder_version": "native-frame-v1", "durable_tail": 1,
            "last_session_time": 30, "started_utc_ns": 2
        }],
        "commits": commits,
        "config_digest": "44".repeat(32),
        "durable_tail": 29,
        "facts": facts,
        "observations": observations(&facts),
        "processed_cursor": 29,
        "replay_identities": [{
            "device_id": 1, "key_epoch": 1, "replay_window_sha256": "aa".repeat(32)
        }],
        "relationships": [stable(200, 28, 29)],
        "schema_version": 1,
        "selected_range": {"first_record_seq": 0, "last_record_seq": 29},
        "store_id": "55".repeat(32),
        "timeline_digest": format!("{:064x}", 40),
        "topology_digest": "77".repeat(32),
        "watermark": 30
    });
    for (record_seq, snapshot) in [(23_usize, &pre_value), (28_usize, &continuation_value)] {
        let baseline_sha256 = sha256(&canonical_cbor_mutation(&snapshot["baselines"]));
        let relationship_sha256 = sha256(&canonical_cbor_mutation(&snapshot["relationships"]));
        trace_facts[record_seq]["transaction_b"]["baseline_sha256"] =
            Value::String(baseline_sha256);
        trace_facts[record_seq]["transaction_b"]["creator_commit_seq"] =
            Value::String((record_seq + 1).to_string());
        trace_facts[record_seq]["transaction_b"]["effects"] = json!([
            "processed_cursor",
            "timeline_digest",
            "projection_watermark",
            "complete_baseline",
            "relationship_projection",
            "creator_commit"
        ]);
        trace_facts[record_seq]["transaction_b"]["relationship_sha256"] =
            Value::String(relationship_sha256);
    }
    let host_trace = canonical_json(&json!({
        "facts": trace_facts,
        "schema_version": 1,
        "session_id": "semantic-1",
        "store_id": "55".repeat(32)
    }));
    let store = include_bytes!("fixtures/evidence/v1/store-pre-stop.cbor").to_vec();
    let continuation = include_bytes!("fixtures/evidence/v1/store-post-continuation.cbor").to_vec();
    let golden_pre: Value = ciborium::from_reader(store.as_slice()).expect("parse pre-stop golden");
    let golden_continuation: Value =
        ciborium::from_reader(continuation.as_slice()).expect("parse continuation golden");
    assert_eq!(golden_pre, pre_value, "pre-stop golden semantics drifted");
    assert_eq!(golden_continuation, continuation_value, "continuation golden semantics drifted");
    let restart = canonical_json(&json!({
        "continuation": {
            "first_commit_seq": "27",
            "first_datagram_sha256": sha256(&datagrams[11]),
            "first_record_seq": "26",
            "knowledge": "stable",
            "later_commit_seq": "29",
            "later_record_seq": "28",
            "later_result_time": "200",
            "most_recent_change_preserved": true,
            "previous_result_time": "100"
        },
        "rebuild": {
            "authorizer": "write_deny",
            "comparisons": {
                "baseline": true, "bytes": true, "creator": true, "cursor": true,
                "relationship": true, "tail": true, "timeline": true, "watermark": true
            },
            "open_flags": ["read_only", "no_mutex", "nofollow"],
            "post_export_sha256": sha256(&store),
            "pre_export_sha256": sha256(&store),
            "query_only": true,
            "total_changes": "0",
            "write_attempted": false,
            "writer_opens": "0"
        },
        "retained": {
            "link": "link-a", "physical_sensor": "sensor-a", "profile": profile,
            "session_id": "semantic-1", "store_id": "55".repeat(32)
        },
        "schema_version": 1,
        "start": {
            "capture_session_id": "capture-2", "durable_tail": "25",
            "host_executable_sha256": host["executable_sha256"], "processed_cursor": "25",
            "utc_ns": "16", "watermark": "26"
        },
        "stop": {
            "capture_session_id": "capture-1", "durable_tail": "25",
            "host_executable_sha256": host["executable_sha256"], "processed_cursor": "25",
            "utc_ns": "13", "watermark": "26"
        }
    }));

    let mut producer_files = vec![
        ("physical-input.json".to_owned(), "application/json", physical),
        ("host-commit-trace.json".to_owned(), "application/json", host_trace),
        ("store-pre-stop.cbor".to_owned(), "application/cbor", store.clone()),
        ("store-post-rebuild.cbor".to_owned(), "application/cbor", store),
        ("store-post-continuation.cbor".to_owned(), "application/cbor", continuation),
        ("restart-trace.json".to_owned(), "application/json", restart),
    ];
    producer_files.extend(datagrams.iter().enumerate().map(|(index, datagram)| {
        (format!("datagrams/{index:06}.bin"), "application/octet-stream", datagram.clone())
    }));
    let mut producer_artifacts = producer_files
        .iter()
        .map(|(path, media_type, bytes)| artifact(path, media_type, bytes))
        .collect::<Vec<_>>();
    producer_artifacts.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    for (path, _, bytes) in &producer_files {
        write_file(root, path, bytes);
    }
    let run = canonical_json(&json!({
        "artifacts": producer_artifacts,
        "identities": {
            "asset_sha256": production_asset_sha256(),
            "config_sha256": "44".repeat(32),
            "firmware": {
                "capability_sha256": encode_hex(&capability_body([1; 32], [3; 32], 1024)[..32]),
                "image_sha256": "01".repeat(32),
                "source_revision": "aa".repeat(20)
            },
            "host": host,
            "provisioning_sha256": "dd".repeat(32),
            "session_id": "semantic-1",
            "store_id": "55".repeat(32),
            "subject": {"link": "link-a", "profile": profile, "session_id": "semantic-1"}
        },
        "interval": {"ended_utc_ns": "20", "started_utc_ns": "1"},
        "negative_claims": ["not_program_completion", "not_formal_e2e_classification"],
        "privacy": {"ciphertext_source_mac_recoverable": true},
        "procedure_version": "rf-relationship-v1",
        "result": "candidate",
        "run_id": "simulated-0001",
        "schema_version": 1
    }));
    write_file(root, "run.json", &run);
    let producer_seal = run_evidence_operation(root, "seal-producer");
    assert!(
        producer_seal.status.success(),
        "producer sealing failed: {}",
        String::from_utf8_lossy(&producer_seal.stderr)
    );

    let http_relationship = |knowledge: Value,
                             result_time: u64,
                             creator: u64,
                             watermark: u64,
                             last_record: u64,
                             change: Option<Value>| {
        let mut data = json!({
            "creator_commit": {"sequence": creator.to_string(), "store_id": "55".repeat(32)},
            "knowledge": knowledge,
            "link": "link-a",
            "profile": profile,
            "result_time": result_time.to_string(),
            "session_id": "semantic-1"
        });
        if let Some(change) = change {
            data["most_recent_change"] = change;
        }
        canonical_json(&json!({
            "data": data,
            "http_schema_version": 1,
            "kind": "ok",
            "receipt": {
                "algorithm_version": "relationship-v1",
                "conditioning_version": "conditioning-v1",
                "decoder_version": "native-frame-v1",
                "first_record_seq": "0",
                "last_record_seq": last_record.to_string(),
                "projection_commit": {
                    "sequence": watermark.to_string(), "store_id": "55".repeat(32)
                },
                "session_id": "semantic-1"
            },
            "resource": "relationship_latest"
        }))
    };
    let change = json!({
        "changed_at": "100",
        "current": {"kind": "known", "value": "stable"},
        "previous": {"kind": "unknown", "reason": "baseline_learning"}
    });
    let http_unknown = http_relationship(
        json!({"kind": "unknown", "reason": "baseline_learning"}),
        3,
        3,
        3,
        2,
        None,
    );
    let http_stable_pre = http_relationship(
        json!({"kind": "known", "value": "stable"}),
        100,
        24,
        26,
        25,
        Some(change.clone()),
    );
    let http_stable_post = http_relationship(
        json!({"kind": "known", "value": "stable"}),
        200,
        29,
        30,
        29,
        Some(change),
    );
    let store_id = "55".repeat(32);
    let websocket = canonical_json(&json!({
        "events": [
            {"kind": "connected", "order": "0", "socket_id": "0",
             "url": "ws://loopback:9001/api/live"},
            {"delivery_sequence": "1", "kind": "message", "order": "1",
             "raw_text_sha256": sha256(&live_payload(&store_id, "3", "1")),
             "socket_id": "0", "store_id": store_id, "watermark": "3"},
            {"delivery_sequence": "2", "kind": "message", "order": "2",
             "raw_text_sha256": sha256(&live_payload(&store_id, "24", "2")),
             "socket_id": "0", "store_id": store_id, "watermark": "24"},
            {"kind": "disconnected", "order": "3", "socket_id": "0"},
            {"kind": "reconnected", "order": "4", "socket_id": "1",
             "url": "ws://loopback:9001/api/live"},
            {"delivery_sequence": "1", "kind": "message", "order": "5",
             "raw_text_sha256": sha256(&live_payload(&store_id, "29", "1")),
             "socket_id": "1", "store_id": store_id, "watermark": "29"}
        ],
        "schema_version": 1,
        "url": "ws://loopback:9001/api/live"
    }));
    let (unknown_state, unknown_foreground) = state_fixture("unknown");
    let (stable_state, stable_foreground) = state_fixture("stable");
    let unknown_png = screenshot_png(&unknown_state, unknown_foreground);
    let stable_pre_png = screenshot_png(&stable_state, stable_foreground);
    let stable_post_png = screenshot_png(&stable_state, stable_foreground);
    let selection = json!({
        "link": "link-a",
        "profile": "55".repeat(32),
        "session_id": "semantic-1"
    });
    let live_audit = json!({
        "connection_detail": "Store view is current",
        "connection_text": "LIVE",
        "opaque_visual_surfaces": [],
        "selection": selection,
        "stale": false,
        "visible_text": ["Sensing", "Committed RF relationship"]
    });
    let stale_audit = json!({
        "connection_detail": "WebSocket closed · fixed 250 ms HTTP polling",
        "connection_text": "POLLING",
        "opaque_visual_surfaces": [],
        "selection": selection,
        "stale": true,
        "visible_text": ["Sensing", "Retained result · stale"]
    });
    let resynchronizing_audit = json!({
        "connection_detail": "Watermark received · reading complete HTTP resources",
        "connection_text": "POLLING",
        "opaque_visual_surfaces": [],
        "selection": selection,
        "stale": true,
        "visible_text": ["Sensing", "Retained result · stale"]
    });
    let chrome = canonical_json(&json!({
        "events": [
            {"connection_state": "LIVE", "kind": "unknown",
             "change_state": null, "change_time": null,
             "state_bounds": {"height": 32, "width": 32, "x": 0, "y": 0},
             "knowledge": "unknown:baseline_learning", "order": "0", "result_time": "3",
             "screenshot": "screenshots/unknown.png", "screenshot_sha256": sha256(&unknown_png),
             "connection_detail": live_audit["connection_detail"],
             "connection_text": live_audit["connection_text"],
             "document_id": "66".repeat(32),
             "opaque_visual_surfaces": live_audit["opaque_visual_surfaces"],
             "selection": selection, "stale": false, "visible_text": live_audit["visible_text"]},
            {"connection_state": "LIVE", "kind": "stable_pre_restart", "knowledge": "stable",
             "change_state": "Unknown(BaselineLearning) → Stable", "change_time": "100",
             "state_bounds": {"height": 32, "width": 32, "x": 0, "y": 0},
             "order": "1", "result_time": "100",
             "screenshot": "screenshots/stable-pre-restart.png",
             "screenshot_sha256": sha256(&stable_pre_png),
             "connection_detail": live_audit["connection_detail"],
             "connection_text": live_audit["connection_text"],
             "document_id": "66".repeat(32),
             "opaque_visual_surfaces": live_audit["opaque_visual_surfaces"],
             "selection": selection, "stale": false,
             "trigger_websocket_order": "2", "trigger_websocket_socket_id": "0",
             "trigger_websocket_watermark": "24",
             "visible_text": live_audit["visible_text"]},
            {"connection_state": "STALE", "kind": "stale", "knowledge": "stable", "order": "2",
             "change_state": "Unknown(BaselineLearning) → Stable", "change_time": "100",
             "result_time": "100", "connection_detail": stale_audit["connection_detail"],
             "connection_text": stale_audit["connection_text"],
             "document_id": "66".repeat(32),
             "opaque_visual_surfaces": stale_audit["opaque_visual_surfaces"],
             "selection": selection, "stale": true, "visible_text": stale_audit["visible_text"]},
            {"connection_state": "RESYNCHRONIZING", "kind": "resynchronizing",
             "knowledge": "stable", "order": "3",
             "change_state": "Unknown(BaselineLearning) → Stable", "change_time": "100",
             "result_time": "100", "connection_detail": resynchronizing_audit["connection_detail"],
             "connection_text": resynchronizing_audit["connection_text"],
             "document_id": "66".repeat(32),
             "opaque_visual_surfaces": resynchronizing_audit["opaque_visual_surfaces"],
             "selection": selection, "stale": true,
             "visible_text": resynchronizing_audit["visible_text"]},
            {"connection_state": "LIVE", "kind": "stable_post_restart", "knowledge": "stable",
             "change_state": "Unknown(BaselineLearning) → Stable", "change_time": "100",
             "state_bounds": {"height": 32, "width": 32, "x": 0, "y": 0},
             "order": "4", "result_time": "200",
             "screenshot": "screenshots/stable-post-restart.png",
             "screenshot_sha256": sha256(&stable_post_png),
             "connection_detail": live_audit["connection_detail"],
             "connection_text": live_audit["connection_text"],
             "document_id": "66".repeat(32),
             "opaque_visual_surfaces": live_audit["opaque_visual_surfaces"],
             "selection": selection, "stale": false,
             "trigger_websocket_order": "5", "trigger_websocket_socket_id": "1",
             "trigger_websocket_watermark": "29",
             "visible_text": live_audit["visible_text"]}
        ],
        "document_id": "66".repeat(32),
        "page_instance_id": "page-1",
        "schema_version": 1,
        "selection": selection
    }));
    let observer_files = [
        ("http/unknown.json", "application/json", http_unknown.as_slice()),
        ("http/stable-pre-restart.json", "application/json", http_stable_pre.as_slice()),
        ("http/stable-post-restart.json", "application/json", http_stable_post.as_slice()),
        ("websocket.json", "application/json", websocket.as_slice()),
        ("chrome-trace.json", "application/json", chrome.as_slice()),
        ("screenshots/unknown.png", "image/png", unknown_png.as_slice()),
        ("screenshots/stable-pre-restart.png", "image/png", stable_pre_png.as_slice()),
        ("screenshots/stable-post-restart.png", "image/png", stable_post_png.as_slice()),
    ];
    let mut observer_artifacts = observer_files
        .iter()
        .map(|(path, media_type, bytes)| artifact(path, media_type, bytes))
        .collect::<Vec<_>>();
    observer_artifacts.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    for (path, _, bytes) in observer_files {
        write_file(root, path, bytes);
    }
    let observer = canonical_json(&json!({
        "artifacts": observer_artifacts,
        "browser": {
            "application_id": "com.google.Chrome",
            "executable_sha256": "ab".repeat(32),
            "name": "Chrome",
            "team_id": "EQHXZ8M8AV",
            "version": "test"
        },
        "environment": "local_production",
        "interval": {"ended_utc_ns": "20", "started_utc_ns": "1"},
        "page_instance_id": "page-1",
        "schema_version": 1,
        "selection": {"link": "link-a", "profile": "55".repeat(32), "session_id": "semantic-1"},
        "served_asset_sha256": production_asset_sha256(),
        "viewport": {"device_scale_factor": "1", "height": "100", "width": "160"}
    }));
    write_file(root, "observer.json", &observer);
    let observer_seal = run_evidence_operation(root, "seal-observer");
    assert!(
        observer_seal.status.success(),
        "observer sealing failed: {}",
        String::from_utf8_lossy(&observer_seal.stderr)
    );
}

fn unseal_file(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("unseal fixture file");
}

fn reseal_file(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o444)).expect("reseal fixture file");
}

fn update_manifest_digest(root: &Path, owner: &str, path: &str) {
    let owner_path = root.join(owner);
    unseal_file(&owner_path);
    let mut value: Value =
        serde_json::from_slice(&fs::read(&owner_path).expect("read artifact owner"))
            .expect("parse artifact owner");
    let digest = sha256(&fs::read(root.join(path)).expect("read changed artifact"));
    let entry = value["artifacts"]
        .as_array_mut()
        .expect("artifact list")
        .iter_mut()
        .find(|artifact| artifact["path"] == path)
        .expect("owned artifact");
    entry["sha256"] = Value::String(digest);
    fs::write(&owner_path, canonical_json(&value)).expect("rewrite artifact owner");
    reseal_file(&owner_path);
}

fn update_store_export(root: &Path, path: &str, update: impl FnOnce(&mut Value)) {
    let target = root.join(path);
    unseal_file(&target);
    let mut value: Value =
        ciborium::from_reader(fs::read(&target).expect("read Store export").as_slice())
            .expect("decode Store export fixture");
    update(&mut value);
    fs::write(&target, canonical_cbor_mutation(&value))
        .expect("rewrite canonical Store export mutation");
    reseal_file(&target);
    update_manifest_digest(root, "run.json", path);
}

fn store_collection_sha256(root: &Path, path: &str, collection: &str) -> String {
    let value: Value =
        ciborium::from_reader(fs::read(root.join(path)).expect("read Store export").as_slice())
            .expect("decode Store export");
    sha256(&canonical_cbor_mutation(&value[collection]))
}

fn refresh_restart_export_digests(root: &Path) {
    let pre = sha256(&fs::read(root.join("store-pre-stop.cbor")).expect("read pre-stop Store"));
    let post =
        sha256(&fs::read(root.join("store-post-rebuild.cbor")).expect("read post-rebuild Store"));
    update_json_artifact(root, "restart-trace.json", "run.json", |trace| {
        trace["rebuild"]["pre_export_sha256"] = Value::String(pre);
        trace["rebuild"]["post_export_sha256"] = Value::String(post);
    });
}

fn rewrite_packet_inputs_as_capabilities(root: &Path) {
    let physical_path = root.join("physical-input.json");
    unseal_file(&physical_path);
    let mut physical: Value =
        serde_json::from_slice(&fs::read(&physical_path).expect("read physical input"))
            .expect("parse physical input");
    let mut replacements = Vec::new();
    for (index, datagram) in
        physical["datagrams"].as_array_mut().expect("physical datagrams").iter_mut().enumerate()
    {
        let sequence = u64::try_from(index + 1).expect("fixture sequence");
        let bytes = fixture_capability_datagram(sequence);
        let path = datagram["path"].as_str().expect("datagram path");
        let target = root.join(path);
        unseal_file(&target);
        fs::write(&target, &bytes).expect("rewrite capability ciphertext");
        reseal_file(&target);
        let receive_utc_ns = datagram["received_utc_ns"]
            .as_str()
            .expect("receive time")
            .parse::<i64>()
            .expect("numeric receive time");
        let (body_sha256, body_binding_sha256) =
            packet_evidence_vector(receive_utc_ns, &bytes, None);
        let datagram_sha256 = sha256(&bytes);
        datagram["body_binding_sha256"] = Value::String(body_binding_sha256.to_owned());
        datagram["sha256"] = Value::String(datagram_sha256.clone());
        replacements.push((body_sha256.to_owned(), datagram_sha256));
    }
    fs::write(&physical_path, canonical_json(&physical)).expect("rewrite physical input");
    reseal_file(&physical_path);
    for datagram in physical["datagrams"].as_array().expect("physical datagrams") {
        update_manifest_digest(root, "run.json", datagram["path"].as_str().expect("datagram path"));
    }
    update_manifest_digest(root, "run.json", "physical-input.json");

    let rewrite_store = |store: &mut Value| {
        let mut packet_index = 0_usize;
        for fact in store["facts"].as_array_mut().expect("Store facts") {
            if fact["kind"] != "packet" {
                continue;
            }
            let (body_sha256, datagram_sha256) =
                replacements.get(packet_index).expect("replacement packet");
            fact["body_sha256"] = Value::String(body_sha256.clone());
            fact["datagram_sha256"] = Value::String(datagram_sha256.clone());
            packet_index += 1;
        }
    };
    for path in ["store-pre-stop.cbor", "store-post-rebuild.cbor", "store-post-continuation.cbor"] {
        update_store_export(root, path, rewrite_store);
    }
    refresh_restart_export_digests(root);

    update_json_artifact(root, "host-commit-trace.json", "run.json", |trace| {
        let mut packet_index = 0_usize;
        for fact in trace["facts"].as_array_mut().expect("Host trace facts") {
            if fact["kind"] != "packet" {
                continue;
            }
            let (body_sha256, datagram_sha256) =
                replacements.get(packet_index).expect("replacement trace packet");
            fact["body_sha256"] = Value::String(body_sha256.clone());
            fact["datagram_sha256"] = Value::String(datagram_sha256.clone());
            fact["decoded_message"] = json!({
                "kind": "capabilities",
                "capability_sha256": encode_hex(&capability_body([1; 32], [3; 32], 1024)[..32]),
                "firmware_image_sha256": "01".repeat(32)
            });
            packet_index += 1;
        }
    });
    update_json_artifact(root, "restart-trace.json", "run.json", |trace| {
        trace["continuation"]["first_datagram_sha256"] = Value::String(replacements[11].1.clone());
    });
}

fn rewrite_post_restart_csi_identity(root: &Path, device_id: u64, source_mac: [u8; 6]) {
    const DATAGRAM_INDEX: usize = 12;
    let physical_path = root.join("physical-input.json");
    unseal_file(&physical_path);
    let mut physical: Value =
        serde_json::from_slice(&fs::read(&physical_path).expect("read physical input"))
            .expect("parse physical input");
    let datagram =
        &mut physical["datagrams"].as_array_mut().expect("physical datagrams")[DATAGRAM_INDEX];
    let old_digest = datagram["sha256"].as_str().expect("old datagram digest").to_owned();
    let sequence = u64::try_from(DATAGRAM_INDEX + 1).expect("fixture sequence");
    let bytes = fixture_datagram_for(sequence, device_id, source_mac);
    let path = datagram["path"].as_str().expect("datagram path").to_owned();
    let receive_utc_ns = datagram["received_utc_ns"]
        .as_str()
        .expect("receive time")
        .parse::<i64>()
        .expect("numeric receive time");
    let (body_sha256, body_binding_sha256) = packet_evidence_digests(receive_utc_ns, &bytes);
    let datagram_sha256 = sha256(&bytes);
    datagram["body_binding_sha256"] = Value::String(body_binding_sha256);
    datagram["device_id"] = Value::String(device_id.to_string());
    datagram["sha256"] = Value::String(datagram_sha256.clone());
    fs::write(&physical_path, canonical_json(&physical)).expect("rewrite physical input");
    reseal_file(&physical_path);

    let target = root.join(&path);
    unseal_file(&target);
    fs::write(&target, bytes).expect("rewrite post-restart ciphertext");
    reseal_file(&target);
    update_manifest_digest(root, "run.json", &path);
    update_manifest_digest(root, "run.json", "physical-input.json");

    let rewrite_fact = |fact: &mut Value| {
        if fact["datagram_sha256"].as_str() == Some(old_digest.as_str()) {
            fact["body_sha256"] = Value::String(body_sha256.clone());
            fact["datagram_sha256"] = Value::String(datagram_sha256.clone());
        }
    };
    for store_path in
        ["store-pre-stop.cbor", "store-post-rebuild.cbor", "store-post-continuation.cbor"]
    {
        update_store_export(root, store_path, |store| {
            for fact in store["facts"].as_array_mut().expect("Store facts") {
                rewrite_fact(fact);
            }
        });
    }
    update_json_artifact(root, "host-commit-trace.json", "run.json", |trace| {
        for fact in trace["facts"].as_array_mut().expect("Host trace facts") {
            rewrite_fact(fact);
        }
    });
    refresh_restart_export_digests(root);
}

fn rewrite_decode_rejected_csi_source_mac(root: &Path, source_mac: [u8; 6]) {
    const DATAGRAM_INDEX: usize = 11;
    const RECORD_SEQ: usize = 26;
    let physical_path = root.join("physical-input.json");
    unseal_file(&physical_path);
    let mut physical: Value =
        serde_json::from_slice(&fs::read(&physical_path).expect("read physical input"))
            .expect("parse physical input");
    let datagram =
        &mut physical["datagrams"].as_array_mut().expect("physical datagrams")[DATAGRAM_INDEX];
    let sequence = u64::try_from(DATAGRAM_INDEX + 1).expect("fixture sequence");
    let bytes = fixture_datagram_for(sequence, 1, source_mac);
    let path = datagram["path"].as_str().expect("datagram path").to_owned();
    let receive_utc_ns = datagram["received_utc_ns"]
        .as_str()
        .expect("receive time")
        .parse::<i64>()
        .expect("numeric receive time");
    let (body_sha256, body_binding_sha256) = packet_evidence_digests(receive_utc_ns, &bytes);
    let datagram_sha256 = sha256(&bytes);
    datagram["body_binding_sha256"] = Value::String(body_binding_sha256);
    datagram["sha256"] = Value::String(datagram_sha256.clone());
    fs::write(&physical_path, canonical_json(&physical)).expect("rewrite physical input");
    reseal_file(&physical_path);

    let target = root.join(&path);
    unseal_file(&target);
    fs::write(&target, bytes).expect("rewrite decode-rejected ciphertext");
    reseal_file(&target);
    update_manifest_digest(root, "run.json", &path);
    update_manifest_digest(root, "run.json", "physical-input.json");

    update_store_export(root, "store-post-continuation.cbor", |store| {
        store["facts"][RECORD_SEQ]["body_sha256"] = Value::String(body_sha256.clone());
        store["facts"][RECORD_SEQ]["datagram_sha256"] = Value::String(datagram_sha256.clone());
        store["commits"][RECORD_SEQ]["kind"] = Value::String("decode_rejected".to_owned());
        store["observations"]
            .as_array_mut()
            .expect("Store observations")
            .retain(|observation| observation["record_seq"] != RECORD_SEQ);
    });
    update_json_artifact(root, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][RECORD_SEQ]["body_sha256"] = Value::String(body_sha256);
        trace["facts"][RECORD_SEQ]["datagram_sha256"] = Value::String(datagram_sha256.clone());
        trace["facts"][RECORD_SEQ]["decoded_message"] = json!({
            "kind": "csi_data",
            "callback_tick_us": "3",
            "capability_sha256": encode_hex(&capability_body([1; 32], [3; 32], 1024)[..32]),
            "capture_sequence": sequence.to_string(),
            "channel": "1",
            "complex_sample_count": "3",
            "driver_rx_timestamp_us": "2"
        });
    });
    update_json_artifact(root, "restart-trace.json", "run.json", |trace| {
        trace["continuation"]["first_datagram_sha256"] = Value::String(datagram_sha256);
    });
    refresh_restart_export_digests(root);
}

fn move_first_datagram_before_run(root: &Path) {
    let physical_path = root.join("physical-input.json");
    unseal_file(&physical_path);
    let mut physical: Value =
        serde_json::from_slice(&fs::read(&physical_path).expect("read physical input"))
            .expect("parse physical input");
    let first = &mut physical["datagrams"].as_array_mut().expect("physical datagrams")[0];
    let path = first["path"].as_str().expect("datagram path").to_owned();
    let bytes = fs::read(root.join(&path)).expect("read first datagram");
    first["received_utc_ns"] = Value::String("0".to_owned());
    let (body_sha256, body_binding_sha256) = packet_evidence_vector(0, &bytes, None);
    first["body_binding_sha256"] = Value::String(body_binding_sha256.to_owned());
    fs::write(&physical_path, canonical_json(&physical)).expect("rewrite physical input");
    reseal_file(&physical_path);
    update_manifest_digest(root, "run.json", "physical-input.json");

    let body_sha256 = body_sha256.to_owned();
    for store_path in
        ["store-pre-stop.cbor", "store-post-rebuild.cbor", "store-post-continuation.cbor"]
    {
        update_store_export(root, store_path, |store| {
            store["facts"][1]["body_sha256"] = Value::String(body_sha256.clone());
        });
    }
    refresh_restart_export_digests(root);
    update_json_artifact(root, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][1]["body_sha256"] = Value::String(body_sha256);
    });
}

fn reorder_store_collection(root: &Path, collection: &str) {
    let paths = ["store-pre-stop.cbor", "store-post-rebuild.cbor", "store-post-continuation.cbor"];
    for path in paths {
        if collection == "capture_sessions" && path != "store-post-continuation.cbor" {
            continue;
        }
        update_store_export(root, path, |store| {
            let values = store[collection].as_array_mut().expect("ordered Store collection");
            match collection {
                "capture_sessions" => values.reverse(),
                "replay_identities" => {
                    let mut extra = values[0].clone();
                    extra["device_id"] = Value::from(2_u64);
                    values.insert(0, extra);
                }
                "baselines" | "relationships" => {
                    let mut extra = values[0].clone();
                    extra["link"] = Value::String("link-z".to_owned());
                    values.insert(0, extra);
                }
                _ => panic!("unsupported Store collection"),
            }
        });
    }
    refresh_restart_export_digests(root);
    if collection == "baselines" || collection == "relationships" {
        let field =
            if collection == "baselines" { "baseline_sha256" } else { "relationship_sha256" };
        let pre = store_collection_sha256(root, "store-pre-stop.cbor", collection);
        let continuation =
            store_collection_sha256(root, "store-post-continuation.cbor", collection);
        update_json_artifact(root, "host-commit-trace.json", "run.json", |trace| {
            trace["facts"][23]["transaction_b"][field] = Value::String(pre);
            trace["facts"][26]["transaction_b"][field] = Value::String(continuation);
        });
    }
}

fn replace_store_with_golden(root: &Path, path: &str, bytes: &[u8]) {
    let target = root.join(path);
    unseal_file(&target);
    fs::write(&target, bytes).expect("replace Store export with golden bytes");
    reseal_file(&target);
    update_manifest_digest(root, "run.json", path);
}

fn install_dynamic_store_exports(root: &Path) {
    let dynamic_pre = include_bytes!("fixtures/evidence/v1/store-pre-stop-dynamic.cbor");
    let dynamic_continuation =
        include_bytes!("fixtures/evidence/v1/store-post-continuation-dynamic.cbor");
    replace_store_with_golden(root, "store-pre-stop.cbor", dynamic_pre);
    replace_store_with_golden(root, "store-post-rebuild.cbor", dynamic_pre);
    replace_store_with_golden(root, "store-post-continuation.cbor", dynamic_continuation);
    refresh_relationship_trace_digests(root);
    refresh_restart_export_digests(root);
}

fn refresh_relationship_trace_digests(root: &Path) {
    let pre_relationships = store_collection_sha256(root, "store-pre-stop.cbor", "relationships");
    let continued_relationships =
        store_collection_sha256(root, "store-post-continuation.cbor", "relationships");
    update_json_artifact(root, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][23]["transaction_b"]["relationship_sha256"] =
            Value::String(pre_relationships);
        trace["facts"][28]["transaction_b"]["relationship_sha256"] =
            Value::String(continued_relationships);
    });
}

fn refresh_baseline_trace_digests(root: &Path) {
    let pre_baselines = store_collection_sha256(root, "store-pre-stop.cbor", "baselines");
    let continued_baselines =
        store_collection_sha256(root, "store-post-continuation.cbor", "baselines");
    update_json_artifact(root, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][23]["transaction_b"]["baseline_sha256"] = Value::String(pre_baselines);
        trace["facts"][28]["transaction_b"]["baseline_sha256"] = Value::String(continued_baselines);
    });
}

fn update_json_artifact(root: &Path, path: &str, owner: &str, update: impl FnOnce(&mut Value)) {
    let target = root.join(path);
    unseal_file(&target);
    let mut value: Value = serde_json::from_slice(&fs::read(&target).expect("read JSON artifact"))
        .expect("parse JSON artifact");
    update(&mut value);
    fs::write(&target, canonical_json(&value)).expect("rewrite canonical JSON artifact");
    reseal_file(&target);
    update_manifest_digest(root, owner, path);
}

fn update_screenshot_trace_digest(root: &Path, screenshot_path: &str) {
    let digest = sha256(&fs::read(root.join(screenshot_path)).expect("read changed screenshot"));
    update_json_artifact(root, "chrome-trace.json", "observer.json", |trace| {
        let event = trace["events"]
            .as_array_mut()
            .expect("Chrome trace events")
            .iter_mut()
            .find(|event| event["screenshot"] == screenshot_path)
            .expect("screenshot trace event");
        event["screenshot_sha256"] = Value::String(digest);
    });
}

fn update_root_receipt(root: &Path, update: impl FnOnce(&mut Value)) {
    let target = root.join("run.json");
    unseal_file(&target);
    let mut value: Value = serde_json::from_slice(&fs::read(&target).expect("read run receipt"))
        .expect("parse run receipt");
    update(&mut value);
    fs::write(&target, canonical_json(&value)).expect("rewrite canonical run receipt");
    reseal_file(&target);
}

fn run_verifier(root: &Path) -> std::process::Output {
    run_evidence_operation(root, "verify")
}

fn run_evidence_operation(root: &Path, operation: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["evidence", operation, root.to_str().expect("UTF-8 package path")])
        .output()
        .expect("run independent evidence process")
}

fn assert_rejected(root: &Path) {
    let output = run_verifier(root);
    assert!(
        !output.status.success(),
        "invalid package unexpectedly passed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!root.join("verification.json").exists());
}

fn assert_rejected_without_panic(root: &Path) {
    let output = run_verifier(root);
    assert!(!output.status.success(), "invalid package unexpectedly passed");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("panicked"),
        "invalid package panicked instead of returning an evidence error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
}

fn assert_promptly_rejected_without_panic(root: &Path) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["evidence", "verify", root.to_str().expect("UTF-8 package path")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start independent evidence process");
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().expect("poll independent evidence process").is_none() {
        if Instant::now() >= deadline {
            child.kill().expect("stop stalled independent evidence process");
            child.wait().expect("reap stalled independent evidence process");
            panic!("invalid package stalled independent evidence verification");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect independent evidence process output");
    assert!(!output.status.success(), "invalid package unexpectedly passed");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("panicked"),
        "invalid package panicked instead of returning an evidence error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
}

fn remove_package(root: &Path) {
    if root.exists() {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("unseal fixture root");
        for directory in ["datagrams", "http", "screenshots"] {
            let path = root.join(directory);
            if path.exists() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .expect("unseal fixture directory");
            }
        }
        fs::remove_dir_all(root).expect("remove evidence package fixture");
    }
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn bounded_audit_entry_exhaustion_does_not_limit_host_commits() {
    let fixture = RuntimeFixture::new();
    let host = start_host_with_manual_clock(&fixture.config).await.expect("start Host");
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let accepted =
        http_request(host.http_address(), &relationship_command(profile, "begin_learning")).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    wait_for_projection(host.http_address(), "1").await;
    let destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        host.capture_address().port(),
    );
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let mut sequence = 0_u64;
    let mut committed_projection = 1_u64;
    while committed_projection < 4097 {
        for _ in 0..16 {
            sequence += 1;
            advance_host_clock(&host, Duration::from_millis(11));
            sender
                .send_to(&seal_runtime_datagram(1, sequence, &capability), destination)
                .await
                .expect("send simulated capability");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        committed_projection = projection_sequence(host.http_address()).await;
        assert!(sequence < 8192, "Host did not commit enough bounded audit inputs");
    }

    let committed = latest_relationship(host.http_address(), profile).await;
    assert!(
        committed["receipt"]["projection_commit"]["sequence"]
            .as_str()
            .expect("projection sequence")
            .parse::<u64>()
            .expect("numeric projection sequence")
            >= 4097
    );
    let error = whisper::evidence::capture_evidence_pre_restart_audit(&host)
        .expect_err("overflowed audit cannot produce bounded evidence");
    assert_eq!(
        error.source().expect("retained evidence cause").to_string(),
        "transaction-B evidence audit is incomplete"
    );
    host.shutdown().await.expect("stop Host");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn bounded_audit_snapshot_exhaustion_does_not_limit_dynamic_subjects() {
    let fixture = RuntimeFixture::new();
    let host = start_host_with_manual_clock(&fixture.config).await.expect("start Host");
    set_evidence_snapshot_row_limit(&host, 1);
    let first_profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let last_profile = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for (profile, projection) in [(first_profile, "1"), (last_profile, "2")] {
        let accepted =
            http_request(host.http_address(), &relationship_command(profile, "begin_learning"))
                .await;
        assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
        wait_for_projection(host.http_address(), projection).await;
    }
    let discovery = response_json(
        &http_request(
            host.http_address(),
            "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    assert_eq!(discovery["receipt"]["projection_commit"]["sequence"], "2");
    assert!(
        discovery["data"]["subjects"]
            .as_array()
            .expect("relationship subjects")
            .iter()
            .any(|subject| subject["profile"] == last_profile)
    );
    let error = whisper::evidence::capture_evidence_pre_restart_audit(&host)
        .expect_err("oversized audit snapshot cannot produce bounded evidence");
    assert_eq!(
        error.source().expect("retained evidence cause").to_string(),
        "transaction-B evidence audit is incomplete"
    );
    host.shutdown().await.expect("stop Host");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn evidence_audit_and_store_snapshot_remain_one_prefix_during_commit_overlap() {
    let fixture = RuntimeFixture::new();
    let mut host = start_host_with_manual_clock(&fixture.config).await.expect("start Host");
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let accepted =
        http_request(host.http_address(), &relationship_command(profile, "begin_learning")).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    wait_for_projection(host.http_address(), "1").await;

    let mut hold = hold_evidence_snapshot(&mut host);
    let host = std::sync::Arc::new(host);
    let capture_host = std::sync::Arc::clone(&host);
    let capture = tokio::task::spawn_blocking(move || {
        whisper::evidence::capture_evidence_pre_restart_audit(&capture_host)
    });
    hold.wait_until_blocked();

    let destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        host.capture_address().port(),
    );
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender
        .send_to(&seal_runtime_datagram(1, 1, &capability), destination)
        .await
        .expect("send overlapping authenticated input");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(projection_sequence(host.http_address()).await, 1);

    hold.release();
    capture.await.expect("join evidence snapshot").unwrap_or_else(|error| {
        let source = error.source().and_then(std::error::Error::source).map(ToString::to_string);
        panic!("capture old consistent audit/Store prefix: {error}; cause={source:?}");
    });
    wait_for_projection(host.http_address(), "2").await;
    whisper::evidence::capture_evidence_pre_restart_audit(&host)
        .expect("capture new consistent audit/Store prefix");

    let host = std::sync::Arc::try_unwrap(host).unwrap_or_else(|_| panic!("release Host clone"));
    host.shutdown().await.expect("stop Host");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn real_host_exports_byte_equal_committed_state_across_read_only_rebuild() {
    let fixture = RuntimeFixture::new();
    let package = fixture.root.join("package");
    fs::create_dir(&package).expect("create simulated evidence package");
    let first = start_host_with_manual_clock(&fixture.config).await.expect("start first Host");
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let accepted =
        http_request(first.http_address(), &relationship_command(profile, "begin_learning")).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    wait_for_projection(first.http_address(), "1").await;

    let first_destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        first.capture_address().port(),
    );
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender
        .send_to(&seal_runtime_datagram(1, 1, &capability), first_destination)
        .await
        .expect("send simulated capability");
    wait_for_projection(first.http_address(), "2").await;
    let mut counters = (0_u64, 1_u64, 2_u64);
    for _ in 0..15 {
        send_csi_window(&first, &sender, first_destination, &capability[..32], &mut counters).await;
    }
    let learning = latest_relationship(first.http_address(), profile).await;
    assert_eq!(
        learning["data"]["knowledge"],
        json!({"kind": "unknown", "reason": "baseline_learning"})
    );
    let (_, unknown_observation) = relationship_observation(first.http_address(), profile).await;
    assert_eq!(unknown_observation, learning);
    let subject = whisper::evidence::EvidenceSubject::new(
        whisper::evidence::EvidenceSemanticSessionId::try_new(
            learning["data"]["session_id"].as_str().expect("Semantic Session"),
        )
        .expect("validated Semantic Session"),
        whisper::evidence::EvidenceLinkId::try_new(
            learning["data"]["link"].as_str().expect("Link"),
        )
        .expect("validated Link"),
        whisper::evidence::EvidenceProfileId::try_new(
            learning["data"]["profile"].as_str().expect("Profile"),
        )
        .expect("validated Profile"),
    );
    let committed_unknown =
        whisper::evidence::capture_evidence_unknown_observation(&first, &subject)
            .expect("capture committed Unknown observation");
    let committed =
        http_request(first.http_address(), &relationship_command(profile, "commit")).await;
    assert!(committed.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    counters.2 += 1;
    counters.2 = wait_for_projection_at_least(first.http_address(), counters.2).await;
    send_csi_window(&first, &sender, first_destination, &capability[..32], &mut counters).await;
    let stable = latest_relationship(first.http_address(), profile).await;
    assert_eq!(stable["data"]["knowledge"], json!({"kind": "known", "value": "stable"}));
    assert!(whisper::evidence::capture_evidence_unknown_observation(&first, &subject).is_err());
    let semantic_session = stable["data"]["session_id"].clone();
    let store_id = stable["receipt"]["projection_commit"]["store_id"].clone();
    let result_time = stable["data"]["result_time"]
        .as_str()
        .expect("pre-restart result time")
        .parse::<u64>()
        .expect("u64 pre-restart result time");
    let most_recent_change = stable["data"]["most_recent_change"].clone();
    let (_, stable_pre_observation) = relationship_observation(first.http_address(), profile).await;
    assert_eq!(stable_pre_observation, stable);

    let pre_stop = package.join("store-pre-stop.cbor");
    whisper::evidence::write_current_store_evidence(&first, &pre_stop)
        .expect("write pre-stop Store export");
    let pre_restart_audit = whisper::evidence::capture_evidence_pre_restart_audit(&first)
        .expect("capture committed pre-restart transaction-B audit");
    assert!(
        whisper::evidence::write_rebuild_store_evidence(&first, package.join("invalid.cbor"))
            .is_err()
    );
    first.shutdown().await.expect("stop first Host");

    let second = start_host_with_manual_clock(&fixture.config).await.expect("restart Host");
    set_evidence_snapshot_row_limit(&second, 2);
    let post_rebuild = package.join("store-post-rebuild.cbor");
    whisper::evidence::write_rebuild_store_evidence(&second, &post_rebuild)
        .expect("write mechanically read-only rebuild export");
    assert_eq!(
        fs::read(&pre_stop).expect("read pre-stop export"),
        fs::read(&post_rebuild).expect("read post-rebuild export")
    );
    let second_destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        second.capture_address().port(),
    );
    counters.1 += 1;
    sender
        .send_to(&seal_runtime_datagram(1, counters.1, &capability), second_destination)
        .await
        .expect("send first post-restart physical record");
    counters.2 += 1;
    counters.2 = wait_for_projection_at_least(second.http_address(), counters.2).await;
    send_csi_window(&second, &sender, second_destination, &capability[..32], &mut counters).await;
    let continued = latest_relationship(second.http_address(), profile).await;
    assert_eq!(continued["data"]["session_id"], semantic_session);
    assert_eq!(continued["receipt"]["projection_commit"]["store_id"], store_id);
    assert_eq!(continued["data"]["knowledge"], stable["data"]["knowledge"]);
    assert_eq!(continued["data"]["most_recent_change"], most_recent_change);
    assert!(
        continued["data"]["result_time"]
            .as_str()
            .expect("continued result time")
            .parse::<u64>()
            .expect("u64 continued result time")
            > result_time
    );
    let (_, stable_post_observation) =
        relationship_observation(second.http_address(), profile).await;
    assert_eq!(stable_post_observation, continued);
    let dynamic_profile = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let accepted = http_request(
        second.http_address(),
        &relationship_command(dynamic_profile, "begin_learning"),
    )
    .await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    counters.2 += 1;
    counters.2 = wait_for_projection_at_least(second.http_address(), counters.2).await;
    let after_dynamic_command = latest_relationship(second.http_address(), profile).await;
    assert_eq!(after_dynamic_command["data"], continued["data"]);
    assert_eq!(
        after_dynamic_command["receipt"]["projection_commit"]["sequence"],
        counters.2.to_string()
    );
    whisper::evidence::write_current_store_evidence(
        &second,
        package.join("store-post-continuation.cbor"),
    )
    .expect("write post-continuation Store export");
    let post_store: Value = ciborium::from_reader(
        fs::read(package.join("store-post-continuation.cbor"))
            .expect("read post-continuation Store")
            .as_slice(),
    )
    .expect("parse post-continuation Store");
    let interval =
        whisper::evidence::EvidenceInterval::try_new(1, 3).expect("validated run interval");
    let identity = whisper::evidence::EvidenceRunIdentity::new(
        whisper::evidence::EvidenceArtifactIdentity::new(
            whisper::evidence::EvidenceConfigSha256::try_new(
                post_store["config_digest"].as_str().expect("config digest"),
            )
            .expect("configuration digest"),
            whisper::evidence::EvidenceProvisioningSha256::try_new("dd".repeat(32))
                .expect("provisioning digest"),
        ),
        whisper::evidence::EvidenceFirmwareIdentity::new(
            whisper::evidence::EvidenceFirmwareCapabilitySha256::try_new(encode_hex(
                &capability[..32],
            ))
            .expect("firmware capability digest"),
            whisper::evidence::EvidenceFirmwareImageSha256::try_new("01".repeat(32))
                .expect("firmware image digest"),
            whisper::evidence::EvidenceFirmwareSourceRevision::try_new("aa".repeat(20))
                .expect("firmware source revision"),
        ),
    );
    let metadata = whisper::evidence::EvidenceRunMetadata::try_new(
        whisper::evidence::EvidenceRunId::try_new("simulated-real-host").expect("validated run ID"),
        interval,
        identity,
        subject.clone(),
        committed_unknown,
    )
    .expect("validated producer metadata");
    let downtime =
        whisper::evidence::EvidenceInterval::try_new(1, 2).expect("validated restart interval");
    whisper::evidence::write_evidence_restart_trace(
        &second,
        &package,
        &whisper::evidence::EvidenceSensorId::try_new("sensor-a").expect("validated Sensor ID"),
        &subject,
        downtime,
    )
    .expect("write controlled restart trace");
    whisper::evidence::write_evidence_input_and_commits(
        &second,
        &package,
        &whisper::evidence::EvidenceSensorId::try_new("sensor-a").expect("validated Sensor ID"),
        &metadata,
        &pre_restart_audit,
    )
    .expect("write committed physical input and A/B trace");
    let physical: Value = serde_json::from_slice(
        &fs::read(package.join("physical-input.json")).expect("read physical input"),
    )
    .expect("parse physical input");
    let trace: Value = serde_json::from_slice(
        &fs::read(package.join("host-commit-trace.json")).expect("read Host trace"),
    )
    .expect("parse Host trace");
    let unknown_creator = learning["data"]["creator_commit"]["sequence"]
        .as_str()
        .expect("Unknown creator commit")
        .parse::<usize>()
        .expect("numeric Unknown creator commit");
    let unknown_fact = &trace["facts"][unknown_creator - 1];
    assert_eq!(
        unknown_fact["transaction_b"]["creator_commit_seq"],
        learning["data"]["creator_commit"]["sequence"]
    );
    assert!(
        unknown_fact["transaction_b"]["effects"]
            .as_array()
            .expect("Unknown transaction-B effects")
            .iter()
            .any(|effect| effect == "relationship_projection")
    );
    assert!(unknown_fact["transaction_b"]["relationship_sha256"].is_string());
    let learning_baseline_effects = trace["facts"]
        .as_array()
        .expect("Host facts")
        .iter()
        .take_while(|fact| fact["command"]["command"] != "commit")
        .filter(|fact| fact["transaction_b"]["baseline_sha256"].is_string())
        .count();
    assert!(
        learning_baseline_effects > 1,
        "commit-time audit omitted intermediate Learning baseline effects"
    );
    let restart: Value = serde_json::from_slice(
        &fs::read(package.join("restart-trace.json")).expect("read restart trace"),
    )
    .expect("parse restart trace");
    assert_eq!(restart["rebuild"]["writer_opens"], "0");
    assert_eq!(restart["continuation"]["knowledge"], "stable");
    assert_eq!(
        physical["datagrams"].as_array().expect("physical datagrams").len(),
        trace["facts"]
            .as_array()
            .expect("Host facts")
            .iter()
            .filter(|fact| fact["kind"] == "packet")
            .count()
    );
    whisper::evidence::write_evidence_run_receipt(&second, &package, &metadata)
        .expect("write root producer receipt");
    let run: Value =
        serde_json::from_slice(&fs::read(package.join("run.json")).expect("read producer receipt"))
            .expect("parse producer receipt");
    assert_eq!(run["identities"]["asset_sha256"], production_asset_sha256());
    whisper::evidence::seal_evidence_producer(&package)
        .unwrap_or_else(|error| panic!("seal real simulated producer set: {error}"));
    second.shutdown().await.expect("stop restarted Host");
    remove_package(&package);
}

#[test]
fn evidence_identity_types_expose_checked_standard_conversions_and_display() {
    use std::str::FromStr;

    fn assert_value_traits<T: Eq + std::hash::Hash + Ord + PartialEq + PartialOrd>() {}
    assert_value_traits::<whisper::evidence::EvidenceSemanticSessionId>();
    assert_value_traits::<whisper::evidence::EvidenceLinkId>();
    assert_value_traits::<whisper::evidence::EvidenceProfileId>();
    assert_value_traits::<whisper::evidence::EvidenceConfigSha256>();
    assert_value_traits::<whisper::evidence::EvidenceProvisioningSha256>();
    assert_value_traits::<whisper::evidence::EvidenceFirmwareCapabilitySha256>();
    assert_value_traits::<whisper::evidence::EvidenceFirmwareImageSha256>();
    assert_value_traits::<whisper::evidence::EvidenceFirmwareSourceRevision>();
    assert_value_traits::<whisper::evidence::EvidenceRunId>();
    assert_value_traits::<whisper::evidence::EvidenceChromeVersion>();
    assert_value_traits::<whisper::evidence::EvidencePageInstanceId>();
    assert_value_traits::<whisper::evidence::EvidenceSensorId>();
    assert_value_traits::<whisper::evidence::EvidenceSubject>();
    assert_value_traits::<whisper::evidence::EvidenceInterval>();
    assert_value_traits::<whisper::evidence::EvidenceViewport>();
    assert_value_traits::<whisper::evidence::EvidenceUnknownObservation>();

    let session = whisper::evidence::EvidenceSemanticSessionId::from_str("semantic-1")
        .expect("parse Semantic Session ID");
    let link =
        whisper::evidence::EvidenceLinkId::try_from("link-a".to_owned()).expect("parse Link ID");
    let profile =
        whisper::evidence::EvidenceProfileId::from_str(&"55".repeat(32)).expect("parse Profile ID");
    assert_eq!(session.to_string(), "semantic-1");
    assert_eq!(link.to_string(), "link-a");
    assert_eq!(profile.to_string(), "55".repeat(32));
    assert!(whisper::evidence::EvidenceSemanticSessionId::from_str("").is_err());
    assert!(whisper::evidence::EvidenceLinkId::from_str("/private/hidden").is_err());
    assert!(whisper::evidence::EvidenceProfileId::from_str(&"AA".repeat(32)).is_err());
    assert!(whisper::evidence::EvidenceRunId::from_str("bad/run").is_err());
    assert!(whisper::evidence::EvidenceChromeVersion::from_str("").is_err());
    assert!(whisper::evidence::EvidencePageInstanceId::from_str("/private/hidden").is_err());
    assert!(whisper::evidence::EvidenceSensorId::from_str(" ").is_err());
}

#[test]
fn verifier_rejects_an_incomplete_package_without_emitting_a_receipt() {
    let root = package_directory();
    std::fs::create_dir(&root).expect("create evidence package root");

    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["evidence", "verify", root.to_str().expect("UTF-8 package path")])
        .output()
        .expect("run independent verifier process");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("evidence verification failed"),
        "verifier used the wrong failure boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());

    std::fs::remove_dir_all(root).expect("remove evidence package fixture");
}

#[test]
fn verifier_accepts_one_complete_sealed_package_and_emits_the_only_pass_receipt() {
    let root = package_directory();
    complete_package(&root);

    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["evidence", "verify", root.to_str().expect("UTF-8 package path")])
        .output()
        .expect("run independent verifier process");

    assert!(
        output.status.success(),
        "verifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verification = fs::read(root.join("verification.json")).expect("verification receipt");
    let value: Value = serde_json::from_slice(&verification).expect("verification JSON");
    assert_eq!(
        value.as_object().expect("verification root").keys().collect::<Vec<_>>(),
        vec![
            "checks",
            "interval",
            "observer_artifacts",
            "observer_sha256",
            "producer_artifacts",
            "result",
            "run_sha256",
            "schema_version",
            "verifier",
        ]
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["result"], "PASS");
    assert_eq!(
        value["verifier"].as_object().expect("verifier identity").keys().collect::<Vec<_>>(),
        vec!["executable_sha256", "source_sha256"]
    );
    let checks = value["checks"].as_array().expect("named check results");
    assert_eq!(checks.len(), 15);
    assert!(checks.iter().all(|check| {
        check.as_object().is_some_and(|fields| {
            fields.keys().collect::<Vec<_>>() == vec!["name", "result"]
                && fields["result"] == "PASS"
        })
    }));

    remove_package(&root);
}

#[test]
fn verifier_accepts_chrome_rgb_state_screenshots() {
    let root = package_directory();
    complete_package(&root);
    for (path, state) in [
        ("screenshots/unknown.png", "unknown"),
        ("screenshots/stable-pre-restart.png", "stable"),
        ("screenshots/stable-post-restart.png", "stable"),
    ] {
        let (pattern, foreground) = state_fixture(state);
        let foreground = [foreground[0], foreground[1], foreground[2]];
        let screenshot = root.join(path);
        unseal_file(&screenshot);
        fs::write(&screenshot, chrome_screenshot_png(&pattern, foreground))
            .expect("write Chrome RGB marker screenshot");
        reseal_file(&screenshot);
        update_manifest_digest(&root, "observer.json", path);
        update_screenshot_trace_digest(&root, path);
    }

    let output = run_verifier(&root);
    assert!(
        output.status.success(),
        "Chrome RGB screenshots were rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    remove_package(&root);
}

#[test]
fn verifier_selects_one_subject_without_imposing_a_relationship_cardinality_limit() {
    let root = package_directory();
    complete_package(&root);
    install_dynamic_store_exports(&root);

    let output = run_verifier(&root);
    assert!(
        output.status.success(),
        "dynamic-N evidence package was rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    remove_package(&root);
}

#[test]
fn verifier_rejects_invalid_non_selected_dynamic_relationship() {
    let root = package_directory();
    complete_package(&root);
    install_dynamic_store_exports(&root);
    for path in ["store-pre-stop.cbor", "store-post-rebuild.cbor", "store-post-continuation.cbor"] {
        update_store_export(&root, path, |store| {
            let relationship = store["relationships"]
                .as_array_mut()
                .expect("dynamic relationships")
                .iter_mut()
                .find(|relationship| relationship["link"] != "link-a")
                .expect("non-selected relationship");
            relationship["knowledge"] = json!({"kind": "known", "value": "presence"});
        });
    }
    refresh_relationship_trace_digests(&root);
    refresh_restart_export_digests(&root);

    assert_rejected(&root);
    remove_package(&root);

    let partial_change = package_directory();
    complete_package(&partial_change);
    install_dynamic_store_exports(&partial_change);
    for path in ["store-pre-stop.cbor", "store-post-rebuild.cbor", "store-post-continuation.cbor"] {
        update_store_export(&partial_change, path, |store| {
            let relationship = store["relationships"]
                .as_array_mut()
                .expect("dynamic relationships")
                .iter_mut()
                .find(|relationship| relationship["link"] != "link-a")
                .expect("non-selected relationship");
            relationship["change_current"] = Value::Null;
        });
    }
    refresh_relationship_trace_digests(&partial_change);
    refresh_restart_export_digests(&partial_change);
    assert_rejected(&partial_change);
    remove_package(&partial_change);

    let invalid_baseline = package_directory();
    complete_package(&invalid_baseline);
    install_dynamic_store_exports(&invalid_baseline);
    for path in ["store-pre-stop.cbor", "store-post-rebuild.cbor", "store-post-continuation.cbor"] {
        update_store_export(&invalid_baseline, path, |store| {
            let mut extra = store["baselines"][0].clone();
            let state = canonical_cbor_mutation(&json!({"not": "a baseline state"}));
            extra["link"] = Value::String("link-z".to_owned());
            extra["profile"] = Value::String("77".repeat(32));
            extra["state_cbor"] = Value::String(encode_hex(&state));
            extra["state_sha256"] = Value::String(sha256(&state));
            store["baselines"].as_array_mut().expect("dynamic baselines").push(extra);
        });
    }
    refresh_baseline_trace_digests(&invalid_baseline);
    refresh_restart_export_digests(&invalid_baseline);
    assert_rejected(&invalid_baseline);
    remove_package(&invalid_baseline);
}

#[test]
fn verifier_rejects_http_change_that_disagrees_with_committed_relationship() {
    let root = package_directory();
    complete_package(&root);
    for path in ["http/stable-pre-restart.json", "http/stable-post-restart.json"] {
        update_json_artifact(&root, path, "observer.json", |response| {
            response["data"]["most_recent_change"]["previous"] =
                json!({"kind": "unknown", "reason": "low_quality"});
            response["data"]["most_recent_change"]["current"] =
                json!({"kind": "known", "value": "changing"});
        });
    }

    assert_rejected(&root);
    remove_package(&root);
}

#[test]
fn verifier_rejects_incorrect_chrome_transition_values() {
    for (event, field, value) in [
        (1_usize, "change_state", "Unknown(LowQuality) → Changing"),
        (4, "change_state", "Unknown(LowQuality) → Changing"),
        (1, "change_time", "101"),
        (4, "change_time", "101"),
    ] {
        let root = package_directory();
        complete_package(&root);
        update_json_artifact(&root, "chrome-trace.json", "observer.json", |trace| {
            trace["events"][event][field] = Value::String(value.to_owned());
        });

        assert_rejected(&root);
        remove_package(&root);
    }
}

#[test]
fn verifier_rejects_changed_selection_or_sensitive_visible_chrome_text() {
    let changed_selection = package_directory();
    complete_package(&changed_selection);
    update_json_artifact(&changed_selection, "chrome-trace.json", "observer.json", |trace| {
        trace["events"][3]["selection"]["link"] = Value::String("link-z".to_owned());
    });
    assert_rejected(&changed_selection);
    remove_package(&changed_selection);

    let sensitive_text = package_directory();
    complete_package(&sensitive_text);
    update_json_artifact(&sensitive_text, "chrome-trace.json", "observer.json", |trace| {
        trace["events"][1]["visible_text"] = json!(["network 192.168.1.10"]);
    });
    assert_rejected(&sensitive_text);
    remove_package(&sensitive_text);
}

#[test]
fn verifier_rejects_raw_cisco_mac_and_private_ipv6_cleartext() {
    for sensitive_text in ["source 02000000000a", "source 0200.0000.000a", "peer fd00::1"] {
        let root = package_directory();
        complete_package(&root);
        update_json_artifact(&root, "chrome-trace.json", "observer.json", |trace| {
            trace["events"][1]["visible_text"] = json!([sensitive_text]);
        });

        let output = run_verifier(&root);
        assert!(!output.status.success(), "sensitive cleartext unexpectedly passed");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("sensitive cleartext"),
            "cleartext was rejected outside the privacy gate: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!root.join("verification.json").exists());
        remove_package(&root);
    }
}

#[test]
fn verifier_rejects_unverified_chrome_application_identity() {
    let root = package_directory();
    complete_package(&root);
    let observer = root.join("observer.json");
    unseal_file(&observer);
    let mut value: Value =
        serde_json::from_slice(&fs::read(&observer).expect("read observer receipt"))
            .expect("parse observer receipt");
    value["browser"]["application_id"] = Value::String("org.chromium.Chromium".to_owned());
    fs::write(&observer, canonical_json(&value)).expect("rewrite observer identity");
    reseal_file(&observer);

    assert_rejected(&root);
    remove_package(&root);
}

#[test]
fn verifier_rejects_a_screenshot_that_does_not_encode_its_trace_state() {
    let root = package_directory();
    complete_package(&root);
    let target = root.join("screenshots/stable-pre-restart.png");
    unseal_file(&target);
    fs::write(
        &target,
        fs::read(root.join("screenshots/unknown.png")).expect("read Unknown marker"),
    )
    .expect("replace Stable marker with Unknown marker");
    reseal_file(&target);
    update_manifest_digest(&root, "observer.json", "screenshots/stable-pre-restart.png");
    update_screenshot_trace_digest(&root, "screenshots/stable-pre-restart.png");

    let output = run_verifier(&root);
    assert!(!output.status.success(), "wrong visual state unexpectedly passed");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("visual state"),
        "wrong marker failed outside the visual state gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
    remove_package(&root);
}

#[test]
fn verifier_rejects_a_screenshot_changed_outside_its_state_marker() {
    let root = package_directory();
    complete_package(&root);
    let (pattern, foreground) = state_fixture("stable");
    let target = root.join("screenshots/stable-pre-restart.png");
    unseal_file(&target);
    fs::write(&target, screenshot_png_with_background(&pattern, foreground, [246, 249, 248, 255]))
        .expect("replace pixels outside the Stable marker");
    reseal_file(&target);
    update_manifest_digest(&root, "observer.json", "screenshots/stable-pre-restart.png");

    assert_rejected(&root);
    remove_package(&root);
}

#[test]
fn public_evidence_path_api_accepts_an_owned_root() {
    let root = package_directory();
    complete_package(&root);

    let error = whisper::evidence::verify_evidence_package(root.clone())
        .expect_err("integration-test executable unexpectedly matched the Host identity");
    assert!(error.source().is_some(), "owned-path verification lost its source error");
    remove_package(&root);
}

#[test]
fn verifier_rejects_an_oversized_member_before_reading_it() {
    let root = package_directory();
    complete_package(&root);
    let target = root.join("chrome-trace.json");
    unseal_file(&target);
    fs::File::options()
        .write(true)
        .open(&target)
        .expect("open oversized member")
        .set_len(16 * 1024 * 1024 + 1)
        .expect("extend oversized member");
    reseal_file(&target);

    let output = run_verifier(&root);
    assert!(!output.status.success(), "oversized member unexpectedly passed");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("bounded byte limit"),
        "member was not rejected at the bounded read boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
    remove_package(&root);
}

#[test]
fn verifier_rejects_an_oversized_package_before_reading_all_members() {
    let root = package_directory();
    complete_package(&root);
    for path in [
        "screenshots/unknown.png",
        "screenshots/stable-pre-restart.png",
        "screenshots/stable-post-restart.png",
    ] {
        let target = root.join(path);
        unseal_file(&target);
        fs::File::options()
            .write(true)
            .open(&target)
            .expect("open package member")
            .set_len(12 * 1024 * 1024)
            .expect("extend package member");
        reseal_file(&target);
    }

    let output = run_verifier(&root);
    assert!(!output.status.success(), "oversized package unexpectedly passed");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("bounded byte limit"),
        "package was not rejected at the bounded read boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
    remove_package(&root);
}

#[test]
fn verifier_rejects_too_many_zero_byte_members_at_the_allocation_boundary() {
    let root = package_directory();
    fs::create_dir_all(&root).expect("create evidence package root");
    for index in 0..=4096 {
        let member = root.join(format!("member-{index:04}"));
        fs::write(&member, []).expect("write empty package member");
        reseal_file(&member);
    }

    let error =
        whisper::evidence::verify_evidence_package(&root).expect_err("member-heavy package passed");
    assert!(
        error.to_string().contains("bounded member limit"),
        "member-heavy package did not reach its allocation bound: {error}"
    );
    remove_package(&root);
}

#[test]
fn public_evidence_errors_redact_sensitive_paths_across_the_source_chain() {
    let sensitive = package_directory().join("operator-secret");
    let sensitive_text = sensitive.to_string_lossy().into_owned();
    let error =
        whisper::evidence::verify_evidence_package(&sensitive).expect_err("missing package passed");

    let mut rendered = vec![error.to_string(), format!("{error:?}")];
    let mut source_count = 0_usize;
    let mut source = error.source();
    while let Some(current) = source {
        source_count += 1;
        rendered.push(current.to_string());
        rendered.push(format!("{current:?}"));
        source = current.source();
    }
    assert!(source_count >= 2, "public evidence error lost its retained I/O cause chain");
    assert!(
        rendered.iter().all(|value| !value.contains(&sensitive_text)),
        "public evidence error leaked the sensitive path: {rendered:?}"
    );
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn public_evidence_store_errors_redact_managed_paths_across_the_source_chain() {
    let fixture = RuntimeFixture::new();
    let host = start_host_with_manual_clock(&fixture.config).await.expect("start Host");
    let managed = fixture.root.join("managed");
    let displaced = fixture.root.join("operator-secret-managed");
    fs::rename(&managed, &displaced).expect("displace managed Store root");
    let error = whisper::evidence::capture_evidence_pre_restart_audit(&host)
        .expect_err("missing managed Store root produced evidence");
    fs::rename(&displaced, &managed).expect("restore managed Store root");

    let sensitive_text = managed.to_string_lossy().into_owned();
    let mut rendered = vec![error.to_string(), format!("{error:?}")];
    let mut source_count = 0_usize;
    let mut source = error.source();
    while let Some(current) = source {
        source_count += 1;
        rendered.push(current.to_string());
        rendered.push(format!("{current:?}"));
        source = current.source();
    }
    assert!(source_count >= 2, "public evidence error lost its retained Store cause chain");
    assert!(
        rendered.iter().all(|value| !value.contains(&sensitive_text)),
        "public evidence error leaked the managed Store path: {rendered:?}"
    );
    host.shutdown().await.expect("stop Host");
}

#[test]
fn public_and_cli_evidence_errors_redact_sensitive_member_names() {
    let root = package_directory();
    fs::create_dir(&root).expect("create evidence package root");
    let sensitive_name = "operator-secret-token";
    std::os::unix::fs::symlink("missing-target", root.join(sensitive_name))
        .expect("create sensitive symlink member");

    let error = whisper::evidence::verify_evidence_package(&root)
        .expect_err("sensitive symlink package passed");
    let mut rendered = vec![error.to_string(), format!("{error:?}")];
    let mut source = error.source();
    while let Some(current) = source {
        rendered.push(current.to_string());
        rendered.push(format!("{current:?}"));
        source = current.source();
    }
    let output = run_verifier(&root);
    rendered.push(String::from_utf8_lossy(&output.stderr).into_owned());
    assert!(
        rendered.iter().all(|value| !value.contains(sensitive_name)),
        "public evidence error leaked a sensitive member name: {rendered:?}"
    );
    remove_package(&root);
}

#[test]
fn verifier_rejects_a_package_without_the_formal_baseline_command_sequence() {
    let root = package_directory();
    complete_package(&root);

    let erase_commands = |store: &mut Value| {
        for fact in store["facts"].as_array_mut().expect("Store facts") {
            if fact["kind"] == "baseline_command" {
                fact["body_sha256"] = Value::String(sha256(&[0xf6]));
                fact["command"] = Value::Null;
                fact["kind"] = Value::String("timeline_advance".to_owned());
            }
        }
    };
    update_store_export(&root, "store-pre-stop.cbor", erase_commands);
    update_store_export(&root, "store-post-rebuild.cbor", erase_commands);
    update_store_export(&root, "store-post-continuation.cbor", erase_commands);
    update_json_artifact(&root, "host-commit-trace.json", "run.json", |trace| {
        for fact in trace["facts"].as_array_mut().expect("Host trace facts") {
            if fact["kind"] == "baseline_command" {
                fact["body_sha256"] = Value::String(sha256(&[0xf6]));
                fact["command"] = Value::Null;
                fact["kind"] = Value::String("timeline_advance".to_owned());
            }
        }
    });

    assert_rejected(&root);
    remove_package(&root);
}

#[test]
fn verifier_rejects_consistently_bound_input_received_before_the_formal_run() {
    let root = package_directory();
    complete_package(&root);
    move_first_datagram_before_run(&root);

    let output = run_verifier(&root);
    assert!(!output.status.success(), "pre-run datagram unexpectedly passed");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("execution interval"),
        "pre-run datagram failed outside the interval gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
    remove_package(&root);
}

#[test]
fn verifier_rejects_a_consistent_capability_only_learning_package() {
    let root = package_directory();
    complete_package(&root);
    rewrite_packet_inputs_as_capabilities(&root);

    let output = run_verifier(&root);
    assert!(!output.status.success(), "capability-only evidence unexpectedly passed");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not CSI data"),
        "capability-only package failed before the CSI semantic gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
    remove_package(&root);
}

#[test]
fn verifier_promptly_rejects_a_screenshot_decode_allocation_bomb() {
    let root = package_directory();
    complete_package(&root);
    let screenshot = root.join("screenshots/unknown.png");
    unseal_file(&screenshot);
    let mut bytes = fs::read(&screenshot).expect("read PNG fixture");
    rewrite_png_dimensions(&mut bytes, u32::MAX, 536_870_911);
    fs::write(&screenshot, bytes).expect("write allocation-bomb PNG dimensions");
    reseal_file(&screenshot);
    update_manifest_digest(&root, "observer.json", "screenshots/unknown.png");
    assert_promptly_rejected_without_panic(&root);
    remove_package(&root);
}

#[test]
fn verifier_rejects_cross_device_and_source_mac_continuation() {
    let cross_device_continuation = package_directory();
    complete_package(&cross_device_continuation);
    rewrite_post_restart_csi_identity(&cross_device_continuation, 2, [2, 0, 0, 0, 0, 10]);
    assert_rejected(&cross_device_continuation);
    remove_package(&cross_device_continuation);

    let cross_mac_continuation = package_directory();
    complete_package(&cross_mac_continuation);
    rewrite_post_restart_csi_identity(&cross_mac_continuation, 1, [2, 0, 0, 0, 0, 11]);
    assert_rejected(&cross_mac_continuation);
    remove_package(&cross_mac_continuation);
}

#[test]
fn verifier_rejects_cross_mac_decode_rejected_csi() {
    let root = package_directory();
    complete_package(&root);
    rewrite_decode_rejected_csi_source_mac(&root, [2, 0, 0, 0, 0, 11]);

    let output = run_verifier(&root);
    assert!(!output.status.success(), "cross-Mac decode rejection unexpectedly passed");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("retained CSI datagrams do not retain one physical source"),
        "cross-Mac decode rejection failed outside the source-continuity gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
    remove_package(&root);
}

#[test]
fn verifier_rejects_run_identity_that_does_not_name_its_receipt_directory() {
    let root = package_directory();
    complete_package(&root);
    update_root_receipt(&root, |run| {
        run["run_id"] = Value::String("simulated-0002".to_owned());
    });

    let output = run_verifier(&root);
    assert!(!output.status.success(), "mismatched run identity unexpectedly passed");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("evidence run directory is incompatible"),
        "mismatched run identity failed outside the directory-binding gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
    remove_package(&root);
}

#[test]
fn verifier_rejects_untrusted_run_identity_path_components() {
    let root = package_directory();
    complete_package(&root);
    update_root_receipt(&root, |run| {
        run["run_id"] = Value::String("simulated/0001".to_owned());
    });

    let output = run_verifier(&root);
    assert!(!output.status.success(), "path-like run identity unexpectedly passed");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("evidence run identity is incompatible"),
        "path-like run identity failed outside the identity gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("verification.json").exists());
    remove_package(&root);
}

#[test]
fn verifier_rejects_unearned_transaction_b_effects_and_projection_bindings() {
    let extra_effect = package_directory();
    complete_package(&extra_effect);
    update_json_artifact(&extra_effect, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][0]["transaction_b"]["effects"] = json!([
            "processed_cursor",
            "timeline_digest",
            "projection_watermark",
            "world_snapshot"
        ]);
    });
    assert_rejected(&extra_effect);
    remove_package(&extra_effect);

    let baseline = package_directory();
    complete_package(&baseline);
    update_json_artifact(&baseline, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][1]["transaction_b"]["baseline_sha256"] = Value::String("ab".repeat(32));
    });
    assert_rejected(&baseline);
    remove_package(&baseline);

    let missing_baseline = package_directory();
    complete_package(&missing_baseline);
    update_json_artifact(&missing_baseline, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][0]["transaction_b"]["baseline_sha256"] = Value::Null;
    });
    assert_rejected(&missing_baseline);
    remove_package(&missing_baseline);

    let relationship = package_directory();
    complete_package(&relationship);
    update_json_artifact(&relationship, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][0]["transaction_b"]["creator_commit_seq"] = Value::String("1".to_owned());
        trace["facts"][0]["transaction_b"]["relationship_sha256"] = Value::String("ab".repeat(32));
    });
    assert_rejected(&relationship);
    remove_package(&relationship);

    let wrong_creator = package_directory();
    complete_package(&wrong_creator);
    update_json_artifact(&wrong_creator, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][4]["transaction_b"]["creator_commit_seq"] = Value::String("4".to_owned());
        trace["facts"][4]["transaction_b"]["effects"] = json!([
            "processed_cursor",
            "timeline_digest",
            "projection_watermark",
            "relationship_projection",
            "creator_commit"
        ]);
        trace["facts"][4]["transaction_b"]["relationship_sha256"] = Value::String("ab".repeat(32));
    });
    assert_rejected(&wrong_creator);
    remove_package(&wrong_creator);
}

#[test]
fn verifier_rejects_wrong_live_websocket_and_socket_bindings() {
    let wrong_websocket_url = package_directory();
    complete_package(&wrong_websocket_url);
    update_json_artifact(&wrong_websocket_url, "websocket.json", "observer.json", |trace| {
        trace["url"] = Value::String("ws://loopback:9001/api/other".to_owned());
        trace["events"][0]["url"] = trace["url"].clone();
        trace["events"][4]["url"] = trace["url"].clone();
    });
    assert_rejected(&wrong_websocket_url);
    remove_package(&wrong_websocket_url);

    let cross_socket_message = package_directory();
    complete_package(&cross_socket_message);
    update_json_artifact(&cross_socket_message, "websocket.json", "observer.json", |trace| {
        trace["events"][5]["socket_id"] = Value::String("0".to_owned());
    });
    assert_rejected(&cross_socket_message);
    remove_package(&cross_socket_message);

    let wrong_trigger_socket = package_directory();
    complete_package(&wrong_trigger_socket);
    update_json_artifact(&wrong_trigger_socket, "chrome-trace.json", "observer.json", |trace| {
        trace["events"][4]["trigger_websocket_socket_id"] = Value::String("0".to_owned());
    });
    assert_rejected(&wrong_trigger_socket);
    remove_package(&wrong_trigger_socket);
}

#[test]
fn verifier_rejects_adversarial_packages_without_emitting_pass() {
    let missing = package_directory();
    complete_package(&missing);
    fs::set_permissions(missing.join("http"), fs::Permissions::from_mode(0o755))
        .expect("unseal HTTP fixture directory");
    fs::remove_file(missing.join("http/unknown.json")).expect("remove required artifact");
    assert_rejected(&missing);
    remove_package(&missing);

    let extra = package_directory();
    complete_package(&extra);
    fs::write(extra.join("unrelated.txt"), b"unrelated").expect("write unrelated artifact");
    fs::set_permissions(extra.join("unrelated.txt"), fs::Permissions::from_mode(0o444))
        .expect("seal unrelated artifact");
    assert_rejected(&extra);
    remove_package(&extra);

    let noncanonical = package_directory();
    complete_package(&noncanonical);
    let websocket = noncanonical.join("websocket.json");
    unseal_file(&websocket);
    fs::write(&websocket, b"{\"schema_version\": 1}").expect("write noncanonical JSON");
    reseal_file(&websocket);
    update_manifest_digest(&noncanonical, "observer.json", "websocket.json");
    assert_rejected(&noncanonical);
    remove_package(&noncanonical);

    let mutable = package_directory();
    complete_package(&mutable);
    unseal_file(&mutable.join("run.json"));
    assert_rejected(&mutable);
    remove_package(&mutable);

    let aliased = package_directory();
    complete_package(&aliased);
    let alias = aliased.with_extension("hard-link");
    fs::hard_link(aliased.join("run.json"), &alias).expect("create external hard link");
    assert_rejected(&aliased);
    fs::remove_file(alias).expect("remove external hard link");
    remove_package(&aliased);

    let symlinked = package_directory();
    complete_package(&symlinked);
    fs::set_permissions(symlinked.join("screenshots"), fs::Permissions::from_mode(0o755))
        .expect("unseal screenshot directory");
    fs::remove_file(symlinked.join("screenshots/unknown.png")).expect("remove screenshot");
    std::os::unix::fs::symlink("stable-pre-restart.png", symlinked.join("screenshots/unknown.png"))
        .expect("replace screenshot with symlink");
    assert_rejected(&symlinked);
    remove_package(&symlinked);

    let digest_mismatch = package_directory();
    complete_package(&digest_mismatch);
    let screenshot = digest_mismatch.join("screenshots/unknown.png");
    unseal_file(&screenshot);
    fs::write(&screenshot, b"\x89PNG\r\n\x1a\nchanged").expect("change screenshot bytes");
    reseal_file(&screenshot);
    assert_rejected(&digest_mismatch);
    remove_package(&digest_mismatch);

    let invalid_png = package_directory();
    complete_package(&invalid_png);
    let screenshot = invalid_png.join("screenshots/unknown.png");
    unseal_file(&screenshot);
    fs::write(&screenshot, b"\x89PNG\r\n\x1a\nfixture").expect("write invalid PNG");
    reseal_file(&screenshot);
    update_manifest_digest(&invalid_png, "observer.json", "screenshots/unknown.png");
    assert_rejected(&invalid_png);
    remove_package(&invalid_png);

    let oversized_png = package_directory();
    complete_package(&oversized_png);
    let screenshot = oversized_png.join("screenshots/unknown.png");
    unseal_file(&screenshot);
    let mut bytes = fs::read(&screenshot).expect("read PNG fixture");
    rewrite_png_dimensions(&mut bytes, u32::MAX, 536_870_913);
    fs::write(&screenshot, bytes).expect("write oversized PNG dimensions");
    reseal_file(&screenshot);
    update_manifest_digest(&oversized_png, "observer.json", "screenshots/unknown.png");
    assert_rejected_without_panic(&oversized_png);
    remove_package(&oversized_png);

    let png_with_extra_chunk = package_directory();
    complete_package(&png_with_extra_chunk);
    let screenshot = png_with_extra_chunk.join("screenshots/unknown.png");
    unseal_file(&screenshot);
    let mut bytes = fs::read(&screenshot).expect("read PNG fixture");
    let end = bytes.split_off(bytes.len() - 12);
    push_png_chunk(&mut bytes, b"ruSt", b"unrelated observer payload");
    bytes.extend_from_slice(&end);
    fs::write(&screenshot, bytes).expect("write PNG with ancillary chunk");
    reseal_file(&screenshot);
    update_manifest_digest(&png_with_extra_chunk, "observer.json", "screenshots/unknown.png");
    assert_rejected(&png_with_extra_chunk);
    remove_package(&png_with_extra_chunk);

    let scale_mismatch = package_directory();
    complete_package(&scale_mismatch);
    let observer = scale_mismatch.join("observer.json");
    unseal_file(&observer);
    let mut value: Value = serde_json::from_slice(&fs::read(&observer).expect("read observer"))
        .expect("parse observer");
    value["viewport"]["device_scale_factor"] = Value::String("2".to_owned());
    fs::write(&observer, canonical_json(&value)).expect("write mismatched device scale factor");
    reseal_file(&observer);
    assert_rejected(&scale_mismatch);
    remove_package(&scale_mismatch);

    let self_certified = package_directory();
    complete_package(&self_certified);
    let run = self_certified.join("run.json");
    unseal_file(&run);
    let mut value: Value = serde_json::from_slice(&fs::read(&run).expect("read run receipt"))
        .expect("parse run receipt");
    value["result"] = Value::String("PASS".to_owned());
    fs::write(&run, canonical_json(&value)).expect("write producer PASS flag");
    reseal_file(&run);
    assert_rejected(&self_certified);
    remove_package(&self_certified);

    let sensitive = package_directory();
    complete_package(&sensitive);
    let trace = sensitive.join("chrome-trace.json");
    unseal_file(&trace);
    fs::write(&trace, canonical_json(&json!({"schema_version": 1, "ssid": "forbidden-network"})))
        .expect("write sensitive cleartext field");
    reseal_file(&trace);
    update_manifest_digest(&sensitive, "observer.json", "chrome-trace.json");
    assert_rejected(&sensitive);
    remove_package(&sensitive);

    let stalled_result = package_directory();
    complete_package(&stalled_result);
    update_store_export(&stalled_result, "store-post-continuation.cbor", |store| {
        store["relationships"][0]["result_time"] = Value::from(100_u64);
    });
    assert_rejected(&stalled_result);
    remove_package(&stalled_result);

    let tampered_transaction = package_directory();
    complete_package(&tampered_transaction);
    update_json_artifact(&tampered_transaction, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][0]["transaction_b"]["timeline_digest"] = Value::String("fe".repeat(32));
    });
    assert_rejected(&tampered_transaction);
    remove_package(&tampered_transaction);

    let extra_host_fact = package_directory();
    complete_package(&extra_host_fact);
    update_json_artifact(&extra_host_fact, "host-commit-trace.json", "run.json", |trace| {
        let facts = trace["facts"].as_array_mut().expect("Host trace facts");
        facts.push(facts.last().expect("last Host trace fact").clone());
    });
    assert_rejected(&extra_host_fact);
    remove_package(&extra_host_fact);

    let fabricated_decoded_fact = package_directory();
    complete_package(&fabricated_decoded_fact);
    update_json_artifact(&fabricated_decoded_fact, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][1]["decoded_message"]["firmware_image_sha256"] =
            Value::String("ef".repeat(32));
    });
    assert_rejected(&fabricated_decoded_fact);
    remove_package(&fabricated_decoded_fact);

    let fabricated_packet_body = package_directory();
    complete_package(&fabricated_packet_body);
    let physical_path = fabricated_packet_body.join("physical-input.json");
    let physical: Value = serde_json::from_slice(
        &fs::read(&physical_path).expect("read fabricated packet physical input"),
    )
    .expect("parse fabricated packet physical input");
    let first_datagram = &physical["datagrams"][0];
    let first_path = first_datagram["path"].as_str().expect("first datagram path");
    let first_bytes = fs::read(fabricated_packet_body.join(first_path))
        .expect("read fabricated packet ciphertext");
    let first_receive_utc_ns = first_datagram["received_utc_ns"]
        .as_str()
        .expect("first receive time")
        .parse::<i64>()
        .expect("numeric first receive time");
    update_json_artifact(&fabricated_packet_body, "physical-input.json", "run.json", |input| {
        input["datagrams"][0]["body_binding_sha256"] = Value::String(
            packet_evidence_vector(first_receive_utc_ns, &first_bytes, Some(&"ef".repeat(32)))
                .1
                .to_owned(),
        );
    });
    for path in ["store-pre-stop.cbor", "store-post-rebuild.cbor", "store-post-continuation.cbor"] {
        update_store_export(&fabricated_packet_body, path, |store| {
            store["facts"][1]["body_sha256"] = Value::String("ef".repeat(32));
        });
    }
    refresh_restart_export_digests(&fabricated_packet_body);
    update_json_artifact(&fabricated_packet_body, "host-commit-trace.json", "run.json", |trace| {
        trace["facts"][1]["body_sha256"] = Value::String("ef".repeat(32))
    });
    assert_rejected(&fabricated_packet_body);
    remove_package(&fabricated_packet_body);

    for collection in ["capture_sessions", "replay_identities", "baselines", "relationships"] {
        let reordered = package_directory();
        complete_package(&reordered);
        reorder_store_collection(&reordered, collection);
        assert_rejected(&reordered);
        remove_package(&reordered);
    }

    let sensitive_store = package_directory();
    complete_package(&sensitive_store);
    update_store_export(&sensitive_store, "store-post-continuation.cbor", |store| {
        store["baselines"][0]["deployment"] = Value::String("192.168.1.2".to_owned());
    });
    assert_rejected(&sensitive_store);
    remove_package(&sensitive_store);

    let writable_restart = package_directory();
    complete_package(&writable_restart);
    update_json_artifact(&writable_restart, "restart-trace.json", "run.json", |trace| {
        trace["rebuild"]["writer_opens"] = Value::String("1".to_owned());
    });
    assert_rejected(&writable_restart);
    remove_package(&writable_restart);

    let wrong_http_creator = package_directory();
    complete_package(&wrong_http_creator);
    update_json_artifact(
        &wrong_http_creator,
        "http/stable-pre-restart.json",
        "observer.json",
        |response| {
            response["data"]["creator_commit"]["sequence"] = Value::String("23".to_owned());
        },
    );
    assert_rejected(&wrong_http_creator);
    remove_package(&wrong_http_creator);

    let wrong_unknown_creator = package_directory();
    complete_package(&wrong_unknown_creator);
    update_json_artifact(
        &wrong_unknown_creator,
        "http/unknown.json",
        "observer.json",
        |response| {
            response["data"]["creator_commit"]["sequence"] = Value::String("4".to_owned());
        },
    );
    assert_rejected(&wrong_unknown_creator);
    remove_package(&wrong_unknown_creator);

    let unknown_without_projection = package_directory();
    complete_package(&unknown_without_projection);
    update_json_artifact(
        &unknown_without_projection,
        "host-commit-trace.json",
        "run.json",
        |trace| {
            trace["facts"][2]["transaction_b"]["creator_commit_seq"] = Value::Null;
            trace["facts"][2]["transaction_b"]["effects"] =
                json!(["processed_cursor", "timeline_digest", "projection_watermark"]);
            trace["facts"][2]["transaction_b"]["relationship_sha256"] = Value::Null;
        },
    );
    assert_rejected(&unknown_without_projection);
    remove_package(&unknown_without_projection);

    let wrong_unknown_time = package_directory();
    complete_package(&wrong_unknown_time);
    update_json_artifact(&wrong_unknown_time, "http/unknown.json", "observer.json", |response| {
        response["data"]["result_time"] = Value::String("4".to_owned());
    });
    assert_rejected(&wrong_unknown_time);
    remove_package(&wrong_unknown_time);

    let wrong_http_time = package_directory();
    complete_package(&wrong_http_time);
    update_json_artifact(
        &wrong_http_time,
        "http/stable-post-restart.json",
        "observer.json",
        |response| {
            response["data"]["result_time"] = Value::String("201".to_owned());
        },
    );
    assert_rejected(&wrong_http_time);
    remove_package(&wrong_http_time);

    let websocket_semantics = package_directory();
    complete_package(&websocket_semantics);
    update_json_artifact(&websocket_semantics, "websocket.json", "observer.json", |trace| {
        trace["events"][2]["knowledge"] = Value::String("stable".to_owned());
    });
    assert_rejected(&websocket_semantics);
    remove_package(&websocket_semantics);

    let wrong_websocket_watermark = package_directory();
    complete_package(&wrong_websocket_watermark);
    update_json_artifact(&wrong_websocket_watermark, "websocket.json", "observer.json", |trace| {
        trace["events"][5]["watermark"] = Value::String("26".to_owned());
    });
    assert_rejected(&wrong_websocket_watermark);
    remove_package(&wrong_websocket_watermark);

    let unbound_stable_invalidation = package_directory();
    complete_package(&unbound_stable_invalidation);
    update_json_artifact(
        &unbound_stable_invalidation,
        "chrome-trace.json",
        "observer.json",
        |trace| {
            trace["events"][1]["trigger_websocket_order"] = Value::String("1".to_owned());
            trace["events"][1]["trigger_websocket_watermark"] = Value::String("3".to_owned());
        },
    );
    assert_rejected(&unbound_stable_invalidation);
    remove_package(&unbound_stable_invalidation);

    let replaced_document = package_directory();
    complete_package(&replaced_document);
    update_json_artifact(&replaced_document, "chrome-trace.json", "observer.json", |trace| {
        trace["events"][4]["document_id"] = Value::String("77".repeat(32));
    });
    assert_rejected(&replaced_document);
    remove_package(&replaced_document);

    let changed_page = package_directory();
    complete_package(&changed_page);
    update_json_artifact(&changed_page, "chrome-trace.json", "observer.json", |trace| {
        trace["page_instance_id"] = Value::String("page-2".to_owned());
    });
    assert_rejected(&changed_page);
    remove_package(&changed_page);

    let wrong_host = package_directory();
    complete_package(&wrong_host);
    update_root_receipt(&wrong_host, |run| {
        run["identities"]["host"]["executable_sha256"] = Value::String("ef".repeat(32));
    });
    assert_rejected(&wrong_host);
    remove_package(&wrong_host);

    let wrong_host_revision = package_directory();
    complete_package(&wrong_host_revision);
    update_root_receipt(&wrong_host_revision, |run| {
        run["identities"]["host"]["source_revision"] = Value::String("ef".repeat(20));
    });
    assert_rejected(&wrong_host_revision);
    remove_package(&wrong_host_revision);

    let wrong_host_clean_state = package_directory();
    complete_package(&wrong_host_clean_state);
    let expected_clean = host_identity()["source_clean"].as_bool().expect("Host clean state");
    update_root_receipt(&wrong_host_clean_state, |run| {
        run["identities"]["host"]["source_clean"] = Value::Bool(!expected_clean);
    });
    assert_rejected(&wrong_host_clean_state);
    remove_package(&wrong_host_clean_state);

    let wrong_host_source = package_directory();
    complete_package(&wrong_host_source);
    update_root_receipt(&wrong_host_source, |run| {
        run["identities"]["host"]["source_sha256"] = Value::String("ef".repeat(32));
    });
    assert_rejected(&wrong_host_source);
    remove_package(&wrong_host_source);

    let wrong_served_asset = package_directory();
    complete_package(&wrong_served_asset);
    let observer = wrong_served_asset.join("observer.json");
    unseal_file(&observer);
    let mut receipt: Value = serde_json::from_slice(&fs::read(&observer).expect("read observer"))
        .expect("parse observer");
    receipt["served_asset_sha256"] = Value::String("ef".repeat(32));
    fs::write(&observer, canonical_json(&receipt)).expect("rewrite served asset identity");
    reseal_file(&observer);
    assert_rejected(&wrong_served_asset);
    remove_package(&wrong_served_asset);

    let wrong_firmware = package_directory();
    complete_package(&wrong_firmware);
    update_root_receipt(&wrong_firmware, |run| {
        run["identities"]["firmware"]["capability_sha256"] = Value::String("ef".repeat(32));
    });
    assert_rejected(&wrong_firmware);
    remove_package(&wrong_firmware);

    let wrong_config = package_directory();
    complete_package(&wrong_config);
    update_root_receipt(&wrong_config, |run| {
        run["identities"]["config_sha256"] = Value::String("ef".repeat(32));
    });
    assert_rejected(&wrong_config);
    remove_package(&wrong_config);

    let duplicate_property = package_directory();
    complete_package(&duplicate_property);
    let websocket = duplicate_property.join("websocket.json");
    unseal_file(&websocket);
    fs::write(&websocket, b"{\"events\":[],\"events\":[],\"schema_version\":1}")
        .expect("write duplicate JSON property");
    reseal_file(&websocket);
    update_manifest_digest(&duplicate_property, "observer.json", "websocket.json");
    assert_rejected(&duplicate_property);
    remove_package(&duplicate_property);
}
