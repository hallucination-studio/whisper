//! Host runtime composition through its public lifecycle seam.

#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use futures_util::StreamExt;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(feature = "ingest-test-hooks")]
use whisper::test_support::{
    advance_host_clock, host_query_store, release_writer, start_host_with_manual_clock,
    start_host_with_panicked_writer, start_host_with_query_held,
    start_host_with_relationship_transaction_a_failure,
    start_host_with_relationship_transaction_b_failure, start_host_with_teardown_held,
    start_host_with_writer_held,
};
use whisper::{HostRuntime, RuntimeFailure, SocketOperation, SocketRole, parse_config};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct RuntimeFixture {
    root: PathBuf,
    database: PathBuf,
    config_path: PathBuf,
    config: whisper::Config,
}

impl RuntimeFixture {
    fn new() -> Self {
        Self::with_queue_capacity(64)
    }

    fn with_queue_capacity(queue_capacity: u32) -> Self {
        Self::with_runtime_settings(queue_capacity, "0.000001")
    }

    #[cfg(feature = "ingest-test-hooks")]
    fn with_unit_variance_floor() -> Self {
        Self::with_runtime_settings(64, "1.0")
    }

    fn with_runtime_settings(queue_capacity: u32, variance_floor: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "whisper-runtime-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create fixture root");
        let managed = root.join("managed");
        create_directory(&managed, 0o700);
        let database = managed.join("host.sqlite3");
        let secrets = root.join("secrets");
        create_directory(&secrets, 0o700);
        for (device, byte) in [(1, 0x11), (2, 0x22)] {
            let device_root = secrets.join(format!("device-{device}"));
            create_directory(&device_root, 0o700);
            let key = device_root.join("key-1.bin");
            fs::write(&key, [byte; 32]).expect("write epoch key");
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("protect key");
        }
        let capability = capability_body([0x01; 32], [0x22; 32], 1024);
        let second_capability = capability_body([0x03; 32], [0x44; 32], 2048);
        let source = include_str!("fixtures/config/valid-two-esp32.toml")
            .replace(
                "0202020202020202020202020202020202020202020202020202020202020202",
                &encode_hex(&capability[..32]),
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
            .replacen(
                "command_queue_capacity = 64",
                &format!("command_queue_capacity = {queue_capacity}"),
                1,
            )
            .replacen("variance_floor = 0.000001", &format!("variance_floor = {variance_floor}"), 1)
            .replace(
                "secret_root = \"./data/secrets\"",
                &format!("secret_root = \"{}\"", secrets.display()),
            )
            .replace(
                "database_path = \"./data/whisper.sqlite3\"",
                &format!("database_path = \"{}\"", database.display()),
            );
        let config_path = root.join("host.toml");
        fs::write(&config_path, &source).expect("write runtime configuration");
        let config = parse_config(&source).expect("parse runtime configuration");
        whisper::init_admission(&config).expect("initialize Store");
        Self { root, database, config_path, config }
    }
}

impl Drop for RuntimeFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_directory(path: &Path, mode: u32) {
    fs::create_dir(path).expect("create protected directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("protect directory");
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

fn csi_body(capability_digest: &[u8]) -> Vec<u8> {
    csi_body_for(capability_digest, [2, 0, 0, 0, 0, 10], 1)
}

fn csi_body_for(capability_digest: &[u8], source_mac: [u8; 6], channel: u8) -> Vec<u8> {
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

fn seal_raw(kind: u8, sequence: u64, body: &[u8]) -> Box<[u8]> {
    seal_raw_for(&[0x11; 32], 1, kind, sequence, body)
}

fn seal_raw_for(key: &[u8; 32], device_id: u64, kind: u8, sequence: u64, body: &[u8]) -> Box<[u8]> {
    const HEADER_BYTES: usize = 32;
    let mut header = [0_u8; HEADER_BYTES];
    header[0] = 1;
    header[1] = kind;
    header[2..4].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    header[4..12].copy_from_slice(&device_id.to_le_bytes());
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[16..20].copy_from_slice(&1_u32.to_le_bytes());
    header[20..28].copy_from_slice(&sequence.to_le_bytes());
    header[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&1_u32.to_le_bytes());
    nonce[4..].copy_from_slice(&sequence.to_le_bytes());
    let ciphertext = Aes256Gcm::new_from_slice(key)
        .expect("test key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &header })
        .expect("seal test datagram");
    header.into_iter().chain(ciphertext).collect::<Vec<_>>().into_boxed_slice()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn http_request(address: std::net::SocketAddr, request: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("connect Host HTTP");
    stream.write_all(request.as_bytes()).await.expect("write HTTP request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read HTTP response");
    response
}

fn response_json(response: &[u8]) -> serde_json::Value {
    let separator = response.windows(4).position(|window| window == b"\r\n\r\n").expect("headers");
    serde_json::from_slice(&response[separator + 4..]).expect("JSON response")
}

async fn capture_session_ids(address: std::net::SocketAddr) -> Vec<String> {
    let topology = response_json(
        &http_request(
            address,
            "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    topology["data"]["sessions"]
        .as_array()
        .expect("Capture Sessions")
        .iter()
        .map(|session| session.as_str().expect("Capture Session ID").to_owned())
        .collect()
}

async fn raw_signals(
    address: std::net::SocketAddr,
    session: &str,
    sensor: &str,
    link: &str,
) -> serde_json::Value {
    let request = format!(
        "GET /api/signals?session={session}&sensor={sensor}&link={link}&from=0&to=18446744073709551615&metric=i&max_time_buckets=8 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let response = http_request(address, &request).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    response_json(&response)
}

fn relationship_command_request(link: &str, profile: &str) -> String {
    relationship_command_request_for(link, profile, "begin_learning")
}

fn relationship_command_request_for(link: &str, profile: &str, command: &str) -> String {
    let body = format!(
        r#"{{"http_schema_version":1,"target":{{"link":"{link}","profile":"{profile}"}},"command":"{command}"}}"#
    );
    format!(
        "POST /api/relationships/commands HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn wait_for_projection(address: std::net::SocketAddr, expected: u64) {
    let expected = expected.to_string();
    for _ in 0..100 {
        let body = response_json(
            &http_request(
                address,
                "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        if body["receipt"]["projection_commit"]["sequence"] == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("projection {expected} did not become query-visible");
}

#[cfg(feature = "ingest-test-hooks")]
async fn wait_for_projection_at_least(address: std::net::SocketAddr, minimum: u64) -> u64 {
    for _ in 0..200 {
        let body = response_json(
            &http_request(
                address,
                "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        let sequence = body["receipt"]["projection_commit"]["sequence"]
            .as_str()
            .expect("projection sequence")
            .parse::<u64>()
            .expect("u64 projection sequence");
        if sequence >= minimum {
            return sequence;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("projection did not reach {minimum}");
}

#[cfg(feature = "ingest-test-hooks")]
async fn latest_relationship(address: std::net::SocketAddr, profile: &str) -> serde_json::Value {
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
async fn stop_host_with_processed_begin_learning(fixture: &RuntimeFixture) {
    let runtime = HostRuntime::start(&fixture.config).await.expect("start first Host");
    assert!(
        http_request(
            runtime.http_address(),
            &relationship_command_request("link-a", &"11".repeat(32)),
        )
        .await
        .starts_with(b"HTTP/1.1 202 Accepted\r\n")
    );
    wait_for_projection(runtime.http_address(), 1).await;
    runtime.shutdown().await.expect("stop first Host");
}

#[cfg(feature = "ingest-test-hooks")]
struct WindowAfterCarry {
    samples: [u8; 6],
    next_samples: [u8; 6],
    additional_frames: u32,
}

#[cfg(feature = "ingest-test-hooks")]
async fn send_csi_window_after_carry(
    runtime: &HostRuntime,
    sender: &tokio::net::UdpSocket,
    destination: std::net::SocketAddr,
    capability_digest: &[u8],
    counters: &mut (u64, u64, u64),
    window: WindowAfterCarry,
) {
    let frame_step_ms = 200_u64;
    for _ in 0..window.additional_frames {
        advance_host_clock(runtime, Duration::from_millis(frame_step_ms));
        counters.0 += 1;
        counters.1 += 1;
        let mut csi = csi_body(capability_digest);
        csi[32..40].copy_from_slice(&counters.0.to_le_bytes());
        let raw = csi.len() - window.samples.len();
        csi[raw..].copy_from_slice(&window.samples);
        sender
            .send_to(&seal_raw(2, counters.1, &csi), destination)
            .await
            .expect("send CSI in current window");
        counters.2 += 1;
        counters.2 = wait_for_projection_at_least(runtime.http_address(), counters.2).await;
    }
    let elapsed_ms = frame_step_ms * u64::from(window.additional_frames);
    advance_host_clock(runtime, Duration::from_millis(1_000 - elapsed_ms));
    counters.0 += 1;
    counters.1 += 1;
    let mut csi = csi_body(capability_digest);
    csi[32..40].copy_from_slice(&counters.0.to_le_bytes());
    let raw = csi.len() - window.next_samples.len();
    csi[raw..].copy_from_slice(&window.next_samples);
    sender
        .send_to(&seal_raw(2, counters.1, &csi), destination)
        .await
        .expect("send next-window carry CSI");
    counters.2 += 2;
    counters.2 = wait_for_projection_at_least(runtime.http_address(), counters.2).await;
}

fn spawn_serve_cli(
    config_path: &Path,
) -> (std::process::Child, String, BufReader<std::process::ChildStdout>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["serve", config_path.to_str().expect("UTF-8 config path")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve CLI");
    let stdout = child.stdout.take().expect("capture serve stdout");
    let (line_tx, line_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        let result = stdout.read_line(&mut line).map(|_| (line, stdout));
        let _ = line_tx.send(result);
    });
    let (line, stdout) = line_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("serve CLI did not report startup")
        .expect("read serve startup");
    (child, line, stdout)
}

fn wait_for_cli_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().expect("poll serve CLI") {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("serve CLI did not exit after fatal shutdown");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn invalid_role_config(server_bind: &str, capture_bind: &str) -> (whisper::Config, PathBuf) {
    let database = std::env::temp_dir().join(format!(
        "whisper-runtime-role-{}-{}.sqlite3",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    let source = include_str!("fixtures/config/valid-two-esp32.toml")
        .replacen("bind = \"127.0.0.1:9000\"", &format!("bind = \"{capture_bind}\""), 1)
        .replacen("bind = \"127.0.0.1:8080\"", &format!("bind = \"{server_bind}\""), 1)
        .replace(
            "database_path = \"./data/whisper.sqlite3\"",
            &format!("database_path = \"{}\"", database.display()),
        );
    (parse_config(&source).expect("parse role configuration"), database)
}

#[tokio::test]
async fn runtime_rejects_network_roles_before_store_or_socket_startup() {
    for (server, capture) in [
        ("0.0.0.0:0", "192.0.2.20:0"),
        ("127.0.0.1:0", "127.0.0.1:0"),
        ("127.0.0.1:0", "192.0.2.20:0"),
    ] {
        let (config, database) = invalid_role_config(server, capture);
        let error = HostRuntime::start(&config).await.expect_err("invalid network role");
        assert!(error.is_network_role());
        assert!(!database.exists(), "role admission must run before Store creation or mutation");
    }

    let missing = RuntimeFixture::new();
    fs::remove_file(&missing.database).expect("remove initialized Store");
    HostRuntime::start(&missing.config)
        .await
        .expect_err("runtime serve must not recreate a missing Store");
    assert!(!missing.database.exists(), "runtime serve recreated a missing Store");
}

#[tokio::test]
async fn http_bind_collision_retains_socket_role_operation_address_and_source() {
    let fixture = RuntimeFixture::new();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy HTTP address");
    let address = occupied.local_addr().expect("read occupied HTTP address");
    let source = fs::read_to_string(&fixture.config_path)
        .expect("read runtime configuration")
        .replacen("bind = \"127.0.0.1:0\"", &format!("bind = \"{address}\""), 1);
    let config = parse_config(&source).expect("parse colliding HTTP configuration");

    let error = HostRuntime::start(&config).await.expect_err("HTTP bind collision was accepted");
    assert_eq!(error.failure(), RuntimeFailure::Socket);
    assert_eq!(error.socket_role(), Some(SocketRole::Http));
    assert_eq!(error.socket_operation(), Some(SocketOperation::Bind));
    assert_eq!(error.socket_address(), Some(address));
    let source = std::error::Error::source(&error)
        .and_then(std::error::Error::source)
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .expect("socket source is an I/O error");
    assert_eq!(source.kind(), std::io::ErrorKind::AddrInUse);
    let sessions: u64 = Connection::open(&fixture.database)
        .expect("open Store")
        .query_row("SELECT count(*) FROM capture_sessions", [], |row| row.get(0))
        .expect("count Capture Sessions");
    assert_eq!(sessions, 0, "HTTP bind collision created a Capture Session");
}

#[tokio::test]
async fn capture_bind_collision_retains_context_before_capture_session_creation() {
    let fixture = RuntimeFixture::new();
    let occupied = std::net::UdpSocket::bind("0.0.0.0:0").expect("occupy capture address");
    let address = occupied.local_addr().expect("read occupied capture address");
    let source = fs::read_to_string(&fixture.config_path)
        .expect("read runtime configuration")
        .replacen("bind = \"0.0.0.0:0\"", &format!("bind = \"{address}\""), 1);
    let config = parse_config(&source).expect("parse colliding capture configuration");

    let error = HostRuntime::start(&config).await.expect_err("capture bind collision was accepted");
    assert_eq!(error.failure(), RuntimeFailure::Socket);
    assert_eq!(error.socket_role(), Some(SocketRole::Capture));
    assert_eq!(error.socket_operation(), Some(SocketOperation::Bind));
    assert_eq!(error.socket_address(), Some(address));
    let source = std::error::Error::source(&error)
        .and_then(std::error::Error::source)
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .expect("socket source is an I/O error");
    assert_eq!(source.kind(), std::io::ErrorKind::AddrInUse);
    let sessions: u64 = Connection::open(&fixture.database)
        .expect("open Store")
        .query_row("SELECT count(*) FROM capture_sessions", [], |row| row.get(0))
        .expect("count Capture Sessions");
    assert_eq!(sessions, 0, "capture bind collision created a Capture Session");
}

#[tokio::test]
async fn runtime_binds_roles_and_shutdown_releases_every_connection_and_lease() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let capture = runtime.capture_address();
    let http = runtime.http_address();
    assert!(capture.ip().is_unspecified());
    assert_ne!(capture.port(), 0);
    assert!(http.ip().is_loopback());
    assert_ne!(http.port(), 0);

    let queue_drop_count = runtime.shutdown().await.expect("stop Host runtime");
    assert_eq!(queue_drop_count, 0);
    HostRuntime::start(&fixture.config)
        .await
        .expect("lifecycle lease is reusable after runtime shutdown")
        .shutdown()
        .await
        .expect("stop replacement Host runtime");
}

#[tokio::test]
async fn runtime_serves_read_only_shell_topology_and_exact_live_upgrade_failure() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let address = runtime.http_address();

    let shell =
        http_request(address, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await;
    let shell = String::from_utf8(shell).expect("UTF-8 shell response");
    assert!(shell.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(shell.contains("Whisper Signals"));
    assert!(shell.contains("data-testid=\"connection-state\">POLLING"));
    assert!(shell.contains("data-max-time-buckets=\"512\""));
    assert!(!shell.contains("<button"));
    assert!(!shell.contains("<form"));

    let styles = http_request(
        address,
        "GET /assets/app.css HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let styles = String::from_utf8(styles).expect("UTF-8 stylesheet response");
    assert!(styles.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(styles.contains("content-type: text/css; charset=utf-8"));
    assert!(styles.contains(".signal-grid"));

    let script = http_request(
        address,
        "GET /assets/app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let script = String::from_utf8(script).expect("UTF-8 script response");
    assert!(script.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(script.contains("content-type: text/javascript; charset=utf-8"));
    assert!(script.contains("POLL_INTERVAL_MS = 250"));

    let topology = http_request(
        address,
        "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let topology = String::from_utf8(topology).expect("UTF-8 topology response");
    assert!(topology.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(topology.contains("\"resource\":\"topology\""));
    assert!(topology.contains("\"sequence\":\"0\""));

    let invalid = http_request(
        address,
        "GET /api/signals?session=x&sensor=s&link=l&from=00&to=1&metric=i&max_time_buckets=1&unknown=x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let invalid = String::from_utf8(invalid).expect("UTF-8 invalid response");
    assert!(invalid.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(invalid.contains("\"code\":\"invalid_request\""));

    let unavailable_request = format!(
        "GET /api/signals?session={}&sensor=sensor-a&link=link-a&from=0&to=1&metric=i&max_time_buckets=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        runtime.session_id()
    );
    let unavailable = http_request(address, &unavailable_request).await;
    let unavailable = String::from_utf8(unavailable).expect("UTF-8 unavailable response");
    assert!(unavailable.starts_with("HTTP/1.1 416 Range Not Satisfiable\r\n"));
    assert!(unavailable.contains("\"code\":\"range_unavailable\""));

    let live = http_request(
        address,
        "GET /api/live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let separator = live.windows(4).position(|window| window == b"\r\n\r\n").expect("headers");
    assert!(live.starts_with(b"HTTP/1.1 426 Upgrade Required\r\n"));
    assert_eq!(&live[separator + 4..], b"");

    let invalid_upgrade =
        tokio_tungstenite::connect_async(format!("ws://{address}/api/live?unknown=x"))
            .await
            .expect_err("live upgrade accepted query properties");
    match invalid_upgrade {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(response.status().as_u16(), 400);
        }
        error => panic!("unexpected invalid-upgrade failure: {error}"),
    }

    let absent = http_request(
        address,
        "POST /api/topology HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(absent.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));

    for forbidden in [
        "GET /api/topology?unknown=x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
        "GET /api/signals?session=x&sensor=s&link=l&from=0&to=1&metric=i&max_time_buckets=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
    ] {
        let response = http_request(address, forbidden).await;
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(response_json(&response)["error"]["code"], "invalid_request");
    }
    let head = http_request(
        address,
        "HEAD /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(head.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));

    runtime.shutdown().await.expect("stop Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn relationship_command_ingress_accepts_only_the_closed_command_set() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_manual_clock(&fixture.config).await.expect("start Host runtime");
    let address = runtime.http_address();
    let profile = "11".repeat(32);
    let request = relationship_command_request("link-a", &profile);
    let accepted = http_request(address, &request).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    let accepted = response_json(&accepted);
    assert_eq!(
        accepted,
        serde_json::json!({
            "http_schema_version": 1,
            "kind": "accepted",
            "resource": "relationship_command",
            "target": {"link": "link-a", "profile": profile},
            "correlation_id": "relationship-command-1"
        })
    );

    let invalid_body = r#"{"http_schema_version":1,"target":{"link":"link-a","profile":"1111111111111111111111111111111111111111111111111111111111111111"},"command":"begin_learning","unknown":true}"#;
    let invalid_request = format!(
        "POST /api/relationships/commands HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{invalid_body}",
        invalid_body.len()
    );
    let invalid = http_request(address, &invalid_request).await;
    assert!(invalid.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(response_json(&invalid)["error"]["code"], "invalid_request");

    let unsupported_request = relationship_command_request_for("link-a", &profile, "freeze");
    let unsupported = http_request(address, &unsupported_request).await;
    assert!(unsupported.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(response_json(&unsupported)["error"]["code"], "invalid_request");

    for method in ["GET", "HEAD", "PUT"] {
        let response = http_request(
            address,
            &format!(
                "{method} /api/relationships/commands HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        if method != "HEAD" {
            assert_eq!(response_json(&response)["error"]["code"], "invalid_request");
        }
    }

    for invalid_read in [
        "GET /api/relationships/latest? HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "GET /api/relationships/latest?session=x&link=link-a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "GET /api/relationships/latest?session=x&link=link-a&profile=1111111111111111111111111111111111111111111111111111111111111111&unknown=x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "GET /api/relationships/latest?session=x&link=link-a&profile=AA HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
    ] {
        let response = http_request(address, invalid_read).await;
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(response_json(&response)["error"]["code"], "invalid_request");
    }
    let head = http_request(
        address,
        "HEAD /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(head.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));

    let mut subjects = None;
    for _ in 0..100 {
        let response = http_request(
            address,
            "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        if response.starts_with(b"HTTP/1.1 200 OK\r\n") {
            let body = response_json(&response);
            if body["data"]["subjects"].as_array().is_some_and(|subjects| subjects.len() == 1) {
                subjects = Some(body);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let subjects = subjects.expect("committed relationship subject did not become visible");
    let semantic_session =
        subjects["data"]["subjects"][0]["session_id"].as_str().expect("Semantic Session ID");
    let store_id = subjects["receipt"]["projection_commit"]["store_id"].as_str().expect("Store ID");
    assert_eq!(
        subjects,
        serde_json::json!({
            "http_schema_version": 1,
            "kind": "ok",
            "resource": "relationship_subjects",
            "data": {"subjects": [{
                "session_id": semantic_session,
                "link": "link-a",
                "profile": profile
            }]},
            "receipt": {"projection_commit": {"store_id": store_id, "sequence": "1"}}
        })
    );

    advance_host_clock(&runtime, Duration::from_millis(1_200));
    wait_for_projection(address, 2).await;

    let latest_request = format!(
        "GET /api/relationships/latest?session={semantic_session}&link=link-a&profile={profile} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let latest = http_request(address, &latest_request).await;
    assert!(latest.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_json(&latest),
        serde_json::json!({
            "http_schema_version": 1,
            "kind": "empty",
            "resource": "relationship_latest",
            "receipt": {
                "projection_commit": {"store_id": store_id, "sequence": "2"},
                "session_id": semantic_session,
                "first_record_seq": "0",
                "last_record_seq": "1",
                "decoder_version": "native-frame-v1",
                "conditioning_version": "amplitude-v1",
                "algorithm_version": "baseline-v1"
            }
        })
    );

    runtime.shutdown().await.expect("stop Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn immature_commit_is_accepted_into_order_without_fabricating_active_state() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_manual_clock(&fixture.config).await.expect("start Host runtime");
    let query = host_query_store(&runtime);
    let address = runtime.http_address();
    let profile = "11".repeat(32);
    let (mut websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/api/live"))
        .await
        .expect("connect runtime WebSocket");
    websocket.next().await.expect("handshake message").expect("valid handshake message");

    let begin = relationship_command_request("link-a", &profile);
    assert!(http_request(address, &begin).await.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    let begin_commit = websocket
        .next()
        .await
        .expect("BeginLearning invalidation")
        .expect("valid BeginLearning invalidation");
    let begin_commit: serde_json::Value =
        serde_json::from_str(begin_commit.to_text().expect("text invalidation"))
            .expect("invalidation JSON");
    assert_eq!(begin_commit["projection_commit"]["sequence"], "1");

    let commit = relationship_command_request_for("link-a", &profile, "commit");
    let accepted = http_request(address, &commit).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    assert_eq!(response_json(&accepted)["correlation_id"], "relationship-command-2");

    tokio::time::timeout(Duration::from_secs(1), runtime.wait_for_stop())
        .await
        .expect("immature Commit did not stop processing");
    if let Ok(Some(Ok(message))) =
        tokio::time::timeout(Duration::from_millis(100), websocket.next()).await
        && message.is_text()
    {
        panic!("immature Commit emitted an invalidation: {message:?}");
    }
    let subjects = serde_json::to_value(query.relationship_subjects().expect("query subjects"))
        .expect("serialize subjects");
    assert_eq!(subjects["receipt"]["projection_commit"]["sequence"], "1");
    assert_eq!(subjects["data"]["subjects"].as_array().expect("subjects").len(), 1);

    drop(websocket);
    drop(query);
    let error = runtime.shutdown().await.expect_err("immature Commit must stop the writer");
    assert!(error.is_writer_failure());
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn mature_commit_and_first_active_window_publish_stable_with_exact_change() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_manual_clock(&fixture.config).await.expect("start Host runtime");
    let address = runtime.http_address();
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let capture = runtime.capture_address();
    let destination =
        std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), capture.port());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");

    let begin = relationship_command_request("link-a", profile);
    assert!(http_request(address, &begin).await.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    wait_for_projection(address, 1).await;
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");
    wait_for_projection(address, 2).await;

    let mut capture_sequence = 0_u64;
    let mut message_sequence = 1_u64;
    let mut minimum_projection = 2_u64;
    for window in 0..15 {
        let frames_before_close = if window == 0 { 4 } else { 3 };
        for _ in 0..frames_before_close {
            advance_host_clock(&runtime, Duration::from_millis(200));
            capture_sequence += 1;
            message_sequence += 1;
            let mut csi = csi_body(&capability[..32]);
            csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
            sender
                .send_to(&seal_raw(2, message_sequence, &csi), destination)
                .await
                .expect("send eligible learning CSI");
            minimum_projection += 1;
            minimum_projection = wait_for_projection_at_least(address, minimum_projection).await;
        }
        advance_host_clock(&runtime, Duration::from_millis(400));
        capture_sequence += 1;
        message_sequence += 1;
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
        sender
            .send_to(&seal_raw(2, message_sequence, &csi), destination)
            .await
            .expect("close eligible learning window");
        minimum_projection += 2;
        minimum_projection = wait_for_projection_at_least(address, minimum_projection).await;
    }

    let learning = latest_relationship(address, profile).await;
    assert_eq!(
        learning["data"]["knowledge"],
        serde_json::json!({"kind": "unknown", "reason": "baseline_learning"})
    );

    let commit = relationship_command_request_for("link-a", profile, "commit");
    let accepted = http_request(address, &commit).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    minimum_projection += 1;
    minimum_projection = wait_for_projection_at_least(address, minimum_projection).await;

    for _ in 0..3 {
        advance_host_clock(&runtime, Duration::from_millis(200));
        capture_sequence += 1;
        message_sequence += 1;
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
        sender
            .send_to(&seal_raw(2, message_sequence, &csi), destination)
            .await
            .expect("send eligible Active CSI");
        minimum_projection += 1;
        minimum_projection = wait_for_projection_at_least(address, minimum_projection).await;
    }
    advance_host_clock(&runtime, Duration::from_millis(400));
    capture_sequence += 1;
    message_sequence += 1;
    let mut csi = csi_body(&capability[..32]);
    csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
    sender
        .send_to(&seal_raw(2, message_sequence, &csi), destination)
        .await
        .expect("close eligible Active window");
    minimum_projection += 2;
    let global_sequence = wait_for_projection_at_least(address, minimum_projection).await;
    minimum_projection = global_sequence;

    let stable = latest_relationship(address, profile).await;
    let store_id = stable["receipt"]["projection_commit"]["store_id"].as_str().expect("Store ID");
    let creator_sequence = stable["data"]["creator_commit"]["sequence"]
        .as_str()
        .expect("creator sequence")
        .parse::<u64>()
        .expect("u64 creator sequence");
    assert_eq!(
        stable["data"]["knowledge"],
        serde_json::json!({"kind": "known", "value": "stable"})
    );
    assert_eq!(stable["data"]["result_time"], "16000000000");
    assert_eq!(stable["data"]["creator_commit"]["store_id"], store_id);
    assert!(creator_sequence <= global_sequence);
    assert_eq!(
        stable["data"]["most_recent_change"],
        serde_json::json!({
            "previous": {"kind": "unknown", "reason": "baseline_learning"},
            "current": {"kind": "known", "value": "stable"},
            "changed_at": "16000000000"
        })
    );

    for _ in 0..3 {
        advance_host_clock(&runtime, Duration::from_millis(200));
        capture_sequence += 1;
        message_sequence += 1;
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
        sender
            .send_to(&seal_raw(2, message_sequence, &csi), destination)
            .await
            .expect("send repeated Stable CSI");
        minimum_projection += 1;
        minimum_projection = wait_for_projection_at_least(address, minimum_projection).await;
    }
    advance_host_clock(&runtime, Duration::from_millis(400));
    capture_sequence += 1;
    message_sequence += 1;
    let mut csi = csi_body(&capability[..32]);
    csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
    sender
        .send_to(&seal_raw(2, message_sequence, &csi), destination)
        .await
        .expect("close repeated Stable window");
    minimum_projection += 2;
    minimum_projection = wait_for_projection_at_least(address, minimum_projection).await;

    let equal = latest_relationship(address, profile).await;
    assert_eq!(equal["data"]["knowledge"], stable["data"]["knowledge"]);
    assert_eq!(equal["data"]["result_time"], "17000000000");
    assert_ne!(equal["data"]["creator_commit"], stable["data"]["creator_commit"]);
    assert_eq!(equal["data"]["most_recent_change"], stable["data"]["most_recent_change"]);

    for _ in 0..3 {
        advance_host_clock(&runtime, Duration::from_millis(200));
        capture_sequence += 1;
        message_sequence += 1;
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
        let raw = csi.len() - 6;
        csi[raw..].copy_from_slice(&[120, 120, 120, 120, 120, 120]);
        sender
            .send_to(&seal_raw(2, message_sequence, &csi), destination)
            .await
            .expect("send Changing CSI");
        minimum_projection += 1;
        minimum_projection = wait_for_projection_at_least(address, minimum_projection).await;
    }
    advance_host_clock(&runtime, Duration::from_millis(400));
    capture_sequence += 1;
    message_sequence += 1;
    let mut csi = csi_body(&capability[..32]);
    csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
    let raw = csi.len() - 6;
    csi[raw..].copy_from_slice(&[120, 120, 120, 120, 120, 120]);
    sender
        .send_to(&seal_raw(2, message_sequence, &csi), destination)
        .await
        .expect("close Changing window");
    minimum_projection += 2;
    wait_for_projection_at_least(address, minimum_projection).await;

    let changing = latest_relationship(address, profile).await;
    assert_eq!(
        changing["data"]["knowledge"],
        serde_json::json!({"kind": "known", "value": "changing"})
    );
    assert_eq!(changing["data"]["result_time"], "18000000000");
    assert_eq!(
        changing["data"]["most_recent_change"],
        serde_json::json!({
            "previous": {"kind": "known", "value": "stable"},
            "current": {"kind": "known", "value": "changing"},
            "changed_at": "18000000000"
        })
    );

    runtime.shutdown().await.expect("stop Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn active_windows_arm_then_adapt_and_reject_low_quality_through_committed_results() {
    let fixture = RuntimeFixture::with_unit_variance_floor();
    let runtime = start_host_with_manual_clock(&fixture.config).await.expect("start Host runtime");
    let address = runtime.http_address();
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        runtime.capture_address().port(),
    );
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let baseline_samples = [1, 2, 3, 4, 5, 6];
    let adaptation_samples = [2, 4, 6, 8, 10, 12];
    let threshold_probe_samples = [5, 29, 17, 47, 11, 70];

    let begin = relationship_command_request("link-a", profile);
    assert!(http_request(address, &begin).await.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    wait_for_projection(address, 1).await;
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");
    wait_for_projection(address, 2).await;

    let mut counters = (0_u64, 1_u64, 2_u64);
    for window in 0..15 {
        let frames_before_close = if window == 0 { 4 } else { 3 };
        for _ in 0..frames_before_close {
            advance_host_clock(&runtime, Duration::from_millis(200));
            counters.0 += 1;
            counters.1 += 1;
            let mut csi = csi_body(&capability[..32]);
            csi[32..40].copy_from_slice(&counters.0.to_le_bytes());
            sender
                .send_to(&seal_raw(2, counters.1, &csi), destination)
                .await
                .expect("send eligible learning CSI");
            counters.2 += 1;
            counters.2 = wait_for_projection_at_least(address, counters.2).await;
        }
        advance_host_clock(&runtime, Duration::from_millis(400));
        counters.0 += 1;
        counters.1 += 1;
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&counters.0.to_le_bytes());
        if window == 14 {
            let raw = csi.len() - adaptation_samples.len();
            csi[raw..].copy_from_slice(&adaptation_samples);
        }
        sender
            .send_to(&seal_raw(2, counters.1, &csi), destination)
            .await
            .expect("close eligible learning window");
        counters.2 += 2;
        counters.2 = wait_for_projection_at_least(address, counters.2).await;
    }

    let commit = relationship_command_request_for("link-a", profile, "commit");
    assert!(http_request(address, &commit).await.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    counters.2 += 1;
    counters.2 = wait_for_projection_at_least(address, counters.2).await;

    send_csi_window_after_carry(
        &runtime,
        &sender,
        destination,
        &capability[..32],
        &mut counters,
        WindowAfterCarry {
            samples: adaptation_samples,
            next_samples: threshold_probe_samples,
            additional_frames: 3,
        },
    )
    .await;
    let armed = latest_relationship(address, profile).await;
    assert_eq!(armed["data"]["knowledge"], serde_json::json!({"kind": "known", "value": "stable"}));
    assert_eq!(armed["data"]["result_time"], "16000000000");

    send_csi_window_after_carry(
        &runtime,
        &sender,
        destination,
        &capability[..32],
        &mut counters,
        WindowAfterCarry {
            samples: threshold_probe_samples,
            next_samples: adaptation_samples,
            additional_frames: 3,
        },
    )
    .await;
    let before_adaptation = latest_relationship(address, profile).await;
    assert_eq!(
        before_adaptation["data"]["knowledge"],
        serde_json::json!({"kind": "unknown", "reason": "ambiguous_evidence"})
    );
    assert_eq!(before_adaptation["data"]["result_time"], "17000000000");
    assert_ne!(before_adaptation["data"]["creator_commit"], armed["data"]["creator_commit"]);
    assert_eq!(
        before_adaptation["data"]["most_recent_change"],
        serde_json::json!({
            "previous": {"kind": "known", "value": "stable"},
            "current": {"kind": "unknown", "reason": "ambiguous_evidence"},
            "changed_at": "17000000000"
        })
    );

    send_csi_window_after_carry(
        &runtime,
        &sender,
        destination,
        &capability[..32],
        &mut counters,
        WindowAfterCarry {
            samples: adaptation_samples,
            next_samples: threshold_probe_samples,
            additional_frames: 3,
        },
    )
    .await;
    let adapted = latest_relationship(address, profile).await;
    assert_eq!(
        adapted["data"]["knowledge"],
        serde_json::json!({"kind": "known", "value": "stable"})
    );
    assert_eq!(adapted["data"]["result_time"], "18000000000");
    assert_ne!(adapted["data"]["creator_commit"], before_adaptation["data"]["creator_commit"]);
    assert_eq!(
        adapted["data"]["most_recent_change"],
        serde_json::json!({
            "previous": {"kind": "unknown", "reason": "ambiguous_evidence"},
            "current": {"kind": "known", "value": "stable"},
            "changed_at": "18000000000"
        })
    );

    send_csi_window_after_carry(
        &runtime,
        &sender,
        destination,
        &capability[..32],
        &mut counters,
        WindowAfterCarry {
            samples: threshold_probe_samples,
            next_samples: baseline_samples,
            additional_frames: 3,
        },
    )
    .await;
    let after_adaptation = latest_relationship(address, profile).await;
    assert_eq!(
        after_adaptation["data"]["knowledge"],
        serde_json::json!({"kind": "known", "value": "stable"})
    );
    assert_eq!(after_adaptation["data"]["result_time"], "19000000000");
    assert_ne!(after_adaptation["data"]["creator_commit"], adapted["data"]["creator_commit"]);
    assert_eq!(
        after_adaptation["data"]["most_recent_change"],
        adapted["data"]["most_recent_change"]
    );

    send_csi_window_after_carry(
        &runtime,
        &sender,
        destination,
        &capability[..32],
        &mut counters,
        WindowAfterCarry {
            samples: baseline_samples,
            next_samples: baseline_samples,
            additional_frames: 2,
        },
    )
    .await;
    let rejected = latest_relationship(address, profile).await;
    assert_eq!(
        rejected["data"]["knowledge"],
        serde_json::json!({"kind": "unknown", "reason": "low_quality"})
    );
    assert_eq!(rejected["data"]["result_time"], "20000000000");
    assert_ne!(rejected["data"]["creator_commit"], after_adaptation["data"]["creator_commit"]);
    assert_eq!(
        rejected["data"]["most_recent_change"],
        serde_json::json!({
            "previous": {"kind": "known", "value": "stable"},
            "current": {"kind": "unknown", "reason": "low_quality"},
            "changed_at": "20000000000"
        })
    );

    runtime.shutdown().await.expect("stop Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn repeated_begin_learning_is_rejected_without_reset_or_publication() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let query = host_query_store(&runtime);
    let address = runtime.http_address();
    let (mut websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/api/live"))
        .await
        .expect("connect runtime WebSocket");
    websocket.next().await.expect("handshake message").expect("valid handshake message");
    let request = relationship_command_request("link-a", &"11".repeat(32));
    assert!(http_request(address, &request).await.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    let first = websocket
        .next()
        .await
        .expect("first command invalidation")
        .expect("valid first command invalidation");
    let first: serde_json::Value =
        serde_json::from_str(first.to_text().expect("text invalidation"))
            .expect("invalidation JSON");
    assert_eq!(first["projection_commit"]["sequence"], "1");

    assert!(http_request(address, &request).await.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    tokio::time::timeout(Duration::from_secs(1), runtime.wait_for_stop())
        .await
        .expect("repeated command stop timeout");
    if let Ok(Some(Ok(message))) =
        tokio::time::timeout(Duration::from_millis(100), websocket.next()).await
        && message.is_text()
    {
        panic!("repeated BeginLearning emitted an invalidation: {message:?}");
    }
    let subjects = serde_json::to_value(query.relationship_subjects().expect("query subjects"))
        .expect("serialize subjects");
    assert_eq!(subjects["data"]["subjects"].as_array().expect("subjects").len(), 1);
    assert_eq!(subjects["receipt"]["projection_commit"]["sequence"], "1");
    drop(query);
    let error = runtime.shutdown().await.expect_err("repeated BeginLearning must stop the writer");
    assert!(error.is_writer_failure());
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn physical_format_csi_before_learning_publishes_committed_baseline_missing() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_manual_clock(&fixture.config).await.expect("start Host runtime");
    let address = runtime.http_address();
    let capture = runtime.capture_address();
    let destination =
        std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), capture.port());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");
    wait_for_projection(address, 1).await;
    for sequence in 1_u64..=4 {
        advance_host_clock(&runtime, Duration::from_millis(200));
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&sequence.to_le_bytes());
        sender
            .send_to(&seal_raw(2, sequence + 1, &csi), destination)
            .await
            .expect("send learning CSI");
        wait_for_projection(address, sequence + 1).await;
    }
    advance_host_clock(&runtime, Duration::from_millis(400));
    let mut later_csi = csi_body(&capability[..32]);
    later_csi[32..40].copy_from_slice(&5_u64.to_le_bytes());
    sender.send_to(&seal_raw(2, 6, &later_csi), destination).await.expect("send later-window CSI");
    wait_for_projection(address, 7).await;

    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let mut latest = None;
    for _ in 0..150 {
        let subjects = response_json(
            &http_request(
                address,
                "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        if let Some(semantic_session) = subjects["data"]["subjects"]
            .as_array()
            .and_then(|subjects| subjects.first())
            .and_then(|subject| subject["session_id"].as_str())
        {
            let request = format!(
                "GET /api/relationships/latest?session={semantic_session}&link=link-a&profile={profile} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            );
            let body = response_json(&http_request(address, &request).await);
            if body["kind"] == "ok" {
                latest = Some(body);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let latest = latest.expect("BaselineMissing relationship did not become query-visible");
    assert_eq!(
        latest["data"]["knowledge"],
        serde_json::json!({"kind": "unknown", "reason": "baseline_missing"})
    );
    assert_eq!(latest["data"]["result_time"], "1000000000");
    assert_eq!(latest["data"]["creator_commit"], latest["receipt"]["projection_commit"]);

    runtime.shutdown().await.expect("stop Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn knowledge_change_is_recorded_once_and_preserved_across_equal_results() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_manual_clock(&fixture.config).await.expect("start Host runtime");
    let address = runtime.http_address();
    let capture = runtime.capture_address();
    let destination =
        std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), capture.port());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";

    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");
    wait_for_projection(address, 1).await;
    for capture_sequence in 1_u64..=4 {
        advance_host_clock(&runtime, Duration::from_millis(200));
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
        sender
            .send_to(&seal_raw(2, capture_sequence + 1, &csi), destination)
            .await
            .expect("send pre-learning CSI");
        wait_for_projection(address, capture_sequence + 1).await;
    }
    advance_host_clock(&runtime, Duration::from_millis(400));
    let mut csi = csi_body(&capability[..32]);
    csi[32..40].copy_from_slice(&5_u64.to_le_bytes());
    sender.send_to(&seal_raw(2, 6, &csi), destination).await.expect("close missing window");
    wait_for_projection(address, 7).await;
    let missing = latest_relationship(address, profile).await;
    assert_eq!(
        missing["data"]["knowledge"],
        serde_json::json!({"kind": "unknown", "reason": "baseline_missing"})
    );
    assert!(missing["data"].get("most_recent_change").is_none());

    let accepted = http_request(address, &relationship_command_request("link-a", profile)).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    wait_for_projection(address, 8).await;
    for (capture_sequence, message_sequence) in [(6_u64, 7_u64), (7, 8), (8, 9)] {
        advance_host_clock(&runtime, Duration::from_millis(200));
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
        if capture_sequence == 7 {
            csi[68] = 4;
        }
        sender
            .send_to(&seal_raw(2, message_sequence, &csi), destination)
            .await
            .expect("send learning CSI");
        wait_for_projection(address, message_sequence + 2).await;
    }
    advance_host_clock(&runtime, Duration::from_millis(400));
    let mut csi = csi_body(&capability[..32]);
    csi[32..40].copy_from_slice(&9_u64.to_le_bytes());
    sender.send_to(&seal_raw(2, 10, &csi), destination).await.expect("close changed window");
    wait_for_projection(address, 13).await;
    let changed = latest_relationship(address, profile).await;
    assert_eq!(
        changed["data"]["knowledge"],
        serde_json::json!({"kind": "unknown", "reason": "baseline_learning"})
    );
    assert_eq!(
        changed["data"]["most_recent_change"],
        serde_json::json!({
            "previous": {"kind": "unknown", "reason": "baseline_missing"},
            "current": {"kind": "unknown", "reason": "baseline_learning"},
            "changed_at": "2000000000"
        })
    );

    for (capture_sequence, message_sequence) in [(10_u64, 11_u64), (11, 12), (12, 13)] {
        advance_host_clock(&runtime, Duration::from_millis(200));
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
        sender
            .send_to(&seal_raw(2, message_sequence, &csi), destination)
            .await
            .expect("send equal-result CSI");
        wait_for_projection(address, message_sequence + 3).await;
    }
    advance_host_clock(&runtime, Duration::from_millis(400));
    let mut csi = csi_body(&capability[..32]);
    csi[32..40].copy_from_slice(&13_u64.to_le_bytes());
    sender.send_to(&seal_raw(2, 14, &csi), destination).await.expect("close equal window");
    wait_for_projection(address, 18).await;
    let equal = latest_relationship(address, profile).await;
    assert_eq!(equal["data"]["result_time"], "3000000000");
    assert_eq!(equal["data"]["most_recent_change"], changed["data"]["most_recent_change"]);

    runtime.shutdown().await.expect("stop Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn begin_learning_and_physical_format_csi_publish_committed_baseline_learning() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_manual_clock(&fixture.config).await.expect("start Host runtime");
    let address = runtime.http_address();
    let (mut websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/api/live"))
        .await
        .expect("connect runtime WebSocket");
    let handshake = tokio::time::timeout(Duration::from_secs(1), websocket.next())
        .await
        .expect("handshake timeout")
        .expect("handshake message")
        .expect("valid handshake message");
    let handshake: serde_json::Value =
        serde_json::from_str(handshake.to_text().expect("text handshake")).expect("handshake JSON");
    assert_eq!(handshake["projection_commit"]["sequence"], "0");

    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let request = relationship_command_request("link-a", profile);
    let accepted = http_request(address, &request).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    let command_commit = tokio::time::timeout(Duration::from_secs(1), websocket.next())
        .await
        .expect("command invalidation timeout")
        .expect("command invalidation")
        .expect("valid command invalidation");
    let command_commit: serde_json::Value =
        serde_json::from_str(command_commit.to_text().expect("text command invalidation"))
            .expect("command invalidation JSON");
    assert_eq!(command_commit["projection_commit"]["sequence"], "1");
    assert_eq!(command_commit["payload"], serde_json::json!({"kind": "projection_watermark"}));

    let capture = runtime.capture_address();
    let destination =
        std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), capture.port());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");
    wait_for_projection(address, 2).await;
    for sequence in 1_u64..=4 {
        advance_host_clock(&runtime, Duration::from_millis(200));
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&sequence.to_le_bytes());
        sender
            .send_to(&seal_raw(2, sequence + 1, &csi), destination)
            .await
            .expect("send learning CSI");
        wait_for_projection(address, sequence + 2).await;
    }
    advance_host_clock(&runtime, Duration::from_millis(400));
    let mut later_csi = csi_body(&capability[..32]);
    later_csi[32..40].copy_from_slice(&5_u64.to_le_bytes());
    sender.send_to(&seal_raw(2, 6, &later_csi), destination).await.expect("send later-window CSI");
    wait_for_projection(address, 8).await;

    let mut latest = None;
    for _ in 0..150 {
        let subjects = response_json(
            &http_request(
                address,
                "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        if let Some(semantic_session) = subjects["data"]["subjects"][0]["session_id"].as_str() {
            let request = format!(
                "GET /api/relationships/latest?session={semantic_session}&link=link-a&profile={profile} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            );
            let response = http_request(address, &request).await;
            let body = response_json(&response);
            if body["kind"] == "ok" {
                latest = Some(body);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let latest = latest.expect("BaselineLearning relationship did not become query-visible");
    let semantic_session = latest["data"]["session_id"].as_str().expect("Semantic Session ID");
    let store_id = latest["receipt"]["projection_commit"]["store_id"].as_str().expect("Store ID");
    assert_eq!(
        latest,
        serde_json::json!({
            "http_schema_version": 1,
            "kind": "ok",
            "resource": "relationship_latest",
            "data": {
                "session_id": semantic_session,
                "link": "link-a",
                "profile": profile,
                "knowledge": {"kind": "unknown", "reason": "baseline_learning"},
                "result_time": "1000000000",
                "creator_commit": {"store_id": store_id, "sequence": "8"}
            },
            "receipt": {
                "projection_commit": {"store_id": store_id, "sequence": "8"},
                "session_id": semantic_session,
                "first_record_seq": "0",
                "last_record_seq": "7",
                "decoder_version": "native-frame-v1",
                "conditioning_version": "amplitude-v1",
                "algorithm_version": "baseline-v1"
            }
        })
    );

    let mut watermarks = vec![command_commit];
    while watermarks.len() < 8 {
        let message = tokio::time::timeout(Duration::from_secs(1), websocket.next())
            .await
            .expect("relationship invalidation timeout")
            .expect("relationship invalidation")
            .expect("valid relationship invalidation");
        watermarks.push(
            serde_json::from_str(message.to_text().expect("text invalidation"))
                .expect("invalidation JSON"),
        );
    }
    for (index, watermark) in watermarks.iter().enumerate() {
        assert_eq!(watermark["delivery_sequence"], (index + 1).to_string());
        assert_eq!(watermark["projection_commit"]["sequence"], (index + 1).to_string());
        assert_eq!(watermark["payload"], serde_json::json!({"kind": "projection_watermark"}));
        assert_eq!(watermark["projection_commit"]["store_id"], store_id);
    }

    drop(websocket);
    runtime.shutdown().await.expect("stop Host runtime");
}

#[tokio::test]
async fn udp_capture_commits_and_becomes_visible_through_canonical_http_queries() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let session = runtime.session_id().to_owned();
    let capture = runtime.capture_address();
    let destination =
        std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), capture.port());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");
    sender
        .send_to(&seal_raw(2, 2, &csi_body(&capability[..32])), destination)
        .await
        .expect("send CSI");

    let address = runtime.http_address();
    let mut committed = false;
    for _ in 0..100 {
        let response = http_request(
            address,
            "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let body = response_json(&response);
        if body["receipt"]["projection_commit"]["sequence"] == "2" {
            committed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(committed, "UDP packets did not become query-visible");

    let request = format!(
        "GET /api/signals?session={session}&sensor=sensor-a&link=link-a&from=0&to=18446744073709551615&metric=i&max_time_buckets=8 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let response = http_request(address, &request).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let body = response_json(&response);
    assert_eq!(body["data"]["tiles"][0]["cells"].as_array().expect("signal cells").len(), 3);
    assert_eq!(body["receipt"]["projection_commit"]["sequence"], "2");
    assert_eq!(runtime.queue_drop_count(), 0);

    runtime.shutdown().await.expect("stop Host runtime");
}

#[tokio::test]
async fn websocket_handshake_and_postcommit_messages_are_ordered_invalidation_only() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let address = runtime.http_address();
    let (mut websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/api/live"))
        .await
        .expect("connect runtime WebSocket");
    let handshake = tokio::time::timeout(std::time::Duration::from_secs(1), websocket.next())
        .await
        .expect("handshake timeout")
        .expect("handshake message")
        .expect("valid handshake message");
    let handshake: serde_json::Value =
        serde_json::from_str(handshake.to_text().expect("text handshake")).expect("handshake JSON");
    assert_eq!(handshake["delivery_sequence"], "0");
    assert_eq!(handshake["projection_commit"]["sequence"], "0");
    assert_eq!(handshake["payload"], serde_json::json!({"kind": "projection_watermark"}));

    let capture = runtime.capture_address();
    let destination =
        std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), capture.port());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");
    sender
        .send_to(&seal_raw(2, 2, &csi_body(&capability[..32])), destination)
        .await
        .expect("send CSI");

    let mut messages = Vec::new();
    while messages.len() < 2 {
        let message = tokio::time::timeout(std::time::Duration::from_secs(1), websocket.next())
            .await
            .expect("invalidation timeout")
            .expect("invalidation message")
            .expect("valid invalidation");
        messages.push(
            serde_json::from_str::<serde_json::Value>(
                message.to_text().expect("text invalidation"),
            )
            .expect("invalidation JSON"),
        );
    }
    assert_eq!(messages[0]["delivery_sequence"], "1");
    assert_eq!(messages[0]["projection_commit"]["sequence"], "1");
    assert_eq!(messages[1]["delivery_sequence"], "2");
    assert_eq!(messages[1]["projection_commit"]["sequence"], "2");
    assert_eq!(
        messages[0]["projection_commit"]["store_id"],
        handshake["projection_commit"]["store_id"]
    );
    assert_eq!(messages[1]["payload"], serde_json::json!({"kind": "projection_watermark"}));

    drop(websocket);
    runtime.shutdown().await.expect("stop Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn relationship_transaction_b_failure_stops_without_projection_or_invalidation() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_relationship_transaction_b_failure(&fixture.config)
        .await
        .expect("start transaction-B-failing Host runtime");
    let query = host_query_store(&runtime);
    let address = runtime.http_address();
    let (mut websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/api/live"))
        .await
        .expect("connect runtime WebSocket");
    websocket.next().await.expect("handshake message").expect("valid handshake message");
    let request = relationship_command_request("link-a", &"11".repeat(32));
    assert!(http_request(address, &request).await.starts_with(b"HTTP/1.1 202 Accepted\r\n"));

    tokio::time::timeout(std::time::Duration::from_secs(1), runtime.wait_for_stop())
        .await
        .expect("fatal runtime stop timeout");
    if let Ok(Some(Ok(message))) =
        tokio::time::timeout(Duration::from_millis(100), websocket.next()).await
        && message.is_text()
    {
        panic!("failed transaction B emitted an invalidation: {message:?}");
    }
    let subjects = serde_json::to_value(query.relationship_subjects().expect("query subjects"))
        .expect("serialize subjects");
    assert_eq!(subjects["data"]["subjects"], serde_json::json!([]));
    assert_eq!(subjects["receipt"]["projection_commit"]["sequence"], "0");
    drop(query);
    let error = runtime.shutdown().await.expect_err("fatal writer failure must reach the caller");
    assert!(error.is_writer_failure());
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn restart_rejects_an_a_only_tail() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_relationship_transaction_b_failure(&fixture.config)
        .await
        .expect("start transaction-B-failing Host runtime");
    assert!(
        http_request(
            runtime.http_address(),
            &relationship_command_request("link-a", &"11".repeat(32)),
        )
        .await
        .starts_with(b"HTTP/1.1 202 Accepted\r\n")
    );
    tokio::time::timeout(Duration::from_secs(1), runtime.wait_for_stop())
        .await
        .expect("transaction-B failure stop timeout");
    let error = runtime.shutdown().await.expect_err("transaction B must fail the writer");
    assert!(error.is_writer_failure());

    let error = HostRuntime::start(&fixture.config)
        .await
        .expect_err("A-only tail must reject controlled restart");
    assert_eq!(error.failure(), RuntimeFailure::Capture);
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn restart_rejects_a_replay_configuration_mismatch() {
    let fixture = RuntimeFixture::new();
    stop_host_with_processed_begin_learning(&fixture).await;

    let source = fs::read_to_string(&fixture.config_path).expect("read runtime configuration");
    let mismatched =
        parse_config(&source.replacen("variance_floor = 0.000001", "variance_floor = 0.000002", 1))
            .expect("parse mismatched replay configuration");
    let error = HostRuntime::start(&mismatched)
        .await
        .expect_err("replay configuration mismatch must reject controlled restart");
    assert_eq!(error.failure(), RuntimeFailure::Capture);
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn restart_rejects_a_distinct_real_executable() {
    let fixture = RuntimeFixture::new();
    stop_host_with_processed_begin_learning(&fixture).await;

    let restarted = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["serve", fixture.config_path.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run the distinct production executable");
    assert!(!restarted.status.success());
    assert!(String::from_utf8_lossy(&restarted.stderr).contains("Capture"));
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn relationship_transaction_a_failure_has_no_projection_or_invalidation_effect() {
    let fixture = RuntimeFixture::new();
    let runtime = start_host_with_relationship_transaction_a_failure(&fixture.config)
        .await
        .expect("start transaction-A-failing Host runtime");
    let query = host_query_store(&runtime);
    let address = runtime.http_address();
    let (mut websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/api/live"))
        .await
        .expect("connect runtime WebSocket");
    websocket.next().await.expect("handshake message").expect("valid handshake message");
    let request = relationship_command_request("link-a", &"11".repeat(32));
    assert!(http_request(address, &request).await.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    tokio::time::timeout(Duration::from_secs(1), runtime.wait_for_stop())
        .await
        .expect("transaction-A failure stop timeout");
    if let Ok(Some(Ok(message))) =
        tokio::time::timeout(Duration::from_millis(100), websocket.next()).await
        && message.is_text()
    {
        panic!("failed transaction A emitted an invalidation: {message:?}");
    }
    let subjects = serde_json::to_value(query.relationship_subjects().expect("query subjects"))
        .expect("serialize subjects");
    assert_eq!(subjects["data"]["subjects"], serde_json::json!([]));
    assert_eq!(subjects["receipt"]["projection_commit"]["sequence"], "0");
    drop(query);
    let error = runtime.shutdown().await.expect_err("transaction-A failure must stop the writer");
    assert!(error.is_writer_failure());
}

#[tokio::test]
async fn controlled_restart_preserves_dynamic_relationship_subjects() {
    let fixture = RuntimeFixture::new();
    let first = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let address = first.http_address();
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    for link in ["link-a", "link-b"] {
        let response = http_request(address, &relationship_command_request(link, profile)).await;
        assert!(response.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    }
    let capture = first.capture_address();
    let destination =
        std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), capture.port());
    let sender =
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind second Sensor sender");
    let first_capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender
        .send_to(&seal_raw(1, 1, &first_capability), destination)
        .await
        .expect("send first capability");
    sender
        .send_to(&seal_raw(2, 2, &csi_body(&first_capability[..32])), destination)
        .await
        .expect("send first CSI");
    let capability = capability_body([0x03; 32], [0x44; 32], 2048);
    sender
        .send_to(&seal_raw_for(&[0x22; 32], 2, 1, 1, &capability), destination)
        .await
        .expect("send second capability");
    sender
        .send_to(
            &seal_raw_for(
                &[0x22; 32],
                2,
                2,
                2,
                &csi_body_for(&capability[..32], [2, 0, 0, 0, 0, 11], 6),
            ),
            destination,
        )
        .await
        .expect("send second CSI");

    let mut committed = false;
    for _ in 0..100 {
        let body = response_json(
            &http_request(
                address,
                "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        if body["receipt"]["projection_commit"]["sequence"] == "6" {
            committed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(committed, "both Sensors' packets did not commit");
    let first_capture_sessions = capture_session_ids(address).await;
    assert_eq!(first_capture_sessions.len(), 1);
    let session = &first_capture_sessions[0];
    let first_request = format!(
        "GET /api/signals?session={session}&sensor=sensor-a&link=link-a&from=0&to=18446744073709551615&metric=i&max_time_buckets=8 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let first_signals = response_json(&http_request(address, &first_request).await);
    assert_eq!(first_signals["data"]["tiles"][0]["stream"]["key"]["sensor"], "sensor-a");
    let request = format!(
        "GET /api/signals?session={session}&sensor=sensor-b&link=link-b&from=0&to=18446744073709551615&metric=q&max_time_buckets=8 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let response = http_request(address, &request).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let body = response_json(&response);
    assert_eq!(body["data"]["tiles"][0]["stream"]["key"]["sensor"], "sensor-b");
    assert_eq!(body["data"]["tiles"][0]["stream"]["device_epoch"]["device_id"], "2");

    let subjects = response_json(
        &http_request(
            address,
            "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    assert_eq!(
        subjects["data"]["subjects"],
        serde_json::json!([
            {"session_id": subjects["data"]["subjects"][0]["session_id"], "link": "link-a", "profile": profile},
            {"session_id": subjects["data"]["subjects"][0]["session_id"], "link": "link-b", "profile": profile}
        ])
    );

    let semantic_session = subjects["data"]["subjects"][0]["session_id"].clone();
    first.shutdown().await.expect("stop first Host runtime");

    let second = HostRuntime::start(&fixture.config).await.expect("restart Host runtime");
    let restarted_subjects = response_json(
        &http_request(
            second.http_address(),
            "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    assert_eq!(restarted_subjects["data"], subjects["data"]);
    assert_eq!(restarted_subjects["receipt"], subjects["receipt"]);
    assert_eq!(capture_session_ids(second.http_address()).await, first_capture_sessions);

    let destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        second.capture_address().port(),
    );
    let mut first_csi = csi_body(&first_capability[..32]);
    first_csi[32..40].copy_from_slice(&2_u64.to_le_bytes());
    sender
        .send_to(&seal_raw(2, 3, &first_csi), destination)
        .await
        .expect("continue first Sensor after restart");
    wait_for_projection(second.http_address(), 7).await;
    let continued_capture_sessions = capture_session_ids(second.http_address()).await;
    assert_eq!(continued_capture_sessions.len(), 2);
    assert!(continued_capture_sessions.contains(session));
    let second_capture = continued_capture_sessions
        .iter()
        .find(|candidate| *candidate != session)
        .expect("new Capture Session");
    let first_continuation =
        raw_signals(second.http_address(), second_capture, "sensor-a", "link-a").await;
    assert_eq!(first_continuation["receipt"]["session_id"], second_capture.as_str());
    assert_eq!(first_continuation["receipt"]["first_record_seq"], "0");
    assert_eq!(first_continuation["receipt"]["last_record_seq"], "0");

    let mut second_csi = csi_body_for(&capability[..32], [2, 0, 0, 0, 0, 11], 6);
    second_csi[32..40].copy_from_slice(&2_u64.to_le_bytes());
    sender
        .send_to(&seal_raw_for(&[0x22; 32], 2, 2, 3, &second_csi), destination)
        .await
        .expect("continue second Sensor after restart");
    wait_for_projection(second.http_address(), 8).await;
    let second_continuation =
        raw_signals(second.http_address(), second_capture, "sensor-b", "link-b").await;
    assert_eq!(second_continuation["receipt"]["session_id"], second_capture.as_str());
    assert_eq!(second_continuation["receipt"]["first_record_seq"], "0");
    assert_eq!(second_continuation["receipt"]["last_record_seq"], "1");

    let continued_subjects = response_json(
        &http_request(
            second.http_address(),
            "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    assert_eq!(continued_subjects["data"], subjects["data"]);
    assert_eq!(continued_subjects["data"]["subjects"][0]["session_id"], semantic_session);
    assert_eq!(continued_subjects["data"]["subjects"].as_array().expect("subjects").len(), 2);
    assert_eq!(continued_subjects["receipt"]["projection_commit"]["sequence"], "8");
    second.shutdown().await.expect("stop restarted Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn relationship_command_queue_exhaustion_is_canonical_and_has_no_extra_store_effect() {
    let fixture = RuntimeFixture::with_queue_capacity(1);
    let mut runtime =
        start_host_with_writer_held(&fixture.config).await.expect("start held Host runtime");
    let address = runtime.http_address();
    let profile = "11".repeat(32);
    let request = relationship_command_request("link-a", &profile);

    let accepted = http_request(address, &request).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    let rejected = http_request(address, &request).await;
    assert!(rejected.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert_eq!(response_json(&rejected)["error"]["code"], "command_queue_full");

    release_writer(&mut runtime);
    for _ in 0..100 {
        let subjects = response_json(
            &http_request(
                address,
                "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        if subjects["data"]["subjects"].as_array().is_some_and(|items| items.len() == 1) {
            runtime.shutdown().await.expect("stop Host runtime");
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the sole accepted relationship command did not commit");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn runtime_queue_exhaustion_counts_the_drop_without_store_effect() {
    let fixture = RuntimeFixture::with_queue_capacity(1);
    let mut runtime =
        start_host_with_writer_held(&fixture.config).await.expect("start held Host runtime");
    let destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        runtime.capture_address().port(),
    );
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("fill writer queue");
    sender.send_to(&seal_raw(1, 2, &capability), destination).await.expect("overflow writer queue");

    for _ in 0..100 {
        if runtime.queue_drop_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(runtime.queue_drop_count(), 1);
    release_writer(&mut runtime);

    let mut committed = false;
    for _ in 0..100 {
        let packets: u64 = Connection::open(&fixture.database)
            .expect("open Store")
            .query_row("SELECT count(*) FROM packet_capture_membership", [], |row| row.get(0))
            .expect("count packets");
        if packets == 1 {
            committed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(committed, "the sole queued packet did not commit");
    let queue_drop_count = runtime.shutdown().await.expect("stop Host runtime");
    assert_eq!(queue_drop_count, 1);
}

#[tokio::test]
async fn shutdown_cancels_an_unread_websocket_and_releases_the_lease() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let (websocket, _) =
        tokio_tungstenite::connect_async(format!("ws://{}/api/live", runtime.http_address()))
            .await
            .expect("connect unread WebSocket");

    tokio::time::timeout(Duration::from_secs(1), runtime.shutdown())
        .await
        .expect("WebSocket retained runtime shutdown")
        .expect("stop Host runtime");
    drop(websocket);
    HostRuntime::start(&fixture.config)
        .await
        .expect("WebSocket shutdown released the lifecycle lease")
        .shutdown()
        .await
        .expect("stop replacement Host runtime");
}

#[tokio::test]
async fn slow_ordinary_http_connection_is_force_closed_before_shutdown_deadline() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let mut connection =
        TcpStream::connect(runtime.http_address()).await.expect("connect ordinary HTTP client");
    connection
        .write_all(b"GET /api/topology HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("send incomplete HTTP headers");
    tokio::time::sleep(Duration::from_millis(20)).await;

    let shutdown = tokio::time::timeout(Duration::from_secs(1), runtime.shutdown()).await;
    drop(connection);
    shutdown
        .expect("slow ordinary HTTP connection retained Host shutdown")
        .expect("stop Host runtime");

    HostRuntime::start(&fixture.config)
        .await
        .expect("bounded HTTP shutdown released the lifecycle lease")
        .shutdown()
        .await
        .expect("stop replacement Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn slow_store_query_is_interrupted_before_shutdown_releases_the_lease() {
    let fixture = RuntimeFixture::new();
    let (runtime, mut query_hold) =
        start_host_with_query_held(&fixture.config).await.expect("start query-gated Host runtime");
    let address = runtime.http_address();
    let request = tokio::spawn(async move {
        http_request(
            address,
            "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
    });
    query_hold = tokio::task::spawn_blocking(move || {
        query_hold.wait_until_blocked();
        query_hold
    })
    .await
    .expect("observe blocked Store query");

    tokio::time::timeout(Duration::from_secs(1), runtime.shutdown())
        .await
        .expect("slow Store query retained Host shutdown")
        .expect("stop query-gated Host runtime");
    drop(query_hold);
    let _ = request.await.expect("join interrupted HTTP request");

    HostRuntime::start(&fixture.config)
        .await
        .expect("interrupted Store query released the lifecycle lease")
        .shutdown()
        .await
        .expect("stop replacement Host runtime");
}

#[tokio::test]
async fn query_failure_stops_the_host_and_is_returned_after_cleanup() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    Connection::open(&fixture.database)
        .expect("open Store")
        .execute("UPDATE store_state SET topology_manifest_digest = zeroblob(32)", [])
        .expect("corrupt query authority");
    let response = http_request(
        runtime.http_address(),
        "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 500 Internal Server Error\r\n"));
    tokio::time::timeout(Duration::from_secs(1), runtime.wait_for_stop())
        .await
        .expect("query fatal did not stop runtime");
    let error = runtime.shutdown().await.expect_err("query fatal must reach the caller");
    assert!(error.is_query_failure());
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn idle_writer_panic_stops_the_host_without_another_datagram() {
    let fixture = RuntimeFixture::new();
    let runtime =
        start_host_with_panicked_writer(&fixture.config).await.expect("start writer-panic runtime");
    tokio::time::timeout(Duration::from_secs(1), runtime.wait_for_stop())
        .await
        .expect("idle writer panic did not stop the Host");
    let error = runtime.shutdown().await.expect_err("writer panic must reach the caller");
    assert!(error.is_writer_failure());
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn cancelled_shutdown_finishes_cleanup_and_releases_the_lease() {
    let fixture = RuntimeFixture::with_queue_capacity(1);
    let runtime =
        start_host_with_writer_held(&fixture.config).await.expect("start held Host runtime");
    let mut shutdown = Box::pin(runtime.shutdown());
    assert!(matches!(futures_util::poll!(&mut shutdown), std::task::Poll::Pending));
    drop(shutdown);

    let mut replacement = None;
    for _ in 0..100 {
        match HostRuntime::start(&fixture.config).await {
            Ok(host) => {
                replacement = Some(host);
                break;
            }
            Err(error) if error.is_lease_conflict() => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("unexpected replacement startup failure: {error}"),
        }
    }
    replacement
        .expect("cancelled shutdown did not release the lifecycle lease")
        .shutdown()
        .await
        .expect("stop replacement Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn blocking_teardown_never_stalls_the_callers_tokio_worker() {
    let fixture = RuntimeFixture::new();
    let (runtime, mut teardown) = start_host_with_teardown_held(&fixture.config)
        .await
        .expect("start teardown-gated Host runtime");
    let heartbeat = std::sync::Arc::new(AtomicU64::new(0));
    let heartbeat_task = {
        let heartbeat = std::sync::Arc::clone(&heartbeat);
        tokio::spawn(async move {
            loop {
                heartbeat.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        })
    };
    let shutdown = tokio::spawn(runtime.shutdown());
    teardown.wait_until_blocked().await;
    let before = heartbeat.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        heartbeat.load(Ordering::Relaxed) > before,
        "blocking teardown stalled the caller's Tokio worker"
    );
    teardown.release();
    shutdown.await.expect("join shutdown waiter").expect("stop Host runtime");
    heartbeat_task.abort();

    HostRuntime::start(&fixture.config)
        .await
        .expect("blocking teardown released the lifecycle lease")
        .shutdown()
        .await
        .expect("stop replacement Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[test]
fn dropping_the_handle_and_callers_executor_cannot_cancel_supervisor_cleanup() {
    let fixture = RuntimeFixture::new();
    let caller = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build caller executor");
    let (runtime, mut teardown) = caller
        .block_on(start_host_with_teardown_held(&fixture.config))
        .expect("start teardown-gated Host runtime");
    drop(caller);
    drop(runtime);

    let waiter = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build teardown observer");
    waiter.block_on(teardown.wait_until_blocked());
    teardown.release();
    drop(waiter);

    let replacement_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build replacement executor");
    let mut replacement = None;
    for _ in 0..100 {
        match replacement_runtime.block_on(HostRuntime::start(&fixture.config)) {
            Ok(host) => {
                replacement = Some(host);
                break;
            }
            Err(error) if error.is_lease_conflict() => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("unexpected replacement startup failure: {error}"),
        }
    }
    replacement_runtime
        .block_on(
            replacement
                .expect("independent supervisor did not release the lifecycle lease")
                .shutdown(),
        )
        .expect("stop replacement Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn fully_processed_restart_continues_the_active_semantic_session() {
    let fixture = RuntimeFixture::new();
    let first = start_host_with_manual_clock(&fixture.config).await.expect("start first Host");
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let first_destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        first.capture_address().port(),
    );
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender
        .send_to(&seal_raw(1, 1, &capability), first_destination)
        .await
        .expect("send pre-restart capability");
    wait_for_projection(first.http_address(), 1).await;
    for capture_sequence in 1_u64..=4 {
        advance_host_clock(&first, Duration::from_millis(200));
        let mut csi = csi_body(&capability[..32]);
        csi[32..40].copy_from_slice(&capture_sequence.to_le_bytes());
        sender
            .send_to(&seal_raw(2, capture_sequence + 1, &csi), first_destination)
            .await
            .expect("send pre-restart CSI");
        wait_for_projection(first.http_address(), capture_sequence + 1).await;
    }
    advance_host_clock(&first, Duration::from_millis(400));
    let mut csi = csi_body(&capability[..32]);
    csi[32..40].copy_from_slice(&5_u64.to_le_bytes());
    sender
        .send_to(&seal_raw(2, 6, &csi), first_destination)
        .await
        .expect("send pre-restart physical tail");
    wait_for_projection(first.http_address(), 7).await;
    let before = response_json(
        &http_request(
            first.http_address(),
            "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    let semantic_session = before["data"]["subjects"][0]["session_id"]
        .as_str()
        .expect("active Semantic Session")
        .to_owned();
    let first_capture_sessions = capture_session_ids(first.http_address()).await;
    assert_eq!(first_capture_sessions.len(), 1);
    first.shutdown().await.expect("stop first Host");

    let second = start_host_with_manual_clock(&fixture.config).await.expect("restart Host");
    assert_eq!(capture_session_ids(second.http_address()).await, first_capture_sessions);
    advance_host_clock(&second, Duration::from_secs(2));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after_deadline = response_json(
        &http_request(
            second.http_address(),
            "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    assert_eq!(after_deadline["receipt"]["projection_commit"]["sequence"], "7");
    let command =
        http_request(second.http_address(), &relationship_command_request("link-a", profile)).await;
    assert!(command.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(response_json(&command)["error"]["code"], "invalid_request");
    let after_command = response_json(
        &http_request(
            second.http_address(),
            "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    assert_eq!(after_command["receipt"]["projection_commit"]["sequence"], "7");
    let destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        second.capture_address().port(),
    );
    let mut tail_plus_one = csi_body(&capability[..32]);
    tail_plus_one[32..40].copy_from_slice(&6_u64.to_le_bytes());
    sender
        .send_to(&seal_raw(2, 7, &tail_plus_one), destination)
        .await
        .expect("send physical tail plus one");
    let first_post_restart_projection =
        wait_for_projection_at_least(second.http_address(), 8).await;
    assert_eq!(first_post_restart_projection, 8);
    let continued_capture_sessions = capture_session_ids(second.http_address()).await;
    assert_eq!(continued_capture_sessions.len(), 2);
    assert!(continued_capture_sessions.contains(&first_capture_sessions[0]));
    let second_capture = continued_capture_sessions
        .iter()
        .find(|candidate| !first_capture_sessions.contains(candidate))
        .expect("new Capture Session");
    let first_continuation =
        raw_signals(second.http_address(), second_capture, "sensor-a", "link-a").await;
    assert_eq!(first_continuation["receipt"]["session_id"], second_capture.as_str());
    assert_eq!(first_continuation["receipt"]["first_record_seq"], "0");
    assert_eq!(first_continuation["receipt"]["last_record_seq"], "0");
    assert_eq!(first_continuation["receipt"]["projection_commit"]["sequence"], "8");

    let accepted =
        http_request(second.http_address(), &relationship_command_request("link-a", profile)).await;
    assert!(accepted.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    wait_for_projection(second.http_address(), 9).await;

    sender
        .send_to(&seal_raw(2, 7, &tail_plus_one), destination)
        .await
        .expect("repeat first post-restart physical record");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after_replay = response_json(
        &http_request(
            second.http_address(),
            "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    assert_eq!(after_replay["receipt"]["projection_commit"]["sequence"], "9");
    let after_replay_signals =
        raw_signals(second.http_address(), second_capture, "sensor-a", "link-a").await;
    assert_eq!(after_replay_signals["receipt"]["session_id"], second_capture.as_str());
    assert_eq!(after_replay_signals["receipt"]["first_record_seq"], "0");
    assert_eq!(after_replay_signals["receipt"]["last_record_seq"], "0");
    assert_eq!(after_replay_signals["receipt"]["projection_commit"]["sequence"], "9");

    let after = response_json(
        &http_request(
            second.http_address(),
            "GET /api/relationships/latest HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await,
    );
    assert_eq!(after["data"]["subjects"].as_array().expect("subjects").len(), 1);
    assert_eq!(after["data"]["subjects"][0]["session_id"], semantic_session);
    second.shutdown().await.expect("stop restarted Host");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn restart_rebuilds_stable_and_later_equal_window_preserves_the_last_change() {
    let fixture = RuntimeFixture::new();
    let first = start_host_with_manual_clock(&fixture.config).await.expect("start first Host");
    let profile = "61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2";
    let destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        first.capture_address().port(),
    );
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    assert!(
        http_request(first.http_address(), &relationship_command_request("link-a", profile))
            .await
            .starts_with(b"HTTP/1.1 202 Accepted\r\n")
    );
    wait_for_projection(first.http_address(), 1).await;
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");
    wait_for_projection(first.http_address(), 2).await;
    let mut counters = (0_u64, 1_u64, 2_u64);
    for window in 0..15 {
        send_csi_window_after_carry(
            &first,
            &sender,
            destination,
            &capability[..32],
            &mut counters,
            WindowAfterCarry {
                samples: [1, 2, 3, 4, 5, 6],
                next_samples: [1, 2, 3, 4, 5, 6],
                additional_frames: if window == 0 { 4 } else { 3 },
            },
        )
        .await;
    }
    assert!(
        http_request(
            first.http_address(),
            &relationship_command_request_for("link-a", profile, "commit"),
        )
        .await
        .starts_with(b"HTTP/1.1 202 Accepted\r\n")
    );
    counters.2 += 1;
    counters.2 = wait_for_projection_at_least(first.http_address(), counters.2).await;
    send_csi_window_after_carry(
        &first,
        &sender,
        destination,
        &capability[..32],
        &mut counters,
        WindowAfterCarry {
            samples: [1, 2, 3, 4, 5, 6],
            next_samples: [1, 2, 3, 4, 5, 6],
            additional_frames: 3,
        },
    )
    .await;
    let stable = latest_relationship(first.http_address(), profile).await;
    assert_eq!(
        stable["data"]["knowledge"],
        serde_json::json!({"kind": "known", "value": "stable"})
    );
    let semantic_session = stable["data"]["session_id"].clone();
    let previous_result_time = stable["data"]["result_time"]
        .as_str()
        .expect("result time")
        .parse::<u64>()
        .expect("u64 result time");
    let previous_change = stable["data"]["most_recent_change"].clone();
    let previous_creator = stable["data"]["creator_commit"].clone();
    let previous_store = stable["receipt"]["projection_commit"]["store_id"].clone();
    let first_capture_sessions = capture_session_ids(first.http_address()).await;
    assert_eq!(first_capture_sessions.len(), 1);
    first.shutdown().await.expect("stop first Host");

    let second = start_host_with_manual_clock(&fixture.config).await.expect("restart Host");
    let rebuilt = latest_relationship(second.http_address(), profile).await;
    assert_eq!(rebuilt["data"], stable["data"]);
    assert_eq!(rebuilt["receipt"], stable["receipt"]);
    assert_eq!(capture_session_ids(second.http_address()).await, first_capture_sessions);

    let destination = std::net::SocketAddr::new(
        "127.0.0.1".parse().expect("loopback"),
        second.capture_address().port(),
    );
    counters.1 += 1;
    sender
        .send_to(&seal_raw(1, counters.1, &capability), destination)
        .await
        .expect("send first post-restart physical record");
    counters.2 += 1;
    counters.2 = wait_for_projection_at_least(second.http_address(), counters.2).await;
    let continued_capture_sessions = capture_session_ids(second.http_address()).await;
    assert_eq!(continued_capture_sessions.len(), 2);
    assert!(continued_capture_sessions.contains(&first_capture_sessions[0]));
    send_csi_window_after_carry(
        &second,
        &sender,
        destination,
        &capability[..32],
        &mut counters,
        WindowAfterCarry {
            samples: [1, 2, 3, 4, 5, 6],
            next_samples: [1, 2, 3, 4, 5, 6],
            additional_frames: 3,
        },
    )
    .await;
    let continued = latest_relationship(second.http_address(), profile).await;
    assert_eq!(continued["data"]["session_id"], semantic_session);
    assert_eq!(continued["receipt"]["projection_commit"]["store_id"], previous_store);
    assert_eq!(continued["data"]["knowledge"], stable["data"]["knowledge"]);
    assert_eq!(continued["data"]["most_recent_change"], previous_change);
    assert_eq!(
        continued["data"]["result_time"],
        (previous_result_time + 1_000_000_000).to_string()
    );
    assert_ne!(continued["data"]["creator_commit"], previous_creator);
    second.shutdown().await.expect("stop restarted Host");
}

#[test]
fn cli_serve_runs_until_sigint_and_reports_network_role_failure() {
    let invalid = RuntimeFixture::new();
    let invalid_source = fs::read_to_string(&invalid.config_path)
        .expect("read runtime configuration")
        .replacen("bind = \"127.0.0.1:0\"", "bind = \"0.0.0.0:0\"", 1);
    fs::write(&invalid.config_path, invalid_source).expect("write invalid server role");
    let failed = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["serve", invalid.config_path.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run invalid serve");
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("network bind roles are invalid"));

    let fixture = RuntimeFixture::new();
    let (mut child, line, mut stdout) = spawn_serve_cli(&fixture.config_path);
    assert!(line.starts_with("Host runtime started: capture="));
    assert!(line.contains(" http=127.0.0.1:"));

    let signal = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("signal serve CLI");
    assert!(signal.success());
    let mut stopped = String::new();
    stdout.read_to_string(&mut stopped).expect("read serve shutdown report");
    let status = child.wait().expect("wait for serve CLI");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("capture serve stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "serve CLI failed after SIGINT: {stderr}");
    assert_eq!(stopped, "Host runtime stopped: queue_drop_count=0\n");
}

#[test]
fn cli_serve_reports_a_fatal_query_and_exits_unsuccessfully() {
    let fixture = RuntimeFixture::new();
    let (mut child, line, mut stdout) = spawn_serve_cli(&fixture.config_path);
    let http_address: std::net::SocketAddr = line
        .split_once(" http=")
        .expect("startup line HTTP address")
        .1
        .trim()
        .parse()
        .expect("parse CLI HTTP address");
    Connection::open(&fixture.database)
        .expect("open Store")
        .execute("UPDATE store_state SET topology_manifest_digest = zeroblob(32)", [])
        .expect("corrupt query authority");
    let mut stream = std::net::TcpStream::connect(http_address).expect("connect CLI HTTP");
    std::io::Write::write_all(
        &mut stream,
        b"GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .expect("request fatal query");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read fatal query response");
    assert!(response.starts_with(b"HTTP/1.1 500 Internal Server Error\r\n"));

    let status = wait_for_cli_exit(&mut child);
    let mut stopped = String::new();
    stdout.read_to_string(&mut stopped).expect("read fatal CLI stdout");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("capture serve stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(!status.success());
    assert!(stopped.is_empty(), "fatal CLI reported a passing queue-drop count: {stopped}");
    assert!(stderr.contains("Host runtime shutdown failed"));
    assert!(stderr.contains("Query Store"));
}
