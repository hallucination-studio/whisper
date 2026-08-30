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

#[tokio::test]
async fn fatal_writer_failure_stops_capture_and_delivery_without_partial_commit() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let capture = runtime.capture_address();
    let destination =
        std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), capture.port());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP sender");
    let capability = capability_body([0x01; 32], [0x22; 32], 1024);
    sender.send_to(&seal_raw(1, 1, &capability), destination).await.expect("send capability");

    let address = runtime.http_address();
    let mut capability_committed = false;
    for _ in 0..100 {
        let body = response_json(
            &http_request(
                address,
                "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        if body["receipt"]["projection_commit"]["sequence"] == "1" {
            capability_committed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(capability_committed, "capability did not commit before corruption");
    Connection::open(&fixture.database)
        .expect("open Store")
        .execute("UPDATE capability_epochs SET descriptor_bytes = zeroblob(79)", [])
        .expect("install capability conflict");
    sender
        .send_to(&seal_raw(1, 2, &capability), destination)
        .await
        .expect("send conflicting capability");

    tokio::time::timeout(std::time::Duration::from_secs(1), runtime.wait_for_stop())
        .await
        .expect("fatal runtime stop timeout");
    let error = runtime.shutdown().await.expect_err("fatal writer failure must reach the caller");
    assert!(error.is_writer_failure());

    let packets: u64 = Connection::open(&fixture.database)
        .expect("open stopped Store")
        .query_row("SELECT count(*) FROM packet_records", [], |row| row.get(0))
        .expect("count committed packets");
    assert_eq!(packets, 1, "fatal packet transaction must roll back completely");
}

#[tokio::test]
async fn runtime_routes_a_nonfirst_configured_sensor_without_singleton_shortcuts() {
    let fixture = RuntimeFixture::new();
    let runtime = HostRuntime::start(&fixture.config).await.expect("start Host runtime");
    let session = runtime.session_id().to_owned();
    let capture = runtime.capture_address();
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

    let address = runtime.http_address();
    let mut committed = false;
    for _ in 0..100 {
        let body = response_json(
            &http_request(
                address,
                "GET /api/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        if body["receipt"]["projection_commit"]["sequence"] == "4" {
            committed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(committed, "both Sensors' packets did not commit");
    let first_request = format!(
        "GET /api/signals?session={session}&sensor=sensor-a&link=link-a&from=0&to=18446744073709551615&metric=i&max_time_buckets=8 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let first = response_json(&http_request(address, &first_request).await);
    assert_eq!(first["data"]["tiles"][0]["stream"]["key"]["sensor"], "sensor-a");
    let request = format!(
        "GET /api/signals?session={session}&sensor=sensor-b&link=link-b&from=0&to=18446744073709551615&metric=q&max_time_buckets=8 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let response = http_request(address, &request).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let body = response_json(&response);
    assert_eq!(body["data"]["tiles"][0]["stream"]["key"]["sensor"], "sensor-b");
    assert_eq!(body["data"]["tiles"][0]["stream"]["device_epoch"]["device_id"], "2");

    runtime.shutdown().await.expect("stop Host runtime");
}

#[cfg(feature = "ingest-test-hooks")]
#[tokio::test]
async fn runtime_queue_exhaustion_counts_the_drop_without_store_effect() {
    let fixture = RuntimeFixture::with_queue_capacity(1);
    let mut runtime = HostRuntime::start_with_writer_held_for_test(&fixture.config)
        .await
        .expect("start held Host runtime");
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
    runtime.release_writer_for_test();

    let mut committed = false;
    for _ in 0..100 {
        let packets: u64 = Connection::open(&fixture.database)
            .expect("open Store")
            .query_row("SELECT count(*) FROM packet_records", [], |row| row.get(0))
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
    let (runtime, mut query_hold) = HostRuntime::start_with_query_held_for_test(&fixture.config)
        .await
        .expect("start query-gated Host runtime");
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
    let runtime = HostRuntime::start_with_panicked_writer_for_test(&fixture.config)
        .await
        .expect("start writer-panic runtime");
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
    let runtime = HostRuntime::start_with_writer_held_for_test(&fixture.config)
        .await
        .expect("start held Host runtime");
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
    let (runtime, mut teardown) = HostRuntime::start_with_teardown_held_for_test(&fixture.config)
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
        .block_on(HostRuntime::start_with_teardown_held_for_test(&fixture.config))
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
