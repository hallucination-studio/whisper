//! Store lifecycle behavior through the public application seam.

#![cfg(all(unix, feature = "ingest-test-hooks"))]

use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::Connection;
use whisper::{Config, parse_config};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

type AdmissionRow = (Vec<u8>, Vec<u8>, u16, Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>);

struct StoreFixture {
    root: PathBuf,
    config: PathBuf,
    database: PathBuf,
}

impl StoreFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "whisper-store-{}-{}",
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

        let source = fs::read_to_string(format!(
            "{}/tests/fixtures/config/valid-two-esp32.toml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("read valid configuration")
        .replace(
            "secret_root = \"./data/secrets\"",
            &format!("secret_root = \"{}\"", secret_root.display()),
        )
        .replace(
            "database_path = \"./data/whisper.sqlite3\"",
            &format!("database_path = \"{}\"", database.display()),
        );
        let config = root.join("host.toml");
        fs::write(&config, source).expect("write runtime configuration");

        Self { root, config, database }
    }

    fn parsed_config(&self) -> Config {
        let source = fs::read_to_string(&self.config).expect("read runtime configuration");
        parse_config(&source).expect("parse runtime configuration")
    }
}

impl Drop for StoreFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_directory(path: &Path, mode: u32) {
    fs::create_dir(path).expect("create protected directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("set protected directory mode");
}

fn private_stages(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .expect("read Managed root")
        .map(|entry| entry.expect("read Managed-root entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".whisper-stage-"))
        })
        .collect()
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex pair");
            u8::from_str_radix(pair, 16).expect("valid hex pair")
        })
        .collect()
}

#[test]
fn init_admission_creates_the_closed_store_and_empty_epochs() {
    let fixture = StoreFixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(
        output.status.success(),
        "init-admission failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut managed_names = fs::read_dir(fixture.database.parent().expect("Managed root"))
        .expect("read closed Managed root")
        .map(|entry| entry.expect("read Managed-root entry").file_name())
        .collect::<Vec<_>>();
    managed_names.sort();
    assert_eq!(
        managed_names,
        [".whisper.lease", "host.sqlite3"],
        "closed initialization must not retain staging, WAL, or SHM companions"
    );

    let connection = Connection::open(&fixture.database).expect("open initialized Store");
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .expect("application ID");
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("user version");
    assert_eq!(application_id, 0x5753_5044);
    assert_eq!(user_version, 1);

    let objects = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type IN ('table', 'index', 'view', 'trigger')
               AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .expect("prepare schema query")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query schema")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect schema objects");
    assert_eq!(
        objects,
        [
            "admission_epochs",
            "capability_epochs",
            "capture_sessions",
            "csi_by_link_time",
            "csi_observations",
            "packet_records",
            "packet_records_time",
            "store_state",
        ]
    );

    let (store_id_bytes, projection_commit_seq): (usize, Vec<u8>) = connection
        .query_row(
            "SELECT length(store_id), projection_commit_seq FROM store_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read Store state");
    assert_eq!(store_id_bytes, 32);
    assert_eq!(projection_commit_seq, [0; 8]);

    let epochs: Vec<AdmissionRow> = connection
        .prepare(
            "SELECT device_id, key_epoch, replay_window_size,
                        highest_boot_generation, maximum_message_sequence, seen_bitmap
                 FROM admission_epochs ORDER BY device_id, key_epoch",
        )
        .expect("prepare epoch query")
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
        })
        .expect("query admission epochs")
        .collect::<Result<_, _>>()
        .expect("collect admission epochs");
    assert_eq!(epochs.len(), 2);
    assert_eq!(epochs[0].0, 1_u64.to_be_bytes());
    assert_eq!(epochs[1].0, 2_u64.to_be_bytes());
    for epoch in epochs {
        assert_eq!(epoch.1, 1_u16.to_be_bytes());
        assert_eq!(epoch.2, 64);
        assert_eq!(epoch.3, None);
        assert_eq!(epoch.4, None);
        assert_eq!(epoch.5, [0; 8]);
    }
}

#[test]
fn init_admission_persists_imported_canonical_receipts() {
    const TOPOLOGY_HEX: &str = concat!(
        "a666736368656d61016a6465706c6f796d656e74636c6162667370616365738164726f6f6d",
        "6c7472616e736d697474657273826474782d616474782d626773656e736f727382a362696468",
        "73656e736f722d616d68617264776172655f6b696e646865737033322d733369646576696365",
        "5f696401a36269646873656e736f722d626d68617264776172655f6b696e646865737033322d",
        "7333696465766963655f696402656c696e6b7382a4626964666c696e6b2d6165737061636564",
        "726f6f6d6b7472616e736d69747465726474782d616872656365697665726873656e736f722d",
        "61a4626964666c696e6b2d6265737061636564726f6f6d6b7472616e736d6974746572647478",
        "2d626872656365697665726873656e736f722d62",
    );
    const TOPOLOGY_DIGEST_HEX: &str =
        "356ac42fb58403435d8aaf8443093e3063e1ef92162b11ea4101b37306e18e30";
    const ADMISSION_IDENTITIES: [&str; 2] = [
        "1a36dfbdf0b553e5494ec01dfeeec928d595bc0f2cea3e3c3fdd8d3f2d3ba606",
        "9673fe9ee066f20a2b4e6b73bf2a35f551e46289499a75932e36ee68af4ab226",
    ];

    let fixture = StoreFixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(
        output.status.success(),
        "init-admission failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let connection = Connection::open(&fixture.database).expect("open initialized Store");
    let (topology, topology_digest, replay, replay_digest): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
        connection
            .query_row(
                "SELECT topology_manifest_cbor, topology_manifest_digest,
                        replay_config_cbor, replay_config_digest
                 FROM store_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read immutable Store receipts");
    assert_eq!(topology, decode_hex(TOPOLOGY_HEX));
    assert_eq!(topology_digest, decode_hex(TOPOLOGY_DIGEST_HEX));
    assert_eq!(
        replay,
        decode_hex(include_str!("fixtures/config/replay-config-canonical.hex").trim())
    );
    assert_eq!(
        replay_digest,
        decode_hex(include_str!("fixtures/config/replay-config-canonical.sha256").trim())
    );

    let identities = connection
        .prepare(
            "SELECT replay_window_identity FROM admission_epochs ORDER BY device_id, key_epoch",
        )
        .expect("prepare admission identity query")
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query admission identities")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect admission identities");
    assert_eq!(
        identities,
        ADMISSION_IDENTITIES.map(decode_hex),
        "each configured route must use the imported D1 identity derivation"
    );
}

#[test]
fn serve_requires_an_existing_store_and_creates_one_empty_capture_session() {
    let fixture = StoreFixture::new();
    let config = fixture.parsed_config();
    let missing = whisper::serve(&config).expect_err("serve without a Store must fail");
    assert!(
        missing.to_string().contains(&fixture.database.display().to_string()),
        "managed I/O error omitted the failing Store path: {missing}"
    );
    assert!(!fixture.database.exists(), "serve must not create the configured Store");

    let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(
        initialized.status.success(),
        "init-admission failed: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let served = whisper::serve(&config).expect("serve initialized Store");
    drop(served);
    let served_again = whisper::serve(&config).expect("serve initialized Store again");
    drop(served_again);

    let connection = Connection::open(&fixture.database).expect("open served Store");
    let sessions = connection
        .prepare(
            "SELECT session_id, length(started_utc_ns), replay_config_digest,
                    decoder_version, conditioning_version, algorithm_version,
                    committed_through_record_seq, last_session_time_ns, projection_commit_seq
             FROM capture_sessions",
        )
        .expect("prepare Capture Session query")
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, usize>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Option<Vec<u8>>>(8)?,
            ))
        })
        .expect("query Capture Sessions")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect Capture Sessions");
    assert_eq!(sessions.len(), 2);
    assert_ne!(sessions[0].0, sessions[1].0);
    for session in sessions {
        assert_eq!(session.0.len(), "capture-".len() + 32);
        assert!(session.0.starts_with("capture-"));
        assert!(session.0["capture-".len()..].bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(session.1, 8);
        assert_eq!(session.2.len(), 32);
        assert_eq!(session.3, "native-frame-v1");
        assert_eq!(session.4, "amplitude-v1");
        assert_eq!(session.5, "native-coordinate-ingest-v1");
        assert_eq!(
            (session.6.as_ref(), session.7.as_ref(), session.8.as_ref()),
            (None, None, None)
        );
    }
    let watermark: Vec<u8> = connection
        .query_row("SELECT projection_commit_seq FROM store_state", [], |row| row.get(0))
        .expect("read Store watermark");
    assert_eq!(watermark, [0; 8]);
}

#[test]
fn serve_returns_committed_session_authority_and_retains_the_lifecycle_lease() {
    let fixture = StoreFixture::new();
    let config = fixture.parsed_config();
    whisper::init_admission(&config).expect("initialize Store");

    let session = whisper::serve(&config).expect("open first Capture Session");
    let connection = Connection::open(&fixture.database).expect("open served Store");
    let (store_id, session_count): (Vec<u8>, u64) = connection
        .query_row(
            "SELECT store_id, (SELECT count(*) FROM capture_sessions WHERE session_id = ?1)
             FROM store_state WHERE singleton = 1",
            [session.session_id()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read committed Session authority");
    assert_eq!(session.store_id().as_slice(), store_id);
    assert_eq!(session_count, 1);
    let first_elapsed = session.elapsed();
    assert!(session.elapsed() >= first_elapsed);

    let conflict = whisper::serve(&config).expect_err("second lifecycle lease must conflict");
    assert!(conflict.is_lease_conflict());
    drop(session);

    let _next =
        whisper::serve(&config).expect("open Capture Session after releasing lifecycle lease");
}

#[test]
fn serve_rejects_a_same_named_but_incompatible_schema_without_mutation() {
    let fixture = StoreFixture::new();
    let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(initialized.status.success());
    let connection = Connection::open(&fixture.database).expect("open Store for corruption");
    connection
        .execute_batch(
            "DROP INDEX csi_by_link_time;
             CREATE INDEX csi_by_link_time ON csi_observations(session_id, record_seq);",
        )
        .expect("replace required index with an incompatible same-named index");
    connection.close().expect("close corrupted Store");
    let before = fs::read(&fixture.database).expect("snapshot corrupted Store");

    let config = fixture.parsed_config();
    whisper::serve(&config).expect_err("serve accepted an incompatible same-named index");
    assert_eq!(fs::read(&fixture.database).expect("read rejected Store"), before);
    let connection = Connection::open(&fixture.database).expect("reopen rejected Store");
    let sessions: u64 = connection
        .query_row("SELECT count(*) FROM capture_sessions", [], |row| row.get(0))
        .expect("count Capture Sessions");
    assert_eq!(sessions, 0);
}

fn assert_serve_rejects_corruption(sql: &str) {
    let fixture = StoreFixture::new();
    let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(initialized.status.success());
    let connection = Connection::open(&fixture.database).expect("open Store for corruption");
    connection.execute_batch(sql).expect("apply Store corruption");
    connection.close().expect("close corrupted Store");
    let before = fs::read(&fixture.database).expect("snapshot corrupted Store");

    let config = fixture.parsed_config();
    assert!(whisper::serve(&config).is_err(), "serve accepted Store corruption from SQL: {sql}");
    assert_eq!(
        fs::read(&fixture.database).expect("read rejected Store"),
        before,
        "serve mutated rejected Store corruption from SQL: {sql}"
    );
}

#[test]
fn serve_rejects_incompatible_identity_schema_and_state_without_mutation() {
    for sql in [
        "PRAGMA application_id = 0;",
        "PRAGMA user_version = 2;",
        "CREATE TABLE unexpected(value INTEGER);",
        "DROP INDEX packet_records_time;",
        "UPDATE store_state SET topology_manifest_digest = zeroblob(32);",
        "UPDATE admission_epochs SET replay_window_size = 63, seen_bitmap = zeroblob(8)
         WHERE device_id = X'0000000000000001';",
        "UPDATE admission_epochs
         SET highest_boot_generation = X'00000001', maximum_message_sequence = zeroblob(8),
             seen_bitmap = X'0100000000000000'
         WHERE device_id = X'0000000000000001';",
        "UPDATE admission_epochs
         SET highest_boot_generation = X'00000001',
             maximum_message_sequence = X'0000000000000001', seen_bitmap = zeroblob(8)
         WHERE device_id = X'0000000000000001';",
    ] {
        assert_serve_rejects_corruption(sql);
    }
}

#[test]
fn managed_root_lease_and_final_trust_fail_closed() {
    let wrong_root = StoreFixture::new();
    let managed_root = wrong_root.database.parent().expect("Managed root");
    fs::set_permissions(managed_root, fs::Permissions::from_mode(0o755))
        .expect("weaken Managed-root mode");
    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", wrong_root.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(!output.status.success());
    assert!(!wrong_root.database.exists());
    assert!(private_stages(managed_root).is_empty());

    let wrong_lease = StoreFixture::new();
    let managed_root = wrong_lease.database.parent().expect("Managed root");
    let lease = managed_root.join(".whisper.lease");
    fs::write(&lease, []).expect("create untrusted lease");
    fs::set_permissions(&lease, fs::Permissions::from_mode(0o644)).expect("weaken lease mode");
    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", wrong_lease.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(!output.status.success());
    assert!(!wrong_lease.database.exists());
    assert!(private_stages(managed_root).is_empty());

    let conflict = StoreFixture::new();
    let managed_root = conflict.database.parent().expect("Managed root");
    let lease = managed_root.join(".whisper.lease");
    fs::write(&lease, []).expect("create trusted lease");
    fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).expect("protect lease");
    let lease_file = OpenOptions::new().read(true).write(true).open(&lease).expect("open lease");
    lease_file.try_lock().expect("hold lifecycle lease");
    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", conflict.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run competing init-admission");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already held"));
    assert!(!conflict.database.exists());
    assert!(private_stages(managed_root).is_empty());

    let occupied = StoreFixture::new();
    fs::write(&occupied.database, b"pre-existing final").expect("create occupied final");
    fs::set_permissions(&occupied.database, fs::Permissions::from_mode(0o600))
        .expect("protect occupied final");
    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", occupied.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission against occupied final");
    assert!(!output.status.success());
    assert_eq!(fs::read(&occupied.database).expect("read occupied final"), b"pre-existing final");
    assert!(private_stages(occupied.database.parent().expect("Managed root")).is_empty());

    let wrong_final = StoreFixture::new();
    let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", wrong_final.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(initialized.status.success());
    let store_bytes = fs::read(&wrong_final.database).expect("snapshot initialized Store");
    fs::set_permissions(&wrong_final.database, fs::Permissions::from_mode(0o644))
        .expect("weaken final mode");
    let config = wrong_final.parsed_config();
    assert!(whisper::serve(&config).is_err());
    assert_eq!(fs::read(&wrong_final.database).expect("read rejected final"), store_bytes);
    assert!(private_stages(wrong_final.database.parent().expect("Managed root")).is_empty());

    fs::set_permissions(&wrong_final.database, fs::Permissions::from_mode(0o600))
        .expect("restore final mode");
    let extra_link = wrong_final.database.with_file_name("extra-link.sqlite3");
    fs::hard_link(&wrong_final.database, &extra_link).expect("add untrusted final hard link");
    assert!(whisper::serve(&config).is_err());
    assert_eq!(fs::read(&wrong_final.database).expect("read hard-linked final"), store_bytes);

    let stale_companion = StoreFixture::new();
    let stale_wal = PathBuf::from(format!("{}-wal", stale_companion.database.display()));
    fs::write(&stale_wal, []).expect("create stale final WAL");
    fs::set_permissions(&stale_wal, fs::Permissions::from_mode(0o600))
        .expect("protect stale final WAL");
    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", stale_companion.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission against stale final WAL");
    assert!(!output.status.success());
    assert!(!stale_companion.database.exists());
    assert!(stale_wal.exists(), "initialization must not adopt or remove a stale companion");

    let wrong_companion = StoreFixture::new();
    let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", wrong_companion.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(initialized.status.success());
    let store_bytes = fs::read(&wrong_companion.database).expect("snapshot initialized Store");
    let wal = PathBuf::from(format!("{}-wal", wrong_companion.database.display()));
    fs::write(&wal, []).expect("create untrusted final WAL");
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o644)).expect("weaken final WAL mode");
    let config = wrong_companion.parsed_config();
    assert!(whisper::serve(&config).is_err());
    assert_eq!(fs::read(&wrong_companion.database).expect("read rejected Store"), store_bytes);
}

fn assert_failed_initialization_has_no_store_or_stage(fixture: &StoreFixture) {
    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run rejected init-admission");
    assert!(!output.status.success());
    assert!(!fixture.database.exists());
    assert!(private_stages(fixture.database.parent().expect("Managed root")).is_empty());
}

#[test]
fn init_admission_loads_every_route_key_and_rejects_invalid_epoch_material() {
    let missing = StoreFixture::new();
    fs::remove_file(missing.root.join("secrets/device-2/key-1.bin")).expect("remove route key");
    assert_failed_initialization_has_no_store_or_stage(&missing);

    let advanced = StoreFixture::new();
    fs::rename(
        advanced.root.join("secrets/device-1/key-1.bin"),
        advanced.root.join("secrets/device-1/key-2.bin"),
    )
    .expect("advance route key");
    assert_failed_initialization_has_no_store_or_stage(&advanced);

    let wrong_size = StoreFixture::new();
    fs::write(wrong_size.root.join("secrets/device-1/key-1.bin"), [0x11; 31])
        .expect("truncate route key");
    assert_failed_initialization_has_no_store_or_stage(&wrong_size);

    let duplicate = StoreFixture::new();
    let source = fs::read_to_string(&duplicate.config).expect("read runtime configuration");
    fs::write(
        &duplicate.config,
        format!(
            "{source}\n[[routes]]\npeer = \"192.0.2.10\"\ndevice_id = 1\nkey_epoch = 1\nlink = \"link-a\"\npeak_packets_per_second = 100\nmaximum_valid_datagram_bytes = 2048\nmaximum_authenticated_bytes_per_second = 204800\nreplay_window_packets = 64\n"
        ),
    )
    .expect("duplicate route");
    assert_failed_initialization_has_no_store_or_stage(&duplicate);
}

#[test]
fn serve_rederives_every_route_epoch_without_repairing_conflicts() {
    for mutation in ["missing", "changed", "advanced"] {
        let fixture = StoreFixture::new();
        let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
            .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
            .output()
            .expect("run init-admission");
        assert!(initialized.status.success());
        let key = fixture.root.join("secrets/device-1/key-1.bin");
        match mutation {
            "missing" => fs::remove_file(&key).expect("remove route key"),
            "changed" => fs::write(&key, [0x33; 32]).expect("change route key"),
            "advanced" => {
                fs::rename(&key, key.with_file_name("key-2.bin")).expect("advance route key")
            }
            _ => unreachable!("test mutation is exhaustive"),
        }
        let before = fs::read(&fixture.database).expect("snapshot initialized Store");
        let config = fixture.parsed_config();
        assert!(whisper::serve(&config).is_err(), "serve accepted {mutation} epoch material");
        assert_eq!(fs::read(&fixture.database).expect("read rejected Store"), before);
    }
}

#[test]
fn serve_writer_uses_a_zero_busy_timeout() {
    let fixture = StoreFixture::new();
    let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(initialized.status.success());
    let lock = Connection::open(&fixture.database).expect("open competing SQLite writer");
    lock.execute_batch("BEGIN IMMEDIATE").expect("hold SQLite writer transaction");

    let config = fixture.parsed_config();
    let error = whisper::serve(&config).expect_err("serve accepted a blocked writer");
    assert!(
        error.to_string().contains("database is locked"),
        "writer conflict did not retain SQLite's lock classification: {error}"
    );
    lock.execute_batch("ROLLBACK").expect("release SQLite writer transaction");
    let sessions: u64 = lock
        .query_row("SELECT count(*) FROM capture_sessions", [], |row| row.get(0))
        .expect("count Capture Sessions");
    assert_eq!(sessions, 0);
}

#[test]
fn serve_preserves_valid_advanced_replay_state() {
    let fixture = StoreFixture::new();
    let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(initialized.status.success());
    let connection = Connection::open(&fixture.database).expect("open Store");
    connection
        .execute(
            "UPDATE admission_epochs
             SET highest_boot_generation = ?1, maximum_message_sequence = ?2, seen_bitmap = ?3
             WHERE device_id = ?4 AND key_epoch = ?5",
            rusqlite::params![
                7_u32.to_be_bytes(),
                42_u64.to_be_bytes(),
                [0x81_u8, 0, 0, 0, 0, 0, 0, 0],
                1_u64.to_be_bytes(),
                1_u16.to_be_bytes(),
            ],
        )
        .expect("advance valid replay state");
    connection.close().expect("close advanced Store");

    let config = fixture.parsed_config();
    let served = whisper::serve(&config).expect("serve advanced replay state");
    drop(served);
    let connection = Connection::open(&fixture.database).expect("reopen Store");
    let replay_state: (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT highest_boot_generation, maximum_message_sequence, seen_bitmap
             FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
            rusqlite::params![1_u64.to_be_bytes(), 1_u16.to_be_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read preserved replay state");
    assert_eq!(
        replay_state,
        (
            7_u32.to_be_bytes().to_vec(),
            42_u64.to_be_bytes().to_vec(),
            vec![0x81, 0, 0, 0, 0, 0, 0, 0]
        )
    );
    let sessions: u64 = connection
        .query_row("SELECT count(*) FROM capture_sessions", [], |row| row.get(0))
        .expect("count Capture Sessions");
    assert_eq!(sessions, 1);
}

#[test]
fn serve_preserves_an_advanced_store_watermark_and_starts_a_fresh_session() {
    let fixture = StoreFixture::new();
    let initialized = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["init-admission", fixture.config.to_str().expect("UTF-8 config path")])
        .output()
        .expect("run init-admission");
    assert!(initialized.status.success());
    let config = fixture.parsed_config();
    let first_serve = whisper::serve(&config).expect("serve initialized Store");
    drop(first_serve);
    let connection = Connection::open(&fixture.database).expect("open Store");
    let first_session: String = connection
        .query_row("SELECT session_id FROM capture_sessions", [], |row| row.get(0))
        .expect("read first Capture Session");
    connection
        .execute(
            "UPDATE capture_sessions
             SET committed_through_record_seq = ?1, last_session_time_ns = ?2,
                 projection_commit_seq = ?3
             WHERE session_id = ?4",
            rusqlite::params![
                1_u64.to_be_bytes(),
                10_u64.to_be_bytes(),
                1_u64.to_be_bytes(),
                first_session,
            ],
        )
        .expect("make first Capture Session visible");
    connection
        .execute(
            "UPDATE store_state SET projection_commit_seq = ?1",
            rusqlite::params![1_u64.to_be_bytes()],
        )
        .expect("advance Store watermark");
    connection.close().expect("close advanced Store");

    let second_serve = whisper::serve(&config).expect("serve valid advanced Store state");
    drop(second_serve);
    let connection = Connection::open(&fixture.database).expect("reopen Store");
    let watermark: Vec<u8> = connection
        .query_row("SELECT projection_commit_seq FROM store_state", [], |row| row.get(0))
        .expect("read preserved Store watermark");
    assert_eq!(watermark, 1_u64.to_be_bytes());
    let sessions: u64 = connection
        .query_row("SELECT count(*) FROM capture_sessions", [], |row| row.get(0))
        .expect("count Capture Sessions");
    assert_eq!(sessions, 2);
}
