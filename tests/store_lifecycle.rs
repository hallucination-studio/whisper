//! Store lifecycle behavior at the public persistence seam.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use whisper::Store;

#[test]
fn explicitly_initialized_store_reopens_with_the_same_identity() {
    let parent = temporary_directory("store-reopen");
    let root = parent.join("world-store");

    let initialized = Store::initialize(&root).expect("absent Store root initializes");
    let store_id = initialized.id();
    drop(initialized);

    let reopened = Store::open(&root).expect("initialized Store reopens");
    assert_eq!(reopened.id(), store_id);

    drop(reopened);
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[test]
fn initialization_rejects_an_existing_target_without_changing_its_bytes() {
    let parent = temporary_directory("store-existing");
    let root = parent.join("world-store");
    fs::create_dir(&root).expect("existing target created");
    let files = [
        ("legacy.sqlite3", b"old-schema-bytes".as_slice()),
        ("legacy.sqlite3-wal", b"old-wal-bytes".as_slice()),
        ("legacy.sqlite3-shm", b"old-shm-bytes".as_slice()),
        ("operator-note", b"preserve this too".as_slice()),
    ];
    for (name, bytes) in files {
        fs::write(root.join(name), bytes).expect("existing byte fixture written");
    }
    let before = snapshot(&root);

    let error = Store::initialize(&root).expect_err("existing target must not initialize");
    assert!(error.is_existing_target());
    assert_eq!(snapshot(&root), before);

    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[cfg(unix)]
#[test]
fn opening_an_old_or_corrupt_store_preserves_database_and_companion_bytes() {
    let parent = temporary_directory("store-old-format");
    let root = parent.join("world-store");
    fs::create_dir(&root).expect("old Store root created");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("old Store root mode set");
    let files = [
        ("facts.sqlite3", b"old-or-corrupt-database".as_slice()),
        ("facts.sqlite3-wal", b"old-wal-bytes".as_slice()),
        ("facts.sqlite3-shm", b"old-shm-bytes".as_slice()),
        ("operator-note", b"preserve this too".as_slice()),
    ];
    for (name, bytes) in files {
        let path = root.join(name);
        fs::write(&path, bytes).expect("old Store byte fixture written");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("old Store file mode set");
    }
    let before = snapshot(&root);

    let error = Store::open(&root).expect_err("old or corrupt Store must not open");
    assert!(error.is_unrecognized_format());
    assert_eq!(snapshot(&root), before);

    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[cfg(unix)]
#[test]
fn opening_a_legacy_sqlite_store_preserves_live_wal_shm_and_side_files() {
    let parent = temporary_directory("store-legacy-sqlite");
    let root = parent.join("world-store");
    fs::create_dir(&root).expect("legacy Store root created");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let database_path = root.join("facts.sqlite3");
    let legacy = rusqlite::Connection::open(&database_path).expect("legacy database opens");
    fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600)).unwrap();
    legacy
        .execute_batch(
            "PRAGMA journal_mode=WAL;
         CREATE TABLE sessions (session_id TEXT PRIMARY KEY, projection BLOB);
         INSERT INTO sessions VALUES ('old-session', x'01020304');",
        )
        .expect("legacy WAL transaction commits");
    fs::write(root.join("operator-note"), b"preserve this too").unwrap();
    assert!(root.join("facts.sqlite3-wal").exists());
    assert!(root.join("facts.sqlite3-shm").exists());
    let before = snapshot(&root);

    let error = Store::open(&root).expect_err("legacy SQLite schema must not open");
    assert!(error.is_unrecognized_format());
    assert_eq!(snapshot(&root), before);

    drop(legacy);
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[cfg(unix)]
#[test]
fn legitimate_new_store_wal_and_shm_are_not_mistaken_for_a_legacy_store() {
    let parent = temporary_directory("store-own-wal");
    let root = parent.join("world-store");
    let initialized = Store::initialize(&root).unwrap();
    let store_id = initialized.id();
    drop(initialized);
    let database_path = root.join("facts.sqlite3");
    let writer = rusqlite::Connection::open(&database_path).expect("new Store database opens");
    writer
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             INSERT INTO raw_losses (observed_utc_ns, kind, count)
             VALUES (1, 'ingress_queue_overflow', 1);",
        )
        .expect("new Store WAL transaction commits");
    assert!(root.join("facts.sqlite3-wal").exists());
    assert!(root.join("facts.sqlite3-shm").exists());

    let reopened = Store::open(&root).expect("new Store with its own companions reopens");
    assert_eq!(reopened.id(), store_id);

    drop(reopened);
    drop(writer);
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[cfg(unix)]
#[test]
fn checkpoint_truncated_zero_byte_wal_with_live_shm_reopens_read_only() {
    let parent = temporary_directory("store-truncated-wal");
    let root = parent.join("world-store");
    let initialized = Store::initialize(&root).unwrap();
    let store_id = initialized.id();
    drop(initialized);
    let database_path = root.join("facts.sqlite3");
    let writer = rusqlite::Connection::open(&database_path).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    let wal = root.join("facts.sqlite3-wal");
    let shm = root.join("facts.sqlite3-shm");
    assert_eq!(fs::metadata(&wal).unwrap().len(), 0);
    assert!(shm.exists());
    let before = snapshot(&root);

    let reopened = Store::open(&root).expect("SQLite's empty-WAL/live-SHM state is valid");
    assert_eq!(reopened.id(), store_id);
    assert_eq!(snapshot(&root), before);

    drop(reopened);
    drop(writer);
    fs::remove_dir_all(parent).unwrap();
}

#[cfg(unix)]
#[test]
fn wal_schema_objects_and_header_pragmas_are_validated_without_target_writes() {
    for (label, mutation) in [
        ("application-id", "PRAGMA application_id=1;"),
        ("user-version", "PRAGMA user_version=3;"),
        ("view", "CREATE VIEW unexpected_facts AS SELECT * FROM raw_facts;"),
        (
            "trigger",
            "CREATE TRIGGER unexpected_loss AFTER INSERT ON raw_losses BEGIN SELECT 1; END;",
        ),
        (
            "sqlite-sequence",
            "CREATE TABLE transient_rowid (id INTEGER PRIMARY KEY AUTOINCREMENT); DROP TABLE transient_rowid;",
        ),
    ] {
        let parent = temporary_directory(&format!("store-wal-schema-{label}"));
        let root = parent.join("world-store");
        drop(Store::initialize(&root).unwrap());
        let database_path = root.join("facts.sqlite3");
        let writer = rusqlite::Connection::open(&database_path).unwrap();
        writer.execute_batch(&format!("PRAGMA journal_mode=WAL; {mutation}")).unwrap();
        assert!(root.join("facts.sqlite3-wal").exists());
        let before = snapshot(&root);

        let error = Store::open(&root).expect_err(label);
        assert!(error.is_unrecognized_format(), "mutation {label} was not rejected as schema");
        assert_eq!(snapshot(&root), before, "mutation {label} changed target bytes");

        drop(writer);
        fs::remove_dir_all(parent).unwrap();
    }
}

#[test]
fn store_lease_allows_only_one_cooperative_owner() {
    let parent = temporary_directory("store-lease");
    let root = parent.join("world-store");
    let first = Store::initialize(&root).unwrap();

    let error = Store::open(&root).expect_err("second Store owner must be rejected");
    assert!(error.is_lease_conflict());

    drop(first);
    let second = Store::open(&root).expect("released Store lease can be reacquired");
    drop(second);
    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[test]
fn store_with_matching_identity_header_but_corrupt_schema_is_rejected_without_writes() {
    let parent = temporary_directory("store-corrupt-schema");
    let root = parent.join("world-store");
    let store = Store::initialize(&root).unwrap();
    drop(store);
    let database_path = root.join("facts.sqlite3");
    let database = fs::read(&database_path).expect("initialized database readable");
    fs::write(&database_path, &database[..200]).expect("database truncated after its header");
    let before = snapshot(&root);

    let error = Store::open(&root).expect_err("corrupt recognized Store must not open");
    assert!(error.is_unrecognized_format());
    assert_eq!(snapshot(&root), before);

    fs::remove_dir_all(parent).expect("temporary Store removed");
}

#[cfg(unix)]
#[test]
fn spoofed_schema_with_matching_header_and_table_names_is_rejected_without_writes() {
    let parent = temporary_directory("store-spoof-schema");
    let root = parent.join("world-store");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let database_path = root.join("facts.sqlite3");
    let database = rusqlite::Connection::open(&database_path).unwrap();
    database
        .execute_batch(
            "PRAGMA application_id = 1465009713;
             PRAGMA user_version = 1;
             CREATE TABLE store_identity(singleton INTEGER PRIMARY KEY, store_id BLOB);
             INSERT INTO store_identity VALUES (1, zeroblob(16));
             CREATE TABLE replay_windows(identity BLOB);
             CREATE TABLE raw_facts(datagram BLOB);
             CREATE TABLE raw_losses(kind TEXT);",
        )
        .unwrap();
    drop(database);
    fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600)).unwrap();
    let lease = root.join(".whisper.lease");
    fs::write(&lease, []).unwrap();
    fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).unwrap();
    let before = snapshot(&root);

    let error = Store::open(&root).expect_err("same names cannot spoof exact schema recognition");
    assert!(error.is_unrecognized_format());
    assert_eq!(snapshot(&root), before);

    fs::remove_dir_all(parent).unwrap();
}

#[cfg(unix)]
#[test]
fn corrupt_wal_companion_is_rejected_without_changing_any_store_bytes() {
    let parent = temporary_directory("store-corrupt-wal");
    let root = parent.join("world-store");
    drop(Store::initialize(&root).unwrap());
    let wal = root.join("facts.sqlite3-wal");
    fs::write(&wal, b"not a sqlite wal").unwrap();
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o600)).unwrap();
    let before = snapshot(&root);

    let error = Store::open(&root).expect_err("corrupt WAL cannot reach a target SQLite open");
    assert!(error.is_unrecognized_format());
    assert_eq!(snapshot(&root), before);

    fs::remove_dir_all(parent).unwrap();
}

#[cfg(unix)]
#[test]
fn orphaned_shm_companion_is_rejected_without_changing_any_store_bytes() {
    let parent = temporary_directory("store-orphan-shm");
    let root = parent.join("world-store");
    drop(Store::initialize(&root).unwrap());
    let shm = root.join("facts.sqlite3-shm");
    fs::write(&shm, vec![0_u8; 32_768]).unwrap();
    fs::set_permissions(&shm, fs::Permissions::from_mode(0o600)).unwrap();
    let before = snapshot(&root);

    let error = Store::open(&root).expect_err("orphaned SHM cannot reach a target SQLite open");
    assert!(error.is_unrecognized_format());
    assert_eq!(snapshot(&root), before);

    fs::remove_dir_all(parent).unwrap();
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

fn snapshot(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut entries = fs::read_dir(root)
        .expect("snapshot root readable")
        .map(|entry| {
            let entry = entry.expect("snapshot entry readable");
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path()).expect("snapshot file readable");
            (name, bytes)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}
