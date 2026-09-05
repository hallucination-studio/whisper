use sha2::{Digest, Sha256};

use crate::key::EpochKey;
use crate::native_csi::{CsiPath, SampleAxis};
use crate::native_frame::{Message, open_datagram};
use crate::replay::{ReplayAdmission, ReplayDecision, derive_replay_window_identity};

const KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

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

#[test]
fn frozen_native_frame_authenticates_and_preserves_native_csi() {
    let bytes = hex_fixture(include_str!(
        "../tests/fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex"
    ));
    let datagram = open_datagram(&KEY, &bytes).expect("fixed authenticated datagram");
    let Message::CsiData(data) = datagram.message() else {
        panic!("fixed datagram must contain CSI")
    };

    assert_eq!(datagram.header().boot_generation(), 9);
    assert_eq!(datagram.header().message_seq(), 13);
    assert_eq!(data.capture_sequence(), 31);
    assert_eq!(data.raw_csi(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa5, 0x5a]);
    assert_eq!(data.first_invalid_bytes(), 4);
    assert_eq!(data.trailing_invalid_bytes(), 2);
    let native = data.native_csi();
    assert_eq!(native.path(), CsiPath::RawPathOrdinal(0));
    assert_eq!(native.sample_axis(), SampleAxis::OpaqueOrdinal { count: 5 });
    assert_eq!(native.samples().len(), 5);
    assert!(!native.samples()[0].valid);
    assert!(!native.samples()[1].valid);
}

#[test]
fn replay_identity_matches_the_cross_language_fixed_vector() {
    let vector = include_str!("../tests/fixtures/replay-window-identity/vector-v1.txt");
    assert!(vector.contains(
        "identity_sha256=e4b92906e619e0e4d87341976f505653b4e72960add36686a2c17444865f7fa4"
    ));
    let key = EpochKey::try_from(KEY.as_slice()).expect("32-byte epoch key");
    let identity = derive_replay_window_identity("lab", 1, 1, &key).expect("bounded deployment");
    assert_eq!(
        identity.as_bytes(),
        hex_fixture("e4b92906e619e0e4d87341976f505653b4e72960add36686a2c17444865f7fa4").as_slice()
    );
    let changed = EpochKey::try_from(
        hex_fixture("ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").as_slice(),
    )
    .expect("32-byte changed key");
    assert_ne!(identity, derive_replay_window_identity("lab", 1, 1, &changed).unwrap());
}

#[test]
fn replay_state_survives_restart_and_rejects_replays() {
    let mut replay = ReplayAdmission::new(4).expect("non-zero bounded window");
    assert_eq!(replay.admit(7, 10), ReplayDecision::Accepted);
    assert_eq!(replay.admit(7, 8), ReplayDecision::Accepted);

    let persisted = replay.encode_state();
    let mut restarted = ReplayAdmission::decode_state(&persisted).expect("valid durable state");
    assert!(ReplayAdmission::decode_state(&persisted[..persisted.len() - 1]).is_err());
    let mut oversized = persisted.to_vec();
    oversized.resize(1024 * 1024, 0);
    assert!(ReplayAdmission::decode_state(&oversized).is_err());
    assert_eq!(restarted.admit(7, 8), ReplayDecision::Rejected);
    assert_eq!(restarted.admit(7, 6), ReplayDecision::Rejected);
    assert_eq!(restarted.admit(8, 1), ReplayDecision::Accepted);
    assert_eq!(restarted.admit(7, 11), ReplayDecision::Rejected);
}

#[test]
fn epoch_key_requires_exact_bytes_and_redacts_debug_output() {
    let key = EpochKey::try_from(KEY.as_slice()).expect("32-byte epoch key");
    assert_eq!(key.as_bytes(), &KEY);
    assert_eq!(format!("{key:?}"), "EpochKey([REDACTED])");
    assert!(EpochKey::try_from(&KEY[..31]).is_err());
}

#[cfg(unix)]
mod secret_store {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::key::{SecretStoreError, load_epoch_key, load_epoch_key_with_after_read};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    fn root_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-rf01-key-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn create_directory(path: &Path) {
        fs::create_dir(path).expect("create key directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("set key directory mode");
    }

    fn write_key(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create key file");
        file.write_all(bytes).expect("write key file");
    }

    fn valid_store() -> (PathBuf, PathBuf, PathBuf) {
        let root = root_path();
        let device = root.join("device-7");
        let key = device.join("key-3.bin");
        create_directory(&root);
        create_directory(&device);
        write_key(&key, &[0xa5; 32]);
        (root, device, key)
    }

    #[test]
    fn loader_selects_exact_device_epoch_and_redacts_diagnostics() {
        let (root, device, _) = valid_store();
        let key = load_epoch_key(&root, 7, 3).expect("trusted exact key");
        assert_eq!(key.as_bytes(), &[0xa5; 32]);
        assert!(matches!(load_epoch_key(&root, 8, 3), Err(SecretStoreError::Missing { .. })));
        assert!(matches!(load_epoch_key(&root, 7, 0), Err(SecretStoreError::ZeroKeyEpoch { .. })));
        assert!(matches!(load_epoch_key(&root, 7, 2), Err(SecretStoreError::WrongEpoch { .. })));

        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let error = load_epoch_key(&root, 7, 3).expect_err("untrusted root mode");
        let diagnostic = format!("{error:?}\n{error}");
        assert!(!diagnostic.contains(root.to_string_lossy().as_ref()));
        assert!(!diagnostic.contains(&"a5".repeat(32)));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root).unwrap();
        let _ = device;
    }

    #[test]
    fn loader_rejects_symlinks_hardlinks_modes_and_lengths() {
        let (root, device, key) = valid_store();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_epoch_key(&root, 7, 3),
            Err(SecretStoreError::UntrustedKeyFile { .. })
        ));
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();

        let hardlink = device.join("hardlink.bin");
        fs::hard_link(&key, &hardlink).unwrap();
        assert!(matches!(
            load_epoch_key(&root, 7, 3),
            Err(SecretStoreError::UntrustedKeyFile { .. })
        ));
        fs::remove_file(hardlink).unwrap();

        let real_key = device.join("real-key.bin");
        fs::rename(&key, &real_key).unwrap();
        symlink(&real_key, &key).unwrap();
        assert!(matches!(
            load_epoch_key(&root, 7, 3),
            Err(SecretStoreError::UntrustedKeyFile { .. })
        ));
        fs::remove_file(&key).unwrap();
        fs::rename(&real_key, &key).unwrap();
        fs::write(&key, [0xa5; 31]).unwrap();
        assert!(matches!(load_epoch_key(&root, 7, 3), Err(SecretStoreError::WrongLength { .. })));
        fs::remove_dir_all(root).unwrap();

        let (root, device, _) = valid_store();
        let alias = root.with_extension("alias");
        symlink(&root, &alias).unwrap();
        assert!(matches!(
            load_epoch_key(&alias, 7, 3),
            Err(SecretStoreError::UntrustedRoot { .. })
        ));
        fs::remove_file(alias).unwrap();
        let real_device = root.join("real-device");
        fs::rename(&device, &real_device).unwrap();
        symlink(&real_device, &device).unwrap();
        assert!(matches!(
            load_epoch_key(&root, 7, 3),
            Err(SecretStoreError::UntrustedDeviceDirectory { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loader_detects_key_replacement_during_read() {
        let (root, device, key) = valid_store();
        let result = load_epoch_key_with_after_read(&root, 7, 3, || {
            fs::rename(&key, device.join("removed-key.bin")).unwrap();
            write_key(&key, &[0xa5; 32]);
        });
        assert!(matches!(result, Err(SecretStoreError::Replaced { object: "key file", .. })));
        fs::remove_dir_all(root).unwrap();

        let (root, device, _) = valid_store();
        let removed = root.with_extension("removed");
        let result = load_epoch_key_with_after_read(&root, 7, 3, || {
            fs::rename(&root, &removed).unwrap();
            create_directory(&root);
            let replacement_device = root.join("device-7");
            create_directory(&replacement_device);
            write_key(&replacement_device.join("key-3.bin"), &[0xa5; 32]);
        });
        assert!(matches!(result, Err(SecretStoreError::Replaced { object: "secret root", .. })));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(removed).unwrap();
        let _ = device;

        let (root, device, _) = valid_store();
        let removed = root.join("removed-device");
        let result = load_epoch_key_with_after_read(&root, 7, 3, || {
            fs::rename(&device, &removed).unwrap();
            create_directory(&device);
            write_key(&device.join("key-3.bin"), &[0xa5; 32]);
        });
        assert!(matches!(
            result,
            Err(SecretStoreError::Replaced { object: "device directory", .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn fixed_firmware_source_digest_is_unchanged() {
    const FILES: &[(&str, &[u8])] = &[
        (
            "firmware/esp32-native-frame/CMakeLists.txt",
            include_bytes!("../firmware/esp32-native-frame/CMakeLists.txt"),
        ),
        (
            "firmware/esp32-native-frame/build_capability_facts.py",
            include_bytes!("../firmware/esp32-native-frame/build_capability_facts.py"),
        ),
        (
            "firmware/esp32-native-frame/main/CMakeLists.txt",
            include_bytes!("../firmware/esp32-native-frame/main/CMakeLists.txt"),
        ),
        (
            "firmware/esp32-native-frame/main/csi_capture_v1.c",
            include_bytes!("../firmware/esp32-native-frame/main/csi_capture_v1.c"),
        ),
        (
            "firmware/esp32-native-frame/main/csi_capture_v1.h",
            include_bytes!("../firmware/esp32-native-frame/main/csi_capture_v1.h"),
        ),
        (
            "firmware/esp32-native-frame/main/main.c",
            include_bytes!("../firmware/esp32-native-frame/main/main.c"),
        ),
        (
            "firmware/esp32-native-frame/main/native_frame_v1.c",
            include_bytes!("../firmware/esp32-native-frame/main/native_frame_v1.c"),
        ),
        (
            "firmware/esp32-native-frame/main/native_frame_v1.h",
            include_bytes!("../firmware/esp32-native-frame/main/native_frame_v1.h"),
        ),
        (
            "firmware/esp32-native-frame/main/provisioning_v1.c",
            include_bytes!("../firmware/esp32-native-frame/main/provisioning_v1.c"),
        ),
        (
            "firmware/esp32-native-frame/main/provisioning_v1.h",
            include_bytes!("../firmware/esp32-native-frame/main/provisioning_v1.h"),
        ),
        (
            "firmware/esp32-native-frame/main/sender_v1.c",
            include_bytes!("../firmware/esp32-native-frame/main/sender_v1.c"),
        ),
        (
            "firmware/esp32-native-frame/main/sender_v1.h",
            include_bytes!("../firmware/esp32-native-frame/main/sender_v1.h"),
        ),
        (
            "firmware/esp32-native-frame/partitions.csv",
            include_bytes!("../firmware/esp32-native-frame/partitions.csv"),
        ),
        (
            "firmware/esp32-native-frame/sdkconfig.defaults",
            include_bytes!("../firmware/esp32-native-frame/sdkconfig.defaults"),
        ),
    ];
    let mut digest = Sha256::new();
    for (path, bytes) in FILES {
        digest.update(u64::try_from(path.len()).expect("path length fits u64").to_be_bytes());
        digest.update(path.as_bytes());
        digest.update(u64::try_from(bytes.len()).expect("file length fits u64").to_be_bytes());
        digest.update(bytes);
    }
    assert_eq!(
        format!("{:x}", digest.finalize()),
        "936b64891faa7c784ecad289c9fb5eeaaf4d5694aaf39c99b03c359cbd2544fd"
    );
}
