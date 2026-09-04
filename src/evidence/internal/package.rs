use super::*;

pub(super) fn read_package(
    root: &Path,
    mode: ReadMode,
) -> Result<BTreeMap<String, ReadArtifact>, EvidenceError> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|source| EvidenceError::Io { path: root.to_path_buf(), source })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(EvidenceError::FileSet);
    }
    let mut files = BTreeMap::new();
    let mut budget = ReadBudget::default();
    walk(root, root, mode, &mut files, &mut budget)?;
    Ok(files)
}

pub(super) fn read_unsealed_artifact(
    path: &Path,
    budget: &mut ReadBudget,
) -> Result<ReadArtifact, EvidenceError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| EvidenceError::Io { path: path.to_path_buf(), source })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(EvidenceError::Artifact("unsealed artifact".to_owned()));
    }
    let relative = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| EvidenceError::Path("unsealed artifact".to_owned()))?;
    budget.include(relative, metadata.len())?;
    read_regular_file(path, relative, &metadata, false)
}

pub(super) fn walk(
    root: &Path,
    directory: &Path,
    mode: ReadMode,
    files: &mut BTreeMap<String, ReadArtifact>,
    budget: &mut ReadBudget,
) -> Result<(), EvidenceError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| EvidenceError::Io { path: directory.to_path_buf(), source })?;
    for entry in entries {
        let entry =
            entry.map_err(|source| EvidenceError::Io { path: directory.to_path_buf(), source })?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| EvidenceError::FileSet)?
            .to_str()
            .ok_or_else(|| EvidenceError::Path("non-UTF-8 path".to_owned()))?
            .to_owned();
        validate_relative_path(&relative)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| EvidenceError::Io { path: path.clone(), source })?;
        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::Artifact(relative));
        }
        if metadata.is_dir() {
            if !matches!(relative.as_str(), "datagrams" | "http" | "screenshots") {
                return Err(EvidenceError::FileSet);
            }
            if mode.requires_readonly_directory(&relative) && file_mode(&metadata) & 0o222 != 0 {
                return Err(EvidenceError::Artifact(relative));
            }
            walk(root, &path, mode, files, budget)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(EvidenceError::Artifact(relative));
        }
        budget.include(&relative, metadata.len())?;
        let artifact =
            read_regular_file(&path, &relative, &metadata, mode.requires_readonly(&relative))?;
        if files.insert(relative.clone(), artifact).is_some() {
            return Err(EvidenceError::Artifact(relative));
        }
    }
    Ok(())
}

pub(super) fn read_regular_file(
    path: &Path,
    relative: &str,
    before: &fs::Metadata,
    require_readonly: bool,
) -> Result<ReadArtifact, EvidenceError> {
    let before = file_identity(before);
    if before.links != 1 || (require_readonly && before.mode & 0o222 != 0) {
        return Err(EvidenceError::Artifact(relative.to_owned()));
    }
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|source| EvidenceError::Io { path: path.to_path_buf(), source })?;
    let opened =
        file.metadata().map_err(|source| EvidenceError::Io { path: path.to_path_buf(), source })?;
    if file_identity(&opened) != before {
        return Err(EvidenceError::Changed(relative.to_owned()));
    }
    let capacity =
        usize::try_from(before.size).map_err(|_| EvidenceError::ByteBound(relative.to_owned()))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| EvidenceError::ByteBound(relative.to_owned()))?;
    Read::by_ref(&mut file)
        .take(before.size + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| EvidenceError::Io { path: path.to_path_buf(), source })?;
    let after = fs::symlink_metadata(path)
        .map_err(|source| EvidenceError::Io { path: path.to_path_buf(), source })?;
    if file_identity(&after) != before || u64::try_from(bytes.len()).ok() != Some(before.size) {
        return Err(EvidenceError::Changed(relative.to_owned()));
    }
    Ok(ReadArtifact { identity: before, digest: sha256(&bytes), bytes })
}

#[cfg(unix)]
pub(super) fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
pub(super) fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
pub(super) fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

#[cfg(not(unix))]
pub(super) fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: 0,
        links: 1,
        mode: 0,
        size: metadata.len(),
        modified_seconds: 0,
        modified_nanoseconds: 0,
    }
}

pub(super) fn validate_relative_path(path: &str) -> Result<(), EvidenceError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(EvidenceError::Path(path.to_owned()));
    }
    let parsed = Path::new(path);
    if parsed.components().any(|component| !matches!(component, Component::Normal(_))) {
        return Err(EvidenceError::Path(path.to_owned()));
    }
    Ok(())
}

pub(super) fn parse_canonical_json<T>(path: &str, bytes: &[u8]) -> Result<T, EvidenceError>
where
    T: for<'de> Deserialize<'de>,
{
    let value: JsonValue =
        serde_json::from_slice(bytes).map_err(|_| EvidenceError::Json(path.to_owned()))?;
    if canonical_json(&value)? != bytes {
        return Err(EvidenceError::Json(path.to_owned()));
    }
    serde_json::from_value(value).map_err(|_| EvidenceError::Json(path.to_owned()))
}

pub(super) fn canonical_json(value: &JsonValue) -> Result<Vec<u8>, EvidenceError> {
    let mut bytes = Vec::new();
    write_json(value, &mut bytes)?;
    Ok(bytes)
}

pub(super) fn write_json(value: &JsonValue, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
    match value {
        JsonValue::Null => output.extend_from_slice(b"null"),
        JsonValue::Bool(true) => output.extend_from_slice(b"true"),
        JsonValue::Bool(false) => output.extend_from_slice(b"false"),
        JsonValue::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                return Err(EvidenceError::Json("floating-point number".to_owned()));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        JsonValue::String(text) => {
            serde_json::to_writer(output, text)
                .map_err(|_| EvidenceError::Json("string".to_owned()))?;
        }
        JsonValue::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_json(item, output)?;
            }
            output.push(b']');
        }
        JsonValue::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| utf16_cmp(left, right));
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|_| EvidenceError::Json("object key".to_owned()))?;
                output.push(b':');
                write_json(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub(super) fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

pub(super) fn validate_canonical_cbor(path: &str, bytes: &[u8]) -> Result<(), EvidenceError> {
    let mut cursor = Cursor::new(bytes);
    let value: CborValue =
        ciborium::from_reader(&mut cursor).map_err(|_| EvidenceError::Cbor(path.to_owned()))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(EvidenceError::Cbor(path.to_owned()));
    }
    let mut canonical = Vec::new();
    write_cbor(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(EvidenceError::Cbor(path.to_owned()));
    }
    Ok(())
}

pub(crate) fn canonical_cbor_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, EvidenceError> {
    let value = CborValue::serialized(value).map_err(|_| cbor_error())?;
    let mut bytes = Vec::new();
    write_cbor(&value, &mut bytes)?;
    Ok(bytes)
}

pub(super) fn write_cbor(value: &CborValue, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
    match value {
        CborValue::Integer(integer) => {
            let value = i128::from(*integer);
            if value >= 0 {
                write_cbor_uint(0, u64::try_from(value).map_err(|_| cbor_error())?, output);
            } else {
                let encoded = (-1_i128)
                    .checked_sub(value)
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or_else(cbor_error)?;
                write_cbor_uint(1, encoded, output);
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
                write_cbor(value, output)?;
            }
        }
        CborValue::Map(values) => {
            let mut encoded = Vec::with_capacity(values.len());
            for (key, value) in values {
                let mut key_bytes = Vec::new();
                let mut value_bytes = Vec::new();
                write_cbor(key, &mut key_bytes)?;
                write_cbor(value, &mut value_bytes)?;
                encoded.push((key_bytes, value_bytes));
            }
            encoded.sort_unstable_by(|left, right| {
                left.0.len().cmp(&right.0.len()).then_with(|| left.0.cmp(&right.0))
            });
            if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(cbor_error());
            }
            write_cbor_uint(5, encoded.len() as u64, output);
            for (key, value) in encoded {
                output.extend_from_slice(&key);
                output.extend_from_slice(&value);
            }
        }
        CborValue::Bool(false) => output.push(0xf4),
        CborValue::Bool(true) => output.push(0xf5),
        CborValue::Null => output.push(0xf6),
        CborValue::Float(_) | CborValue::Tag(_, _) => return Err(cbor_error()),
        _ => return Err(cbor_error()),
    }
    Ok(())
}

pub(super) fn write_cbor_uint(major: u8, value: u64, output: &mut Vec<u8>) {
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

pub(super) fn cbor_error() -> EvidenceError {
    EvidenceError::Cbor("unsupported canonical value".to_owned())
}

pub(super) fn write_verification(root: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    let path = root.join("verification.json");
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o444);
    let mut file =
        options.open(&path).map_err(|source| EvidenceError::Io { path: path.clone(), source })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| EvidenceError::Io { path, source })
}

pub(super) fn is_producer_path(path: &str) -> bool {
    path == "run.json"
        || path == "physical-input.json"
        || path == "host-commit-trace.json"
        || path == "store-pre-stop.cbor"
        || path == "store-post-rebuild.cbor"
        || path == "store-post-continuation.cbor"
        || path == "restart-trace.json"
        || path.starts_with("datagrams/")
}

pub(super) fn seal_paths<'a>(
    root: &Path,
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<(), EvidenceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for relative in paths {
            let path = root.join(relative);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
                .map_err(|source| EvidenceError::Io { path, source })?;
        }
    }
    #[cfg(not(unix))]
    let _ = (root, paths);
    Ok(())
}

pub(super) fn seal_directory(root: &Path, relative: &str) -> Result<(), EvidenceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join(relative);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555))
            .map_err(|source| EvidenceError::Io { path, source })?;
    }
    #[cfg(not(unix))]
    let _ = (root, relative);
    Ok(())
}

pub(super) fn seal_complete_package(root: &Path) -> Result<(), EvidenceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in ["datagrams", "http", "screenshots"] {
            let path = root.join(directory);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o555))
                .map_err(|source| EvidenceError::Io { path, source })?;
        }
        fs::set_permissions(root, fs::Permissions::from_mode(0o555))
            .map_err(|source| EvidenceError::Io { path: root.to_path_buf(), source })?;
    }
    Ok(())
}
