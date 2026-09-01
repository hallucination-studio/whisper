//! Identity of the complete executable bytes running the Host process.

use std::fmt;
#[cfg(target_os = "macos")]
use std::fs::OpenOptions;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;

use sha2::{Digest, Sha256};

/// Read buffer size in bytes used while hashing the running executable.
///
/// The 64-KiB chunk bounds stack use while amortizing file-read syscalls. It
/// changes only I/O granularity; SHA-256 still covers the complete byte stream.
const EXECUTABLE_HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ExecutableIdentity([u8; 32]);

impl ExecutableIdentity {
    pub(crate) fn running() -> Result<Self, ExecutableIdentityError> {
        let mut executable = RunningExecutable::open()?;
        let identity = Self::from_reader(&mut executable.file)?;
        executable.verify()?;
        Ok(identity)
    }

    fn from_reader(mut reader: impl Read) -> Result<Self, ExecutableIdentityError> {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; EXECUTABLE_HASH_BUFFER_BYTES];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|source| ExecutableIdentityError::Read { source })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(Self(hasher.finalize().into()))
    }

    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    #[cfg(test)]
    fn from_bytes_for_test(bytes: &[u8]) -> Self {
        Self::from_reader(bytes).expect("in-memory executable bytes are readable")
    }
}

#[derive(Debug)]
struct RunningExecutable {
    file: File,
    identity: FileIdentity,
    #[cfg(target_os = "macos")]
    mapped_image: whisper_executable_sys::LoadedMainExecutable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

impl RunningExecutable {
    #[cfg(target_os = "linux")]
    fn open() -> Result<Self, ExecutableIdentityError> {
        let file = File::open("/proc/self/exe")
            .map_err(|source| ExecutableIdentityError::Open { source })?;
        let identity = FileIdentity::from_metadata(
            &file.metadata().map_err(|source| ExecutableIdentityError::Inspect { source })?,
        );
        Ok(Self { file, identity })
    }

    #[cfg(target_os = "macos")]
    fn open() -> Result<Self, ExecutableIdentityError> {
        let mapped_image = whisper_executable_sys::loaded_main_executable()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(mapped_image.path())
            .map_err(|source| ExecutableIdentityError::Open { source })?;
        let metadata =
            file.metadata().map_err(|source| ExecutableIdentityError::Inspect { source })?;
        if !mapped_image.matches_metadata(&metadata) {
            return Err(ExecutableIdentityError::Changed);
        }
        let identity = FileIdentity::from_metadata(&metadata);
        Ok(Self { file, identity, mapped_image })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn open() -> Result<Self, ExecutableIdentityError> {
        Err(ExecutableIdentityError::UnsupportedPlatform)
    }

    fn verify(&self) -> Result<(), ExecutableIdentityError> {
        verify_file_identity(&self.file, self.identity)?;
        #[cfg(target_os = "macos")]
        if whisper_executable_sys::loaded_main_executable()? != self.mapped_image {
            return Err(ExecutableIdentityError::Changed);
        }
        Ok(())
    }
}

fn verify_file_identity(
    file: &File,
    expected: FileIdentity,
) -> Result<(), ExecutableIdentityError> {
    let actual = FileIdentity::from_metadata(
        &file.metadata().map_err(|source| ExecutableIdentityError::Inspect { source })?,
    );
    ensure_same_identity(actual, expected)
}

fn ensure_same_identity(
    actual: FileIdentity,
    expected: FileIdentity,
) -> Result<(), ExecutableIdentityError> {
    if actual == expected { Ok(()) } else { Err(ExecutableIdentityError::Changed) }
}

impl fmt::Debug for ExecutableIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecutableIdentity([REDACTED])")
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExecutableIdentityError {
    #[error("running executable bytes could not be opened: {source}")]
    Open {
        #[source]
        source: io::Error,
    },
    #[error("running executable descriptor could not be inspected: {source}")]
    Inspect {
        #[source]
        source: io::Error,
    },
    #[error("running executable bytes could not be read: {source}")]
    Read {
        #[source]
        source: io::Error,
    },
    #[cfg(target_os = "macos")]
    #[error("the kernel could not identify the mapped main executable image: {source}")]
    MappedImage {
        #[source]
        source: Box<whisper_executable_sys::LoadedMainExecutableError>,
    },
    #[error("running executable identity changed while it was being read")]
    Changed,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[error("this platform cannot pin the loaded executable image")]
    UnsupportedPlatform,
}

#[cfg(target_os = "macos")]
impl From<whisper_executable_sys::LoadedMainExecutableError> for ExecutableIdentityError {
    fn from(source: whisper_executable_sys::LoadedMainExecutableError) -> Self {
        Self::MappedImage { source: Box::new(source) }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::io::{self, Read};

    use super::{
        ExecutableIdentity, ExecutableIdentityError, FileIdentity, ensure_same_identity,
        verify_file_identity,
    };

    #[test]
    fn executable_identity_uses_complete_bytes_and_redacts_debug_output() {
        let first = ExecutableIdentity::from_bytes_for_test(b"abc");
        let second = ExecutableIdentity::from_bytes_for_test(b"whisper 0.1.0 build B");

        assert_ne!(first, second);
        assert_eq!(
            first.as_bytes(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_eq!(format!("{first:?}"), "ExecutableIdentity([REDACTED])");
    }

    #[test]
    fn executable_identity_fails_closed_when_the_running_bytes_cannot_be_read() {
        const SENSITIVE_PREFIX: &[u8] = b"/private/deployment/whisper";

        struct FailingReader {
            returned_prefix: bool,
        }

        impl Read for FailingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.returned_prefix {
                    self.returned_prefix = true;
                    buffer[..SENSITIVE_PREFIX.len()].copy_from_slice(SENSITIVE_PREFIX);
                    return Ok(SENSITIVE_PREFIX.len());
                }
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "read denied"))
            }
        }

        let error = ExecutableIdentity::from_reader(FailingReader { returned_prefix: false })
            .expect_err("an unreadable executable must not produce an identity");
        assert!(matches!(error, ExecutableIdentityError::Read { .. }));
        assert!(!format!("{error:?}").contains("/private/deployment/whisper"));
    }

    #[test]
    fn running_executable_identity_is_stable() {
        let first = ExecutableIdentity::running().expect("identify running executable");
        let second = ExecutableIdentity::running().expect("identify running executable again");
        assert_eq!(first, second);
    }

    #[test]
    fn executable_descriptor_change_fails_closed() {
        let path = std::env::temp_dir()
            .join(format!("whisper-executable-identity-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("create executable identity fixture");
        file.write_all(b"first").expect("write initial fixture bytes");
        let identity = FileIdentity::from_metadata(&file.metadata().expect("fixture metadata"));
        file.write_all(b"-changed").expect("mutate fixture bytes");

        assert!(matches!(
            verify_file_identity(&file, identity),
            Err(ExecutableIdentityError::Changed)
        ));
        std::fs::remove_file(path).expect("remove executable identity fixture");
    }

    #[test]
    fn executable_identity_mismatch_fails_closed() {
        let first = FileIdentity {
            device: 1,
            inode: 2,
            size: 3,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
        };
        let second = FileIdentity { inode: 4, ..first };
        assert!(matches!(
            ensure_same_identity(first, second),
            Err(ExecutableIdentityError::Changed)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mapped_image_failure_has_a_canonical_source_conversion() {
        fn assert_from<T: From<whisper_executable_sys::LoadedMainExecutableError>>() {}

        assert_from::<ExecutableIdentityError>();
    }
}
