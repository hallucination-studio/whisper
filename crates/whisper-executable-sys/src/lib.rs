//! Safe access to the loaded main executable image on Darwin.

#[cfg(target_os = "macos")]
use std::backtrace::Backtrace;
#[cfg(target_os = "macos")]
use std::ffi::OsStr;
#[cfg(target_os = "macos")]
use std::fmt;
#[cfg(target_os = "macos")]
use std::fs::Metadata;
#[cfg(target_os = "macos")]
use std::io;
#[cfg(target_os = "macos")]
use std::mem::{MaybeUninit, size_of};
#[cfg(target_os = "macos")]
use std::num::TryFromIntError;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};

/// The loaded main executable path and kernel-reported file identity.
#[cfg(target_os = "macos")]
#[derive(Debug, Eq, PartialEq)]
pub struct LoadedMainExecutable {
    path: PathBuf,
    identity: FileIdentity,
}

#[cfg(target_os = "macos")]
impl LoadedMainExecutable {
    /// Returns the absolute path backing the loaded main executable mapping.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the loaded executable size in bytes.
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.identity.size
    }

    /// Returns whether file metadata has the loaded executable's complete identity.
    #[must_use]
    pub fn matches_metadata(&self, metadata: &Metadata) -> bool {
        self.identity == FileIdentity::from_metadata(metadata)
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(target_os = "macos")]
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

/// Failure to obtain a complete loaded main-executable identity from Darwin.
#[cfg(target_os = "macos")]
pub struct LoadedMainExecutableError {
    operation: &'static str,
    kind: ErrorKind,
    source: Option<FailureSource>,
    backtrace: Backtrace,
}

#[cfg(target_os = "macos")]
impl fmt::Debug for LoadedMainExecutableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("LoadedMainExecutableError");
        debug.field("operation", &self.operation).field("kind", &self.kind);
        match &self.source {
            Some(FailureSource::Io(source)) => {
                debug
                    .field("source_kind", &source.kind())
                    .field("source_raw_os_error", &source.raw_os_error());
            }
            Some(FailureSource::Integer(_)) => {
                debug.field("source_kind", &"integer conversion");
            }
            None => {
                debug.field("source_kind", &Option::<&str>::None);
            }
        }
        debug.field("backtrace", &self.backtrace).finish()
    }
}

#[cfg(target_os = "macos")]
impl LoadedMainExecutableError {
    fn new(operation: &'static str, kind: ErrorKind) -> Self {
        Self { operation, kind, source: None, backtrace: Backtrace::capture() }
    }

    fn from_io(operation: &'static str, kind: ErrorKind, source: io::Error) -> Self {
        Self {
            operation,
            kind,
            source: Some(FailureSource::Io(source)),
            backtrace: Backtrace::capture(),
        }
    }

    fn from_integer(operation: &'static str, kind: ErrorKind, source: TryFromIntError) -> Self {
        Self {
            operation,
            kind,
            source: Some(FailureSource::Integer(source)),
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns the captured backtrace for this failure.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum ErrorKind {
    MainImageUnavailable,
    AddressOutOfRange,
    NativeBufferSizeOutOfRange,
    RegionQueryFailed,
    RegionRecordIncomplete,
    PathMissingTerminator,
    PathEmpty,
    FileSizeOutOfRange,
}

#[cfg(target_os = "macos")]
impl ErrorKind {
    const fn description(&self) -> &'static str {
        match self {
            Self::MainImageUnavailable => "the main image was unavailable",
            Self::AddressOutOfRange => "the main-image address was outside the kernel interface",
            Self::NativeBufferSizeOutOfRange => {
                "the native region buffer size was outside the kernel interface"
            }
            Self::RegionQueryFailed => "the kernel region query failed",
            Self::RegionRecordIncomplete => "the kernel returned an incomplete region record",
            Self::PathMissingTerminator => "the kernel path was not terminated",
            Self::PathEmpty => "the kernel path was empty",
            Self::FileSizeOutOfRange => "the executable size was invalid",
        }
    }
}

#[cfg(target_os = "macos")]
enum FailureSource {
    Io(io::Error),
    Integer(TryFromIntError),
}

#[cfg(target_os = "macos")]
impl fmt::Display for LoadedMainExecutableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to obtain the loaded main-executable identity while attempting to {}: {}",
            self.operation,
            self.kind.description()
        )
    }
}

#[cfg(target_os = "macos")]
impl std::error::Error for LoadedMainExecutableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| match source {
            FailureSource::Io(source) => source as &(dyn std::error::Error + 'static),
            FailureSource::Integer(source) => source as &(dyn std::error::Error + 'static),
        })
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcRegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    object_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcRegionWithPathInfo {
    region: ProcRegionInfo,
    vnode: libc::vnode_info_path,
}

/// Returns the loaded main executable's absolute path and stable file identity.
///
/// The returned values are copied from the current process's dyld image table and
/// the corresponding kernel region record. No native pointer escapes this call.
///
/// # Errors
///
/// Returns an error when Darwin omits the main image, its address does not fit the
/// kernel interface, or `proc_pidinfo` returns an incomplete region record or path.
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    deprecated,
    reason = "Darwin exposes loaded image identity only through this native adapter"
)]
pub fn loaded_main_executable() -> Result<LoadedMainExecutable, LoadedMainExecutableError> {
    // Darwin's <libproc.h> defines PROC_PIDREGIONPATHINFO as selector 8. A
    // different selector returns a different ABI shape and invalidates the
    // exact-size initialization check for `ProcRegionWithPathInfo` below.
    const PROC_PID_REGION_PATH_INFO: libc::c_int = 8;

    // SAFETY: dyld owns the returned header for the process lifetime. Index zero is the
    // main executable image, and the pointer is only converted to an address here.
    let header = unsafe { libc::_dyld_get_image_header(0) };
    if header.is_null() {
        return Err(LoadedMainExecutableError::new(
            "read the dyld main image",
            ErrorKind::MainImageUnavailable,
        ));
    }
    let address = u64::try_from(header.addr()).map_err(|source| {
        LoadedMainExecutableError::from_integer(
            "convert the main-image address",
            ErrorKind::AddressOutOfRange,
            source,
        )
    })?;
    let mut info = MaybeUninit::<ProcRegionWithPathInfo>::zeroed();
    let buffer_size = i32::try_from(size_of::<ProcRegionWithPathInfo>()).map_err(|source| {
        LoadedMainExecutableError::from_integer(
            "convert the native region buffer size",
            ErrorKind::NativeBufferSizeOutOfRange,
            source,
        )
    })?;
    // SAFETY: `info` is an aligned, writable buffer of exactly `buffer_size` bytes. The
    // kernel initializes the complete C structure on the exact-size success checked below.
    let written = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PID_REGION_PATH_INFO,
            address,
            info.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    if written <= 0 {
        return Err(LoadedMainExecutableError::from_io(
            "query the loaded executable region",
            ErrorKind::RegionQueryFailed,
            io::Error::last_os_error(),
        ));
    }
    if written != buffer_size {
        return Err(LoadedMainExecutableError::new(
            "query the loaded executable region",
            ErrorKind::RegionRecordIncomplete,
        ));
    }
    // SAFETY: the exact-size successful call above initialized the complete structure.
    let info = unsafe { info.assume_init() };
    let path = info.vnode.vip_path.as_flattened();
    let path_end = path.iter().position(|byte| *byte == 0).ok_or_else(|| {
        LoadedMainExecutableError::new(
            "decode the loaded executable path",
            ErrorKind::PathMissingTerminator,
        )
    })?;
    if path_end == 0 {
        return Err(LoadedMainExecutableError::new(
            "decode the loaded executable path",
            ErrorKind::PathEmpty,
        ));
    }
    let path_bytes = path[..path_end].iter().map(|byte| *byte as u8).collect::<Vec<_>>();
    let size = u64::try_from(info.vnode.vip_vi.vi_stat.vst_size).map_err(|source| {
        LoadedMainExecutableError::from_integer(
            "convert the loaded executable size",
            ErrorKind::FileSizeOutOfRange,
            source,
        )
    })?;
    Ok(LoadedMainExecutable {
        path: PathBuf::from(OsStr::from_bytes(&path_bytes)),
        identity: FileIdentity {
            device: u64::from(info.vnode.vip_vi.vi_stat.vst_dev),
            inode: info.vnode.vip_vi.vi_stat.vst_ino,
            size,
            modified_seconds: info.vnode.vip_vi.vi_stat.vst_mtime,
            modified_nanoseconds: info.vnode.vip_vi.vi_stat.vst_mtimensec,
            changed_seconds: info.vnode.vip_vi.vi_stat.vst_ctime,
            changed_nanoseconds: info.vnode.vip_vi.vi_stat.vst_ctimensec,
        },
    })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::error::Error as _;
    use std::io;
    use std::mem::{offset_of, size_of};

    #[test]
    fn proc_region_abi_layout_matches_the_darwin_contract() {
        assert_eq!(size_of::<super::ProcRegionInfo>(), 96);
        assert_eq!(size_of::<libc::vinfo_stat>(), 136);
        assert_eq!(size_of::<libc::vnode_info_path>(), 1_176);
        assert_eq!(offset_of!(super::ProcRegionWithPathInfo, vnode), 96);
        assert_eq!(size_of::<super::ProcRegionWithPathInfo>(), 1_272);
    }

    #[test]
    fn loaded_executable_error_retains_operation_and_os_cause_without_a_path() {
        const SENSITIVE_PATH: &str = "/private/sensitive/whisper-host";
        let error = super::LoadedMainExecutableError::from_io(
            "query loaded executable region",
            super::ErrorKind::RegionQueryFailed,
            io::Error::new(io::ErrorKind::PermissionDenied, SENSITIVE_PATH),
        );

        assert!(error.to_string().contains("query loaded executable region"));
        assert!(!error.to_string().contains(SENSITIVE_PATH));
        assert!(!format!("{error:?}").contains(SENSITIVE_PATH));
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .expect("the upstream OS error must remain available");
        assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
        assert!(source.to_string().contains(SENSITIVE_PATH));
        let _ = error.backtrace();
    }
}
