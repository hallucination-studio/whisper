//! Embeds the local Git and target provenance used by bounded evidence receipts.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

// The accepted Host source identity covers every regular file below `src/` plus these build and
// observer inputs. This intentionally includes more than the evidence modules so changes in direct
// runtime plumbing cannot retain an old identity. Membership, path spelling, or bytes change the
// digest and require regenerating the independent golden identity fixture.
const EVIDENCE_SOURCE_FILES: &[&str] = &[
    "build.rs",
    "scripts/evidence-observer.mjs",
    "scripts/strict-json.mjs",
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
];
const EVIDENCE_SOURCE_DIRECTORIES: &[&str] = &["src", "crates/whisper-executable-sys"];

fn git_output(root: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(["-C"]).arg(root).args(arguments).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn collect_source_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to list source {}: {error}", directory.display()))
        .map(|entry| entry.expect("failed to inspect source directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("failed to inspect source {}: {error}", path.display()));
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            collect_source_files(root, &path, files);
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            files.push(path.strip_prefix(root).expect("source remains below root").to_owned());
        } else {
            panic!("source identity member is not a regular file: {}", path.display());
        }
    }
}

fn evidence_source_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = EVIDENCE_SOURCE_FILES.iter().map(PathBuf::from).collect::<Vec<_>>();
    for directory in EVIDENCE_SOURCE_DIRECTORIES {
        collect_source_files(root, &root.join(directory), &mut paths);
    }
    paths.sort();
    paths
}

fn evidence_source_sha256(root: &Path, paths: &[PathBuf]) -> String {
    let mut digest = Sha256::new();
    for relative in paths {
        let path = root.join(relative);
        let source = fs::read(&path).unwrap_or_else(|error| {
            panic!("failed to read evidence source {}: {error}", path.display())
        });
        let relative = relative.to_str().expect("Host source paths are UTF-8").as_bytes();
        digest.update(
            u64::try_from(relative.len()).expect("source path length fits u64").to_be_bytes(),
        );
        digest.update(relative);
        digest.update(
            u64::try_from(source.len()).expect("evidence source length fits u64").to_be_bytes(),
        );
        digest.update(source);
    }
    digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let root = env::var_os("CARGO_MANIFEST_DIR").expect("Cargo provides CARGO_MANIFEST_DIR");
    let root = Path::new(&root);
    let source_paths = evidence_source_paths(root);
    let revision = git_output(root, &["rev-parse", "--verify", "HEAD"])
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| "0".repeat(40));
    // Evidence names the complete checkout as clean, not merely the files included in its source
    // digest. Narrowing this command could let unrelated modified or untracked repository content
    // survive into a retained formal-run provenance claim.
    let clean = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| output.stdout.is_empty());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_owned());
    let source_sha256 = evidence_source_sha256(root, &source_paths);

    println!("cargo::rustc-env=WHISPER_HOST_SOURCE_REVISION={revision}");
    println!("cargo::rustc-env=WHISPER_HOST_SOURCE_CLEAN={clean}");
    println!("cargo::rustc-env=WHISPER_HOST_TARGET={target}");
    println!("cargo::rustc-env=WHISPER_HOST_SOURCE_SHA256={source_sha256}");
    for relative in EVIDENCE_SOURCE_FILES {
        println!("cargo::rerun-if-changed={relative}");
    }
    for directory in EVIDENCE_SOURCE_DIRECTORIES {
        println!("cargo::rerun-if-changed={directory}");
    }
    if let Some(git_dir) = git_output(root, &["rev-parse", "--absolute-git-dir"]) {
        println!("cargo::rerun-if-changed={git_dir}/HEAD");
        println!("cargo::rerun-if-changed={git_dir}/index");
    }
    if let Some(git_common_dir) =
        git_output(root, &["rev-parse", "--path-format=absolute", "--git-common-dir"])
    {
        println!("cargo::rerun-if-changed={git_common_dir}/packed-refs");
    }
    if let Some(symbolic_head) = git_output(root, &["symbolic-ref", "-q", "HEAD"])
        && let Some(head_ref) =
            git_output(root, &["rev-parse", "--path-format=absolute", "--git-path", &symbolic_head])
    {
        println!("cargo::rerun-if-changed={head_ref}");
    }
}
