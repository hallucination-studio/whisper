//! Repository terminology checks for production and test source.

use std::fs;
use std::path::{Path, PathBuf};

const MATURITY_TERM: &str = concat!("de", "mo");
const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cmake", "css", "csv", "defaults", "h", "hex", "html", "js", "json", "mjs", "py", "rs",
    "sh", "toml", "ts", "txt", "yaml", "yml",
];

#[test]
fn source_and_fixture_names_use_domain_terminology() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for relative in ["src", "tests", "firmware/esp32-native-frame"] {
        inspect_path(root, &root.join(relative), &mut violations);
    }

    assert!(
        violations.is_empty(),
        "delivery-maturity terminology found outside documentation and evidence:\n{}",
        violations.join("\n")
    );
}

fn inspect_path(root: &Path, path: &Path, violations: &mut Vec<String>) {
    let relative = path.strip_prefix(root).expect("inspected path stays under repository root");
    if relative.components().any(|component| {
        matches!(component.as_os_str().to_str(), Some("build" | "node_modules" | "target"))
    }) {
        return;
    }

    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    if contains_maturity_term(name) {
        violations.push(format!("path: {}", relative.display()));
    }

    if path.is_dir() {
        let mut entries = fs::read_dir(path)
            .unwrap_or_else(|error| panic!("read source directory {}: {error}", path.display()))
            .map(|entry| entry.expect("read source directory entry").path())
            .collect::<Vec<PathBuf>>();
        entries.sort();
        for entry in entries {
            inspect_path(root, &entry, violations);
        }
        return;
    }

    let extension = path.extension().and_then(|extension| extension.to_str()).unwrap_or_default();
    if !SOURCE_EXTENSIONS.contains(&extension) {
        return;
    }
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read source file {}: {error}", path.display()));
    for (index, line) in source.lines().enumerate() {
        if contains_maturity_term(line) {
            violations.push(format!("content: {}:{}", relative.display(), index + 1));
        }
    }
}

fn contains_maturity_term(text: &str) -> bool {
    let lowercase = text.to_ascii_lowercase();
    lowercase.match_indices(MATURITY_TERM).any(|(start, _)| {
        let end = start + MATURITY_TERM.len();
        let previous = start.checked_sub(1).and_then(|index| text.as_bytes().get(index)).copied();
        let next = text.as_bytes().get(end).copied();
        let starts_token = previous.is_none_or(|byte| !byte.is_ascii_alphanumeric())
            || previous == Some(b'_')
            || previous == Some(b'-')
            || (text.as_bytes()[start].is_ascii_uppercase()
                && previous.is_some_and(|byte| byte.is_ascii_lowercase()));
        let ends_token = next.is_none_or(|byte| !byte.is_ascii_alphanumeric())
            || next == Some(b'_')
            || next == Some(b'-')
            || next.is_some_and(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
        starts_token && ends_token
    })
}

#[test]
fn terminology_matcher_distinguishes_scope_labels_from_longer_words() {
    for forbidden in [
        concat!("de", "mo"),
        concat!("De", "moRuntime"),
        concat!("de", "moRuntime"),
        concat!("de", "mo_runtime"),
        concat!("de", "mo-smoke"),
        concat!("capture_", "de", "mo.rs"),
        concat!("fixture-", "de", "mo"),
        concat!("test_", "de", "mo_smoke"),
        concat!("capture", "De", "moRuntime"),
    ] {
        assert!(contains_maturity_term(forbidden), "missed forbidden term: {forbidden}");
    }
    assert!(!contains_maturity_term("demonstration"));
}
