//! Darwin loaded-main-executable interface tests.

#![cfg(target_os = "macos")]

use whisper_executable_sys::loaded_main_executable;

#[test]
fn loaded_main_executable_has_a_stable_absolute_path_and_file_identity() {
    let first = loaded_main_executable().expect("identify the loaded main executable");
    let second = loaded_main_executable().expect("identify the loaded main executable again");

    assert!(first.path().is_absolute());
    assert!(first.file_size() > 0);
    assert_eq!(first, second);
}
