#!/usr/bin/env python3
"""Record the unified gate rejecting a controlled domain-behavior regression."""

from argparse import ArgumentParser
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile


ORIGINAL_ASSERTION = 'assert!(option_env!("CARGO_BIN_EXE_whisper").is_none());'
FAILING_ASSERTION = 'assert!(option_env!("CARGO_BIN_EXE_whisper").is_some());'


def run(command: list[str], root: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=root, check=False, capture_output=True)


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    repository = Path(__file__).parents[1]

    if run(["git", "status", "--porcelain"], repository).stdout:
        parser.error("the source checkout must be clean so the receipt identifies exact bytes")
    revision = run(["git", "rev-parse", "HEAD"], repository).stdout.decode().strip()
    arguments.output.mkdir(parents=True, exist_ok=False)

    with tempfile.TemporaryDirectory() as directory:
        copy = Path(directory) / "repository"
        copy.mkdir()
        archive = run(["git", "archive", "--format=tar", "HEAD"], repository)
        if archive.returncode != 0:
            return archive.returncode
        archive_path = Path(directory) / "repository.tar"
        archive_path.write_bytes(archive.stdout)
        with tarfile.open(archive_path) as source:
            source.extractall(copy, filter="data")

        test = copy / "tests" / "package_shape.rs"
        contents = test.read_text(encoding="utf-8")
        if contents.count(ORIGINAL_ASSERTION) != 1:
            raise RuntimeError("controlled assertion target is not unique")
        test.write_text(contents.replace(ORIGINAL_ASSERTION, FAILING_ASSERTION), encoding="utf-8")

        started_at = datetime.now(timezone.utc)
        result = run(["make", "check"], copy)
        finished_at = datetime.now(timezone.utc)
        output = result.stdout + result.stderr

    required = (b"package_has_no_legacy_host_binary_target ... FAILED", b"make: *** [check-rust]")
    if result.returncode == 0 or not all(marker in output for marker in required):
        print(output.decode(errors="replace"))
        return 1

    log = arguments.output / "intentional-domain-failure.log"
    log.write_bytes(output)
    metadata = {
        "command": "make check",
        "controlled_mutation": f"{ORIGINAL_ASSERTION} -> {FAILING_ASSERTION}",
        "exit_status": result.returncode,
        "finished_at_utc": finished_at.isoformat(),
        "log_sha256": hashlib.sha256(output).hexdigest(),
        "observed": [marker.decode() for marker in required],
        "platform": platform.platform(),
        "repository_revision": revision,
        "started_at_utc": started_at.isoformat(),
    }
    (arguments.output / "receipt.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
