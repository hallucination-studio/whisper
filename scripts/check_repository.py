#!/usr/bin/env python3
"""Check repository policies that are not expressed by language toolchains."""

from argparse import ArgumentParser
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote


MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+[^)]*)?\)")
# Authoritative source: docs/specs/rf-world-model-v1.md, derived from the
# unchanged user-frozen design named there. A change requires coordinated
# specification/ADR review; changing this check alone must never bless a new design.
FROZEN_RF_DESIGN_DIGEST = "fa485d3e052bbb0444036b2815bef8236147252d98f08d79feca0d612a75991e"
RETIRED_PRODUCTION_PATTERNS = (
    ("BaselineCommand", r"\bBaselineCommand\b"),
    ("CaptureRuntime", r"\bCaptureRuntime\b"),
    ("Engine", r"\bEngine\b"),
    ("RelationshipEstimator", r"\bRelationshipEstimator\b"),
    ("Semantic Session", r"\b(?:SemanticSession|semantic_session)\b"),
    ("Semantic Session handoff", r"\b(?:SessionHandoff|semantic_session_handoff)\b"),
    ("SessionTime", r"\bSessionTime\b"),
    ("WindowProjection", r"\bWindowProjection\b"),
    ("WorldSnapshot", r"\bWorldSnapshot\b"),
    ("topology endpoint", r"(?:['\"]/(?:api/)?topology(?:[/?'\"]|$))"),
    ("signals endpoint", r"(?:['\"]/(?:api/)?signals(?:[/?'\"]|$))"),
    ("projection receipt", r"\b(?:ProjectionReceipt|projection_receipt)\b"),
    ("Store watermark", r"\b(?:StoreWatermark|store_watermark)\b"),
    ("legacy reconnect contract", r"\b(?:LegacyReconnect|legacy_reconnect)\b"),
    ("relationship classification", r"\b(?:RelationshipKnowledge|relationship_classification)\b"),
    ("Demo classification", r"\b(?:DemoClassification|demo_classification)\b"),
    ("legacy compatibility alias", r"\b(?:legacy_alias|compatibility_alias)\b"),
    ("dual write", r"\bdual_write\b"),
    ("shadow old system", r"\b(?:shadow_legacy|shadow_old_system)\b"),
)
PRODUCTION_ROOTS = ("src", "scripts", "firmware", "web", "browser", "app", "mobile")
PRODUCTION_SUFFIXES = {".c", ".cc", ".cpp", ".css", ".h", ".html", ".js", ".mjs", ".py", ".rs", ".swift", ".ts"}
EXCLUDED_PRODUCTION_TREES = (
    Path("firmware/esp32-native-frame/build"),
    Path("firmware/esp32-native-frame/tests"),
)
RETIRED_PRODUCTION_PATHS = (
    "scripts/evidence-observer.mjs",
    "scripts/strict-json.mjs",
    "src/application.rs",
    "src/capture.rs",
    "src/database.rs",
    "src/evidence",
    "src/main.rs",
    "src/relationship.rs",
    "src/session.rs",
    "src/timeline.rs",
)
PRESERVED_INPUTS = (
    "docs/evidence/receipts/check-entry-a331dd5/README.md",
    "docs/evidence/receipts/check-entry-a331dd5/intentional-domain-failure.log",
    "docs/evidence/receipts/check-entry-a331dd5/receipt.json",
    "docs/evidence/receipts/demo-smoke-e151145/DemoSmokeReceipt.json",
    "docs/evidence/receipts/demo-smoke-e151145/README.md",
    "docs/evidence/receipts/demo-smoke-e151145/chrome.png",
    "docs/evidence/receipts/demo-smoke-e151145/signals.json",
    "docs/evidence/receipts/demo-smoke-e151145/topology.json",
    "docs/evidence/receipts/firmware-ed466ae/README.md",
    "docs/evidence/receipts/firmware-ed466ae/parity-build.log",
    "docs/evidence/receipts/firmware-ed466ae/parity-flasher-args.json",
    "docs/evidence/receipts/firmware-ed466ae/parity-qemu-crlf-wrapper-failure.log",
    "docs/evidence/receipts/firmware-ed466ae/parity-qemu.log",
    "docs/evidence/receipts/firmware-ed466ae/production-build.log",
    "docs/evidence/receipts/firmware-ed466ae/production-capability-build-facts.json",
    "docs/evidence/receipts/firmware-ed466ae/production-flasher-args.json",
    "docs/evidence/receipts/firmware-ed466ae/production-image-info.log",
    "docs/evidence/receipts/firmware-ed466ae/production-qemu.log",
    "firmware/esp32-native-frame/tests/main/parity_main.c",
    "firmware/esp32-native-frame/tests/test_provision.py",
    "firmware/esp32-native-frame/tests/test_run_production_qemu.py",
    "src/conformance.rs",
    "tests/fixtures/native-frame/capabilities-v1.hex",
    "tests/fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex",
    "tests/fixtures/native-frame/csi-ht-stbc-7-pairs.hex",
    "tests/fixtures/native-frame/csi-non-ht-3-pairs.hex",
    "tests/fixtures/native-frame/health-v1.hex",
)
CHECK_FAILURE_RECEIPT_DIRECTORY = Path("docs/evidence/receipts/check-entry-a331dd5")
CHECK_FAILURE_RECEIPT_FIELDS = {
    "command",
    "controlled_mutation",
    "environment",
    "exit_status",
    "finished_at_utc",
    "log_sha256",
    "observed",
    "outcome",
    "procedure",
    "repository_revision",
    "schema",
    "started_at_utc",
}
CHECK_FAILURE_REVISION = "a331dd5519b5bb4565aa59454c251803ebae7585"
CHECK_FAILURE_MUTATION = 'assert!(option_env!("CARGO_BIN_EXE_whisper").is_none()); -> assert!(option_env!("CARGO_BIN_EXE_whisper").is_some());'
CHECK_FAILURE_OBSERVED = [
    "package_has_no_legacy_host_binary_target ... FAILED",
    "make: *** [check-rust]",
]


def check_links(root: Path) -> list[str]:
    failures: list[str] = []
    for document in sorted((root / "docs").rglob("*.md")):
        for line_number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            for match in MARKDOWN_LINK.finditer(line):
                target = unquote(match.group(1) or match.group(2))
                if target.startswith(("https://", "http://", "mailto:", "#")):
                    continue
                path_text = target.split("#", 1)[0]
                if path_text and not (document.parent / path_text).resolve().exists():
                    relative = document.relative_to(root)
                    failures.append(f"{relative}:{line_number}: missing local link {target}")
    return failures


def check_design_digest(root: Path) -> list[str]:
    specification = root / "docs" / "specs" / "rf-world-model-v1.md"
    if not specification.is_file():
        return ["missing RF world-model specification"]
    if specification.read_text(encoding="utf-8").count(FROZEN_RF_DESIGN_DIGEST) != 1:
        return ["RF world-model specification must contain the frozen RF design digest exactly once"]
    return []


def check_hard_cut(root: Path) -> list[str]:
    failures = [f"retired production path remains: {path}" for path in RETIRED_PRODUCTION_PATHS if (root / path).exists()]
    production_files: list[Path] = []
    for production_root in PRODUCTION_ROOTS:
        directory = root / production_root
        if directory.is_dir():
            production_files.extend(
                path
                for path in directory.rglob("*")
                if path.is_file()
                and path.suffix in PRODUCTION_SUFFIXES
                and not any(
                    path.is_relative_to(root / excluded)
                    for excluded in EXCLUDED_PRODUCTION_TREES
                )
                and path != root / "scripts" / "check_repository.py"
            )
    for production_file in sorted(production_files):
        text = production_file.read_text(encoding="utf-8")
        for label, pattern in RETIRED_PRODUCTION_PATTERNS:
            if re.search(pattern, text):
                failures.append(
                    f"{production_file.relative_to(root)}: retired production interface {label} remains"
                )
    return failures


def check_failure_receipt(root: Path) -> list[str]:
    directory = root / CHECK_FAILURE_RECEIPT_DIRECTORY
    receipt_path = directory / "receipt.json"
    log_path = directory / "intentional-domain-failure.log"
    if not receipt_path.is_file() or not log_path.is_file():
        return []
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        return [f"check failure receipt is malformed JSON: {error}"]
    if not isinstance(receipt, dict) or set(receipt) != CHECK_FAILURE_RECEIPT_FIELDS:
        return ["check failure receipt schema fields do not match the closed v1 schema"]

    failures: list[str] = []
    expected = {
        "schema": "whisper-check-failure-receipt-v1",
        "repository_revision": CHECK_FAILURE_REVISION,
        "command": "make check",
        "procedure": "controlled-domain-assertion-inversion-v1",
        "controlled_mutation": CHECK_FAILURE_MUTATION,
        "outcome": "rejected-controlled-domain-regression",
        "exit_status": 2,
        "observed": CHECK_FAILURE_OBSERVED,
    }
    for field, value in expected.items():
        if receipt[field] != value:
            failures.append(f"check failure receipt has invalid {field}")

    environment = receipt["environment"]
    if (
        not isinstance(environment, dict)
        or set(environment) != {"platform", "python"}
        or not all(isinstance(environment[field], str) and environment[field] for field in environment)
    ):
        failures.append("check failure receipt has invalid environment")

    timestamps: list[datetime] = []
    for field in ("started_at_utc", "finished_at_utc"):
        try:
            timestamp = datetime.fromisoformat(receipt[field])
            if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
                raise ValueError
            timestamps.append(timestamp)
        except (TypeError, ValueError):
            failures.append(f"check failure receipt has invalid {field}")
    if len(timestamps) == 2 and timestamps[1] < timestamps[0]:
        failures.append("check failure receipt finish precedes start")

    digest = receipt["log_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        failures.append("check failure receipt has invalid log_sha256")
    elif hashlib.sha256(log_path.read_bytes()).hexdigest() != digest:
        failures.append("check failure receipt log_sha256 does not match the retained log")
    return failures


def check_preserved_inputs(root: Path) -> list[str]:
    failures = [f"required preserved input is missing: {path}" for path in PRESERVED_INPUTS if not (root / path).is_file()]
    failures.extend(check_failure_receipt(root))
    return failures


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1])
    parser.add_argument(
        "checks",
        nargs="*",
        choices=["links", "design-digest", "hard-cut", "preserved-inputs"],
    )
    arguments = parser.parse_args()
    checks = arguments.checks or ["links", "design-digest", "hard-cut", "preserved-inputs"]
    root = arguments.root.resolve()
    failures: list[str] = []
    if "links" in checks:
        failures.extend(check_links(root))
    if "design-digest" in checks:
        failures.extend(check_design_digest(root))
    if "hard-cut" in checks:
        failures.extend(check_hard_cut(root))
    if "preserved-inputs" in checks:
        failures.extend(check_preserved_inputs(root))
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
