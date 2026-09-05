#!/usr/bin/env python3
"""Check repository policies that are not expressed by language toolchains."""

from argparse import ArgumentParser
from pathlib import Path
import re
import sys
from urllib.parse import unquote


MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+[^)]*)?\)")
FROZEN_RF_DESIGN_DIGEST = "fa485d3e052bbb0444036b2815bef8236147252d98f08d79feca0d612a75991e"
RETIRED_PRODUCTION_INTERFACES = (
    "BaselineCommand",
    "CaptureRuntime",
    "RelationshipEstimator",
    "SemanticSession",
    "WindowProjection",
    "WorldSnapshot",
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
    source = root / "src"
    if source.is_dir():
        for rust_file in sorted(source.rglob("*.rs")):
            text = rust_file.read_text(encoding="utf-8")
            for interface in RETIRED_PRODUCTION_INTERFACES:
                if re.search(rf"\b{re.escape(interface)}\b", text):
                    failures.append(
                        f"{rust_file.relative_to(root)}: retired production interface {interface} remains"
                    )
    return failures


def check_preserved_inputs(root: Path) -> list[str]:
    return [f"required preserved input is missing: {path}" for path in PRESERVED_INPUTS if not (root / path).is_file()]


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
