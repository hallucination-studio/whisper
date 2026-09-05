"""Behavior tests for the repository policy check entry point."""

from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest


CHECKER = Path(__file__).parents[1] / "scripts" / "check_repository.py"


class RepositoryPolicyCheckTests(unittest.TestCase):
    def run_checker(self, root: Path, check: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CHECKER), "--root", str(root), check],
            check=False,
            capture_output=True,
            text=True,
        )

    def write_check_failure_receipt(self, root: Path, *, log_digest: str | None = None) -> Path:
        receipt_directory = root / "docs" / "evidence" / "receipts" / "check-entry-a331dd5"
        receipt_directory.mkdir(parents=True)
        log = b"controlled failure\n"
        (receipt_directory / "intentional-domain-failure.log").write_bytes(log)
        receipt = {
            "schema": "whisper-check-failure-receipt-v1",
            "repository_revision": "a331dd5519b5bb4565aa59454c251803ebae7585",
            "environment": {"platform": "test-platform", "python": "test-python"},
            "command": "make check",
            "procedure": "controlled-domain-assertion-inversion-v1",
            "controlled_mutation": "assertion inversion",
            "started_at_utc": "2026-09-05T07:04:06+00:00",
            "finished_at_utc": "2026-09-05T07:04:18+00:00",
            "outcome": "rejected-controlled-domain-regression",
            "exit_status": 2,
            "log_sha256": log_digest or hashlib.sha256(log).hexdigest(),
            "observed": [
                "package_has_no_legacy_host_binary_target ... FAILED",
                "make: *** [check-rust]",
            ],
        }
        path = receipt_directory / "receipt.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        return path

    def test_rejects_broken_local_documentation_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "README.md").write_text(
                "[missing](not-present.md)\n", encoding="utf-8"
            )

            result = self.run_checker(root, "links")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("docs/README.md:1", result.stderr)
            self.assertIn("not-present.md", result.stderr)

    def test_rejects_changed_frozen_design_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            specification = root / "docs" / "specs" / "rf-world-model-v1.md"
            specification.parent.mkdir(parents=True)
            specification.write_text("design digest: `wrong`\n", encoding="utf-8")

            result = self.run_checker(root, "design-digest")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("frozen RF design digest", result.stderr)

    def test_rejects_retired_production_interface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                "pub struct CaptureRuntime;\n", encoding="utf-8"
            )

            result = self.run_checker(root, "hard-cut")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("CaptureRuntime", result.stderr)
            self.assertIn("src/lib.rs", result.stderr)

    def test_rejects_retired_interfaces_in_production_scripts_and_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "web" / "assets").mkdir(parents=True)
            (root / "scripts" / "serve.py").write_text(
                "class Engine: pass\n", encoding="utf-8"
            )
            (root / "web" / "assets" / "app.js").write_text(
                "fetch('/api/signals');\n", encoding="utf-8"
            )

            result = self.run_checker(root, "hard-cut")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Engine", result.stderr)
            self.assertIn("signals endpoint", result.stderr)

    def test_rejects_legacy_compatibility_and_dual_authority_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "mobile").mkdir()
            (root / "mobile" / "bridge.swift").write_text(
                "let legacy_alias = dual_write\nlet state = shadow_old_system\n",
                encoding="utf-8",
            )

            result = self.run_checker(root, "hard-cut")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("legacy compatibility alias", result.stderr)
            self.assertIn("dual write", result.stderr)
            self.assertIn("shadow old system", result.stderr)

    def test_rejects_forbidden_array_shortcuts_and_static_path_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "shortcuts.rs").write_text(
                "struct OrdinaryEspAoa;\n"
                "struct CrossArrayPhaseFusion;\n"
                "struct ArrayPersonPosition;\n"
                "fn delete_static_path() {}\n"
                "struct SecondPathInterpreter;\n",
                encoding="utf-8",
            )

            result = self.run_checker(root, "hard-cut")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ordinary ESP AoA", result.stderr)
            self.assertIn("cross-array phase fusion", result.stderr)
            self.assertIn("array path as person position", result.stderr)
            self.assertIn("permanent static-path deletion", result.stderr)
            self.assertIn("second path interpreter", result.stderr)

    def test_build_named_production_directories_cannot_bypass_hard_cut(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rejected = (
                root / "src" / "build" / "legacy.rs",
                root / "scripts" / "build" / "serve.py",
                root / "web" / "build" / "app.js",
            )
            for path in rejected:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("struct SessionTime;\n", encoding="utf-8")
            actual_test = root / "firmware" / "esp32-native-frame" / "tests" / "legacy.c"
            actual_generated = root / "firmware" / "esp32-native-frame" / "build" / "legacy.c"
            for path in (actual_test, actual_generated):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("struct SessionTime;\n", encoding="utf-8")

            result = self.run_checker(root, "hard-cut")

            self.assertNotEqual(result.returncode, 0)
            for path in rejected:
                self.assertIn(str(path.relative_to(root)), result.stderr)
            self.assertNotIn(str(actual_test.relative_to(root)), result.stderr)
            self.assertNotIn(str(actual_generated.relative_to(root)), result.stderr)

    def test_rejects_missing_preserved_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_checker(Path(directory), "preserved-inputs")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DemoSmokeReceipt.json", result.stderr)
            self.assertIn("native-frame", result.stderr)

    def test_rejects_check_failure_log_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_check_failure_receipt(root, log_digest="0" * 64)

            result = self.run_checker(root, "preserved-inputs")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("log_sha256 does not match", result.stderr)

    def test_rejects_missing_or_invalid_check_failure_receipt_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = self.write_check_failure_receipt(root)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            del receipt["procedure"]
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

            result = self.run_checker(root, "preserved-inputs")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("receipt schema fields", result.stderr)

            receipt["procedure"] = "controlled-domain-assertion-inversion-v1"
            receipt["exit_status"] = 0
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            result = self.run_checker(root, "preserved-inputs")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exit_status", result.stderr)


if __name__ == "__main__":
    unittest.main()
