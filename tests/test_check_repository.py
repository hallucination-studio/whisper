"""Behavior tests for the repository policy check entry point."""

from pathlib import Path
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

    def test_rejects_missing_preserved_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_checker(Path(directory), "preserved-inputs")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DemoSmokeReceipt.json", result.stderr)
            self.assertIn("native-frame", result.stderr)


if __name__ == "__main__":
    unittest.main()
