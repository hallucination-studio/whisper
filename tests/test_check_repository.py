"""Behavior tests for the repository policy check entry point."""

from pathlib import Path
import subprocess
import tempfile
import unittest


CHECKER = Path(__file__).parents[1] / "scripts" / "check_repository.py"


class RepositoryPolicyCheckTests(unittest.TestCase):
    def test_rejects_broken_local_documentation_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "README.md").write_text(
                "[missing](not-present.md)\n", encoding="utf-8"
            )

            result = subprocess.run(
                ["python3", str(CHECKER), "--root", str(root), "links"],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("docs/README.md:1", result.stderr)
            self.assertIn("not-present.md", result.stderr)

    def test_rejects_changed_frozen_design_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            specification = root / "docs" / "specs" / "rf-world-model-v1.md"
            specification.parent.mkdir(parents=True)
            specification.write_text("design digest: `wrong`\n", encoding="utf-8")

            result = subprocess.run(
                ["python3", str(CHECKER), "--root", str(root), "design-digest"],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("frozen RF design digest", result.stderr)

    def test_rejects_retired_production_interface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                "pub struct CaptureRuntime;\n", encoding="utf-8"
            )

            result = subprocess.run(
                ["python3", str(CHECKER), "--root", str(root), "hard-cut"],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("CaptureRuntime", result.stderr)
            self.assertIn("src/lib.rs", result.stderr)

    def test_rejects_missing_preserved_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["python3", str(CHECKER), "--root", directory, "preserved-inputs"],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DemoSmokeReceipt.json", result.stderr)
            self.assertIn("native-frame", result.stderr)


if __name__ == "__main__":
    unittest.main()
