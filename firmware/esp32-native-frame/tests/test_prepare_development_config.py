#!/usr/bin/env python3
"""Behavior tests for the build-bound development Config generator."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


MODULE_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE_DIRECTORY))
try:
    import prepare_development_config
    import provision
finally:
    sys.path.pop(0)


class PrepareDevelopmentConfigTests(unittest.TestCase):
    def test_prepare_binds_build_facts_without_changing_fixed_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "development.template.toml"
            output = root / "build" / "development.toml"
            image = root / "build" / "application.bin"
            facts = root / "build" / "capability-build-facts.json"
            template.write_text(
                """[[sensors]]
id = "sensor-a"
device_id = 1
key_epoch = 1
firmware_build_digest = "{zero}"
capability_digest = "{zero}"
""".format(zero="00" * 32),
                encoding="utf-8",
            )
            image.parent.mkdir()
            image.write_bytes(b"application")
            facts.write_text(json.dumps({"idf_wifi_abi_digest": "02" * 32}), encoding="utf-8")

            def fake_run(arguments, **_kwargs):
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    f"Validation hash: {'01' * 32} (valid)\n",
                )

            prepare_development_config.prepare(
                template,
                output,
                image,
                facts,
                run=fake_run,
            )

            generated = tomllib.loads(output.read_text(encoding="utf-8"))
            sensor = generated["sensors"][0]
            self.assertEqual(sensor["id"], "sensor-a")
            self.assertEqual(sensor["device_id"], 1)
            self.assertEqual(sensor["key_epoch"], 1)
            self.assertEqual(sensor["firmware_build_digest"], "01" * 32)
            self.assertEqual(
                sensor["capability_digest"],
                provision.capability_digest(bytes([1]) * 32, bytes([2]) * 32).hex(),
            )

    def test_prepare_rejects_a_template_that_claims_build_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "development.template.toml"
            template.write_text(
                """[[sensors]]
id = "sensor-a"
device_id = 1
key_epoch = 1
firmware_build_digest = "{digest}"
capability_digest = "{zero}"
""".format(digest="01" * 32, zero="00" * 32),
                encoding="utf-8",
            )

            with self.assertRaises(prepare_development_config.ConfigBuildError):
                prepare_development_config.prepare(
                    template,
                    root / "build" / "development.toml",
                    root / "build" / "application.bin",
                    root / "build" / "capability-build-facts.json",
                )


if __name__ == "__main__":
    unittest.main()
