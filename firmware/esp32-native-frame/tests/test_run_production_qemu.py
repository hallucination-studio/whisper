import csv
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "run_production_qemu.py"
SPEC = importlib.util.spec_from_file_location("production_qemu", SCRIPT)
production_qemu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(production_qemu)


class PartialStream(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(size, 5))


class ProductionQemuTest(unittest.TestCase):
    def test_qemu_consumes_inherited_key_into_runtime_only_provisioning(self):
        stream = PartialStream(bytes(range(32)))
        with tempfile.TemporaryDirectory() as temporary:
            csv_path = Path(temporary) / "provision.csv"

            key = production_qemu.consume_runtime_key(stream)
            production_qemu.write_provisioning(
                csv_path,
                key,
                bytes.fromhex("5a" * 32),
                0x12,
                7,
            )

            self.assertTrue(stream.closed)
            with csv_path.open(encoding="utf-8") as source:
                rows = {row[0]: row for row in csv.reader(source) if row}
            self.assertEqual(rows["aes_key"][3], bytes(range(32)).hex())
            self.assertEqual(rows["cap_digest"][3], "5a" * 32)
            self.assertEqual(rows["schema"][3], "2")
            self.assertEqual(rows["device_id"][3], str(0x12))
            self.assertEqual(rows["key_epoch"][3], "7")
        self.assertFalse((SCRIPT.parent / "disposable-provision.csv").exists())


if __name__ == "__main__":
    unittest.main()
