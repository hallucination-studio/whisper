import csv
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "provision.py"
SPEC = importlib.util.spec_from_file_location("world_provision", SCRIPT)
provision = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provision)


class PartialStream(io.BytesIO):
    def __init__(self, data, chunk_sizes):
        super().__init__(data)
        self.chunk_sizes = iter(chunk_sizes)
        self.requests = []

    def read(self, size=-1):
        self.requests.append(size)
        try:
            size = min(size, next(self.chunk_sizes))
        except StopIteration:
            pass
        return super().read(size)


class FakeRun:
    def __init__(self, chip="Chip is ESP32-S3", flash="Detected flash size: 8MB", fail=None,
                 version="esptool v5.3.1\n"):
        self.commands = []
        self.chip = chip
        self.flash = flash
        self.fail = fail
        self.version = version

    def __call__(self, argv, **kwargs):
        self.commands.append(argv)
        command = argv[-1]
        output = ""
        if command == "version":
            output = self.version
        elif command == "chip-id":
            output = self.chip
        elif command == "flash-id":
            output = self.flash
        elif "generate" in argv:
            Path(argv[-2]).write_bytes(bytes(provision.NVS_SIZE))
        if self.fail and self.fail in argv:
            return subprocess.CompletedProcess(argv, 1, "forced failure")
        return subprocess.CompletedProcess(argv, 0, output)


class ProvisionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.generator = root / "generator.py"
        self.generator.write_text(
            "def f(data, encoding):\n        # Set size of data\n        datalen = len(data)\n",
            encoding="utf-8")
        self.tool_directory = root / "nvs-tool"
        self.tool_directory.mkdir()
        for name in provision.NVS_TOOL_SOURCE_SHA256:
            (self.tool_directory / name).write_text(f"# {name}\n", encoding="utf-8")
        self.digest_patch = mock.patch.multiple(provision,
            GENERATOR_SOURCE_SHA256=hashlib.sha256(self.generator.read_bytes()).hexdigest(),
            NVS_TOOL_SOURCE_SHA256={name: hashlib.sha256(
                (self.tool_directory / name).read_bytes()).hexdigest()
                for name in provision.NVS_TOOL_SOURCE_SHA256})
        self.digest_patch.start()
        self.args = provision.parser().parse_args([
            "--port", "/dev/test", "--device-id", "0x12", "--key-epoch", "7",
            "--ssid", "世界",
            "--probe-port", "9000", "--collector-ip", "192.0.2.10",
            "--collector-port", "9000", "--capability-digest", "5a" * 32,
            "--key-output", str(root / "key.bin"),
            "--receipt-output", str(root / "receipt.json"),
            "--generator-source", str(self.generator),
            "--nvs-tool", str(self.tool_directory / "nvs_tool.py"),
        ])

    def tearDown(self):
        self.digest_patch.stop()
        self.temporary.cleanup()

    def test_helper_commands_cannot_read_inherited_standard_input(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess(
            ["tool"], 0, "complete\n"))

        self.assertEqual(provision.checked(run, ["tool"]), "complete\n")

        run.assert_called_once()
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_capability_digest_matches_the_native_frame_descriptor_vector(self):
        self.assertEqual(
            provision.capability_digest(bytes([1]) * 32, bytes([2]) * 32).hex(),
            "e1b35c57ed78ff9a7c0ec3784a727ec7a977f59f97c3ec1ab054b773d60841f8",
        )

    def test_inherited_key_accepts_partial_reads_only_after_exact_eof(self):
        stream = PartialStream(bytes(range(32)), [1, 2, 3, 5, 8, 13])

        key = provision.consume_inherited_key(stream)

        self.assertEqual(key, bytes(range(32)))
        self.assertTrue(stream.closed)
        self.assertGreater(len(stream.requests), 2)
        self.assertEqual(stream.requests[-1], 1)

    def test_inherited_key_closes_the_actual_closefd_false_descriptor(self):
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, bytes(range(32)))
        os.close(write_descriptor)
        stream = os.fdopen(read_descriptor, "rb", closefd=False)

        key = provision.consume_inherited_key(stream)

        self.assertEqual(key, bytes(range(32)))
        self.assertTrue(stream.closed)
        with self.assertRaises(OSError) as error:
            os.fstat(read_descriptor)
        self.assertEqual(error.exception.errno, errno.EBADF)

    def test_inherited_key_rejects_every_short_length_and_closes_stream(self):
        for length in range(32):
            stream = PartialStream(bytes(range(length)), [1] * 33)
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "ended before byte 32"):
                    provision.consume_inherited_key(stream)
                self.assertTrue(stream.closed)

    def test_inherited_key_rejects_byte_33_after_partial_reads_and_closes_stream(self):
        stream = PartialStream(bytes(range(33)), [30, 2, 1])

        with self.assertRaisesRegex(ValueError, "contained byte 33"):
            provision.consume_inherited_key(stream)

        self.assertTrue(stream.closed)
        self.assertEqual(stream.requests, [33, 3, 1])
        self.assertTrue(all(1 <= request <= 33 for request in stream.requests))

    def test_inherited_provisioning_closes_stream_when_argument_validation_fails(self):
        args = provision.parser().parse_args([
            "--port", "/dev/test", "--device-id", "0x12", "--key-epoch", "7",
            "--ssid", "fixture-network",
            "--probe-port", "9000", "--collector-ip", "127.0.0.1",
            "--collector-port", "9000", "--capability-digest", "5a" * 32,
            "--key-stdin",
        ])
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, bytes(range(32)))
        os.close(write_descriptor)
        stream = os.fdopen(read_descriptor, "rb", closefd=False)

        with self.assertRaisesRegex(ValueError, "collector IP must be unicast and non-loopback"):
            provision.provision(args, "secret-pass", key_stream=stream)

        self.assertTrue(stream.closed)
        with self.assertRaises(OSError) as error:
            os.fstat(read_descriptor)
        self.assertEqual(error.exception.errno, errno.EBADF)

    def test_inherited_provisioning_uses_stream_without_retaining_key_or_receipt(self):
        root = Path(self.temporary.name)
        args = provision.parser().parse_args([
            "--port", "/dev/test", "--device-id", "0x12", "--key-epoch", "7",
            "--ssid", "fixture-network",
            "--probe-port", "9000", "--collector-ip", "192.0.2.10",
            "--collector-port", "9000", "--capability-digest", "5a" * 32,
            "--key-stdin",
            "--generator-source", str(self.generator),
            "--nvs-tool", str(self.tool_directory / "nvs_tool.py"),
        ])
        stream = PartialStream(bytes(range(32)), [7, 11, 14])
        fake = FakeRun()

        result = provision.provision(
            args,
            "secret-pass",
            run=fake,
            random_bytes=lambda _length: self.fail("random source must not be used"),
            key_stream=stream,
        )

        self.assertEqual(result, {
            "schema": 2,
            "target": "ESP32-S3",
            "device_id": 0x12,
            "key_epoch": 7,
            "flash_status": "verified",
            "verified": True,
        })
        self.assertTrue(stream.closed)
        self.assertEqual(list(root.glob("*.bin")), [])
        self.assertEqual(list(root.glob("*.json")), [])
        flattened = "\n".join(" ".join(command) for command in fake.commands)
        self.assertNotIn(bytes(range(32)).hex(), flattened)
        self.assertNotIn("secret-pass", flattened)

    def test_full_mapping_utf8_and_safe_flash_order(self):
        fake = FakeRun()
        receipt = provision.provision(self.args, "secret-pass", run=fake,
            random_bytes=lambda length: bytes(range(length)))
        commands = fake.commands
        generated = next(command for command in commands if "generate" in command)
        csv_path = Path(generated[-3])
        # The private temporary CSV is gone after provisioning.
        self.assertFalse(csv_path.exists())
        patched = Path(generated[1]).read_text(encoding="utf-8") if Path(generated[1]).exists() else ""
        self.assertEqual(patched, "")
        flat = "\n".join(" ".join(command) for command in commands)
        self.assertNotIn("secret-pass", flat)
        self.assertNotIn("password", json.dumps(receipt))
        self.assertNotIn("bssid", receipt)
        self.assertNotIn("channel", receipt)
        self.assertEqual(receipt["schema"], 2)
        self.assertEqual(receipt["device_id"], 0x12)
        self.assertEqual(receipt["nvs_offset"], 0x11000)
        self.assertEqual(receipt["nvs_size"], 0x7000)
        self.assertTrue(receipt["verified"])
        self.assertTrue(json.loads(Path(self.args.receipt_output).read_text())["verified"])
        chip = next(i for i, command in enumerate(commands) if command[-1] == "chip-id")
        flash = next(i for i, command in enumerate(commands) if command[-1] == "flash-id")
        write = next(i for i, command in enumerate(commands) if "write-flash" in command)
        verify = next(i for i, command in enumerate(commands) if "verify-flash" in command)
        self.assertLess(chip, flash)
        self.assertLess(flash, write)
        self.assertLess(write, verify)
        self.assertEqual(commands[write][-2], hex(provision.NVS_OFFSET))
        self.assertEqual(commands[verify][-2], hex(provision.NVS_OFFSET))
        self.assertEqual(os.stat(self.args.key_output).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.args.receipt_output).st_mode & 0o777, 0o600)

    def test_field_csv_and_utf8_generator_patch(self):
        config = provision.validate(self.args, "secret-pass")
        path = Path(self.temporary.name) / "mapping.csv"
        provision.write_csv(path, config, bytes(range(32)))
        with path.open(encoding="utf-8") as source:
            rows = {row[0]: row for row in csv.reader(source) if row}
        self.assertEqual(rows["ssid"][3], "世界")
        self.assertEqual(rows["collector_ip"][3], "192.0.2.10")
        self.assertEqual(rows["aes_key"][3], bytes(range(32)).hex())
        self.assertEqual(rows["schema"][3], "2")
        self.assertNotIn("bssid", rows)
        self.assertNotIn("channel", rows)
        patched = Path(self.temporary.name) / "patched.py"
        provision.patched_generator(self.generator, patched)
        source = patched.read_text(encoding="utf-8")
        self.assertIn("len(data.encode('utf8'))", source)
        self.assertNotIn("# Set size of data\n        datalen = len(data)", source)

    def test_bad_board_and_persistence_failure_do_not_write(self):
        for fake in (FakeRun(chip="Chip is ESP32-C6"), FakeRun(flash="Detected flash size: 4MB")):
            with self.subTest(commands=fake):
                with self.assertRaises(RuntimeError):
                    provision.provision(self.args, "secret-pass", run=fake,
                        random_bytes=lambda length: bytes(length))
                self.assertFalse(Path(self.args.key_output).exists())
                self.assertFalse(Path(self.args.receipt_output).exists())
                self.assertFalse(any("write-flash" in command for command in fake.commands))
        fake = FakeRun()
        with mock.patch.object(provision, "persist_prepared", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                provision.provision(self.args, "secret-pass", run=fake,
                    random_bytes=lambda length: bytes(length))
        self.assertFalse(any("write-flash" in command for command in fake.commands))
        self.assertFalse(Path(self.args.key_output).exists())
        self.assertFalse(Path(self.args.receipt_output).exists())

    def test_mutation_failures_retain_prepared_artifacts(self):
        for failure in ("write-flash", "verify-flash"):
            fake = FakeRun(fail=failure)
            with self.subTest(failure=failure):
                with self.assertRaises(RuntimeError):
                    provision.provision(self.args, "secret-pass", run=fake,
                        random_bytes=lambda length: bytes(length))
                self.assertTrue(Path(self.args.key_output).is_file())
                receipt = json.loads(Path(self.args.receipt_output).read_text())
                self.assertFalse(receipt["verified"])
                self.assertEqual(receipt["flash_status"], "prepared")
                Path(self.args.key_output).unlink()
                Path(self.args.receipt_output).unlink()

    def test_receipt_finalize_failure_retains_prepared_receipt(self):
        fake = FakeRun()
        with mock.patch.object(provision, "finalize_receipt", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                provision.provision(self.args, "secret-pass", run=fake,
                    random_bytes=lambda length: bytes(length))
        self.assertTrue(any("verify-flash" in command for command in fake.commands))
        self.assertTrue(Path(self.args.key_output).is_file())
        self.assertFalse(json.loads(Path(self.args.receipt_output).read_text())["verified"])

    def test_validation_precedes_commands(self):
        self.args.collector_ip = "127.0.0.1"
        fake = FakeRun()
        with self.assertRaises(ValueError):
            provision.provision(self.args, "secret-pass", run=fake)
        self.assertEqual(fake.commands, [])

    def test_modified_pinned_sources_stop_before_write(self):
        sources = [self.generator]
        sources.extend(self.tool_directory / name for name in provision.NVS_TOOL_SOURCE_SHA256)
        for source in sources:
            original = source.read_bytes()
            source.write_bytes(original + b"x")
            fake = FakeRun()
            with self.subTest(source=source):
                with self.assertRaises(RuntimeError):
                    provision.provision(self.args, "secret-pass", run=fake,
                        random_bytes=lambda length: bytes(length))
                self.assertFalse(any("write-flash" in command for command in fake.commands))
                self.assertFalse(Path(self.args.key_output).exists())
                self.assertFalse(Path(self.args.receipt_output).exists())
            source.write_bytes(original)

    def test_primary_esptool_version_cannot_be_hidden_by_compatibility_text(self):
        fake = FakeRun(version="esptool v6.0.0\ncompatibility data: 5.3.1\n")
        with self.assertRaises(RuntimeError):
            provision.provision(self.args, "secret-pass", run=fake,
                random_bytes=lambda length: bytes(length))
        self.assertEqual(len(fake.commands), 1)
        self.assertFalse(Path(self.args.key_output).exists())
        self.assertFalse(Path(self.args.receipt_output).exists())


if __name__ == "__main__":
    unittest.main()
