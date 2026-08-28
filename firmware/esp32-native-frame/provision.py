#!/usr/bin/env python3
"""Provision the fixed World ESP32-S3 native-frame NVS partition."""

import argparse
import csv
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile

CHIP = "esp32s3"
NVS_OFFSET = 0x11000
NVS_SIZE = 0x7000
DEFAULT_BAUD = 115200
ESPTOOL_VERSION = "5.3.1"
PROVISIONING_SCHEMA = 2

# Extracted from espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb.
GENERATOR_SOURCE_SHA256 = "5adcd0e787ea41b8c3a1d42bdeb3dcc333e2d63949ee0778ba10c6ba901ad80e"
NVS_TOOL_SOURCE_SHA256 = {
    "nvs_tool.py": "7c3969b276136aa9554bbeb577912c15fe2ac07e9535e176def87d0fbcaee44a",
    "nvs_check.py": "d4b59240c06287faf8848aef80f4bf434844583eccce4f9b2e15aaed3cfe751f",
    "nvs_logger.py": "bc309a7d2e594c8e471f3fe636e7e9d86860541777e6adbc91ac771cd09d4cd8",
    "nvs_parser.py": "621bdbf0ac60e34ae190f63be10f0f1a4dd4d18c25ebab0cf56ff53a6f2b6c2c",
}


def bounded_int(name, value, low, high):
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not low <= number <= high:
        raise ValueError(f"{name} must be in {low}..{high}")
    return number


def validate(args, password):
    device_id = bounded_int("device ID", args.device_id, 0, (1 << 64) - 1)
    key_epoch = bounded_int("key epoch", args.key_epoch, 1, 65535)
    probe_port = bounded_int("probe port", args.probe_port, 1, 65535)
    collector_port = bounded_int("collector port", args.collector_port, 1, 65535)
    baud = bounded_int("baud", args.baud, 1, 4_000_000)
    if "\0" in args.ssid or not 1 <= len(args.ssid.encode("utf-8")) <= 32:
        raise ValueError("SSID must contain 1..32 UTF-8 bytes without NUL")
    password_bytes = password.encode("utf-8")
    if "\0" in password or (password_bytes and not 8 <= len(password_bytes) <= 63):
        raise ValueError("Wi-Fi password must be empty or contain 8..63 UTF-8 bytes without NUL")
    collector = ipaddress.ip_address(args.collector_ip)
    if collector.is_unspecified or collector.is_loopback or collector.is_multicast:
        raise ValueError("collector IP must be unicast and non-loopback")
    if collector.version == 6 and (collector.is_link_local or collector.ipv4_mapped is not None):
        raise ValueError("collector IPv6 address must not be link-local or IPv4-mapped")
    if re.fullmatch(r"[0-9A-Fa-f]{64}", args.capability_digest) is None:
        raise ValueError("capability digest must be exactly 32 hexadecimal bytes")
    key_output = Path(args.key_output).expanduser().resolve()
    receipt_output = Path(args.receipt_output).expanduser().resolve()
    if key_output == receipt_output:
        raise ValueError("key and receipt outputs must be different files")
    for output in (key_output, receipt_output):
        if output.exists():
            raise ValueError(f"refusing to overwrite {output}")
        if not output.parent.is_dir():
            raise ValueError(f"output directory does not exist: {output.parent}")
    return {
        "device_id": device_id, "key_epoch": key_epoch, "ssid": args.ssid,
        "password": password, "probe_port": probe_port, "collector_ip": str(collector),
        "collector_port": collector_port,
        "capability_digest": bytes.fromhex(args.capability_digest), "baud": baud,
        "key_output": key_output, "receipt_output": receipt_output,
    }


def write_csv(path, config, key):
    rows = [
        ("key", "type", "encoding", "value"),
        ("provision", "namespace", "", ""),
        ("schema", "data", "u16", str(PROVISIONING_SCHEMA)),
        ("device_id", "data", "u64", str(config["device_id"])),
        ("key_epoch", "data", "u16", str(config["key_epoch"])),
        ("aes_key", "data", "hex2bin", key.hex()),
        ("ssid", "data", "string", config["ssid"]),
        ("wifi_pass", "data", "string", config["password"]),
        ("probe_port", "data", "u16", str(config["probe_port"])),
        ("collector_ip", "data", "string", config["collector_ip"]),
        ("collect_port", "data", "u16", str(config["collector_port"])),
        ("cap_digest", "data", "hex2bin", config["capability_digest"].hex()),
        ("runtime", "namespace", "", ""),
        ("boot_generation", "data", "u32", "0"),
    ]
    with path.open("w", encoding="utf-8", newline="") as output:
        os.chmod(path, 0o600)
        csv.writer(output).writerows(rows)


def patched_generator(source, destination):
    text = source.read_text(encoding="utf-8")
    old = "        # Set size of data\n        datalen = len(data)\n"
    new = ("        # ESP-IDF 5.4 fix: NVS string length is encoded UTF-8 bytes.\n"
           "        datalen = len(data.encode('utf8')) if encoding == 'string' "
           "and type(data) != bytes else len(data)\n")
    if text.count(old) != 1:
        raise RuntimeError("unsupported NVS generator; expected ESP-IDF 5.4 source")
    destination.write_text(text.replace(old, new), encoding="utf-8")
    os.chmod(destination, 0o700)


def verified_copy(source, destination, expected_sha256):
    try:
        data = source.read_bytes()
    except OSError as error:
        raise RuntimeError(f"required pinned source is unavailable: {source}") from error
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise RuntimeError(f"pinned source digest mismatch: {source}")
    destination.write_bytes(data)
    os.chmod(destination, 0o600)


def command_prefix(python, tool, module):
    return [python, tool] if tool else [python, "-m", module]


def checked(run, argv):
    result = run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(argv[:2])}\n{result.stdout.strip()}")
    return result.stdout


def reserve(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)


def sync_parent(path):
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def persist_prepared(config, key, receipt):
    with config["key_output"].open("wb") as output:
        output.write(key)
        output.flush()
        os.fsync(output.fileno())
    with config["receipt_output"].open("w", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    sync_parent(config["key_output"])
    if config["receipt_output"].parent != config["key_output"].parent:
        sync_parent(config["receipt_output"])


def finalize_receipt(path, receipt):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump(receipt, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_parent(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def provision(args, password, run=subprocess.run, random_bytes=secrets.token_bytes):
    config = validate(args, password)
    key = random_bytes(32)
    if len(key) != 32:
        raise RuntimeError("random source did not return 32 bytes")
    esptool = command_prefix(args.python, args.esptool, "esptool")
    reserved = []
    try:
        for output in (config["key_output"], config["receipt_output"]):
            reserve(output)
            reserved.append(output)
        version_output = checked(run, esptool + ["version"])
        version = re.escape(ESPTOOL_VERSION)
        if re.fullmatch(rf"esptool(?:\.py)? v{version}(?:\r?\n{version})?\r?\n?",
                version_output) is None:
            raise RuntimeError(f"esptool {ESPTOOL_VERSION} is required")

        generator_source = Path(args.generator_source).resolve() if args.generator_source else None
        if generator_source is None:
            located = checked(run, [args.python, "-c", "import inspect; import "
                "esp_idf_nvs_partition_gen.nvs_partition_gen as n; print(inspect.getfile(n))"])
            generator_source = Path(located.strip())
        nvs_tool = args.nvs_tool
        if not nvs_tool:
            idf_path = os.environ.get("IDF_PATH")
            if not idf_path:
                raise RuntimeError("--nvs-tool or IDF_PATH is required")
            nvs_tool = str(Path(idf_path) / "components/nvs_flash/nvs_partition_tool/nvs_tool.py")

        with tempfile.TemporaryDirectory(prefix="whisper-provision-") as temporary:
            directory = Path(temporary)
            csv_path = directory / "provision.csv"
            bin_path = directory / "provision.bin"
            raw_generator = directory / "nvs_partition_gen.pinned.py"
            generator = directory / "nvs_partition_gen.py"
            verified_copy(generator_source, raw_generator, GENERATOR_SOURCE_SHA256)
            nvs_tool_source = Path(nvs_tool).resolve()
            for name, digest in NVS_TOOL_SOURCE_SHA256.items():
                source = nvs_tool_source if name == "nvs_tool.py" else nvs_tool_source.parent / name
                verified_copy(source, directory / name, digest)
            write_csv(csv_path, config, key)
            patched_generator(raw_generator, generator)
            checked(run, [args.python, str(generator), "generate", str(csv_path), str(bin_path),
                hex(NVS_SIZE)])
            if not bin_path.is_file() or bin_path.stat().st_size != NVS_SIZE:
                raise RuntimeError(f"generator did not produce exactly {NVS_SIZE:#x} bytes")
            checked(run, [args.python, str(directory / "nvs_tool.py"),
                "--integrity-check", "--dump", "none",
                str(bin_path)])

            common = esptool + ["--chip", CHIP, "--port", args.port, "--baud",
                str(config["baud"])]
            chip_output = checked(run, common + ["chip-id"])
            if "ESP32-S3" not in chip_output.upper():
                raise RuntimeError("connected target is not ESP32-S3")
            flash_output = checked(run, common + ["flash-id"])
            if re.search(r"(?:detected )?flash size:\s*8\s*MB\b", flash_output,
                    re.IGNORECASE) is None:
                raise RuntimeError("connected ESP32-S3 does not report 8 MB flash")

            receipt = {
                "schema": PROVISIONING_SCHEMA, "target": "ESP32-S3", "port": args.port,
                "baud": config["baud"], "device_id": config["device_id"],
                "key_epoch": config["key_epoch"], "key_file": str(config["key_output"]),
                "key_format": "raw-aes-256", "key_sha256": hashlib.sha256(key).hexdigest(),
                "ssid": config["ssid"], "probe_port": config["probe_port"],
                "collector_ip": config["collector_ip"],
                "collector_port": config["collector_port"],
                "capability_digest": config["capability_digest"].hex(),
                "nvs_offset": NVS_OFFSET, "nvs_size": NVS_SIZE,
                "esptool_version": ESPTOOL_VERSION, "flash_status": "prepared",
                "verified": False,
            }
            persist_prepared(config, key, receipt)
            reserved.clear()
            checked(run, common + ["write-flash", hex(NVS_OFFSET), str(bin_path)])
            checked(run, common + ["verify-flash", hex(NVS_OFFSET), str(bin_path)])
            receipt["flash_status"] = "verified"
            receipt["verified"] = True
            finalize_receipt(config["receipt_output"], receipt)
        print(f"Provisioned ESP32-S3; receipt: {config['receipt_output']}")
        return receipt
    except BaseException:
        for output in reserved:
            try:
                output.unlink()
            except FileNotFoundError:
                pass
        raise


def parser():
    result = argparse.ArgumentParser(description="Provision World native-frame ESP32-S3 NVS")
    result.add_argument("--port", required=True)
    result.add_argument("--device-id", required=True, help="u64; decimal or 0x-prefixed")
    result.add_argument("--key-epoch", required=True, help="nonzero u16")
    result.add_argument("--ssid", required=True)
    result.add_argument("--probe-port", required=True)
    result.add_argument("--collector-ip", required=True)
    result.add_argument("--collector-port", required=True)
    result.add_argument("--capability-digest", required=True)
    result.add_argument("--key-output", required=True)
    result.add_argument("--receipt-output", required=True)
    result.add_argument("--baud", default=str(DEFAULT_BAUD))
    result.add_argument("--python", default=sys.executable)
    result.add_argument("--esptool", help="esptool 5.3.1 script; default: Python module")
    result.add_argument("--generator-source", help="ESP-IDF 5.4 generator module source")
    result.add_argument("--nvs-tool", help="ESP-IDF 5.4 nvs_tool.py path")
    return result


def main():
    args = parser().parse_args()
    password = getpass.getpass("Wi-Fi password (empty for open network): ")
    try:
        provision(args, password)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
