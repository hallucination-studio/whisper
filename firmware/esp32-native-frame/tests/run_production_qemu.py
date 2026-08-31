#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
PROVISION_SPEC = importlib.util.spec_from_file_location(
    "whisper_firmware_provision", PROJECT / "provision.py")
provision = importlib.util.module_from_spec(PROVISION_SPEC)
PROVISION_SPEC.loader.exec_module(provision)


def provisioning_config(capability_digest, device_id, key_epoch):
    return {
        "device_id": device_id,
        "key_epoch": key_epoch,
        "ssid": "native-frame-test",
        "password": "test-only-password",
        "probe_port": 9000,
        "collector_ip": "192.0.2.10",
        "collector_port": 9000,
        "capability_digest": capability_digest,
    }


def write_provisioning(path, key, capability_digest, device_id, key_epoch):
    provision.write_csv(
        path,
        provisioning_config(capability_digest, device_id, key_epoch),
        key,
    )


def consume_runtime_key(stream):
    return provision.consume_inherited_key(stream)


def run(command, *, cwd=None, timeout=None):
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return subprocess.CompletedProcess(command, 124, output)


def main():
    key = consume_runtime_key(sys.stdin.buffer)
    build = PROJECT / "build"
    idf_path = Path(os.environ["IDF_PATH"])
    device_id = provision.bounded_int(
        "device ID", os.environ["WHISPER_FIXTURE_DEVICE_ID"], 0, (1 << 64) - 1)
    key_epoch = provision.bounded_int(
        "key epoch", os.environ["WHISPER_FIXTURE_KEY_EPOCH"], 1, 65535)
    with (build / "flasher_args.json").open(encoding="utf-8") as source:
        flasher = json.load(source)
    with (build / "capability-build-facts.json").open(encoding="utf-8") as source:
        facts = json.load(source)

    image_info = run([
        sys.executable, "-m", "esptool", "image_info", "--version", "2",
        str(build / flasher["app"]["file"]),
    ])
    match = re.search(r"Validation hash: ([0-9a-f]{64}) \(valid\)", image_info.stdout)
    if image_info.returncode != 0 or match is None:
        sys.stdout.write(image_info.stdout)
        return 1
    build_digest = bytes.fromhex(match.group(1))

    abi_files = [
        idf_path / "components/esp_wifi/include/esp_wifi_types_generic.h",
        idf_path / "components/esp_wifi/include/local/esp_wifi_types_native.h",
    ]
    framed = bytearray(b"esp-idf-wifi-csi-abi-v1\0")
    for source in abi_files:
        data = source.read_bytes()
        framed.extend(struct.pack("<Q", len(data)))
        framed.extend(data)
    abi_digest = hashlib.sha256(framed).digest()
    generated_header = (build / "esp-idf/main/capability_build_facts.h").read_text(encoding="ascii")
    header_digest = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})", generated_header))
    if abi_digest.hex() != facts["idf_wifi_abi_digest"] or header_digest != abi_digest:
        return 1
    capability_digest = provision.capability_digest(build_digest, abi_digest).hex()

    with tempfile.TemporaryDirectory(prefix="native-frame-qemu-") as temporary:
        temporary = Path(temporary)
        generator = idf_path / "components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py"
        qemu = idf_path.parent / "tools/qemu-xtensa/esp_develop_9.0.0_20240606/qemu/bin/qemu-system-xtensa"
        valid_csv = temporary / "valid.csv"
        write_provisioning(
            valid_csv,
            key,
            bytes.fromhex(capability_digest),
            device_id,
            key_epoch,
        )

        def boot(name, digest, provision_csv=None):
            if provision_csv is None:
                provision_csv = temporary / f"{name}.csv"
                write_provisioning(
                    provision_csv,
                    key,
                    bytes.fromhex(digest),
                    device_id,
                    key_epoch,
                )
            provision_bin = temporary / f"{name}.bin"
            flash = temporary / f"{name}-flash.bin"
            generated = run([
                sys.executable, str(generator), "generate",
                str(provision_csv), str(provision_bin), "0x7000",
            ])
            if generated.returncode != 0:
                return generated.stdout
            files = []
            for offset, relative in flasher["flash_files"].items():
                files.extend([offset, str(build / relative)])
            files.extend(["0x11000", str(provision_bin)])
            merged = run([
                sys.executable, "-m", "esptool", "--chip", "esp32s3", "merge_bin",
                "--flash_mode", flasher["flash_settings"]["flash_mode"],
                "--flash_freq", flasher["flash_settings"]["flash_freq"],
                "--flash_size", flasher["flash_settings"]["flash_size"],
                "--fill-flash-size", "8MB", "-o", str(flash), *files,
            ])
            if merged.returncode != 0:
                return merged.stdout
            return run([
                str(qemu), "-nographic", "-machine", "esp32s3",
                "-drive", f"file={flash},if=mtd,format=raw",
            ], timeout=15).stdout

        output = boot("valid", capability_digest, valid_csv)
        accepted = "provisioning accepted; boot generation 1; awaiting network prerequisites"
        if accepted not in output or "runtime startup failed" in output:
            sys.stdout.write(output)
            return 1
        mismatch = boot("mismatch", "00" * 32)
        if accepted in mismatch or "runtime startup failed" not in mismatch:
            sys.stdout.write(mismatch)
            return 1

    print("PRODUCTION_CAPABILITY_BINDING_QEMU_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
