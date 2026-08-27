#!/usr/bin/env python3
import csv
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


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
    project = Path(__file__).resolve().parent.parent
    build = project / "build"
    idf_path = Path(os.environ["IDF_PATH"])
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
    descriptor = bytes([1, 1, 1, 1, 1, 1, 1, 32, 0x07])
    descriptor += struct.pack("<HHH", 612, 705, 1200) + build_digest + abi_digest
    capability_digest = hashlib.sha256(descriptor).hexdigest()

    with tempfile.TemporaryDirectory(prefix="native-frame-qemu-") as temporary:
        temporary = Path(temporary)
        generator = idf_path / "components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py"
        qemu = idf_path.parent / "tools/qemu-xtensa/esp_develop_9.0.0_20240606/qemu/bin/qemu-system-xtensa"
        with (project / "tests/disposable-provision.csv").open(newline="", encoding="ascii") as source:
            rows = list(csv.reader(source))

        def boot(name, digest):
            provision_csv = temporary / f"{name}.csv"
            provision_bin = temporary / f"{name}.bin"
            flash = temporary / f"{name}-flash.bin"
            replaced = [row[:-1] + [digest] if row and row[0] == "cap_digest" else row for row in rows]
            with provision_csv.open("w", newline="", encoding="ascii") as output:
                csv.writer(output).writerows(replaced)
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

        output = boot("valid", capability_digest)
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
