#!/usr/bin/env python3
"""Bind the fixed development Config template to one prebuilt application."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

import provision


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
BUILD_DIRECTORY = SCRIPT_DIRECTORY / "build"
TEMPLATE_PATH = SCRIPT_DIRECTORY / "development.template.toml"
OUTPUT_PATH = BUILD_DIRECTORY / "development.toml"
APPLICATION_PATH = BUILD_DIRECTORY / "esp32_native_frame.bin"
CAPABILITY_FACTS_PATH = BUILD_DIRECTORY / "capability-build-facts.json"
ZERO_DIGEST = "00" * 32


class ConfigBuildError(RuntimeError):
    """Report an invalid template or incompatible firmware build."""


def load_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ConfigBuildError("firmware build facts are unavailable") from error
    if not isinstance(value, dict):
        raise ConfigBuildError("firmware build facts are invalid")
    return value


def replace_digest(source, name, digest):
    pattern = rf'(?m)^({re.escape(name)}\s*=\s*)"{ZERO_DIGEST}"\s*$'
    updated, count = re.subn(pattern, rf'\1"{digest}"', source)
    if count != 1:
        raise ConfigBuildError("development Config template is invalid")
    return updated


def prepare(template_path, output_path, application_path, capability_facts_path, *,
            run=subprocess.run):
    """Write one Config containing fixed identity and verified build facts."""
    try:
        source = template_path.read_text(encoding="utf-8")
        template = tomllib.loads(source)
        application_path.read_bytes()
        sensors = template["sensors"]
        sensor = sensors[0]
    except (OSError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
        raise ConfigBuildError("development Config inputs are invalid") from error
    if (
        len(sensors) != 1
        or sensor.get("id") != "sensor-a"
        or sensor.get("device_id") != 1
        or sensor.get("key_epoch") != 1
        or sensor.get("firmware_build_digest") != ZERO_DIGEST
        or sensor.get("capability_digest") != ZERO_DIGEST
    ):
        raise ConfigBuildError("development Config template is invalid")

    facts = load_json(capability_facts_path)
    try:
        abi_value = facts["idf_wifi_abi_digest"]
        if not isinstance(abi_value, str) or re.fullmatch(r"[0-9a-f]{64}", abi_value) is None:
            raise ValueError("invalid Wi-Fi ABI digest")
        abi_digest = bytes.fromhex(abi_value)
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigBuildError("firmware capability facts are invalid") from error
    result = run(
        [sys.executable, "-m", "esptool", "image-info", str(application_path)],
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise ConfigBuildError("application image validation failed")
    match = re.search(r"Validation hash: ([0-9a-f]{64}) \(valid\)", result.stdout or "")
    if match is None:
        raise ConfigBuildError("application image validation failed")
    build_digest = match.group(1)
    capability_digest = provision.capability_digest(
        bytes.fromhex(build_digest), abi_digest).hex()
    generated = replace_digest(source, "firmware_build_digest", build_digest)
    generated = replace_digest(generated, "capability_digest", capability_digest)

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output_path.name}.", dir=output_path.parent)
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(generated)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, output_path)
    except OSError as error:
        raise ConfigBuildError("development Config could not be written") from error
    finally:
        if "temporary" in locals():
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def main():
    try:
        prepare(
            TEMPLATE_PATH,
            OUTPUT_PATH,
            APPLICATION_PATH,
            CAPABILITY_FACTS_PATH,
        )
    except ConfigBuildError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
