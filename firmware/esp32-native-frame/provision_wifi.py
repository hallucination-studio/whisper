#!/usr/bin/env python3
"""Adapt a fixed development fixture to local macOS Wi-Fi provisioning."""

from contextlib import redirect_stderr, redirect_stdout
import fnmatch
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import provision


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
BUILD_DIRECTORY = SCRIPT_DIRECTORY / "build"
PROVISION_TOOLS_DIRECTORY = BUILD_DIRECTORY / "provision-tools"
NVS_TOOL = PROVISION_TOOLS_DIRECTORY / "nvs-partition-tool" / "nvs_tool.py"
SERIAL_PATTERNS = ("cu.usbserial-*", "cu.usbmodem*")
FIXTURE_FACTS = (
    "WHISPER_FIXTURE_SENSOR_ID",
    "WHISPER_FIXTURE_DEVICE_ID",
    "WHISPER_FIXTURE_KEY_EPOCH",
    "WHISPER_FIXTURE_FIRMWARE_BUILD_DIGEST",
    "WHISPER_FIXTURE_CAPABILITY_DIGEST",
    "WHISPER_FIXTURE_CAPTURE_IP",
    "WHISPER_FIXTURE_CAPTURE_PORT",
)
SYSTEM_PROFILER = "/usr/sbin/system_profiler"
MACOS_REDACTED_SSID = "<SSID Redacted>"
IOREG = "/usr/sbin/ioreg"


class AdapterError(RuntimeError):
    """Report one redacted operating-system or build validation failure."""


def checked(arguments, *, run=subprocess.run):
    """Run one non-secret helper command without exposing inherited standard input."""
    result = run(
        [str(argument) for argument in arguments],
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise AdapterError("operational command failed")
    return result.stdout or ""


def run_optional(arguments, *, run=subprocess.run):
    """Return output for a successful optional command, otherwise no value."""
    try:
        result = run(
            [str(argument) for argument in arguments],
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    return result.stdout if result.returncode == 0 else None


def require_commands(*names):
    """Require preinstalled commands without attempting installation."""
    if any(shutil.which(name) is None for name in names):
        raise AdapterError("required provisioning command is unavailable")


def require_tty():
    """Require a controlling terminal for hidden fallback prompts."""
    descriptor = os.open("/dev/tty", os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    os.close(descriptor)


def fixture_fact(environment, name):
    """Read one required fact validated by the Host fixture interface."""
    value = environment.get(name, "")
    if not value:
        raise AdapterError("validated fixture facts are unavailable")
    return value


def discover_serial_port(device_root=Path("/dev")):
    """Return the sole character device matching supported ESP32 serial adapters."""
    candidates = []
    try:
        entries = device_root.iterdir()
        for path in entries:
            if not any(fnmatch.fnmatchcase(path.name, pattern) for pattern in SERIAL_PATTERNS):
                continue
            if stat.S_ISCHR(path.lstat().st_mode):
                candidates.append(path)
    except OSError as error:
        raise AdapterError("serial discovery failed") from error
    if len(candidates) != 1:
        raise AdapterError("serial discovery was ambiguous")
    return candidates[0]


def resolve_wifi_interface():
    """Resolve the Mac interface assigned to the Wi-Fi hardware port."""
    output = run_optional(["networksetup", "-listallhardwareports"])
    interfaces = []
    if output is not None:
        lines = output.splitlines()
        for index, line in enumerate(lines[:-1]):
            if line.strip() != "Hardware Port: Wi-Fi":
                continue
            name, separator, value = lines[index + 1].partition(":")
            if separator and name.strip() == "Device" and value.strip():
                interfaces.append(value.strip())
    if not interfaces:
        try:
            profile = json.loads(checked([SYSTEM_PROFILER, "SPAirPortDataType", "-json"]))
            sections = profile["SPAirPortDataType"]
            for section in sections:
                for interface in section.get("spairport_airport_interfaces", []):
                    name = interface.get("_name")
                    if isinstance(name, str) and name:
                        interfaces.append(name)
        except (KeyError, TypeError, ValueError) as error:
            raise AdapterError("Wi-Fi interface discovery failed") from error
    interfaces = list(dict.fromkeys(interfaces))
    if len(interfaces) != 1:
        raise AdapterError("Wi-Fi interface discovery failed")
    return interfaces[0]


def resolve_collector_ip(interface):
    """Return the usable IPv4 address currently assigned to the Wi-Fi interface."""
    output = run_optional(["ipconfig", "getifaddr", interface])
    values = [output.strip()] if output is not None and output.strip() else []
    if not values:
        details = checked(["ifconfig", interface])
        values = re.findall(r"^\s*inet\s+(\S+)", details, re.MULTILINE)
    if len(values) != 1:
        raise AdapterError("collector address discovery failed")
    try:
        address = ipaddress.ip_address(values[0])
    except ValueError as error:
        raise AdapterError("collector address discovery failed") from error
    if (
        address.version != 4
        or address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
    ):
        raise AdapterError("collector address discovery failed")
    return str(address)


def resolve_current_ssid(interface):
    """Return the associated SSID when macOS makes it available."""
    def usable(value):
        return bool(value) and value.casefold() != MACOS_REDACTED_SSID.casefold()

    output = run_optional(["networksetup", "-getairportnetwork", interface])
    if output is not None:
        prefix = "Current Wi-Fi Network: "
        line = output.rstrip("\r\n")
        if line.startswith(prefix):
            ssid = line[len(prefix):]
            if usable(ssid):
                return ssid
    output = run_optional([IOREG, "-l"])
    if output is None:
        return None
    encoded = re.findall(r'"IO80211SSID"\s*=\s*("(?:\\.|[^"\\])*")', output)
    values = []
    for value in encoded:
        try:
            decoded = json.loads(value)
        except ValueError:
            continue
        if isinstance(decoded, str) and usable(decoded):
            values.append(decoded)
    values = list(dict.fromkeys(values))
    return values[0] if len(values) == 1 else None


def resolve_keychain_password(ssid):
    """Return the saved AirPort password when Keychain permits access."""
    output = run_optional([
        "security",
        "find-generic-password",
        "-D",
        "AirPort network password",
        "-a",
        ssid,
        "-w",
    ])
    return None if output is None else output.rstrip("\r\n")


def validate_capture_route(configured_ip, collector_ip):
    """Require the fixed Host listener to accept the discovered collector address."""
    try:
        configured = ipaddress.ip_address(configured_ip)
        collector = ipaddress.ip_address(collector_ip)
    except ValueError as error:
        raise AdapterError("configured capture route is invalid") from error
    if configured.version != 4 or collector.version != 4:
        raise AdapterError("configured capture route is invalid")
    if not configured.is_unspecified and configured != collector:
        raise AdapterError("configured capture route does not match Wi-Fi")


def execute(environment=os.environ, key_stream=None):
    """Refresh one fixed development fixture using local network facts."""
    require_commands("ifconfig")
    facts = {name: fixture_fact(environment, name) for name in FIXTURE_FACTS}
    if facts["WHISPER_FIXTURE_SENSOR_ID"] != "sensor-a":
        raise AdapterError("fixed development Sensor does not match")
    port = discover_serial_port()
    interface = resolve_wifi_interface()
    collector_ip = resolve_collector_ip(interface)
    validate_capture_route(facts["WHISPER_FIXTURE_CAPTURE_IP"], collector_ip)

    ssid = resolve_current_ssid(interface)
    if ssid is None:
        require_tty()
        ssid = getpass.getpass("Wi-Fi SSID: ")
    password = resolve_keychain_password(ssid)
    if password is None:
        require_tty()
        password = getpass.getpass("Wi-Fi password: ")

    arguments = provision.parser().parse_args([
        "--port",
        str(port),
        "--device-id",
        facts["WHISPER_FIXTURE_DEVICE_ID"],
        "--key-epoch",
        facts["WHISPER_FIXTURE_KEY_EPOCH"],
        "--ssid",
        ssid,
        "--probe-port",
        facts["WHISPER_FIXTURE_CAPTURE_PORT"],
        "--collector-ip",
        collector_ip,
        "--collector-port",
        facts["WHISPER_FIXTURE_CAPTURE_PORT"],
        "--capability-digest",
        facts["WHISPER_FIXTURE_CAPABILITY_DIGEST"],
        "--nvs-tool",
        str(NVS_TOOL),
        "--key-stdin",
    ])
    inherited = key_stream if key_stream is not None else sys.stdin.buffer
    with open(os.devnull, "w", encoding="utf-8") as sink, \
            redirect_stdout(sink), redirect_stderr(sink):
        provision.provision(arguments, password, key_stream=inherited)


def main():
    """Run the redacted adapter command."""
    try:
        execute()
    except KeyboardInterrupt:
        print("provisioning failed", file=sys.stderr)
        return 130
    except (AdapterError, OSError, RuntimeError, ValueError):
        print("provisioning failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
