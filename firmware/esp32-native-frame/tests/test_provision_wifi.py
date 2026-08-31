#!/usr/bin/env python3
"""Behavior tests for the macOS Wi-Fi provisioning adapter."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock


MODULE_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE_DIRECTORY))
try:
    import provision_wifi
finally:
    sys.path.pop(0)


class ProvisionWifiTests(unittest.TestCase):
    def fixture_environment(self):
        return {
            "WHISPER_FIXTURE_SENSOR_ID": "sensor-a",
            "WHISPER_FIXTURE_DEVICE_ID": "1",
            "WHISPER_FIXTURE_KEY_EPOCH": "1",
            "WHISPER_FIXTURE_FIRMWARE_BUILD_DIGEST": "01" * 32,
            "WHISPER_FIXTURE_CAPABILITY_DIGEST": (
                "e1b35c57ed78ff9a7c0ec3784a727ec7a977f59f97c3ec1ab054b773d60841f8"
            ),
            "WHISPER_FIXTURE_CAPTURE_IP": "0.0.0.0",
            "WHISPER_FIXTURE_CAPTURE_PORT": "9000",
        }

    def test_execute_passes_fixed_facts_and_discovered_network_to_provision(self):
        environment = self.fixture_environment()
        key_stream = io.BytesIO(bytes(range(32)))
        captured = []

        def capture(arguments, password, **kwargs):
            captured.append((arguments, password, kwargs["key_stream"]))

        with mock.patch.object(provision_wifi, "require_tty"), \
                mock.patch.object(provision_wifi, "require_commands"), \
                mock.patch.object(provision_wifi, "discover_serial_port",
                                  return_value=Path("/dev/cu.usbserial-private")), \
                mock.patch.object(provision_wifi, "resolve_wifi_interface", return_value="en0"), \
                mock.patch.object(provision_wifi, "resolve_current_ssid",
                                  return_value="Private Lab SSID"), \
                mock.patch.object(provision_wifi, "resolve_collector_ip",
                                  return_value="192.0.2.44"), \
                mock.patch.object(provision_wifi, "validate_capture_route"), \
                mock.patch.object(
                    provision_wifi, "run_optional",
                    side_effect=AssertionError("credential lookup must not run"),
                ), \
                mock.patch.object(provision_wifi.provision, "provision", side_effect=capture), \
                mock.patch.object(
                    provision_wifi.getpass, "getpass", return_value="Private Password",
                ) as prompt:
            provision_wifi.execute(environment, key_stream)

        prompt.assert_called_once_with("Wi-Fi password: ")
        self.assertEqual(len(captured), 1)
        arguments, password, inherited = captured[0]
        self.assertIs(inherited, key_stream)
        self.assertEqual(password, "Private Password")
        self.assertEqual(arguments.port, "/dev/cu.usbserial-private")
        self.assertEqual(arguments.device_id, "1")
        self.assertEqual(arguments.key_epoch, "1")
        self.assertEqual(arguments.ssid, "Private Lab SSID")
        self.assertFalse(hasattr(arguments, "wifi_country"))
        self.assertEqual(arguments.probe_port, "9000")
        self.assertEqual(arguments.collector_ip, "192.0.2.44")
        self.assertEqual(arguments.collector_port, "9000")
        self.assertEqual(arguments.capability_digest, environment[
            "WHISPER_FIXTURE_CAPABILITY_DIGEST"])
        self.assertEqual(
            Path(arguments.nvs_tool),
            provision_wifi.PROVISION_TOOLS_DIRECTORY / "nvs-partition-tool" / "nvs_tool.py",
        )
        self.assertIsNone(arguments.generator_source)
        self.assertTrue(arguments.key_stdin)
        self.assertIsNone(arguments.key_output)
        self.assertIsNone(arguments.receipt_output)

    def test_execute_prompts_for_missing_ssid_and_always_for_password(self):
        prompts = iter(["Private Lab SSID", "Private Password"])
        with mock.patch.object(provision_wifi, "require_tty"), \
                mock.patch.object(provision_wifi, "require_commands"), \
                mock.patch.object(provision_wifi, "discover_serial_port",
                                  return_value=Path("/dev/cu.usbserial-private")), \
                mock.patch.object(provision_wifi, "resolve_wifi_interface", return_value="en0"), \
                mock.patch.object(provision_wifi, "resolve_current_ssid", return_value=None), \
                mock.patch.object(provision_wifi, "resolve_collector_ip",
                                  return_value="192.0.2.44"), \
                mock.patch.object(provision_wifi, "validate_capture_route"), \
                mock.patch.object(provision_wifi.provision, "provision"), \
                mock.patch.object(provision_wifi.getpass, "getpass",
                                  side_effect=lambda _prompt: next(prompts)) as prompt:
            provision_wifi.execute(self.fixture_environment(), io.BytesIO(bytes(32)))

        self.assertEqual(prompt.call_args_list, [
            mock.call("Wi-Fi SSID: "),
            mock.call("Wi-Fi password: "),
        ])

    def test_execute_requires_terminal_before_prompting(self):
        with mock.patch.object(
                provision_wifi, "require_tty",
                side_effect=provision_wifi.AdapterError("interactive terminal required")), \
                mock.patch.object(provision_wifi, "require_commands"), \
                mock.patch.object(provision_wifi, "discover_serial_port",
                                  return_value=Path("/dev/cu.usbserial-private")), \
                mock.patch.object(provision_wifi, "resolve_wifi_interface", return_value="en0"), \
                mock.patch.object(provision_wifi, "resolve_collector_ip",
                                  return_value="192.0.2.44"), \
                mock.patch.object(provision_wifi, "validate_capture_route"), \
                mock.patch.object(provision_wifi, "resolve_current_ssid") as resolve_ssid, \
                mock.patch.object(provision_wifi.getpass, "getpass") as prompt, \
                mock.patch.object(provision_wifi.provision, "provision") as provision:
            with self.assertRaisesRegex(
                    provision_wifi.AdapterError, "interactive terminal required"):
                provision_wifi.execute(self.fixture_environment(), io.BytesIO(bytes(32)))

        resolve_ssid.assert_not_called()
        prompt.assert_not_called()
        provision.assert_not_called()

    def test_serial_discovery_requires_exactly_one_character_device(self):
        character = types.SimpleNamespace(
            name="cu.usbserial-1",
            lstat=lambda: types.SimpleNamespace(st_mode=stat.S_IFCHR),
        )
        regular = types.SimpleNamespace(
            name="cu.usbmodem2",
            lstat=lambda: types.SimpleNamespace(st_mode=stat.S_IFREG),
        )
        root = types.SimpleNamespace(iterdir=lambda: iter((character, regular)))
        self.assertIs(provision_wifi.discover_serial_port(root), character)

        for entries in ((), (character, character)):
            with self.subTest(count=len(entries)), self.assertRaises(
                    provision_wifi.AdapterError):
                provision_wifi.discover_serial_port(
                    types.SimpleNamespace(iterdir=lambda entries=entries: iter(entries)))

    def test_wifi_interface_and_collector_must_resolve_to_unicast_ipv4(self):
        hardware = "Hardware Port: Wi-Fi\nDevice: en0\n"
        with mock.patch.object(provision_wifi, "run_optional", return_value=hardware):
            self.assertEqual(provision_wifi.resolve_wifi_interface(), "en0")

        profile = json.dumps({
            "SPAirPortDataType": [{
                "spairport_airport_interfaces": [{"_name": "en0"}],
            }],
        })
        with mock.patch.object(provision_wifi, "run_optional", return_value=None), \
                mock.patch.object(provision_wifi, "checked", return_value=profile):
            self.assertEqual(provision_wifi.resolve_wifi_interface(), "en0")

        with mock.patch.object(provision_wifi, "run_optional", return_value="192.0.2.44\n"):
            self.assertEqual(provision_wifi.resolve_collector_ip("en0"), "192.0.2.44")

        with mock.patch.object(provision_wifi, "run_optional", return_value=None), \
                mock.patch.object(
                    provision_wifi, "checked",
                    return_value="en0: flags=0\n\tinet 192.0.2.44 netmask 0xffffff00\n"):
            self.assertEqual(provision_wifi.resolve_collector_ip("en0"), "192.0.2.44")

        for address in ("", "127.0.0.1", "169.254.1.2", "::1"):
            with self.subTest(address=address), \
                    mock.patch.object(provision_wifi, "run_optional", return_value=address), \
                    mock.patch.object(provision_wifi, "checked", return_value=""), \
                    self.assertRaises(provision_wifi.AdapterError):
                provision_wifi.resolve_collector_ip("en0")

    def test_current_ssid_is_best_effort(self):
        with mock.patch.object(
                provision_wifi, "run_optional",
                return_value="Current Wi-Fi Network: Private Lab SSID\n"):
            ssid = provision_wifi.resolve_current_ssid("en0")
        self.assertEqual(ssid, "Private Lab SSID")

        ioreg = '    "IO80211SSID" = "Private Lab SSID"\n'
        with mock.patch.object(provision_wifi, "run_optional", side_effect=[None, ioreg]):
            self.assertEqual(provision_wifi.resolve_current_ssid("en0"), "Private Lab SSID")

        redacted = "<SSID Redacted>"
        with mock.patch.object(
                provision_wifi, "run_optional",
                side_effect=[f"Current Wi-Fi Network: {redacted}\n", None]):
            self.assertIsNone(provision_wifi.resolve_current_ssid("en0"))
        with mock.patch.object(
                provision_wifi, "run_optional",
                side_effect=[None, f'    "IO80211SSID" = "{redacted}"\n']):
            self.assertIsNone(provision_wifi.resolve_current_ssid("en0"))

        with mock.patch.object(provision_wifi, "run_optional", return_value=None):
            self.assertIsNone(provision_wifi.resolve_current_ssid("en0"))

    def test_helper_subprocesses_cannot_read_inherited_key_stdin(self):
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, bytes(range(32)))
        os.close(write_descriptor)
        saved_stdin = os.dup(0)
        try:
            os.dup2(read_descriptor, 0)
            output = provision_wifi.checked([
                sys.executable, "-c", "import sys; print(len(sys.stdin.buffer.read()))",
            ])
        finally:
            os.dup2(saved_stdin, 0)
            os.close(saved_stdin)
            os.close(read_descriptor)

        self.assertEqual(output.strip(), "0")

    def test_main_redacts_all_downstream_failures(self):
        sentinel = "Private Lab SSID / Private Password / /dev/cu.private"
        for error in (
            provision_wifi.AdapterError(sentinel),
            RuntimeError(sentinel),
            ValueError(sentinel),
            OSError(sentinel),
        ):
            output = io.StringIO()
            errors = io.StringIO()
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(provision_wifi, "execute", side_effect=error), \
                    redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(provision_wifi.main(), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "provisioning failed\n")
            self.assertNotIn(sentinel, errors.getvalue())


if __name__ == "__main__":
    unittest.main()
