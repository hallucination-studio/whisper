#!/usr/bin/env python3
"""Behavior tests for the zero-argument Wi-Fi provisioning Shell."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest


PROJECT = Path(__file__).resolve().parents[3]
SCRIPT = PROJECT / "firmware" / "esp32-native-frame" / "provision-wifi.sh"


class ProvisionWifiShellTests(unittest.TestCase):
    def write_executable(self, path, source):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def staged_shell(self, root, helper_exit=0):
        firmware = root / "firmware" / "esp32-native-frame"
        firmware.mkdir(parents=True)
        staged = firmware / SCRIPT.name
        shutil.copy2(SCRIPT, staged)
        (firmware / "development.toml").write_text("fixed development config\n", encoding="utf-8")
        shutil.copy2(SCRIPT.parent / "provision_wifi.py", firmware / "provision_wifi.py")
        shutil.copy2(SCRIPT.parent / "provision.py", firmware / "provision.py")
        helper = root / "target" / "release" / "whisper"
        self.write_executable(helper, f"""
            #!/usr/bin/env python3
            import json, os, pathlib, sys
            pathlib.Path(os.environ["FIXTURE_RECORD"]).write_text(
                json.dumps(sys.argv[1:]), encoding="utf-8")
            print("Private Lab SSID / /dev/cu.private / 192.0.2.44")
            print("internal fixture failure with identity 42", file=sys.stderr)
            raise SystemExit({helper_exit})
        """)
        return staged

    def staged_public_adapter_shell(self, root):
        staged = self.staged_shell(root)
        helper = root / "target" / "release" / "whisper"
        self.write_executable(helper, """
            #!/usr/bin/env python3
            import importlib.util, io, json, os, pathlib, sys
            from unittest import mock

            adapter_path = pathlib.Path(sys.argv[5])
            sys.path.insert(0, str(adapter_path.parent))
            spec = importlib.util.spec_from_file_location("public_adapter", adapter_path)
            adapter = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(adapter)
            mode = os.environ["PUBLIC_WIFI_MODE"]
            calls = []
            prompts = []
            tty_checks = []

            def observed(name, value):
                calls.append(name)
                return value

            def hidden_prompt(prompt):
                prompts.append(prompt)
                return {
                    "missing-ssid": "Prompted SSID",
                    "missing-password": "Prompted Password",
                }[mode]

            def capture(arguments, password, *, key_stream):
                expected_ssid = "Prompted SSID" if mode == "missing-ssid" else "Auto SSID"
                expected_password = (
                    "Prompted Password" if mode == "missing-password" else "Auto Password"
                )
                calls.append("provision")
                checks.update({
                    "fixed_facts": (
                        arguments.device_id == "1"
                        and arguments.key_epoch == "1"
                        and arguments.probe_port == "9000"
                        and arguments.collector_port == "9000"
                    ),
                    "discovered_facts": (
                        arguments.port == "/dev/cu.test"
                        and arguments.collector_ip == "192.0.2.44"
                    ),
                    "wifi_values": (
                        arguments.ssid == expected_ssid and password == expected_password
                    ),
                    "inherited_key": key_stream.read() == bytes(range(32)),
                })

            checks = {
                "fixed_invocation": (
                    sys.argv[1] == "development-fixture"
                    and pathlib.Path(sys.argv[2]).name == "development.toml"
                    and sys.argv[3:5] == ["sensor-a", "python3"]
                )
            }
            environment = {
                "WHISPER_FIXTURE_SENSOR_ID": "sensor-a",
                "WHISPER_FIXTURE_DEVICE_ID": "1",
                "WHISPER_FIXTURE_KEY_EPOCH": "1",
                "WHISPER_FIXTURE_FIRMWARE_BUILD_DIGEST": "01" * 32,
                "WHISPER_FIXTURE_CAPABILITY_DIGEST": "02" * 32,
                "WHISPER_FIXTURE_CAPTURE_IP": "0.0.0.0",
                "WHISPER_FIXTURE_CAPTURE_PORT": "9000",
            }
            ssid = None if mode == "missing-ssid" else "Auto SSID"
            password = None if mode == "missing-password" else "Auto Password"
            with mock.patch.object(adapter, "require_commands",
                                   side_effect=lambda *_names: calls.append("commands")), \
                    mock.patch.object(adapter, "require_tty",
                                      side_effect=lambda: tty_checks.append(True)), \
                    mock.patch.object(adapter, "discover_serial_port",
                                      side_effect=lambda: observed(
                                          "serial", pathlib.Path("/dev/cu.test"))), \
                    mock.patch.object(adapter, "resolve_wifi_interface",
                                      side_effect=lambda: observed("interface", "en0")), \
                    mock.patch.object(adapter, "resolve_collector_ip",
                                      side_effect=lambda _interface: observed(
                                          "collector", "192.0.2.44")), \
                    mock.patch.object(adapter, "resolve_current_ssid",
                                      side_effect=lambda _interface: observed("ssid", ssid)), \
                    mock.patch.object(adapter, "resolve_keychain_password",
                                      side_effect=lambda _ssid: observed("password", password)), \
                    mock.patch.object(adapter, "validate_capture_route",
                                      side_effect=lambda *_values: calls.append("route")), \
                    mock.patch.object(adapter, "validate_build_and_board",
                                      side_effect=lambda *_values: calls.append("build-board")), \
                    mock.patch.object(adapter.getpass, "getpass", side_effect=hidden_prompt), \
                    mock.patch.object(adapter.provision, "provision", side_effect=capture):
                adapter.execute(environment, io.BytesIO(bytes(range(32))))

            checks.update({
                "automatic_discovery": all(
                    name in calls
                    for name in ("serial", "interface", "collector", "ssid", "password")
                ),
                "tty_checks": len(tty_checks),
                "prompts": prompts,
                "provision_called": calls.count("provision") == 1,
            })
            pathlib.Path(os.environ["FIXTURE_RECORD"]).write_text(
                json.dumps(checks), encoding="utf-8")
        """)
        return staged

    def run_shell(self, script, *arguments, environment_overrides=None):
        record = script.parents[2] / "fixture-record.json"
        environment = os.environ.copy()
        environment["FIXTURE_RECORD"] = str(record)
        environment.update(environment_overrides or {})
        result = subprocess.run(
            [str(script), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            check=False,
        )
        return result, record

    def test_success_uses_fixed_config_and_prints_only_stable_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self.staged_shell(root)

            result, record = self.run_shell(script)

            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(result.stdout, "Wi-Fi provisioning complete.\n")
            canonical_root = root.resolve()
            self.assertEqual(json.loads(record.read_text(encoding="utf-8")), [
                "development-fixture",
                str(canonical_root / "firmware" / "esp32-native-frame" / "development.toml"),
                "sensor-a",
                "python3",
                str(canonical_root / "firmware" / "esp32-native-frame" / "provision_wifi.py"),
            ])

    def test_downstream_failure_is_redacted_and_propagated(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = self.staged_shell(Path(temporary), helper_exit=1)

            result, _record = self.run_shell(script)

            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "Wi-Fi provisioning failed.\n")

    def test_arguments_fail_without_starting_the_prebuilt_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self.staged_shell(root)

            result, record = self.run_shell(script, "unexpected")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "Wi-Fi provisioning failed.\n")
            self.assertFalse(record.exists())

    def test_missing_prebuilt_helper_fails_without_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self.staged_shell(root)
            (root / "target" / "release" / "whisper").unlink()

            result, record = self.run_shell(script)

            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "Wi-Fi provisioning failed.\n")
            self.assertFalse(record.exists())

    def test_public_command_runs_real_adapter_auto_and_single_fallback_paths(self):
        cases = (
            ("automatic", 0, []),
            ("missing-ssid", 1, ["Wi-Fi SSID: "]),
            ("missing-password", 1, ["Wi-Fi password: "]),
        )
        for mode, tty_checks, prompts in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                script = self.staged_public_adapter_shell(Path(temporary))

                result, record = self.run_shell(
                    script, environment_overrides={"PUBLIC_WIFI_MODE": mode})

                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "Wi-Fi provisioning complete.\n")
                checks = json.loads(record.read_text(encoding="utf-8"))
                for name in (
                    "fixed_invocation",
                    "fixed_facts",
                    "discovered_facts",
                    "wifi_values",
                    "inherited_key",
                    "automatic_discovery",
                    "provision_called",
                ):
                    self.assertTrue(checks[name], name)
                self.assertEqual(checks["tty_checks"], tty_checks)
                self.assertEqual(checks["prompts"], prompts)

    def test_public_shell_does_not_invoke_build_install_or_cache_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self.staged_shell(root)
            commands = root / "forbidden-commands"
            marker = root / "forbidden-command-invoked"
            for command in ("cargo", "docker", "pip", "pip3", "make", "idf.py"):
                self.write_executable(commands / command, """
                    #!/usr/bin/env bash
                    printf 'invoked' > "$FORBIDDEN_COMMAND_RECORD"
                    exit 99
                """)

            result, _record = self.run_shell(script, environment_overrides={
                "FORBIDDEN_COMMAND_RECORD": str(marker),
                "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}",
            })

            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(result.stdout, "Wi-Fi provisioning complete.\n")
            self.assertFalse(marker.exists())

if __name__ == "__main__":
    unittest.main()
