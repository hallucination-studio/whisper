#!/usr/bin/env bash
set -uo pipefail

fail() {
  printf 'Wi-Fi provisioning failed.\n' >&2
  exit "${1:-1}"
}

if (( $# != 0 )); then
  fail 2
fi

SCRIPT_DIRECTORY=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || fail
REPOSITORY_ROOT=$(cd -- "$SCRIPT_DIRECTORY/../.." && pwd -P) || fail
CONFIG_PATH="$SCRIPT_DIRECTORY/build/development.toml"
ADAPTER_PATH="$SCRIPT_DIRECTORY/provision_wifi.py"
WHISPER_BINARY="$REPOSITORY_ROOT/target/release/whisper"
PROVISION_TOOLS_DIRECTORY="$SCRIPT_DIRECTORY/build/provision-tools"
PROVISION_PYTHON="$PROVISION_TOOLS_DIRECTORY/venv/bin/python"
NVS_PARTITION_TOOL_DIRECTORY="$PROVISION_TOOLS_DIRECTORY/nvs-partition-tool"

if [[ ! -x "$WHISPER_BINARY" || ! -r "$CONFIG_PATH" || ! -r "$ADAPTER_PATH" \
    || ! -x "$PROVISION_PYTHON" \
    || ! -r "$NVS_PARTITION_TOOL_DIRECTORY/nvs_tool.py" \
    || ! -r "$NVS_PARTITION_TOOL_DIRECTORY/nvs_check.py" \
    || ! -r "$NVS_PARTITION_TOOL_DIRECTORY/nvs_logger.py" \
    || ! -r "$NVS_PARTITION_TOOL_DIRECTORY/nvs_parser.py" ]]; then
  fail
fi

cd -- "$REPOSITORY_ROOT" || fail
"$WHISPER_BINARY" \
  development-fixture "$CONFIG_PATH" sensor-a \
  "$PROVISION_PYTHON" "$ADAPTER_PATH" \
  >/dev/null 2>&1
status=$?
if (( status != 0 )); then
  fail "$status"
fi

printf 'Wi-Fi provisioning complete.\n'
