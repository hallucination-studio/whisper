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
CONFIG_PATH="$SCRIPT_DIRECTORY/development.toml"
ADAPTER_PATH="$SCRIPT_DIRECTORY/provision_wifi.py"
WHISPER_BINARY="$REPOSITORY_ROOT/target/release/whisper"

if [[ ! -x "$WHISPER_BINARY" || ! -r "$CONFIG_PATH" || ! -r "$ADAPTER_PATH" ]] \
    || ! command -v python3 >/dev/null 2>&1; then
  fail
fi

cd -- "$REPOSITORY_ROOT" || fail
"$WHISPER_BINARY" \
  development-fixture "$CONFIG_PATH" sensor-a \
  python3 "$ADAPTER_PATH" \
  >/dev/null 2>&1
status=$?
if (( status != 0 )); then
  fail "$status"
fi

printf 'Wi-Fi provisioning complete.\n'
