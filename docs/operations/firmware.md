# Firmware operations

This runbook owns build, parity, QEMU, provisioning, flash, verification, live
smoke, and receipt-retention procedures. It points to the
[native-frame v1 specification](../specs/native-frame-v1.md) for requirements
and to [the reference](../references/native-frame.md) for immutable external
tool identities.

No procedure below establishes success until its output and identified inputs
are retained as described under "Receipts".

## Prepare

Use a clean checkout at the commit under test. Record:

```sh
git rev-parse HEAD
git status --short
shasum -a 256 firmware/esp32-native-frame/sdkconfig.defaults \
  firmware/esp32-native-frame/partitions.csv
```

Set `PORT` only after identifying the candidate serial device. Keep raw AES
keys, Wi-Fi credentials, secret-bearing provisioning CSV or binary files, and
other raw secret artifacts outside the repository. Retain sanitized immutable
receipt metadata and non-secret evidence artifacts in the repository as
described under "Receipts".

## Build the production image

From the repository root, use the repository Makefile. It pins the official
Espressif container by immutable digest, builds the application, builds the
development-fixture-enabled Host, exports the official ESP-IDF NVS inspection
tools, and prepares a Host Python environment containing Espressif's pinned
`esptool` and NVS generator releases. It then combines the fixed
`development.template.toml` identity with the generated application and
capability digests in `build/development.toml`:

```sh
make esp32-native-frame
```

Retain the complete command output, container digest, `build/flasher_args.json`,
`build/capability-build-facts.json`, application image validation hash, and
partition-table digest. Confirm the generated target, flash size, partition
offsets, application digest, Wi-Fi ABI digest, capability digest, and maximum
datagram size against the specification.

## Build parity test source

The parity project consumes the frozen Rust vectors. It must not regenerate or
rewrite them to match firmware output.

```sh
docker run --rm \
  -v "$PWD:/project" \
  -w /project/firmware/esp32-native-frame/tests \
  "$IDF_IMAGE" \
  bash -lc 'idf.py set-target esp32s3 && idf.py build'
```

A successful build is not a parity execution result. Retain the build output
and any actual target or emulator execution output separately.

## Run production capability-binding QEMU

After the production image build, select a validated runtime configuration and
one configured Sensor. Its `capture.secret_root` must name an absent disposable
directory whose parent already exists. Run the non-default fixture facade from
the repository root; it creates and removes that secret root, validates the
derived key through the production Host loader, and gives the container only an
inherited input stream plus non-secret identity environment variables:

```sh
cargo run --quiet --features development-fixture -- \
  development-fixture "$QEMU_CONFIG" "$QEMU_SENSOR_ID" \
  docker run --rm -i \
    --env WHISPER_FIXTURE_DEVICE_ID \
    --env WHISPER_FIXTURE_KEY_EPOCH \
    -v "$PWD:/project" \
    -w /project/firmware/esp32-native-frame \
    "$IDF_IMAGE" \
    bash -lc 'python tests/run_production_qemu.py'
```

The expected success marker is
`PRODUCTION_CAPABILITY_BINDING_QEMU_PASS`. This procedure verifies application
and Wi-Fi ABI digest binding before network startup, plus the production Host
loader and inherited-stream provisioning composition. It retains no static key
CSV or disposable secret store. It does not verify Wi-Fi association, CSI
callbacks, UDP transmission, physical flash, or host decode.

## Probe the board

Use the esptool version identified in the reference. Run both probes before
every committed-state application flash:

```sh
python -m esptool version
python -m esptool --chip esp32s3 --port "$PORT" chip-id
python -m esptool --chip esp32s3 --port "$PORT" flash-id
```

Stop unless the primary version is the pinned version, the target reports
ESP32-S3, and flash reports 8 MB. A CP2102N serial adapter name is not board or
flash proof. Do not substitute a 4 MB layout, RuView image, display profile, or
different target.

## Flash and verify the application

Read offset/image pairs and flash settings from the production build's
`flasher_args.json` and use those generated values for `write-flash`. Treat
esptool's successful per-image write verification as the integrity result for
the complete generated flash set. Do not transcribe addresses from a document
or another project.

When an independent post-write identity check is required, run `verify-flash`
for the immutable application image. Do not require a post-boot byte comparison
for runtime-owned mutable partitions. In particular, the boot process may
legitimately update the initial OTA data, and provisioning replaces the NVS
partition. A mismatch between those current partition bytes and their initial
build artifacts is not an application-image verification failure.

Record the exact expanded commands, serial port, baud, probe outputs,
`flasher_args.json`, application-image digest, write result, and application
verification result.

## Fixed development Wi-Fi provisioning

Use the zero-argument command only after `make esp32-native-frame` has completed
and its application image has been flashed:

```sh
firmware/esp32-native-frame/provision-wifi.sh
```

The command uses the generated `build/development.toml` and its sole
`sensor-a` entry. It does not accept a Config path, Sensor, identity, epoch,
digest, port, serial path, collector address, or tool path. It discovers the
Mac Wi-Fi interface, collector IPv4 address, and sole supported serial
interface. It reads the current SSID when macOS makes it available, otherwise
it asks for the SSID through a hidden prompt. It always asks for the Wi-Fi
password through a hidden prompt and does not access macOS Keychain.

The command hands the fixed fixture key to `provision.py`, which probes the
ESP32-S3 and 8 MB flash, generates a fresh complete schema-2 NVS, overwrites
offset `0x11000`, and runs `verify-flash`. It does not compare or rewrite the
application image; flash the intended application before running this command.
Successful verification prints exactly `Wi-Fi provisioning complete.`.
Failures are redacted and fail closed.

The command uses only the fixed tools prepared under the firmware build
directory. It does not read `IDF_PATH` or accept any tool path. It does not
build the Host or firmware, flash the application, install tools, create a
virtual environment, pull a container image, manage a cache, or retain a key,
credential, or generated NVS.
The fixed `key_epoch = 1` is disposable: after the Sensor has transmitted under
that epoch, update the sole Config to a fresh epoch before provisioning again.
The command never creates or persists a second epoch counter.

## Legacy standalone provisioning (not Program 1)

Use this command only for bounded private smoke with disposable, non-real
inputs. Generate all output paths in a protected external directory. Never
reuse a key epoch after NVS erase. Invoke:

```sh
python firmware/esp32-native-frame/provision.py \
  --port "$PORT" \
  --device-id "$DEVICE_ID" \
  --key-epoch "$KEY_EPOCH" \
  --ssid "$SSID" \
  --probe-port "$PROBE_PORT" \
  --collector-ip "$COLLECTOR_IP" \
  --collector-port "$COLLECTOR_PORT" \
  --capability-digest "$CAPABILITY_DIGEST" \
  --key-output "$LEGACY_PRIVATE_KEY_FILE" \
  --receipt-output "$LEGACY_PRIVATE_OUTPUT"
```

Treat this command and all of its outputs as private and secret-bearing. Keep
them in protected external storage; do not add them to the repository or any
evidence package. Its JSON output is legacy private output, not a Program 1
`ProvisioningOperationRecord` or `ProvisioningReceipt`, and this command cannot
satisfy either artifact contract.

## Historical Program 1 provisioning references

The legacy command above cannot satisfy Program 1. Do not infer a replacement
command from this runbook. Follow the Host validation contract in
[persistence v1](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/specs/persistence-v1.md#program-1-development-secret-store),
the provisioning handoff contract in
[native-frame v1](../specs/native-frame-v1.md#provisioning-and-image-compatibility),
and the artifact contract in
[development E2E v1](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/specs/development-e2e-v1.md#provisioning-artifacts).
These are fixed historical clauses, not active Program work. New RF
implementation and evidence tasks are owned by
[Spec #163](https://github.com/hallucination-studio/whisper/issues/163). Existing
fixed-device acceptance does not execute flash, reprovisioning or configuration
changes from this runbook.

For the single-board development path, set both the firmware collector target
and the Host capture listener to UDP port `9000`. The firmware target is the
Mac IPv4 address on the interface attached to the board's Wi-Fi LAN; the Host
listener binds `0.0.0.0:9000` or that exact address. Loopback is not reachable
from the board.

## Network and live smoke

1. Reserve the station MAC at the exact peer IP admitted by the host
   configuration. Confirm that the board dynamically associated to the
   provisioned SSID on a 2.4 GHz channel.
2. Send bounded ordinary UDP traffic from the collector to the provisioned
   probe port. Do not interpret the probe payload as a native frame.
3. Retain the serial startup log showing application/build/capability identity,
   boot generation, association, probe-socket readiness, and CSI enablement.
4. Capture complete UDP datagrams plus peer and receive context at the collector.
   Preserve encrypted bytes; do not substitute console-decoded fields.
5. Pass a retained capabilities datagram and later CSI datagram through the
   production host admission and decode path. Record the exact host revision,
   configuration digests, non-secret pins, command, and classified result.
6. Confirm the decoded device epoch, source/link route, capture sequence,
   dynamic sample count, validity, I/Q mapping, and capability identity.

The current repository evidence index identifies whether an executable host
path exists. When it does not, stop at an encrypted capture and keep the live
gate open rather than replacing it with a synthetic decoder-only test.

## Failure and rotation

- On probe, digest, partition, flash, verify, association, capability, source,
  radio, or host-decode mismatch, stop and retain the failed receipt.
- After NVS erase, provision a fresh key epoch and reset host admission through
  its approved procedure; do not reuse the old key/generation pair.
- After changing image or Wi-Fi ABI inputs, generate new build and capability
  identities and update host pins before live admission.
- Do not edit frozen vectors or relax route pins to make an artifact pass.

## Receipts

For build, parity, QEMU, probe, flash, verification, live capture, and Host
decode, each immutable procedure receipt must include:

- UTC start and finish time;
- repository commit and dirty-state classification;
- target board and serial port;
- immutable tool/container identities;
- exact command or numbered procedure;
- input and output artifact paths plus SHA-256 digests;
- non-secret device, key-epoch, boot-generation, build, capability, partition,
  and host-configuration identities;
- exit status and unedited output or log path;
- explicit result for build, parity execution, QEMU, probe, write, verify, live
  capture, and host decode.

Never retain AES keys, Wi-Fi passwords, secret-bearing provisioning artifacts,
or other raw secrets in a repository receipt. Sanitize immutable receipt
metadata and non-secret evidence artifacts, retain them in the repository, and
index both accepted and failed results in
[the firmware evidence index](../evidence/firmware.md).
