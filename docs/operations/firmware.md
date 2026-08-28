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

Set `IDF_IMAGE` to the immutable ESP-IDF container identity in the reference.
Set `PORT` only after identifying the candidate serial device. Keep raw AES
keys, Wi-Fi credentials, secret-bearing provisioning CSV or binary files, and
other raw secret artifacts outside the repository. Retain sanitized immutable
receipt metadata and non-secret evidence artifacts in the repository as
described under "Receipts".

## Build the production image

From the repository root:

```sh
docker run --rm \
  -v "$PWD:/project" \
  -w /project/firmware/esp32-native-frame \
  "$IDF_IMAGE" \
  bash -lc 'idf.py set-target esp32s3 && idf.py build'
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

After the production image build, run inside the same pinned container:

```sh
docker run --rm \
  -v "$PWD:/project" \
  -w /project/firmware/esp32-native-frame \
  "$IDF_IMAGE" \
  bash -lc 'python tests/run_production_qemu.py'
```

The expected success marker is
`PRODUCTION_CAPABILITY_BINDING_QEMU_PASS`. This procedure verifies application
and Wi-Fi ABI digest binding before network startup. It does not verify Wi-Fi
association, CSI callbacks, UDP transmission, physical flash, or host decode.

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
`flasher_args.json`. Use those generated values for `write-flash`, then use the
same offset/image pairs for `verify-flash`. Do not transcribe addresses from a
document or another project.

Record the exact expanded commands, serial port, baud, probe outputs,
`flasher_args.json`, image digests, write result, and verification result.

## Provision disposable development identity

Generate new output paths in a protected external directory. Never reuse a key
epoch after NVS erase. Invoke:

```sh
python firmware/esp32-native-frame/provision.py \
  --port "$PORT" \
  --device-id "$DEVICE_ID" \
  --key-epoch "$KEY_EPOCH" \
  --ssid "$SSID" \
  --bssid "$BSSID" \
  --channel "$CHANNEL" \
  --probe-port "$PROBE_PORT" \
  --collector-ip "$COLLECTOR_IP" \
  --collector-port "$COLLECTOR_PORT" \
  --capability-digest "$CAPABILITY_DIGEST" \
  --key-output "$KEY_FILE" \
  --receipt-output "$PROVISION_RECEIPT"
```

The script probes first, writes only the NVS partition, verifies the same
range, retains the raw 32-byte host key with restrictive permissions, and
finalizes a JSON receipt. If application and provisioning flashes are separate
operations, retain both receipts and their ordering.

## Network and live smoke

1. Reserve the station MAC at the exact peer IP admitted by the host
   configuration. Associate the board to the provisioned 2.4 GHz BSSID.
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

Each immutable receipt must include:

- UTC start and finish time;
- repository commit and dirty-state classification;
- target board and serial port;
- immutable tool/container identities;
- exact command or numbered procedure;
- input and output artifact paths plus SHA-256 digests;
- non-secret device, key-epoch, boot-generation, build, capability, partition,
  and host-configuration identities;
- exit status and unedited output or log path;
- explicit result for build, parity execution, QEMU, probe, write, verify,
  provisioning, live capture, and host decode.

Never retain AES keys, Wi-Fi passwords, secret-bearing provisioning artifacts,
or other raw secrets in a repository receipt. Sanitize immutable receipt
metadata and non-secret evidence artifacts, retain them in the repository, and
index both accepted and failed results in
[the firmware evidence index](../evidence/firmware.md).
