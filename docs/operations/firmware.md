# Firmware operations

This runbook covers the fixed ESP32-S3 native-frame firmware while the RF Host
is being rebuilt. The native-frame v1 device and provisioning contracts remain
in force. RF-01 intentionally provides no Host-owned provisioning, capture,
serve, live-decode, or query command.

## Prepare

Use a clean checkout at the commit under test and record:

```sh
git rev-parse HEAD
git status --short
shasum -a 256 firmware/esp32-native-frame/sdkconfig.defaults \
  firmware/esp32-native-frame/partitions.csv
```

Keep AES keys, Wi-Fi credentials, provisioning CSV/BIN files, and other secret
artifacts outside the repository. Never reuse a key epoch after runtime storage
is erased.

## Build the production image

The default target builds only the firmware with the immutable Espressif
container identity recorded in the Makefile:

```sh
make esp32-native-frame
```

Retain the command output, container digest, generated `flasher_args.json`,
`capability-build-facts.json`, application validation hash, and partition-table
digest. Confirm the target, flash size, offsets, application digest, Wi-Fi ABI
digest, capability digest, and maximum datagram size against native-frame v1.

The independent `esp32-native-frame-provision-tools` target exports pinned
Espressif tooling. It does not generate a Host configuration or a runnable Host
provisioning flow.

## Build frozen-vector parity source

The parity application consumes checked-in native-frame vectors and must not
regenerate them to match firmware output:

```sh
docker run --rm \
  -v "$PWD:/project" \
  -w /project/firmware/esp32-native-frame/tests \
  espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb \
  bash -lc 'idf.py set-target esp32s3 && idf.py build'
```

A successful build is not a parity execution result. Retain actual target or
emulator execution separately.

## Probe, flash, and verify

Use the pinned esptool release and verify that the target is an ESP32-S3 with
8 MB flash. Read offset/image pairs and flash settings from the generated
`flasher_args.json`; do not transcribe another build's offsets. Treat complete
write verification and an independent application-image `verify-flash` as the
immutable checks. Runtime-owned OTA and NVS partitions may legitimately change.

Record exact commands, serial port, baud, probe output, flasher arguments,
application digest, write result, and verification result.

## Provisioning boundary during the hard rebuild

The firmware provisioning record, NVS layout, epoch-key rules, and low-level
`provision.py` implementation remain part of the fixed device boundary. Its
unit tests continue to verify schema, digest, image, key-transfer, and receipt
behavior.

RF-01 removes the former Host development-fixture composition. There is no
current repository command that safely selects a deployment key, generates a
Host-bound development configuration, provisions a board, and initializes Host
replay state as one operation. Do not revive the removed CLI or infer a new
workflow from historical revisions. The later Host Store work must compose the
preserved key loader, cryptographically bound replay identity, and provisioning
handoff under the new schema.

Direct manual use of `provision.py` is private operator work with protected
external inputs. It does not satisfy an end-to-end RF deployment or evidence
gate by itself.

## Live capture boundary

The repository preserves firmware emission plus Rust authentication, native
grammar, replay, and lossless native-CSI conformance tests. It intentionally has
no runnable Host in RF-01. A physical exercise therefore stops at retained
encrypted datagrams with peer and receive context. Keep the Host live-admission
gate open; do not replace it with decoder-only fixture evidence.

On target, digest, partition, flash, association, authentication, grammar, or
parity failure, stop and retain the failure. Do not edit frozen vectors, relax
identity binding, or reuse an old key/generation pair to make the run pass.

## Receipts

An immutable execution receipt records UTC start/finish, repository revision
and dirty state, target and serial port, immutable tool identities, exact
procedure, input/output artifact digests, non-secret device/build/capability
identities, exit status, and unedited output. Never retain AES keys, Wi-Fi
passwords, or secret-bearing NVS artifacts in repository evidence.
