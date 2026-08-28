# Firmware build, parity, and production QEMU receipt

This receipt retains the Issue #11 execution surfaces for firmware revision
`ed466ae32bba30524b0ae49473e97c4de85076ce`. The clean published revision
`d1deeb5d78b5dbee2786190cccdbf987add91895` is four commits ahead and has an
identical `firmware/esp32-native-frame/` tree. The runs were executed at
`ed466ae`; tree equality does not relabel them as executions at `d1deeb5`.

## Scope and identity

| Field | Retained value |
| --- | --- |
| Repository revision under test | `ed466ae32bba30524b0ae49473e97c4de85076ce` |
| Dirty state at build start | clean; `git status --short` produced no lines between the revision and input digests in the production log |
| Later published revision | `d1deeb5d78b5dbee2786190cccdbf987add91895`; no firmware-tree changes from `ed466ae` |
| Container | `espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb` |
| ESP-IDF and Python | ESP-IDF `v5.4`; Python `3.12.3` |
| C/C++ toolchain | GNU `14.2.0`; `xtensa-esp-elf/esp-14.2.0_20241119` |
| Build image tool | esptool `4.8.1` |
| Emulator | QEMU `9.0.0` (`esp_develop_9.0.0_20240606`) at the path recorded in the parity and production QEMU procedures |
| Configured target | ESP32-S3, DIO, 80 MHz, 8 MB, no PSRAM dependency, CSI enabled |
| Physical board and serial port | not used; not applicable to these container/QEMU runs |

The production log starts with the full revision, input digests, and immutable
container identity before the build output. The parity and QEMU commands use
the same clean checkout path and pinned container immediately after that build.

## Results

| Surface | UTC interval | Exit | Result and raw output |
| --- | --- | ---: | --- |
| Production ESP32-S3 build | 2026-08-27T15:27:49Z to 2026-08-27T15:28:24Z | 0 | PASS; [complete log](production-build.log) |
| Parity ESP32-S3 build | 2026-08-27T15:29:13Z to 2026-08-27T15:29:44Z | 0 | PASS; [complete log](parity-build.log) |
| Production capability-binding QEMU | 2026-08-27T15:29:13Z to 2026-08-27T15:29:45Z | 0 | PASS; [complete script output](production-qemu.log) |
| First parity QEMU wrapper | 2026-08-27T15:30:42Z to 2026-08-27T15:31:04Z | 1 | FAIL; all four firmware PASS markers were present, but `grep -qx` failed on CRLF-terminated serial lines; [unaltered failed receipt](parity-qemu-crlf-wrapper-failure.log) |
| Normalized parity QEMU assertion | 2026-08-27T15:31:21Z to 2026-08-27T15:31:42Z | 0 | PASS; raw QEMU output was printed unedited, while a separate assertion copy had only `\r` removed; [complete accepted log](parity-qemu.log) |
| Production image inspection | 2026-08-27T16:31:27Z to 2026-08-27T16:31:29Z | 0 | PASS; [complete output](production-image-info.log) |

The accepted parity log contains each marker exactly once and contains no
`NATIVE_FRAME_V1_*_FAIL` marker:

```text
NATIVE_FRAME_V1_PROVISIONING_PASS
NATIVE_FRAME_V1_PARITY_PASS
NATIVE_FRAME_V1_CSI_CAPTURE_PASS
NATIVE_FRAME_V1_SENDER_PASS
```

The accepted run records QEMU process exit `124`, the expected timeout after
all markers, and wrapper exit `0`. The first receipt is retained because its
wrapper result was a real failure; the CRLF mismatch is not rewritten as a
successful first run.

The identified production QEMU script has SHA-256
`1e6f65e3be23c0ee973afed1786401e0e6ef36ee7e236642e6990bbf04278f1f`.
It emits `PRODUCTION_CAPABILITY_BINDING_QEMU_PASS` and exits zero only after
both script gates pass:

| Script gate | Required observation | Retained result |
| --- | --- | --- |
| Valid disposable provisioning | `provisioning accepted; boot generation 1; awaiting network prerequisites` present and `runtime startup failed` absent | PASS |
| Mismatched capability provisioning | accepted message absent and `runtime startup failed` present | PASS |
| Combined marker | `PRODUCTION_CAPABILITY_BINDING_QEMU_PASS` | PASS |

The successful internal boot transcripts are intentionally captured by the
script rather than printed. The linked log is the complete unedited stdout and
stderr produced by that identified script; the two result rows above are its
exit-zero control-flow gates, not a claim that suppressed boot transcripts were
retained.

## Production build facts

| Fact or artifact | Value |
| --- | --- |
| `sdkconfig.defaults` SHA-256 | `eb109b00643fd9cb25b9ba091f743c14316bed4a562bd657636cb7b368430a02` |
| `partitions.csv` SHA-256 | `b84eedf6aae9951097f07365ab85006c421a10506e557e91c41ef83cb4a078dc` |
| Bootloader binary SHA-256 | `0bc5c5a22f7106cff907c8647a9b551b7e6d4f447d7114476193718fb31726e7` |
| Partition-table binary SHA-256 | `bbb59f28c8347e73faf9e9efcd6dae110f9ce41b4f8be9f209abdc322b63e3f3` |
| Initial OTA data SHA-256 | `7d2c7ac4888bfd75cd5f56e8d61f69595121183afc81556c876732fd3782c62f` |
| Application binary SHA-256 | `dee5f6c9edf0a22e2f9afcd53aed541e7c8ce547367482a847d7ebf019deaa59` |
| Application ELF SHA-256 | `d42807f3dee87b0aa35e249109b303e449bc1d2cee0e9eed35ce379d10c1cd70` |
| Application validation hash | `7580a422619d393945202ec12297f247425d1cf9ac1cb702662f5f35b75610e8` (valid) |
| Wi-Fi ABI digest | `601077a28cec92a5e9c13ea999029e92c2a2a529e3a0c62d977543ca6246d535` |
| Capability digest | `d9ff77bbe19d865dd353a4caf70fc3899e7700d4fc8936038cfeba656c5f7ca2` |
| Maximum datagram bytes bound into capability | `1200` |
| Build flash arguments | [retained JSON](production-flasher-args.json), SHA-256 `13e24744198a5d2a3bb935d0361a1f73cb3affea9efecbb97d23991105fe611a` |
| Capability build facts | [retained JSON](production-capability-build-facts.json), SHA-256 `0a66bfcdcecfafffde3ccaada8b11022f2c3531693733db95dcd4bbf9c1fe51d` |

The image inspection reports ESP32-S3, DIO, 80 MHz, 8 MB, embedded app version
`ed466ae`, ESP-IDF `v5.4`, the validation hash, and the matching ELF SHA-256.
The capability digest is SHA-256 over the identified script's 79-byte
descriptor: its fixed schema/profile fields, maximum sizes `612`, `705`, and
`1200`, the application validation hash, and the Wi-Fi ABI digest.
It can be independently recomputed from those retained fields:

```sh
printf '%s' '0101010101010120076402c102b0047580a422619d393945202ec12297f247425d1cf9ac1cb702662f5f35b75610e8601077a28cec92a5e9c13ea999029e92c2a2a529e3a0c62d977543ca6246d535' | xxd -r -p | shasum -a 256
```

The retained flasher metadata fixes the production offsets at bootloader
`0x0`, partition table `0x10000`, initial OTA data `0x18000`, and application
`0x20000`. The source partition CSV additionally fixes NVS `0x11000`, PHY
initialization `0x1a000`, and the two 3 MB OTA application slots at `0x20000`
and `0x320000`.

## Parity artifact identity

The parity CMake source consumes the five checked-in frozen Rust vectors. The
inputs and produced artifacts are:

| Input or artifact | SHA-256 |
| --- | --- |
| `capabilities-v1.hex` | `6ee46b79dcbdf69c545552310f2aaa65b21af7e619f52ec6034583476e2e84fd` |
| `csi-non-ht-3-pairs.hex` | `8a97f00914e6d21e54c393018a140b2633b2b49aed963042357d17abfc6ec07d` |
| `csi-ht-5-pairs-first-invalid.hex` | `f032fd667621a5f9b445ac6b6781501fafb18f7f682a3f38f8de9cd3e3d72973` |
| `csi-ht-stbc-7-pairs.hex` | `baeafd8c5239ee4d3e7d77854bbed74aa22d524edccc610e5ad1846c9b57f3eb` |
| `health-v1.hex` | `7da1b454cc3d7abf4790add5dca7627d200c935536115121c93d967bb5d60865` |
| Frozen-vector generator | `e45570ad6a789e9d3025ed13abbe04f74415b52d6413eb6880bc67d13f0b891d` |
| Parity source | `598fe43003b0d5cc75a6fbd777185462535c0635f97caaa5d8ea0effd37863ca` |
| Parity bootloader binary | `492f62e2a8662f34a272baff5c2fd161111b28f71767cc658abc2ed8283f4576` |
| Parity partition-table binary | `7f00b6c042a89b15b0cac534f82ed988caf29278ff5700b0c511eb1b5bb7c820` |
| Parity application binary | `9fa29a0ec3d0916a1929de443284042505e66ddb0ee5e2f52cacbe647bc12a7b` |
| Parity application ELF | `86ba5664814bf264d9db44fa5b1a6aef2700e21cee1e2b75e9bdd9a34cb1ae28` |
| Merged 8 MB parity QEMU flash | `aa9585c082514780033382e880fc516d8a3ff833dde23cd8184274ad1502a213` |
| Parity flash arguments | [retained JSON](parity-flasher-args.json), SHA-256 `80f12953a63de08e91b8eaea35488e58222b470faca009e1657be2b84722c5d3` |

## Exact commands

These are the commands as executed. The checkout path was temporary; artifact
identity is retained above so the path is not treated as an enduring locator.

### Production build

```sh
set -o pipefail
IDF_IMAGE='espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb'
REPO=/private/tmp/whisper-persistence-publish.oWuR9k/repo
LOG=/private/tmp/whisper-firmware-production-ed466ae.log
{
  date -u '+START_UTC=%Y-%m-%dT%H:%M:%SZ'
  git -C "$REPO" rev-parse HEAD
  git -C "$REPO" status --short
  shasum -a 256 "$REPO/firmware/esp32-native-frame/sdkconfig.defaults" "$REPO/firmware/esp32-native-frame/partitions.csv"
  docker image inspect "$IDF_IMAGE" --format '{{json .RepoDigests}}'
  docker run --rm -v "$REPO:/project" -w /project/firmware/esp32-native-frame "$IDF_IMAGE" bash -lc 'idf.py set-target esp32s3 && idf.py build'
  build_status=$?
  date -u '+FINISH_UTC=%Y-%m-%dT%H:%M:%SZ'
  printf 'BUILD_EXIT=%s\n' "$build_status"
  exit "$build_status"
} 2>&1 | tee "$LOG"
```

### Parity build

```sh
set -o pipefail
IDF_IMAGE='espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb'
REPO=/private/tmp/whisper-persistence-publish.oWuR9k/repo
LOG=/private/tmp/whisper-firmware-parity-ed466ae.log
{ date -u '+START_UTC=%Y-%m-%dT%H:%M:%SZ'; docker run --rm -v "$REPO:/project" -w /project/firmware/esp32-native-frame/tests "$IDF_IMAGE" bash -lc 'idf.py set-target esp32s3 && idf.py build'; run_status=$?; date -u '+FINISH_UTC=%Y-%m-%dT%H:%M:%SZ'; printf 'BUILD_EXIT=%s\n' "$run_status"; exit "$run_status"; } 2>&1 | tee "$LOG"
```

### Production capability-binding QEMU

```sh
set -o pipefail
IDF_IMAGE='espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb'
REPO=/private/tmp/whisper-persistence-publish.oWuR9k/repo
LOG=/private/tmp/whisper-firmware-qemu-ed466ae.log
{ date -u '+START_UTC=%Y-%m-%dT%H:%M:%SZ'; docker run --rm -v "$REPO:/project" -w /project/firmware/esp32-native-frame "$IDF_IMAGE" bash -lc 'python tests/run_production_qemu.py'; run_status=$?; date -u '+FINISH_UTC=%Y-%m-%dT%H:%M:%SZ'; printf 'QEMU_EXIT=%s\n' "$run_status"; exit "$run_status"; } 2>&1 | tee "$LOG"
```

### First parity QEMU wrapper, failed on CRLF assertions

```sh
set -o pipefail
IDF_IMAGE='espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb'
REPO=/private/tmp/whisper-persistence-publish.oWuR9k/repo
LOG=/private/tmp/whisper-firmware-parity-qemu-ed466ae.log
{ date -u '+START_UTC=%Y-%m-%dT%H:%M:%SZ'; docker run --rm -v "$REPO:/project" -w /project/firmware/esp32-native-frame/tests "$IDF_IMAGE" bash -lc '
set -e
PY=/opt/esp/python_env/idf5.4_py3.12_env/bin/python
QEMU=/opt/esp/tools/qemu-xtensa/esp_develop_9.0.0_20240606/qemu/bin/qemu-system-xtensa
"$PY" -m esptool --chip esp32s3 merge_bin --flash_mode dio --flash_freq 80m --flash_size 8MB --fill-flash-size 8MB -o build/parity-qemu-flash.bin 0x0 build/bootloader/bootloader.bin 0x8000 build/partition_table/partition-table.bin 0x10000 build/native_frame_v1_parity.bin
set +e
timeout 20 "$QEMU" -nographic -machine esp32s3 -drive file=build/parity-qemu-flash.bin,if=mtd,format=raw > build/parity-qemu.raw.log 2>&1
qemu_status=$?
set -e
cat build/parity-qemu.raw.log
for marker in NATIVE_FRAME_V1_PROVISIONING_PASS NATIVE_FRAME_V1_PARITY_PASS NATIVE_FRAME_V1_CSI_CAPTURE_PASS NATIVE_FRAME_V1_SENDER_PASS; do grep -qx "$marker" build/parity-qemu.raw.log; done
if grep -q "NATIVE_FRAME_V1_.*_FAIL" build/parity-qemu.raw.log; then exit 1; fi
printf "QEMU_PROCESS_EXIT=%s (timeout after all markers is expected)\n" "$qemu_status"
'; run_status=$?; date -u '+FINISH_UTC=%Y-%m-%dT%H:%M:%SZ'; printf 'PARITY_EXEC_EXIT=%s\n' "$run_status"; exit "$run_status"; } 2>&1 | tee "$LOG"
```

### Parity QEMU with normalized assertion copy

```sh
set -o pipefail
IDF_IMAGE='espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb'
REPO=/private/tmp/whisper-persistence-publish.oWuR9k/repo
LOG=/private/tmp/whisper-firmware-parity-qemu-ed466ae-pass.log
{ date -u '+START_UTC=%Y-%m-%dT%H:%M:%SZ'; docker run --rm -v "$REPO:/project" -w /project/firmware/esp32-native-frame/tests "$IDF_IMAGE" bash -lc '
set -e
QEMU=/opt/esp/tools/qemu-xtensa/esp_develop_9.0.0_20240606/qemu/bin/qemu-system-xtensa
set +e
timeout 20 "$QEMU" -nographic -machine esp32s3 -drive file=build/parity-qemu-flash.bin,if=mtd,format=raw > build/parity-qemu.raw.log 2>&1
qemu_status=$?
set -e
cat build/parity-qemu.raw.log
tr -d "\r" < build/parity-qemu.raw.log > build/parity-qemu.assert.log
for marker in NATIVE_FRAME_V1_PROVISIONING_PASS NATIVE_FRAME_V1_PARITY_PASS NATIVE_FRAME_V1_CSI_CAPTURE_PASS NATIVE_FRAME_V1_SENDER_PASS; do grep -qx "$marker" build/parity-qemu.assert.log; done
if grep -q "NATIVE_FRAME_V1_.*_FAIL" build/parity-qemu.assert.log; then exit 1; fi
printf "QEMU_PROCESS_EXIT=%s (timeout after all markers is expected)\n" "$qemu_status"
'; run_status=$?; date -u '+FINISH_UTC=%Y-%m-%dT%H:%M:%SZ'; printf 'PARITY_EXEC_EXIT=%s\n' "$run_status"; exit "$run_status"; } 2>&1 | tee "$LOG"
```

### Production application image inspection

```sh
set -o pipefail
IDF_IMAGE='espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb'
REPO=/private/tmp/whisper-persistence-publish.oWuR9k/repo
LOG=/private/tmp/whisper-firmware-image-info-ed466ae.log
{ date -u '+START_UTC=%Y-%m-%dT%H:%M:%SZ'; docker image inspect "$IDF_IMAGE" --format '{{json .RepoDigests}}'; docker run --rm -v "$REPO:/project" -w /project/firmware/esp32-native-frame "$IDF_IMAGE" bash -lc 'python -m esptool image_info --version 2 build/esp32_native_frame.bin'; run_status=$?; date -u '+FINISH_UTC=%Y-%m-%dT%H:%M:%SZ'; printf 'IMAGE_INFO_EXIT=%s\n' "$run_status"; exit "$run_status"; } 2>&1 | tee "$LOG"
```

## Retained receipt artifact digests

| Retained file | Bytes | SHA-256 |
| --- | ---: | --- |
| `production-build.log` | 129904 | `b355049eb35adf0a77d436e82103714686325cae44289b10710014e6686e1efe` |
| `parity-build.log` | 129498 | `f48a000670bb072cd9788e7a0c6fb8ba1d5370c641af667539590638ac4887b8` |
| `production-qemu.log` | 639 | `06a3fbb14d907bba38751b0a0f01e7101c73d94f7d51858c9dc322e1388711b6` |
| `parity-qemu-crlf-wrapper-failure.log` | 3767 | `254a55cbfdf73dd18fe61ac26c6e86ecb6acf4790e2e43311a41c2f466fa2c14` |
| `parity-qemu.log` | 3700 | `c346655ec05b2b415b28464ebacfc3fc9d5afae3064c1a4402a9ee1d3285e162` |
| `production-image-info.log` | 2205 | `4ab864ab9be38c5e3d4d90ef969f711f1ba90f673fa59a83fab7f35f565a3b57` |

The original log bytes are retained without newline conversion. In particular,
the CRLF serial output in both parity QEMU logs remains CRLF.

## Claim boundary

This receipt proves the identified production build, parity build, four-marker
parity execution in QEMU, and production pre-network capability-binding QEMU
procedure. It does not prove a physical ESP32-S3 or 8 MB flash device, serial
probe, write, same-range verify, Wi-Fi association, CSI callback, UDP datagram,
credential ceremony, or production host admission/decode. QEMU is not board,
flash, network, or live evidence.
