# Native-frame v1 specification

Status: accepted target

This specification is the sole normative owner of Whisper native-frame v1,
ESP32-S3 firmware compatibility, and firmware-to-host admission behavior.
Current implementation and execution maturity are recorded separately in the
[firmware evidence index](../evidence/firmware.md).

The key words MUST, MUST NOT, SHOULD, and MAY are normative.

## Scope

Native-frame v1 carries authenticated firmware observations and control facts
in one UDP datagram. It supports one fixed ESP32-S3 capability schema while
preserving dynamic CSI sample counts. It does not define a canonical RF tensor,
application fragmentation, negotiation, extensions, a wire CRC, or a legacy
ADR-018/RuView compatibility mode.

The firmware image, provisioning record, encrypted datagram, captured packet,
and decoded observation are distinct artifacts. A datagram is never executable
firmware or an update payload.

All unsigned integers are little-endian. Signed one-byte fields use two's
complement. Byte arrays retain their source order. Encoders MUST serialize
fields explicitly and MUST NOT serialize C or Rust memory layouts.

## Identities and route phases

Each sender has a deployment-unique `device_id:u64`. Each active key is selected
by a nonzero `key_epoch:u16` and contains exactly 32 bytes for AES-256.
The device MAC address, peer address, source MAC address, message sequence, and
capture sequence are not substitutes for `device_id`.

Operational key material MUST be generated from a cryptographically secure
random source. Program 1 uses one explicit exception for disposable development
fixtures. Its public seed is the exact 33 ASCII bytes
`whisper-v1-public-e2e-fixture-key`. For one fixture Sensor identifier and
nonzero `key_epoch`, the temporary key is SHA-256 over this exact preimage,
concatenated in order:

1. the ASCII bytes `whisper.development-fixture-key`;
2. one byte with value `0x00`;
3. one unsigned byte with value `1` for the derivation version;
4. the fixture-seed length as unsigned `u32` big-endian;
5. the exact fixture-seed bytes;
6. the Sensor identifier length as unsigned `u32` big-endian;
7. the exact Sensor identifier UTF-8 bytes; and
8. `key_epoch` as unsigned `u16` big-endian.

Equal fixture inputs MUST derive equal key bytes. Changing the seed, Sensor
identifier, or key epoch changes the derivation input and expected key identity.
This exception MUST NOT be used as a production credential or generalized into
a production key-management design.

Admission has two phases:

1. Before authentication, the host MUST select exactly one `HeaderRoute` by the
   datagram peer IP plus clear `device_id` and `key_epoch`. That route supplies
   the exact key and its datagram, packet-rate, byte-rate, and replay limits.
   Source port is not identity and wildcard routes are forbidden.
2. After authentication and durable replay admission, the host MAY construct a
   `DecodedRoute`. It MUST match the configured sensor, authenticated
   `source_mac`, channel policy, radio facts, pinned firmware build, and pinned
   capability before resolving a link or capture profile.

The peer allowlist limits unauthenticated work; only the GCM tag authenticates
the header and body. Firmware-side source filtering reduces traffic but does
not replace host-side source and radio validation.

## Datagram envelope

The datagram is exactly a 32-byte header, `ciphertext_bytes` encrypted body
bytes, and a 16-byte authentication tag.

| Offset | Size | Field | Required value |
| --- | ---: | --- | --- |
| 0 | 1 | `wire_version` | `1` |
| 1 | 1 | `message_kind` | `1` capabilities, `2` CSI data, `3` health; other v1 values are authenticated unknown kinds |
| 2 | 2 | `header_bytes` | `32` |
| 4 | 8 | `device_id` | provisioned opaque identity |
| 12 | 2 | `key_epoch` | nonzero |
| 14 | 2 | `reserved_a` | zero |
| 16 | 4 | `boot_generation` | nonzero persistent generation |
| 20 | 8 | `message_sequence` | nonzero, starts at 1, never wraps within a generation |
| 28 | 2 | `ciphertext_bytes` | exact encrypted body length, at most 705 |
| 30 | 2 | `reserved_b` | zero |
| 32 | variable | `ciphertext` | encrypted body |
| `32 + ciphertext_bytes` | 16 | `tag` | AES-256-GCM tag |

The header is the complete GCM additional authenticated data. The 12-byte nonce
is `boot_generation:u32 LE || message_sequence:u64 LE`. The sender MUST reserve
a fresh message sequence before every sealing attempt and MUST NOT reuse it
after an encode, seal, or UDP-send failure. Before any message is sealed, the
firmware MUST increment, commit, and reread `boot_generation` from persistent
runtime storage. Sequence exhaustion, generation exhaustion, missing key, or a
failed generation commit MUST stop transmission.

Erasing runtime storage requires provisioning a fresh key epoch. It MUST NOT
silently restart a generation under the old key.

The minimum route budget that can carry the largest v1 body is 753 bytes:
32-byte header + 705-byte body + 16-byte tag. The deployment default is 1200
bytes. Every supported message MUST fit one datagram within the configured
budget.

## Capability identity

### Capabilities body

The capabilities body is exactly 113 bytes.

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 32 | `capability_digest` |
| 32 | 2 | `descriptor_bytes`, exactly `79` |
| 34 | 79 | capability descriptor |

`capability_digest` is SHA-256 of the 79 descriptor bytes only. The descriptor
has no trailing fields or extension area.

### Capability descriptor

| Descriptor offset | Size | Field | Required value |
| --- | ---: | --- | --- |
| 0 | 1 | `descriptor_version` | `1` |
| 1 | 1 | `target_kind` | `1` (`Esp32S3`) |
| 2 | 1 | `source_iq_order` | `1` (`ImaginaryReal`) |
| 3 | 1 | `output_encoding` | `1` (`SignedI8`) |
| 4 | 1 | `sample_axis` | `1` (`OpaqueOrdinal`) |
| 5 | 1 | `sample_order` | `1` (`PathThenSample`) |
| 6 | 1 | `phase_state` | `1` (`Raw`) |
| 7 | 1 | `driver_rx_timestamp_bits` | `32` |
| 8 | 1 | `capture_config` | `0x07` |
| 9 | 2 | `max_raw_csi_bytes` | `612` |
| 11 | 2 | `max_csi_plaintext_bytes` | `705` |
| 13 | 2 | `datagram_budget_bytes` | at least `753` and no greater than the admitted route budget |
| 15 | 32 | `firmware_build_digest` | SHA-256 identity of the running application image |
| 47 | 32 | `idf_wifi_abi_digest` | versioned digest of the pinned Wi-Fi ABI inputs |

`capture_config == 0x07` identifies LLTF, HT-LTF, and STBC-HT-LTF enabled,
with LTF merge, channel filtering, manual scaling, and ACK dump disabled. A
descriptor change creates a different capability identity. A capability is not
runtime parser negotiation: the host MUST already pin its capability digest and
firmware build digest.

The firmware MUST announce capabilities after boot and periodically. A CSI body
is eligible for semantic decoding only when a matching capabilities body was
durably recorded earlier in the same `(device_id, key_epoch,
boot_generation)` epoch. Later capability arrival MUST NOT retroactively decode
an earlier CSI body.

## CSI data body

The fixed prefix is 75 bytes, followed by one to three 6-byte block descriptors
and the raw CSI bytes.

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 32 | `capability_digest` |
| 32 | 8 | `capture_sequence`, nonzero |
| 40 | 4 | `driver_rx_timestamp_us` |
| 44 | 8 | `callback_tick_us` |
| 52 | 6 | `source_mac`, not all zero |
| 58 | 1 | `channel`, `1..=14` |
| 59 | 1 | `secondary`, `0=None`, `1=Above`, `2=Below` |
| 60 | 1 | `phy`, `1=NonHt`, `2=Ht` |
| 61 | 1 | `bandwidth`, `1=20MHz`, `2=40MHz` |
| 62 | 1 | `stbc`, `0=No`, `1=Yes` |
| 63 | 1 | `rssi_dbm:i8` |
| 64 | 1 | `noise_floor_dbm:i8` |
| 65 | 1 | `rate` |
| 66 | 1 | `mcs` |
| 67 | 1 | `rx_antenna`, `0` or `1` |
| 68 | 1 | `first_invalid_bytes`, `0` or `4` |
| 69 | 1 | `trailing_invalid_bytes`, `0` or `2` |
| 70 | 1 | `ltf_block_count`, `1..=3` |
| 71 | 2 | `raw_csi_bytes`, at most `612` |
| 73 | 2 | `complex_sample_count` |
| 75 | variable | block descriptors, then `raw_csi` |

The permitted radio combinations are:

- Non-HT: 20 MHz, no secondary channel, no STBC, and `mcs == 0`.
- HT 20 MHz: no secondary channel and `rate == 0`; STBC may be off or on.
- HT 40 MHz: secondary channel Above or Below and `rate == 0`; STBC may be off
  or on.

The `rate` field carries the ESP-IDF rate for Non-HT. The `mcs` field carries
the ESP-IDF MCS for HT. Values assigned to the other PHY MUST be zero.

### LTF blocks and raw accounting

Each block is:

| Block offset | Size | Field |
| --- | ---: | --- |
| 0 | 1 | `ltf_kind`, `1=LLTF`, `2=HTLTF`, `3=StbcHtLtf` |
| 1 | 1 | reserved, zero |
| 2 | 2 | `sample_count`, nonzero |
| 4 | 2 | `raw_offset_bytes` |

Non-HT has LLTF only. HT without STBC has LLTF then HTLTF. HT with STBC has
LLTF, HTLTF, then StbcHtLtf. Offsets MUST start at zero and be contiguous in
the encoded raw byte stream. Block sample counts MUST sum to
`complex_sample_count`.

`raw_csi` preserves ESP-IDF signed bytes in `[imaginary, real]` pair order. The
host maps each pair to `IqSample { i: real, q: imaginary }`. V1 has no scaling
field. The accounting rule is:

```text
raw_csi_bytes == 2 * complex_sample_count + trailing_invalid_bytes
```

The first invalid bytes remain within the first block and within
`complex_sample_count`; four invalid bytes mark the first two pairs invalid.
Trailing invalid bytes remain in `raw_csi` but create no logical pair. Other
pairs MUST NOT be marked invalid based on their value, count, or familiar
layout. Decoders MUST NOT pad, truncate, reorder, or infer physical tone
coordinates.

The domain view for this capability is exactly one `RawPathOrdinal(0)` with an
`OpaqueSampleOrdinal` axis and `PathThenSample` order. `driver_rx_timestamp_us`
and `callback_tick_us` are unsynchronized device facts. Neither authorizes UTC,
capture-time, or coherent-phase claims. Phase state is `Raw`.

### ESP32-S3 production sender layouts

The production sender selects a row by the complete radio tuple and then MUST
verify the corresponding raw byte total. Length alone MUST NOT select PHY,
bandwidth, secondary placement, STBC, or LTF meaning.

| PHY | Bandwidth | Secondary | STBC | LTF samples in order | Raw bytes |
| --- | --- | --- | --- | --- | ---: |
| Non-HT | 20 MHz | None | No | `64` | 128 |
| HT | 20 MHz | None | No | `64, 64` | 256 |
| HT | 20 MHz | None | Yes | `64, 64, 64` | 384 |
| HT | 40 MHz | Above or Below | No | `64, 128` | 384 |
| HT | 40 MHz | Above or Below | Yes | `64, 121, 121` | 612 |

This adopted table is sourced from the pinned ESP-IDF material identified in
[the native-frame reference](../references/native-frame.md). The general wire
grammar remains dynamic and accepts smaller conforming test or captured bodies;
the table is the fixed production sender profile for the pinned S3 capability.

## Health body

The health body is exactly 98 bytes.

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 32 | `capability_digest` |
| 32 | 8 | `callback_tick_us` |
| 40 | 8 | `capture_seen` |
| 48 | 8 | `queue_drop_no_slot` |
| 56 | 8 | `queue_drop_full` |
| 64 | 8 | `oversize_reject` |
| 72 | 8 | `encode_reject` |
| 80 | 8 | `send_failure` |
| 88 | 2 | `pool_high_water_slots` |
| 90 | 4 | `callback_max_us` |
| 94 | 4 | `encoder_max_us` |

Counters are monotonic within a boot generation and saturate rather than wrap.
Capabilities and health consume normal message sequences. Until latency
measurement is separately accepted, the two latency fields MUST be zero.
Counter gaps are observable loss; they MUST NOT create synthetic CSI.

## Capture and sender behavior

The firmware callback MUST validate the pointer, boot-resolved channel,
complete radio combination, boot-resolved associated AP BSSID, destination
station MAC, and the 612-byte ceiling. It MUST assign `capture_sequence` before attempting a
nonblocking slot allocation, copy the complete accepted driver buffer into a
preallocated slot, and enqueue only a slot index. It MUST NOT allocate, block,
log, seal, perform socket I/O, or perform inference.

`capture_sequence` starts at 1 and MUST NOT wrap. After allocating
`u64::MAX`, the callback MUST reject later captures and expose the rejection in
health rather than beginning a new implicit source epoch.

A single lower-priority sender owns message sequencing, body encoding, sealing,
UDP transmission, and capability and health emission. Queue or slot exhaustion
drops the complete capture and exposes the consumed capture sequence as a gap.
A sender MUST emit either one complete authenticated datagram or none.

## Provisioning and image compatibility

The v1 firmware target is ESP32-S3-DevKitC-1-compatible, display-less, 8 MB
QSPI flash, and has no PSRAM dependency. The image MUST be built for ESP32-S3
with DIO flash mode, the pinned ESP-IDF v5.4 build environment identified in
[the reference](../references/native-frame.md), CSI enabled, and the partition
table at offset `0x10000`:

| Name | Type | Subtype | Offset | Size | Flag |
| --- | --- | --- | ---: | ---: | --- |
| `nvs` | data | nvs | `0x11000` | `0x7000` | encrypted |
| `otadata` | data | ota | `0x18000` | `0x2000` | encrypted |
| `phy_init` | data | phy | `0x1a000` | `0x1000` | encrypted |
| `ota_0` | app | ota_0 | `0x20000` | `0x300000` | none |
| `ota_1` | app | ota_1 | `0x320000` | `0x300000` | none |

The encrypted partition flags preserve the release layout. They do not provide
at-rest security while development flash encryption is disabled.

The development provisioning record schema is `2` and contains `device_id`,
nonzero `key_epoch`, a 32-byte AES key, station SSID/password, probe port,
collector IP/port, and one capability digest. BSSID and channel are runtime
association facts and MUST NOT be provisioned. The separate runtime
namespace contains only `boot_generation`. Development provisioning uses
disposable credentials and makes no production-security claim.

Program 1 provisioning MUST place the derived fixture key in this ordinary
record field. Firmware authentication MUST NOT add a fixture-only branch.
The production Host/fixture loader defined by
[persistence v1](persistence-v1.md#program-1-development-secret-store) produces
validated key material. The fixture producer MUST write exactly 32
already-validated bytes to one inherited pipe or file descriptor and then close
its write end. Firmware provisioning owns the one readable descriptor and MUST
perform bounded repeated reads; partial reads are normal. It MUST retain at most
33 bytes and accept only after observing end-of-file immediately after total
byte 32. End-of-file after zero through 31 bytes is short input, and observing
byte 33 is long input; either MUST fail.

Firmware provisioning MUST close its descriptor on every success or failure
and MUST NOT reuse it. It MUST receive no secret path, implement no filesystem
trust policy, and log or emit no key material.

Provisioning MUST NOT log, display, screenshot, or emit raw key bytes, Wi-Fi
credentials, real SSIDs, or other secret provisioning values. Program 1
evidence-artifact rules are owned by
[development E2E v1](development-e2e-v1.md#provisioning-artifacts).

Startup MUST validate the record, compute the running application digest and
the pinned Wi-Fi ABI digest, reconstruct the capability descriptor, match its
digest to provisioning, advance and reread boot generation, scan for and
associate to the provisioned SSID, obtain a nonzero unicast BSSID and channel
in `1..=14` from the associated AP, freeze those values for callback
validation, bind the probe socket, start the sender, and only then enable CSI.
Any failure MUST fail closed.

After association, the station uses no power save, promiscuous mode, channel
hopping, roaming, or BLE coexistence. It accepts callbacks only from the
boot-resolved associated AP BSSID on the boot-resolved channel to its own
station MAC. A disconnect fails the runtime; a later boot performs discovery
again. Probe traffic is an ordinary rate-limited UDP receive trigger; its
payload is discarded and is not a second protocol grammar.

## Replay interaction and reject behavior

Replay admission is durable host state, separate from parsing. Its key is the
configured device and key epoch plus authenticated boot generation and message
sequence. Within the configured replay window, a previously unseen reordered
sequence MAY be admitted. A duplicate, a sequence older than the window, or a
lower or reused boot generation MUST be rejected. Restart and session rotation
MUST NOT reset this state.

The host applies outcomes in this order:

| Failure or outcome | Authentication state | Raw packet retained | Semantic decode |
| --- | --- | --- | --- |
| Oversize, malformed header, unknown peer, unknown version, unknown key or route | unauthenticated | no | no |
| Bad tag | authentication failed | no | no |
| Authenticated route rate or byte limit | authenticated but not replay-admitted | no | no |
| Replay reject | authenticated but not admitted | no | no |
| Authenticated unknown v1 kind | authenticated and replay-admitted | yes, bounded | `UnknownKind`; body uninterpreted |
| Malformed known body | authenticated and replay-admitted | yes, bounded | classified reject |
| Missing earlier capability | authenticated and replay-admitted | yes, bounded | `CapabilityUnavailable` |
| Build, capability, source, radio, or body budget mismatch | authenticated and replay-admitted | yes, bounded | classified reject; no observation |
| Fully conforming CSI | authenticated and replay-admitted | yes | one typed dynamic observation |

Errors MUST preserve the distinction among envelope/version, exact route,
authentication, replay/budget, unknown kind, malformed body, capability,
source, radio, and decoded-domain failures. Parsing failure MUST NOT create an
`Unknown` observation or world state.

## Conformance and acceptance

Acceptance is cumulative and each surface requires its own retained evidence:

1. Language-neutral golden vectors cover exact header, AAD, nonce, tag,
   capability descriptor, CSI bodies, health, malformed inputs, and truncation.
2. Production sender tests exercise every row of the S3 production layout
   table through the callback/queue/sender path.
3. A datagram emitted by the production C sender passes the Rust header route,
   authentication, capability, decoded route, and CSI construction path.
4. The pinned production firmware and parity projects build, and the production
   capability-binding QEMU procedure executes against the identified artifacts.
5. A probed ESP32-S3 with 8 MB flash is flashed and verified from build-generated
   arguments, reports matching identity and digests, emits an authenticated
   live datagram, and that retained datagram is decoded by the host path.

Checked-in source or a historical status statement is not execution evidence.
The required receipt contents and current gaps are listed in the
[firmware evidence index](../evidence/firmware.md); operational steps live in
[the firmware runbook](../operations/firmware.md).
