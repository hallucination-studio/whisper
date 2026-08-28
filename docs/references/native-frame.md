# Native-frame references

This document preserves external source identity, version, date, provenance,
and refresh points. It does not define Whisper's normative protocol or report
implementation status.

Sources were last checked on 2026-08-27.

## ESP-IDF v5.4

- Publisher: Espressif Systems.
- Product and version: ESP-IDF v5.4.
- Release: [ESP-IDF Release v5.4](https://github.com/espressif/esp-idf/releases/tag/v5.4),
  published 2025-01-04T17:56:49Z.
- Source identity: annotated tag [`v5.4`](https://api.github.com/repos/espressif/esp-idf/git/refs/tags/v5.4),
  [tag object `8e27ea72c6688b79348b123ff40d556cfe16c8c3`](https://api.github.com/repos/espressif/esp-idf/git/tags/8e27ea72c6688b79348b123ff40d556cfe16c8c3),
  resolving to [commit `67c1de1eebe095d554d281952fde63c16ee2dca0`](https://github.com/espressif/esp-idf/commit/67c1de1eebe095d554d281952fde63c16ee2dca0).
- Target guide: [ESP32-S3 Wi-Fi Channel State Information](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32s3/api-guides/wifi.html#wi-fi-channel-state-information).
- Immutable source: [`docs/en/api-guides/wifi.rst` at the resolved commit](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/docs/en/api-guides/wifi.rst#L2205-L2257),
  [Git blob `f2a0deb5e91880da6f3e7aeb643dd78d00c9ae32`](https://api.github.com/repos/espressif/esp-idf/git/blobs/f2a0deb5e91880da6f3e7aeb643dd78d00c9ae32).
- Retrieved source: [raw `wifi.rst` bytes at the resolved commit](https://raw.githubusercontent.com/espressif/esp-idf/67c1de1eebe095d554d281952fde63c16ee2dca0/docs/en/api-guides/wifi.rst).
- Retrieved source SHA-256:
  `7558f3f027fe47e900daad4127f983f1f8d67cd0be8b14b1b122c03d2e8cdc44`.
- Receipt access time: 2026-08-27T15:59:42Z.

The pinned guide defines each CSI item as two signed bytes in imaginary, real
order and introduces LLTF, HT-LTF, and STBC-HT-LTF
([lines 2205-2210](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/docs/en/api-guides/wifi.rst#L2205-L2210)).
Its table keys columns by secondary channel, signal mode, bandwidth, and STBC;
lists each LTF's sub-carrier range; and gives the corresponding total bytes
([lines 2212-2228](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/docs/en/api-guides/wifi.rst#L2212-L2228)).
The guide binds those column dimensions to `wifi_csi_info_t` fields, binds the
total to `len`, and fixes buffer order as LLTF, HT-LTF, STBC-HT-LTF
([lines 2230-2238](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/docs/en/api-guides/wifi.rst#L2230-L2238)).

### Production-layout adoption trace

The following trace maps every row of the Whisper production profile, expanding
the two rows that permit either secondary-channel placement. Counts are the
inclusive cardinalities of the pinned table's published sub-carrier ranges;
raw-byte totals are taken from its `total bytes` row. Each locator names one
specific upstream column in
[`docs/en/api-guides/wifi.rst` lines 2212-2228](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/docs/en/api-guides/wifi.rst#L2212-L2228).

| Whisper production row | Pinned ESP-IDF v5.4 table column | Adopted LTF sample counts | Adopted raw bytes |
| --- | --- | --- | ---: |
| Non-HT, 20 MHz, None, non-STBC | `none / non HT / 20 MHz / non STBC` | LLTF `0..31, -32..-1` = `64` | 128 |
| HT, 20 MHz, None, non-STBC | `none / HT / 20 MHz / non STBC` | LLTF `64`; HT-LTF `0..31, -32..-1` = `64` | 256 |
| HT, 20 MHz, None, STBC | `none / HT / 20 MHz / STBC` | LLTF `64`; HT-LTF `64`; STBC-HT-LTF `0..31, -32..-1` = `64` | 384 |
| HT, 40 MHz, Below, non-STBC | `below / HT / 40 MHz / non STBC` | LLTF `0..63` = `64`; HT-LTF `0..63, -64..-1` = `128` | 384 |
| HT, 40 MHz, Above, non-STBC | `above / HT / 40 MHz / non STBC` | LLTF `-64..-1` = `64`; HT-LTF `0..63, -64..-1` = `128` | 384 |
| HT, 40 MHz, Below, STBC | `below / HT / 40 MHz / STBC` | LLTF `64`; HT-LTF `0..60, -60..-1` = `121`; STBC-HT-LTF `121` | 612 |
| HT, 40 MHz, Above, STBC | `above / HT / 40 MHz / STBC` | LLTF `64`; HT-LTF `0..60, -60..-1` = `121`; STBC-HT-LTF `121` | 612 |

The upstream table contains additional columns that Whisper does not adopt.
ESP-IDF also notes that disabling an LTF reduces `len`
([lines 2253-2257](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/docs/en/api-guides/wifi.rst#L2253-L2257)).
Consequently this receipt traces only the fixed production subset; it does not
make the upstream table normative. The adopted contract remains solely in the
[native-frame v1 specification](../specs/native-frame-v1.md).

## ESP-IDF build container

- Publisher: Espressif Systems, Docker Hub repository `espressif/idf`.
- Tag provenance: `v5.4`, pushed 2025-01-03 according to the Docker Hub v2 tag
  record checked on 2026-08-27.
- Immutable multi-platform image identity:
  `espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb`.
- Registry record: [Docker Hub `espressif/idf` tags](https://hub.docker.com/r/espressif/idf/tags).

The digest, not the mutable tag, identifies the accepted build environment.

## esptool 5.3.1

- Publisher: Espressif Systems.
- Product and version: esptool v5.3.1.
- Release: [esptool v5.3.1](https://github.com/espressif/esptool/releases/tag/v5.3.1),
  published 2026-06-29.
- Documentation: [esptool documentation](https://docs.espressif.com/projects/esptool/en/latest/esp32s3/).

The operational pin is the primary version reported by `esptool`; incidental
compatibility text is not version identity.
