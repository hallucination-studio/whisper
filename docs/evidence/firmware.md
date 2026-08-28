# Firmware evidence index

This index distinguishes implementation facts, checked-in test source, and
executed evidence for firmware and native-frame v1. It owns no protocol or
procedure.

## Snapshot classification

Baseline revision: `f83428c31aba285277fc95db4079228b97ecaa62`

Classification date: 2026-08-27

At this revision, code plus behavior-test source establishes a Rust v1
encoder/decoder and route resolver, a C v1 encoder, an ESP-IDF capture/sender
kernel, provisioning code, frozen cross-language vectors, and tests around
those interfaces. No Cargo, ESP-IDF build, parity execution, QEMU, board probe,
application flash, live capture, or production host interoperability execution
receipt was identified in the repository.

The original working tree also contained unstaged Rust persistence/world work
and generated Python bytecode. Those files are WIP or generated artifacts and
are not part of this snapshot's firmware/native-frame implementation evidence.

## Executed receipts

The [firmware `ed466ae` receipt](receipts/firmware-ed466ae/README.md) retains a
clean production ESP32-S3 build, parity build, four-marker parity execution in
QEMU, and production pre-network capability-binding QEMU execution in the
pinned ESP-IDF container. It includes complete logs, exact commands and UTC
intervals, failed and accepted parity wrappers, build metadata, and artifact
digests. The later published revision `d1deeb5` has the same firmware tree, but
the executions remain attributed to `ed466ae`.

These QEMU receipts establish no physical-board, flash/write/verify, Wi-Fi,
UDP, live CSI, or production host-decode result.

## Coverage and receipt matrix

| Acceptance surface | Implementation/test source at baseline | Repository-retained execution receipt | Status |
| --- | --- | --- | --- |
| Rust envelope, AES-GCM, exact bodies, validity/IQ mapping, route phases | implementation and behavior tests present | none identified | implemented fact plus test source; execution open |
| C encoder against five frozen Rust vectors | implementation and parity test source present | [`ed466ae` parity build and four-marker QEMU execution](receipts/firmware-ed466ae/README.md) | executed in pinned QEMU environment |
| Production sender 612-byte HT40/STBC, Above/Below, rejection, send failure, exhaustion | implementation and test source present | none identified | partial test source |
| Production sender 128/256/384 layout rows | implementation present; behavior tests absent | none | open coverage gap |
| Production C sender datagram through Rust admission/decode | no checked-in cross-language production-seam test | none | open interoperability gap |
| Provisioning validation and failure ordering | Python tests use a fake esptool runner | none | test source only; not hardware evidence |
| Production firmware build and artifact facts | build configuration and scripts present | [`ed466ae` production build](receipts/firmware-ed466ae/README.md) | executed in pinned container |
| Production capability-binding QEMU | executable script present | [`ed466ae` production QEMU](receipts/firmware-ed466ae/README.md) | executed; pre-network scope only |
| ESP32-S3 and 8 MB probe | procedure and mock test source present | none | physical gate open |
| Application write and same-range verify | procedure and mock test source present | none | physical gate open |
| Board identity/digests, authenticated live datagram, host decode | no retained corpus or receipt identified | none | live gate open |

The legacy implementation plan's `PASS` sentence is a historical status claim,
not a receipt. The receipt above fills the build, parity, and QEMU gap. WP 1.3
remains open for the separate physical probe, flash/verify, identity,
authenticated live datagram, and host-decode evidence gates.

## Active gaps

The live authority for open work is GitHub Issues. Issue #3 is the closed
recovery parent. Its bounded native delivery issues are:

- [#9](https://github.com/hallucination-studio/whisper/issues/9): ESP-IDF v5.4
  S3 provenance and all production sender layout branches.
- [#10](https://github.com/hallucination-studio/whisper/issues/10): production
  C-sender-to-Rust interoperability.
- [#11](https://github.com/hallucination-studio/whisper/issues/11): completed;
  retained pinned build, parity, and production QEMU receipts are indexed
  above.
- [#13](https://github.com/hallucination-studio/whisper/issues/13): retained
  physical probe, flash/verify, identity, live datagram, and host-decode
  receipts. Its remaining issue blockers are #9 and #10; #11 is closed. It also
  requires human control of the board and network.

The normative acceptance surface is
[native-frame v1](../specs/native-frame-v1.md); the execution procedure and
required receipt fields are in the
[firmware runbook](../operations/firmware.md).
