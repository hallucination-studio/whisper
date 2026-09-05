# Firmware and native-input evidence

The existing ESP32-S3 firmware and authenticated native-frame input remain
unchanged by the RF architecture reset. Source and tests describe implementation;
the following retained packages describe identified executions only.

| Retained execution | Scope |
| --- | --- |
| [Firmware ed466ae](receipts/firmware-ed466ae/README.md) | Pinned production build, C/Rust parity and QEMU checks within the receipt's stated pre-network limits |
| [Physical demo-smoke e151145](receipts/demo-smoke-e151145/README.md) | The identified real-board native-frame-to-Host/Chrome path; no new world-model accuracy or long-running qualification |

Capture and verification artifacts remain unchanged. A prior plan's PASS or
closed ticket is not additional physical evidence. The
[former evidence index](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/evidence/firmware.md)
records its historical implementation and evidence assessment, not a live work
queue.

New raw/typed-CSI acceptance uses the already deployed device and unchanged
firmware, configuration, UDP and position. It does not require reflashing or
reprovisioning. The new [RF issue graph](https://github.com/hallucination-studio/whisper/issues/163)
owns that execution and any missing input evidence; retired issues supply no
blockers or completion credit.

The external contract is [native-frame v1](../specs/native-frame-v1.md).
[Firmware procedures](../operations/firmware.md) remain available for the
separate explicitly selected build/provisioning operations.
