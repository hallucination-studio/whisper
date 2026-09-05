# Architecture index

Load architecture for non-discoverable responsibility, dependency direction,
seam, or invariant questions. Exact behavior belongs to the linked versioned
specification, and current implementation remains discoverable from code and
behavior tests.

## Current architecture

| Trigger | Owner |
| --- | --- |
| RF source adaptation, immutable facts, measurement assembly, time/phase/geometry qualification, scene and calibration artifacts, model execution, state checkpoints, world publication, history, prediction, and query ownership | [RF world-model architecture](rf-world-model.md) |
| Existing ESP32-S3 capture, native-frame v1 sender, provisioning, authenticated UDP admission, and native CSI decode | [Firmware and native-frame architecture](firmware-native-frame.md) |

The RF world-model architecture is first-applicable for all Host behavior after
authenticated native observation admission. Its hard-rebuild rationale and the
scope it supersedes are recorded in
[ADR 0020](../adr/0020-rf-world-model-hard-rebuild.md). The existing device
firmware and its UDP contract remain an external input boundary; preserving
that boundary does not preserve the former Host, Store, world, or query
contracts.

## Superseded architecture

The former Demo Slice, Host persistence, temporal world runtime, and query
runtime architecture is available only in the
[fixed pre-rebuild Git history](https://github.com/hallucination-studio/whisper/tree/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/architecture).
It is not authority for the RF world model and cannot supply compatibility
behavior or fill a gap in the new specification. Historical execution evidence
remains historical evidence even though the architecture that produced it has
been removed from the current target.
