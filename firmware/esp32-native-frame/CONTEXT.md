# ESP-IDF firmware

This context names the concepts used to discuss the firmware sensing endpoint.
It exists to keep firmware domain language consistent.

## Language

**Native frame**:
The authenticated firmware-to-host protocol message used for observations and
control information.
_Avoid_: CSI packet, when the complete message is meant.

**Capability identity**:
The domain identity used to distinguish firmware and Wi-Fi ABI capabilities.
_Avoid_: device identity.

**Capability digest**:
A compact representation of capability identity.
_Avoid_: application image hash.

**Provisioning record**:
The domain description of information provisioned for a firmware sender.
_Avoid_: runtime configuration.

**Physical capture lineage**:
The procedure-recorded relationship between retained native frames and the
identified physical sender used during a capture.
_Avoid_: hardware attestation, because Program 1 has no attestation mechanism.

**Development fixture key**:
A key used by the bounded Program 1 development fixture.
_Avoid_: device credential or attestation key.

**Boot generation**:
The domain identifier for one firmware boot generation.
_Avoid_: message sequence or capture sequence.

**Message sequence**:
The domain ordering label for native-frame messages.
_Avoid_: capture sequence.

**Capture sequence**:
The domain ordering label for CSI capture occurrences.
_Avoid_: message sequence.

**CSI block layout**:
The domain description of the ordered sample blocks in a CSI observation.
_Avoid_: raw byte length.
