# Accepted specifications

Specifications define accepted behavior, not proof of implementation. There are
two operative scopes; all other former Host target specifications are removed.

| Scope | Owner |
| --- | --- |
| Fixed ESP firmware, authenticated UDP, capability, native CSI and provisioning input | [Native-frame v1](native-frame-v1.md) |
| Phone calibration, heterogeneous RF, selected joint model, A/B/C, history, runtime and acceptance | [RF world-model v1](rf-world-model-v1.md) |
| Versioned local Python worker and Rust numerical-client boundary | [Model worker protocol v1](model-worker-v1.md) |

The RF specification is the accepted direct-rebuild target. Its implementations
and any narrower byte/schema artifacts are owned by the new
[issue graph](https://github.com/hallucination-studio/whisper/issues/163).
No old Store or API migration is supported. An old database must be rejected
before mutation; hard-deleting code does not authorize runtime data erasure.
