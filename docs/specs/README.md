# Accepted specifications

Specifications define accepted behavior, not proof of implementation. There are
two operative scopes; all other former Host target specifications are removed.

| Scope | Owner |
| --- | --- |
| Fixed ESP firmware, authenticated UDP, capability, native CSI and provisioning input | [Native-frame v1](native-frame-v1.md) |
| Phone calibration, heterogeneous RF, selected joint model, A/B/C, history, runtime and acceptance | [RF world-model v1](rf-world-model-v1.md) |
| Canonical locally coherent array-capture bytes and qualified path-adapter behavior | [Array capture v1](array-capture-v1.md) |
| Versioned local Python worker and Rust numerical-client boundary | [Model worker protocol v1](model-worker-v1.md) |

The RF specification records the accepted direct-rebuild target. Its former
[issue graph](https://github.com/hallucination-studio/whisper/issues/163) has been
withdrawn; new implementation work requires separately scoped tickets through
[issue tracking](../agents/issue-tracker.md). Withdrawal does not certify the
target as implemented or change its byte/schema contracts.
No old Store or API migration is supported. An old database must be rejected
before mutation; hard-deleting code does not authorize runtime data erasure.
