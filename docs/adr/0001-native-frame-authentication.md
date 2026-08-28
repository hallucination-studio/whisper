---
status: accepted
---

# Use a custom authenticated native-frame protocol

Whisper uses one custom, capability-pinned, authenticated firmware-to-host
protocol instead of retaining ADR-018/RuView compatibility. Reusing the legacy
wire would preserve its magic routing, fixed-shape assumptions, and ambiguous
identity and validity semantics; a compatibility decoder would also keep two
security and replay surfaces alive. The chosen protocol costs a coordinated C,
Rust, provisioning, fixture, and retained-session transition, but gives one
explicit trust boundary and preserves target facts without a legacy fallback.
Its operative contract is [native-frame v1](../specs/native-frame-v1.md).
