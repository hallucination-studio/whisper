# Firmware and native-frame architecture

This document owns the non-discoverable responsibilities, seams, and invariants
for ESP32-S3 capture and native-frame ingestion. The exact protocol and behavior
contract lives only in the [native-frame v1 specification](../specs/native-frame-v1.md).

## Responsibilities

The firmware capture module owns target-specific callback validation, sequence
allocation, bounded snapshot slots, and loss counters. It exports complete
capture facts to the firmware sender module and has no world-model or host
identity responsibility.

The firmware sender module owns the single serialization and authenticated
transport path. It owns transport-sequence and nonce allocation, but it does
not own link identity, durable replay state, or semantic profile admission.

The host admission module owns the unauthenticated cost boundary: endpoint,
peer allowlist, fixed header, exact key lookup, and configured limits. The
durability module owns replay admission and immutable encrypted packet
retention. The host wire module owns the sole body decoder and the conversion
from authenticated firmware facts to dynamic host-domain facts. No one of
these modules may silently absorb another module's trust decision.

## Seams

```text
shared image
    + per-device provisioning record
    -> firmware startup/capability seam
    -> callback snapshot seam
    -> single sender/native-frame seam
    -> pre-authentication HeaderRoute seam
    -> durable replay and packet seam
    -> post-authentication DecodedRoute seam
    -> typed dynamic CSI
```

The provisioning seam separates common executable identity from per-device
secrets and deployment bindings. Changing a device record does not create a
different application image; changing the running image or Wi-Fi ABI changes
the capability identity that the host must admit. The provisioning record owns
station credentials and the collector endpoint, while firmware resolves the
associated AP BSSID and channel at startup and freezes them for that boot's
callback validation.

The production Host/fixture secret loader is the sole owner of filesystem
trust for `secret_root`: layout, mode, aliases, replacement, readability,
device/key-epoch selection, and key-material validation. The validated value
crosses the fixture-to-firmware provisioning boundary without a second
filesystem trust policy. The exact handoff and consumption behavior lives in
the
[native-frame v1 specification](../specs/native-frame-v1.md#provisioning-and-image-compatibility).

The callback snapshot seam isolates the Wi-Fi task from encoding, crypto, and
network latency. Snapshot ownership transfers through a bounded queue and has
one lifecycle; pressure is represented as explicit loss rather than partial
data.

The HeaderRoute seam exists before authentication and exposes only facts needed
to bound work and select one key. The DecodedRoute seam exists only after
authentication and durable admission, where source, radio, capability, sensor,
link, and profile identity can be resolved.

The durable packet seam separates security admission from semantic decoding.
It permits authenticated but semantically unsupported input to remain an
immutable fact while preventing unauthenticated or replayed traffic from
becoming session data.

## Invariants

- There is one language-neutral native-frame specification and one host decoder
  for its version. C source, Rust source, fixtures, and tests conform to that
  interface; none is a parallel authority.
- Firmware image bytes, provisioning data, native-frame datagrams, captured
  packets, and typed observations retain distinct identities and lifecycles.
- Identity is refined across trust seams. Peer address bounds work, AEAD
  authenticates device/key/epoch/message facts, and authenticated source/radio
  facts resolve the physical link.
- Wi-Fi association discovery does not weaken capture admission. One boot uses
  only the resolved associated AP BSSID and channel, and disconnect fails the
  runtime instead of silently changing the physical link.
- Raw encrypted bytes and receive context are immutable after durable admission.
  Typed CSI and profiles remain reproducible derivatives.
- Firmware preserves target facts and dynamic sample cardinality. It does not
  create a canonical tensor, physical tone axis, coherent clock, or transmitter
  identity that the target did not supply.
- Queue pressure, encode failure, send failure, and sequence exhaustion are
  observable and fail closed. No path emits a partial or nonce-reusing message.
- Runtime sensing and firmware update are separate planes. A native-frame
  endpoint never accepts executable content.
- ADR-018/RuView compatibility is absent rather than hidden behind an adapter,
  fallback, magic registry, or feature flag.

The rationale for the last invariant is recorded in
[ADR 0001](../adr/0001-native-frame-authentication.md). External target facts
are identified in [the reference](../references/native-frame.md), procedures in
[the runbook](../operations/firmware.md), and maturity in
[the evidence index](../evidence/firmware.md).
