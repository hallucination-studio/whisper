---
status: accepted
---

# Bind replay admission identity to the epoch key

Whisper binds a durable replay-admission window to deployment, wire version,
device, key epoch, and the secret epoch key, so reusing public labels with
different key material cannot inherit admission state. Peer and link routing,
rate and datagram budgets, firmware and capability pins, window size, and the
global replay configuration are intentionally excluded: changing those values
must not imply a new cryptographic epoch, while window size is checked
separately. This choice requires secret access during provisioning and capture
open but avoids persisting the key itself. The exact preimage, digest, and
comparison behavior live in the
[host persistence v1 specification](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/specs/persistence-v1.md#replay-window-identity).
