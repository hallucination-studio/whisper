# Domain docs

This repository uses a multi-context domain-documentation layout.

## Before exploring

1. Read root `CONTEXT-MAP.md`.
2. Read each relevant context:
   - `src/CONTEXT.md` for the Rust host.
   - `firmware/esp32-native-frame/CONTEXT.md` for ESP-IDF firmware.
3. Read relevant system ADRs under `docs/adr/`.
4. Read context-specific ADRs under `src/docs/adr/` or
   `firmware/esp32-native-frame/docs/adr/`.

Missing context or ADR files are created lazily by domain-modeling workflows;
their absence does not block ordinary work.

## Boundaries

System-wide contracts, including native-frame wire semantics, capability
identity, provisioning boundaries, and Rust/firmware parity, belong in root
`docs/adr/`.

Host-only decisions belong in `src/docs/adr/`. Firmware-only decisions belong
in `firmware/esp32-native-frame/docs/adr/`.

Use terms defined by the relevant `CONTEXT.md`. Surface conflicts with existing
ADRs explicitly instead of silently overriding them.
