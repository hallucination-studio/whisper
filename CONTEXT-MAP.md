# Context map

Use this map after the authority router in [`docs/README.md`](docs/README.md).
It selects vocabulary scope; it does not own architecture, contracts,
implementation status, evidence, or plans.

| Context | Load when | Glossary |
| --- | --- | --- |
| Rust host | Working on host domain types, configuration, capture, persistence, replay, or host runtime | [`src/CONTEXT.md`](src/CONTEXT.md) |
| ESP-IDF firmware | Working on board capture, provisioning, native-frame encoding, sender behavior, or firmware runtime | [`firmware/esp32-native-frame/CONTEXT.md`](firmware/esp32-native-frame/CONTEXT.md) |

Load both glossaries when a topic crosses the host/firmware boundary, including
native-frame compatibility, capability identity, provisioning compatibility,
and parity. Route the substantive cross-context claim by document kind through
[`docs/README.md`](docs/README.md); neither glossary becomes its contract owner.
