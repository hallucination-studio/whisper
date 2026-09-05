# Context map

Use the [authority router](docs/README.md) to select a claim kind first. These
glossaries define words, not implementation status, responsibilities or plans.

| Context | Load when | Glossary |
| --- | --- | --- |
| RF Host | Observations, space, calibration, model execution, world state, storage or query | [Host language](src/CONTEXT.md) |
| ESP-IDF firmware | Fixed device capture, provisioning, authenticated native-frame and sender behavior | [Firmware language](firmware/esp32-native-frame/CONTEXT.md) |

Crossing the fixed device/Host boundary requires both vocabularies. Phone
SceneSnapshot and SupervisionSegment products use the Host spatial terminology;
mobile platform details do not redefine RF observation facts.
