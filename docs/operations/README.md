# Operations index

Load operations guidance for a human or agent procedure. Procedures do not own
normative behavior and do not establish execution evidence without a retained
receipt.

| Trigger | Owner |
| --- | --- |
| Repository software and policy checks | Run `make check` from the repository root. |
| Phone Swift package build, export, or companion recovery | [Phone client operations](phone-client.md) |
| ESP-IDF build, parity, QEMU, provisioning, flash, verification, live smoke, or receipt retention | [Firmware operations](firmware.md) |

No host-runtime or browser operations runbook has been recovered. Any active
need for one belongs in [GitHub Issues](../agents/issue-tracker.md) until a
bounded documentation ticket creates a concrete owner.

`make check` runs Rust formatting, compilation, behavior tests, Clippy and
rustdoc; the checked-in Python tests; the pinned ESP32-S3 production image
build; and deterministic checks for local documentation links, the frozen RF
design digest, the retired production surface, native safety inputs and
historical receipts. CI runs that same command, so a failing domain behavior
test fails the job visibly.

The firmware build requires a running Docker service and access to the exact
`espressif/idf` image digest declared in the Makefile. Missing Docker, an
unavailable pinned image or any firmware build failure makes `make check` fail;
there is no skip path. The image supplies the remaining ESP-IDF dependencies.

The command is software evidence only. It does not run or silently pass phone,
LiDAR, RF-array, ESP hardware, trained-model accuracy, or 14-day acceptance.
Those checks need their ticket-specific equipment and retained execution
evidence. The phone Swift package build and behavior command is included in
`make check` by the phone-client ticket; future Python or browser packages must
add their own commands when introduced.
