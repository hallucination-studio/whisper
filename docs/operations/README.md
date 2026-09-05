# Operations index

Load operations guidance for a human or agent procedure. Procedures do not own
normative behavior and do not establish execution evidence without a retained
receipt.

| Trigger | Owner |
| --- | --- |
| Repository software and policy checks | Run `make check` from the repository root. |
| ESP-IDF build, parity, QEMU, provisioning, flash, verification, live smoke, or receipt retention | [Firmware operations](firmware.md) |
| Local deterministic model-protocol fixture | Run `python3 -m model_worker --socket /new/path/worker.sock --operator deterministic-test`. |

No composed Host-runtime or browser operations runbook has been recovered. Any active
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
evidence. A future Python, Swift or browser package must add its build and
behavior command to `make check` in the ticket that introduces the package.

The deterministic worker operator validates protocol dispatch and failure
handling only. It is not an RF model or accuracy result. The socket path must
not already exist; the worker never deletes or replaces it. A production model
integration must supply its frozen PyTorch evaluator and declare
`production_gpu`; unavailable GPU execution fails explicitly rather than
falling back to CPU.
