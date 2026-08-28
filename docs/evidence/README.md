# Evidence index

Load an evidence index to distinguish implementation facts, test source,
executed receipts, WIP, accepted targets, and open evidence gaps. An index is
not itself proof of a run; only a retained receipt identified there is executed
evidence.

| Trigger | Owner |
| --- | --- |
| Rust/native-frame, firmware build or QEMU, interoperability, board, flash, or live CSI evidence | [Firmware evidence](firmware.md) |
| Configuration, session, SQLite, recovery, retention, or replay evidence | [Host persistence evidence](host-persistence.md) |
| Timeline, conditioning, estimator, Engine, semantic replay, or evaluation evidence | [Temporal world runtime evidence](world-runtime.md) |
| Query, HTTP, WebSocket, browser, disconnect/resync, or end-to-end UI evidence | [Query and UI evidence](query-ui.md) |
