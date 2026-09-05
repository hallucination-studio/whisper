# Evidence index

A retained receipt proves only its identified revision, environment, procedure
and result. A test file, closed ticket or design-review pass is not executed
RF accuracy evidence. New implementation and acceptance work is tracked by
[Spec #163](https://github.com/hallucination-studio/whisper/issues/163).

| Evidence scope | Owner |
| --- | --- |
| Unchanged native-frame, firmware build/provisioning, board and UDP acquisition | [Firmware evidence](firmware.md) |
| Raw segments, A/B/C, request/checkpoint recovery, retention and independent history | [Host persistence evidence](host-persistence.md) |
| Phone/calibration qualification, RF observability, joint state, training, prediction and comparative accuracy | [World-model evidence](world-runtime.md) |
| Current/history queries, freshness/expiry, browser disconnect/resync and sustained delivery | [Query and browser evidence](query-ui.md) |

Existing physical capture receipts remain bounded historical evidence. Their
capture and verification payloads are unchanged; historical contract locators
are pinned to the revision that owned those contracts. No prior Demo or
Semantic Program classification satisfies the new RF world-model target.
