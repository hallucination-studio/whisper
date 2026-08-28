# Architecture Decision Records

Load an ADR only for a decision that is hard to reverse, surprising without
context, and the result of a real trade-off. ADRs own the decision and rationale;
the linked specification owns operative behavior.

| Decision question | ADR |
| --- | --- |
| Why use a custom authenticated protocol instead of legacy wire compatibility? | [ADR 0001](0001-native-frame-authentication.md) |
| Why keep one sequential Engine writer? | [ADR 0002](0002-engine-single-writer.md) |
| Why use SQLite as the authoritative session store? | [ADR 0003](0003-sqlite-authoritative-session-store.md) |
| Why require evidence before research changes production semantics? | [ADR 0004](0004-research-promotion-evidence.md) |
| Why rotate by logical session facts instead of physical SQLite size? | [ADR 0005](0005-logical-session-fact-bytes.md) |
| Why bind replay admission identity to the epoch key? | [ADR 0006](0006-bind-replay-admission-to-epoch-key.md) |
