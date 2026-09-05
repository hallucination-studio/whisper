# Architecture Decision Records

Load an ADR only for a decision that is hard to reverse, surprising without
context, and the result of a real trade-off. ADRs own the decision and rationale;
the linked specification owns operative behavior.

| Decision question | ADR |
| --- | --- |
| Why use a custom authenticated protocol instead of legacy wire compatibility? | [ADR 0001](0001-native-frame-authentication.md) |
| Why bind replay admission identity to the epoch key? | [ADR 0006](0006-bind-replay-admission-to-epoch-key.md) |
| Why trust the Program 1 local store namespace instead of building hostile same-credential isolation? | [ADR 0013](0013-trust-program-1-local-store-namespace.md) |
| Why does an independent thread own Host cleanup and lease release? | [ADR 0018](0018-independent-host-supervisor.md) |
| Why must production compatibility identities use domain rather than delivery-maturity terminology? | [ADR 0019](0019-maturity-neutral-compatibility-identities.md) |
| Why hard-rebuild the Host world model while preserving the existing firmware UDP input? | [ADR 0020](0020-rf-world-model-hard-rebuild.md) |

[ADR 0020](0020-rf-world-model-hard-rebuild.md) is first-applicable for the RF
world-model rebuild. It links the removed ADRs in fixed Git history and
identifies the exact post-admission scope it supersedes. That history does not
define a migration route, compatibility requirement, or parallel authority.
Native-frame authentication and replay-admission decisions remain applicable
only at the preserved firmware UDP input boundary as stated there.
