# Host persistence evidence index

This index distinguishes clean-HEAD implementation facts, checked-in test
source, fresh execution receipts, accepted targets, and uncommitted WIP for
host configuration, sessions, and persistence. It owns no normative behavior.

## Snapshot classification

Baseline revision: `f83428c31aba285277fc95db4079228b97ecaa62`

Classification date: 2026-08-27

At this revision, code plus behavior-test source establishes a validated
`Config`/`ReplayConfig` split, canonical replay bytes and digest, dormant
private file-session primitives, strict manifest/record codecs, an advisory
lock primitive, crash-tail/CRC reading, and file-retention helpers. The binary
exposes only `check-config`; no production capture, persistence, recovery, or
replay workflow calls those session primitives.

Clean HEAD has no SQLite dependency or database module. Its session storage
path is a directory, its manifest seed is snapshot-only, and its private
session format is an `RFWSESS` CRC-framed file. These are implemented and
tested predecessor primitives, not the accepted v1 SQLite target and not a
production persistence runtime.

## Clean HEAD receipt

At `2026-08-27T12:46:47Z`, an archive of the exact baseline revision was tested
from `/private/tmp/whisper-f83428c.KMslrV` with a fresh
`CARGO_TARGET_DIR=/private/tmp/whisper-clean-f83428c-target` on
`aarch64-apple-darwin`:

```text
rustc 1.91.0 (f8297e351 2025-10-28)
cargo 1.91.0 (ea2d97820 2025-10-10)
cargo test --workspace --all-features
PASS: 66 library tests + 7 integration tests; 0 failures; 0 doc tests
```

At `2026-08-27T12:47:10Z`, the same clean archive was checked with
`rustfmt 1.8.0-stable`:

```text
cargo fmt --all -- --check
FAIL: rustfmt proposed broad changes to existing Rust source
```

The passing tests are executed HEAD evidence, not WP 2.1 or v1 acceptance.
The format failure is a historical result from that identified run. Live work
and gates are owned by [GitHub Issues](../agents/issue-tracker.md).

## Historical WIP audit observations

The original worktree was inspected at the same baseline on the classification
date with uncommitted
persistence work in `Cargo.toml`, `Cargo.lock`, `src/config.rs`,
`src/domain/world.rs`, `src/lib.rs`, `src/session.rs`,
`tests/config_validation.rs`, the config fixture, and an untracked
`src/database.rs`. The tracked persisted session fixture was deleted.

The delta proposes a SQLite dependency and schema, database-path configuration,
complete baseline state, strict SQLite session codecs, admission/lifecycle
primitives, and retention. It is uncommitted WIP and is not current
implementation authority.

At `2026-08-27T13:22:17Z`, the then-observed tracked product delta had SHA-256
`1cfd883c4d1252ba087e0bae3f3f16600b971b45ec43f73f2515ca600a97f457`,
computed reproducibly from this exact path set:

```sh
LC_ALL=C git diff --binary --full-index --no-ext-diff --no-textconv --no-color \
  f83428c31aba285277fc95db4079228b97ecaa62 -- \
  Cargo.lock Cargo.toml src/config.rs src/domain/world.rs src/lib.rs \
  src/session.rs tests/config_validation.rs \
  tests/fixtures/config/valid-two-esp32.toml \
  tests/fixtures/session/session-v1.hex | shasum -a 256
```

The binary diff includes the deleted persisted session fixture. The untracked
`src/database.rs` separately had SHA-256
`528d723c4e48fde594b4f56f03ef2e30b50370a13bb25e1054514d43ffc3f779`,
computed with:

```sh
shasum -a 256 src/database.rs
```

Generated firmware `__pycache__` files and all documentation paths were outside
both fingerprints. These fingerprints bind only that historical classification
snapshot; later worktree changes are intentionally outside their scope.

At `2026-08-27T12:46:21Z`, a WIP state in the original worktree was tested with
a fresh `CARGO_TARGET_DIR=/private/tmp/whisper-f83428c-target` on the same
toolchain and host:

```text
cargo test --workspace --all-features
PASS: 65 library tests + 7 integration tests; 0 failures; 0 doc tests
```

At `2026-08-27T12:47:10Z`:

```text
cargo fmt --all -- --check
PASS
```

No execution-time patch digest or archived worktree was retained for these two
runs. The product-file modification times observed during classification did
not show a later edit, but that observation cannot independently bind the
recorded fingerprints to the executed bytes. The pass lines are therefore
non-reconstructable audit observations, not immutable receipts or evidence for
the recorded fingerprint.
They do not prove conformance, production wiring, recovery, faithful replay, or
WP 2.1 completion.

## Coverage and maturity matrix

| Surface | Clean HEAD | WIP observed on 2026-08-27 | V1 maturity |
| --- | --- | --- | --- |
| Config root and replay digest | implementation, behavior-test source, and passing execution | preserved; proposes runtime database-path rename | implemented predecessor plus accepted rename target |
| Manifest and record strong codecs | strict private codecs and passing test source | proposes complete baseline-state codec and SQLite-facing reuse | predecessor implementation; accepted target incomplete |
| File-session append/recovery/retention | dormant private CRC-framed primitives and passing test source | removed/replaced in delta | implemented predecessor only; no production caller |
| SQLite schema and admission transaction | absent | proposed module and three unit-test sources | accepted target; WIP only |
| Production capture/recovery/replay app | absent; binary has `check-config` only | absent | accepted-but-unimplemented |
| Semantic projections and Engine handoff | absent | absent | accepted-but-unimplemented in later work packages |
| WP 2.1 acceptance | no applicable SQLite implementation | known non-compliance and missing direct evidence | blocked |

## Settled WIP blockers

The following are known WP 2.1 non-compliance or acceptance blockers, not open
design questions:

- `body_cbor` stores a complete encoded record while the row also stores
  sequence, time, and kind. Read-time cross-checks do not cure the forbidden
  duplicate representation.
- The required persisted session fixture is missing. An in-memory roundtrip
  does not prove exclusion of TOML source, RuntimeConfig, secrets, and lossy
  snapshot-only baseline state.
- Database open checks for a file and then uses a create-capable open. Removal
  between those operations can create a new artifact, so capture-not-create is
  not mechanically guaranteed.
- Direct acceptance evidence is still missing for duplicate record-sequence
  rejection, corrupt-database rejection, pre-existing incompatible pragma
  handling, full-width record-sequence ordering, and persisted artifact
  exclusions.

## Accepted design targets without implementation evidence

The persistence specification and ADRs now settle the design targets for:

- persistent versus connection-local SQLite settings;
- logical session fact-byte accounting;
- removal of the predecessor flush policy;
- managed database and runtime lock identity;
- application-owned recovery proof and lifecycle coordination;
- Engine-produced complete-baseline handoff; and
- epoch-key-bound replay-window admission identity.

These are accepted targets, not implementation facts. Clean HEAD does not
implement them, and the classified WIP snapshot and retained receipts do not
prove them.
The settled decision content is distinct from remaining delivery obligations;
the bounded implementation and evidence gaps are listed below.

## Active gaps

Issue #6 is the recovery parent. Its bounded native child issues are:

- [#32](https://github.com/hallucination-studio/whisper/issues/32): correct the
  duplicate full record envelope stored in `body_cbor`.
- [#31](https://github.com/hallucination-studio/whisper/issues/31): restore the
  persisted session fixture and its exclusion checks; natively blocked by
  #32.
- [#34](https://github.com/hallucination-studio/whisper/issues/34): make
  operational database open mechanically non-creating.
- [#30](https://github.com/hallucination-studio/whisper/issues/30): add direct
  corruption, duplicate-sequence, and full-width unsigned-order evidence.
- [#33](https://github.com/hallucination-studio/whisper/issues/33): add direct
  incompatible persistent-setting and connection-local-setting evidence.
- [#28](https://github.com/hallucination-studio/whisper/issues/28): remove
  `flush_policy` from configuration, runtime types, the configuration fixture,
  and behavior tests.

Managed runtime lock identity and replay-window admission identity additionally
require delivery and execution evidence under
[#25 runtime lock identity](https://github.com/hallucination-studio/whisper/issues/25)
and
[#35 replay-window admission identity](https://github.com/hallucination-studio/whisper/issues/35).
Their normative decisions are accepted, but implementation and execution
evidence have not been established.

Issue #24 has closed the pragma-semantics decision; implementation conformance
and executed evidence remain open under #33. The accepted target includes
pragma semantics, logical session byte accounting, Engine-produced complete-
baseline handoff, removal of the predecessor flush policy, and compatible Host
restart inside the same active session. Neither Clean HEAD, the classified WIP
snapshot, nor the retained receipts establish implementation or executed
acceptance evidence for those targets.

The exact accepted behavior is in the
[host persistence v1 specification](../specs/persistence-v1.md), and
non-discoverable ownership is in the
[host persistence architecture](../architecture/host-persistence.md).
