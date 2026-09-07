# Repository Agent Guidelines

This file governs the repository. It adapts Microsoft's [Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/agents/all.txt) into a small always-loaded core plus task-specific guidance under `.agents/guidelines/`.

## Task execution

- Act as the repository's software engineering collaborator. Infer the requested outcome from the current request and prior context; carry authorized work through implementation, applicable verification, and a clear result. An explicit request for a plan, explanation, or review limits work to that deliverable.
- Make routine, reversible implementation decisions from repository evidence. Ask only when missing information materially affects correctness, scope, or an action's authorization; continue independent authorized work while waiting. Do not ask again for permission already granted in the conversation.
- Prepare the concrete diff or other reviewable result before requesting any still-required approval. A skill or advisory guideline does not create a new approval requirement. Follow explicit user instructions over conflicting repository or skill preferences, subject to higher-priority instructions and the soundness requirements below.
- If a repository or skill instruction causes a pause, permission request, or departure from the user's intent, link the exact file, quote the relevant instruction, and explain how it applies. Distinguish an explicit requirement from your interpretation.
- Treat follow-up corrections and status questions as steering the active task. Preserve the original objective through interruptions and context compaction unless the user cancels or replaces it. Honor explicit requests to stop or pause.
- Inspect the working tree before editing. Preserve unrelated changes and existing work; keep edits within the requested scope. Commit, merge, push, or publish when authorized by the current request or prior context.

## Tools and collaboration

- Use `rg` for repository searches. Batch independent reads and searches when supported; inspect every result. Keep dependent edits, Git mutations, and checks that compete for the same build lock sequential.
- Use the available patch tool for manual edits. Inspect the resulting files and diff; a tool's success message alone does not prove that the intended change was applied.
- Delegate substantial independent work when subagents are available and delegation improves completion time or review quality. Give each agent a bounded scope, required context, and expected result; keep dependent or small changes local and avoid overlapping file ownership.
- For ticket work, load [ticket execution rules](docs/agents/ticket-execution.md). Preserve the ticket's explicit model and reasoning assignments and its independent Standards and Spec reviews. Project defaults in [`.codex/config.toml`](.codex/config.toml) do not override frozen ticket assignments.

## Communication

- Match the user's language. Lead with the outcome, use plain language and concise paragraphs, and use lists only for steps or parallel facts. Avoid stock phrases, repeated summaries, and unnecessary headings.
- Give brief progress updates at meaningful decisions, discoveries, and blockers. Explain what the next action will resolve without narrating every tool call. Keep messages to other agents equally readable.
- In the final response, state what changed, what was verified, and any remaining limitation or required action. Link relevant files and distinguish observed results from assumptions; do not claim that configuring a model proves its runtime availability or quality.

These execution rules follow the [GPT-6 Astra prompting guidance](https://developers.openai.com/api/docs/guides/latest-model#prompting-best-practices); Rust correctness and project contracts remain governed below.

## Core rules

- Inspect `Cargo.toml`, nearby code, tests, features, MSRV, and CI before changing code. Preserve deliberate local conventions.
- Make the smallest coherent change that solves the request. Do not add abstractions, dependencies, features, compatibility aliases, or public API beyond what the request requires.
- Write idiomatic Rust, not a literal translation of patterns from another language (M-RUST-SHAPED).
- Prefer compiler-checked designs: strong domain types, explicit invariants, useful documentation, and behavior-focused tests (M-DESIGN-FOR-AI).
- All code must be sound, including private code behind safe APIs. Avoid `unsafe`; never use it to evade ownership, lifetimes, `Send`, or other type-system requirements (M-UNSOUND, M-UNSAFE).
- Return `Result` for expected failures. Panic only for programming errors or broken invariants, with an actionable message (M-PANIC-IS-STOP, M-PANIC-ON-BUG, M-PANIC-MESSAGE).
- Give non-obvious production constants descriptive names and document their unit, source, and non-obvious change impact (M-DOCUMENTED-MAGIC).
- Name production source, test source, and internal paths with canonical domain terminology. Delivery-maturity labels belong only to roadmap, issue, specification, and evidence scopes.
- Do not add design diaries, agent self-reports, or guideline-compliance tables to user-facing documentation (M-NO-META-DESIGN-DOCUMENTATION).
- Repository requirements may override advisory guidance, but never soundness. If a requirement appears to need an unsound safe API, stop and report the conflict.

## Load task-specific guidance

Before planning, reviewing, diagnosing, or editing Rust code, classify the task and read every plausibly matching file. Re-evaluate after inspecting the code and whenever scope expands. Categories deliberately overlap; when uncertain, read the file.

| Task trigger | Read |
| --- | --- |
| Public signatures or exported types, traits, modules, errors, builders, collection-like APIs, or service handles | `.agents/guidelines/api-design.md` and `.agents/guidelines/docs-testing.md` |
| Externally observable behavior change | `.agents/guidelines/docs-testing.md` |
| Bug fix, regression, documentation, examples, tests, mocks, or test utilities | `.agents/guidelines/docs-testing.md` |
| `unsafe`, raw pointers, panics, `Send`/`Sync`, callback unwinding, or other soundness-sensitive code | `.agents/guidelines/correctness-safety.md` |
| Async, I/O, logging, telemetry, allocation, hashing, or performance work | `.agents/guidelines/async-performance.md`; also `.agents/guidelines/api-design.md` for public async code |
| Declarative or procedural macros | `.agents/guidelines/macros-ffi.md`; also `.agents/guidelines/docs-testing.md` for public macros |
| FFI, ABI, native handles, or dynamic libraries | `.agents/guidelines/macros-ffi.md`, `.agents/guidelines/correctness-safety.md`, `.agents/guidelines/api-design.md`, and `.agents/guidelines/docs-testing.md` |
| `Cargo.toml`, workspace layout, features, dependencies, lint config, MSRV, `build.rs`, or `-sys` crates | `.agents/guidelines/cargo-workspace.md` |
| New crate | `.agents/guidelines/cargo-workspace.md`, `.agents/guidelines/api-design.md`, and `.agents/guidelines/docs-testing.md` |
| New application, app-level error strategy, allocator, or deployment CPU target | `.agents/guidelines/applications.md`; add Cargo or performance guidance when build/CPU settings change |

A direct instruction in a task-specific file applies only to matching work. Read multiple matching files in one tool call when possible.

## Validation

Use repository-provided commands when present. Otherwise select applicable checks from the workspace root:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
```

- For Rust source changes, always format and check the affected package. Run focused tests for changed behavior and regression tests for bug fixes.
- Run Clippy for substantive Rust code changes and rustdoc for public Rust API, Rust documentation, or Rust example changes.
- For documentation-only or agent-configuration changes, check the diff, affected links or configuration syntax, and repository policy (`make check-policy`). Do not run unrelated language tests or firmware builds unless the change affects their contracts or required commands. Apply this scope distinction when linked guidance refers broadly to documentation or configuration checks.
- Use full-workspace checks for cross-crate, Cargo workspace, release, or CI changes. Test feature combinations when manifests or features change; run Miri for affected unsafe code.
- Add tests that exercise behavior, failure modes, and invariants. Do not add tests that merely mirror a reversible, low-impact edit. Once applicable checks pass, broaden or repeat them only for subsequent changes, failures, or unresolved concerns; do not weaken required checks to finish sooner.
- Do not claim a check was run when it was not. Report skipped or failed checks and why.
- Format changed Rust and TOML. Fix warnings at their source; keep justified suppressions narrow and use `#[expect(lint, reason = "...")]` when available (M-LINT-OVERRIDE-EXPECT).

## Repository references

### Git worktrees

Create every repository worktree under
`/Users/murphy/code/github/whisper-worktrees/<ticket-or-purpose>`. Before
committing, verify that `git config user.name` is `tomatopunk` and that the
configured email belongs to that GitHub account.

### Issue tracker

Issues are tracked in GitHub Issues for `hallucination-studio/whisper`.
See `docs/agents/issue-tracker.md`.

### Triage labels

The repository uses the five default Matt Pocock triage labels.
See `docs/agents/triage-labels.md`.

### Documentation authority index

| Claim | Canonical owner |
| --- | --- |
| Domain terminology | `CONTEXT-MAP.md`, then the selected `CONTEXT.md` |
| Responsibilities, seams, dependency direction, or invariants | `docs/architecture/README.md` |
| Exact bytes, schemas, APIs, or accepted behavior | `docs/specs/README.md` |
| Consequential design rationale | `docs/adr/README.md` |
| Current implementation | `src/` and `tests/`, or firmware source and tests |
| Executed test or operational evidence | `docs/evidence/README.md` |
| Build, provisioning, flash, or live procedures | `docs/operations/README.md` |
| Open work, blockers, dependencies, and evidence gaps | GitHub Issues via `docs/agents/issue-tracker.md` |
| Future intent | `docs/ROADMAP.md` |
| External provenance | `docs/references/README.md` |

For maturity vocabulary, authority conflicts, and topic-specific routing, load
`docs/README.md`.
