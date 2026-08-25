# Rust Agent Guidelines

This file governs the repository. It adapts the checked-in [`all.txt`](all.txt) snapshot of Microsoft's [Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/agents/all.txt) into a small always-loaded core plus task-specific guidance under `.agents/guidelines/`.

## Core rules

- Inspect `Cargo.toml`, nearby code, tests, features, MSRV, and CI before changing code. Preserve deliberate local conventions.
- Make the smallest coherent change that solves the request. Do not add abstractions, dependencies, features, compatibility aliases, or public API beyond what the request requires.
- Write idiomatic Rust, not a literal translation of patterns from another language (M-RUST-SHAPED).
- Prefer compiler-checked designs: strong domain types, explicit invariants, useful documentation, and behavior-focused tests (M-DESIGN-FOR-AI).
- All code must be sound, including private code behind safe APIs. Avoid `unsafe`; never use it to evade ownership, lifetimes, `Send`, or other type-system requirements (M-UNSOUND, M-UNSAFE).
- Return `Result` for expected failures. Panic only for programming errors or broken invariants, with an actionable message (M-PANIC-IS-STOP, M-PANIC-ON-BUG, M-PANIC-MESSAGE).
- Give non-obvious production constants descriptive names and document their unit, source, and non-obvious change impact (M-DOCUMENTED-MAGIC).
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

- Always format and check the affected package. Run focused tests for changed behavior and regression tests for bug fixes.
- Run Clippy for substantive code changes and rustdoc for public API or documentation changes.
- Use full-workspace checks for cross-crate, workspace, release, or CI changes. Test feature combinations when manifests or features change; run Miri for affected unsafe code.
- Do not claim a check was run when it was not. Report skipped or failed checks and why.
- Format changed Rust and TOML. Fix warnings at their source; keep justified suppressions narrow and use `#[expect(lint, reason = "...")]` when available (M-LINT-OVERRIDE-EXPECT).
