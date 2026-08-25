# Correctness and Safety

Read this file for `unsafe`, panic behavior, concurrency, FFI safety, or other soundness-sensitive changes.

- All code must be sound. Safe APIs must remain sound for every accepted input, regardless of visibility or documentation; there are no exceptions for undefined behavior (M-UNSOUND).
- Use `unsafe` only for a sound abstraction unavailable elsewhere, measured performance, or necessary FFI/platform access. Keep it minimal and encapsulated (M-UNSAFE).
- Prefer an established safe abstraction. Never use `unsafe` to bypass ownership, lifetimes, `Send`, or other compiler requirements.
- Explain the safety invariant in plain language at each unsafe operation. Test adversarial `Deref`, `Clone`, `Drop`, callback-panic, aliasing, and concurrency behavior where relevant. Run Miri over affected paths.
- Mark a function or trait `unsafe` only when misuse can cause undefined behavior, not merely data loss or another dangerous side effect. Document a `# Safety` contract (M-UNSAFE-IMPLIES-UB).
- Panics mean stop, not recoverable exceptions. Do not use them for invalid external input, I/O failure, or error propagation (M-PANIC-IS-STOP).
- Panic for detected programmer mistakes or broken invariants; return `Result` for expected operational failure. Prefer unrepresentable invalid states (M-PANIC-ON-BUG).
- Production `panic!`, `assert!`, `unreachable!`, and `todo!` calls need messages explaining the violated condition and relevant values. Test assertions usually do not (M-PANIC-MESSAGE).
- `catch_unwind` is a last-resort isolation boundary. Do not continue indefinitely after a panic; arrange controlled restart where applicable (M-PANIC-CONTINUATION).
