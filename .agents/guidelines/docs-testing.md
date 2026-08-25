# Documentation and Testing

Read this file when changing documentation, examples, tests, mocks, or test support.

## Documentation

- Add `//!` docs to public modules and `///` docs to public items. Explain purpose, important invariants, and normal use for a competent Rust developer (M-MODULE-DOCS).
- Begin with a one-line summary of roughly 15 words. Add canonical sections when relevant, ordered as examples, errors, panics, safety, and abort. Explain parameters in prose; do not create parameter tables (M-FIRST-DOC-SENTENCE, M-CANONICAL-DOCS).
- Examples use the public API, are directly usable, use `?` for fallible calls, and compile as doctests where practical.
- Mark re-exports of this crate's own items with `#[doc(inline)]` at their canonical path. Do not inline re-exported standard-library or third-party items (M-DOC-INLINE).
- Document unusual constants and magic values with units, origin, range, or rationale (M-DOCUMENTED-MAGIC).
- Describe current behavior and enduring architecture. Do not add design journals, agent self-reports, process narratives, or guideline-compliance tables (M-NO-META-DESIGN-DOCUMENTATION).

## Tests

- Test observable behavior, boundary cases, failure modes, and invariants. Do not mirror constants or reconstruct the implementation's own result (M-TAUTOLOGICAL-TESTS).
- Keep tests needing private details beside the implementation. Put tests that exercise only public API in `tests/`; prefer integration tests when either location works (M-INTEGRATION-TESTS).
- Gate reusable mocks, fakes, test helpers, sensitive-data inspection, safety-check bypasses, and fake-data facilities behind a non-default feature (M-TEST-UTIL).
- Make external I/O, clocks, randomness, environment access, and system calls replaceable through small capabilities or explicit dependencies. Avoid a giant mock-everything trait (M-MOCKABLE-SYSCALLS).
- Add an economical regression test for a reproducible bug. Do not weaken or delete meaningful tests just to make a change pass.
