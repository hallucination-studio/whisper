# Async, I/O, Logging, and Performance

Read this file for async, I/O, telemetry, allocation, hashing, throughput, or performance-sensitive work.

## Async and operations

- Prefer `async fn`. An explicit `Future` is appropriate for trait constraints, unusual lifetimes, or measured hot/heavy futures whose construction is separated to reduce retained state (M-ASYNC-FN).
- Public futures must be `Send` unless thread affinity is an explicit API contract (M-TYPES-SEND).
- Long-running compute loops and always-ready streams yield cooperatively. Optimize throughput with batching/chunking and independent partitions; avoid per-item task switches, contended locks, empty polling, and spinning (M-YIELD-POINTS, M-THROUGHPUT).
- Put user-facing I/O, clocks, entropy, environment access, and other nondeterministic or external-state system calls behind small replaceable capabilities (M-MOCKABLE-SYSCALLS).
- Production services use the repository telemetry facade, not `println!`, `eprintln!`, or `dbg!`. Intentional CLI stdout/stderr is a user interface and is allowed. Use stable event names and message templates with structured, consistently named fields; redact sensitive values (M-LOG-NOT-PRINT, M-LOG-STRUCTURED).
- Assume telemetry may remain enabled under load: control event volume and avoid events in hot inner loops. Disabled paths must also avoid eager formatting, allocation, and expensive field computation (M-LOG-OVERHEAD).

## Performance

- Correctness and clarity come first. Establish representative benchmarks, profile periodically, and optimize demonstrated hot paths. Preserve durable hotspot knowledge in code or design documentation when future maintainers need it; keep temporary benchmark narratives out of user-facing API docs (M-HOTPATH).
- Pre-size collections from reliable bounds, reuse allocations in repeated work, and shrink oversized build-time collections before retaining them (M-INITIAL-CAPACITY, M-MEM-REUSE, M-SHRINK-TO-FIT).
- Consider `Box<[T]>` or `Box<str>` for frequently instantiated internal, immutable, non-user-visible sequences that need no spare capacity; do not rewrite public APIs or cold data for this alone (M-BOX-DST).
- Use a faster non-cryptographic hasher only when collision attacks are irrelevant and measurement supports it (M-FAST-HASHER).
- Reduce the future size of measured hot async functions by separating setup and moving large parameters or temporaries out of state retained across `.await`. Verify before/after size and add a size regression test when the bound is performance-critical (M-ASYNC-STACK-SIZE).
- Avoid needless indirection in nested type hierarchies (M-AVOID-INDIRECTION).
