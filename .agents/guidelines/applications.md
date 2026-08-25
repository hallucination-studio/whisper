# Application Binaries

Read this file for application-level errors, allocator selection, or deployment CPU settings. These rules do not apply blindly to reusable libraries.

- An application and its app-only crates may standardize on one error stack such as `anyhow`, `eyre`, or `ohno`. Do not mix frameworks. Reusable libraries expose their own canonical error types (M-APP-ERROR).
- Application binaries should use `mimalloc` when the target supports it; document an opt-out when platform or project constraints prevent it (M-MIMALLOC-APPS).
- Server applications should compile for the highest `target-cpu` guaranteed by every deployment environment. Do not impose application CPU flags on libraries (M-TARGET-CPU).
