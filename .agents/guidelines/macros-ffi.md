# Macros and FFI

Read the matching section for macro or foreign-language interface work.

## Macros

- Prefer ordinary Rust functions, traits, and generics. If a macro is necessary, prefer `macro_rules!` over a procedural macro (M-MACRO-LAST-RESORT, M-EXAMPLE-OVER-PROC).
- Declarative macros use `$crate` for hygienic crate-relative paths. Procedural macros may assume the main crate's canonical name. Expose third-party helper items through a documented public-but-hidden `_private` module so users need not import helper crates (M-MACRO-MAIN-CRATE, M-MACRO-HELPERS).
- Syntax must reflect generated behavior; do not disguise fallibility, async work, or control flow behind misleading signatures (M-MACROS-DONT-LIE).
- Procedural macros must not generate hidden or additional public items absent from the visible source contract; a deliberately same-named supporting namespace is a narrow exception. Put parsing and generation logic in a separate non-proc-macro implementation crate with ordinary unit tests (M-PROC-IMPLIED-ITEMS, M-PROC-IMPL).

## FFI

- Name crates that import a native API with a `-sys` suffix and crates that export a foreign ABI with a `-ffi` suffix. Follow platform naming conventions for native types and scope lint exceptions narrowly (M-FFI-NAMING).
- Keep business logic in safe core crates. FFI layers only translate types, errors, ownership, and calls (M-FFI-TRANSLATES).
- Document ownership, lifetimes, threading, nullability, ABI, and failure behavior. Encapsulate unsafe calls behind the smallest sound API and test the boundary from both sides.
- Across dynamic-library boundaries, pass only portable state with a stable C-compatible representation and no dependency on either library's statics, TLS, allocator, `TypeId`, or Rust implementation layout. Do not pass `String`, `Vec`, `Box`, `repr(Rust)` values, or pointers whose allocation/deallocation or methods can cross DLL ownership. Treat each DLL's Rust runtime and statics as isolated (M-ISOLATE-DLL-STATE).
