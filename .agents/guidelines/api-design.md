# API and Type Design

Read this file for work involving public APIs, domain types, errors, modules, builders, collections, or services.

## Public surface

- Give each public item one canonical path. Do not keep duplicate re-exports as accidental compatibility layers (M-SINGLE-ITEM-PATH).
- Do not define preludes or glob import entry points. Avoid glob re-exports except narrow technical forwarding layers such as platform HALs. Re-export foreign items only from umbrella crates, deliberately split implementations, or stable macro support paths (M-NO-PRELUDE, M-NO-GLOB-REEXPORTS, M-FOREIGN-REEXPORTS).
- Avoid leaking third-party types when that binds consumers to an implementation detail. Use meaningful local abstractions. Native-handle wrappers provide a documented `unsafe from_native`/equivalent when callers must uphold validity or ownership, plus safe borrowing or consuming conversions where ownership semantics permit them (M-DONT-LEAK-TYPES, M-ESCAPE-HATCHES).
- Public types implement `Debug`. User-readable values also implement `Display`. Neither representation may leak secrets; sensitive types require redacted implementations and tests proving secret values are absent (M-PUBLIC-DEBUG, M-PUBLIC-DISPLAY).
- Use newtypes and the correct standard type family for distinct concepts and units. Invariant-bearing newtypes keep fields private, expose a fallible constructor, and use `TryFrom`/`FromStr` for weaker inputs. Do not implement `From<Weak>` for a non-total conversion, and never panic inside `From`. Safe methods preserve invariants (M-STRONG-TYPES, M-STRONG-TYPES-GUARD).
- Prefer concrete types over generics and generics over trait objects. Avoid nested generic service types, smart pointers, and implementation wrappers in primary APIs (M-DI-HIERARCHY, M-SIMPLE-ABSTRACTIONS, M-AVOID-WRAPPERS).
- Put essential operations in inherent methods; trait implementations may forward to them (M-ESSENTIAL-FN-INHERENT).

## Naming and signatures

- Prefer an ordinary function unless receiver or type association is meaningful (M-REGULAR-FN).
- Keep names short and precise. Avoid vague `Manager`, `Helper`, `Util`, `Data`, or `Info` names unless they accurately express the domain (M-SHORT-NAMES, M-WEASEL-WORDS).
- Follow Rust API conventions for conversions, getters, constructors, feature names, and common traits such as `Clone`, `Eq`, `Hash`, and `Default`. A repeatable object producer is normally a builder; a passed-in factory is normally `impl Fn() -> Foo` (M-UPSTREAM-GUIDELINES, M-WEASEL-WORDS).
- Keep conceptual parameters in a consistent order: operation-specific values first, ubiquitous context last, and a single closure last (M-PARAMETER-CONSISTENCY).
- Use `impl AsRef<T>` for clear borrowed function inputs, but do not infect stored types with unnecessary generics; accept owned values directly on hot ownership paths. Accept arbitrary ranges as `impl RangeBounds<T>`, never as raw `(low, high)` pairs. Prefer sans-I/O `Read`/`Write`-style capabilities for one-shot work; keep runtime-specific async handles explicit when a type must retain them (M-IMPL-ASREF, M-IMPL-RANGEBOUNDS, M-IMPL-IO).
- Public futures must be `Send`, and most public types should be `Send` unless thread affinity is an explicit part of their contract. Do not accidentally hide `Rc` or other thread-affine internals in them (M-TYPES-SEND).
- Heavyweight service handles should be cheap to `Clone`, normally via private `Arc<Inner>` shared ownership (M-SERVICES-CLONE).
- Avoid statics and thread-local state when correctness depends on a unique or consistent instance: multiple crate versions or dynamic libraries can silently duplicate them. Pass dependencies explicitly. Performance-only immutable state is acceptable when duplication cannot affect correctness (M-AVOID-STATICS).

## Construction and organization

- Use `FooBuilder`, exposed through `Foo::builder(...)`, once a type has more than two optional parameters or at least four meaningful construction permutations. Do not expose `FooBuilder::new()`. Use chainable field-named methods and finish with `build()` (M-INIT-BUILDER).
- Pass required dependencies when creating the builder, preferably grouped semantically. Setter methods accept values and remain infallible; validate individual and cross-field constraints in `build()`, returning `Result` when validation can fail (M-BUILD-RESULT).
- Replace constructors with four or more raw parameters with semantic helper types (M-INIT-CASCADED).
- Keep modules cohesive and balanced. Put the most important entry types at the crate root without flattening dozens of items or forcing needless navigation. Split independently useful subsystems and crates with unrelated responsibilities along domain and dependency boundaries; avoid generic `errors` or `traits` dumping modules (M-BALANCED-MODULES, M-SMALLER-CRATES).
- Avoid needless boxes, `Arc`s, nested wrappers, and pointer chasing internally (M-AVOID-INDIRECTION).
- Collection-like types provide `iter`/`iter_mut`, owned and borrowed `IntoIterator` forms, and applicable `FromIterator`/`Extend` implementations. Iterator `size_hint` values must be truthful (M-COLLECTION-TRAITS).

## Errors

- Libraries expose situation-specific error structs implementing `Debug`, `Display`, and `std::error::Error`, retaining a `Backtrace`, upstream cause, and useful context. Keep an internal `ErrorKind` private and expose focused query methods when callers need classification. Do not expose a catch-all error enum solely for implementation convenience (M-ERRORS-CANONICAL-STRUCTS).
- For owned errors, implement canonical `From<UpstreamError>` conversions and use `?`. Use `map_err` for foreign error types or call-site context that `From` cannot preserve (M-FROM-ERROR).
