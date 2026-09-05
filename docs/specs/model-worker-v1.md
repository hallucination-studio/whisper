# Model worker protocol v1

This specification defines the local, authority-free numerical boundary between
the Rust Host and a Python/PyTorch worker. It refines the immutable-request
contract in [RF world-model v1](rf-world-model-v1.md); it does not define Store,
activation, publication, result arbitration, or ACK behavior.

## Frame and transport

One request and one response use a local Unix-domain stream. Each message is
exactly `WMW1`, a four-byte unsigned big-endian JSON byte count, and one UTF-8
JSON object. The count excludes the eight-byte header. Implementations reject a
declared frame exceeding their configured ceiling before allocating its body.
The configured ceiling is at least 404 bytes, the size required for a complete
failure response with the canonical fallback identity. There is no HTTP or
WebSocket endpoint.

JSON is emitted without insignificant whitespace. Binary material and SHA-256
digests use canonical lowercase hexadecimal strings; uppercase or otherwise
non-canonical encodings are rejected rather than normalized. Protocol and
artifact schema version `1` are the only accepted versions. Text identities are
non-empty and no longer than 128 UTF-8 bytes.

## Request

The request contains these independently checked groups:

- `identity`: model run, continuity epoch, request ID, causal cutoff in
  nanoseconds, and committed predecessor digest;
- `model_run`: exact weights and digest; algorithm, preprocessing,
  normalization, input/output/label semantics, calibration/tolerance/fusion
  policies, state format, input shape maxima, exact output shape, and numerical
  execution declaration;
- `input_manifest`: canonical frozen manifest bytes and digest, the matching
  run/epoch/cutoff/predecessor, preprocessing and input semantics, canonical
  packed little-endian float32 tensor bytes and digest, shape, source count, and
  raw-clock-domain count;
- `checkpoint`: the matching run and epoch plus exact self-contained predecessor
  bytes and digest;
- `deadline_monotonic_ns`: a deadline in the shared local monotonic clock.

All repeated identities must match. Shapes are multiplied with overflow checks;
the materialized tensor byte count must equal four times the element count.
Manifest, weights, tensor, checkpoint, frame, dimension, element, source, and
clock-domain limits are checked before numerical execution. The worker receives
all context explicitly, so a restart rematerializes the same input from the
frozen request and has no hidden continuation state.

## Feature front-end manifest

The numerical front-end uses the canonical JSON identity `rf-feature-manifest-v1`
inside the request's immutable `manifest_hex`. Its required top-level fields are
`run_id`, `epoch`, `cutoff_ns`, `preprocessing_version`, `weights_digest`,
`qualification_epoch`, `causal_context_ns`, `source_provenance`, `blocks`,
`paths`, and `map_grid`. JSON uses sorted keys, compact separators, UTF-8, and
no non-finite numbers; the SHA-256 digest covers those exact bytes.

Each block names a unique `block_id`, source and boot identity, capture time,
the raw `absolute_response`, `spectrum_shape`, `background_residual`, and
`fast_values`, plus a shape-matched mask for every vector and the preprocessing
version. Source provenance retains profile, radio, channel, clock-domain, and
raw-record digest. Blocks are strictly ordered per source and cannot lie after
the causal cutoff or repeat an identity.

The slow branch consumes the current absolute response, spectrum shape, and
conditional background residual without centering away the absolute stationary
level. The fast branch is a bounded causal TCN whose context is at most two
seconds; it records actual block intervals and masks and never reads a future
block. Missing or metadata-only values remain masked rather than becoming an
empty-room conclusion.

Each path must declare `qualified=true`, `operator=angle_delay`, and
`adapter_kind=qualified_array`, with angle, delay, path class, uncertainty,
coverage, calibration digest, phase-calibration digest, and qualification epoch.
The path also records its qualification expiry and an explicit capture-interval
coherence assertion; an expired or non-coherent path is rejected.
The four classes (`direct_path_possible`, `stable_static`,
`dynamic_candidate`, and `unexplained`) are all retained. Ordinary ESP input,
unqualified paths, or an epoch mismatch fail closed; no path is a person or
world-state position.

The front-end also contains a small supervised scattering bias/noise head. It
returns a three-coordinate foot/root-node bias, noise, and conservative
propagated uncertainty; fitting is deterministic and bounded and does not claim
real-world accuracy. Two-person inputs use order-independent sum and absolute
difference features. Explicit map cells are fused once by deterministic
cross-source attention, retaining source weights and masks rather than adding a
second task vote. Materialization rejects oversized vectors/tensors and any
NaN/Inf before returning the packed little-endian float32 tensor.

`execution.class` is either `production_gpu` or the explicitly declared
`cpu_baseline`. It also records whether deterministic algorithms are requested,
finite non-negative absolute and relative tolerances, and a reproducibility
environment identity. A missing GPU never selects CPU implicitly. Bitwise
identity is required only by the deterministic test operator; production GPU
qualification follows the declared settings and tolerances.

## Response and failures

Every response repeats protocol version and request identity. Success returns
bounded candidate and successor-checkpoint bytes plus three distinct digests:
the input tensor digest, numerical output digest, and digest of the exact
candidate-plus-successor return payload. It also returns the operator's exact
output shape and repeats the numerical qualification.
The Rust client rejects an identity, input digest, output shape, payload digest,
or numerical qualification that differs from the request.

Failures carry an empty output shape and no candidate, checkpoint, or
qualification. Status is one of
`unsupported_version`, `malformed_request`, `contract_mismatch`,
`digest_mismatch`, `invalid_shape`, `limit_exceeded`, `deadline_exceeded`,
`epoch_mismatch`, `non_finite`, `gpu_oom`, `backend_unavailable`, or
`request_conflict`, or `operator_failure`. Detail is limited to 256 bytes. OOM, NaN/Inf, invalid shape,
oversize, digest, deadline, and epoch faults therefore remain bounded model
failures and grant no publication authority.

The worker retains a bounded cache of response bytes keyed by request ID and
exact framed-request digest. An identical retry returns the same response bytes;
a different frame under the same ID returns `request_conflict`. Durable retry
and first-result arbitration remain the Rust coordinator's later C-commit
responsibility.

## Scheduling and authority

The Rust per-state-stream queue has at most one in-flight request and one latest
pending context. Submitting while busy replaces only that pending context and
returns immediately, so numerical backpressure does not block raw ingress.
Frames and retained pending context each have explicit byte ceilings.

The cross-language fixture holds a model request in flight, admits authenticated
native capability and CSI datagrams through the production Host UDP seam, and
observes their raw transaction-A facts before releasing a bounded worker
failure. The worker is checked before and after execution for the absence of any
Store or fact-log handle.

The worker is a replaceable calculator. It has no Store handle, fact log,
artifact registry, predecessor selection, activation, current-world or history
writer, publication channel, or ACK operation. Its process cache is never a
second fact log and cannot advance formal state.
