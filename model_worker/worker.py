"""Versioned, bounded local execution boundary for immutable model requests."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import math
import socket
import struct
import time
from types import MappingProxyType
from typing import Callable, Protocol


MAGIC = b"WMW1"
PROTOCOL_VERSION = 1
HEX_DIGEST_CHARS = 64
# Smallest complete WMW1 failure frame, using the canonical fallback identity,
# the longest known failure status, and an empty detail string.
MIN_FRAME_BYTES = 404
FAILURE_STATUSES = frozenset(
    {
        "unsupported_version",
        "malformed_request",
        "contract_mismatch",
        "digest_mismatch",
        "invalid_shape",
        "limit_exceeded",
        "deadline_exceeded",
        "epoch_mismatch",
        "non_finite",
        "gpu_oom",
        "backend_unavailable",
        "request_conflict",
        "operator_failure",
    }
)
FALLBACK_IDENTITY = MappingProxyType(
    {
        "run_id": "unknown",
        "epoch": 0,
        "request_id": "unknown",
        "cutoff_ns": 0,
        "predecessor_digest": "0" * HEX_DIGEST_CHARS,
    }
)


@dataclass(frozen=True)
class Limits:
    """Resource ceilings applied before allocation or numerical execution."""

    max_frame_bytes: int = 1_048_576
    max_manifest_bytes: int = 131_072
    max_weights_bytes: int = 262_144
    max_tensor_bytes: int = 524_288
    max_result_bytes: int = 524_288
    max_checkpoint_bytes: int = 131_072
    max_shape_dimensions: int = 8
    max_dimension: int = 65_536
    max_elements: int = 131_072
    max_sources: int = 64
    max_clock_domains: int = 64
    max_completed_replies: int = 64

    def __post_init__(self) -> None:
        if self.max_frame_bytes < MIN_FRAME_BYTES:
            raise ValueError(f"max_frame_bytes must be at least {MIN_FRAME_BYTES}")


class Operator(Protocol):
    """Numerical implementation that cannot access persistence or publication."""

    def evaluate(self, request: Mapping[str, object]) -> tuple[bytes, tuple[int, ...], bytes]:
        """Return candidate bytes, exact output shape, and successor material."""


def _immutable(value: object) -> object:
    """Recursively freeze decoded JSON before it crosses the operator boundary."""

    if isinstance(value, dict):
        return MappingProxyType({key: _immutable(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_immutable(item) for item in value)
    return value


def _canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def encode_frame(value: dict, limits: Limits) -> bytes:
    """Encode one canonical JSON message behind a bounded WMW1 frame."""

    payload = _canonical_json(value)
    if len(payload) > limits.max_frame_bytes - 8:
        raise ValueError("frame exceeds configured byte limit")
    return MAGIC + struct.pack(">I", len(payload)) + payload


def decode_frame(frame: bytes, limits: Limits) -> dict:
    """Decode one complete frame after validating its declared size."""

    if len(frame) < 8 or frame[:4] != MAGIC:
        raise ValueError("invalid worker frame magic")
    declared = struct.unpack(">I", frame[4:8])[0]
    if declared > limits.max_frame_bytes - 8:
        raise ValueError("frame exceeds configured byte limit")
    if len(frame) != declared + 8:
        raise ValueError("worker frame length mismatch")
    value = json.loads(frame[8:])
    if not isinstance(value, dict):
        raise ValueError("worker payload must be an object")
    return value


def read_frame(stream: socket.socket, limits: Limits) -> bytes:
    """Read exactly one bounded frame without trusting its length prefix."""

    header = _read_exact(stream, 8)
    if header[:4] != MAGIC:
        raise ValueError("invalid worker frame magic")
    length = struct.unpack(">I", header[4:])[0]
    if length > limits.max_frame_bytes - 8:
        raise ValueError("frame exceeds configured byte limit")
    return header + _read_exact(stream, length)


def _read_exact(stream: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = stream.recv(count - len(chunks))
        if not chunk:
            raise EOFError("worker connection closed during frame")
        chunks.extend(chunk)
    return bytes(chunks)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex_bytes(value: object, maximum: int, field: str) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) % 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ContractFailure("malformed_request", f"{field} is not canonical lowercase hex")
    if len(value) // 2 > maximum:
        raise ContractFailure("limit_exceeded", f"{field} exceeds its byte limit")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ContractFailure("malformed_request", f"{field} is not hex") from error


def _check_digest(value: object, content: bytes, field: str) -> None:
    if not isinstance(value, str) or len(value) != HEX_DIGEST_CHARS or value != _digest(content):
        raise ContractFailure("digest_mismatch", f"{field} does not match content")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 128:
        raise ContractFailure("malformed_request", f"{field} must be 1..128 UTF-8 bytes")
    return value


class ContractFailure(Exception):
    """Expected invalid-input or bounded numerical failure."""

    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status if status in FAILURE_STATUSES else "operator_failure"
        self.detail = detail


class DeterministicTestOperator:
    """A fixture-only numeric operator used to verify dispatch and restart behavior."""

    def evaluate(self, request: Mapping[str, object]) -> tuple[bytes, tuple[int, ...], bytes]:
        tensor = bytes.fromhex(request["input_manifest"]["tensor_hex"])
        values = struct.unpack(f"<{len(tensor) // 4}f", tensor)
        candidate = struct.pack(f"<{len(values)}f", *(value * 2.0 for value in values))
        checkpoint = bytes.fromhex(request["checkpoint"]["bytes_hex"])
        successor = hashlib.sha256(b"successor-v1" + checkpoint + tensor).digest()
        return candidate, (len(values),), successor


class TorchOperator:
    """PyTorch execution adapter with explicit device selection and no fallback."""

    def __init__(self, evaluate: Callable[[object, Mapping[str, object]], tuple[object, object]]):
        self._evaluate = evaluate

    def evaluate(self, request: Mapping[str, object]) -> tuple[bytes, tuple[int, ...], bytes]:
        try:
            import torch
        except ImportError as error:
            raise ContractFailure("backend_unavailable", "PyTorch is not installed") from error

        try:
            execution = request["model_run"]["execution"]
            execution_class = execution["class"]
            if execution_class == "production_gpu":
                if not torch.cuda.is_available():
                    raise ContractFailure("backend_unavailable", "requested GPU is unavailable")
                device = torch.device("cuda")
            elif execution_class == "cpu_baseline":
                device = torch.device("cpu")
            else:
                raise ContractFailure("contract_mismatch", "execution class is not declared")

            torch.use_deterministic_algorithms(execution["deterministic_algorithms"])
            tensor_bytes = bytes.fromhex(request["input_manifest"]["tensor_hex"])
            tensor = torch.frombuffer(bytearray(tensor_bytes), dtype=torch.float32).clone().to(device)
            candidate, successor = self._evaluate(tensor, request)
            candidate = candidate.detach().to("cpu").contiguous()
            if not torch.isfinite(candidate).all().item():
                raise ContractFailure("non_finite", "operator returned NaN or Inf")
            output_shape = tuple(candidate.shape)
            candidate_bytes = candidate.numpy().tobytes(order="C")
            successor_bytes = bytes(successor)
            return candidate_bytes, output_shape, successor_bytes
        except torch.cuda.OutOfMemoryError as error:
            raise ContractFailure("gpu_oom", "GPU allocation failed") from error


class Worker:
    """Validates immutable requests and returns candidate material without authority."""

    def __init__(self, operator: Operator, limits: Limits, *, now_ns: Callable[[], int] = time.monotonic_ns):
        self._operator = operator
        self._limits = limits
        self._now_ns = now_ns
        self._completed: OrderedDict[str, tuple[str, bytes]] = OrderedDict()

    def handle_frame(self, frame: bytes) -> bytes:
        """Validate and execute one request, always returning a bounded response frame."""

        try:
            request = decode_frame(frame, self._limits)
        except (ValueError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
            return self._failure({}, "malformed_request", str(error))

        identity = self._safe_identity(request.get("identity"))
        request_id = identity.get("request_id", "")
        request_payload_digest = _digest(frame)
        completed = self._completed.get(request_id)
        if completed is not None:
            previous_digest, previous_response = completed
            if previous_digest == request_payload_digest:
                return previous_response
            return self._failure(identity, "request_conflict", "request ID was reused with different bytes")

        try:
            tensor, deadline, output_elements, execution = self._validate(request)
            candidate, output_shape, successor = self._operator.evaluate(_immutable(request))
            if self._now_ns() > deadline:
                raise ContractFailure("deadline_exceeded", "request deadline elapsed during execution")
            if len(candidate) > self._limits.max_result_bytes or len(successor) > self._limits.max_checkpoint_bytes:
                raise ContractFailure("limit_exceeded", "operator output exceeds configured limit")
            if len(candidate) != output_elements * 4:
                raise ContractFailure("invalid_shape", "candidate bytes do not match declared output shape")
            if not isinstance(output_shape, tuple) or output_shape != tuple(request["model_run"]["output_shape"]):
                raise ContractFailure("invalid_shape", "candidate shape differs from declared output shape")
            if any(not math.isfinite(value) for value in struct.unpack(f"<{len(candidate) // 4}f", candidate)):
                raise ContractFailure("non_finite", "operator returned NaN or Inf")
            response = self._success(identity, tensor, candidate, output_shape, successor, execution)
        except MemoryError:
            response = self._failure(identity, "operator_failure", "numerical allocation failed")
        except ContractFailure as error:
            response = self._failure(identity, error.status, error.detail)
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            response = self._failure(identity, "malformed_request", str(error))
        except Exception as error:
            response = self._failure(identity, "operator_failure", f"numerical operator failed: {type(error).__name__}")

        if request_id:
            self._completed[request_id] = (request_payload_digest, response)
            self._completed.move_to_end(request_id)
            while len(self._completed) > self._limits.max_completed_replies:
                self._completed.popitem(last=False)
        return response

    def _validate(self, request: dict) -> tuple[bytes, int, int, dict]:
        if self._integer(request.get("protocol_version"), "protocol version", 16) != PROTOCOL_VERSION:
            raise ContractFailure("unsupported_version", "unsupported protocol version")
        identity = request["identity"]
        run = request["model_run"]
        manifest = request["input_manifest"]
        checkpoint = request["checkpoint"]
        for value, field in ((identity["run_id"], "run_id"), (identity["request_id"], "request_id")):
            _text(value, field)
        for owner, field in (
            (run, "model run_id"),
            (manifest, "manifest run_id"),
            (checkpoint, "checkpoint run_id"),
        ):
            _text(owner["run_id"], field)
        if self._integer(run["schema_version"], "model schema version", 16) != 1 or self._integer(
            manifest["schema_version"], "manifest schema version", 16
        ) != 1:
            raise ContractFailure("unsupported_version", "unsupported artifact schema")
        deadline = self._integer(request["deadline_monotonic_ns"], "deadline", 64)
        identity_epoch = self._integer(identity["epoch"], "identity epoch", 64)
        identity_cutoff = self._integer(identity["cutoff_ns"], "identity cutoff", 64)
        manifest_epoch = self._integer(manifest["epoch"], "manifest epoch", 64)
        manifest_cutoff = self._integer(manifest["cutoff_ns"], "manifest cutoff", 64)
        checkpoint_epoch = self._integer(checkpoint["epoch"], "checkpoint epoch", 64)
        if self._now_ns() > deadline:
            raise ContractFailure("deadline_exceeded", "request deadline elapsed")
        if not all(owner["run_id"] == identity["run_id"] for owner in (run, manifest, checkpoint)):
            raise ContractFailure("contract_mismatch", "run identity differs across request")
        if manifest_epoch != identity_epoch or checkpoint_epoch != identity_epoch:
            raise ContractFailure("epoch_mismatch", "epoch differs across request")
        if manifest_cutoff != identity_cutoff:
            raise ContractFailure("contract_mismatch", "causal cutoff differs across request")
        if manifest["predecessor_digest"] != identity["predecessor_digest"]:
            raise ContractFailure("contract_mismatch", "manifest predecessor differs")

        manifest_bytes = _hex_bytes(manifest["manifest_hex"], self._limits.max_manifest_bytes, "manifest")
        _check_digest(manifest["manifest_digest"], manifest_bytes, "manifest digest")
        weights = _hex_bytes(run["weights_hex"], self._limits.max_weights_bytes, "weights")
        _check_digest(run["weights_digest"], weights, "weights digest")
        checkpoint_bytes = _hex_bytes(checkpoint["bytes_hex"], self._limits.max_checkpoint_bytes, "checkpoint")
        _check_digest(checkpoint["digest"], checkpoint_bytes, "checkpoint digest")
        if checkpoint["digest"] != identity["predecessor_digest"]:
            raise ContractFailure("digest_mismatch", "checkpoint is not the declared predecessor")
        tensor = _hex_bytes(manifest["tensor_hex"], self._limits.max_tensor_bytes, "tensor")
        _check_digest(manifest["tensor_digest"], tensor, "tensor digest")

        contract_fields = ("preprocessing", "input_semantics")
        if any(_text(run[field], f"model {field}") != _text(manifest[field], f"manifest {field}") for field in contract_fields):
            raise ContractFailure("contract_mismatch", "manifest and model semantics differ")
        for field in ("algorithm", "normalization", "output_semantics", "label_semantics", "calibration_policy", "tolerance_policy", "fusion_policy", "state_format"):
            _text(run[field], field)

        shape = manifest["shape"]
        max_shape = run["max_shape"]
        if not isinstance(shape, list) or not shape or len(shape) > self._limits.max_shape_dimensions:
            raise ContractFailure("invalid_shape", "tensor rank is outside configured bounds")
        if not isinstance(max_shape, list) or len(shape) != len(max_shape):
            raise ContractFailure("invalid_shape", "model shape rank differs")
        elements = self._shape_elements(shape, max_shape)
        output_elements = self._shape_elements(run["output_shape"], None)
        if elements * 4 != len(tensor):
            raise ContractFailure("invalid_shape", "tensor byte count does not match float32 shape")
        counts = (manifest["source_count"], manifest["clock_domain_count"])
        if any(isinstance(count, bool) or not isinstance(count, int) or count < 0 for count in counts):
            raise ContractFailure("malformed_request", "manifest reference counts must be non-negative integers")
        if manifest["source_count"] > self._limits.max_sources or manifest["clock_domain_count"] > self._limits.max_clock_domains:
            raise ContractFailure("limit_exceeded", "manifest reference count exceeds limit")
        if any(not math.isfinite(value) for value in struct.unpack(f"<{elements}f", tensor)):
            raise ContractFailure("non_finite", "input contains NaN or Inf")

        execution = run["execution"]
        if execution["class"] not in ("production_gpu", "cpu_baseline"):
            raise ContractFailure("contract_mismatch", "execution class is invalid")
        if not isinstance(execution["deterministic_algorithms"], bool):
            raise ContractFailure("contract_mismatch", "determinism setting is invalid")
        for name in ("absolute_tolerance", "relative_tolerance"):
            tolerance = execution[name]
            if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)):
                raise ContractFailure("malformed_request", "numeric tolerance has a weak scalar type")
            if not math.isfinite(tolerance) or tolerance < 0:
                raise ContractFailure("contract_mismatch", "numeric tolerance is invalid")
        _text(execution["environment"], "numeric environment")
        numeric_qualification = {
            "class": execution["class"],
            "deterministic_algorithms": execution["deterministic_algorithms"],
            "absolute_tolerance": execution["absolute_tolerance"],
            "relative_tolerance": execution["relative_tolerance"],
            "environment": execution["environment"],
        }
        return tensor, deadline, output_elements, numeric_qualification

    def _shape_elements(self, shape: object, maximum_shape: object | None) -> int:
        if not isinstance(shape, list) or not shape or len(shape) > self._limits.max_shape_dimensions:
            raise ContractFailure("invalid_shape", "tensor rank is outside configured bounds")
        if maximum_shape is not None and (not isinstance(maximum_shape, list) or len(shape) != len(maximum_shape)):
            raise ContractFailure("invalid_shape", "model shape rank differs")
        elements = 1
        maxima = maximum_shape if maximum_shape is not None else [self._limits.max_dimension] * len(shape)
        for actual, maximum in zip(shape, maxima):
            if isinstance(actual, bool) or isinstance(maximum, bool) or not isinstance(actual, int) or not isinstance(maximum, int):
                raise ContractFailure("malformed_request", "shape dimensions must be integers")
            if (
                actual <= 0
                or actual > maximum
                or actual > self._limits.max_dimension
            ):
                raise ContractFailure("invalid_shape", "tensor dimension is outside model bounds")
            elements *= actual
            if elements > self._limits.max_elements:
                raise ContractFailure("limit_exceeded", "tensor element count exceeds limit")
        return elements

    def _success(
        self,
        identity: dict,
        tensor: bytes,
        candidate: bytes,
        output_shape: tuple[int, ...],
        successor: bytes,
        execution: dict,
    ) -> bytes:
        payload = candidate + successor
        return encode_frame(
            {
                "protocol_version": PROTOCOL_VERSION,
                "identity": identity,
                "status": "success",
                "detail": "",
                "candidate_hex": candidate.hex(),
                "successor_hex": successor.hex(),
                "output_shape": list(output_shape),
                "input_tensor_digest": _digest(tensor),
                "output_numeric_digest": _digest(candidate),
                "return_payload_digest": _digest(payload),
                "numeric_qualification": execution,
            },
            self._limits,
        )

    def _failure(self, identity: dict, status: str, detail: str) -> bytes:
        safe_identity = self._safe_identity(identity)
        safe_status = status if status in FAILURE_STATUSES else "operator_failure"
        safe_detail = detail.encode("utf-8", errors="replace")[:256].decode("utf-8", errors="ignore")
        full = {
                "protocol_version": PROTOCOL_VERSION,
                "identity": safe_identity,
                "status": safe_status,
                "detail": safe_detail,
                "candidate_hex": "",
                "successor_hex": "",
                "output_shape": [],
                "input_tensor_digest": "",
                "output_numeric_digest": "",
                "return_payload_digest": "",
                "numeric_qualification": None,
        }
        candidates = (
            full,
            {**full, "identity": dict(FALLBACK_IDENTITY), "detail": ""},
        )
        for candidate in candidates:
            try:
                return encode_frame(candidate, self._limits)
            except ValueError:
                continue
        raise ValueError("configured frame limit cannot encode a minimal failure")

    @staticmethod
    def _integer(value: object, field: str, bits: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= 1 << bits:
            raise ContractFailure("malformed_request", f"{field} must be an unsigned {bits}-bit integer")
        return value

    @classmethod
    def _safe_identity(cls, value: object) -> dict:
        if not isinstance(value, dict):
            return dict(FALLBACK_IDENTITY)
        try:
            run_id = _text(value["run_id"], "run_id")
            request_id = _text(value["request_id"], "request_id")
            epoch = cls._integer(value["epoch"], "epoch", 64)
            cutoff = cls._integer(value["cutoff_ns"], "cutoff", 64)
            predecessor = value["predecessor_digest"]
            if (
                not isinstance(predecessor, str)
                or len(predecessor) != HEX_DIGEST_CHARS
                or any(character not in "0123456789abcdef" for character in predecessor)
            ):
                return dict(FALLBACK_IDENTITY)
            bytes.fromhex(predecessor)
            return {
                "run_id": run_id,
                "epoch": epoch,
                "request_id": request_id,
                "cutoff_ns": cutoff,
                "predecessor_digest": predecessor,
            }
        except (ContractFailure, KeyError, TypeError, ValueError):
            return dict(FALLBACK_IDENTITY)


def serve_connection(connection: socket.socket, worker: Worker) -> None:
    """Serve one connection and return an explicit frame for malformed input."""

    try:
        frame = read_frame(connection, worker._limits)
        response = worker.handle_frame(frame)
    except (EOFError, OSError, ValueError, UnicodeError, RecursionError) as error:
        response = worker._failure({}, "malformed_request", str(error))
    connection.sendall(response)


def serve_unix(socket_path: str, worker: Worker, *, request_timeout_seconds: float = 1.0) -> None:
    """Serve local WMW1 requests serially on a Unix-domain socket."""

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(socket_path)
        listener.listen(1)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(request_timeout_seconds)
                try:
                    serve_connection(connection, worker)
                except OSError:
                    continue
