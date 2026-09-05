import hashlib
import json
import math
import socket
import struct
import sys
import types
import unittest
from unittest.mock import patch

from model_worker.worker import (
    ContractFailure,
    DeterministicTestOperator,
    FALLBACK_IDENTITY,
    FAILURE_STATUSES,
    Limits,
    MIN_FRAME_BYTES,
    TorchOperator,
    Worker,
    decode_frame,
    encode_frame,
    serve_connection,
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request(*, tensor: bytes | None = None, request_id: str = "request-1") -> dict:
    tensor = tensor if tensor is not None else struct.pack("<ff", 1.5, -2.0)
    manifest_bytes = b"frozen-input-manifest-v1"
    weights = b"deterministic-test-weights"
    checkpoint = b"checkpoint-v1"
    identity = {
        "run_id": "run-1",
        "epoch": 7,
        "request_id": request_id,
        "cutoff_ns": 250_000_000,
        "predecessor_digest": digest(checkpoint),
    }
    return {
        "protocol_version": 1,
        "identity": identity,
        "deadline_monotonic_ns": 9_000_000_000,
        "model_run": {
            "schema_version": 1,
            "run_id": "run-1",
            "weights_digest": digest(weights),
            "weights_hex": weights.hex(),
            "algorithm": "deterministic-double-v1",
            "preprocessing": "f32-le-v1",
            "normalization": "identity-v1",
            "input_semantics": "qualified-rf-test-values-v1",
            "output_semantics": "candidate-potentials-f32-le-v1",
            "label_semantics": "joint-state-test-v1",
            "calibration_policy": "frozen-references-v1",
            "tolerance_policy": "bitwise-test-only-v1",
            "fusion_policy": "test-identity-v1",
            "state_format": "test-state-v1",
            "max_shape": [8],
            "output_shape": [2],
            "execution": {
                "class": "cpu_baseline",
                "deterministic_algorithms": True,
                "absolute_tolerance": 0.0,
                "relative_tolerance": 0.0,
                "environment": "python-struct-f32",
            },
        },
        "input_manifest": {
            "schema_version": 1,
            "manifest_digest": digest(manifest_bytes),
            "manifest_hex": manifest_bytes.hex(),
            "run_id": "run-1",
            "epoch": 7,
            "cutoff_ns": 250_000_000,
            "predecessor_digest": digest(checkpoint),
            "preprocessing": "f32-le-v1",
            "input_semantics": "qualified-rf-test-values-v1",
            "shape": [2],
            "tensor_digest": digest(tensor),
            "tensor_hex": tensor.hex(),
            "source_count": 2,
            "clock_domain_count": 2,
        },
        "checkpoint": {
            "run_id": "run-1",
            "epoch": 7,
            "digest": digest(checkpoint),
            "bytes_hex": checkpoint.hex(),
        },
    }


class WorkerProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = Worker(DeterministicTestOperator(), Limits(), now_ns=lambda: 1)

    def run_request(self, value: dict) -> tuple[bytes, dict]:
        response_bytes = self.worker.handle_frame(encode_frame(value, Limits()))
        return response_bytes, decode_frame(response_bytes, Limits())

    def test_deterministic_operator_returns_bound_candidate_and_successor(self) -> None:
        response_bytes, response = self.run_request(request())
        self.assertEqual(response["status"], "success")
        self.assertEqual(struct.unpack("<ff", bytes.fromhex(response["candidate_hex"])), (3.0, -4.0))
        self.assertEqual(response["output_shape"], [2])
        self.assertEqual(response["input_tensor_digest"], digest(struct.pack("<ff", 1.5, -2.0)))
        self.assertEqual(response["output_numeric_digest"], digest(struct.pack("<ff", 3.0, -4.0)))
        payload = bytes.fromhex(response["candidate_hex"]) + bytes.fromhex(response["successor_hex"])
        self.assertEqual(response["return_payload_digest"], digest(payload))
        self.assertLessEqual(len(response_bytes), Limits().max_frame_bytes)

    def test_same_payload_retry_is_byte_identical_and_conflict_is_rejected(self) -> None:
        frame = encode_frame(request(), Limits())
        first = self.worker.handle_frame(frame)
        self.assertEqual(self.worker.handle_frame(frame), first)
        conflicting = request(tensor=struct.pack("<ff", 2.0, -2.0))
        conflicting["input_manifest"]["tensor_digest"] = digest(bytes.fromhex(conflicting["input_manifest"]["tensor_hex"]))
        response = decode_frame(self.worker.handle_frame(encode_frame(conflicting, Limits())), Limits())
        self.assertEqual(response["status"], "request_conflict")

    def test_restart_rematerializes_from_request_without_hidden_context(self) -> None:
        frame = encode_frame(request(), Limits())
        first = self.worker.handle_frame(frame)
        restarted = Worker(DeterministicTestOperator(), Limits(), now_ns=lambda: 1)
        self.assertEqual(restarted.handle_frame(frame), first)

    def test_invalid_contracts_return_bounded_failures(self) -> None:
        mutations = []
        bad_version = request(); bad_version["protocol_version"] = 2
        mutations.append((bad_version, "unsupported_version"))
        bad_model = request(); bad_model["model_run"]["input_semantics"] = "other"
        mutations.append((bad_model, "contract_mismatch"))
        bad_epoch = request(); bad_epoch["checkpoint"]["epoch"] = 8
        mutations.append((bad_epoch, "epoch_mismatch"))
        bad_predecessor = request(); bad_predecessor["checkpoint"]["digest"] = "00" * 32
        mutations.append((bad_predecessor, "digest_mismatch"))
        bad_shape = request(); bad_shape["input_manifest"]["shape"] = [3]
        mutations.append((bad_shape, "invalid_shape"))
        expired = request(); expired["deadline_monotonic_ns"] = 0
        mutations.append((expired, "deadline_exceeded"))
        nan_tensor = struct.pack("<f", math.nan)
        nonfinite = request(tensor=nan_tensor); nonfinite["input_manifest"]["shape"] = [1]
        mutations.append((nonfinite, "non_finite"))
        for index, (value, expected) in enumerate(mutations):
            with self.subTest(expected=expected):
                value["identity"]["request_id"] = f"invalid-{index}"
                _, response = self.run_request(value)
                self.assertEqual(response["status"], expected)
                self.assertEqual(response["candidate_hex"], "")
                self.assertEqual(response["successor_hex"], "")

    def test_oversized_tensor_is_rejected_before_operator(self) -> None:
        limits = Limits(max_tensor_bytes=4)
        worker = Worker(DeterministicTestOperator(), limits, now_ns=lambda: 1)
        response = decode_frame(worker.handle_frame(encode_frame(request(), limits)), limits)
        self.assertEqual(response["status"], "limit_exceeded")

    def test_operator_failures_are_explicit_and_do_not_create_a_fact_log(self) -> None:
        class FailingOperator:
            def evaluate(self, _request):
                raise ContractFailure("gpu_oom", "simulated GPU OOM")

        worker = Worker(FailingOperator(), Limits(), now_ns=lambda: 1)
        response = decode_frame(worker.handle_frame(encode_frame(request(), Limits())), Limits())
        self.assertEqual(response["status"], "gpu_oom")
        self.assertFalse(hasattr(worker, "store"))
        self.assertFalse(hasattr(worker, "fact_log"))

    def test_operator_contract_failure_cannot_emit_success_or_unknown_status(self) -> None:
        for supplied_status in ("success", "invented_failure"):
            with self.subTest(status=supplied_status):
                class FailingOperator:
                    def evaluate(self, _request):
                        raise ContractFailure(supplied_status, "invalid operator status")

                worker = Worker(FailingOperator(), Limits(), now_ns=lambda: 1)
                response = decode_frame(worker.handle_frame(encode_frame(request(), Limits())), Limits())
                self.assertEqual(response["status"], "operator_failure")
                self.assertEqual(response["candidate_hex"], "")
                self.assertIsNone(response["numeric_qualification"])

    def test_wrong_result_shape_is_a_bounded_failure(self) -> None:
        class WrongShapeOperator:
            def evaluate(self, _request):
                return struct.pack("<f", 1.0), (1,), b"successor"

        worker = Worker(WrongShapeOperator(), Limits(), now_ns=lambda: 1)
        response = decode_frame(worker.handle_frame(encode_frame(request(), Limits())), Limits())
        self.assertEqual(response["status"], "invalid_shape")

    def test_same_element_wrong_output_shape_is_rejected(self) -> None:
        class WrongShapeOperator:
            def evaluate(self, _request):
                return struct.pack("<ff", 1.0, 2.0), (1, 2), b"successor"

        worker = Worker(WrongShapeOperator(), Limits(), now_ns=lambda: 1)
        response = decode_frame(worker.handle_frame(encode_frame(request(), Limits())), Limits())
        self.assertEqual(response["status"], "invalid_shape")
        self.assertEqual(response["output_shape"], [])

    def test_negative_reference_counts_and_unexpected_operator_faults_are_bounded(self) -> None:
        negative = request(request_id="negative-count")
        negative["input_manifest"]["source_count"] = -1
        response = decode_frame(self.worker.handle_frame(encode_frame(negative, Limits())), Limits())
        self.assertEqual(response["status"], "malformed_request")

        class CrashingOperator:
            def evaluate(self, _request):
                raise RuntimeError("simulated kernel crash")

        worker = Worker(CrashingOperator(), Limits(), now_ns=lambda: 1)
        response = decode_frame(worker.handle_frame(encode_frame(request(), Limits())), Limits())
        self.assertEqual(response["status"], "operator_failure")

    def test_frame_length_is_checked_before_json_decode(self) -> None:
        with self.assertRaises(ValueError):
            decode_frame(b"WMW1" + struct.pack(">I", Limits().max_frame_bytes + 1), Limits())

    def test_torch_backend_unavailable_is_explicit_without_cpu_fallback(self) -> None:
        worker = Worker(TorchOperator(lambda _tensor, _request: None), Limits(), now_ns=lambda: 1)
        value = request(request_id="gpu-request")
        value["model_run"]["execution"]["class"] = "production_gpu"
        response = decode_frame(worker.handle_frame(encode_frame(value, Limits())), Limits())
        self.assertEqual(response["status"], "backend_unavailable")

    def test_deadline_is_rechecked_after_numerical_execution(self) -> None:
        ticks = iter((1, 10_000_000_000))
        worker = Worker(DeterministicTestOperator(), Limits(), now_ns=lambda: next(ticks))
        response = decode_frame(worker.handle_frame(encode_frame(request(), Limits())), Limits())
        self.assertEqual(response["status"], "deadline_exceeded")
        self.assertEqual(response["candidate_hex"], "")

    def test_operator_cannot_mutate_validated_response_contracts_or_deadline(self) -> None:
        test_case = self

        class MutatingOperator:
            @staticmethod
            def replace(mapping, key, replacement):
                mapping[key] = replacement

            def evaluate(self, value):
                mutations = (
                    lambda: self.replace(value, "deadline_monotonic_ns", 20_000_000_000),
                    lambda: self.replace(value["model_run"], "output_shape", [1]),
                    lambda: self.replace(
                        value["model_run"]["execution"], "environment", "operator-controlled"
                    ),
                )
                for mutate in mutations:
                    with test_case.assertRaises(TypeError):
                        mutate()
                return struct.pack("<ff", 3.0, -4.0), (2,), b"successor"

        ticks = iter((1, 10_000_000_000))
        worker = Worker(MutatingOperator(), Limits(), now_ns=lambda: next(ticks))
        response = decode_frame(worker.handle_frame(encode_frame(request(), Limits())), Limits())
        self.assertEqual(response["status"], "deadline_exceeded")
        self.assertEqual(response["candidate_hex"], "")
        self.assertIsNone(response["numeric_qualification"])

    def test_weak_json_scalar_types_are_rejected(self) -> None:
        mutations = (
            ("protocol_version", lambda value: value.__setitem__("protocol_version", True)),
            ("epoch", lambda value: value["identity"].__setitem__("epoch", 7.5)),
            ("cutoff", lambda value: value["identity"].__setitem__("cutoff_ns", True)),
            ("dimension", lambda value: value["input_manifest"].__setitem__("shape", [True])),
            (
                "tolerance",
                lambda value: value["model_run"]["execution"].__setitem__("absolute_tolerance", True),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                value = request(request_id=f"weak-{name}")
                mutate(value)
                worker = Worker(DeterministicTestOperator(), Limits(), now_ns=lambda: 1)
                response = decode_frame(worker.handle_frame(encode_frame(value, Limits())), Limits())
                self.assertEqual(response["status"], "malformed_request")

    def test_uppercase_binary_and_digest_hex_are_rejected_as_bounded_failures(self) -> None:
        mutations = (
            ("weights bytes", "malformed_request", lambda value: value["model_run"].__setitem__("weights_hex", value["model_run"]["weights_hex"].upper())),
            ("manifest bytes", "malformed_request", lambda value: value["input_manifest"].__setitem__("manifest_hex", value["input_manifest"]["manifest_hex"].upper())),
            ("tensor bytes", "malformed_request", lambda value: value["input_manifest"].__setitem__("tensor_hex", "0A00000000000000")),
            ("checkpoint bytes", "malformed_request", lambda value: value["checkpoint"].__setitem__("bytes_hex", value["checkpoint"]["bytes_hex"].upper())),
            ("weights digest", "digest_mismatch", lambda value: value["model_run"].__setitem__("weights_digest", value["model_run"]["weights_digest"].upper())),
            ("manifest digest", "digest_mismatch", lambda value: value["input_manifest"].__setitem__("manifest_digest", value["input_manifest"]["manifest_digest"].upper())),
            ("tensor digest", "digest_mismatch", lambda value: value["input_manifest"].__setitem__("tensor_digest", value["input_manifest"]["tensor_digest"].upper())),
            ("checkpoint digest", "digest_mismatch", lambda value: value["checkpoint"].__setitem__("digest", value["checkpoint"]["digest"].upper())),
        )
        for index, (name, expected, mutate) in enumerate(mutations):
            with self.subTest(name=name):
                value = request(request_id=f"uppercase-{index}")
                mutate(value)
                response = decode_frame(self.worker.handle_frame(encode_frame(value, Limits())), Limits())
                self.assertEqual(response["status"], expected)
                self.assertEqual(response["candidate_hex"], "")

    def test_malformed_identity_and_unicode_detail_always_fit_failure_frame(self) -> None:
        limits = Limits(max_frame_bytes=1024)
        malformed = {
            "protocol_version": 1,
            "identity": {"request_id": "界" * 100},
            "unexpected": "x" * 40,
        }
        frame = encode_frame(malformed, limits)
        response_frame = Worker(DeterministicTestOperator(), limits).handle_frame(frame)
        self.assertLessEqual(len(response_frame), limits.max_frame_bytes)
        response = decode_frame(response_frame, limits)
        self.assertEqual(response["identity"], dict(FALLBACK_IDENTITY))
        self.assertLessEqual(len(response["detail"].encode("utf-8")), 256)

    def test_minimum_frame_limit_always_returns_complete_schema_valid_failure(self) -> None:
        limits = Limits(max_frame_bytes=MIN_FRAME_BYTES)
        oversized_request = encode_frame(request(), Limits())
        response_frame = Worker(DeterministicTestOperator(), limits).handle_frame(oversized_request)
        self.assertLessEqual(len(response_frame), MIN_FRAME_BYTES)
        response = decode_frame(response_frame, limits)
        self.assertEqual(response["status"], "malformed_request")
        self.assertEqual(response["identity"], dict(FALLBACK_IDENTITY))
        self.assertEqual(response["candidate_hex"], "")
        self.assertEqual(response["successor_hex"], "")
        self.assertEqual(response["output_shape"], [])
        self.assertEqual(response["input_tensor_digest"], "")
        self.assertEqual(response["output_numeric_digest"], "")
        self.assertEqual(response["return_payload_digest"], "")
        self.assertIsNone(response["numeric_qualification"])

        worker = Worker(DeterministicTestOperator(), limits)
        for status in FAILURE_STATUSES:
            with self.subTest(status=status):
                response_frame = worker._failure({}, status, "界" * 200)
                response = decode_frame(response_frame, limits)
                self.assertEqual(response["status"], status)
                self.assertEqual(response["identity"], dict(FALLBACK_IDENTITY))
                self.assertLessEqual(len(response_frame), MIN_FRAME_BYTES)

    def test_frame_limit_below_protocol_minimum_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, str(MIN_FRAME_BYTES)):
            Limits(max_frame_bytes=MIN_FRAME_BYTES - 1)

    def test_connection_returns_failure_frame_for_invalid_input(self) -> None:
        worker_side, client_side = socket.socketpair()
        try:
            worker_side.settimeout(1)
            client_side.settimeout(1)
            client_side.sendall(b"BAD!" + struct.pack(">I", 0))
            serve_connection(worker_side, Worker(DeterministicTestOperator(), Limits()))
            response = decode_frame(client_side.recv(Limits().max_frame_bytes), Limits())
            self.assertEqual(response["status"], "malformed_request")
        finally:
            worker_side.close()
            client_side.close()

    def test_cuda_oom_during_tensor_materialization_is_mapped(self) -> None:
        class FakeOutOfMemoryError(Exception):
            pass

        fake_torch = types.SimpleNamespace(
            cuda=types.SimpleNamespace(is_available=lambda: True, OutOfMemoryError=FakeOutOfMemoryError),
            device=lambda name: name,
            use_deterministic_algorithms=lambda _enabled: None,
            frombuffer=lambda *_args, **_kwargs: (_ for _ in ()).throw(FakeOutOfMemoryError()),
            float32=object(),
        )
        value = request(request_id="materialize-oom")
        value["model_run"]["execution"]["class"] = "production_gpu"
        with patch.dict(sys.modules, {"torch": fake_torch}):
            worker = Worker(TorchOperator(lambda _tensor, _request: None), Limits(), now_ns=lambda: 1)
            response = decode_frame(worker.handle_frame(encode_frame(value, Limits())), Limits())
        self.assertEqual(response["status"], "gpu_oom")


if __name__ == "__main__":
    unittest.main()
