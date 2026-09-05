import hashlib
import json
import math
import struct
import unittest

from model_worker.worker import (
    ContractFailure,
    DeterministicTestOperator,
    Limits,
    TorchOperator,
    Worker,
    decode_frame,
    encode_frame,
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

    def test_wrong_result_shape_is_a_bounded_failure(self) -> None:
        class WrongShapeOperator:
            def evaluate(self, _request):
                return struct.pack("<f", 1.0), b"successor"

        worker = Worker(WrongShapeOperator(), Limits(), now_ns=lambda: 1)
        response = decode_frame(worker.handle_frame(encode_frame(request(), Limits())), Limits())
        self.assertEqual(response["status"], "invalid_shape")

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


if __name__ == "__main__":
    unittest.main()
