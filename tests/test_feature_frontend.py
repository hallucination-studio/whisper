import hashlib
import json
import math
import struct
import unittest
from dataclasses import replace

from model_worker.feature_frontend import (
    CausalTCN,
    CrossSourceAttention,
    FeatureBlock,
    FeatureFrontend,
    FeatureFrontendError,
    FeatureFrontendOperator,
    FeatureLimits,
    FeatureManifest,
    FeatureQuality,
    MapCell,
    MapGrid,
    PathClass,
    QualifiedPath,
    ScatteringBiasNoiseHead,
    ScatteringExample,
    SlowMLP,
    SourceEmbedding,
    SourceProvenance,
)
from model_worker.worker import ContractFailure


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


EXPECTED_FIXTURE_TENSOR_DIGEST = "ac0e6b2fedb0e1005ff2f9b11e74dd6a3d2f7ac99182f5e32b63caf9595007bf"


def provenance(source_id: str, boot_id: str) -> SourceProvenance:
    return SourceProvenance(
        source_id=source_id,
        boot_id=boot_id,
        profile="array-profile-v1",
        radio="radio-v1",
        channel=36,
        clock_domain=f"clock-{source_id}",
        raw_record_digest=digest(f"raw-{source_id}-{boot_id}".encode()),
    )


def block(
    source: SourceProvenance,
    block_id: str,
    timestamp_ns: int,
    value: float,
    *,
    fast_value: float | None = None,
) -> FeatureBlock:
    fast_value = value if fast_value is None else fast_value
    return FeatureBlock(
        block_id=block_id,
        source=source,
        timestamp_ns=timestamp_ns,
        absolute_response=(value, value + 0.5),
        spectrum_shape=(value * 0.1, value * 0.2, value * 0.3),
        background_residual=(value * 0.01, -value * 0.02),
        fast_values=(fast_value, fast_value * 0.5),
        absolute_mask=(True, True),
        spectrum_mask=(True, True, True),
        residual_mask=(True, True),
        fast_mask=(True, True),
        preprocessing_version="rf-feature-pre-v1",
    )


def path(source: SourceProvenance, path_id: str, path_class: PathClass) -> QualifiedPath:
    return QualifiedPath(
        path_id=path_id,
        source=source,
        observed_at_ns=1_100_000_000,
        angle_radians=0.2,
        delay_seconds=2.0e-9,
        path_class=path_class,
        uncertainty=0.03,
        coverage=0.95,
        normalized_power=0.7,
        calibration_epoch=4,
        calibration_digest="cd" * 32,
        phase_calibration_digest="ef" * 32,
    )


def manifest(*, cutoff_ns: int = 1_500_000_000, blocks=None, paths=None) -> FeatureManifest:
    source_a = provenance("array-a", "boot-a")
    source_b = provenance("array-b", "boot-b")
    blocks = blocks if blocks is not None else (
        block(source_a, "a-1", 100_000_000, 5.0),
        block(source_a, "a-2", 600_000_000, 5.0, fast_value=1.0),
        block(source_a, "a-3", 1_100_000_000, 5.0, fast_value=2.0),
        block(source_b, "b-1", 900_000_000, 8.0, fast_value=-1.0),
    )
    paths = paths if paths is not None else tuple(
        path(source_a, f"p-{index}", path_class)
        for index, path_class in enumerate(PathClass)
    )
    return FeatureManifest(
        run_id="run-frontend-fixture",
        epoch=4,
        cutoff_ns=cutoff_ns,
        preprocessing_version="rf-feature-pre-v1",
        weights_digest=FeatureFrontend().weights_digest(),
        blocks=tuple(blocks),
        paths=tuple(paths),
        map_grid=MapGrid(
            cells=(
                MapCell("cell-0", (0.0, 0.0, 0.0)),
                MapCell("cell-1", (2.0, 1.0, 0.0)),
            )
        ),
        qualification_epoch=4,
        causal_context_ns=2_000_000_000,
    )


def operator_request(value: FeatureManifest, frontend: FeatureFrontend | None = None) -> dict:
    frontend = frontend or FeatureFrontend()
    materialized = frontend.materialize(value)
    weights = frontend.weights_canonical_bytes()
    return {
        "identity": {
            "run_id": value.run_id,
            "epoch": value.epoch,
            "cutoff_ns": value.cutoff_ns,
        },
        "model_run": {
            "run_id": value.run_id,
            "preprocessing": value.preprocessing_version,
            "weights_digest": frontend.weights_digest(),
            "weights_hex": weights.hex(),
            "output_shape": list(materialized.feature_shape),
        },
        "input_manifest": {
            "run_id": value.run_id,
            "epoch": value.epoch,
            "cutoff_ns": value.cutoff_ns,
            "preprocessing": value.preprocessing_version,
            "manifest_digest": value.digest(),
            "manifest_hex": value.canonical_bytes().hex(),
            "tensor_digest": materialized.tensor_digest,
            "tensor_hex": materialized.tensor_bytes.hex(),
            "shape": list(materialized.feature_shape),
            "source_count": len(value.source_provenance),
            "clock_domain_count": len({item.clock_domain for item in value.source_provenance}),
        },
    }


class FeatureFrontendTests(unittest.TestCase):
    def test_manifest_and_materialization_are_immutable_and_deterministic(self) -> None:
        value = manifest()
        frontend = FeatureFrontend()

        first = frontend.materialize(value)
        second = frontend.materialize(value)

        self.assertIsInstance(value.blocks, tuple)
        self.assertEqual(value.canonical_bytes(), value.canonical_bytes())
        self.assertEqual(value.digest(), digest(value.canonical_bytes()))
        self.assertEqual(first.manifest_digest, value.digest())
        self.assertEqual(first.tensor_bytes, second.tensor_bytes)
        self.assertEqual(first.tensor_digest, second.tensor_digest)
        self.assertEqual(first.tensor_digest, EXPECTED_FIXTURE_TENSOR_DIGEST)
        self.assertEqual(first, second)
        payload = json.loads(value.canonical_bytes())
        self.assertEqual(payload["schema"], "rf-feature-manifest-v1")
        self.assertEqual(payload["preprocessing_version"], "rf-feature-pre-v1")
        self.assertEqual(payload["blocks"][0]["masks"]["absolute"], [True, True])
        self.assertEqual(payload["blocks"][0]["source"]["boot_id"], "boot-a")

    def test_slow_branch_keeps_absolute_stationary_information_and_residual(self) -> None:
        value = manifest()
        result = FeatureFrontend().materialize(value)

        slow_a = next(item for item in result.slow_outputs if item.source_key == "array-a/boot-a")
        self.assertEqual(slow_a.absolute_response, (5.0, 5.5))
        self.assertEqual(slow_a.background_residual, (0.05, -0.1))
        self.assertNotEqual(slow_a.absolute_level, 0.0)
        self.assertEqual(slow_a.absolute_mask, (True, True))
        self.assertEqual(slow_a.preprocessing_version, "rf-feature-pre-v1")

    def test_causal_tcn_uses_real_intervals_and_rejects_future_blocks(self) -> None:
        value = manifest()
        result = FeatureFrontend().materialize(value)
        tcn_a = next(item for item in result.tcn_outputs if item.source_key == "array-a/boot-a")
        self.assertEqual(tcn_a.timestamps_ns, (100_000_000, 600_000_000, 1_100_000_000))
        self.assertEqual(tcn_a.time_deltas_ns, (0, 500_000_000, 500_000_000))
        self.assertEqual(tcn_a.cutoff_ns, value.cutoff_ns)

        future = block(provenance("array-a", "boot-a"), "a-future", 1_500_000_001, 99.0)
        with self.assertRaisesRegex(FeatureFrontendError, "future"):
            FeatureFrontend().materialize(
                manifest(blocks=(*value.blocks, future), cutoff_ns=value.cutoff_ns)
            )

        changed_interval = block(provenance("array-a", "boot-a"), "a-2", 700_000_000, 5.0, fast_value=1.0)
        changed = manifest(blocks=(value.blocks[0], changed_interval, value.blocks[2], value.blocks[3]))
        changed_output = FeatureFrontend().materialize(changed)
        changed_tcn = next(item for item in changed_output.tcn_outputs if item.source_key == "array-a/boot-a")
        self.assertEqual(changed_tcn.time_deltas_ns, (0, 600_000_000, 400_000_000))
        self.assertNotEqual(tcn_a.embedding, changed_tcn.embedding)

    def test_path_branch_requires_qualified_array_and_retains_every_path_class(self) -> None:
        result = FeatureFrontend().materialize(manifest())
        self.assertEqual(
            {item.path_class for item in result.path_output.paths},
            set(PathClass),
        )
        self.assertTrue(all(item.adapter_kind == "qualified_array" for item in result.path_output.paths))
        self.assertTrue(all(item.operator == "angle_delay" for item in result.path_output.paths))
        self.assertTrue(all(item.coverage == 0.95 for item in result.path_output.paths))

        with self.assertRaisesRegex(FeatureFrontendError, "expired"):
            FeatureFrontend().materialize(
                manifest(paths=(replace(path(provenance("array-a", "boot-a"), "expired", PathClass.STABLE_STATIC), qualification_valid_until_ns=1_200_000_000),))
            )
        with self.assertRaisesRegex(FeatureFrontendError, "coherent"):
            replace(path(provenance("array-a", "boot-a"), "incoherent", PathClass.UNEXPLAINED), phase_coherent=False)

        unqualified = path(provenance("array-a", "boot-a"), "ordinary", PathClass.DYNAMIC_CANDIDATE)
        with self.assertRaisesRegex(FeatureFrontendError, "qualified"):
            replace(unqualified, qualified=False, adapter_kind="ordinary_esp")

    def test_manifest_rejects_duplicate_nonfinite_and_oversized_inputs(self) -> None:
        value = manifest()
        duplicate = block(value.blocks[0].source, value.blocks[0].block_id, 1_200_000_000, 1.0)
        with self.assertRaisesRegex(FeatureFrontendError, "duplicate"):
            FeatureFrontend().materialize(manifest(blocks=(*value.blocks, duplicate)))

        with self.assertRaisesRegex(FeatureFrontendError, "finite"):
            nonfinite = block(value.blocks[0].source, "nonfinite", 1_200_000_000, math.inf)
            FeatureFrontend().materialize(manifest(blocks=(*value.blocks, nonfinite)))

        with self.assertRaisesRegex(FeatureFrontendError, "block"):
            FeatureFrontend(FeatureLimits(max_blocks=2)).materialize(value)
        with self.assertRaisesRegex(FeatureFrontendError, "tensor"):
            FeatureFrontend(FeatureLimits(max_tensor_bytes=8)).materialize(value)

    def test_manifest_weights_bind_every_configured_component_before_materialization(self) -> None:
        value = manifest()
        baseline = FeatureFrontend()
        baseline_result = baseline.materialize(value)

        changed_slow = FeatureFrontend(slow_mlp=SlowMLP(hidden_width=9))
        with self.assertRaisesRegex(FeatureFrontendError, "weights digest"):
            changed_slow.materialize(value)
        changed_slow_manifest = replace(value, weights_digest=changed_slow.weights_digest())
        changed_slow_result = changed_slow.materialize(changed_slow_manifest)
        self.assertNotEqual(changed_slow_manifest.digest(), value.digest())
        self.assertNotEqual(changed_slow_result.feature_shape, baseline_result.feature_shape)
        self.assertNotEqual(changed_slow_result.tensor_bytes, baseline_result.tensor_bytes)

        default_head = ScatteringBiasNoiseHead.default(5)
        changed_bias = tuple(
            tuple(0.125 if row == 0 and column == 0 else weight for column, weight in enumerate(weights))
            for row, weights in enumerate(default_head.bias_weights)
        )
        changed_head = ScatteringBiasNoiseHead(
            bias_weights=changed_bias,
            noise_weights=default_head.noise_weights,
        )
        changed_frontend = FeatureFrontend(scattering_head=changed_head)
        with self.assertRaisesRegex(FeatureFrontendError, "weights digest"):
            changed_frontend.materialize(value)
        changed_manifest = replace(value, weights_digest=changed_frontend.weights_digest())
        changed_result = changed_frontend.materialize(changed_manifest)
        self.assertEqual(changed_result.feature_shape, baseline_result.feature_shape)
        self.assertNotEqual(changed_result.tensor_bytes, baseline_result.tensor_bytes)

        weights = json.loads(baseline.weights_canonical_bytes())
        self.assertEqual(weights["schema"], "rf-feature-weights-v1")
        self.assertEqual(
            [component["name"] for component in weights["components"]],
            [
                "slow_mlp",
                "causal_tcn",
                "qualified_path_encoder",
                "scattering_bias_noise_head",
                "cross_source_attention",
            ],
        )
        for component in weights["components"]:
            self.assertEqual(
                digest(bytes.fromhex(component["encoding_hex"])),
                component["encoding_digest"],
            )

    def test_weights_digest_changes_for_each_configured_numeric_parameter(self) -> None:
        baseline = FeatureFrontend()
        slow = baseline.slow_mlp
        tcn = baseline.causal_tcn
        attention = baseline.attention
        variants = (
            FeatureFrontend(slow_mlp=replace(slow, hidden_width=9)),
            FeatureFrontend(slow_mlp=replace(slow, hidden_bias=0.071)),
            FeatureFrontend(slow_mlp=replace(slow, sinusoid_frequency=0.371)),
            FeatureFrontend(slow_mlp=replace(slow, input_scale=0.081)),
            FeatureFrontend(causal_tcn=replace(tcn, context_ns=tcn.context_ns - 1)),
            FeatureFrontend(causal_tcn=replace(tcn, layers=3, delta_scales=(0.05, 0.03, 0.02))),
            FeatureFrontend(causal_tcn=replace(tcn, max_lag=4)),
            FeatureFrontend(causal_tcn=replace(tcn, current_scale=0.421)),
            FeatureFrontend(causal_tcn=replace(tcn, layer_scale_step=0.041)),
            FeatureFrontend(causal_tcn=replace(tcn, layer_bias=0.031)),
            FeatureFrontend(causal_tcn=replace(tcn, lag_scale=0.191)),
            FeatureFrontend(causal_tcn=replace(tcn, mask_scale=0.111)),
            FeatureFrontend(causal_tcn=replace(tcn, delta_scales=(0.051, 0.03))),
            FeatureFrontend(causal_tcn=replace(tcn, delta_scales=(0.05, 0.031))),
            FeatureFrontend(attention=replace(attention, temperature=1.001)),
            FeatureFrontend(attention=replace(attention, max_sources=15)),
            FeatureFrontend(attention=replace(attention, score_bias=1.001)),
            FeatureFrontend(attention=replace(attention, exponent_clamp_min=-59.0)),
            FeatureFrontend(attention=replace(attention, exponent_clamp_max=59.0)),
        )
        self.assertTrue(all(frontend.weights_digest() != baseline.weights_digest() for frontend in variants))
        for frontend in variants:
            with self.assertRaisesRegex(FeatureFrontendError, "weights digest"):
                frontend.materialize(manifest())

        head = baseline.scattering_head
        changed_bias = [list(row) for row in head.bias_weights]
        changed_bias[0][0] += 0.001
        changed_noise = list(head.noise_weights)
        changed_noise[0] += 0.001
        for changed in (
            replace(head, bias_weights=tuple(tuple(row) for row in changed_bias)),
            replace(head, noise_weights=tuple(changed_noise)),
        ):
            changed_frontend = FeatureFrontend(scattering_head=changed)
            self.assertNotEqual(changed_frontend.weights_digest(), baseline.weights_digest())
            with self.assertRaisesRegex(FeatureFrontendError, "weights digest"):
                changed_frontend.materialize(manifest())

        class ForgedSlowMLP(SlowMLP):
            pass

        with self.assertRaisesRegex(FeatureFrontendError, "built-in"):
            FeatureFrontend(slow_mlp=ForgedSlowMLP()).weights_digest()

    def test_supervised_scattering_head_propagates_known_bias_and_is_pair_symmetric(self) -> None:
        examples = tuple(
            ScatteringExample(
                features=(amplitude,),
                bias_target_m=(0.25 * amplitude, -0.1 * amplitude, 0.05 * amplitude),
                noise_target_m=0.04 * amplitude,
                provenance=f"fixture-{amplitude}",
            )
            for amplitude in (1.0, 2.0, 3.0)
        )
        head = ScatteringBiasNoiseHead.fit(examples)
        estimate = head.predict_features((2.0,), source_key="array-a/boot-a", path_id="p")
        self.assertAlmostEqual(estimate.bias_m[0], 0.5, places=4)
        self.assertAlmostEqual(estimate.bias_m[1], -0.2, places=4)
        self.assertAlmostEqual(estimate.bias_m[2], 0.1, places=4)
        self.assertAlmostEqual(estimate.noise_m, 0.08, places=4)
        self.assertGreaterEqual(estimate.propagated_uncertainty_m, estimate.noise_m)

        left = head.pair_features((1.0, 2.0), (3.0, 4.0))
        right = head.pair_features((3.0, 4.0), (1.0, 2.0))
        self.assertEqual(left, right)
        self.assertEqual(left.sum_features, (4.0, 6.0))
        self.assertEqual(left.absolute_difference, (2.0, 2.0))

    def test_scattering_fit_consumes_at_most_limit_plus_one_and_accepts_exact_boundary(self) -> None:
        examples = tuple(
            ScatteringExample(
                features=(float(index),),
                bias_target_m=(float(index), 0.0, 0.0),
                noise_target_m=0.1,
                provenance=f"bounded-{index}",
            )
            for index in range(3)
        )

        class CountingGenerator:
            def __init__(self, values):
                self.values = iter(values)
                self.pulls = 0

            def __iter__(self):
                return self

            def __next__(self):
                self.pulls += 1
                return next(self.values)

        exact = CountingGenerator(examples)
        head = ScatteringBiasNoiseHead.fit(exact, max_samples=3)
        self.assertEqual(len(head.noise_weights), 2)
        self.assertEqual(exact.pulls, 4)

        overflow = CountingGenerator((*examples, examples[-1]))
        with self.assertRaisesRegex(FeatureFrontendError, "sample count"):
            ScatteringBiasNoiseHead.fit(overflow, max_samples=3)
        self.assertEqual(overflow.pulls, 4)

        class HostileGenerator:
            def __init__(self):
                self.pulls = 0

            def __iter__(self):
                return self

            def __next__(self):
                self.pulls += 1
                return examples[0]

        hostile = HostileGenerator()
        with self.assertRaisesRegex(FeatureFrontendError, "sample count"):
            ScatteringBiasNoiseHead.fit(hostile, max_samples=3)
        self.assertEqual(hostile.pulls, 4)

    def test_map_query_attention_fuses_two_sources_without_a_second_vote(self) -> None:
        grid = MapGrid(
            cells=(MapCell("cell-0", (0.0, 0.0, 0.0)), MapCell("cell-1", (1.0, 0.0, 0.0)))
        )
        attention = CrossSourceAttention()
        embeddings = (
            SourceEmbedding("array-a/boot-a", (1.0, 0.0, 0.5), (True, True, True)),
            SourceEmbedding("array-b/boot-b", (0.0, 1.0, 0.5), (True, True, True)),
        )
        first = attention.fuse(grid, embeddings)
        second = attention.fuse(grid, tuple(reversed(embeddings)))
        self.assertEqual(first, second)
        for cell in first:
            self.assertEqual(cell.source_count, 2)
            self.assertAlmostEqual(sum(weight for _, weight in cell.weights), 1.0, places=7)
            self.assertEqual(tuple(source for source, _ in cell.weights), ("array-a/boot-a", "array-b/boot-b"))
            self.assertTrue(cell.mask)

    def test_json_round_trip_is_canonical_and_operator_fixture_is_bounded(self) -> None:
        value = manifest()
        restored = FeatureManifest.from_bytes(value.canonical_bytes())
        self.assertEqual(restored, value)
        self.assertEqual(restored.digest(), value.digest())
        with self.assertRaisesRegex(FeatureFrontendError, "canonical"):
            FeatureManifest.from_bytes(json.dumps(value.to_dict()).encode())

        candidate, shape, successor = FeatureFrontendOperator().evaluate(operator_request(value))
        self.assertEqual(shape, (len(candidate) // 4,))
        self.assertEqual(len(successor), 32)
        self.assertEqual(len(candidate), shape[0] * 4)

    def test_operator_binds_outer_tensor_and_rejects_causal_cutoff_bypass(self) -> None:
        value = manifest()
        operator = FeatureFrontendOperator()

        altered_tensor = operator_request(value)
        altered_tensor_bytes = bytearray.fromhex(altered_tensor["input_manifest"]["tensor_hex"])
        altered_tensor_bytes[0] ^= 0x01
        altered_tensor["input_manifest"]["tensor_hex"] = bytes(altered_tensor_bytes).hex()
        altered_tensor["input_manifest"]["tensor_digest"] = digest(bytes(altered_tensor_bytes))
        with self.assertRaisesRegex(ContractFailure, "canonical manifest materialization"):
            operator.evaluate(altered_tensor)

        bypassed = operator_request(replace(value, cutoff_ns=value.cutoff_ns - 1))
        bypassed["identity"]["cutoff_ns"] = value.cutoff_ns
        bypassed["input_manifest"]["cutoff_ns"] = value.cutoff_ns
        with self.assertRaisesRegex(ContractFailure, "causal cutoff"):
            operator.evaluate(bypassed)

        class MustNotMaterialize(FeatureFrontend):
            def __init__(self) -> None:
                super().__init__()
                self.materialize_calls = 0

            def materialize(self, manifest_value):
                self.materialize_calls += 1
                raise AssertionError("causal identity must be checked before materialization")

        guarded = MustNotMaterialize()
        with self.assertRaisesRegex(ContractFailure, "causal cutoff"):
            FeatureFrontendOperator(guarded).evaluate(bypassed)
        self.assertEqual(guarded.materialize_calls, 0)

    def test_metadata_only_blocks_remain_masked_and_do_not_create_attention_evidence(self) -> None:
        value = manifest()
        empty_blocks = tuple(
            replace(
                item,
                absolute_response=tuple(0.0 for _ in item.absolute_response),
                spectrum_shape=tuple(0.0 for _ in item.spectrum_shape),
                background_residual=tuple(0.0 for _ in item.background_residual),
                fast_values=tuple(0.0 for _ in item.fast_values),
                absolute_mask=tuple(False for _ in item.absolute_mask),
                spectrum_mask=tuple(False for _ in item.spectrum_mask),
                residual_mask=tuple(False for _ in item.residual_mask),
                fast_mask=tuple(False for _ in item.fast_mask),
                quality=FeatureQuality.METADATA_ONLY,
            )
            for item in value.blocks
        )
        empty = manifest(blocks=empty_blocks, paths=())
        result = FeatureFrontend().materialize(empty)
        self.assertTrue(all(not cell.mask and cell.source_count == 0 for cell in result.attention))
        self.assertTrue(all(not mask for item in result.tcn_outputs for mask in item.masks))

    def test_tcn_retains_distinct_quality_states_and_lost_quality_fixture(self) -> None:
        value = manifest()
        quality_blocks = (
            replace(value.blocks[0], quality=FeatureQuality.LOST),
            replace(value.blocks[1], quality=FeatureQuality.INVALID),
            replace(value.blocks[2], quality=FeatureQuality.INTERPOLATED),
            replace(value.blocks[3], quality=FeatureQuality.TRAINING_MASKED),
        )
        result = FeatureFrontend().materialize(manifest(blocks=quality_blocks, paths=()))

        tcn_a = next(item for item in result.tcn_outputs if item.source_key == "array-a/boot-a")
        self.assertEqual(
            tcn_a.quality_states,
            (FeatureQuality.LOST, FeatureQuality.INVALID, FeatureQuality.INTERPOLATED),
        )
        self.assertEqual(tcn_a.masks, (False, False, True))
        tcn_b = next(item for item in result.tcn_outputs if item.source_key == "array-b/boot-b")
        self.assertEqual(tcn_b.quality_states, (FeatureQuality.TRAINING_MASKED,))
        self.assertEqual(tcn_b.masks, (False,))


if __name__ == "__main__":
    unittest.main()
