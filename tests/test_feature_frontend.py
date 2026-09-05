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
    MapCell,
    MapGrid,
    PathClass,
    QualifiedPath,
    ScatteringBiasNoiseHead,
    ScatteringExample,
    SourceEmbedding,
    SourceProvenance,
)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
        weights_digest="ab" * 32,
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

        candidate, shape, successor = FeatureFrontendOperator().evaluate(
            {"input_manifest": {"manifest_hex": value.canonical_bytes().hex()}}
        )
        self.assertEqual(shape, (len(candidate) // 4,))
        self.assertEqual(len(successor), 32)
        self.assertEqual(len(candidate), shape[0] * 4)

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
            )
            for item in value.blocks
        )
        empty = manifest(blocks=empty_blocks, paths=())
        result = FeatureFrontend().materialize(empty)
        self.assertTrue(all(not cell.mask and cell.source_count == 0 for cell in result.attention))
        self.assertTrue(all(not mask for item in result.tcn_outputs for mask in item.masks))


if __name__ == "__main__":
    unittest.main()
