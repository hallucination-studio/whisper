"""Deterministic, bounded RF feature front-end for the numerical worker.

The module keeps RF feature extraction separate from persistence and world-state
authority.  A :class:`FeatureManifest` is the complete input boundary: every
block, mask, source boot, preprocessing identity, qualified path, and map cell
is frozen before the three numerical branches run.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
import struct


MANIFEST_SCHEMA = "rf-feature-manifest-v1"
FRONTEND_VERSION = "rf-feature-frontend-v1"
PREPROCESSING_VERSION = "rf-feature-pre-v1"
COMPONENT_SCHEMA = "rf-feature-component-v1"
WEIGHTS_SCHEMA = "rf-feature-weights-v1"
MAX_TEXT_BYTES = 128
MAX_FEATURE_WIDTH = 256
MAX_TCN_CONTEXT_NS = 2_000_000_000
# Default supervised-example count; bounding n keeps ridge accumulation O(n * width²).
MAX_SCATTERING_SAMPLES = 1_024
PATH_CLASSES = 4


class FeatureFrontendError(ValueError):
    """A bounded, fail-closed feature contract or materialization failure."""

    def __init__(self, reason: str, detail: str):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


@dataclass(frozen=True, slots=True)
class FeatureLimits:
    """Resource ceilings applied before feature materialization or allocation."""

    max_manifest_bytes: int = 131_072
    max_blocks: int = 64
    max_sources: int = 16
    max_paths: int = 128
    max_cells: int = 256
    max_feature_width: int = MAX_FEATURE_WIDTH
    max_tcn_context_ns: int = MAX_TCN_CONTEXT_NS
    max_tensor_bytes: int = 524_288

    def __post_init__(self) -> None:
        for field_name in (
            "max_manifest_bytes",
            "max_blocks",
            "max_sources",
            "max_paths",
            "max_cells",
            "max_feature_width",
            "max_tcn_context_ns",
            "max_tensor_bytes",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise FeatureFrontendError("contract", f"{field} must be 1..{MAX_TEXT_BYTES} UTF-8 bytes")
    return value


def _unsigned(value: object, field: str, bits: int = 64) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= 1 << bits:
        raise FeatureFrontendError("contract", f"{field} must be an unsigned {bits}-bit integer")
    return value


def _digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise FeatureFrontendError("contract", f"{field} must be canonical lowercase SHA-256 hex")
    return value


def _floats(value: object, field: str) -> tuple[float, ...]:
    if isinstance(value, (str, bytes, bytearray)):
        raise FeatureFrontendError("contract", f"{field} must be a finite numeric sequence")
    try:
        result = tuple(value)  # type: ignore[arg-type]
    except TypeError as error:
        raise FeatureFrontendError("contract", f"{field} must be a finite numeric sequence") from error
    if not result:
        raise FeatureFrontendError("contract", f"{field} must not be empty")
    if len(result) > MAX_FEATURE_WIDTH:
        raise FeatureFrontendError("limit", f"{field} exceeds the feature-width limit")
    converted: list[float] = []
    for index, item in enumerate(result):
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise FeatureFrontendError("non_finite", f"{field}[{index}] is not numeric")
        number = float(item)
        if not math.isfinite(number):
            raise FeatureFrontendError("non_finite", f"{field}[{index}] is not finite")
        converted.append(number)
    return tuple(converted)


def _mask(value: object, field: str, expected: int | None = None) -> tuple[bool, ...]:
    if isinstance(value, (str, bytes, bytearray)):
        raise FeatureFrontendError("contract", f"{field} must be a boolean sequence")
    try:
        result = tuple(value)  # type: ignore[arg-type]
    except TypeError as error:
        raise FeatureFrontendError("contract", f"{field} must be a boolean sequence") from error
    if expected is not None and len(result) != expected:
        raise FeatureFrontendError("contract", f"{field} length does not match its feature shape")
    if any(not isinstance(item, bool) for item in result):
        raise FeatureFrontendError("contract", f"{field} contains a non-boolean mask value")
    return result


def _canonical_json(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise FeatureFrontendError("contract", "manifest is not canonical JSON") from error


def _duplicate_key_error(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FeatureFrontendError("contract", f"manifest repeats JSON key {key!r}")
        value[key] = item
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FeatureFrontendError("contract", f"{field} must be an object")
    return value


def _float64_hex(value: float, field: str) -> str:
    """Encode one finite parameter as canonical little-endian IEEE-754 binary64."""

    if not math.isfinite(value):
        raise FeatureFrontendError("non_finite", f"{field} is not finite")
    return struct.pack("<d", value).hex()


def _float64_sequence_hex(values: Sequence[float], field: str) -> str:
    """Encode a finite numerical sequence without allowing platform float formatting."""

    if any(not math.isfinite(value) for value in values):
        raise FeatureFrontendError("non_finite", f"{field} contains a non-finite parameter")
    return struct.pack(f"<{len(values)}d", *values).hex()


def _component_bytes(component: str, parameters: Mapping[str, object]) -> bytes:
    """Build the canonical identity bytes for one configured numerical component."""

    return _canonical_json(
        {
            "schema": COMPONENT_SCHEMA,
            "component": component,
            "parameters": parameters,
        }
    )


def _component_digest(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def _source_key(source_id: str, boot_id: str) -> str:
    return f"{source_id}/{boot_id}"


@dataclass(frozen=True, slots=True)
class SourceProvenance:
    """Immutable source, boot, RF-profile, clock, and raw-record identity."""

    source_id: str
    boot_id: str
    profile: str
    radio: str
    channel: int
    clock_domain: str
    raw_record_digest: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.source_id, "source ID"),
            (self.boot_id, "boot ID"),
            (self.profile, "profile"),
            (self.radio, "radio"),
            (self.clock_domain, "clock domain"),
        ):
            _text(value, field)
        _unsigned(self.channel, "channel", 16)
        _digest(self.raw_record_digest, "raw-record digest")

    @property
    def source_key(self) -> str:
        """Returns the source-plus-boot identity used for grouping blocks."""

        return _source_key(self.source_id, self.boot_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "boot_id": self.boot_id,
            "profile": self.profile,
            "radio": self.radio,
            "channel": self.channel,
            "clock_domain": self.clock_domain,
            "raw_record_digest": self.raw_record_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SourceProvenance:
        data = _mapping(value, "source provenance")
        return cls(
            source_id=data["source_id"],
            boot_id=data["boot_id"],
            profile=data["profile"],
            radio=data["radio"],
            channel=data["channel"],
            clock_domain=data["clock_domain"],
            raw_record_digest=data["raw_record_digest"],
        )


@dataclass(frozen=True, slots=True)
class FeatureBlock:
    """One causal block containing uncentered slow, residual, and fast inputs."""

    block_id: str
    source: SourceProvenance
    timestamp_ns: int
    absolute_response: tuple[float, ...]
    spectrum_shape: tuple[float, ...]
    background_residual: tuple[float, ...]
    fast_values: tuple[float, ...]
    absolute_mask: tuple[bool, ...]
    spectrum_mask: tuple[bool, ...]
    residual_mask: tuple[bool, ...]
    fast_mask: tuple[bool, ...]
    preprocessing_version: str = PREPROCESSING_VERSION

    def __post_init__(self) -> None:
        _text(self.block_id, "block ID")
        if not isinstance(self.source, SourceProvenance):
            raise FeatureFrontendError("contract", "block source is not source provenance")
        _unsigned(self.timestamp_ns, "block timestamp")
        for field_name in (
            "absolute_response",
            "spectrum_shape",
            "background_residual",
            "fast_values",
        ):
            values = _floats(getattr(self, field_name), field_name)
            object.__setattr__(self, field_name, values)
        for field_name, value, feature_name in (
            ("absolute_mask", self.absolute_mask, "absolute_response"),
            ("spectrum_mask", self.spectrum_mask, "spectrum_shape"),
            ("residual_mask", self.residual_mask, "background_residual"),
            ("fast_mask", self.fast_mask, "fast_values"),
        ):
            feature = getattr(self, feature_name)
            object.__setattr__(self, field_name, _mask(value, field_name, len(feature)))
        _text(self.preprocessing_version, "block preprocessing version")

    @property
    def source_key(self) -> str:
        """Returns the source-plus-boot identity for this block."""

        return self.source.source_key

    def to_dict(self) -> dict[str, object]:
        return {
            "block_id": self.block_id,
            "source": self.source.to_dict(),
            "timestamp_ns": self.timestamp_ns,
            "features": {
                "absolute_response": list(self.absolute_response),
                "spectrum_shape": list(self.spectrum_shape),
                "background_residual": list(self.background_residual),
                "fast_values": list(self.fast_values),
            },
            "shapes": {
                "absolute_response": [len(self.absolute_response)],
                "spectrum_shape": [len(self.spectrum_shape)],
                "background_residual": [len(self.background_residual)],
                "fast_values": [len(self.fast_values)],
            },
            "masks": {
                "absolute": list(self.absolute_mask),
                "spectrum": list(self.spectrum_mask),
                "residual": list(self.residual_mask),
                "fast": list(self.fast_mask),
            },
            "preprocessing_version": self.preprocessing_version,
        }

    @classmethod
    def from_dict(cls, value: object) -> FeatureBlock:
        data = _mapping(value, "feature block")
        features = _mapping(data["features"], "block features")
        masks = _mapping(data["masks"], "block masks")
        return cls(
            block_id=data["block_id"],
            source=SourceProvenance.from_dict(data["source"]),
            timestamp_ns=data["timestamp_ns"],
            absolute_response=features["absolute_response"],
            spectrum_shape=features["spectrum_shape"],
            background_residual=features["background_residual"],
            fast_values=features["fast_values"],
            absolute_mask=masks["absolute"],
            spectrum_mask=masks["spectrum"],
            residual_mask=masks["residual"],
            fast_mask=masks["fast"],
            preprocessing_version=data["preprocessing_version"],
        )


class PathClass(str, Enum):
    """Path classes emitted by the qualified array adapter."""

    DIRECT_PATH_POSSIBLE = "direct_path_possible"
    STABLE_STATIC = "stable_static"
    DYNAMIC_CANDIDATE = "dynamic_candidate"
    UNEXPLAINED = "unexplained"


@dataclass(frozen=True, slots=True)
class QualifiedPath:
    """One qualified angle-delay candidate with its immutable RF provenance."""

    path_id: str
    source: SourceProvenance
    observed_at_ns: int
    angle_radians: float
    delay_seconds: float
    path_class: PathClass
    uncertainty: float
    coverage: float
    normalized_power: float
    calibration_epoch: int
    calibration_digest: str
    phase_calibration_digest: str
    qualified: bool = True
    operator: str = "angle_delay"
    adapter_kind: str = "qualified_array"
    qualification_valid_until_ns: int = (1 << 64) - 1
    phase_coherent: bool = True

    def __post_init__(self) -> None:
        _text(self.path_id, "path ID")
        if not isinstance(self.source, SourceProvenance):
            raise FeatureFrontendError("contract", "path source is not source provenance")
        _unsigned(self.observed_at_ns, "path observation time")
        for value, field in (
            (self.angle_radians, "path angle"),
            (self.delay_seconds, "path delay"),
            (self.uncertainty, "path uncertainty"),
            (self.coverage, "path coverage"),
            (self.normalized_power, "path normalized power"),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise FeatureFrontendError("non_finite", f"{field} is not finite")
        if self.uncertainty < 0.0:
            raise FeatureFrontendError("contract", "path uncertainty must be non-negative")
        if not 0.0 <= self.coverage <= 1.0:
            raise FeatureFrontendError("contract", "path coverage must be between zero and one")
        if not 0.0 <= self.normalized_power <= 1.0:
            raise FeatureFrontendError("contract", "path normalized power must be between zero and one")
        if not isinstance(self.path_class, PathClass):
            try:
                object.__setattr__(self, "path_class", PathClass(self.path_class))
            except (TypeError, ValueError) as error:
                raise FeatureFrontendError("contract", "path class is not recognized") from error
        if not isinstance(self.qualified, bool) or not self.qualified:
            raise FeatureFrontendError("qualification", "path is not physically qualified")
        if self.operator != "angle_delay":
            raise FeatureFrontendError("qualification", "path operator is not angle_delay")
        if self.adapter_kind != "qualified_array":
            raise FeatureFrontendError("qualification", "path is not from the qualified array adapter")
        _unsigned(self.calibration_epoch, "path calibration epoch", 32)
        _unsigned(self.qualification_valid_until_ns, "path qualification expiry")
        if self.observed_at_ns > self.qualification_valid_until_ns:
            raise FeatureFrontendError("qualification", "path qualification was expired at capture time")
        if not isinstance(self.phase_coherent, bool) or not self.phase_coherent:
            raise FeatureFrontendError("qualification", "path phase relation is not coherent")
        _digest(self.calibration_digest, "path calibration digest")
        _digest(self.phase_calibration_digest, "path phase-calibration digest")

    @property
    def source_key(self) -> str:
        """Returns the source-plus-boot identity for this path."""

        return self.source.source_key

    def to_dict(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "source": self.source.to_dict(),
            "observed_at_ns": self.observed_at_ns,
            "angle_radians": self.angle_radians,
            "delay_seconds": self.delay_seconds,
            "path_class": self.path_class.value,
            "uncertainty": self.uncertainty,
            "coverage": self.coverage,
            "normalized_power": self.normalized_power,
            "calibration_epoch": self.calibration_epoch,
            "calibration_digest": self.calibration_digest,
            "phase_calibration_digest": self.phase_calibration_digest,
            "qualified": self.qualified,
            "operator": self.operator,
            "adapter_kind": self.adapter_kind,
            "qualification_valid_until_ns": self.qualification_valid_until_ns,
            "phase_coherent": self.phase_coherent,
        }

    @classmethod
    def from_dict(cls, value: object) -> QualifiedPath:
        data = _mapping(value, "qualified path")
        return cls(
            path_id=data["path_id"],
            source=SourceProvenance.from_dict(data["source"]),
            observed_at_ns=data["observed_at_ns"],
            angle_radians=data["angle_radians"],
            delay_seconds=data["delay_seconds"],
            path_class=data["path_class"],
            uncertainty=data["uncertainty"],
            coverage=data["coverage"],
            normalized_power=data["normalized_power"],
            calibration_epoch=data["calibration_epoch"],
            calibration_digest=data["calibration_digest"],
            phase_calibration_digest=data["phase_calibration_digest"],
            qualified=data.get("qualified", True),
            operator=data.get("operator", "angle_delay"),
            adapter_kind=data.get("adapter_kind", "qualified_array"),
            qualification_valid_until_ns=data.get("qualification_valid_until_ns", (1 << 64) - 1),
            phase_coherent=data.get("phase_coherent", True),
        )


@dataclass(frozen=True, slots=True)
class MapCell:
    """An explicit world-coordinate grid cell; no opaque resampling is implied."""

    cell_id: str
    position_m: tuple[float, float, float]
    valid: bool = True

    def __post_init__(self) -> None:
        _text(self.cell_id, "map cell ID")
        position = _floats(self.position_m, "map cell position")
        if len(position) != 3:
            raise FeatureFrontendError("contract", "map cell position must have three coordinates")
        object.__setattr__(self, "position_m", position)
        if not isinstance(self.valid, bool):
            raise FeatureFrontendError("contract", "map cell validity must be boolean")

    def to_dict(self) -> dict[str, object]:
        return {"cell_id": self.cell_id, "position_m": list(self.position_m), "valid": self.valid}

    @classmethod
    def from_dict(cls, value: object) -> MapCell:
        data = _mapping(value, "map cell")
        return cls(cell_id=data["cell_id"], position_m=data["position_m"], valid=data.get("valid", True))


@dataclass(frozen=True, slots=True)
class MapGrid:
    """Bounded explicit map-query cells used by cross-source attention."""

    cells: tuple[MapCell, ...]

    def __post_init__(self) -> None:
        cells = tuple(self.cells)
        if not cells:
            raise FeatureFrontendError("contract", "map grid must contain at least one cell")
        if any(not isinstance(cell, MapCell) for cell in cells):
            raise FeatureFrontendError("contract", "map grid contains an invalid cell")
        if len({cell.cell_id for cell in cells}) != len(cells):
            raise FeatureFrontendError("contract", "map grid repeats a cell ID")
        object.__setattr__(self, "cells", cells)

    def to_dict(self) -> dict[str, object]:
        return {"cells": [cell.to_dict() for cell in self.cells]}

    @classmethod
    def from_dict(cls, value: object) -> MapGrid:
        data = _mapping(value, "map grid")
        return cls(cells=tuple(MapCell.from_dict(item) for item in data["cells"]))


@dataclass(frozen=True, slots=True)
class FeatureManifest:
    """Immutable manifest defining one deterministic frontend materialization."""

    run_id: str
    epoch: int
    cutoff_ns: int
    preprocessing_version: str
    weights_digest: str
    blocks: tuple[FeatureBlock, ...]
    paths: tuple[QualifiedPath, ...]
    map_grid: MapGrid
    qualification_epoch: int
    causal_context_ns: int = MAX_TCN_CONTEXT_NS
    source_provenance: tuple[SourceProvenance, ...] = ()

    def __post_init__(self) -> None:
        _text(self.run_id, "feature run ID")
        _unsigned(self.epoch, "feature epoch")
        _unsigned(self.cutoff_ns, "feature cutoff")
        _text(self.preprocessing_version, "manifest preprocessing version")
        _digest(self.weights_digest, "weights digest")
        _unsigned(self.qualification_epoch, "qualification epoch", 32)
        _unsigned(self.causal_context_ns, "causal context")
        if self.causal_context_ns == 0:
            raise FeatureFrontendError("contract", "causal context must be positive")

        blocks = tuple(self.blocks)
        paths = tuple(self.paths)
        if not blocks:
            raise FeatureFrontendError("contract", "feature manifest must contain at least one block")
        if any(not isinstance(item, FeatureBlock) for item in blocks):
            raise FeatureFrontendError("contract", "feature manifest contains an invalid block")
        if any(not isinstance(item, QualifiedPath) for item in paths):
            raise FeatureFrontendError("contract", "feature manifest contains an invalid path")
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(self, "paths", paths)
        if not isinstance(self.map_grid, MapGrid):
            raise FeatureFrontendError("contract", "feature manifest map is invalid")

        derived: dict[str, SourceProvenance] = {}
        seen_blocks: set[str] = set()
        last_by_source: dict[str, int] = {}
        for item in blocks:
            if item.block_id in seen_blocks:
                raise FeatureFrontendError("contract", f"duplicate block ID {item.block_id}")
            seen_blocks.add(item.block_id)
            if item.timestamp_ns > self.cutoff_ns:
                raise FeatureFrontendError("future", f"block {item.block_id} is after the causal cutoff")
            if item.preprocessing_version != self.preprocessing_version:
                raise FeatureFrontendError("contract", f"block {item.block_id} has a different preprocessing version")
            previous = last_by_source.get(item.source_key)
            if previous is not None and item.timestamp_ns <= previous:
                raise FeatureFrontendError("contract", f"source {item.source_key} blocks are not strictly ordered")
            last_by_source[item.source_key] = item.timestamp_ns
            existing = derived.get(item.source_key)
            if existing is not None and existing != item.source:
                raise FeatureFrontendError("contract", f"source {item.source_key} changes provenance")
            derived[item.source_key] = item.source

        supplied = tuple(self.source_provenance)
        if supplied:
            if any(not isinstance(item, SourceProvenance) for item in supplied):
                raise FeatureFrontendError("contract", "manifest source provenance is invalid")
            supplied_by_key = {item.source_key: item for item in supplied}
            if len(supplied_by_key) != len(supplied) or supplied_by_key != derived:
                raise FeatureFrontendError("contract", "manifest source provenance does not match blocks")
        else:
            supplied = tuple(derived[key] for key in sorted(derived))
            object.__setattr__(self, "source_provenance", supplied)

        seen_paths: set[str] = set()
        for item in paths:
            if item.path_id in seen_paths:
                raise FeatureFrontendError("contract", f"duplicate path ID {item.path_id}")
            seen_paths.add(item.path_id)
            if item.source_key not in derived:
                raise FeatureFrontendError("contract", f"path {item.path_id} names an unknown source")
            if item.source != derived[item.source_key]:
                raise FeatureFrontendError("contract", f"path {item.path_id} changes source provenance")
            if item.observed_at_ns > self.cutoff_ns:
                raise FeatureFrontendError("future", f"path {item.path_id} is after the causal cutoff")
            if item.qualification_valid_until_ns < self.cutoff_ns:
                raise FeatureFrontendError("qualification", f"path {item.path_id} qualification expired before cutoff")
            if item.calibration_epoch != self.qualification_epoch:
                raise FeatureFrontendError("qualification", f"path {item.path_id} has the wrong qualification epoch")

    def validate(self, limits: FeatureLimits) -> None:
        """Checks configured count, shape, context, and canonical-byte limits."""

        if len(self.blocks) > limits.max_blocks:
            raise FeatureFrontendError("limit", "feature block count exceeds its configured limit")
        if len(self.source_provenance) > limits.max_sources:
            raise FeatureFrontendError("limit", "source count exceeds its configured limit")
        if len(self.paths) > limits.max_paths:
            raise FeatureFrontendError("limit", "qualified path count exceeds its configured limit")
        if len(self.map_grid.cells) > limits.max_cells:
            raise FeatureFrontendError("limit", "map cell count exceeds its configured limit")
        if self.causal_context_ns > limits.max_tcn_context_ns:
            raise FeatureFrontendError("limit", "causal context exceeds its configured limit")
        for block in self.blocks:
            for field_name in (
                "absolute_response",
                "spectrum_shape",
                "background_residual",
                "fast_values",
            ):
                if len(getattr(block, field_name)) > limits.max_feature_width:
                    raise FeatureFrontendError("limit", f"{field_name} exceeds its configured feature width")
        encoded = self.canonical_bytes()
        if len(encoded) > limits.max_manifest_bytes:
            raise FeatureFrontendError("limit", "feature manifest exceeds its configured byte limit")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": MANIFEST_SCHEMA,
            "run_id": self.run_id,
            "epoch": self.epoch,
            "cutoff_ns": self.cutoff_ns,
            "preprocessing_version": self.preprocessing_version,
            "weights_digest": self.weights_digest,
            "qualification_epoch": self.qualification_epoch,
            "causal_context_ns": self.causal_context_ns,
            "source_provenance": [item.to_dict() for item in sorted(self.source_provenance, key=lambda item: item.source_key)],
            "blocks": [item.to_dict() for item in self.blocks],
            "paths": [item.to_dict() for item in self.paths],
            "map_grid": self.map_grid.to_dict(),
        }

    def canonical_bytes(self) -> bytes:
        """Returns the exact canonical bytes used as the manifest identity."""

        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        """Returns the SHA-256 digest of the exact canonical manifest bytes."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> FeatureManifest:
        data = _mapping(value, "feature manifest")
        if data.get("schema") != MANIFEST_SCHEMA:
            raise FeatureFrontendError("contract", "unsupported feature manifest schema")
        return cls(
            run_id=data["run_id"],
            epoch=data["epoch"],
            cutoff_ns=data["cutoff_ns"],
            preprocessing_version=data["preprocessing_version"],
            weights_digest=data["weights_digest"],
            qualification_epoch=data["qualification_epoch"],
            causal_context_ns=data.get("causal_context_ns", MAX_TCN_CONTEXT_NS),
            source_provenance=tuple(
                SourceProvenance.from_dict(item) for item in data.get("source_provenance", ())
            ),
            blocks=tuple(FeatureBlock.from_dict(item) for item in data["blocks"]),
            paths=tuple(QualifiedPath.from_dict(item) for item in data.get("paths", ())),
            map_grid=MapGrid.from_dict(data["map_grid"]),
        )

    @classmethod
    def from_bytes(cls, value: bytes, limits: FeatureLimits | None = None) -> FeatureManifest:
        """Parses only canonical JSON bytes under the configured manifest limit."""

        limits = limits or FeatureLimits()
        if not isinstance(value, bytes) or len(value) > limits.max_manifest_bytes:
            raise FeatureFrontendError("limit", "feature manifest exceeds its configured byte limit")
        try:
            decoded = json.loads(value, object_pairs_hook=_duplicate_key_error)
        except FeatureFrontendError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise FeatureFrontendError("contract", "feature manifest is not valid JSON") from error
        result = cls.from_dict(decoded)
        if result.canonical_bytes() != value:
            raise FeatureFrontendError("contract", "feature manifest bytes are not canonical")
        result.validate(limits)
        return result


@dataclass(frozen=True, slots=True)
class SlowMLPOutput:
    """Slow branch output retaining raw stationary fields beside its embedding."""

    source_key: str
    timestamp_ns: int
    embedding: tuple[float, ...]
    absolute_response: tuple[float, ...]
    spectrum_shape: tuple[float, ...]
    background_residual: tuple[float, ...]
    absolute_mask: tuple[bool, ...]
    spectrum_mask: tuple[bool, ...]
    residual_mask: tuple[bool, ...]
    absolute_level: float
    preprocessing_version: str


class SlowMLP:
    """Small deterministic MLP that never removes absolute stationary response."""

    def __init__(self, hidden_width: int = 8):
        if isinstance(hidden_width, bool) or not isinstance(hidden_width, int) or not 1 <= hidden_width <= 64:
            raise ValueError("hidden_width must be in 1..64")
        self.hidden_width = hidden_width

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes for the configured slow branch."""

        if isinstance(self.hidden_width, bool) or not isinstance(self.hidden_width, int) or not 1 <= self.hidden_width <= 64:
            raise FeatureFrontendError("contract", "slow MLP hidden width is outside its supported bound")
        return _component_bytes(
            "slow_mlp",
            {
                "algorithm_version": "slow-mlp-v1",
                "hidden_width": self.hidden_width,
            },
        )

    def digest(self) -> str:
        """Return the SHA-256 digest of the configured slow branch bytes."""

        return _component_digest(self.canonical_bytes())

    def encode(self, block: FeatureBlock) -> SlowMLPOutput:
        values = (
            tuple(value if present else 0.0 for value, present in zip(block.absolute_response, block.absolute_mask)),
            tuple(value if present else 0.0 for value, present in zip(block.spectrum_shape, block.spectrum_mask)),
            tuple(value if present else 0.0 for value, present in zip(block.background_residual, block.residual_mask)),
        )
        flattened = tuple(number for group in values for number in group)
        embedding: list[float] = []
        for hidden in range(self.hidden_width):
            total = 0.07 * (hidden + 1)
            for index, number in enumerate(flattened):
                total += number * math.sin((hidden + 1) * (index + 1) * 0.37) * 0.08
            embedding.append(math.tanh(total))
        present = [value for value, is_present in zip(block.absolute_response, block.absolute_mask) if is_present]
        absolute_level = math.fsum(present) / len(present) if present else 0.0
        return SlowMLPOutput(
            source_key=block.source_key,
            timestamp_ns=block.timestamp_ns,
            embedding=tuple(embedding),
            absolute_response=block.absolute_response,
            spectrum_shape=block.spectrum_shape,
            background_residual=block.background_residual,
            absolute_mask=block.absolute_mask,
            spectrum_mask=block.spectrum_mask,
            residual_mask=block.residual_mask,
            absolute_level=absolute_level,
            preprocessing_version=block.preprocessing_version,
        )


@dataclass(frozen=True, slots=True)
class CausalTCNOutput:
    """Bounded causal history output with its actual timestamps and masks."""

    source_key: str
    cutoff_ns: int
    timestamps_ns: tuple[int, ...]
    time_deltas_ns: tuple[int, ...]
    masks: tuple[bool, ...]
    embedding: tuple[float, ...]


class CausalTCN:
    """A tiny causal temporal convolution using real intervals and no future input."""

    def __init__(self, context_ns: int = MAX_TCN_CONTEXT_NS):
        if isinstance(context_ns, bool) or not isinstance(context_ns, int) or not 1 <= context_ns <= MAX_TCN_CONTEXT_NS:
            raise ValueError(f"context_ns must be in 1..{MAX_TCN_CONTEXT_NS}")
        self.context_ns = context_ns

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes for the configured causal temporal branch."""

        if isinstance(self.context_ns, bool) or not isinstance(self.context_ns, int) or not 1 <= self.context_ns <= MAX_TCN_CONTEXT_NS:
            raise FeatureFrontendError("contract", "causal TCN context is outside its supported bound")
        return _component_bytes(
            "causal_tcn",
            {
                "algorithm_version": "causal-tcn-v1",
                "context_ns": self.context_ns,
            },
        )

    def digest(self) -> str:
        """Return the SHA-256 digest of the configured causal temporal branch bytes."""

        return _component_digest(self.canonical_bytes())

    @staticmethod
    def _summary(block: FeatureBlock) -> tuple[float, float]:
        present = [value for value, is_present in zip(block.fast_values, block.fast_mask) if is_present]
        if not present:
            return 0.0, 0.0
        return math.fsum(present) / len(present), len(present) / len(block.fast_values)

    def encode(self, blocks: Sequence[FeatureBlock], cutoff_ns: int) -> CausalTCNOutput:
        if not blocks:
            raise FeatureFrontendError("contract", "TCN requires at least one block")
        ordered = tuple(blocks)
        if any(item.timestamp_ns > cutoff_ns for item in ordered):
            raise FeatureFrontendError("future", "TCN received a block after its causal cutoff")
        if any(left.timestamp_ns >= right.timestamp_ns for left, right in zip(ordered, ordered[1:])):
            raise FeatureFrontendError("contract", "TCN blocks are not strictly time ordered")
        latest = ordered[-1].timestamp_ns
        selected = tuple(item for item in ordered if latest - item.timestamp_ns <= self.context_ns)
        timestamps = tuple(item.timestamp_ns for item in selected)
        deltas = tuple(0 if index == 0 else timestamps[index] - timestamps[index - 1] for index in range(len(timestamps)))
        summaries = tuple(self._summary(item) for item in selected)
        layer = [summary[0] for summary in summaries]
        for layer_index in range(2):
            next_layer: list[float] = []
            for index, current in enumerate(layer):
                total = current * (0.42 - 0.04 * layer_index) + 0.03 * (layer_index + 1)
                for lag in range(1, min(3, index + 1) + 1):
                    earlier = index - lag
                    age = timestamps[index] - timestamps[earlier]
                    if age > self.context_ns:
                        continue
                    decay = math.exp(-age / self.context_ns)
                    total += layer[earlier] * (0.19 / lag) * decay
                total += summaries[index][1] * 0.11
                total += (deltas[index] / 1_000_000_000.0) * (0.05 if layer_index == 0 else 0.03)
                next_layer.append(math.tanh(total))
            layer = next_layer
        masks = tuple(any(item.fast_mask) for item in selected)
        return CausalTCNOutput(
            source_key=selected[-1].source_key,
            cutoff_ns=cutoff_ns,
            timestamps_ns=timestamps,
            time_deltas_ns=deltas,
            masks=masks,
            embedding=(layer[-1], summaries[-1][0], summaries[-1][1], deltas[-1] / 1_000_000_000.0),
        )


@dataclass(frozen=True, slots=True)
class PathBranchOutput:
    """Qualified path candidates retained without class deletion or position claims."""

    paths: tuple[QualifiedPath, ...]
    class_counts: tuple[int, int, int, int]
    mean_coverage: float
    mean_uncertainty: float


class QualifiedPathEncoder:
    """Passes qualified angle-delay candidates into model features verbatim."""

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes for the configured qualified-path branch."""

        return _component_bytes(
            "qualified_path_encoder",
            {
                "algorithm_version": "qualified-path-encoder-v1",
                "path_classes": [path_class.value for path_class in PathClass],
            },
        )

    def digest(self) -> str:
        """Return the SHA-256 digest of the configured qualified-path branch bytes."""

        return _component_digest(self.canonical_bytes())

    def encode(self, paths: Iterable[QualifiedPath]) -> PathBranchOutput:
        ordered = tuple(paths)
        if any(not isinstance(item, QualifiedPath) for item in ordered):
            raise FeatureFrontendError("qualification", "path branch received a non-qualified path")
        counts = [0] * PATH_CLASSES
        order = tuple(PathClass)
        for item in ordered:
            counts[order.index(item.path_class)] += 1
        mean_coverage = math.fsum(item.coverage for item in ordered) / len(ordered) if ordered else 0.0
        mean_uncertainty = math.fsum(item.uncertainty for item in ordered) / len(ordered) if ordered else 0.0
        return PathBranchOutput(
            paths=ordered,
            class_counts=tuple(counts),  # type: ignore[arg-type]
            mean_coverage=mean_coverage,
            mean_uncertainty=mean_uncertainty,
        )


@dataclass(frozen=True, slots=True)
class ScatteringExample:
    """Supervised reflection-to-root/foot bias and noise training example."""

    features: tuple[float, ...]
    bias_target_m: tuple[float, float, float]
    noise_target_m: float
    provenance: str
    mask: bool = True

    def __post_init__(self) -> None:
        features = _floats(self.features, "scattering features")
        if len(features) > MAX_FEATURE_WIDTH:
            raise FeatureFrontendError("limit", "scattering feature width exceeds its limit")
        bias = _floats(self.bias_target_m, "scattering bias target")
        if len(bias) != 3:
            raise FeatureFrontendError("contract", "scattering bias target must have three coordinates")
        if isinstance(self.noise_target_m, bool) or not isinstance(self.noise_target_m, (int, float)):
            raise FeatureFrontendError("non_finite", "scattering noise target is not numeric")
        if not math.isfinite(float(self.noise_target_m)) or self.noise_target_m < 0.0:
            raise FeatureFrontendError("non_finite", "scattering noise target is invalid")
        _text(self.provenance, "scattering example provenance")
        if not isinstance(self.mask, bool):
            raise FeatureFrontendError("contract", "scattering example mask must be boolean")
        object.__setattr__(self, "features", features)
        object.__setattr__(self, "bias_target_m", (bias[0], bias[1], bias[2]))


@dataclass(frozen=True, slots=True)
class ScatteringEstimate:
    """Bounded bias/noise estimate with conservative propagated uncertainty."""

    source_key: str
    path_id: str
    bias_m: tuple[float, float, float]
    noise_m: float
    propagated_uncertainty_m: float


@dataclass(frozen=True, slots=True)
class SymmetricPairFeatures:
    """Order-independent two-person entrance for the supervised head."""

    sum_features: tuple[float, ...]
    absolute_difference: tuple[float, ...]


def _solve_linear(matrix: list[list[float]], target: list[float]) -> list[float]:
    """Solve a small regularized linear system with deterministic pivoting."""

    size = len(target)
    augmented = [row[:] + [target[index]] for index, row in enumerate(matrix)]
    for column in range(size):
        pivot = max(range(column, size), key=lambda row: abs(augmented[row][column]))
        if abs(augmented[pivot][column]) <= 1.0e-12:
            raise FeatureFrontendError("contract", "scattering training design is singular")
        if pivot != column:
            augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        scale = augmented[column][column]
        augmented[column] = [value / scale for value in augmented[column]]
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            if factor == 0.0:
                continue
            augmented[row] = [left - factor * right for left, right in zip(augmented[row], augmented[column])]
    return [augmented[index][-1] for index in range(size)]


@dataclass(frozen=True, slots=True)
class ScatteringBiasNoiseHead:
    """Tiny supervised linear head for reflection bias and observation noise."""

    bias_weights: tuple[tuple[float, ...], ...]
    noise_weights: tuple[float, ...]

    def __post_init__(self) -> None:
        bias = tuple(tuple(float(item) for item in row) for row in self.bias_weights)
        noise = tuple(float(item) for item in self.noise_weights)
        if len(bias) != 3 or not bias or len(noise) != len(bias[0]):
            raise FeatureFrontendError("contract", "scattering head weight shapes are invalid")
        if any(len(row) != len(noise) for row in bias):
            raise FeatureFrontendError("contract", "scattering head bias weights are ragged")
        if any(not math.isfinite(item) for row in bias for item in row) or any(not math.isfinite(item) for item in noise):
            raise FeatureFrontendError("non_finite", "scattering head weights are not finite")
        object.__setattr__(self, "bias_weights", bias)
        object.__setattr__(self, "noise_weights", noise)

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes for every fitted scattering-head parameter."""

        width = len(self.noise_weights)
        if len(self.bias_weights) != 3 or not self.bias_weights or any(
            len(row) != width for row in self.bias_weights
        ):
            raise FeatureFrontendError("contract", "scattering head weight shapes are invalid")
        return _component_bytes(
            "scattering_bias_noise_head",
            {
                "algorithm_version": "scattering-bias-noise-head-v1",
                "bias_shape": [len(self.bias_weights), width],
                "bias_weights_f64le_hex": [
                    _float64_sequence_hex(row, "scattering bias weights") for row in self.bias_weights
                ],
                "noise_shape": [width],
                "noise_weights_f64le_hex": _float64_sequence_hex(
                    self.noise_weights, "scattering noise weights"
                ),
            },
        )

    def digest(self) -> str:
        """Return the SHA-256 digest of the configured scattering-head bytes."""

        return _component_digest(self.canonical_bytes())

    @classmethod
    def default(cls, feature_width: int = 5) -> ScatteringBiasNoiseHead:
        """Returns a deterministic untrained fixture head; real fitting is separate."""

        if not 1 <= feature_width <= MAX_FEATURE_WIDTH:
            raise ValueError("feature_width is outside the supported bound")
        width = feature_width + 1
        return cls(
            bias_weights=tuple(tuple(0.0 for _ in range(width)) for _ in range(3)),
            noise_weights=tuple(0.0 for _ in range(width)),
        )

    @classmethod
    def fit(
        cls,
        examples: Iterable[ScatteringExample],
        *,
        ridge: float = 1.0e-6,
        max_samples: int = MAX_SCATTERING_SAMPLES,
    ) -> ScatteringBiasNoiseHead:
        """Fits the small supervised head with bounded deterministic ridge regression."""

        if isinstance(max_samples, bool) or not isinstance(max_samples, int) or max_samples <= 0:
            raise FeatureFrontendError("contract", "scattering sample limit must be a positive integer")
        iterator = iter(examples)
        collected: list[ScatteringExample] = []
        for _ in range(max_samples):
            try:
                collected.append(next(iterator))
            except StopIteration:
                break
        else:
            try:
                next(iterator)
            except StopIteration:
                pass
            else:
                raise FeatureFrontendError("limit", "scattering sample count exceeds its configured limit")

        examples = tuple(example for example in collected if example.mask)
        if not examples:
            raise FeatureFrontendError("contract", "scattering training requires a masked example")
        width = len(examples[0].features)
        if any(len(example.features) != width for example in examples):
            raise FeatureFrontendError("contract", "scattering examples have different feature widths")
        if isinstance(ridge, bool) or not isinstance(ridge, (int, float)) or not math.isfinite(float(ridge)) or ridge <= 0.0:
            raise FeatureFrontendError("contract", "scattering ridge must be finite and positive")
        design = [(1.0, *example.features) for example in examples]
        gram = [[0.0 for _ in range(width + 1)] for _ in range(width + 1)]
        for row in design:
            for left in range(width + 1):
                for right in range(width + 1):
                    gram[left][right] += row[left] * row[right]
        for index in range(1, width + 1):
            gram[index][index] += float(ridge)
        outputs: list[tuple[float, ...]] = []
        for coordinate in range(3):
            target = [
                math.fsum(row[index] * example.bias_target_m[coordinate] for row, example in zip(design, examples))
                for index in range(width + 1)
            ]
            outputs.append(tuple(_solve_linear(gram, target)))
        noise_target = [
            math.fsum(row[index] * example.noise_target_m for row, example in zip(design, examples))
            for index in range(width + 1)
        ]
        noise_weights = tuple(_solve_linear(gram, noise_target))
        return cls(bias_weights=tuple(outputs), noise_weights=noise_weights)

    @staticmethod
    def _design(features: Sequence[float]) -> tuple[float, ...]:
        values = _floats(features, "scattering input features")
        return (1.0, *values)

    def predict_features(
        self,
        features: Sequence[float],
        *,
        source_key: str,
        path_id: str,
        base_uncertainty_m: float = 0.0,
    ) -> ScatteringEstimate:
        """Predicts bounded bias/noise and carries path uncertainty through the head."""

        _text(source_key, "scattering source key")
        _text(path_id, "scattering path ID")
        design = self._design(features)
        if len(design) != len(self.noise_weights):
            raise FeatureFrontendError("contract", "scattering input width differs from head weights")
        bias = tuple(math.fsum(weight * value for weight, value in zip(row, design)) for row in self.bias_weights)
        noise = max(0.0, math.fsum(weight * value for weight, value in zip(self.noise_weights, design)))
        if isinstance(base_uncertainty_m, bool) or not isinstance(base_uncertainty_m, (int, float)) or base_uncertainty_m < 0.0 or not math.isfinite(float(base_uncertainty_m)):
            raise FeatureFrontendError("non_finite", "base scattering uncertainty is invalid")
        propagated = float(base_uncertainty_m) + noise + math.sqrt(math.fsum(item * item for item in bias))
        if any(not math.isfinite(item) for item in (*bias, noise, propagated)):
            raise FeatureFrontendError("non_finite", "scattering head returned a non-finite estimate")
        return ScatteringEstimate(
            source_key=source_key,
            path_id=path_id,
            bias_m=(bias[0], bias[1], bias[2]),
            noise_m=noise,
            propagated_uncertainty_m=propagated,
        )

    def predict(self, example: ScatteringExample, *, source_key: str, path_id: str) -> ScatteringEstimate:
        """Predicts from one supervised example while retaining its feature contract."""

        return self.predict_features(example.features, source_key=source_key, path_id=path_id)

    @staticmethod
    def pair_features(first: Sequence[float], second: Sequence[float]) -> SymmetricPairFeatures:
        """Builds order-independent sum and absolute-difference features for two people."""

        left = _floats(first, "first pair features")
        right = _floats(second, "second pair features")
        if len(left) != len(right):
            raise FeatureFrontendError("contract", "pair feature widths differ")
        return SymmetricPairFeatures(
            sum_features=tuple(a + b for a, b in zip(left, right)),
            absolute_difference=tuple(abs(a - b) for a, b in zip(left, right)),
        )


@dataclass(frozen=True, slots=True)
class SourceEmbedding:
    """One source-specific embedding and feature mask supplied to attention."""

    source_key: str
    values: tuple[float, ...]
    mask: tuple[bool, ...]

    def __post_init__(self) -> None:
        _text(self.source_key, "source embedding key")
        values = _floats(self.values, "source embedding values")
        masks = _mask(self.mask, "source embedding mask", len(values))
        object.__setattr__(self, "values", values)
        object.__setattr__(self, "mask", masks)


@dataclass(frozen=True, slots=True)
class AttentionCell:
    """One map-cell cross-source fused value and normalized source weights."""

    cell_id: str
    fused: tuple[float, ...]
    weights: tuple[tuple[str, float], ...]
    mask: bool
    source_count: int


class CrossSourceAttention:
    """Deterministic map-query attention over qualified source embeddings."""

    def __init__(self, temperature: float = 1.0, max_sources: int = 16):
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)) or not math.isfinite(float(temperature)) or temperature <= 0.0:
            raise ValueError("temperature must be finite and positive")
        if isinstance(max_sources, bool) or not isinstance(max_sources, int) or max_sources <= 0:
            raise ValueError("max_sources must be positive")
        self.temperature = float(temperature)
        self.max_sources = max_sources

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes for the configured cross-source attention branch."""

        if not math.isfinite(self.temperature) or self.temperature <= 0.0:
            raise FeatureFrontendError("contract", "attention temperature is outside its supported bound")
        if isinstance(self.max_sources, bool) or not isinstance(self.max_sources, int) or self.max_sources <= 0:
            raise FeatureFrontendError("contract", "attention source limit is outside its supported bound")
        return _component_bytes(
            "cross_source_attention",
            {
                "algorithm_version": "cross-source-attention-v1",
                "temperature_f64le_hex": _float64_hex(self.temperature, "attention temperature"),
                "max_sources": self.max_sources,
            },
        )

    def digest(self) -> str:
        """Return the SHA-256 digest of the configured attention branch bytes."""

        return _component_digest(self.canonical_bytes())

    @staticmethod
    def _score(position: Sequence[float], values: Sequence[float], masks: Sequence[bool]) -> float:
        coefficients = (position[0], position[1], position[2], 1.0)
        return math.fsum(
            value * coefficients[index % len(coefficients)] if masks[index] else 0.0
            for index, value in enumerate(values)
        )

    def fuse(self, grid: MapGrid, embeddings: Iterable[SourceEmbedding]) -> tuple[AttentionCell, ...]:
        """Fuses each explicit cell from all available sources exactly once."""

        if not isinstance(grid, MapGrid):
            raise FeatureFrontendError("contract", "attention map is invalid")
        ordered = tuple(sorted(embeddings, key=lambda item: item.source_key))
        if len(ordered) > self.max_sources:
            raise FeatureFrontendError("limit", "attention source count exceeds its configured limit")
        if len({item.source_key for item in ordered}) != len(ordered):
            raise FeatureFrontendError("contract", "attention received duplicate source embeddings")
        width = len(ordered[0].values) if ordered else 1
        if any(len(item.values) != width for item in ordered):
            raise FeatureFrontendError("contract", "attention source embedding widths differ")
        output: list[AttentionCell] = []
        for cell in grid.cells:
            if not cell.valid or not ordered:
                output.append(AttentionCell(cell.cell_id, tuple(0.0 for _ in range(width)), (), False, 0))
                continue
            available = tuple(item for item in ordered if any(item.mask))
            if not available:
                output.append(AttentionCell(cell.cell_id, tuple(0.0 for _ in range(width)), (), False, 0))
                continue
            scores = tuple(self._score(cell.position_m, item.values, item.mask) / self.temperature for item in available)
            maximum = max(scores)
            exponents = tuple(math.exp(max(-60.0, min(60.0, score - maximum))) for score in scores)
            denominator = math.fsum(exponents)
            weights = tuple(exponent / denominator for exponent in exponents)
            fused = tuple(
                math.fsum(
                    weight * item.values[index] if item.mask[index] else 0.0
                    for weight, item in zip(weights, available)
                )
                for index in range(width)
            )
            output.append(
                AttentionCell(
                    cell_id=cell.cell_id,
                    fused=fused,
                    weights=tuple((item.source_key, weight) for item, weight in zip(available, weights)),
                    mask=True,
                    source_count=len(available),
                )
            )
        return tuple(output)


@dataclass(frozen=True, slots=True)
class FeatureMaterialization:
    """Complete deterministic frontend output and its tensor identity."""

    manifest_digest: str
    tensor_digest: str
    tensor_bytes: bytes
    feature_shape: tuple[int, ...]
    values: tuple[float, ...]
    slow_outputs: tuple[SlowMLPOutput, ...]
    tcn_outputs: tuple[CausalTCNOutput, ...]
    path_output: PathBranchOutput
    scattering: tuple[ScatteringEstimate, ...]
    attention: tuple[AttentionCell, ...]


class FeatureFrontend:
    """Runs slow, causal, qualified-path, supervised, and map-query branches."""

    def __init__(
        self,
        limits: FeatureLimits | None = None,
        *,
        slow_mlp: SlowMLP | None = None,
        causal_tcn: CausalTCN | None = None,
        path_encoder: QualifiedPathEncoder | None = None,
        scattering_head: ScatteringBiasNoiseHead | None = None,
        attention: CrossSourceAttention | None = None,
    ):
        self.limits = limits or FeatureLimits()
        self.slow_mlp = slow_mlp or SlowMLP()
        self.causal_tcn = causal_tcn or CausalTCN()
        self.path_encoder = path_encoder or QualifiedPathEncoder()
        self.scattering_head = scattering_head or ScatteringBiasNoiseHead.default(5)
        self.attention = attention or CrossSourceAttention(max_sources=self.limits.max_sources)

    def weights_canonical_bytes(self) -> bytes:
        """Return canonical bytes binding every configured numerical component."""

        configured = (
            ("slow_mlp", self.slow_mlp.canonical_bytes()),
            ("causal_tcn", self.causal_tcn.canonical_bytes()),
            ("qualified_path_encoder", self.path_encoder.canonical_bytes()),
            ("scattering_bias_noise_head", self.scattering_head.canonical_bytes()),
            ("cross_source_attention", self.attention.canonical_bytes()),
        )
        return _canonical_json(
            {
                "schema": WEIGHTS_SCHEMA,
                "frontend_version": FRONTEND_VERSION,
                "components": [
                    {
                        "name": name,
                        "encoding_hex": encoded.hex(),
                        "encoding_digest": _component_digest(encoded),
                    }
                    for name, encoded in configured
                ],
            }
        )

    def weights_digest(self) -> str:
        """Return the SHA-256 digest bound into a matching feature manifest."""

        return hashlib.sha256(self.weights_canonical_bytes()).hexdigest()

    @staticmethod
    def _source_embedding(
        source_key: str,
        slow: SlowMLPOutput,
        tcn: CausalTCNOutput,
        paths: Sequence[QualifiedPath],
    ) -> SourceEmbedding:
        order = tuple(PathClass)
        counts = tuple(sum(item.path_class == path_class for item in paths) for path_class in order)
        values = (
            *slow.embedding,
            slow.absolute_level,
            tcn.embedding[0],
            tcn.embedding[1],
            tcn.embedding[2],
            tcn.embedding[3],
            *(float(count) for count in counts),
            *(
                math.fsum(item.coverage for item in paths) / len(paths) if paths else 0.0,
                math.fsum(item.uncertainty for item in paths) / len(paths) if paths else 0.0,
            ),
        )
        slow_valid = bool(slow.absolute_mask or slow.spectrum_mask or slow.residual_mask) and any(
            (*slow.absolute_mask, *slow.spectrum_mask, *slow.residual_mask)
        )
        tcn_valid = any(tcn.masks)
        masks = (
            (slow_valid,) * len(slow.embedding)
            + (any(slow.absolute_mask),)
            + (tcn_valid,) * 4
            + (bool(paths),) * len(counts)
            + (bool(paths), bool(paths))
        )
        return SourceEmbedding(source_key=source_key, values=values, mask=masks)

    def materialize(self, manifest: FeatureManifest) -> FeatureMaterialization:
        """Materializes one manifest without consulting future or mutable state."""

        if not isinstance(manifest, FeatureManifest):
            raise FeatureFrontendError("contract", "frontend input is not a feature manifest")
        if manifest.weights_digest != self.weights_digest():
            raise FeatureFrontendError("digest", "manifest weights digest differs from the configured frontend")
        manifest.validate(self.limits)
        if self.causal_tcn.context_ns != manifest.causal_context_ns:
            raise FeatureFrontendError("contract", "manifest causal context differs from the configured TCN")
        by_source: dict[str, list[FeatureBlock]] = {item.source_key: [] for item in manifest.source_provenance}
        for item in manifest.blocks:
            by_source[item.source_key].append(item)
        slow_outputs: list[SlowMLPOutput] = []
        tcn_outputs: list[CausalTCNOutput] = []
        path_by_source: dict[str, tuple[QualifiedPath, ...]] = {
            key: tuple(item for item in manifest.paths if item.source_key == key)
            for key in by_source
        }
        source_embeddings: list[SourceEmbedding] = []
        for source_key in sorted(by_source):
            blocks = tuple(sorted(by_source[source_key], key=lambda item: item.timestamp_ns))
            slow = self.slow_mlp.encode(blocks[-1])
            tcn = self.causal_tcn.encode(blocks, manifest.cutoff_ns)
            slow_outputs.append(slow)
            tcn_outputs.append(tcn)
            source_embeddings.append(self._source_embedding(source_key, slow, tcn, path_by_source[source_key]))

        path_output = self.path_encoder.encode(manifest.paths)
        scattering = tuple(
            self.scattering_head.predict_features(
                (
                    item.normalized_power,
                    item.delay_seconds,
                    item.angle_radians,
                    item.uncertainty,
                    item.coverage,
                ),
                source_key=item.source_key,
                path_id=item.path_id,
                base_uncertainty_m=item.uncertainty,
            )
            for item in path_output.paths
        )
        attention = self.attention.fuse(manifest.map_grid, source_embeddings)

        values: list[float] = []
        for slow, tcn in zip(slow_outputs, tcn_outputs):
            values.extend(slow.embedding)
            values.extend((slow.absolute_level, float(sum(slow.absolute_mask)) / len(slow.absolute_mask)))
            values.extend(tcn.embedding)
            values.extend(float(mask) for mask in tcn.masks)
        for item in path_output.paths:
            values.extend((item.angle_radians, item.delay_seconds, item.normalized_power, item.uncertainty, item.coverage))
            values.extend(float(item.path_class == path_class) for path_class in PathClass)
        for estimate in scattering:
            values.extend((*estimate.bias_m, estimate.noise_m, estimate.propagated_uncertainty_m))
        for cell in attention:
            values.extend(cell.fused)
            values.extend(weight for _, weight in cell.weights)
            values.append(float(cell.mask))
        if any(not math.isfinite(value) for value in values):
            raise FeatureFrontendError("non_finite", "feature materialization produced NaN or Inf")
        try:
            tensor_bytes = struct.pack(f"<{len(values)}f", *values)
        except (OverflowError, struct.error) as error:
            raise FeatureFrontendError("limit", "feature tensor shape or byte count is invalid") from error
        if len(tensor_bytes) > self.limits.max_tensor_bytes:
            raise FeatureFrontendError("limit", "feature tensor exceeds its configured byte limit")
        return FeatureMaterialization(
            manifest_digest=manifest.digest(),
            tensor_digest=hashlib.sha256(tensor_bytes).hexdigest(),
            tensor_bytes=tensor_bytes,
            feature_shape=(len(values),),
            values=tuple(values),
            slow_outputs=tuple(slow_outputs),
            tcn_outputs=tuple(tcn_outputs),
            path_output=path_output,
            scattering=scattering,
            attention=attention,
        )


class FeatureFrontendOperator:
    """Adapter exposing manifest materialization through the bounded worker seam."""

    def __init__(self, frontend: FeatureFrontend | None = None):
        self.frontend = frontend or FeatureFrontend()

    def evaluate(self, request: Mapping[str, object]) -> tuple[bytes, tuple[int, ...], bytes]:
        """Reads only frozen manifest bytes and returns tensor plus successor material."""

        try:
            manifest_hex = request["input_manifest"]["manifest_hex"]  # type: ignore[index]
            if not isinstance(manifest_hex, str) or len(manifest_hex) % 2 or any(
                character not in "0123456789abcdef" for character in manifest_hex
            ):
                raise FeatureFrontendError("contract", "manifest bytes are not canonical lowercase hex")
            manifest = FeatureManifest.from_bytes(bytes.fromhex(manifest_hex), self.frontend.limits)
            result = self.frontend.materialize(manifest)
        except FeatureFrontendError as error:
            try:
                from .worker import ContractFailure

                status = {
                    "limit": "limit_exceeded",
                    "non_finite": "non_finite",
                    "qualification": "contract_mismatch",
                    "future": "contract_mismatch",
                    "digest": "digest_mismatch",
                }.get(error.reason, "malformed_request")
                raise ContractFailure(status, str(error)) from error
            except ImportError:
                raise
        successor = hashlib.sha256(
            b"feature-frontend-successor-v1"
            + bytes.fromhex(result.manifest_digest)
            + result.tensor_bytes
        ).digest()
        return result.tensor_bytes, result.feature_shape, successor


__all__ = [
    "AttentionCell",
    "CausalTCN",
    "CausalTCNOutput",
    "COMPONENT_SCHEMA",
    "CrossSourceAttention",
    "FeatureBlock",
    "FeatureFrontend",
    "FeatureFrontendError",
    "FeatureFrontendOperator",
    "FeatureLimits",
    "FeatureManifest",
    "FeatureMaterialization",
    "FRONTEND_VERSION",
    "MANIFEST_SCHEMA",
    "MAX_SCATTERING_SAMPLES",
    "MapCell",
    "MapGrid",
    "PathBranchOutput",
    "PathClass",
    "PREPROCESSING_VERSION",
    "QualifiedPath",
    "QualifiedPathEncoder",
    "ScatteringBiasNoiseHead",
    "ScatteringEstimate",
    "ScatteringExample",
    "SlowMLP",
    "SlowMLPOutput",
    "SourceEmbedding",
    "SourceProvenance",
    "SymmetricPairFeatures",
    "WEIGHTS_SCHEMA",
]
