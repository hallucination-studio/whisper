//! Bounded local protocol between the Rust coordinator and numerical worker.

use std::backtrace::Backtrace;
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 4] = b"WMW1";
const PROTOCOL_VERSION: u16 = 1;
const ARTIFACT_SCHEMA_VERSION: u16 = 1;
const MAX_TEXT_BYTES: usize = 128;

/// SHA-256 digest used for immutable worker inputs and outputs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Computes a digest over the exact supplied bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    fn as_hex(self) -> String {
        let mut result = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            write!(result, "{byte:02x}").expect("writing to String cannot fail");
        }
        result
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ContentDigest").field(&self.as_hex()).finish()
    }
}

impl Serialize for ContentDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64 {
            return Err(serde::de::Error::custom("digest must contain 64 hex characters"));
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(pair).map_err(serde::de::Error::custom)?;
            bytes[index] = u8::from_str_radix(text, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(Self(bytes))
    }
}

macro_rules! text_id {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Validated ", $label, " carried by the worker protocol.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Returns the validated identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ModelWorkerError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                validate_text(value, $label)?;
                Ok(Self(value.to_owned()))
            }
        }
    };
}

text_id!(ModelRunId, "model run ID");
text_id!(ModelRequestId, "model request ID");

/// Fixed resource ceilings for request, response, tensor, and queue material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerLimits {
    /// Maximum complete frame bytes, including the eight-byte header.
    pub max_frame_bytes: usize,
    /// Maximum canonical input-manifest bytes.
    pub max_manifest_bytes: usize,
    /// Maximum model-weight bytes carried by the bounded fixture protocol.
    pub max_weights_bytes: usize,
    /// Maximum materialized input-tensor bytes.
    pub max_tensor_bytes: usize,
    /// Maximum candidate-result bytes.
    pub max_result_bytes: usize,
    /// Maximum predecessor or successor checkpoint bytes.
    pub max_checkpoint_bytes: usize,
    /// Maximum tensor rank.
    pub max_shape_dimensions: usize,
    /// Maximum size of one tensor dimension.
    pub max_dimension: u32,
    /// Maximum tensor element count.
    pub max_elements: usize,
    /// Maximum immutable source references in one manifest.
    pub max_sources: u32,
    /// Maximum raw clock domains in one manifest.
    pub max_clock_domains: u32,
    /// Maximum serialized bytes retained for the latest pending context.
    pub max_pending_context_bytes: usize,
}

impl Default for WorkerLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1_048_576,
            max_manifest_bytes: 131_072,
            max_weights_bytes: 262_144,
            max_tensor_bytes: 524_288,
            max_result_bytes: 524_288,
            max_checkpoint_bytes: 131_072,
            max_shape_dimensions: 8,
            max_dimension: 65_536,
            max_elements: 131_072,
            max_sources: 64,
            max_clock_domains: 64,
            max_pending_context_bytes: 1_048_576,
        }
    }
}

/// Explicit numerical execution class; CPU execution is never an implicit fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    /// Production execution that requires an available GPU.
    ProductionGpu,
    /// Explicit comparison or degraded CPU baseline.
    CpuBaseline,
}

/// Reproducibility and numeric-tolerance declaration for one model run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NumericContract {
    #[serde(rename = "class")]
    execution_class: ExecutionClass,
    deterministic_algorithms: bool,
    absolute_tolerance: f32,
    relative_tolerance: f32,
    environment: String,
}

impl NumericContract {
    /// Creates an explicit numerical contract.
    pub fn new(
        execution_class: ExecutionClass,
        deterministic_algorithms: bool,
        absolute_tolerance: f32,
        relative_tolerance: f32,
        environment: String,
    ) -> Result<Self, ModelWorkerError> {
        let value = Self {
            execution_class,
            deterministic_algorithms,
            absolute_tolerance,
            relative_tolerance,
            environment,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ModelWorkerError> {
        validate_text(&self.environment, "numeric environment")?;
        if !self.absolute_tolerance.is_finite()
            || self.absolute_tolerance < 0.0
            || !self.relative_tolerance.is_finite()
            || self.relative_tolerance < 0.0
        {
            return Err(ModelWorkerError::invalid(
                "numeric tolerances must be finite and non-negative",
            ));
        }
        Ok(())
    }
}

/// Immutable model and interpretation selected for one run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelRun {
    schema_version: u16,
    run_id: ModelRunId,
    weights_digest: ContentDigest,
    #[serde(with = "hex_bytes")]
    weights_hex: Vec<u8>,
    algorithm: String,
    preprocessing: String,
    normalization: String,
    input_semantics: String,
    output_semantics: String,
    label_semantics: String,
    calibration_policy: String,
    tolerance_policy: String,
    fusion_policy: String,
    state_format: String,
    max_shape: Vec<u32>,
    output_shape: Vec<u32>,
    execution: NumericContract,
}

impl ModelRun {
    /// Starts a builder with immutable identity, weights, shape, and numeric policy.
    #[must_use]
    pub fn builder(
        run_id: ModelRunId,
        weights: Vec<u8>,
        max_shape: Vec<u32>,
        execution: NumericContract,
    ) -> ModelRunBuilder {
        ModelRunBuilder {
            run_id,
            weights,
            max_shape,
            execution,
            algorithm: None,
            preprocessing: None,
            normalization: None,
            input_semantics: None,
            output_semantics: None,
            label_semantics: None,
            calibration_policy: None,
            tolerance_policy: None,
            fusion_policy: None,
            state_format: None,
            output_shape: None,
        }
    }
}

/// Builder for the versioned model-run contract.
#[derive(Debug)]
pub struct ModelRunBuilder {
    run_id: ModelRunId,
    weights: Vec<u8>,
    max_shape: Vec<u32>,
    execution: NumericContract,
    algorithm: Option<String>,
    preprocessing: Option<String>,
    normalization: Option<String>,
    input_semantics: Option<String>,
    output_semantics: Option<String>,
    label_semantics: Option<String>,
    calibration_policy: Option<String>,
    tolerance_policy: Option<String>,
    fusion_policy: Option<String>,
    state_format: Option<String>,
    output_shape: Option<Vec<u32>>,
}

macro_rules! builder_text {
    ($name:ident) => {
        #[doc = concat!("Sets the ", stringify!($name), " identity.")]
        #[must_use]
        pub fn $name(mut self, value: impl Into<String>) -> Self {
            self.$name = Some(value.into());
            self
        }
    };
}

impl ModelRunBuilder {
    builder_text!(algorithm);
    builder_text!(preprocessing);
    builder_text!(normalization);
    builder_text!(input_semantics);
    builder_text!(output_semantics);
    builder_text!(label_semantics);
    builder_text!(calibration_policy);
    builder_text!(tolerance_policy);
    builder_text!(fusion_policy);
    builder_text!(state_format);

    /// Sets the exact packed-float32 candidate shape expected from this run.
    #[must_use]
    pub fn output_shape(mut self, value: Vec<u32>) -> Self {
        self.output_shape = Some(value);
        self
    }

    /// Validates and returns the immutable run description.
    pub fn build(self) -> Result<ModelRun, ModelWorkerError> {
        let required = |value: Option<String>, field| {
            let value =
                value.ok_or_else(|| ModelWorkerError::invalid(format!("missing {field}")))?;
            validate_text(&value, field)?;
            Ok(value)
        };
        Ok(ModelRun {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            run_id: self.run_id,
            weights_digest: ContentDigest::of(&self.weights),
            weights_hex: self.weights,
            algorithm: required(self.algorithm, "algorithm")?,
            preprocessing: required(self.preprocessing, "preprocessing")?,
            normalization: required(self.normalization, "normalization")?,
            input_semantics: required(self.input_semantics, "input semantics")?,
            output_semantics: required(self.output_semantics, "output semantics")?,
            label_semantics: required(self.label_semantics, "label semantics")?,
            calibration_policy: required(self.calibration_policy, "calibration policy")?,
            tolerance_policy: required(self.tolerance_policy, "tolerance policy")?,
            fusion_policy: required(self.fusion_policy, "fusion policy")?,
            state_format: required(self.state_format, "state format")?,
            max_shape: self.max_shape,
            output_shape: self
                .output_shape
                .ok_or_else(|| ModelWorkerError::invalid("missing output shape"))?,
            execution: self.execution,
        })
    }
}

/// Frozen manifest binding and its canonical materialized tensor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InputManifest {
    schema_version: u16,
    manifest_digest: ContentDigest,
    #[serde(with = "hex_bytes")]
    manifest_hex: Vec<u8>,
    run_id: ModelRunId,
    epoch: u64,
    cutoff_ns: u64,
    predecessor_digest: ContentDigest,
    preprocessing: String,
    input_semantics: String,
    shape: Vec<u32>,
    tensor_digest: ContentDigest,
    #[serde(with = "hex_bytes")]
    tensor_hex: Vec<u8>,
    source_count: u32,
    clock_domain_count: u32,
}

impl InputManifest {
    /// Starts a builder with the immutable manifest and causal identity binding.
    #[must_use]
    pub fn builder(
        manifest: Vec<u8>,
        run_id: ModelRunId,
        epoch: u64,
        cutoff_ns: u64,
        predecessor_digest: ContentDigest,
    ) -> InputManifestBuilder {
        InputManifestBuilder {
            manifest,
            run_id,
            epoch,
            cutoff_ns,
            predecessor_digest,
            preprocessing: None,
            input_semantics: None,
            shape: None,
            tensor: None,
            source_count: None,
            clock_domain_count: None,
        }
    }
}

/// Builder that names every semantically distinct manifest field.
#[derive(Debug)]
pub struct InputManifestBuilder {
    manifest: Vec<u8>,
    run_id: ModelRunId,
    epoch: u64,
    cutoff_ns: u64,
    predecessor_digest: ContentDigest,
    preprocessing: Option<String>,
    input_semantics: Option<String>,
    shape: Option<Vec<u32>>,
    tensor: Option<Vec<u8>>,
    source_count: Option<u32>,
    clock_domain_count: Option<u32>,
}

impl InputManifestBuilder {
    /// Sets the preprocessing identity bound by the manifest.
    #[must_use]
    pub fn preprocessing(mut self, value: impl Into<String>) -> Self {
        self.preprocessing = Some(value.into());
        self
    }

    /// Sets the input semantics identity bound by the manifest.
    #[must_use]
    pub fn input_semantics(mut self, value: impl Into<String>) -> Self {
        self.input_semantics = Some(value.into());
        self
    }

    /// Sets the materialized tensor shape.
    #[must_use]
    pub fn shape(mut self, value: Vec<u32>) -> Self {
        self.shape = Some(value);
        self
    }

    /// Sets the exact canonical packed tensor bytes.
    #[must_use]
    pub fn tensor(mut self, value: Vec<u8>) -> Self {
        self.tensor = Some(value);
        self
    }

    /// Sets the number of frozen source references.
    #[must_use]
    pub fn source_count(mut self, value: u32) -> Self {
        self.source_count = Some(value);
        self
    }

    /// Sets the number of independently frozen raw clock domains.
    #[must_use]
    pub fn clock_domain_count(mut self, value: u32) -> Self {
        self.clock_domain_count = Some(value);
        self
    }

    /// Validates required semantic fields and builds the immutable binding.
    pub fn build(self) -> Result<InputManifest, ModelWorkerError> {
        let preprocessing = self
            .preprocessing
            .ok_or_else(|| ModelWorkerError::invalid("missing manifest preprocessing"))?;
        let input_semantics = self
            .input_semantics
            .ok_or_else(|| ModelWorkerError::invalid("missing manifest input semantics"))?;
        validate_text(&preprocessing, "manifest preprocessing")?;
        validate_text(&input_semantics, "manifest input semantics")?;
        let shape = self.shape.ok_or_else(|| ModelWorkerError::invalid("missing tensor shape"))?;
        if shape.is_empty() || shape.contains(&0) {
            return Err(ModelWorkerError::invalid("tensor shape dimensions must be non-zero"));
        }
        let tensor =
            self.tensor.ok_or_else(|| ModelWorkerError::invalid("missing tensor bytes"))?;
        Ok(InputManifest {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            manifest_digest: ContentDigest::of(&self.manifest),
            manifest_hex: self.manifest,
            run_id: self.run_id,
            epoch: self.epoch,
            cutoff_ns: self.cutoff_ns,
            predecessor_digest: self.predecessor_digest,
            preprocessing,
            input_semantics,
            shape,
            tensor_digest: ContentDigest::of(&tensor),
            tensor_hex: tensor,
            source_count: self
                .source_count
                .ok_or_else(|| ModelWorkerError::invalid("missing source count"))?,
            clock_domain_count: self
                .clock_domain_count
                .ok_or_else(|| ModelWorkerError::invalid("missing clock-domain count"))?,
        })
    }
}

/// Bounded predecessor material supplied explicitly with every request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    run_id: ModelRunId,
    epoch: u64,
    digest: ContentDigest,
    #[serde(rename = "bytes_hex", with = "hex_bytes")]
    bytes: Vec<u8>,
}

impl Checkpoint {
    /// Creates a checkpoint binding and computes its digest.
    #[must_use]
    pub fn new(run_id: ModelRunId, epoch: u64, bytes: Vec<u8>) -> Self {
        Self { run_id, epoch, digest: ContentDigest::of(&bytes), bytes }
    }

    /// Returns the exact checkpoint digest.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Identity shared by a request, response, and eventual coordinator decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestIdentity {
    run_id: ModelRunId,
    epoch: u64,
    request_id: ModelRequestId,
    cutoff_ns: u64,
    predecessor_digest: ContentDigest,
}

impl RequestIdentity {
    /// Creates a fully bound model-request identity.
    #[must_use]
    pub fn new(
        run_id: ModelRunId,
        epoch: u64,
        request_id: ModelRequestId,
        cutoff_ns: u64,
        predecessor_digest: ContentDigest,
    ) -> Self {
        Self { run_id, epoch, request_id, cutoff_ns, predecessor_digest }
    }

    /// Returns the request identifier.
    #[must_use]
    pub fn request_id(&self) -> &ModelRequestId {
        &self.request_id
    }
}

/// Complete immutable calculation request sent to the local worker.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelRequest {
    protocol_version: u16,
    identity: RequestIdentity,
    deadline_monotonic_ns: u64,
    model_run: ModelRun,
    input_manifest: InputManifest,
    checkpoint: Checkpoint,
}

impl ModelRequest {
    /// Creates a request whose cross-field bindings are checked before encoding.
    #[must_use]
    pub fn new(
        identity: RequestIdentity,
        deadline_monotonic_ns: u64,
        model_run: ModelRun,
        input_manifest: InputManifest,
        checkpoint: Checkpoint,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            identity,
            deadline_monotonic_ns,
            model_run,
            input_manifest,
            checkpoint,
        }
    }

    /// Returns the request identity.
    #[must_use]
    pub fn identity(&self) -> &RequestIdentity {
        &self.identity
    }

    /// Encodes and validates one bounded request frame.
    pub fn encode(&self, limits: &WorkerLimits) -> Result<Vec<u8>, ModelWorkerError> {
        self.validate(limits)?;
        encode_json(self, limits)
    }

    /// Decodes and validates one complete bounded request frame.
    pub fn decode(frame: &[u8], limits: &WorkerLimits) -> Result<Self, ModelWorkerError> {
        let value: Self = decode_json(frame, limits)?;
        value.validate(limits)?;
        Ok(value)
    }

    fn validate(&self, limits: &WorkerLimits) -> Result<(), ModelWorkerError> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.model_run.schema_version != ARTIFACT_SCHEMA_VERSION
            || self.input_manifest.schema_version != ARTIFACT_SCHEMA_VERSION
        {
            return Err(ModelWorkerError::invalid("unsupported request or artifact version"));
        }
        for (value, field) in [
            (&self.identity.run_id.0, "identity run ID"),
            (&self.identity.request_id.0, "request ID"),
            (&self.model_run.run_id.0, "model run ID"),
            (&self.input_manifest.run_id.0, "manifest run ID"),
            (&self.checkpoint.run_id.0, "checkpoint run ID"),
        ] {
            validate_text(value, field)?;
        }
        for (value, field) in [
            (&self.model_run.algorithm, "algorithm"),
            (&self.model_run.preprocessing, "preprocessing"),
            (&self.model_run.normalization, "normalization"),
            (&self.model_run.input_semantics, "input semantics"),
            (&self.model_run.output_semantics, "output semantics"),
            (&self.model_run.label_semantics, "label semantics"),
            (&self.model_run.calibration_policy, "calibration policy"),
            (&self.model_run.tolerance_policy, "tolerance policy"),
            (&self.model_run.fusion_policy, "fusion policy"),
            (&self.model_run.state_format, "state format"),
            (&self.input_manifest.preprocessing, "manifest preprocessing"),
            (&self.input_manifest.input_semantics, "manifest input semantics"),
        ] {
            validate_text(value, field)?;
        }
        self.model_run.execution.validate()?;
        if self.identity.run_id != self.model_run.run_id
            || self.identity.run_id != self.input_manifest.run_id
            || self.identity.run_id != self.checkpoint.run_id
        {
            return Err(ModelWorkerError::invalid("run identity differs across request"));
        }
        if self.identity.epoch != self.input_manifest.epoch
            || self.identity.epoch != self.checkpoint.epoch
        {
            return Err(ModelWorkerError::invalid("epoch differs across request"));
        }
        if self.identity.cutoff_ns != self.input_manifest.cutoff_ns
            || self.identity.predecessor_digest != self.input_manifest.predecessor_digest
            || self.identity.predecessor_digest != self.checkpoint.digest
        {
            return Err(ModelWorkerError::invalid("cutoff or predecessor differs across request"));
        }
        if self.model_run.weights_digest != ContentDigest::of(&self.model_run.weights_hex)
            || self.input_manifest.manifest_digest
                != ContentDigest::of(&self.input_manifest.manifest_hex)
            || self.input_manifest.tensor_digest
                != ContentDigest::of(&self.input_manifest.tensor_hex)
            || self.checkpoint.digest != ContentDigest::of(&self.checkpoint.bytes)
        {
            return Err(ModelWorkerError::invalid("content digest mismatch"));
        }
        if self.input_manifest.preprocessing != self.model_run.preprocessing
            || self.input_manifest.input_semantics != self.model_run.input_semantics
        {
            return Err(ModelWorkerError::invalid("model and manifest semantics differ"));
        }
        check_limit(self.input_manifest.manifest_hex.len(), limits.max_manifest_bytes, "manifest")?;
        check_limit(self.model_run.weights_hex.len(), limits.max_weights_bytes, "weights")?;
        check_limit(self.input_manifest.tensor_hex.len(), limits.max_tensor_bytes, "tensor")?;
        check_limit(self.checkpoint.bytes.len(), limits.max_checkpoint_bytes, "checkpoint")?;
        if self.input_manifest.source_count > limits.max_sources
            || self.input_manifest.clock_domain_count > limits.max_clock_domains
        {
            return Err(ModelWorkerError::invalid("manifest reference count exceeds limit"));
        }
        validate_shape(
            &self.input_manifest.shape,
            &self.model_run.max_shape,
            self.input_manifest.tensor_hex.len(),
            limits,
        )?;
        validate_shape_dimensions(&self.model_run.output_shape, limits).map(|_| ())
    }
}

/// Bounded result status returned by the numerical worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    /// Candidate and successor material passed worker validation.
    Success,
    /// Worker protocol or artifact schema is unsupported.
    UnsupportedVersion,
    /// Request fields are malformed.
    MalformedRequest,
    /// Immutable model and manifest contracts disagree.
    ContractMismatch,
    /// A content digest does not match its exact bytes.
    DigestMismatch,
    /// Tensor or result shape is invalid.
    InvalidShape,
    /// A configured count or byte ceiling was exceeded.
    LimitExceeded,
    /// Request deadline elapsed before execution.
    DeadlineExceeded,
    /// Continuity epoch bindings disagree.
    EpochMismatch,
    /// Numerical input or result contains NaN or infinity.
    NonFinite,
    /// GPU allocation failed.
    GpuOom,
    /// Explicitly requested numerical backend is unavailable.
    BackendUnavailable,
    /// Request ID was reused with different request bytes.
    RequestConflict,
    /// Numerical operator raised an isolated, non-resource-specific failure.
    OperatorFailure,
}

/// Candidate result returned for coordinator validation; it has no publish authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelResponse {
    protocol_version: u16,
    identity: RequestIdentity,
    status: ResponseStatus,
    detail: String,
    #[serde(with = "hex_bytes")]
    candidate_hex: Vec<u8>,
    #[serde(with = "hex_bytes")]
    successor_hex: Vec<u8>,
    #[serde(default, with = "optional_digest")]
    input_tensor_digest: Option<ContentDigest>,
    #[serde(default, with = "optional_digest")]
    output_numeric_digest: Option<ContentDigest>,
    #[serde(default, with = "optional_digest")]
    return_payload_digest: Option<ContentDigest>,
    numeric_qualification: Option<NumericContract>,
}

impl ModelResponse {
    /// Creates an authority-free bounded failure response.
    #[must_use]
    pub fn failure(
        identity: RequestIdentity,
        status: ResponseStatus,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            identity,
            status,
            detail: detail.into(),
            candidate_hex: Vec::new(),
            successor_hex: Vec::new(),
            input_tensor_digest: None,
            output_numeric_digest: None,
            return_payload_digest: None,
            numeric_qualification: None,
        }
    }

    /// Returns the explicit worker outcome.
    #[must_use]
    pub fn status(&self) -> ResponseStatus {
        self.status
    }

    /// Encodes one bounded response frame.
    pub fn encode(&self, limits: &WorkerLimits) -> Result<Vec<u8>, ModelWorkerError> {
        self.validate(limits)?;
        encode_json(self, limits)
    }

    /// Decodes and validates one bounded response frame.
    pub fn decode(frame: &[u8], limits: &WorkerLimits) -> Result<Self, ModelWorkerError> {
        let value: Self = decode_json(frame, limits)?;
        value.validate(limits)?;
        Ok(value)
    }

    fn validate(&self, limits: &WorkerLimits) -> Result<(), ModelWorkerError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ModelWorkerError::invalid("unsupported response version"));
        }
        validate_text(&self.identity.run_id.0, "response run ID")?;
        validate_text(&self.identity.request_id.0, "response request ID")?;
        check_limit(self.candidate_hex.len(), limits.max_result_bytes, "candidate")?;
        check_limit(self.successor_hex.len(), limits.max_checkpoint_bytes, "successor checkpoint")?;
        if self.detail.len() > 256 {
            return Err(ModelWorkerError::invalid("response detail exceeds 256 bytes"));
        }
        if self.status == ResponseStatus::Success {
            let candidate_digest = ContentDigest::of(&self.candidate_hex);
            let mut payload = self.candidate_hex.clone();
            payload.extend_from_slice(&self.successor_hex);
            if self.output_numeric_digest != Some(candidate_digest)
                || self.return_payload_digest != Some(ContentDigest::of(&payload))
                || self.input_tensor_digest.is_none()
                || self.numeric_qualification.is_none()
            {
                return Err(ModelWorkerError::invalid(
                    "successful response digest or qualification mismatch",
                ));
            }
            self.numeric_qualification
                .as_ref()
                .expect("qualification presence checked above")
                .validate()?;
        } else if !self.candidate_hex.is_empty()
            || !self.successor_hex.is_empty()
            || self.input_tensor_digest.is_some()
            || self.output_numeric_digest.is_some()
            || self.return_payload_digest.is_some()
            || self.numeric_qualification.is_some()
        {
            return Err(ModelWorkerError::invalid("failure response carries candidate material"));
        }
        Ok(())
    }
}

/// Immediate result of submitting a context to the per-stream bounded scheduler.
#[derive(Debug, PartialEq)]
pub enum DispatchDecision {
    /// Request can be sent immediately and is now the sole in-flight context.
    Dispatch(Box<ModelRequest>),
    /// Request is retained as the sole pending context.
    Pending,
    /// Newest context replaced the previously pending context.
    PendingReplaced {
        /// Identifier of the context that will never be dispatched.
        replaced_request_id: ModelRequestId,
    },
}

/// Per-state-stream scheduler retaining at most one in-flight and one pending request.
#[derive(Debug)]
pub struct DispatchQueue {
    limits: WorkerLimits,
    in_flight: Option<ModelRequestId>,
    pending: Option<ModelRequest>,
}

impl DispatchQueue {
    /// Creates an empty bounded stream queue.
    #[must_use]
    pub fn new(limits: WorkerLimits) -> Self {
        Self { limits, in_flight: None, pending: None }
    }

    /// Submits without waiting for worker progress, replacing only the latest pending context.
    pub fn submit(&mut self, request: ModelRequest) -> Result<DispatchDecision, ModelWorkerError> {
        let encoded = request.encode(&self.limits)?;
        check_limit(encoded.len(), self.limits.max_pending_context_bytes, "pending context")?;
        if self.in_flight.is_none() {
            self.in_flight = Some(request.identity.request_id.clone());
            return Ok(DispatchDecision::Dispatch(Box::new(request)));
        }
        let replaced = self.pending.replace(request);
        Ok(match replaced {
            Some(request) => DispatchDecision::PendingReplaced {
                replaced_request_id: request.identity.request_id,
            },
            None => DispatchDecision::Pending,
        })
    }

    /// Completes the active request and promotes exactly one latest pending context.
    pub fn complete(
        &mut self,
        request_id: ModelRequestId,
    ) -> Result<Option<ModelRequest>, ModelWorkerError> {
        if self.in_flight.as_ref() != Some(&request_id) {
            return Err(ModelWorkerError::invalid("completed request is not the active request"));
        }
        self.in_flight = None;
        let next = self.pending.take();
        if let Some(request) = &next {
            self.in_flight = Some(request.identity.request_id.clone());
        }
        Ok(next)
    }
}

/// Synchronous local-socket transport for one bounded request/response exchange.
#[derive(Clone, Debug)]
pub struct WorkerClient {
    limits: WorkerLimits,
    io_timeout: Duration,
}

impl WorkerClient {
    /// Creates a local client with explicit frame limits and I/O timeout.
    #[must_use]
    pub fn new(limits: WorkerLimits, io_timeout: Duration) -> Self {
        Self { limits, io_timeout }
    }

    /// Executes one request over a Unix-domain socket and validates response identity.
    pub fn execute(
        &self,
        socket_path: impl AsRef<Path>,
        request: &ModelRequest,
    ) -> Result<ModelResponse, ModelWorkerError> {
        let frame = request.encode(&self.limits)?;
        let mut stream = UnixStream::connect(socket_path).map_err(ModelWorkerError::io)?;
        stream.set_read_timeout(Some(self.io_timeout)).map_err(ModelWorkerError::io)?;
        stream.set_write_timeout(Some(self.io_timeout)).map_err(ModelWorkerError::io)?;
        stream.write_all(&frame).map_err(ModelWorkerError::io)?;
        let response_frame = read_frame(&mut stream, &self.limits)?;
        let response = ModelResponse::decode(&response_frame, &self.limits)?;
        if response.identity != request.identity {
            return Err(ModelWorkerError::invalid("response identity differs from request"));
        }
        response.validate_for(request, &self.limits)?;
        Ok(response)
    }
}

impl ModelResponse {
    fn validate_for(
        &self,
        request: &ModelRequest,
        limits: &WorkerLimits,
    ) -> Result<(), ModelWorkerError> {
        if self.status != ResponseStatus::Success {
            return Ok(());
        }
        let elements = validate_shape_dimensions(&request.model_run.output_shape, limits)?;
        let expected_bytes = elements
            .checked_mul(size_of::<f32>())
            .ok_or_else(|| ModelWorkerError::invalid("candidate byte count overflow"))?;
        if self.candidate_hex.len() != expected_bytes
            || self.input_tensor_digest != Some(request.input_manifest.tensor_digest)
            || self.numeric_qualification.as_ref() != Some(&request.model_run.execution)
        {
            return Err(ModelWorkerError::invalid(
                "response shape, input digest, or numeric qualification differs from request",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
enum ErrorKind {
    Invalid(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

/// Failure to validate, encode, transport, or decode a bounded worker message.
pub struct ModelWorkerError {
    kind: ErrorKind,
    backtrace: Backtrace,
}

impl ModelWorkerError {
    fn invalid(message: impl Into<String>) -> Self {
        Self { kind: ErrorKind::Invalid(message.into()), backtrace: Backtrace::capture() }
    }

    fn io(error: std::io::Error) -> Self {
        Self { kind: ErrorKind::Io(error), backtrace: Backtrace::capture() }
    }

    fn json(error: serde_json::Error) -> Self {
        Self { kind: ErrorKind::Json(error), backtrace: Backtrace::capture() }
    }

    /// Returns the captured diagnostic backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Debug for ModelWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelWorkerError")
            .field("kind", &self.kind)
            .field("backtrace", &self.backtrace)
            .finish()
    }
}

impl fmt::Display for ModelWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Invalid(message) => formatter.write_str(message),
            ErrorKind::Io(error) => write!(formatter, "model worker I/O failed: {error}"),
            ErrorKind::Json(error) => write!(formatter, "model worker JSON failed: {error}"),
        }
    }
}

impl std::error::Error for ModelWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io(error) => Some(error),
            ErrorKind::Json(error) => Some(error),
            ErrorKind::Invalid(_) => None,
        }
    }
}

fn validate_text(value: &str, field: &str) -> Result<(), ModelWorkerError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(ModelWorkerError::invalid(format!(
            "{field} must contain 1..={MAX_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn check_limit(actual: usize, maximum: usize, field: &str) -> Result<(), ModelWorkerError> {
    if actual > maximum {
        return Err(ModelWorkerError::invalid(format!("{field} exceeds {maximum}-byte limit")));
    }
    Ok(())
}

fn validate_shape(
    shape: &[u32],
    max_shape: &[u32],
    tensor_bytes: usize,
    limits: &WorkerLimits,
) -> Result<(), ModelWorkerError> {
    if shape.is_empty()
        || shape.len() > limits.max_shape_dimensions
        || shape.len() != max_shape.len()
    {
        return Err(ModelWorkerError::invalid("tensor shape rank is invalid"));
    }
    let mut elements = 1_usize;
    for (&actual, &maximum) in shape.iter().zip(max_shape) {
        if actual == 0 || actual > maximum || actual > limits.max_dimension {
            return Err(ModelWorkerError::invalid("tensor dimension exceeds model shape"));
        }
        elements = elements
            .checked_mul(actual as usize)
            .ok_or_else(|| ModelWorkerError::invalid("tensor element count overflow"))?;
        if elements > limits.max_elements {
            return Err(ModelWorkerError::invalid("tensor element count exceeds limit"));
        }
    }
    let expected_bytes = elements
        .checked_mul(size_of::<f32>())
        .ok_or_else(|| ModelWorkerError::invalid("tensor byte count overflow"))?;
    if expected_bytes != tensor_bytes {
        return Err(ModelWorkerError::invalid("tensor byte count does not match float32 shape"));
    }
    Ok(())
}

fn validate_shape_dimensions(
    shape: &[u32],
    limits: &WorkerLimits,
) -> Result<usize, ModelWorkerError> {
    if shape.is_empty() || shape.len() > limits.max_shape_dimensions {
        return Err(ModelWorkerError::invalid("shape rank is invalid"));
    }
    let mut elements = 1_usize;
    for &dimension in shape {
        if dimension == 0 || dimension > limits.max_dimension {
            return Err(ModelWorkerError::invalid("shape dimension exceeds limit"));
        }
        elements = elements
            .checked_mul(dimension as usize)
            .ok_or_else(|| ModelWorkerError::invalid("shape element count overflow"))?;
        if elements > limits.max_elements {
            return Err(ModelWorkerError::invalid("shape element count exceeds limit"));
        }
    }
    Ok(elements)
}

fn encode_json<T: Serialize>(
    value: &T,
    limits: &WorkerLimits,
) -> Result<Vec<u8>, ModelWorkerError> {
    let payload = serde_json::to_vec(value).map_err(ModelWorkerError::json)?;
    let length = payload
        .len()
        .checked_add(8)
        .ok_or_else(|| ModelWorkerError::invalid("frame length overflow"))?;
    check_limit(length, limits.max_frame_bytes, "frame")?;
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| ModelWorkerError::invalid("frame exceeds u32 length"))?;
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_json<T: for<'de> Deserialize<'de>>(
    frame: &[u8],
    limits: &WorkerLimits,
) -> Result<T, ModelWorkerError> {
    if frame.len() < 8 || &frame[..4] != MAGIC {
        return Err(ModelWorkerError::invalid("invalid worker frame magic"));
    }
    let declared = u32::from_be_bytes(
        frame[4..8].try_into().map_err(|_| ModelWorkerError::invalid("frame header truncated"))?,
    ) as usize;
    let full_length = declared
        .checked_add(8)
        .ok_or_else(|| ModelWorkerError::invalid("frame length overflow"))?;
    check_limit(full_length, limits.max_frame_bytes, "frame")?;
    if frame.len() != full_length {
        return Err(ModelWorkerError::invalid("worker frame length mismatch"));
    }
    serde_json::from_slice(&frame[8..]).map_err(ModelWorkerError::json)
}

fn read_frame(stream: &mut UnixStream, limits: &WorkerLimits) -> Result<Vec<u8>, ModelWorkerError> {
    let mut header = [0_u8; 8];
    stream.read_exact(&mut header).map_err(ModelWorkerError::io)?;
    if &header[..4] != MAGIC {
        return Err(ModelWorkerError::invalid("invalid worker frame magic"));
    }
    let payload_length = u32::from_be_bytes(
        header[4..].try_into().map_err(|_| ModelWorkerError::invalid("frame header truncated"))?,
    ) as usize;
    let frame_length = payload_length
        .checked_add(8)
        .ok_or_else(|| ModelWorkerError::invalid("frame length overflow"))?;
    check_limit(frame_length, limits.max_frame_bytes, "frame")?;
    let mut frame = Vec::with_capacity(frame_length);
    frame.extend_from_slice(&header);
    frame.resize(frame_length, 0);
    stream.read_exact(&mut frame[8..]).map_err(ModelWorkerError::io)?;
    Ok(frame)
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(text, "{byte:02x}").expect("writing to String cannot fail");
        }
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        if text.len() % 2 != 0 {
            return Err(serde::de::Error::custom("hex bytes require an even character count"));
        }
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).map_err(serde::de::Error::custom)?;
                u8::from_str_radix(pair, 16).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

mod optional_digest {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::ContentDigest;

    pub fn serialize<S>(digest: &Option<ContentDigest>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match digest {
            Some(digest) => serializer.serialize_some(digest),
            None => serializer.serialize_str(""),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<ContentDigest>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() {
            Ok(None)
        } else {
            serde_json::from_value(serde_json::Value::String(value))
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}
