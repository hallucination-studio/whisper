//! Produces, seals, and independently verifies bounded RF relationship evidence packages.
//!
//! A producer writes the exact producer artifact set before sealing it. The read-only Chrome
//! observer then writes and seals its disjoint artifact set. Only after both sets are sealed may a
//! separate verifier validate the complete package and add `verification.json`. Sealing rejects
//! mutable or aliased members, and verification fails closed if either sealed set changes.

mod internal;

pub(crate) use internal::canonical_cbor_bytes;

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt;

#[cfg(unix)]
use crate::HostRuntime;

/// Failure while producing, observing, sealing, or verifying a bounded evidence package.
#[cfg(feature = "development-fixture")]
pub struct EvidenceError {
    source: EvidenceFailure,
    backtrace: Backtrace,
}

#[cfg(feature = "development-fixture")]
struct EvidenceFailure {
    message: &'static str,
    retained_source: Box<internal::EvidenceError>,
}

/// One explicitly selected Semantic Session and Link/Profile evidence subject.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceSubject {
    session_id: String,
    link: String,
    profile: String,
}

/// A validated Semantic Session identifier used by evidence selection.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceSemanticSessionId(String);

/// A validated Link identifier used by evidence selection.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceLinkId(String);

/// A validated Profile identifier used by evidence selection.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceProfileId(String);

/// A validated bounded evidence run identifier.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceRunId(String);

/// A validated Chrome version identity recorded by the read-only observer.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceChromeVersion(String);

/// A validated SHA-256 identity for the signed Chrome executable.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceChromeExecutableSha256(String);

/// A validated already-open Chrome page instance identity.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidencePageInstanceId(String);

/// A validated physical Sensor identity selected for one evidence run.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceSensorId(String);

/// A validated runtime-configuration SHA-256 identity used by evidence receipts.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceConfigSha256(String);

/// A validated provisioning SHA-256 identity used by evidence receipts.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceProvisioningSha256(String);

/// A validated firmware-capability SHA-256 identity used by evidence receipts.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceFirmwareCapabilitySha256(String);

/// A validated firmware-image SHA-256 identity used by evidence receipts.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceFirmwareImageSha256(String);

/// A validated firmware source revision used by evidence receipts.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceFirmwareSourceRevision(String);

/// A checked UTC nanosecond interval used by evidence receipts.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceInterval {
    started_utc_ns: u128,
    ended_utc_ns: u128,
}

/// Sanitized external identities needed to bind one producer evidence run.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug)]
pub struct EvidenceRunIdentity {
    config_sha256: String,
    firmware_capability_sha256: String,
    firmware_image_sha256: String,
    firmware_source_revision: String,
    provisioning_sha256: String,
}

/// Validated runtime-configuration and provisioning digests for one run.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug)]
pub struct EvidenceArtifactIdentity {
    config_sha256: EvidenceConfigSha256,
    provisioning_sha256: EvidenceProvisioningSha256,
}

/// Validated firmware capability, image, and source identities for one run.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug)]
pub struct EvidenceFirmwareIdentity {
    capability_sha256: EvidenceFirmwareCapabilitySha256,
    image_sha256: EvidenceFirmwareImageSha256,
    source_revision: EvidenceFirmwareSourceRevision,
}

/// Validated metadata needed to bind one producer evidence run.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug)]
pub struct EvidenceRunMetadata {
    identity: EvidenceRunIdentity,
    interval: EvidenceInterval,
    run_id: String,
    subject: EvidenceSubject,
    unknown: EvidenceUnknownObservation,
}

/// Opaque transaction-B audit captured at the fully processed pre-restart cursor.
#[cfg(all(feature = "development-fixture", unix))]
pub struct EvidencePreRestartAudit {
    effects: Vec<crate::store::EvidenceTransactionBEffect>,
    session_id: String,
    store_id: String,
}

/// The exact committed BaselineLearning observation bound into producer transaction evidence.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceUnknownObservation {
    creator_commit_seq: u64,
    result_time: u64,
    subject: EvidenceSubject,
}

/// The actual Chrome viewport recorded by the read-only observer.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceViewport {
    device_scale_factor: String,
    height: u32,
    width: u32,
}

/// Verified signed Google Chrome application identity used by the read-only observer.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug)]
pub struct EvidenceChromeIdentity {
    executable_sha256: String,
    version: String,
}

/// Validated metadata needed to bind one read-only Chrome observation.
#[cfg(feature = "development-fixture")]
#[derive(Clone, Debug)]
pub struct EvidenceObserverMetadata {
    chrome: EvidenceChromeIdentity,
    interval: EvidenceInterval,
    page_instance_id: String,
    subject: EvidenceSubject,
    viewport: EvidenceViewport,
}

#[cfg(feature = "development-fixture")]
impl EvidenceSubject {
    /// Creates one selected Semantic Session and Link/Profile subject from checked identities.
    #[must_use]
    pub fn new(
        session_id: EvidenceSemanticSessionId,
        link: EvidenceLinkId,
        profile: EvidenceProfileId,
    ) -> Self {
        Self { session_id: session_id.0, link: link.0, profile: profile.0 }
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceSemanticSessionId {
    /// Validates one Semantic Session evidence identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is empty or sensitive.
    pub fn try_new(value: impl Into<String>) -> Result<Self, EvidenceError> {
        let value = value.into();
        internal::validate_evidence_text_id(&value).map_err(EvidenceError::evidence)?;
        Ok(Self(value))
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceLinkId {
    /// Validates one Link evidence identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is empty or sensitive.
    pub fn try_new(value: impl Into<String>) -> Result<Self, EvidenceError> {
        let value = value.into();
        internal::validate_evidence_text_id(&value).map_err(EvidenceError::evidence)?;
        Ok(Self(value))
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceProfileId {
    /// Validates one lowercase hexadecimal Profile digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not lowercase hexadecimal SHA-256 text.
    pub fn try_new(value: impl Into<String>) -> Result<Self, EvidenceError> {
        let value = value.into();
        internal::validate_evidence_digest(&value).map_err(EvidenceError::evidence)?;
        Ok(Self(value))
    }
}

#[cfg(feature = "development-fixture")]
macro_rules! impl_evidence_string_traits {
    ($name:ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl std::str::FromStr for $name {
            type Err = EvidenceError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = EvidenceError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::try_new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = EvidenceError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_new(value)
            }
        }
    };
}

#[cfg(feature = "development-fixture")]
impl_evidence_string_traits!(EvidenceSemanticSessionId);
#[cfg(feature = "development-fixture")]
impl_evidence_string_traits!(EvidenceLinkId);
#[cfg(feature = "development-fixture")]
impl_evidence_string_traits!(EvidenceProfileId);

#[cfg(feature = "development-fixture")]
macro_rules! evidence_string_value {
    ($name:ident, $validator:path) => {
        impl $name {
            /// Validates one typed evidence identity value.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is malformed or sensitive.
            pub fn try_new(value: impl Into<String>) -> Result<Self, EvidenceError> {
                let value = value.into();
                $validator(&value).map_err(EvidenceError::evidence)?;
                Ok(Self(value))
            }
        }

        impl_evidence_string_traits!($name);
    };
}

evidence_string_value!(EvidenceConfigSha256, internal::validate_evidence_digest);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidenceProvisioningSha256, internal::validate_evidence_digest);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidenceFirmwareCapabilitySha256, internal::validate_evidence_digest);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidenceFirmwareImageSha256, internal::validate_evidence_digest);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidenceFirmwareSourceRevision, internal::validate_evidence_revision);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidenceRunId, internal::validate_evidence_run_id);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidenceChromeVersion, internal::validate_evidence_text_id);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidenceChromeExecutableSha256, internal::validate_evidence_digest);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidencePageInstanceId, internal::validate_evidence_text_id);
#[cfg(feature = "development-fixture")]
evidence_string_value!(EvidenceSensorId, internal::validate_evidence_text_id);
#[cfg(feature = "development-fixture")]
impl EvidenceInterval {
    /// Validates a non-empty UTC nanosecond interval.
    ///
    /// # Errors
    ///
    /// Returns an error unless `ended_utc_ns` is strictly greater than `started_utc_ns`.
    pub fn try_new(started_utc_ns: u128, ended_utc_ns: u128) -> Result<Self, EvidenceError> {
        if ended_utc_ns <= started_utc_ns {
            return Err(EvidenceError::evidence(internal::EvidenceError::Semantic(
                "evidence interval is incompatible",
            )));
        }
        Ok(Self { started_utc_ns, ended_utc_ns })
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceRunIdentity {
    /// Creates one run identity from validated artifact and firmware identities.
    #[must_use]
    pub fn new(artifacts: EvidenceArtifactIdentity, firmware: EvidenceFirmwareIdentity) -> Self {
        Self {
            config_sha256: artifacts.config_sha256.0,
            firmware_capability_sha256: firmware.capability_sha256.0,
            firmware_image_sha256: firmware.image_sha256.0,
            firmware_source_revision: firmware.source_revision.0,
            provisioning_sha256: artifacts.provisioning_sha256.0,
        }
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceArtifactIdentity {
    /// Creates the runtime-configuration and provisioning identity group.
    #[must_use]
    pub fn new(
        config_sha256: EvidenceConfigSha256,
        provisioning_sha256: EvidenceProvisioningSha256,
    ) -> Self {
        Self { config_sha256, provisioning_sha256 }
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceFirmwareIdentity {
    /// Creates the firmware capability, production image, and source identity group.
    #[must_use]
    pub fn new(
        capability_sha256: EvidenceFirmwareCapabilitySha256,
        image_sha256: EvidenceFirmwareImageSha256,
        source_revision: EvidenceFirmwareSourceRevision,
    ) -> Self {
        Self { capability_sha256, image_sha256, source_revision }
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceRunMetadata {
    /// Validates one producer receipt identity, interval, selected subject, and committed Unknown.
    ///
    /// # Errors
    ///
    /// Returns an error when the run identity is empty, contains a path separator, or is
    /// sensitive, or when the committed Unknown belongs to a different evidence subject.
    pub fn try_new(
        run_id: EvidenceRunId,
        interval: EvidenceInterval,
        identity: EvidenceRunIdentity,
        subject: EvidenceSubject,
        unknown: EvidenceUnknownObservation,
    ) -> Result<Self, EvidenceError> {
        let value = Self { identity, interval, run_id: run_id.0, subject, unknown };
        internal::validate_run_metadata(&value).map_err(EvidenceError::evidence)?;
        Ok(value)
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceViewport {
    /// Validates the actual CSS viewport and positive decimal device scale factor.
    ///
    /// # Errors
    ///
    /// Returns an error for zero dimensions or a noncanonical, nonpositive scale factor.
    pub fn try_new(
        width: u32,
        height: u32,
        device_scale_factor: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        let value = Self { device_scale_factor: device_scale_factor.into(), height, width };
        internal::validate_viewport(&value).map_err(EvidenceError::evidence)?;
        Ok(value)
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceObserverMetadata {
    /// Validates one separate read-only Chrome observation identity.
    ///
    /// # Errors
    ///
    /// Returns an error when browser or page identity is empty or sensitive.
    pub fn try_new(
        chrome: EvidenceChromeIdentity,
        page_instance_id: EvidencePageInstanceId,
        interval: EvidenceInterval,
        viewport: EvidenceViewport,
        subject: EvidenceSubject,
    ) -> Result<Self, EvidenceError> {
        let value =
            Self { chrome, interval, page_instance_id: page_instance_id.0, subject, viewport };
        internal::validate_observer_metadata(&value).map_err(EvidenceError::evidence)?;
        Ok(value)
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceChromeIdentity {
    /// Binds the retained Chrome version to one verified signed executable digest.
    #[must_use]
    pub fn new(
        version: EvidenceChromeVersion,
        executable_sha256: EvidenceChromeExecutableSha256,
    ) -> Self {
        Self { executable_sha256: executable_sha256.0, version: version.0 }
    }
}

#[cfg(feature = "development-fixture")]
impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bounded RF relationship evidence operation failed: {}", self.source)
    }
}

#[cfg(feature = "development-fixture")]
impl fmt::Debug for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("EvidenceError").finish_non_exhaustive()
    }
}

#[cfg(all(feature = "development-fixture", unix))]
impl fmt::Debug for EvidencePreRestartAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("EvidencePreRestartAudit").finish_non_exhaustive()
    }
}

#[cfg(feature = "development-fixture")]
impl Error for EvidenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(feature = "development-fixture")]
impl fmt::Display for EvidenceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

#[cfg(feature = "development-fixture")]
impl fmt::Debug for EvidenceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.retained_source;
        formatter.debug_struct("EvidenceFailure").finish_non_exhaustive()
    }
}

#[cfg(feature = "development-fixture")]
impl Error for EvidenceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.retained_source.as_ref())
    }
}

#[cfg(feature = "development-fixture")]
impl EvidenceError {
    /// Returns the backtrace captured at the public evidence API boundary.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn evidence(source: internal::EvidenceError) -> Self {
        let message = source.redacted_message();
        Self {
            source: EvidenceFailure { message, retained_source: Box::new(source) },
            backtrace: Backtrace::capture(),
        }
    }
}

/// Independently verifies one sealed bounded RF relationship evidence package.
///
/// # Errors
///
/// Returns an error when the package is incomplete, mutable, noncanonical, aliased,
/// sensitive, digest-inconsistent, or does not prove the bounded relationship outcome.
#[cfg(feature = "development-fixture")]
pub fn verify_evidence_package(root: impl AsRef<std::path::Path>) -> Result<(), EvidenceError> {
    internal::verify(root.as_ref()).map_err(EvidenceError::evidence)
}

/// Validates and seals the producer-owned bounded evidence artifact set.
///
/// # Errors
///
/// Returns an error when producer artifacts are incomplete, unsafe, or inconsistent.
#[cfg(feature = "development-fixture")]
pub fn seal_evidence_producer(root: impl AsRef<std::path::Path>) -> Result<(), EvidenceError> {
    internal::seal_producer(root.as_ref()).map_err(EvidenceError::evidence)
}

/// Validates producer sealing, then validates and seals the observer-owned artifact set.
///
/// # Errors
///
/// Returns an error when producer sealing or observer artifacts are incomplete or inconsistent.
#[cfg(feature = "development-fixture")]
pub fn seal_evidence_observer(root: impl AsRef<std::path::Path>) -> Result<(), EvidenceError> {
    internal::seal_observer(root.as_ref()).map_err(EvidenceError::evidence)
}

/// Writes a canonical sanitized logical Store export from committed Host query state.
///
/// # Errors
///
/// Returns an error when the committed snapshot cannot be read or the new artifact cannot be
/// created and synchronized. Existing files are never replaced.
#[cfg(all(feature = "development-fixture", unix))]
pub fn write_current_store_evidence(
    runtime: &HostRuntime,
    path: impl AsRef<std::path::Path>,
) -> Result<(), EvidenceError> {
    internal::write_current_store_export(runtime, path.as_ref()).map_err(EvidenceError::evidence)
}

/// Captures the selected committed `Unknown(BaselineLearning)` from the production QueryStore.
///
/// # Errors
///
/// Returns an error unless the selected subject currently has that exact committed relationship.
#[cfg(all(feature = "development-fixture", unix))]
pub fn capture_evidence_unknown_observation(
    runtime: &HostRuntime,
    subject: &EvidenceSubject,
) -> Result<EvidenceUnknownObservation, EvidenceError> {
    internal::capture_unknown_observation(runtime, subject).map_err(EvidenceError::evidence)
}

/// Writes the canonical logical Store export captured by restart rebuild before writer creation.
///
/// # Errors
///
/// Returns an error when this Host did not rebuild an active Semantic Session or the new artifact
/// cannot be created and synchronized. Existing files are never replaced.
#[cfg(all(feature = "development-fixture", unix))]
pub fn write_rebuild_store_evidence(
    runtime: &HostRuntime,
    path: impl AsRef<std::path::Path>,
) -> Result<(), EvidenceError> {
    internal::write_rebuild_store_export(runtime, path.as_ref()).map_err(EvidenceError::evidence)
}

/// Captures the writer-owned transaction-B audit at one fully processed pre-restart cursor.
///
/// # Errors
///
/// Returns an error unless the current committed Store snapshot and writer audit are an exact,
/// ordered prefix with matching transaction-B identities, cursors, Timeline digests, and
/// watermarks.
#[cfg(all(feature = "development-fixture", unix))]
pub fn capture_evidence_pre_restart_audit(
    runtime: &HostRuntime,
) -> Result<EvidencePreRestartAudit, EvidenceError> {
    let (snapshot, effects) = runtime
        .evidence_snapshot_with_transaction_b_audit()
        .map_err(internal::EvidenceError::Store)
        .map_err(EvidenceError::evidence)?
        .ok_or_else(|| {
            EvidenceError::evidence(internal::EvidenceError::Semantic(
                "transaction-B evidence audit is incomplete",
            ))
        })?;
    internal::validate_transaction_b_audit(&snapshot, &effects, true)
        .map_err(EvidenceError::evidence)?;
    Ok(EvidencePreRestartAudit {
        effects,
        session_id: snapshot.active_session.session_id,
        store_id: snapshot.store_id,
    })
}

/// Writes exact committed ciphertext, sanitized physical provenance, and ordered A/B trace files.
///
/// # Errors
///
/// Returns an error when committed Host state cannot be read, contains no packet input, or any
/// target path already exists or cannot be synchronized.
#[cfg(all(feature = "development-fixture", unix))]
pub fn write_evidence_input_and_commits(
    runtime: &HostRuntime,
    root: impl AsRef<std::path::Path>,
    sensor_id: &EvidenceSensorId,
    metadata: &EvidenceRunMetadata,
    pre_restart_audit: &EvidencePreRestartAudit,
) -> Result<(), EvidenceError> {
    internal::write_input_and_commit_artifacts(
        runtime,
        root.as_ref(),
        &sensor_id.0,
        metadata,
        pre_restart_audit,
    )
    .map_err(EvidenceError::evidence)
}

/// Writes the bounded controlled-restart trace from retained and continued Host state.
///
/// # Errors
///
/// Returns an error unless the existing pre-stop and rebuild exports are byte-equal, this Host
/// carries the corresponding read-only rebuild, and committed continuation has advanced.
#[cfg(all(feature = "development-fixture", unix))]
pub fn write_evidence_restart_trace(
    runtime: &HostRuntime,
    root: impl AsRef<std::path::Path>,
    sensor_id: &EvidenceSensorId,
    subject: &EvidenceSubject,
    downtime: EvidenceInterval,
) -> Result<(), EvidenceError> {
    internal::write_restart_artifact(runtime, root.as_ref(), &sensor_id.0, subject, downtime)
        .map_err(EvidenceError::evidence)
}

/// Writes `run.json` after independently hashing the exact producer artifact set.
///
/// # Errors
///
/// Returns an error when metadata, committed identities, producer files, or digests are invalid.
#[cfg(all(feature = "development-fixture", unix))]
pub fn write_evidence_run_receipt(
    runtime: &HostRuntime,
    root: impl AsRef<std::path::Path>,
    metadata: &EvidenceRunMetadata,
) -> Result<(), EvidenceError> {
    internal::write_run_receipt(runtime, root.as_ref(), metadata).map_err(EvidenceError::evidence)
}

/// Writes `observer.json` after independently hashing the exact observer artifact set.
///
/// # Errors
///
/// Returns an error when metadata, selection, observer files, or digests are invalid.
#[cfg(all(feature = "development-fixture", unix))]
pub fn write_evidence_observer_receipt(
    root: impl AsRef<std::path::Path>,
    metadata: &EvidenceObserverMetadata,
) -> Result<(), EvidenceError> {
    internal::write_observer_receipt(root.as_ref(), metadata).map_err(EvidenceError::evidence)
}
