//! Store lifecycle, atomic capture, and committed query interfaces.

#[cfg(feature = "development-fixture")]
mod evidence;
mod managed;
mod query;
mod sqlite;

#[cfg(feature = "development-fixture")]
pub(crate) use evidence::{
    EvidenceBaselineCommand, EvidenceKnowledge, EvidenceRebuildSnapshot, EvidenceRelationship,
    EvidenceStoreSnapshot, EvidenceTransactionBAudit, EvidenceTransactionBEffect,
};
#[cfg(all(unix, feature = "ingest-test-hooks"))]
pub use query::QueryHold;
#[cfg(feature = "ingest-test-hooks")]
pub use query::{
    EmptyEnvelope, RelationshipLatestResponse, RelationshipSubjectsOk, SignalQueryBuilder,
    SignalsOk, SignalsResponse, TopologyOk,
};
pub use query::{
    ErrorEnvelope, Metric, QueryError, QueryLimits, QueryStore, RelationshipSelection, SignalPath,
    SignalQuery, SignalRange, SignalSelection,
};
#[cfg(feature = "ingest-test-hooks")]
pub(crate) use sqlite::RelationshipFailureStage;
pub(crate) use sqlite::{
    AdmissionEpochSeed, CaptureSession, PreparedSession, Store, StoreError,
    prepare_semantic_session,
};
