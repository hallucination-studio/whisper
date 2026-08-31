//! Store lifecycle, atomic capture, and committed query interfaces.

mod managed;
mod query;
mod relationship;
mod sqlite;

#[cfg(all(unix, feature = "ingest-test-hooks"))]
pub use query::QueryHold;
#[cfg(feature = "ingest-test-hooks")]
pub use query::{EmptyEnvelope, SignalQueryBuilder, SignalsOk, SignalsResponse, TopologyOk};
pub use query::{
    ErrorEnvelope, Metric, QueryError, QueryLimits, QueryStore, RelationshipLatestResponse,
    RelationshipSelection, RelationshipSubjectsOk, SignalPath, SignalQuery, SignalRange,
    SignalSelection,
};
#[cfg(feature = "ingest-test-hooks")]
pub(crate) use sqlite::RelationshipFailureStage;
pub(crate) use sqlite::{AdmissionEpochSeed, CaptureSession, Store, StoreError};
