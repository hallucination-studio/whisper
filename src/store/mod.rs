//! Store lifecycle, atomic capture, and committed query interfaces.

mod managed;
mod query;
mod sqlite;

#[cfg(all(unix, feature = "ingest-test-hooks"))]
pub use query::QueryHold;
#[cfg(feature = "ingest-test-hooks")]
pub use query::{EmptyEnvelope, SignalQueryBuilder, SignalsOk, SignalsResponse, TopologyOk};
pub use query::{
    ErrorEnvelope, Metric, QueryError, QueryLimits, QueryStore, SignalPath, SignalQuery,
    SignalRange, SignalSelection,
};
pub(crate) use sqlite::{AdmissionEpochSeed, CaptureSession, Store, StoreError};
