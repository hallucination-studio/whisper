//! Store lifecycle, atomic capture, and committed query interfaces.

mod managed;
mod query;
mod sqlite;

#[cfg(all(unix, feature = "ingest-test-hooks"))]
pub use query::QueryHold;
pub use query::{
    EmptyEnvelope, ErrorEnvelope, Metric, QueryError, QueryLimits, QueryStore, SignalPath,
    SignalQuery, SignalQueryBuilder, SignalRange, SignalSelection, SignalsOk, SignalsResponse,
    TopologyOk,
};
pub(crate) use sqlite::{AdmissionEpochSeed, CaptureSession, Store, StoreError};
