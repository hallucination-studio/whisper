//! Deterministic domain types and validated configuration for the Whisper RF world model.

#![forbid(unsafe_code)]

pub(crate) mod application;
pub(crate) mod capture;
mod config;
pub(crate) mod database;
#[cfg(feature = "development-fixture")]
pub mod development_fixture;
pub(crate) mod domain;
#[cfg(unix)]
mod executable;
#[cfg(unix)]
mod hex;
#[cfg(unix)]
mod host;
pub(crate) mod key_material;
#[cfg(unix)]
mod relationship;
pub(crate) mod session;
#[cfg(unix)]
mod store;
#[cfg(all(unix, feature = "ingest-test-hooks"))]
#[doc(hidden)]
pub mod test_support;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Timeline is integrated by a later Engine work package")
)]
pub(crate) mod timeline;
#[expect(dead_code, reason = "wire item surface is consumed by later work packages")]
pub(crate) mod wire;

pub(crate) use capture::{
    CaptureRecordSequence, CapturedDatagram, CommitOutcome, CommitReceipt, PacketDisposition,
    ProjectionCommit, ProjectionSequence,
};
pub use config::{Config, ConfigError, RouteError, parse_config};
#[doc(inline)]
pub use domain::identity::SessionId;
#[cfg(unix)]
#[doc(inline)]
pub use host::{HostRuntime, RuntimeError, RuntimeFailure, SocketOperation, SocketRole};

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt;

/// An application lifecycle failure from a bounded delivery command.
#[derive(Debug)]
pub struct LifecycleError {
    source: application::HostError,
    backtrace: Backtrace,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for LifecycleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl LifecycleError {
    /// Returns whether another process or session holds the Managed-store lease.
    #[must_use]
    pub const fn is_lease_conflict(&self) -> bool {
        self.source.is_lease_conflict()
    }

    /// Returns the backtrace captured at the public command boundary.
    pub const fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }

    fn host(source: application::HostError) -> Self {
        Self { source, backtrace: Backtrace::capture() }
    }
}

/// Initializes the configured Store and its empty admission epochs.
///
/// # Errors
///
/// Returns an error if Managed-store trust, secret loading, SQLite initialization,
/// validation, or no-replace publication fails. Non-Unix platforms always return
/// an error because they cannot enforce the Managed-store contract.
pub fn init_admission(config: &Config) -> Result<(), LifecycleError> {
    application::init_admission(config).map_err(LifecycleError::host)
}
