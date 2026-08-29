//! Deterministic domain types and validated configuration for the Whisper RF world model.

pub(crate) mod application;
pub(crate) mod capture;
mod config;
pub(crate) mod database;
#[cfg(unix)]
mod demo_store;
#[cfg(feature = "development-fixture")]
pub mod development_fixture;
pub(crate) mod domain;
#[cfg(unix)]
mod hex;
pub(crate) mod key_material;
#[cfg(unix)]
mod managed_store;
pub(crate) mod session;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Timeline is integrated by a later Engine work package")
)]
pub(crate) mod timeline;
#[expect(dead_code, reason = "wire item surface is consumed by later work packages")]
pub(crate) mod wire;

pub use config::{Config, ConfigError, RouteError, parse_config};

use std::error::Error;
use std::fmt;

/// An application lifecycle failure from a bounded Demo command.
#[derive(Debug)]
pub struct DemoError {
    source: application::HostError,
}

/// A newly created Capture Session and its retained Managed-store lifecycle lease.
#[derive(Debug)]
#[must_use = "dropping the Demo Session releases its Managed-store lifecycle lease"]
pub struct DemoSession {
    inner: application::DemoSession,
}

impl DemoSession {
    /// Returns the Store-scoped random identity read from the validated Demo Store.
    #[must_use]
    pub const fn store_id(&self) -> [u8; 32] {
        self.inner.store_id()
    }

    /// Returns the random identity of this Capture Session.
    #[must_use]
    pub fn session_id(&self) -> &str {
        self.inner.session_id()
    }

    /// Returns elapsed monotonic time since this Capture Session was created.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.inner.elapsed()
    }
}

impl fmt::Display for DemoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for DemoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl DemoError {
    /// Returns whether another process or session holds the Managed-store lease.
    #[must_use]
    pub const fn is_lease_conflict(&self) -> bool {
        self.source.is_lease_conflict()
    }

    fn host(source: application::HostError) -> Self {
        Self { source }
    }
}

/// Initializes the configured Demo Store and its empty admission epochs.
///
/// # Errors
///
/// Returns an error if Managed-store trust, secret loading, SQLite initialization,
/// validation, or no-replace publication fails. Non-Unix platforms always return
/// an error because they cannot enforce the Managed-store contract.
pub fn init_admission(config: &Config) -> Result<(), DemoError> {
    application::init_admission(config).map_err(DemoError::host)
}

/// Opens an existing Demo Store and starts one empty Capture Session.
///
/// The returned handle retains the Managed-store lifecycle lease and the
/// Capture Session's monotonic origin until it is dropped.
///
/// # Errors
///
/// Returns an error if the Store is missing, untrusted, incompatible, or cannot
/// atomically create the Capture Session. Non-Unix platforms always return an
/// error because they cannot enforce the Managed-store contract.
pub fn serve(config: &Config) -> Result<DemoSession, DemoError> {
    application::serve(config).map(|inner| DemoSession { inner }).map_err(DemoError::host)
}
