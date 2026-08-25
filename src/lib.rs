//! Deterministic domain types and validated configuration for an RF world model.

mod config;
pub(crate) mod domain;

pub use config::{ConfigError, EffectiveConfig, RouteError, parse_config};
