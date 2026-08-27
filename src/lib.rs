//! Deterministic domain types and validated configuration for an RF world model.

pub(crate) mod capture;
mod config;
pub(crate) mod domain;
#[expect(dead_code, reason = "wire item surface is consumed by later work packages")]
pub(crate) mod wire;

pub use config::{ConfigError, EffectiveConfig, RouteError, parse_config};
