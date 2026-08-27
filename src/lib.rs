//! Deterministic domain types and validated configuration for the Whisper RF world model.

pub(crate) mod capture;
mod config;
pub(crate) mod domain;
#[cfg_attr(not(test), expect(dead_code, reason = "session API is consumed by work-package 2.2"))]
pub(crate) mod session;
#[expect(dead_code, reason = "wire item surface is consumed by later work packages")]
pub(crate) mod wire;

pub use config::{Config, ConfigError, RouteError, parse_config};
