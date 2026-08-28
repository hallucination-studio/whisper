//! Deterministic domain types and validated configuration for the Whisper RF world model.

pub(crate) mod application;
pub(crate) mod capture;
mod config;
pub(crate) mod database;
pub(crate) mod domain;
pub(crate) mod session;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Timeline is integrated by a later Engine work package")
)]
pub(crate) mod timeline;
#[expect(dead_code, reason = "wire item surface is consumed by later work packages")]
pub(crate) mod wire;

pub use config::{Config, ConfigError, RouteError, parse_config};
