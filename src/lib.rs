//! Deterministic domain types and validated configuration for an RF world model.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "capture types are consumed by the work-package 1.2 ingest boundary"
    )
)]
pub(crate) mod capture;
mod config;
pub(crate) mod domain;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "ESP32 decoder is consumed by the work-package 1.2 ingest boundary"
    )
)]
pub(crate) mod esp32;

pub use config::{ConfigError, EffectiveConfig, RouteError, parse_config};
