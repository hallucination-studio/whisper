//! Preserved native RF input contracts for the RF world-model rebuild.

#![forbid(unsafe_code)]

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "retained for the next authenticated raw-fact Host slice")
)]
pub(crate) mod key;
#[expect(dead_code, reason = "retained for the next lossless native-CSI fact slice")]
pub(crate) mod native_csi;
/// Native-frame v1 authentication, parsing, and lossless body values.
#[expect(dead_code, reason = "retained as the fixed deployed-device input contract")]
#[path = "wire.rs"]
pub(crate) mod native_frame;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "retained for durable authenticated raw-fact admission")
)]
pub(crate) mod replay;

#[cfg(test)]
mod conformance;
