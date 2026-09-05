//! Bounded replay admission for authenticated native-frame sequence identities.

use sha2::{Digest, Sha256};

use crate::key::EpochKey;
use crate::native_frame::WIRE_SCHEMA_VERSION;

const REPLAY_IDENTITY_DOMAIN: &[u8] = b"whisper.replay-window.identity";
const REPLAY_IDENTITY_VERSION: u8 = 1;
const REPLAY_STATE_VERSION: u8 = 1;
const REPLAY_STATE_FIXED_BYTES: usize = 1 + 2 + 1 + 4 + 8;

/// Cryptographic identity binding durable replay state to its secret epoch key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplayWindowIdentity([u8; 32]);

impl ReplayWindowIdentity {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derives the fixed replay identity without persisting the secret key itself.
pub(crate) fn derive_replay_window_identity(
    deployment: &str,
    device: u64,
    key_epoch: u16,
    epoch_key: &EpochKey,
) -> Result<ReplayWindowIdentity, ReplayIdentityError> {
    if key_epoch == 0 {
        return Err(ReplayIdentityError::ZeroKeyEpoch);
    }
    let deployment = deployment.as_bytes();
    let deployment_length =
        u32::try_from(deployment.len()).map_err(|_| ReplayIdentityError::DeploymentTooLong)?;
    let mut preimage =
        Vec::with_capacity(REPLAY_IDENTITY_DOMAIN.len() + 3 + 4 + deployment.len() + 8 + 2 + 32);
    preimage.extend_from_slice(REPLAY_IDENTITY_DOMAIN);
    preimage.push(0);
    preimage.push(REPLAY_IDENTITY_VERSION);
    preimage.push(WIRE_SCHEMA_VERSION);
    preimage.extend_from_slice(&deployment_length.to_be_bytes());
    preimage.extend_from_slice(deployment);
    preimage.extend_from_slice(&device.to_be_bytes());
    preimage.extend_from_slice(&key_epoch.to_be_bytes());
    preimage.extend_from_slice(epoch_key.as_bytes());
    Ok(ReplayWindowIdentity(Sha256::digest(preimage).into()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ReplayIdentityError {
    #[error("replay identity key epoch must be non-zero")]
    ZeroKeyEpoch,
    #[error("deployment identity exceeds the replay identity u32 length limit")]
    DeploymentTooLong,
}

/// The result of checking one authenticated native-frame sequence identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDecision {
    /// The identity was new within the active key and boot epoch.
    Accepted,
    /// The identity was duplicated, stale, invalid, or from an older boot generation.
    Rejected,
}

/// In-memory replay-window state suitable for durable fact-store serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAdmission {
    window_packets: u16,
    boot_generation: Option<u32>,
    maximum_message_sequence: Option<u64>,
    seen: Box<[u8]>,
}

/// Serializable fields required to resume replay admission without clearing its window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplayState {
    window_packets: u16,
    boot_generation: Option<u32>,
    maximum_message_sequence: Option<u64>,
    seen: Box<[u8]>,
}

impl ReplayAdmission {
    pub(crate) const fn window_packets(&self) -> u16 {
        self.window_packets
    }

    pub(crate) const fn boot_generation(&self) -> Option<u32> {
        self.boot_generation
    }

    pub(crate) const fn maximum_message_sequence(&self) -> Option<u64> {
        self.maximum_message_sequence
    }

    /// Creates empty replay state for a non-zero bounded packet window.
    pub fn new(window_packets: u16) -> Result<Self, ReplayStateError> {
        if window_packets == 0 {
            return Err(ReplayStateError::EmptyWindow);
        }
        Ok(Self {
            window_packets,
            boot_generation: None,
            maximum_message_sequence: None,
            seen: vec![0; usize::from(window_packets).div_ceil(8)].into_boxed_slice(),
        })
    }

    /// Restores previously committed replay state after validating every invariant.
    pub(crate) fn from_state(state: ReplayState) -> Result<Self, ReplayStateError> {
        if state.window_packets == 0 {
            return Err(ReplayStateError::EmptyWindow);
        }
        if state.seen.len() != usize::from(state.window_packets).div_ceil(8) {
            return Err(ReplayStateError::InvalidBitmap);
        }
        let used_bits = state.window_packets % 8;
        if used_bits != 0 {
            let padding_mask = !((1_u8 << used_bits) - 1);
            if state.seen.last().is_some_and(|byte| byte & padding_mask != 0) {
                return Err(ReplayStateError::InvalidBitmap);
            }
        }
        match (state.boot_generation, state.maximum_message_sequence) {
            (None, None) if state.seen.iter().all(|byte| *byte == 0) => {}
            (Some(boot), Some(sequence))
                if boot != 0 && sequence != 0 && is_seen(&state.seen, 0) => {}
            _ => return Err(ReplayStateError::InvalidState),
        }
        Ok(Self {
            window_packets: state.window_packets,
            boot_generation: state.boot_generation,
            maximum_message_sequence: state.maximum_message_sequence,
            seen: state.seen,
        })
    }

    /// Encodes all replay-window fields needed for restart without secret material.
    pub(crate) fn encode_state(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(REPLAY_STATE_FIXED_BYTES + self.seen.len());
        bytes.push(REPLAY_STATE_VERSION);
        bytes.extend_from_slice(&self.window_packets.to_be_bytes());
        match (self.boot_generation, self.maximum_message_sequence) {
            (Some(boot), Some(sequence)) => {
                bytes.push(1);
                bytes.extend_from_slice(&boot.to_be_bytes());
                bytes.extend_from_slice(&sequence.to_be_bytes());
            }
            (None, None) => {
                bytes.push(0);
                bytes.extend_from_slice(&0_u32.to_be_bytes());
                bytes.extend_from_slice(&0_u64.to_be_bytes());
            }
            _ => unreachable!("ReplayAdmission constructors preserve paired sequence state"),
        }
        bytes.extend_from_slice(&self.seen);
        bytes.into_boxed_slice()
    }

    /// Decodes and validates replay-window state loaded after process restart.
    pub(crate) fn decode_state(bytes: &[u8]) -> Result<Self, ReplayStateError> {
        if bytes.len() < REPLAY_STATE_FIXED_BYTES || bytes[0] != REPLAY_STATE_VERSION {
            return Err(ReplayStateError::InvalidEncoding);
        }
        let window_packets = u16::from_be_bytes([bytes[1], bytes[2]]);
        let bitmap_bytes = usize::from(window_packets).div_ceil(8);
        let expected_bytes = REPLAY_STATE_FIXED_BYTES
            .checked_add(bitmap_bytes)
            .ok_or(ReplayStateError::InvalidEncoding)?;
        if bytes.len() != expected_bytes {
            return Err(ReplayStateError::InvalidEncoding);
        }
        let present = bytes[3];
        let boot_generation =
            u32::from_be_bytes(bytes[4..8].try_into().expect("fixed replay-state boot width"));
        let maximum_message_sequence =
            u64::from_be_bytes(bytes[8..16].try_into().expect("fixed replay-state sequence width"));
        let (boot_generation, maximum_message_sequence) = match present {
            0 if boot_generation == 0 && maximum_message_sequence == 0 => (None, None),
            1 if boot_generation != 0 && maximum_message_sequence != 0 => {
                (Some(boot_generation), Some(maximum_message_sequence))
            }
            _ => return Err(ReplayStateError::InvalidEncoding),
        };
        Self::from_state(ReplayState {
            window_packets,
            boot_generation,
            maximum_message_sequence,
            seen: bytes[REPLAY_STATE_FIXED_BYTES..].into(),
        })
    }

    /// Checks and records one authenticated `(boot_generation, message_sequence)` pair.
    #[must_use]
    pub fn admit(&mut self, boot_generation: u32, message_sequence: u64) -> ReplayDecision {
        if boot_generation == 0 || message_sequence == 0 {
            return ReplayDecision::Rejected;
        }
        match (self.boot_generation, self.maximum_message_sequence) {
            (None, None) => self.begin_boot(boot_generation, message_sequence),
            (Some(previous_boot), Some(_)) if boot_generation > previous_boot => {
                self.begin_boot(boot_generation, message_sequence)
            }
            (Some(previous_boot), Some(_)) if boot_generation < previous_boot => {
                ReplayDecision::Rejected
            }
            (Some(_), Some(previous_maximum)) if message_sequence > previous_maximum => {
                shift_seen(
                    &mut self.seen,
                    message_sequence - previous_maximum,
                    self.window_packets,
                );
                set_seen(&mut self.seen, 0);
                self.maximum_message_sequence = Some(message_sequence);
                ReplayDecision::Accepted
            }
            (Some(_), Some(previous_maximum)) => {
                let age = previous_maximum - message_sequence;
                if age >= u64::from(self.window_packets) || is_seen(&self.seen, age) {
                    ReplayDecision::Rejected
                } else {
                    set_seen(&mut self.seen, age);
                    ReplayDecision::Accepted
                }
            }
            _ => ReplayDecision::Rejected,
        }
    }

    fn begin_boot(&mut self, boot_generation: u32, message_sequence: u64) -> ReplayDecision {
        self.seen.fill(0);
        set_seen(&mut self.seen, 0);
        self.boot_generation = Some(boot_generation);
        self.maximum_message_sequence = Some(message_sequence);
        ReplayDecision::Accepted
    }
}

/// Invalid replay-state construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayStateError {
    /// A replay window cannot contain zero packets.
    #[error("replay window must contain at least one packet")]
    EmptyWindow,
    /// The durable replay bitmap has the wrong length or nonzero padding bits.
    #[error("durable replay bitmap is invalid")]
    InvalidBitmap,
    /// Durable boot, sequence, and bitmap fields disagree.
    #[error("durable replay state is internally inconsistent")]
    InvalidState,
    /// The persisted bytes do not encode one complete replay state.
    #[error("persisted replay state encoding is invalid")]
    InvalidEncoding,
}

fn is_seen(bitmap: &[u8], age: u64) -> bool {
    let Ok(age) = usize::try_from(age) else {
        return false;
    };
    bitmap.get(age / 8).is_some_and(|byte| byte & (1 << (age % 8)) != 0)
}

fn set_seen(bitmap: &mut [u8], age: u64) {
    let age = usize::try_from(age).expect("replay age is bounded by the u16 window size");
    bitmap[age / 8] |= 1 << (age % 8);
}

fn shift_seen(bitmap: &mut [u8], amount: u64, window_packets: u16) {
    if amount >= u64::from(window_packets) {
        bitmap.fill(0);
        return;
    }
    for age in (0..u64::from(window_packets)).rev() {
        let value = age.checked_sub(amount).is_some_and(|source| is_seen(bitmap, source));
        let index = usize::try_from(age).expect("replay age fits usize");
        let mask = 1 << (index % 8);
        if value {
            bitmap[index / 8] |= mask;
        } else {
            bitmap[index / 8] &= !mask;
        }
    }
}
