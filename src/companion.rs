//! One-time paired encrypted companion artifact upload protocol.

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use crate::artifact::{ArtifactImportError, ArtifactRejectReason, ImportedArtifact};

/// Maximum clock exchanges admitted by one pairing handshake.
const MAX_CLOCK_EXCHANGES: usize = 8;
/// Maximum client-observed round-trip uncertainty admitted in nanoseconds.
const MAX_CLOCK_ROUND_TRIP_NS: u64 = 1_000_000_000;
/// Maximum chunks in one bounded upload.
const MAX_UPLOAD_CHUNKS: usize = 1_024;
/// Maximum simultaneous incomplete uploads in one companion session.
const MAX_INCOMPLETE_UPLOADS: usize = 4;
/// Maximum outstanding one-time offers retained by one Host.
const MAX_PAIRING_OFFERS: usize = 4;
/// Maximum simultaneously paired companion sessions retained by one Host.
const MAX_COMPANION_SESSIONS: usize = 8;
/// Canonical encrypted companion chunk frame magic.
const CHUNK_MAGIC: &[u8; 4] = b"WSC1";
/// Fixed companion chunk header before ciphertext.
const CHUNK_HEADER_BYTES: usize = 88;

/// Stable public identity pinned by a companion client.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompanionServerIdentity([u8; 32]);

impl CompanionServerIdentity {
    pub(crate) fn derive(store_id: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"whisper companion server identity v1\0");
        digest.update(store_id);
        Self(digest.finalize().into())
    }

    /// Returns the stable public identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstructs a previously pinned public server identity.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for CompanionServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CompanionServerIdentity({self})")
    }
}

impl fmt::Display for CompanionServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Opaque identity for one one-time pairing offer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PairingId([u8; 16]);

/// Host-displayed one-time companion pairing information.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingOffer {
    pub(crate) id: PairingId,
    pub(crate) code: [u8; 16],
    pub(crate) server_identity: CompanionServerIdentity,
    pub(crate) expires_utc_ns: u64,
}

impl fmt::Debug for PairingOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingOffer")
            .field("id", &self.id)
            .field("code", &"[REDACTED]")
            .field("server_identity", &self.server_identity)
            .field("expires_utc_ns", &self.expires_utc_ns)
            .finish()
    }
}

impl PairingOffer {
    /// Returns the server identity the companion must pin before connecting.
    #[must_use]
    pub const fn server_identity(&self) -> CompanionServerIdentity {
        self.server_identity
    }

    /// Returns the UTC nanosecond at which this offer expires.
    #[must_use]
    pub const fn expires_utc_ns(&self) -> u64 {
        self.expires_utc_ns
    }
}

/// One bounded four-timestamp companion-to-Host clock exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockExchange {
    /// Client send timestamp.
    pub client_send_ns: u64,
    /// Host receive timestamp.
    pub host_receive_ns: u64,
    /// Host reply timestamp.
    pub host_send_ns: u64,
    /// Client receive timestamp.
    pub client_receive_ns: u64,
}

/// Bounded client-clock relation to Host time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompanionClockRelation {
    offset_ns: i64,
    error_ns: u64,
}

impl CompanionClockRelation {
    /// Returns the estimated Host-minus-client offset in nanoseconds.
    #[must_use]
    pub const fn offset_ns(self) -> i64 {
        self.offset_ns
    }

    /// Returns the conservative half-round-trip error in nanoseconds.
    #[must_use]
    pub const fn error_ns(self) -> u64 {
        self.error_ns
    }
}

/// Stable caller-chosen identity for one resumable upload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UploadId([u8; 16]);

impl UploadId {
    /// Creates an upload identity from caller-retained bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Client half of a paired encrypted companion session.
pub struct CompanionConnection {
    session_id: [u8; 16],
    key: [u8; 32],
    server_identity: CompanionServerIdentity,
    clock_relation: CompanionClockRelation,
}

impl fmt::Debug for CompanionConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompanionConnection")
            .field("session_id", &self.session_id)
            .field("key", &"[REDACTED]")
            .field("server_identity", &self.server_identity)
            .field("clock_relation", &self.clock_relation)
            .finish()
    }
}

impl CompanionConnection {
    /// Returns the bounded clock relation established during pairing.
    #[must_use]
    pub const fn clock_relation(&self) -> CompanionClockRelation {
        self.clock_relation
    }

    /// Encrypts exact sealed artifact bytes into bounded resumable chunks.
    ///
    /// # Errors
    ///
    /// Returns an error for empty content, invalid chunk size, too many chunks,
    /// or encryption failure.
    pub fn seal_upload(
        &self,
        upload_id: UploadId,
        sealed_bytes: &[u8],
        chunk_bytes: usize,
    ) -> Result<Vec<CompanionChunk>, CompanionError> {
        if sealed_bytes.is_empty() || chunk_bytes == 0 {
            return Err(CompanionError::new(
                CompanionRejectReason::LimitExceeded,
                "upload and chunk sizes must be non-zero",
            ));
        }
        let chunk_count = sealed_bytes.len().div_ceil(chunk_bytes);
        if chunk_count > MAX_UPLOAD_CHUNKS || chunk_count > u32::MAX as usize {
            return Err(CompanionError::new(
                CompanionRejectReason::LimitExceeded,
                "companion upload chunk limit exceeded",
            ));
        }
        let full_digest: [u8; 32] = Sha256::digest(sealed_bytes).into();
        let total_bytes = u64::try_from(sealed_bytes.len()).map_err(|_| {
            CompanionError::new(CompanionRejectReason::LimitExceeded, "upload size is unsupported")
        })?;
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| crypto_error())?;
        sealed_bytes
            .chunks(chunk_bytes)
            .enumerate()
            .map(|(index, plaintext)| {
                let index = u32::try_from(index).expect("bounded upload index fits u32");
                let chunk_count = u32::try_from(chunk_count).expect("bounded chunk count fits u32");
                let nonce = chunk_nonce(&self.session_id, upload_id, index);
                let aad = chunk_aad(
                    self.server_identity,
                    upload_id,
                    index,
                    chunk_count,
                    total_bytes,
                    &full_digest,
                );
                let ciphertext = cipher
                    .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
                    .map_err(|_| crypto_error())?;
                Ok(CompanionChunk {
                    session_id: self.session_id,
                    upload_id,
                    index,
                    chunk_count,
                    total_bytes,
                    full_digest,
                    ciphertext: ciphertext.into_boxed_slice(),
                })
            })
            .collect()
    }
}

/// One authenticated encrypted chunk of a sealed artifact upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompanionChunk {
    session_id: [u8; 16],
    upload_id: UploadId,
    index: u32,
    chunk_count: u32,
    total_bytes: u64,
    full_digest: [u8; 32],
    ciphertext: Box<[u8]>,
}

impl CompanionChunk {
    /// Encodes this authenticated chunk for transport over the companion channel.
    #[must_use]
    pub fn bytes(&self) -> Box<[u8]> {
        let ciphertext_len =
            u32::try_from(self.ciphertext.len()).expect("bounded encrypted chunk length fits u32");
        let mut bytes = Vec::with_capacity(CHUNK_HEADER_BYTES + self.ciphertext.len());
        bytes.extend_from_slice(CHUNK_MAGIC);
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.upload_id.0);
        bytes.extend_from_slice(&self.index.to_le_bytes());
        bytes.extend_from_slice(&self.chunk_count.to_le_bytes());
        bytes.extend_from_slice(&self.total_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.full_digest);
        bytes.extend_from_slice(&ciphertext_len.to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes.into_boxed_slice()
    }

    pub(crate) fn parse(bytes: &[u8], max_artifact_bytes: usize) -> Result<Self, CompanionError> {
        let maximum_frame = CHUNK_HEADER_BYTES
            .checked_add(max_artifact_bytes)
            .and_then(|length| length.checked_add(16))
            .ok_or_else(limit_error)?;
        if bytes.len() < CHUNK_HEADER_BYTES
            || bytes.len() > maximum_frame
            || &bytes[..4] != CHUNK_MAGIC
        {
            return Err(CompanionError::new(
                CompanionRejectReason::AuthenticationFailed,
                "companion chunk frame is malformed",
            ));
        }
        let ciphertext_len =
            u32::from_le_bytes(bytes[84..88].try_into().expect("fixed ciphertext length field"))
                as usize;
        if bytes.len() != CHUNK_HEADER_BYTES + ciphertext_len {
            return Err(CompanionError::new(
                CompanionRejectReason::AuthenticationFailed,
                "companion chunk frame length is invalid",
            ));
        }
        Ok(Self {
            session_id: bytes[4..20].try_into().expect("fixed session identity"),
            upload_id: UploadId(bytes[20..36].try_into().expect("fixed upload identity")),
            index: u32::from_le_bytes(bytes[36..40].try_into().expect("fixed chunk index")),
            chunk_count: u32::from_le_bytes(bytes[40..44].try_into().expect("fixed chunk count")),
            total_bytes: u64::from_le_bytes(bytes[44..52].try_into().expect("fixed total length")),
            full_digest: bytes[52..84].try_into().expect("fixed upload digest"),
            ciphertext: bytes[88..].into(),
        })
    }
}

/// Result of accepting one companion upload chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UploadProgress {
    /// More chunks are required; exact duplicate chunks are idempotent.
    Pending {
        /// Unique chunks currently retained.
        received_chunks: usize,
        /// Declared total chunk count.
        total_chunks: usize,
    },
    /// The complete sealed artifact was validated and committed as a candidate.
    Imported(ImportedArtifact),
}

/// Fail-closed companion protocol rejection classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompanionRejectReason {
    /// Pairing offer is unknown, already used, or expired.
    PairingUnavailable,
    /// The client pinned a different server identity.
    ServerIdentityMismatch,
    /// Clock samples are absent, malformed, or outside their bound.
    InvalidClockRelation,
    /// Session is unknown or expired.
    SessionUnavailable,
    /// Authentication or encryption failed.
    AuthenticationFailed,
    /// Chunk count, upload count, or byte limit was exceeded.
    LimitExceeded,
    /// A duplicate index or upload identity conflicts with retained content.
    UploadConflict,
    /// The assembled sealed artifact failed the shared import policy.
    ArtifactRejected,
}

/// Failure to pair, authenticate, or assemble a companion upload.
#[derive(Debug)]
pub struct CompanionError {
    reason: CompanionRejectReason,
    message: &'static str,
    backtrace: Box<Backtrace>,
    artifact_reason: Option<ArtifactRejectReason>,
}

impl CompanionError {
    pub(crate) fn new(reason: CompanionRejectReason, message: &'static str) -> Self {
        Self { reason, message, backtrace: Box::new(Backtrace::capture()), artifact_reason: None }
    }

    pub(crate) fn from_artifact(source: ArtifactImportError) -> Self {
        Self {
            reason: CompanionRejectReason::ArtifactRejected,
            message: "assembled companion artifact was rejected",
            backtrace: Box::new(Backtrace::capture()),
            artifact_reason: Some(source.reason()),
        }
    }

    /// Returns the fail-closed rejection classification.
    #[must_use]
    pub const fn reason(&self) -> CompanionRejectReason {
        self.reason
    }

    /// Returns the shared artifact rejection when assembly reached import.
    #[must_use]
    pub const fn artifact_reason(&self) -> Option<ArtifactRejectReason> {
        self.artifact_reason
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for CompanionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for CompanionError {}

#[derive(Debug)]
pub(crate) struct CompanionState {
    server_identity: CompanionServerIdentity,
    offers: BTreeMap<PairingId, PairingOffer>,
    sessions: BTreeMap<[u8; 16], ServerSession>,
}

#[derive(Debug)]
struct ServerSession {
    key: [u8; 32],
    expires_utc_ns: u64,
    uploads: BTreeMap<UploadId, IncompleteUpload>,
}

#[derive(Debug)]
struct IncompleteUpload {
    chunk_count: u32,
    total_bytes: u64,
    full_digest: [u8; 32],
    chunks: BTreeMap<u32, Box<[u8]>>,
}

pub(crate) struct AssembledUpload {
    pub(crate) bytes: Box<[u8]>,
    pub(crate) received_chunks: usize,
    pub(crate) total_chunks: usize,
}

impl CompanionState {
    pub(crate) fn new(server_identity: CompanionServerIdentity) -> Self {
        Self { server_identity, offers: BTreeMap::new(), sessions: BTreeMap::new() }
    }

    pub(crate) const fn server_identity(&self) -> CompanionServerIdentity {
        self.server_identity
    }

    pub(crate) fn offer(
        &mut self,
        now_utc_ns: u64,
        id: [u8; 16],
        code: [u8; 16],
        expires_utc_ns: u64,
    ) -> Result<PairingOffer, CompanionError> {
        self.offers.retain(|_, offer| offer.expires_utc_ns >= now_utc_ns);
        self.sessions.retain(|_, session| session.expires_utc_ns >= now_utc_ns);
        if self.offers.len() >= MAX_PAIRING_OFFERS {
            return Err(CompanionError::new(
                CompanionRejectReason::LimitExceeded,
                "outstanding companion pairing offer limit exceeded",
            ));
        }
        let offer = PairingOffer {
            id: PairingId(id),
            code,
            server_identity: self.server_identity,
            expires_utc_ns,
        };
        self.offers.insert(offer.id, offer.clone());
        Ok(offer)
    }

    pub(crate) fn connect(
        &mut self,
        offered: &PairingOffer,
        pinned: CompanionServerIdentity,
        exchanges: &[ClockExchange],
        now_utc_ns: u64,
        session_id: [u8; 16],
    ) -> Result<CompanionConnection, CompanionError> {
        if pinned != self.server_identity || offered.server_identity != self.server_identity {
            return Err(CompanionError::new(
                CompanionRejectReason::ServerIdentityMismatch,
                "companion server identity does not match the pinned identity",
            ));
        }
        let retained = self.offers.get(&offered.id).ok_or_else(|| {
            CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is unavailable",
            )
        })?;
        if retained != offered || retained.expires_utc_ns < now_utc_ns {
            return Err(CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is invalid or expired",
            ));
        }
        let clock_relation = estimate_clock_relation(exchanges)?;
        self.sessions.retain(|_, session| session.expires_utc_ns >= now_utc_ns);
        if self.sessions.len() >= MAX_COMPANION_SESSIONS {
            return Err(CompanionError::new(
                CompanionRejectReason::LimitExceeded,
                "paired companion session limit exceeded",
            ));
        }
        let key = session_key(&offered.code, &offered.id, self.server_identity, &session_id);
        self.offers.remove(&offered.id);
        self.sessions.insert(
            session_id,
            ServerSession { key, expires_utc_ns: offered.expires_utc_ns, uploads: BTreeMap::new() },
        );
        Ok(CompanionConnection {
            session_id,
            key,
            server_identity: self.server_identity,
            clock_relation,
        })
    }

    pub(crate) fn accept_chunk(
        &mut self,
        chunk: CompanionChunk,
        now_utc_ns: u64,
        max_bytes: usize,
    ) -> Result<AssembledUpload, CompanionError> {
        let session = self.sessions.get_mut(&chunk.session_id).ok_or_else(|| {
            CompanionError::new(
                CompanionRejectReason::SessionUnavailable,
                "companion session is unavailable",
            )
        })?;
        if session.expires_utc_ns < now_utc_ns {
            self.sessions.remove(&chunk.session_id);
            return Err(CompanionError::new(
                CompanionRejectReason::SessionUnavailable,
                "companion session expired",
            ));
        }
        let count = usize::try_from(chunk.chunk_count).expect("u32 fits usize on supported hosts");
        let total = usize::try_from(chunk.total_bytes).map_err(|_| limit_error())?;
        if count == 0
            || count > MAX_UPLOAD_CHUNKS
            || chunk.index >= chunk.chunk_count
            || total > max_bytes
        {
            return Err(limit_error());
        }
        let nonce = chunk_nonce(&chunk.session_id, chunk.upload_id, chunk.index);
        let aad = chunk_aad(
            self.server_identity,
            chunk.upload_id,
            chunk.index,
            chunk.chunk_count,
            chunk.total_bytes,
            &chunk.full_digest,
        );
        let cipher = Aes256Gcm::new_from_slice(&session.key).map_err(|_| crypto_error())?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &chunk.ciphertext, aad: &aad })
            .map_err(|_| crypto_error())?
            .into_boxed_slice();
        if !session.uploads.contains_key(&chunk.upload_id)
            && session.uploads.len() >= MAX_INCOMPLETE_UPLOADS
        {
            return Err(limit_error());
        }
        let upload = match session.uploads.entry(chunk.upload_id) {
            Entry::Vacant(entry) => entry.insert(IncompleteUpload {
                chunk_count: chunk.chunk_count,
                total_bytes: chunk.total_bytes,
                full_digest: chunk.full_digest,
                chunks: BTreeMap::new(),
            }),
            Entry::Occupied(entry) => {
                let upload = entry.into_mut();
                if upload.chunk_count != chunk.chunk_count
                    || upload.total_bytes != chunk.total_bytes
                    || upload.full_digest != chunk.full_digest
                {
                    return Err(conflict_error());
                }
                upload
            }
        };
        match upload.chunks.entry(chunk.index) {
            Entry::Vacant(entry) => {
                entry.insert(plaintext);
            }
            Entry::Occupied(entry) if entry.get().as_ref() == plaintext.as_ref() => {}
            Entry::Occupied(_) => return Err(conflict_error()),
        }
        let received_chunks = upload.chunks.len();
        if received_chunks != count {
            return Ok(AssembledUpload {
                bytes: Box::new([]),
                received_chunks,
                total_chunks: count,
            });
        }
        let mut bytes = Vec::with_capacity(total);
        for index in 0..chunk.chunk_count {
            let part = upload.chunks.get(&index).ok_or_else(conflict_error)?;
            bytes.extend_from_slice(part);
        }
        if bytes.len() != total || <[u8; 32]>::from(Sha256::digest(&bytes)) != upload.full_digest {
            return Err(conflict_error());
        }
        session.uploads.remove(&chunk.upload_id);
        Ok(AssembledUpload {
            bytes: bytes.into_boxed_slice(),
            received_chunks,
            total_chunks: count,
        })
    }
}

fn estimate_clock_relation(
    exchanges: &[ClockExchange],
) -> Result<CompanionClockRelation, CompanionError> {
    if exchanges.is_empty() || exchanges.len() > MAX_CLOCK_EXCHANGES {
        return Err(clock_error());
    }
    let mut best = None;
    for exchange in exchanges {
        if exchange.client_receive_ns < exchange.client_send_ns
            || exchange.host_send_ns < exchange.host_receive_ns
        {
            return Err(clock_error());
        }
        let client_elapsed = exchange.client_receive_ns - exchange.client_send_ns;
        let host_elapsed = exchange.host_send_ns - exchange.host_receive_ns;
        if host_elapsed > client_elapsed {
            return Err(clock_error());
        }
        let network_round_trip = client_elapsed - host_elapsed;
        if network_round_trip > MAX_CLOCK_ROUND_TRIP_NS {
            return Err(clock_error());
        }
        let left = i128::from(exchange.host_receive_ns) - i128::from(exchange.client_send_ns);
        let right = i128::from(exchange.host_send_ns) - i128::from(exchange.client_receive_ns);
        let offset = (left + right) / 2;
        let offset = i64::try_from(offset).map_err(|_| clock_error())?;
        let relation =
            CompanionClockRelation { offset_ns: offset, error_ns: network_round_trip.div_ceil(2) };
        if best.is_none_or(|current: CompanionClockRelation| relation.error_ns < current.error_ns) {
            best = Some(relation);
        }
    }
    best.ok_or_else(clock_error)
}

fn session_key(
    code: &[u8; 16],
    pairing_id: &PairingId,
    server: CompanionServerIdentity,
    session_id: &[u8; 16],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"whisper companion session key v1\0");
    digest.update(code);
    digest.update(pairing_id.0);
    digest.update(server.0);
    digest.update(session_id);
    digest.finalize().into()
}

fn chunk_nonce(session_id: &[u8; 16], upload_id: UploadId, index: u32) -> [u8; 12] {
    let mut digest = Sha256::new();
    digest.update(b"whisper companion chunk nonce v1\0");
    digest.update(session_id);
    digest.update(upload_id.0);
    digest.update(index.to_le_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    digest[..12].try_into().expect("fixed nonce prefix")
}

fn chunk_aad(
    server: CompanionServerIdentity,
    upload_id: UploadId,
    index: u32,
    count: u32,
    total: u64,
    digest: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(96);
    aad.extend_from_slice(b"whisper companion chunk v1\0");
    aad.extend_from_slice(&server.0);
    aad.extend_from_slice(&upload_id.0);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&count.to_le_bytes());
    aad.extend_from_slice(&total.to_le_bytes());
    aad.extend_from_slice(digest);
    aad
}

fn clock_error() -> CompanionError {
    CompanionError::new(
        CompanionRejectReason::InvalidClockRelation,
        "companion clock exchanges are invalid or exceed the round-trip bound",
    )
}

fn crypto_error() -> CompanionError {
    CompanionError::new(
        CompanionRejectReason::AuthenticationFailed,
        "companion encrypted chunk authentication failed",
    )
}

fn limit_error() -> CompanionError {
    CompanionError::new(CompanionRejectReason::LimitExceeded, "companion upload limit exceeded")
}

fn conflict_error() -> CompanionError {
    CompanionError::new(
        CompanionRejectReason::UploadConflict,
        "companion upload conflicts with retained chunks",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_and_connection_debug_output_redacts_secrets() {
        let mut state = CompanionState::new(CompanionServerIdentity::from_bytes([2; 32]));
        let code = [7; 16];
        let offer = state.offer(10, [3; 16], code, 100).unwrap();
        assert!(!format!("{offer:?}").contains(&format!("{code:?}")));
        let connection = state
            .connect(
                &offer,
                offer.server_identity(),
                &[ClockExchange {
                    client_send_ns: 10,
                    host_receive_ns: 20,
                    host_send_ns: 21,
                    client_receive_ns: 31,
                }],
                11,
                [4; 16],
            )
            .unwrap();
        assert!(!format!("{connection:?}").contains(&format!("{:?}", connection.key)));
    }
}
