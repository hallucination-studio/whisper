//! One-time paired encrypted companion artifact upload protocol.

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::artifact::{
    ArtifactImportError, ArtifactRejectReason, ClockErrorNanoseconds, ClockOffsetNanoseconds,
    HostNanoseconds, ImportedArtifact, PhoneNanoseconds, PhoneTimeRelation, UtcNanoseconds,
};

/// Maximum clock exchanges admitted by one pairing handshake.
const MAX_CLOCK_EXCHANGES: usize = 8;
/// Minimum separated samples needed to estimate both offset and drift.
const MIN_CLOCK_EXCHANGES: usize = 3;
/// Maximum client-observed round-trip uncertainty admitted in nanoseconds.
const MAX_CLOCK_ROUND_TRIP_NS: u64 = 1_000_000_000;
/// Maximum chunks in one bounded upload.
const MAX_UPLOAD_CHUNKS: usize = 1_024;
/// Maximum simultaneous incomplete uploads in one companion session.
const MAX_INCOMPLETE_UPLOADS: usize = 4;
/// Maximum acknowledged uploads retained for lost-final-response retries.
const MAX_COMPLETED_UPLOADS: usize = 16;
/// Maximum outstanding one-time offers retained by one Host.
const MAX_PAIRING_OFFERS: usize = 4;
/// Maximum simultaneously paired companion sessions retained by one Host.
const MAX_COMPANION_SESSIONS: usize = 8;
/// Canonical encrypted companion chunk frame magic.
const CHUNK_MAGIC: &[u8; 4] = b"WSC1";
/// Fixed companion chunk header before ciphertext.
const CHUNK_HEADER_BYTES: usize = 88;
/// Maximum plaintext carried by one independently authenticated chunk (64 KiB).
const MAX_COMPANION_CHUNK_BYTES: usize = 64 * 1024;
const OFFER_WIRE_MAGIC: &[u8; 4] = b"WSO1";
const CHALLENGE_WIRE_MAGIC: &[u8; 4] = b"WSH1";
const CLOCK_RESPONSE_WIRE_MAGIC: &[u8; 4] = b"WSR1";
const HANDSHAKE_REQUEST_WIRE_MAGIC: &[u8; 4] = b"WSQ1";
const HANDSHAKE_RESPONSE_WIRE_MAGIC: &[u8; 4] = b"WSK1";
const OFFER_WIRE_BYTES: usize = 140;
const CHALLENGE_WIRE_BYTES: usize = 140;
const CLOCK_RESPONSE_WIRE_BYTES: usize = 152;
const HANDSHAKE_RESPONSE_WIRE_BYTES: usize = 148;

/// Injectable cryptographic entropy boundary for companion pairing and sessions.
pub trait CompanionEntropy: Send + Sync {
    /// Fills the complete output buffer with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns the platform or injected entropy failure without partial success.
    fn fill(&self, output: &mut [u8]) -> std::io::Result<()>;
}

/// Tier-1 platform cryptographic entropy used by default.
#[derive(Debug)]
pub struct SystemCompanionEntropy;

impl CompanionEntropy for SystemCompanionEntropy {
    fn fill(&self, output: &mut [u8]) -> std::io::Result<()> {
        getrandom::fill(output).map_err(std::io::Error::other)
    }
}

/// Stable public identity pinned by a companion client.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompanionServerIdentity([u8; 32]);

impl CompanionServerIdentity {
    pub(crate) fn from_signing_key(key: &SigningKey) -> Self {
        Self(key.verifying_key().to_bytes())
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

impl PairingId {
    /// Returns the opaque pairing identity bytes for a transport handshake.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// One-time secret displayed locally by the Host for companion pairing.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PairingCode([u8; 16]);

impl fmt::Debug for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingCode([REDACTED])")
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl PairingCode {
    /// Formats the one-time code for the explicit local display surface.
    #[must_use]
    pub fn format_for_display(self) -> String {
        let mut displayed = String::with_capacity(39);
        use std::fmt::Write as _;
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 && index.is_multiple_of(2) {
                displayed.push('-');
            }
            write!(displayed, "{byte:02x}").expect("writing to String is infallible");
        }
        displayed
    }
    /// Returns the one-time secret bytes for a client-side key derivation.
    ///
    /// Callers must avoid logging or persisting this value after pairing.
    #[must_use]
    pub const fn expose_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Client-generated nonce binding one authenticated handshake response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientNonce([u8; 32]);

impl ClientNonce {
    /// Creates a nonce from client-generated random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Host-displayed one-time companion pairing information.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingOffer {
    pub(crate) id: PairingId,
    pub(crate) code: PairingCode,
    pub(crate) server_identity: CompanionServerIdentity,
    pub(crate) expires_at_utc: UtcNanoseconds,
    pub(crate) server_proof: [u8; 64],
}

impl fmt::Debug for PairingOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingOffer")
            .field("id", &self.id)
            .field("code", &"[REDACTED]")
            .field("server_identity", &self.server_identity)
            .field("expires_at_utc", &self.expires_at_utc)
            .field("server_proof", &self.server_proof)
            .finish()
    }
}

impl PairingOffer {
    /// Returns the public pairing identity sent in the handshake request.
    #[must_use]
    pub const fn pairing_id(&self) -> PairingId {
        self.id
    }

    /// Returns the one-time code intended for local display or QR transfer.
    #[must_use]
    pub const fn display_code(&self) -> PairingCode {
        self.code
    }
    /// Returns the server identity the companion must pin before connecting.
    #[must_use]
    pub const fn server_identity(&self) -> CompanionServerIdentity {
        self.server_identity
    }

    /// Returns the UTC nanosecond at which this offer expires.
    #[must_use]
    pub const fn expires_at_utc(&self) -> UtcNanoseconds {
        self.expires_at_utc
    }

    /// Verifies that the pinned persistent server signed this complete offer.
    ///
    /// # Errors
    ///
    /// Returns an error if the pin differs or the Ed25519 proof is invalid.
    pub fn verify_server_proof(
        &self,
        pinned: CompanionServerIdentity,
    ) -> Result<(), CompanionError> {
        if pinned != self.server_identity {
            return Err(CompanionError::new(
                CompanionRejectReason::ServerIdentityMismatch,
                "pairing offer server identity differs from the pin",
            ));
        }
        let key = VerifyingKey::from_bytes(self.server_identity.as_bytes())
            .map_err(CompanionError::signature)?;
        key.verify_strict(&offer_transcript(self), &Signature::from_bytes(&self.server_proof))
            .map_err(CompanionError::signature)
    }

    /// Encodes the complete signed offer for an arbitrary byte transport.
    #[must_use]
    pub fn to_wire(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(OFFER_WIRE_BYTES);
        bytes.extend_from_slice(OFFER_WIRE_MAGIC);
        bytes.extend_from_slice(&self.id.0);
        bytes.extend_from_slice(&self.code.0);
        bytes.extend_from_slice(&self.server_identity.0);
        bytes.extend_from_slice(&self.expires_at_utc.get().to_le_bytes());
        bytes.extend_from_slice(&self.server_proof);
        bytes.into_boxed_slice()
    }

    /// Reconstructs and authenticates a signed offer received over any transport.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed encoding, wrong pin, or invalid proof.
    pub fn from_wire(
        bytes: &[u8],
        pinned: CompanionServerIdentity,
    ) -> Result<Self, CompanionError> {
        if bytes.len() != OFFER_WIRE_BYTES || &bytes[..4] != OFFER_WIRE_MAGIC {
            return Err(authentication_error("pairing offer wire encoding is malformed"));
        }
        let offer = Self {
            id: PairingId(bytes[4..20].try_into().expect("fixed pairing id")),
            code: PairingCode(bytes[20..36].try_into().expect("fixed pairing code")),
            server_identity: CompanionServerIdentity(
                bytes[36..68].try_into().expect("fixed identity"),
            ),
            expires_at_utc: u64::from_le_bytes(bytes[68..76].try_into().expect("fixed expiry"))
                .into(),
            server_proof: bytes[76..140].try_into().expect("fixed offer proof"),
        };
        offer.verify_server_proof(pinned)?;
        Ok(offer)
    }

    /// Builds the authenticated client request after collecting clock responses.
    #[must_use]
    pub fn handshake_request(
        &self,
        client_nonce: ClientNonce,
        clock_responses: Vec<ClockSampleResponse>,
    ) -> CompanionHandshakeRequest {
        CompanionHandshakeRequest {
            pairing_id: self.id,
            pairing_code: self.code,
            pinned_server_identity: self.server_identity,
            client_nonce,
            clock_responses,
        }
    }
}

/// Signed Host timing challenge returned for one client send timestamp.
#[derive(Clone, Eq, PartialEq)]
pub struct ClockSampleChallenge {
    pairing_id: PairingId,
    client_nonce: ClientNonce,
    client_send: PhoneNanoseconds,
    host_receive: HostNanoseconds,
    host_send: HostNanoseconds,
    server_proof: [u8; 64],
}

impl fmt::Debug for ClockSampleChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClockSampleChallenge")
            .field("pairing_id", &self.pairing_id)
            .field("client_nonce", &self.client_nonce)
            .field("client_send", &self.client_send)
            .field("host_receive", &self.host_receive)
            .field("host_send", &self.host_send)
            .field("server_proof", &self.server_proof)
            .finish()
    }
}

impl ClockSampleChallenge {
    /// Encodes this signed challenge for an arbitrary byte transport.
    #[must_use]
    pub fn to_wire(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(CHALLENGE_WIRE_BYTES);
        bytes.extend_from_slice(CHALLENGE_WIRE_MAGIC);
        bytes.extend_from_slice(&self.pairing_id.0);
        bytes.extend_from_slice(&self.client_nonce.0);
        bytes.extend_from_slice(&self.client_send.get().to_le_bytes());
        bytes.extend_from_slice(&self.host_receive.get().to_le_bytes());
        bytes.extend_from_slice(&self.host_send.get().to_le_bytes());
        bytes.extend_from_slice(&self.server_proof);
        bytes.into_boxed_slice()
    }

    /// Reconstructs and authenticates a signed challenge from any byte transport.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes, a wrong pin, or a forged Host time.
    pub fn from_wire(
        bytes: &[u8],
        pinned: CompanionServerIdentity,
    ) -> Result<Self, CompanionError> {
        if bytes.len() != CHALLENGE_WIRE_BYTES || &bytes[..4] != CHALLENGE_WIRE_MAGIC {
            return Err(authentication_error("clock challenge wire encoding is malformed"));
        }
        let challenge = Self {
            pairing_id: PairingId(bytes[4..20].try_into().expect("fixed pairing id")),
            client_nonce: ClientNonce(bytes[20..52].try_into().expect("fixed client nonce")),
            client_send: u64::from_le_bytes(bytes[52..60].try_into().expect("fixed phone time"))
                .into(),
            host_receive: u64::from_le_bytes(bytes[60..68].try_into().expect("fixed Host time"))
                .into(),
            host_send: u64::from_le_bytes(bytes[68..76].try_into().expect("fixed Host time"))
                .into(),
            server_proof: bytes[76..140].try_into().expect("fixed challenge proof"),
        };
        let key = VerifyingKey::from_bytes(pinned.as_bytes()).map_err(CompanionError::signature)?;
        key.verify_strict(
            &challenge_transcript(&challenge),
            &Signature::from_bytes(&challenge.server_proof),
        )
        .map_err(CompanionError::signature)?;
        Ok(challenge)
    }
}

/// Client completion of one signed two-way clock sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockSampleResponse {
    challenge: ClockSampleChallenge,
    client_receive: PhoneNanoseconds,
}

impl ClockSampleResponse {
    /// Completes a challenge with the independently measured phone receive time.
    #[must_use]
    pub const fn new(challenge: ClockSampleChallenge, client_receive: PhoneNanoseconds) -> Self {
        Self { challenge, client_receive }
    }

    /// Encodes the complete sample for an arbitrary byte transport.
    #[must_use]
    pub fn to_wire(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(CLOCK_RESPONSE_WIRE_BYTES);
        bytes.extend_from_slice(CLOCK_RESPONSE_WIRE_MAGIC);
        bytes.extend_from_slice(&self.challenge.to_wire());
        bytes.extend_from_slice(&self.client_receive.get().to_le_bytes());
        bytes.into_boxed_slice()
    }

    /// Reconstructs a clock response received over any transport.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed canonical encoding.
    pub fn from_wire(
        bytes: &[u8],
        pinned: CompanionServerIdentity,
    ) -> Result<Self, CompanionError> {
        if bytes.len() != CLOCK_RESPONSE_WIRE_BYTES || &bytes[..4] != CLOCK_RESPONSE_WIRE_MAGIC {
            return Err(authentication_error("clock response wire encoding is malformed"));
        }
        Ok(Self {
            challenge: ClockSampleChallenge::from_wire(&bytes[4..144], pinned)?,
            client_receive: u64::from_le_bytes(
                bytes[144..152].try_into().expect("fixed phone time"),
            )
            .into(),
        })
    }
}

/// Canonical client request that proves code possession and carries signed samples.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompanionHandshakeRequest {
    pairing_id: PairingId,
    pairing_code: PairingCode,
    pinned_server_identity: CompanionServerIdentity,
    client_nonce: ClientNonce,
    clock_responses: Vec<ClockSampleResponse>,
}

impl CompanionHandshakeRequest {
    /// Encodes the request for an arbitrary byte transport.
    #[must_use]
    pub fn to_wire(&self) -> Box<[u8]> {
        let mut bytes =
            Vec::with_capacity(88 + self.clock_responses.len() * CLOCK_RESPONSE_WIRE_BYTES);
        bytes.extend_from_slice(HANDSHAKE_REQUEST_WIRE_MAGIC);
        bytes.extend_from_slice(&self.pairing_id.0);
        bytes.extend_from_slice(&self.pairing_code.0);
        bytes.extend_from_slice(&self.pinned_server_identity.0);
        bytes.extend_from_slice(&self.client_nonce.0);
        bytes.extend_from_slice(&(self.clock_responses.len() as u32).to_le_bytes());
        for response in &self.clock_responses {
            bytes.extend_from_slice(&response.to_wire());
        }
        bytes.into_boxed_slice()
    }

    /// Reconstructs a bounded handshake request from any byte transport.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed lengths or an out-of-bounds sample count.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, CompanionError> {
        const HEADER: usize = 104;
        if bytes.len() < HEADER || &bytes[..4] != HANDSHAKE_REQUEST_WIRE_MAGIC {
            return Err(authentication_error("handshake request wire encoding is malformed"));
        }
        let count =
            u32::from_le_bytes(bytes[100..104].try_into().expect("fixed sample count")) as usize;
        if !(MIN_CLOCK_EXCHANGES..=MAX_CLOCK_EXCHANGES).contains(&count)
            || bytes.len() != HEADER + count * CLOCK_RESPONSE_WIRE_BYTES
        {
            return Err(clock_error());
        }
        let pinned_server_identity =
            CompanionServerIdentity(bytes[36..68].try_into().expect("fixed identity"));
        let mut clock_responses = Vec::with_capacity(count);
        for chunk in bytes[HEADER..].chunks_exact(CLOCK_RESPONSE_WIRE_BYTES) {
            clock_responses.push(ClockSampleResponse::from_wire(chunk, pinned_server_identity)?);
        }
        Ok(Self {
            pairing_id: PairingId(bytes[4..20].try_into().expect("fixed pairing id")),
            pairing_code: PairingCode(bytes[20..36].try_into().expect("fixed pairing code")),
            pinned_server_identity,
            client_nonce: ClientNonce(bytes[68..100].try_into().expect("fixed client nonce")),
            clock_responses,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClockExchange {
    /// Client send timestamp.
    pub client_send: PhoneNanoseconds,
    /// Host receive timestamp.
    pub host_receive: HostNanoseconds,
    /// Host reply timestamp.
    pub host_send: HostNanoseconds,
    /// Client receive timestamp.
    pub client_receive: PhoneNanoseconds,
}

pub(crate) struct ClockChallengeMeasurement {
    pub(crate) now_utc: UtcNanoseconds,
    pub(crate) client_send: PhoneNanoseconds,
    pub(crate) host_receive: HostNanoseconds,
    pub(crate) host_send: HostNanoseconds,
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

/// Signed server response from which the phone independently constructs its session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompanionHandshakeResponse {
    session_id: [u8; 16],
    clock_relation: PhoneTimeRelation,
    server_proof: [u8; 64],
}

impl CompanionHandshakeResponse {
    /// Encodes the signed response for an arbitrary byte transport.
    #[must_use]
    pub fn to_wire(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(HANDSHAKE_RESPONSE_WIRE_BYTES);
        bytes.extend_from_slice(HANDSHAKE_RESPONSE_WIRE_MAGIC);
        bytes.extend_from_slice(&self.session_id);
        encode_relation(&mut bytes, self.clock_relation);
        bytes.extend_from_slice(&self.server_proof);
        bytes.into_boxed_slice()
    }

    /// Reconstructs the canonical response from any byte transport.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes or an invalid clock relation.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, CompanionError> {
        if bytes.len() != HANDSHAKE_RESPONSE_WIRE_BYTES
            || &bytes[..4] != HANDSHAKE_RESPONSE_WIRE_MAGIC
        {
            return Err(authentication_error("handshake response wire encoding is malformed"));
        }
        Ok(Self {
            session_id: bytes[4..20].try_into().expect("fixed session id"),
            clock_relation: decode_relation(&bytes[20..84])?,
            server_proof: bytes[84..148].try_into().expect("fixed response proof"),
        })
    }
}

/// Client half of a paired encrypted companion session.
pub struct CompanionConnection {
    session_id: [u8; 16],
    key: [u8; 32],
    server_identity: CompanionServerIdentity,
    clock_relation: PhoneTimeRelation,
    client_nonce: ClientNonce,
    server_proof: [u8; 64],
}

impl fmt::Debug for CompanionConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompanionConnection")
            .field("session_id", &self.session_id)
            .field("key", &"[REDACTED]")
            .field("server_identity", &self.server_identity)
            .field("clock_relation", &self.clock_relation)
            .field("client_nonce", &self.client_nonce)
            .field("server_proof", &self.server_proof)
            .finish()
    }
}

impl CompanionConnection {
    /// Independently constructs the phone session from a signed wire response.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed server proof or response relation is invalid.
    pub fn from_handshake(
        offer: &PairingOffer,
        client_nonce: ClientNonce,
        response: CompanionHandshakeResponse,
    ) -> Result<Self, CompanionError> {
        let key = session_key(
            offer.code.expose_bytes(),
            &offer.id,
            offer.server_identity,
            &response.session_id,
            client_nonce,
        );
        let connection = Self {
            session_id: response.session_id,
            key,
            server_identity: offer.server_identity,
            clock_relation: response.clock_relation,
            client_nonce,
            server_proof: response.server_proof,
        };
        connection.verify_server_proof()?;
        Ok(connection)
    }
    /// Verifies the persistent server's client-nonce-bound handshake proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed identity or response proof is invalid.
    pub fn verify_server_proof(&self) -> Result<(), CompanionError> {
        let key = VerifyingKey::from_bytes(self.server_identity.as_bytes())
            .map_err(CompanionError::signature)?;
        key.verify_strict(
            &connection_transcript(
                self.server_identity,
                &self.session_id,
                self.client_nonce,
                self.clock_relation,
            ),
            &Signature::from_bytes(&self.server_proof),
        )
        .map_err(CompanionError::signature)
    }
    /// Returns the bounded clock relation established during pairing.
    #[must_use]
    pub const fn clock_relation(&self) -> PhoneTimeRelation {
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
        if sealed_bytes.is_empty() || chunk_bytes == 0 || chunk_bytes > MAX_COMPANION_CHUNK_BYTES {
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
            .checked_add(max_artifact_bytes.min(MAX_COMPANION_CHUNK_BYTES))
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
    kind: Box<CompanionErrorKind>,
    backtrace: Box<Backtrace>,
}

#[derive(Debug, thiserror::Error)]
enum CompanionErrorKind {
    #[error("{message}")]
    Rejected { reason: CompanionRejectReason, message: &'static str },
    #[error("companion entropy failed: {0}")]
    Entropy(#[source] std::io::Error),
    #[error("companion server proof failed: {0}")]
    Signature(#[source] ed25519_dalek::SignatureError),
    #[error("companion artifact import failed: {0}")]
    Artifact(#[source] ArtifactImportError),
}

impl CompanionError {
    pub(crate) fn new(reason: CompanionRejectReason, message: &'static str) -> Self {
        Self {
            kind: Box::new(CompanionErrorKind::Rejected { reason, message }),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    pub(crate) fn entropy(source: std::io::Error) -> Self {
        Self {
            kind: Box::new(CompanionErrorKind::Entropy(source)),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    fn signature(source: ed25519_dalek::SignatureError) -> Self {
        Self {
            kind: Box::new(CompanionErrorKind::Signature(source)),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    pub(crate) fn from_artifact(source: ArtifactImportError) -> Self {
        Self {
            kind: Box::new(CompanionErrorKind::Artifact(source)),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    /// Returns the fail-closed rejection classification.
    #[must_use]
    pub fn reason(&self) -> CompanionRejectReason {
        match self.kind.as_ref() {
            CompanionErrorKind::Rejected { reason, .. } => *reason,
            CompanionErrorKind::Entropy(_) | CompanionErrorKind::Signature(_) => {
                CompanionRejectReason::AuthenticationFailed
            }
            CompanionErrorKind::Artifact(_) => CompanionRejectReason::ArtifactRejected,
        }
    }

    /// Returns the shared artifact rejection when assembly reached import.
    #[must_use]
    pub fn artifact_reason(&self) -> Option<ArtifactRejectReason> {
        match self.kind.as_ref() {
            CompanionErrorKind::Artifact(source) => Some(source.reason()),
            CompanionErrorKind::Rejected { .. }
            | CompanionErrorKind::Entropy(_)
            | CompanionErrorKind::Signature(_) => None,
        }
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for CompanionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for CompanionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.kind.as_ref())
    }
}

pub(crate) struct CompanionState {
    signing_key: SigningKey,
    server_identity: CompanionServerIdentity,
    offers: BTreeMap<PairingId, PairingOffer>,
    sessions: BTreeMap<[u8; 16], ServerSession>,
}

struct ServerSession {
    key: [u8; 32],
    clock_relation: PhoneTimeRelation,
    expires_at_utc: UtcNanoseconds,
    uploads: BTreeMap<UploadId, IncompleteUpload>,
    completed: BTreeMap<UploadId, CompletedUpload>,
}

impl fmt::Debug for CompanionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompanionState")
            .field("signing_key", &"[REDACTED]")
            .field("server_identity", &self.server_identity)
            .field("offer_count", &self.offers.len())
            .field("session_count", &self.sessions.len())
            .finish()
    }
}

impl fmt::Debug for ServerSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerSession")
            .field("key", &"[REDACTED]")
            .field("clock_relation", &self.clock_relation)
            .field("expires_at_utc", &self.expires_at_utc)
            .field("incomplete_upload_count", &self.uploads.len())
            .field("completed_upload_count", &self.completed.len())
            .finish()
    }
}

#[derive(Debug)]
struct CompletedUpload {
    chunk_count: u32,
    total_bytes: u64,
    full_digest: [u8; 32],
    receipt: ImportedArtifact,
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
    pub(crate) session_id: [u8; 16],
    pub(crate) upload_id: UploadId,
    pub(crate) full_digest: [u8; 32],
    pub(crate) completed_receipt: Option<ImportedArtifact>,
    pub(crate) clock_relation: PhoneTimeRelation,
}

impl CompanionState {
    pub(crate) fn new(signing_seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let server_identity = CompanionServerIdentity::from_signing_key(&signing_key);
        Self { signing_key, server_identity, offers: BTreeMap::new(), sessions: BTreeMap::new() }
    }

    pub(crate) const fn server_identity(&self) -> CompanionServerIdentity {
        self.server_identity
    }

    pub(crate) fn offer(
        &mut self,
        now_utc: UtcNanoseconds,
        id: [u8; 16],
        code: [u8; 16],
        expires_at_utc: UtcNanoseconds,
    ) -> Result<PairingOffer, CompanionError> {
        self.offers.retain(|_, offer| offer.expires_at_utc >= now_utc);
        self.sessions.retain(|_, session| session.expires_at_utc >= now_utc);
        if self.offers.len() >= MAX_PAIRING_OFFERS {
            return Err(CompanionError::new(
                CompanionRejectReason::LimitExceeded,
                "outstanding companion pairing offer limit exceeded",
            ));
        }
        let mut offer = PairingOffer {
            id: PairingId(id),
            code: PairingCode(code),
            server_identity: self.server_identity,
            expires_at_utc,
            server_proof: [0; 64],
        };
        use ed25519_dalek::Signer;
        offer.server_proof = self.signing_key.sign(&offer_transcript(&offer)).to_bytes();
        self.offers.insert(offer.id, offer.clone());
        Ok(offer)
    }

    pub(crate) fn clock_challenge(
        &mut self,
        pairing_id: PairingId,
        pinned: CompanionServerIdentity,
        client_nonce: ClientNonce,
        measurement: ClockChallengeMeasurement,
    ) -> Result<ClockSampleChallenge, CompanionError> {
        if pinned != self.server_identity {
            return Err(CompanionError::new(
                CompanionRejectReason::ServerIdentityMismatch,
                "companion server identity does not match the pinned identity",
            ));
        }
        let offer = self.offers.get(&pairing_id).ok_or_else(|| {
            CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is unavailable",
            )
        })?;
        if offer.expires_at_utc < measurement.now_utc {
            return Err(CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is expired",
            ));
        }
        let mut challenge = ClockSampleChallenge {
            pairing_id,
            client_nonce,
            client_send: measurement.client_send,
            host_receive: measurement.host_receive,
            host_send: measurement.host_send,
            server_proof: [0; 64],
        };
        use ed25519_dalek::Signer;
        challenge.server_proof =
            self.signing_key.sign(&challenge_transcript(&challenge)).to_bytes();
        Ok(challenge)
    }

    pub(crate) fn connect(
        &mut self,
        request: CompanionHandshakeRequest,
        now_utc: UtcNanoseconds,
        session_id: [u8; 16],
    ) -> Result<CompanionHandshakeResponse, CompanionError> {
        if request.pinned_server_identity != self.server_identity {
            return Err(CompanionError::new(
                CompanionRejectReason::ServerIdentityMismatch,
                "companion server identity does not match the pinned identity",
            ));
        }
        let offered = self.offers.get(&request.pairing_id).cloned().ok_or_else(|| {
            CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is unavailable",
            )
        })?;
        if offered.code != request.pairing_code || offered.expires_at_utc < now_utc {
            return Err(CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is invalid or expired",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(self.server_identity.as_bytes())
            .map_err(CompanionError::signature)?;
        let mut exchanges = Vec::with_capacity(request.clock_responses.len());
        let mut client_sends = std::collections::BTreeSet::new();
        for response in &request.clock_responses {
            let challenge = &response.challenge;
            if challenge.pairing_id != request.pairing_id
                || challenge.client_nonce != request.client_nonce
                || !client_sends.insert(challenge.client_send)
            {
                return Err(clock_error());
            }
            verifying_key
                .verify_strict(
                    &challenge_transcript(challenge),
                    &Signature::from_bytes(&challenge.server_proof),
                )
                .map_err(CompanionError::signature)?;
            exchanges.push(ClockExchange {
                client_send: challenge.client_send,
                host_receive: challenge.host_receive,
                host_send: challenge.host_send,
                client_receive: response.client_receive,
            });
        }
        let clock_relation = estimate_clock_relation(&exchanges, session_id)?;
        self.sessions.retain(|_, session| session.expires_at_utc >= now_utc);
        if self.sessions.len() >= MAX_COMPANION_SESSIONS {
            return Err(CompanionError::new(
                CompanionRejectReason::LimitExceeded,
                "paired companion session limit exceeded",
            ));
        }
        let key = session_key(
            request.pairing_code.expose_bytes(),
            &request.pairing_id,
            self.server_identity,
            &session_id,
            request.client_nonce,
        );
        use ed25519_dalek::Signer;
        let server_proof = self
            .signing_key
            .sign(&connection_transcript(
                self.server_identity,
                &session_id,
                request.client_nonce,
                clock_relation,
            ))
            .to_bytes();
        self.offers.remove(&request.pairing_id);
        self.sessions.insert(
            session_id,
            ServerSession {
                key,
                clock_relation,
                expires_at_utc: offered.expires_at_utc,
                uploads: BTreeMap::new(),
                completed: BTreeMap::new(),
            },
        );
        Ok(CompanionHandshakeResponse { session_id, clock_relation, server_proof })
    }

    pub(crate) fn accept_chunk(
        &mut self,
        chunk: CompanionChunk,
        now_utc: UtcNanoseconds,
        max_bytes: usize,
    ) -> Result<AssembledUpload, CompanionError> {
        let session = self.sessions.get_mut(&chunk.session_id).ok_or_else(|| {
            CompanionError::new(
                CompanionRejectReason::SessionUnavailable,
                "companion session is unavailable",
            )
        })?;
        if session.expires_at_utc < now_utc {
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
        if plaintext.len() > MAX_COMPANION_CHUNK_BYTES || plaintext.len() > total {
            return Err(limit_error());
        }
        if let Some(completed) = session.completed.get(&chunk.upload_id) {
            if completed.chunk_count != chunk.chunk_count
                || completed.total_bytes != chunk.total_bytes
                || completed.full_digest != chunk.full_digest
            {
                return Err(conflict_error());
            }
            return Ok(AssembledUpload {
                bytes: Box::new([]),
                received_chunks: count,
                total_chunks: count,
                session_id: chunk.session_id,
                upload_id: chunk.upload_id,
                full_digest: chunk.full_digest,
                completed_receipt: Some(completed.receipt.clone()),
                clock_relation: session.clock_relation,
            });
        }
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
        let retained_bytes = upload
            .chunks
            .values()
            .try_fold(0_usize, |sum, part| sum.checked_add(part.len()).ok_or_else(limit_error))?;
        if !upload.chunks.contains_key(&chunk.index)
            && retained_bytes.checked_add(plaintext.len()).ok_or_else(limit_error)? > total
        {
            return Err(limit_error());
        }
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
                session_id: chunk.session_id,
                upload_id: chunk.upload_id,
                full_digest: chunk.full_digest,
                completed_receipt: None,
                clock_relation: session.clock_relation,
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
            session_id: chunk.session_id,
            upload_id: chunk.upload_id,
            full_digest: chunk.full_digest,
            completed_receipt: None,
            clock_relation: session.clock_relation,
        })
    }

    pub(crate) fn record_completed(
        &mut self,
        assembled: &AssembledUpload,
        receipt: ImportedArtifact,
    ) -> Result<(), CompanionError> {
        let session = self.sessions.get_mut(&assembled.session_id).ok_or_else(|| {
            CompanionError::new(
                CompanionRejectReason::SessionUnavailable,
                "companion session is unavailable",
            )
        })?;
        if session.completed.len() >= MAX_COMPLETED_UPLOADS {
            let oldest = *session.completed.keys().next().expect("nonempty completed upload set");
            session.completed.remove(&oldest);
        }
        session.completed.insert(
            assembled.upload_id,
            CompletedUpload {
                chunk_count: u32::try_from(assembled.total_chunks).expect("bounded chunk count"),
                total_bytes: u64::try_from(assembled.bytes.len()).expect("bounded upload length"),
                full_digest: assembled.full_digest,
                receipt,
            },
        );
        Ok(())
    }
}

fn estimate_clock_relation(
    exchanges: &[ClockExchange],
    relation_id: [u8; 16],
) -> Result<PhoneTimeRelation, CompanionError> {
    if exchanges.len() < MIN_CLOCK_EXCHANGES || exchanges.len() > MAX_CLOCK_EXCHANGES {
        return Err(clock_error());
    }
    let mut samples = Vec::with_capacity(exchanges.len());
    for exchange in exchanges {
        if exchange.client_receive < exchange.client_send
            || exchange.host_send < exchange.host_receive
        {
            return Err(clock_error());
        }
        let client_elapsed = exchange.client_receive.get() - exchange.client_send.get();
        let host_elapsed = exchange.host_send.get() - exchange.host_receive.get();
        if host_elapsed > client_elapsed {
            return Err(clock_error());
        }
        let network_round_trip = client_elapsed - host_elapsed;
        if network_round_trip > MAX_CLOCK_ROUND_TRIP_NS {
            return Err(clock_error());
        }
        let left = i128::from(exchange.host_receive.get()) - i128::from(exchange.client_send.get());
        let right =
            i128::from(exchange.host_send.get()) - i128::from(exchange.client_receive.get());
        let offset = (left + right) / 2;
        let offset = i64::try_from(offset).map_err(|_| clock_error())?;
        let midpoint = exchange.client_send.get() + client_elapsed / 2;
        samples.push((midpoint, offset, network_round_trip.div_ceil(2)));
    }
    samples.sort_unstable_by_key(|sample| sample.0);
    if samples.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(clock_error());
    }
    let first = samples.first().ok_or_else(clock_error)?;
    let last = samples.last().ok_or_else(clock_error)?;
    let elapsed = i128::from(last.0 - first.0);
    let offset_delta = i128::from(last.1) - i128::from(first.1);
    let endpoint_uncertainty = i128::from(first.2) + i128::from(last.2);
    let drift = if offset_delta.abs() <= endpoint_uncertainty {
        0
    } else {
        offset_delta.checked_mul(1_000_000_000).ok_or_else(clock_error)? / elapsed
    };
    let drift = i64::try_from(drift).map_err(|_| clock_error())?;
    let mut maximum_error = 0_u64;
    for (time, offset, sample_error) in &samples {
        let predicted =
            i128::from(first.1) + i128::from(drift) * i128::from(*time - first.0) / 1_000_000_000;
        let residual = predicted.abs_diff(i128::from(*offset));
        let residual = u64::try_from(residual).map_err(|_| clock_error())?;
        let cross_sample_bound = first
            .2
            .checked_add(*sample_error)
            .and_then(|value| value.checked_add(last.2))
            .ok_or_else(clock_error)?;
        if residual > cross_sample_bound {
            return Err(clock_error());
        }
        maximum_error =
            maximum_error.max(sample_error.checked_add(residual).ok_or_else(clock_error)?);
    }
    PhoneTimeRelation::new(
        relation_id,
        ClockOffsetNanoseconds::from(first.1),
        drift,
        PhoneNanoseconds::from(first.0),
        ClockErrorNanoseconds::from(maximum_error),
        PhoneNanoseconds::from(
            exchanges.iter().map(|e| e.client_send.get()).min().ok_or_else(clock_error)?,
        ),
        PhoneNanoseconds::from(
            exchanges.iter().map(|e| e.client_receive.get()).max().ok_or_else(clock_error)?,
        ),
    )
    .map_err(|_| clock_error())
}

fn session_key(
    code: &[u8; 16],
    pairing_id: &PairingId,
    server: CompanionServerIdentity,
    session_id: &[u8; 16],
    client_nonce: ClientNonce,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"whisper companion session key v1\0");
    digest.update(code);
    digest.update(pairing_id.0);
    digest.update(server.0);
    digest.update(session_id);
    digest.update(client_nonce.0);
    digest.finalize().into()
}

fn offer_transcript(offer: &PairingOffer) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(96);
    transcript.extend_from_slice(b"whisper companion pairing offer v1\0");
    transcript.extend_from_slice(&offer.id.0);
    transcript.extend_from_slice(offer.code.expose_bytes());
    transcript.extend_from_slice(offer.server_identity.as_bytes());
    transcript.extend_from_slice(&offer.expires_at_utc.get().to_le_bytes());
    transcript
}

fn connection_transcript(
    server: CompanionServerIdentity,
    session_id: &[u8; 16],
    client_nonce: ClientNonce,
    relation: PhoneTimeRelation,
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(128);
    transcript.extend_from_slice(b"whisper companion handshake response v1\0");
    transcript.extend_from_slice(server.as_bytes());
    transcript.extend_from_slice(session_id);
    transcript.extend_from_slice(&client_nonce.0);
    transcript.extend_from_slice(&relation.relation_id());
    transcript.extend_from_slice(&relation.offset_at_reference().get().to_le_bytes());
    transcript.extend_from_slice(&relation.drift_parts_per_billion().to_le_bytes());
    transcript.extend_from_slice(&relation.reference_phone_time().get().to_le_bytes());
    transcript.extend_from_slice(&relation.maximum_error().get().to_le_bytes());
    transcript.extend_from_slice(&relation.valid_from_phone_time().get().to_le_bytes());
    transcript.extend_from_slice(&relation.valid_until_phone_time().get().to_le_bytes());
    transcript
}

fn encode_relation(output: &mut Vec<u8>, relation: PhoneTimeRelation) {
    output.extend_from_slice(&relation.relation_id());
    output.extend_from_slice(&relation.offset_at_reference().get().to_le_bytes());
    output.extend_from_slice(&relation.drift_parts_per_billion().to_le_bytes());
    output.extend_from_slice(&relation.reference_phone_time().get().to_le_bytes());
    output.extend_from_slice(&relation.maximum_error().get().to_le_bytes());
    output.extend_from_slice(&relation.valid_from_phone_time().get().to_le_bytes());
    output.extend_from_slice(&relation.valid_until_phone_time().get().to_le_bytes());
}

fn decode_relation(bytes: &[u8]) -> Result<PhoneTimeRelation, CompanionError> {
    if bytes.len() != 64 {
        return Err(clock_error());
    }
    PhoneTimeRelation::new(
        bytes[..16].try_into().expect("fixed relation id"),
        i64::from_le_bytes(bytes[16..24].try_into().expect("fixed offset")).into(),
        i64::from_le_bytes(bytes[24..32].try_into().expect("fixed drift")),
        u64::from_le_bytes(bytes[32..40].try_into().expect("fixed phone time")).into(),
        u64::from_le_bytes(bytes[40..48].try_into().expect("fixed error")).into(),
        u64::from_le_bytes(bytes[48..56].try_into().expect("fixed phone time")).into(),
        u64::from_le_bytes(bytes[56..64].try_into().expect("fixed phone time")).into(),
    )
    .map_err(|_| clock_error())
}

fn challenge_transcript(challenge: &ClockSampleChallenge) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(128);
    transcript.extend_from_slice(b"whisper companion clock challenge v1\0");
    transcript.extend_from_slice(&challenge.pairing_id.0);
    transcript.extend_from_slice(&challenge.client_nonce.0);
    transcript.extend_from_slice(&challenge.client_send.get().to_le_bytes());
    transcript.extend_from_slice(&challenge.host_receive.get().to_le_bytes());
    transcript.extend_from_slice(&challenge.host_send.get().to_le_bytes());
    transcript
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

fn authentication_error(message: &'static str) -> CompanionError {
    CompanionError::new(CompanionRejectReason::AuthenticationFailed, message)
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
        let mut state = CompanionState::new([2; 32]);
        let code = [7; 16];
        let offer = state.offer(10.into(), [3; 16], code, 100.into()).unwrap();
        assert!(!format!("{offer:?}").contains(&format!("{code:?}")));
        assert_eq!(offer.display_code().to_string(), "[REDACTED]");
        let nonce = ClientNonce::from_bytes([5; 32]);
        let mut responses = Vec::new();
        for start in [10_u64, 110, 210] {
            let challenge = state
                .clock_challenge(
                    offer.id,
                    offer.server_identity(),
                    nonce,
                    ClockChallengeMeasurement {
                        now_utc: 11.into(),
                        client_send: start.into(),
                        host_receive: (start + 10).into(),
                        host_send: (start + 11).into(),
                    },
                )
                .unwrap();
            responses.push(ClockSampleResponse::new(challenge, (start + 21).into()));
        }
        let response =
            state.connect(offer.handshake_request(nonce, responses), 11.into(), [4; 16]).unwrap();
        let connection = CompanionConnection::from_handshake(&offer, nonce, response).unwrap();
        assert!(!format!("{connection:?}").contains(&format!("{:?}", connection.key)));
        assert!(!format!("{state:?}").contains(&format!("{:?}", state.signing_key.to_bytes())));
        let session = state.sessions.values().next().unwrap();
        assert!(!format!("{session:?}").contains(&format!("{:?}", session.key)));
    }

    #[test]
    fn clock_relation_rejects_cross_sample_offset_discontinuity() {
        let exchanges = [
            ClockExchange {
                client_send: 100.into(),
                host_receive: 120.into(),
                host_send: 125.into(),
                client_receive: 150.into(),
            },
            ClockExchange {
                client_send: 1_100.into(),
                host_receive: 2_120.into(),
                host_send: 2_125.into(),
                client_receive: 1_150.into(),
            },
            ClockExchange {
                client_send: 2_100.into(),
                host_receive: 2_120.into(),
                host_send: 2_125.into(),
                client_receive: 2_150.into(),
            },
        ];
        assert_eq!(
            estimate_clock_relation(&exchanges, [7; 16]).unwrap_err().reason(),
            CompanionRejectReason::InvalidClockRelation,
        );
    }
}
