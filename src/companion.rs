//! One-time paired encrypted companion artifact upload protocol.

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::artifact::{
    ArtifactImportError, ArtifactRejectReason, ClockErrorNanoseconds, ClockOffsetNanoseconds,
    HostNanoseconds, ImportedArtifact, PhoneNanoseconds, PhoneTimeRelation, UtcNanoseconds,
};
use crate::store::CompanionSigningSeed;

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
/// Four-byte companion chunk magic at wire bytes 0..4.
///
/// Source: companion chunk wire contract v1. Changing these bytes requires a new decoder version.
const CHUNK_MAGIC: &[u8; 4] = b"WSC1";
/// 92-byte companion chunk header: magic(4), session(16), upload(16), index(4),
/// count(4), canonical chunk plaintext bytes(4), total plaintext bytes(8), content digest(32),
/// ciphertext bytes(4).
///
/// Source: companion chunk wire contract v1. The unit is bytes; changing any width or order
/// requires a new decoder version and changes authenticated additional data.
const CHUNK_HEADER_BYTES: usize = 92;
/// Maximum plaintext carried by one independently authenticated chunk (64 KiB).
const MAX_COMPANION_CHUNK_BYTES: usize = 64 * 1024;
/// Four-byte signed invitation magic at wire bytes 0..4.
///
/// Source: companion pairing wire contract v2. Changing these bytes requires a new decoder
/// version and changes the signed invitation representation.
const OFFER_WIRE_MAGIC: &[u8; 4] = b"WSO1";
/// Four-byte signed clock-challenge magic at wire bytes 0..4.
///
/// Source: companion pairing wire contract v2. Changing these bytes requires a new decoder
/// version and changes the signed clock sample representation.
const CHALLENGE_WIRE_MAGIC: &[u8; 4] = b"WSH1";
/// Four-byte clock-response magic at wire bytes 0..4.
///
/// Source: companion pairing wire contract v2. Changing these bytes requires a new decoder
/// version and changes the pairing request transcript.
const CLOCK_RESPONSE_WIRE_MAGIC: &[u8; 4] = b"WSR1";
/// Four-byte authenticated handshake-request magic at wire bytes 0..4.
///
/// Source: companion pairing wire contract v2. Changing these bytes requires a new decoder
/// version and changes the transport framing.
const HANDSHAKE_REQUEST_WIRE_MAGIC: &[u8; 4] = b"WSQ1";
/// Four-byte signed handshake-response magic at wire bytes 0..4.
///
/// Source: companion pairing wire contract v2. Changing these bytes requires a new decoder
/// version and changes the signed completion representation.
const HANDSHAKE_RESPONSE_WIRE_MAGIC: &[u8; 4] = b"WSK1";
/// 156-byte invitation: magic(4), pairing id(16), Ed25519 identity(32), UTC expiry(8),
/// server X25519 public key(32), Ed25519 proof(64).
///
/// Source: companion pairing wire contract v2. The unit is bytes; changing a field width or
/// layout requires coordinated encoder, decoder, and signature-transcript versioning.
const OFFER_WIRE_BYTES: usize = 156;
/// 140-byte challenge: magic(4), pairing id(16), client nonce(32), phone send(8),
/// Host receive(8), Host send(8), Ed25519 proof(64).
///
/// Source: companion pairing wire contract v2. The unit is bytes; changing a field width or
/// layout requires coordinated encoder, decoder, and signature-transcript versioning.
const CHALLENGE_WIRE_BYTES: usize = 140;
/// 152-byte response: response magic(4), complete challenge(140), phone receive(8).
///
/// Source: companion pairing wire contract v2. The unit is bytes; changing a field width or
/// layout requires coordinated encoder, decoder, and code-proof transcript versioning.
const CLOCK_RESPONSE_WIRE_BYTES: usize = 152;
/// 148-byte server response: magic(4), session id(16), clock relation(64), Ed25519 proof(64).
///
/// Source: companion pairing wire contract v2. The unit is bytes; changing a field width or
/// layout requires coordinated encoder, decoder, and signature-transcript versioning.
const HANDSHAKE_RESPONSE_WIRE_BYTES: usize = 148;
/// 152-byte request header: magic(4), pairing id(16), Ed25519 identity(32), client
/// nonce(32), client X25519 public key(32), code proof(32), sample count(4).
///
/// Source: companion pairing wire contract v2. The unit is bytes; changing a field width or
/// layout requires coordinated encoder, decoder, and code-proof transcript versioning.
const HANDSHAKE_REQUEST_HEADER_BYTES: usize = 152;

/// Domain separator for signed invitations, followed by pairing id, fixed server identity, UTC
/// expiry, and server X25519 public key.
///
/// Source: companion pairing cryptographic transcript v2. Changing these bytes or the stated
/// layout requires a protocol version and invalidates existing invitation signatures.
const INVITATION_SIGNATURE_DOMAIN: &[u8] = b"whisper companion X25519 invitation v2\0";
/// Domain separator for pairing-code HMAC input, followed by pairing id, fixed server identity,
/// client nonce, client X25519 public key, and canonical clock-response wires.
///
/// Source: companion pairing cryptographic transcript v2. Changing these bytes or the stated
/// layout requires a protocol version and invalidates existing pairing proofs.
const PAIRING_PROOF_DOMAIN: &[u8] = b"whisper companion pairing-code proof v2\0";
/// HKDF info for deriving the pairing-code HMAC key from X25519 output and the code salt.
///
/// Source: companion pairing KDF contract v2. No fields follow this separator; changing it
/// requires a protocol version and makes client/server proofs incompatible.
const PAIRING_AUTH_KEY_DOMAIN: &[u8] = b"whisper companion pairing-code authentication key v2\0";
/// HKDF info prefix for the session key, followed by pairing id, fixed server identity, client
/// X25519 public key, session id, client nonce, and the complete clock relation.
///
/// Source: companion pairing KDF contract v2. Changing these bytes or the stated layout requires
/// a protocol version and makes independently reconstructed session keys incompatible.
const SESSION_KEY_DOMAIN: &[u8] = b"whisper companion X25519 session key v2\0";
/// Domain separator for the signed session response, followed by fixed server identity, pairing
/// id, session id, client nonce, client X25519 public key, and the complete clock relation.
///
/// Source: companion pairing cryptographic transcript v2. Changing these bytes or the stated
/// layout requires a protocol version and invalidates existing response signatures.
const SESSION_SIGNATURE_DOMAIN: &[u8] = b"whisper companion authenticated handshake response v2\0";
/// Domain separator for a signed clock challenge, followed by pairing id, client nonce, phone
/// send time, Host receive time, and Host send time.
///
/// Source: companion clock transcript v1. Changing these bytes or the stated layout requires a
/// protocol version and invalidates existing clock-challenge signatures.
const CLOCK_CHALLENGE_SIGNATURE_DOMAIN: &[u8] = b"whisper companion clock challenge v1\0";
/// Domain separator for deterministic 96-bit chunk nonces, followed by session id, upload id,
/// canonical chunk layout, and chunk index.
///
/// Source: companion upload cryptographic contract v2. Changing these bytes or the stated layout
/// requires a protocol version; reuse under a key would violate AES-GCM security.
const CHUNK_NONCE_DOMAIN: &[u8] = b"whisper companion chunk nonce v2\0";
/// HKDF info prefix for a per-upload AES-256-GCM key, followed by upload id, content digest,
/// canonical chunk plaintext bytes, chunk count, and total plaintext bytes.
///
/// Source: companion upload KDF contract v3. Changing these bytes or the stated layout requires a
/// protocol version and makes upload encryption incompatible.
const UPLOAD_KEY_DOMAIN: &[u8] =
    b"whisper companion AES-256-GCM per-content-layout upload key v3\0";
/// AAD domain separator followed by fixed server identity, upload id, chunk index, canonical
/// chunk count, canonical chunk plaintext bytes, total plaintext bytes, and content digest.
///
/// Source: companion upload authentication contract v2. Changing these bytes or the stated
/// layout requires a protocol version and invalidates existing AES-GCM tags.
const CHUNK_AAD_DOMAIN: &[u8] = b"whisper companion chunk v2\0";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SecretBytes([u8; 32]);

impl SecretBytes {
    const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug)]
struct ServerEphemeralSecret(SecretBytes);

#[derive(Debug)]
struct SharedSecret(SecretBytes);

#[derive(Debug)]
struct AuthenticationKey(SecretBytes);

#[derive(Debug)]
struct SessionKey(SecretBytes);

#[derive(Debug)]
struct UploadKey(SecretBytes);

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
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
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
    /// Reconstructs a code explicitly entered or scanned on the companion.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Formats the one-time code for the explicit local display surface.
    #[must_use]
    pub fn format_for_display(&self) -> String {
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
    pub(crate) server_ephemeral_public: [u8; 32],
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
            .field("server_ephemeral_public", &self.server_ephemeral_public)
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
    pub const fn display_code(&self) -> &PairingCode {
        &self.code
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
        self.invitation().verify_server_proof(pinned)
    }

    /// Encodes the complete signed offer for an arbitrary byte transport.
    #[must_use]
    pub fn to_wire(&self) -> Box<[u8]> {
        self.invitation().to_wire()
    }

    fn invitation(&self) -> PairingInvitation {
        PairingInvitation {
            id: self.id,
            server_identity: self.server_identity,
            expires_at_utc: self.expires_at_utc,
            server_ephemeral_public: self.server_ephemeral_public,
            server_proof: self.server_proof,
        }
    }
}

/// Public signed pairing data received by a companion; it contains no pairing secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingInvitation {
    id: PairingId,
    server_identity: CompanionServerIdentity,
    expires_at_utc: UtcNanoseconds,
    server_ephemeral_public: [u8; 32],
    server_proof: [u8; 64],
}

impl PairingInvitation {
    /// Returns the opaque pairing identity used for clock challenges.
    #[must_use]
    pub const fn pairing_id(&self) -> PairingId {
        self.id
    }

    /// Returns the authenticated fixed server identity.
    #[must_use]
    pub const fn server_identity(&self) -> CompanionServerIdentity {
        self.server_identity
    }

    /// Reconstructs and authenticates an invitation from any byte transport.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes, a wrong pin, or invalid Ed25519 proof.
    pub fn from_wire(
        bytes: &[u8],
        pinned: CompanionServerIdentity,
    ) -> Result<Self, CompanionError> {
        if bytes.len() != OFFER_WIRE_BYTES || &bytes[..4] != OFFER_WIRE_MAGIC {
            return Err(authentication_error("pairing invitation wire encoding is malformed"));
        }
        let invitation = Self {
            id: PairingId(bytes[4..20].try_into().expect("fixed pairing id")),
            server_identity: CompanionServerIdentity(
                bytes[20..52].try_into().expect("fixed identity"),
            ),
            expires_at_utc: u64::from_le_bytes(bytes[52..60].try_into().expect("fixed expiry"))
                .into(),
            server_ephemeral_public: bytes[60..92].try_into().expect("fixed X25519 public key"),
            server_proof: bytes[92..156].try_into().expect("fixed invitation proof"),
        };
        invitation.verify_server_proof(pinned)?;
        Ok(invitation)
    }

    fn to_wire(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(OFFER_WIRE_BYTES);
        bytes.extend_from_slice(OFFER_WIRE_MAGIC);
        bytes.extend_from_slice(&self.id.0);
        bytes.extend_from_slice(&self.server_identity.0);
        bytes.extend_from_slice(&self.expires_at_utc.get().to_le_bytes());
        bytes.extend_from_slice(&self.server_ephemeral_public);
        bytes.extend_from_slice(&self.server_proof);
        bytes.into_boxed_slice()
    }

    fn verify_server_proof(&self, pinned: CompanionServerIdentity) -> Result<(), CompanionError> {
        if pinned != self.server_identity {
            return Err(CompanionError::new(
                CompanionRejectReason::ServerIdentityMismatch,
                "pairing invitation identity differs from the pin",
            ));
        }
        let key = VerifyingKey::from_bytes(self.server_identity.as_bytes()).map_err(|source| {
            CompanionError::signature("decode pairing invitation server identity", source)
        })?;
        key.verify_strict(&invitation_transcript(self), &Signature::from_bytes(&self.server_proof))
            .map_err(|source| CompanionError::signature("verify pairing invitation", source))
    }

    /// Creates the code-authenticated request and retained client completion state.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid X25519 secret or low-order server public key.
    pub fn begin_handshake(
        &self,
        pairing_code: PairingCode,
        client_nonce: ClientNonce,
        client_secret: ClientEphemeralSecret,
        clock_responses: Vec<ClockSampleResponse>,
    ) -> Result<(CompanionHandshakeRequest, PendingCompanionConnection), CompanionError> {
        let client_secret = StaticSecret::from(*client_secret.0.as_bytes());
        let client_public = X25519PublicKey::from(&client_secret).to_bytes();
        let shared_secret = SharedSecret::new(
            client_secret
                .diffie_hellman(&X25519PublicKey::from(self.server_ephemeral_public))
                .to_bytes(),
        )?;
        let mut request = CompanionHandshakeRequest {
            pairing_id: self.id,
            pinned_server_identity: self.server_identity,
            client_nonce,
            client_ephemeral_public: client_public,
            code_proof: [0; 32],
            clock_responses,
        };
        request.code_proof = code_proof(&shared_secret, &pairing_code, &request)?;
        Ok((
            request,
            PendingCompanionConnection {
                pairing_id: self.id,
                server_identity: self.server_identity,
                client_nonce,
                pairing_code,
                shared_secret,
                client_ephemeral_public: client_public,
            },
        ))
    }
}

/// Caller-generated X25519 secret retained only through handshake completion.
pub struct ClientEphemeralSecret(SecretBytes);

impl fmt::Debug for ClientEphemeralSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientEphemeralSecret([REDACTED])")
    }
}

impl ClientEphemeralSecret {
    /// Accepts 32 bytes from the companion platform CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error for the all-zero sentinel.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CompanionError> {
        if bytes == [0; 32] {
            return Err(authentication_error("client ephemeral secret is invalid"));
        }
        Ok(Self(SecretBytes::new(bytes)))
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
        let key = VerifyingKey::from_bytes(pinned.as_bytes()).map_err(|source| {
            CompanionError::signature("decode clock challenge server identity", source)
        })?;
        key.verify_strict(
            &challenge_transcript(&challenge),
            &Signature::from_bytes(&challenge.server_proof),
        )
        .map_err(|source| CompanionError::signature("verify clock challenge", source))?;
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
    pinned_server_identity: CompanionServerIdentity,
    client_nonce: ClientNonce,
    client_ephemeral_public: [u8; 32],
    code_proof: [u8; 32],
    clock_responses: Vec<ClockSampleResponse>,
}

impl CompanionHandshakeRequest {
    /// Encodes the request for an arbitrary byte transport.
    #[must_use]
    pub fn to_wire(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(
            HANDSHAKE_REQUEST_HEADER_BYTES + self.clock_responses.len() * CLOCK_RESPONSE_WIRE_BYTES,
        );
        bytes.extend_from_slice(HANDSHAKE_REQUEST_WIRE_MAGIC);
        bytes.extend_from_slice(&self.pairing_id.0);
        bytes.extend_from_slice(&self.pinned_server_identity.0);
        bytes.extend_from_slice(&self.client_nonce.0);
        bytes.extend_from_slice(&self.client_ephemeral_public);
        bytes.extend_from_slice(&self.code_proof);
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
        if bytes.len() < HANDSHAKE_REQUEST_HEADER_BYTES
            || &bytes[..4] != HANDSHAKE_REQUEST_WIRE_MAGIC
        {
            return Err(authentication_error("handshake request wire encoding is malformed"));
        }
        let count =
            u32::from_le_bytes(bytes[148..152].try_into().expect("fixed sample count")) as usize;
        if !(MIN_CLOCK_EXCHANGES..=MAX_CLOCK_EXCHANGES).contains(&count)
            || bytes.len() != HANDSHAKE_REQUEST_HEADER_BYTES + count * CLOCK_RESPONSE_WIRE_BYTES
        {
            return Err(clock_error());
        }
        let pinned_server_identity =
            CompanionServerIdentity(bytes[20..52].try_into().expect("fixed identity"));
        let mut clock_responses = Vec::with_capacity(count);
        for chunk in bytes[HANDSHAKE_REQUEST_HEADER_BYTES..].chunks_exact(CLOCK_RESPONSE_WIRE_BYTES)
        {
            clock_responses.push(ClockSampleResponse::from_wire(chunk, pinned_server_identity)?);
        }
        Ok(Self {
            pairing_id: PairingId(bytes[4..20].try_into().expect("fixed pairing id")),
            pinned_server_identity,
            client_nonce: ClientNonce(bytes[52..84].try_into().expect("fixed client nonce")),
            client_ephemeral_public: bytes[84..116].try_into().expect("fixed X25519 public key"),
            code_proof: bytes[116..148].try_into().expect("fixed code proof"),
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
    pairing_id: PairingId,
    session_id: [u8; 16],
    key: SessionKey,
    server_identity: CompanionServerIdentity,
    clock_relation: PhoneTimeRelation,
    client_nonce: ClientNonce,
    client_ephemeral_public: [u8; 32],
    server_proof: [u8; 64],
}

/// Secret client state retained between sending a request and receiving its response.
pub struct PendingCompanionConnection {
    pairing_id: PairingId,
    server_identity: CompanionServerIdentity,
    client_nonce: ClientNonce,
    pairing_code: PairingCode,
    shared_secret: SharedSecret,
    client_ephemeral_public: [u8; 32],
}

impl fmt::Debug for PendingCompanionConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingCompanionConnection")
            .field("pairing_id", &self.pairing_id)
            .field("server_identity", &self.server_identity)
            .field("client_nonce", &self.client_nonce)
            .field("pairing_code", &"[REDACTED]")
            .field("shared_secret", &"[REDACTED]")
            .field("client_ephemeral_public", &self.client_ephemeral_public)
            .finish()
    }
}

impl PendingCompanionConnection {
    /// Verifies the signed response and constructs the independent client session.
    ///
    /// # Errors
    ///
    /// Returns an error for a forged response or key-derivation failure.
    pub fn complete(
        self,
        response: CompanionHandshakeResponse,
    ) -> Result<CompanionConnection, CompanionError> {
        let key_context = SessionKeyContext {
            pairing_id: self.pairing_id,
            server: self.server_identity,
            client_ephemeral_public: self.client_ephemeral_public,
            session_id: response.session_id,
            client_nonce: self.client_nonce,
            relation: response.clock_relation,
        };
        let key = session_key(&self.shared_secret, &self.pairing_code, &key_context)?;
        let connection = CompanionConnection {
            pairing_id: self.pairing_id,
            session_id: response.session_id,
            key,
            server_identity: self.server_identity,
            clock_relation: response.clock_relation,
            client_nonce: self.client_nonce,
            client_ephemeral_public: self.client_ephemeral_public,
            server_proof: response.server_proof,
        };
        connection.verify_server_proof()?;
        Ok(connection)
    }
}

impl fmt::Debug for CompanionConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompanionConnection")
            .field("session_id", &self.session_id)
            .field("pairing_id", &self.pairing_id)
            .field("key", &"[REDACTED]")
            .field("server_identity", &self.server_identity)
            .field("clock_relation", &self.clock_relation)
            .field("client_nonce", &self.client_nonce)
            .field("client_ephemeral_public", &self.client_ephemeral_public)
            .field("server_proof", &self.server_proof)
            .finish()
    }
}

impl CompanionConnection {
    /// Verifies the persistent server's client-nonce-bound handshake proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed identity or response proof is invalid.
    pub fn verify_server_proof(&self) -> Result<(), CompanionError> {
        let key = VerifyingKey::from_bytes(self.server_identity.as_bytes()).map_err(|source| {
            CompanionError::signature("decode handshake response server identity", source)
        })?;
        key.verify_strict(
            &connection_transcript(
                self.server_identity,
                self.pairing_id,
                &self.session_id,
                self.client_nonce,
                &self.client_ephemeral_public,
                self.clock_relation,
            ),
            &Signature::from_bytes(&self.server_proof),
        )
        .map_err(|source| CompanionError::signature("verify handshake response", source))
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
        let chunk_plaintext_bytes = u32::try_from(chunk_bytes).map_err(|_| limit_error())?;
        let chunk_count = u32::try_from(chunk_count).expect("bounded chunk count fits u32");
        let layout = ChunkLayout { chunk_plaintext_bytes, chunk_count, total_bytes };
        let upload_key = upload_key(&self.key, upload_id, &full_digest, layout)?;
        let cipher = Aes256Gcm::new_from_slice(upload_key.0.as_bytes())
            .expect("AES-256 accepts a 32-byte upload key");
        sealed_bytes
            .chunks(chunk_bytes)
            .enumerate()
            .map(|(index, plaintext)| {
                let index = u32::try_from(index).expect("bounded upload index fits u32");
                let nonce = chunk_nonce(&self.session_id, upload_id, layout, index);
                let aad = chunk_aad(self.server_identity, upload_id, index, layout, &full_digest);
                let ciphertext = cipher
                    .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
                    .map_err(|source| {
                        CompanionError::crypto("encrypt companion upload chunk", source)
                    })?;
                Ok(CompanionChunk {
                    session_id: self.session_id,
                    upload_id,
                    index,
                    chunk_count,
                    chunk_plaintext_bytes,
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
    chunk_plaintext_bytes: u32,
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
        bytes.extend_from_slice(&self.chunk_plaintext_bytes.to_le_bytes());
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
            u32::from_le_bytes(bytes[88..92].try_into().expect("fixed ciphertext length field"))
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
            chunk_plaintext_bytes: u32::from_le_bytes(
                bytes[44..48].try_into().expect("fixed canonical chunk size"),
            ),
            total_bytes: u64::from_le_bytes(bytes[48..56].try_into().expect("fixed total length")),
            full_digest: bytes[56..88].try_into().expect("fixed upload digest"),
            ciphertext: bytes[92..].into(),
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
    #[error("{operation} failed: {source}")]
    Signature {
        operation: &'static str,
        #[source]
        source: ed25519_dalek::SignatureError,
    },
    #[error("{operation} failed: {source}")]
    Crypto {
        operation: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
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

    fn signature(operation: &'static str, source: ed25519_dalek::SignatureError) -> Self {
        Self {
            kind: Box::new(CompanionErrorKind::Signature { operation, source }),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    fn crypto(
        operation: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind: Box::new(CompanionErrorKind::Crypto { operation, source: Box::new(source) }),
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
            CompanionErrorKind::Entropy(_)
            | CompanionErrorKind::Signature { .. }
            | CompanionErrorKind::Crypto { .. } => CompanionRejectReason::AuthenticationFailed,
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
            | CompanionErrorKind::Signature { .. }
            | CompanionErrorKind::Crypto { .. } => None,
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
    offers: BTreeMap<PairingId, RetainedOffer>,
    sessions: BTreeMap<[u8; 16], ServerSession>,
}

struct RetainedOffer {
    offer: PairingOffer,
    server_ephemeral_secret: ServerEphemeralSecret,
}

struct ServerSession {
    key: SessionKey,
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
    chunk_plaintext_bytes: u32,
    total_bytes: u64,
    full_digest: [u8; 32],
    receipt: ImportedArtifact,
}

#[derive(Debug)]
struct IncompleteUpload {
    chunk_count: u32,
    chunk_plaintext_bytes: u32,
    total_bytes: u64,
    full_digest: [u8; 32],
    chunks: BTreeMap<u32, Box<[u8]>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChunkLayout {
    chunk_plaintext_bytes: u32,
    chunk_count: u32,
    total_bytes: u64,
}

impl ChunkLayout {
    fn expected_plaintext_bytes(self, index: u32) -> Result<usize, CompanionError> {
        let start = u64::from(index)
            .checked_mul(u64::from(self.chunk_plaintext_bytes))
            .ok_or_else(limit_error)?;
        let remaining = self.total_bytes.checked_sub(start).ok_or_else(limit_error)?;
        usize::try_from(remaining.min(u64::from(self.chunk_plaintext_bytes)))
            .map_err(|_| limit_error())
    }
}

pub(crate) struct AssembledUpload {
    pub(crate) bytes: Box<[u8]>,
    pub(crate) received_chunks: usize,
    pub(crate) total_chunks: usize,
    pub(crate) chunk_plaintext_bytes: u32,
    pub(crate) session_id: [u8; 16],
    pub(crate) upload_id: UploadId,
    pub(crate) full_digest: [u8; 32],
    pub(crate) completed_receipt: Option<ImportedArtifact>,
    pub(crate) clock_relation: PhoneTimeRelation,
}

impl CompanionState {
    pub(crate) fn new(signing_seed: CompanionSigningSeed) -> Self {
        let signing_key = SigningKey::from_bytes(signing_seed.as_bytes());
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
        code: PairingCode,
        server_ephemeral_secret: [u8; 32],
        expires_at_utc: UtcNanoseconds,
    ) -> Result<PairingOffer, CompanionError> {
        self.offers.retain(|_, retained| retained.offer.expires_at_utc >= now_utc);
        self.sessions.retain(|_, session| session.expires_at_utc >= now_utc);
        if self.offers.len() >= MAX_PAIRING_OFFERS {
            return Err(CompanionError::new(
                CompanionRejectReason::LimitExceeded,
                "outstanding companion pairing offer limit exceeded",
            ));
        }
        let server_ephemeral_secret =
            ServerEphemeralSecret(SecretBytes::new(server_ephemeral_secret));
        let server_ephemeral_public =
            X25519PublicKey::from(&StaticSecret::from(*server_ephemeral_secret.0.as_bytes()))
                .to_bytes();
        let mut offer = PairingOffer {
            id: PairingId(id),
            code,
            server_identity: self.server_identity,
            expires_at_utc,
            server_ephemeral_public,
            server_proof: [0; 64],
        };
        use ed25519_dalek::Signer;
        offer.server_proof =
            self.signing_key.sign(&invitation_transcript(&offer.invitation())).to_bytes();
        self.offers
            .insert(offer.id, RetainedOffer { offer: offer.clone(), server_ephemeral_secret });
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
        let retained = self.offers.get(&pairing_id).ok_or_else(|| {
            CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is unavailable",
            )
        })?;
        if retained.offer.expires_at_utc < measurement.now_utc {
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
        let retained = self.offers.get(&request.pairing_id).ok_or_else(|| {
            CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is unavailable",
            )
        })?;
        if retained.offer.expires_at_utc < now_utc {
            return Err(CompanionError::new(
                CompanionRejectReason::PairingUnavailable,
                "pairing offer is invalid or expired",
            ));
        }
        let shared_secret = SharedSecret::new(
            StaticSecret::from(*retained.server_ephemeral_secret.0.as_bytes())
                .diffie_hellman(&X25519PublicKey::from(request.client_ephemeral_public))
                .to_bytes(),
        )?;
        verify_code_proof(&shared_secret, &retained.offer.code, &request)?;
        let verifying_key =
            VerifyingKey::from_bytes(self.server_identity.as_bytes()).map_err(|source| {
                CompanionError::signature("decode fixed companion server identity", source)
            })?;
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
                .map_err(|source| {
                    CompanionError::signature("verify handshake clock challenge", source)
                })?;
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
        let key_context = SessionKeyContext {
            pairing_id: request.pairing_id,
            server: self.server_identity,
            client_ephemeral_public: request.client_ephemeral_public,
            session_id,
            client_nonce: request.client_nonce,
            relation: clock_relation,
        };
        let key = session_key(&shared_secret, &retained.offer.code, &key_context)?;
        let expires_at_utc = retained.offer.expires_at_utc;
        use ed25519_dalek::Signer;
        let server_proof = self
            .signing_key
            .sign(&connection_transcript(
                self.server_identity,
                request.pairing_id,
                &session_id,
                request.client_nonce,
                &request.client_ephemeral_public,
                clock_relation,
            ))
            .to_bytes();
        self.offers.remove(&request.pairing_id);
        self.sessions.insert(
            session_id,
            ServerSession {
                key,
                clock_relation,
                expires_at_utc,
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
        let layout = ChunkLayout {
            chunk_plaintext_bytes: chunk.chunk_plaintext_bytes,
            chunk_count: chunk.chunk_count,
            total_bytes: chunk.total_bytes,
        };
        let canonical_count = if chunk.chunk_plaintext_bytes == 0 {
            0
        } else {
            chunk.total_bytes.div_ceil(u64::from(chunk.chunk_plaintext_bytes))
        };
        if count == 0
            || count > MAX_UPLOAD_CHUNKS
            || chunk.index >= chunk.chunk_count
            || chunk.chunk_plaintext_bytes == 0
            || usize::try_from(chunk.chunk_plaintext_bytes).map_err(|_| limit_error())?
                > MAX_COMPANION_CHUNK_BYTES
            || u64::from(chunk.chunk_count) != canonical_count
            || total == 0
            || total > max_bytes
        {
            return Err(limit_error());
        }
        let nonce = chunk_nonce(&chunk.session_id, chunk.upload_id, layout, chunk.index);
        let aad = chunk_aad(
            self.server_identity,
            chunk.upload_id,
            chunk.index,
            layout,
            &chunk.full_digest,
        );
        let upload_key = upload_key(&session.key, chunk.upload_id, &chunk.full_digest, layout)?;
        let cipher = Aes256Gcm::new_from_slice(upload_key.0.as_bytes())
            .expect("AES-256 accepts a 32-byte upload key");
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &chunk.ciphertext, aad: &aad })
            .map_err(|source| {
                CompanionError::crypto("authenticate and decrypt companion upload chunk", source)
            })?
            .into_boxed_slice();
        if plaintext.len() != layout.expected_plaintext_bytes(chunk.index)? {
            return Err(limit_error());
        }
        if let Some(completed) = session.completed.get(&chunk.upload_id) {
            if completed.chunk_count != chunk.chunk_count
                || completed.chunk_plaintext_bytes != chunk.chunk_plaintext_bytes
                || completed.total_bytes != chunk.total_bytes
                || completed.full_digest != chunk.full_digest
            {
                return Err(conflict_error());
            }
            return Ok(AssembledUpload {
                bytes: Box::new([]),
                received_chunks: count,
                total_chunks: count,
                chunk_plaintext_bytes: chunk.chunk_plaintext_bytes,
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
                chunk_plaintext_bytes: chunk.chunk_plaintext_bytes,
                total_bytes: chunk.total_bytes,
                full_digest: chunk.full_digest,
                chunks: BTreeMap::new(),
            }),
            Entry::Occupied(entry) => {
                let upload = entry.into_mut();
                if upload.chunk_count != chunk.chunk_count
                    || upload.chunk_plaintext_bytes != chunk.chunk_plaintext_bytes
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
                chunk_plaintext_bytes: chunk.chunk_plaintext_bytes,
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
            chunk_plaintext_bytes: chunk.chunk_plaintext_bytes,
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
                chunk_plaintext_bytes: assembled.chunk_plaintext_bytes,
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

struct SessionKeyContext {
    pairing_id: PairingId,
    server: CompanionServerIdentity,
    client_ephemeral_public: [u8; 32],
    session_id: [u8; 16],
    client_nonce: ClientNonce,
    relation: PhoneTimeRelation,
}

fn session_key(
    shared_secret: &SharedSecret,
    code: &PairingCode,
    context: &SessionKeyContext,
) -> Result<SessionKey, CompanionError> {
    let hkdf = Hkdf::<Sha256>::new(Some(code.expose_bytes()), shared_secret.0.as_bytes());
    let mut info = Vec::with_capacity(192);
    info.extend_from_slice(SESSION_KEY_DOMAIN);
    info.extend_from_slice(&context.pairing_id.0);
    info.extend_from_slice(&context.server.0);
    info.extend_from_slice(&context.client_ephemeral_public);
    info.extend_from_slice(&context.session_id);
    info.extend_from_slice(&context.client_nonce.0);
    encode_relation(&mut info, context.relation);
    let mut key = SecretBytes::new([0; 32]);
    hkdf.expand(&info, &mut key.0)
        .map_err(|source| CompanionError::crypto("derive companion session key", source))?;
    Ok(SessionKey(key))
}

fn upload_key(
    session_key: &SessionKey,
    upload_id: UploadId,
    full_digest: &[u8; 32],
    layout: ChunkLayout,
) -> Result<UploadKey, CompanionError> {
    let hkdf = Hkdf::<Sha256>::new(Some(full_digest), session_key.0.as_bytes());
    let mut info = Vec::with_capacity(128);
    info.extend_from_slice(UPLOAD_KEY_DOMAIN);
    info.extend_from_slice(&upload_id.0);
    info.extend_from_slice(full_digest);
    encode_chunk_layout(&mut info, layout);
    let mut key = SecretBytes::new([0; 32]);
    hkdf.expand(&info, &mut key.0)
        .map_err(|source| CompanionError::crypto("derive companion upload key", source))?;
    Ok(UploadKey(key))
}

fn invitation_transcript(invitation: &PairingInvitation) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(128);
    transcript.extend_from_slice(INVITATION_SIGNATURE_DOMAIN);
    transcript.extend_from_slice(&invitation.id.0);
    transcript.extend_from_slice(invitation.server_identity.as_bytes());
    transcript.extend_from_slice(&invitation.expires_at_utc.get().to_le_bytes());
    transcript.extend_from_slice(&invitation.server_ephemeral_public);
    transcript
}

fn request_transcript(request: &CompanionHandshakeRequest) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(128 + request.clock_responses.len() * CLOCK_RESPONSE_WIRE_BYTES);
    transcript.extend_from_slice(PAIRING_PROOF_DOMAIN);
    transcript.extend_from_slice(&request.pairing_id.0);
    transcript.extend_from_slice(&request.pinned_server_identity.0);
    transcript.extend_from_slice(&request.client_nonce.0);
    transcript.extend_from_slice(&request.client_ephemeral_public);
    for response in &request.clock_responses {
        transcript.extend_from_slice(&response.to_wire());
    }
    transcript
}

fn code_proof(
    shared_secret: &SharedSecret,
    code: &PairingCode,
    request: &CompanionHandshakeRequest,
) -> Result<[u8; 32], CompanionError> {
    let authentication_key = code_authentication_key(shared_secret, code)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(authentication_key.0.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(&request_transcript(request));
    Ok(mac.finalize().into_bytes().into())
}

fn code_authentication_key(
    shared_secret: &SharedSecret,
    code: &PairingCode,
) -> Result<AuthenticationKey, CompanionError> {
    let hkdf = Hkdf::<Sha256>::new(Some(code.expose_bytes()), shared_secret.0.as_bytes());
    let mut authentication_key = SecretBytes::new([0; 32]);
    hkdf.expand(PAIRING_AUTH_KEY_DOMAIN, &mut authentication_key.0).map_err(|source| {
        CompanionError::crypto("derive companion pairing authentication key", source)
    })?;
    Ok(AuthenticationKey(authentication_key))
}

fn verify_code_proof(
    shared_secret: &SharedSecret,
    code: &PairingCode,
    request: &CompanionHandshakeRequest,
) -> Result<(), CompanionError> {
    let authentication_key = code_authentication_key(shared_secret, code)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(authentication_key.0.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(&request_transcript(request));
    mac.verify_slice(&request.code_proof)
        .map_err(|source| CompanionError::crypto("verify companion pairing-code proof", source))
}

impl SharedSecret {
    fn new(bytes: [u8; 32]) -> Result<Self, CompanionError> {
        if bytes == [0; 32] {
            Err(authentication_error("X25519 peer public key is low order"))
        } else {
            Ok(Self(SecretBytes::new(bytes)))
        }
    }
}

fn connection_transcript(
    server: CompanionServerIdentity,
    pairing_id: PairingId,
    session_id: &[u8; 16],
    client_nonce: ClientNonce,
    client_ephemeral_public: &[u8; 32],
    relation: PhoneTimeRelation,
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(128);
    transcript.extend_from_slice(SESSION_SIGNATURE_DOMAIN);
    transcript.extend_from_slice(server.as_bytes());
    transcript.extend_from_slice(&pairing_id.0);
    transcript.extend_from_slice(session_id);
    transcript.extend_from_slice(&client_nonce.0);
    transcript.extend_from_slice(client_ephemeral_public);
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
    transcript.extend_from_slice(CLOCK_CHALLENGE_SIGNATURE_DOMAIN);
    transcript.extend_from_slice(&challenge.pairing_id.0);
    transcript.extend_from_slice(&challenge.client_nonce.0);
    transcript.extend_from_slice(&challenge.client_send.get().to_le_bytes());
    transcript.extend_from_slice(&challenge.host_receive.get().to_le_bytes());
    transcript.extend_from_slice(&challenge.host_send.get().to_le_bytes());
    transcript
}

fn chunk_nonce(
    session_id: &[u8; 16],
    upload_id: UploadId,
    layout: ChunkLayout,
    index: u32,
) -> [u8; 12] {
    let mut digest = Sha256::new();
    digest.update(CHUNK_NONCE_DOMAIN);
    digest.update(session_id);
    digest.update(upload_id.0);
    digest.update(layout.chunk_plaintext_bytes.to_le_bytes());
    digest.update(layout.chunk_count.to_le_bytes());
    digest.update(layout.total_bytes.to_le_bytes());
    digest.update(index.to_le_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    digest[..12].try_into().expect("fixed nonce prefix")
}

fn chunk_aad(
    server: CompanionServerIdentity,
    upload_id: UploadId,
    index: u32,
    layout: ChunkLayout,
    digest: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(112);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(&server.0);
    aad.extend_from_slice(&upload_id.0);
    aad.extend_from_slice(&index.to_le_bytes());
    encode_chunk_layout(&mut aad, layout);
    aad.extend_from_slice(digest);
    aad
}

fn encode_chunk_layout(output: &mut Vec<u8>, layout: ChunkLayout) {
    output.extend_from_slice(&layout.chunk_plaintext_bytes.to_le_bytes());
    output.extend_from_slice(&layout.chunk_count.to_le_bytes());
    output.extend_from_slice(&layout.total_bytes.to_le_bytes());
}

fn clock_error() -> CompanionError {
    CompanionError::new(
        CompanionRejectReason::InvalidClockRelation,
        "companion clock exchanges are invalid or exceed the round-trip bound",
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
        assert!(std::mem::needs_drop::<PairingCode>());
        let mut disposable_code = PairingCode::from_bytes([0xab; 16]);
        assert_eq!(format!("{disposable_code:?}"), "PairingCode([REDACTED])");
        disposable_code.zeroize();
        assert_eq!(disposable_code.expose_bytes(), &[0; 16]);

        let mut state = CompanionState::new(CompanionSigningSeed::new([2; 32]));
        let code = PairingCode::from_bytes([7; 16]);
        let code_bytes = *code.expose_bytes();
        let offer = state.offer(10.into(), [3; 16], code, [8; 32], 100.into()).unwrap();
        assert!(!format!("{offer:?}").contains(&format!("{code_bytes:?}")));
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
        let invitation =
            PairingInvitation::from_wire(&offer.to_wire(), offer.server_identity()).unwrap();
        let (request, pending) = invitation
            .begin_handshake(
                offer.code.clone(),
                nonce,
                ClientEphemeralSecret::from_bytes([9; 32]).unwrap(),
                responses,
            )
            .unwrap();
        let response = state.connect(request, 11.into(), [4; 16]).unwrap();
        let connection = pending.complete(response).unwrap();
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
