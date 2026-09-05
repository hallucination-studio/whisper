import Foundation

// MARK: - Companion identity and wire values

private let invitationSignatureDomain = Data("whisper companion X25519 invitation v2\0".utf8)
private let clockChallengeSignatureDomain = Data("whisper companion clock challenge v1\0".utf8)
private let pairingProofDomain = Data("whisper companion pairing-code proof v2\0".utf8)
private let pairingAuthenticationDomain = Data("whisper companion pairing-code authentication key v2\0".utf8)
private let sessionKeyDomain = Data("whisper companion X25519 session key v2\0".utf8)
private let sessionSignatureDomain = Data("whisper companion authenticated handshake response v2\0".utf8)
private let chunkNonceDomain = Data("whisper companion chunk nonce v2\0".utf8)
private let uploadKeyDomain = Data("whisper companion AES-256-GCM per-content-layout upload key v3\0".utf8)
private let chunkAADDomain = Data("whisper companion chunk v2\0".utf8)

/// Stable public Ed25519 identity pinned by the phone before it accepts Host data.
public struct CompanionServerIdentity: Codable, Equatable, Hashable, Sendable, CustomStringConvertible {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 32 else {
            throw PhoneClientError.serverIdentityMismatch
        }
        self.bytes = bytes
    }

    public var description: String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

/// Opaque one-time pairing identifier.
public struct PairingID: Codable, Equatable, Hashable, Sendable {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 16 else { throw PhoneClientError.malformedWire("pairing ID must contain sixteen bytes") }
        self.bytes = bytes
    }
}

/// Secret pairing code entered or scanned on the phone.
public struct PairingCode: Equatable, Sendable, CustomStringConvertible {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 16 else { throw PhoneClientError.authenticationFailed("pairing code must contain sixteen bytes") }
        self.bytes = bytes
    }

    /// Formats the code for a local display surface without exposing it in debug output.
    public var displayValue: String {
        bytes.enumerated().map { index, byte in
            let separator = index > 0 && index.isMultiple(of: 2) ? "-" : ""
            return separator + String(format: "%02x", byte)
        }.joined()
    }

    public var description: String { "[REDACTED]" }
}

/// Client nonce binding one authenticated handshake response.
public struct ClientNonce: Codable, Equatable, Hashable, Sendable {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 32 else { throw PhoneClientError.authenticationFailed("client nonce must contain thirty-two bytes") }
        self.bytes = bytes
    }
}

/// Caller-retained X25519 private key used only through handshake completion.
public struct ClientEphemeralSecret: Equatable, Sendable {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 32, bytes.contains(where: { $0 != 0 }) else {
            throw PhoneClientError.authenticationFailed("client ephemeral secret is invalid")
        }
        self.bytes = bytes
    }
}

/// Stable identity for a resumable companion upload.
public struct UploadID: Codable, Equatable, Hashable, Sendable {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 16 else { throw PhoneClientError.malformedWire("upload ID must contain sixteen bytes") }
        self.bytes = bytes
    }
}

/// Signed invitation received from the Host over a local transport.
public struct CompanionInvitation: Equatable, Sendable {
    public let pairingID: PairingID
    public let serverIdentity: CompanionServerIdentity
    public let expiresAtUTC: UInt64
    public let serverEphemeralPublicKey: Data
    public let serverProof: Data

    public init(
        pairingID: PairingID,
        serverIdentity: CompanionServerIdentity,
        expiresAtUTC: UInt64,
        serverEphemeralPublicKey: Data,
        serverProof: Data
    ) throws {
        guard serverEphemeralPublicKey.count == 32, serverProof.count == 64 else {
            throw PhoneClientError.malformedWire("pairing invitation key or proof has the wrong length")
        }
        self.pairingID = pairingID
        self.serverIdentity = serverIdentity
        self.expiresAtUTC = expiresAtUTC
        self.serverEphemeralPublicKey = serverEphemeralPublicKey
        self.serverProof = serverProof
    }

    /// Parses and authenticates the fixed-size WSO1 invitation.
    public static func fromWire(
        _ wire: Data,
        pinnedServerIdentity: CompanionServerIdentity,
        crypto: any CompanionCrypto = SystemCompanionCrypto()
    ) throws -> CompanionInvitation {
        guard wire.count == 156, wire.prefix(4) == Data("WSO1".utf8) else {
            throw PhoneClientError.malformedWire("pairing invitation has the wrong length or magic")
        }
        let invitation = try CompanionInvitation(
            pairingID: PairingID(bytes: Data(wire[4..<20])),
            serverIdentity: CompanionServerIdentity(bytes: Data(wire[20..<52])),
            expiresAtUTC: wire.readUInt64LE(at: 52),
            serverEphemeralPublicKey: Data(wire[60..<92]),
            serverProof: Data(wire[92..<156])
        )
        guard invitation.serverIdentity == pinnedServerIdentity else {
            throw PhoneClientError.serverIdentityMismatch
        }
        try crypto.verifyEd25519(
            publicKey: pinnedServerIdentity.bytes,
            message: invitation.signatureTranscript,
            signature: invitation.serverProof
        )
        return invitation
    }

    /// Encodes the canonical WSO1 invitation.
    public func toWire() -> Data {
        var wire = Data("WSO1".utf8)
        wire.append(pairingID.bytes)
        wire.append(serverIdentity.bytes)
        wire.appendUInt64LE(expiresAtUTC)
        wire.append(serverEphemeralPublicKey)
        wire.append(serverProof)
        return wire
    }

    /// Creates a code-authenticated handshake request and retained completion state.
    public func beginHandshake(
        pairingCode: PairingCode,
        clientNonce: ClientNonce,
        clientEphemeralSecret: ClientEphemeralSecret,
        clockResponses: [ClockSampleResponse],
        crypto: any CompanionCrypto = SystemCompanionCrypto()
    ) throws -> (request: CompanionHandshakeRequest, pending: PendingCompanionConnection) {
        guard (3...8).contains(clockResponses.count) else {
            throw PhoneClientError.timeRelationError("three to eight clock responses are required")
        }
        var clientSends = Set<UInt64>()
        for response in clockResponses {
            guard response.challenge.pairingID == pairingID,
                  response.challenge.clientNonce == clientNonce,
                  clientSends.insert(response.challenge.clientSend).inserted else {
                throw PhoneClientError.timeRelationError("clock responses do not match the pairing request")
            }
        }
        let clientPublicKey = try crypto.x25519PublicKey(privateKey: clientEphemeralSecret.bytes)
        let sharedSecret = try crypto.x25519SharedSecret(privateKey: clientEphemeralSecret.bytes, publicKey: serverEphemeralPublicKey)
        guard sharedSecret.count == 32, sharedSecret.contains(where: { $0 != 0 }) else {
            throw PhoneClientError.authenticationFailed("X25519 peer public key is low order")
        }
        var request = try CompanionHandshakeRequest(
            pairingID: pairingID,
            pinnedServerIdentity: serverIdentity,
            clientNonce: clientNonce,
            clientEphemeralPublicKey: clientPublicKey,
            codeProof: Data(repeating: 0, count: 32),
            clockResponses: clockResponses
        )
        let authenticationKey = try hkdfSHA256(inputKeyMaterial: sharedSecret, salt: pairingCode.bytes, info: pairingAuthenticationDomain, outputByteCount: 32)
        request.codeProof = hmacSHA256(key: authenticationKey, message: request.transcript)
        return (
            request,
            PendingCompanionConnection(
                pairingID: pairingID,
                serverIdentity: serverIdentity,
                clientNonce: clientNonce,
                pairingCode: pairingCode,
                sharedSecret: sharedSecret,
                clientEphemeralPublicKey: clientPublicKey,
                crypto: crypto
            )
        )
    }

    private var signatureTranscript: Data {
        var transcript = invitationSignatureDomain
        transcript.append(pairingID.bytes)
        transcript.append(serverIdentity.bytes)
        transcript.appendUInt64LE(expiresAtUTC)
        transcript.append(serverEphemeralPublicKey)
        return transcript
    }
}

/// Signed Host timing challenge for one phone send timestamp.
public struct ClockSampleChallenge: Equatable, Sendable {
    public let pairingID: PairingID
    public let clientNonce: ClientNonce
    public let clientSend: UInt64
    public let hostReceive: UInt64
    public let hostSend: UInt64
    public let serverProof: Data

    public init(pairingID: PairingID, clientNonce: ClientNonce, clientSend: UInt64, hostReceive: UInt64, hostSend: UInt64, serverProof: Data) throws {
        guard serverProof.count == 64 else { throw PhoneClientError.malformedWire("clock challenge proof must contain sixty-four bytes") }
        self.pairingID = pairingID
        self.clientNonce = clientNonce
        self.clientSend = clientSend
        self.hostReceive = hostReceive
        self.hostSend = hostSend
        self.serverProof = serverProof
    }

    public static func fromWire(_ wire: Data, pinnedServerIdentity: CompanionServerIdentity, crypto: any CompanionCrypto = SystemCompanionCrypto()) throws -> ClockSampleChallenge {
        guard wire.count == 140, wire.prefix(4) == Data("WSH1".utf8) else {
            throw PhoneClientError.malformedWire("clock challenge has the wrong length or magic")
        }
        let challenge = try ClockSampleChallenge(
            pairingID: PairingID(bytes: Data(wire[4..<20])),
            clientNonce: ClientNonce(bytes: Data(wire[20..<52])),
            clientSend: wire.readUInt64LE(at: 52),
            hostReceive: wire.readUInt64LE(at: 60),
            hostSend: wire.readUInt64LE(at: 68),
            serverProof: Data(wire[76..<140])
        )
        try crypto.verifyEd25519(publicKey: pinnedServerIdentity.bytes, message: challenge.signatureTranscript, signature: challenge.serverProof)
        return challenge
    }

    public func toWire() -> Data {
        var wire = Data("WSH1".utf8)
        wire.append(pairingID.bytes)
        wire.append(clientNonce.bytes)
        wire.appendUInt64LE(clientSend)
        wire.appendUInt64LE(hostReceive)
        wire.appendUInt64LE(hostSend)
        wire.append(serverProof)
        return wire
    }

    private var signatureTranscript: Data {
        var transcript = clockChallengeSignatureDomain
        transcript.append(pairingID.bytes)
        transcript.append(clientNonce.bytes)
        transcript.appendUInt64LE(clientSend)
        transcript.appendUInt64LE(hostReceive)
        transcript.appendUInt64LE(hostSend)
        return transcript
    }
}

/// Complete signed two-way timing sample.
public struct ClockSampleResponse: Equatable, Sendable {
    public let challenge: ClockSampleChallenge
    public let clientReceive: UInt64

    public init(challenge: ClockSampleChallenge, clientReceive: UInt64) {
        self.challenge = challenge
        self.clientReceive = clientReceive
    }

    public func toWire() -> Data {
        var wire = Data("WSR1".utf8)
        wire.append(challenge.toWire())
        wire.appendUInt64LE(clientReceive)
        return wire
    }

    public static func fromWire(_ wire: Data, pinnedServerIdentity: CompanionServerIdentity, crypto: any CompanionCrypto = SystemCompanionCrypto()) throws -> ClockSampleResponse {
        guard wire.count == 152, wire.prefix(4) == Data("WSR1".utf8) else {
            throw PhoneClientError.malformedWire("clock response has the wrong length or magic")
        }
        return ClockSampleResponse(
            challenge: try ClockSampleChallenge.fromWire(Data(wire[4..<144]), pinnedServerIdentity: pinnedServerIdentity, crypto: crypto),
            clientReceive: wire.readUInt64LE(at: 144)
        )
    }
}

/// Canonical code-authenticated handshake request.
public struct CompanionHandshakeRequest: Equatable, Sendable {
    public let pairingID: PairingID
    public let pinnedServerIdentity: CompanionServerIdentity
    public let clientNonce: ClientNonce
    public let clientEphemeralPublicKey: Data
    fileprivate var codeProof: Data
    public let clockResponses: [ClockSampleResponse]

    fileprivate init(pairingID: PairingID, pinnedServerIdentity: CompanionServerIdentity, clientNonce: ClientNonce, clientEphemeralPublicKey: Data, codeProof: Data, clockResponses: [ClockSampleResponse]) throws {
        guard clientEphemeralPublicKey.count == 32, codeProof.count == 32, (3...8).contains(clockResponses.count) else {
            throw PhoneClientError.malformedWire("handshake request fields are outside their bounds")
        }
        self.pairingID = pairingID
        self.pinnedServerIdentity = pinnedServerIdentity
        self.clientNonce = clientNonce
        self.clientEphemeralPublicKey = clientEphemeralPublicKey
        self.codeProof = codeProof
        self.clockResponses = clockResponses
    }

    public func toWire() -> Data {
        var wire = Data("WSQ1".utf8)
        wire.append(pairingID.bytes)
        wire.append(pinnedServerIdentity.bytes)
        wire.append(clientNonce.bytes)
        wire.append(clientEphemeralPublicKey)
        wire.append(codeProof)
        wire.appendUInt32LE(UInt32(clockResponses.count))
        for response in clockResponses { wire.append(response.toWire()) }
        return wire
    }

    public static func fromWire(_ wire: Data, crypto: any CompanionCrypto = SystemCompanionCrypto()) throws -> CompanionHandshakeRequest {
        guard wire.count >= 152, wire.prefix(4) == Data("WSQ1".utf8) else {
            throw PhoneClientError.malformedWire("handshake request has the wrong length or magic")
        }
        let count = Int(wire.readUInt32LE(at: 148))
        guard (3...8).contains(count), wire.count == 152 + count * 152 else {
            throw PhoneClientError.timeRelationError("handshake clock response count is invalid")
        }
        let identity = try CompanionServerIdentity(bytes: Data(wire[20..<52]))
        let pairingID = try PairingID(bytes: Data(wire[4..<20]))
        let clientNonce = try ClientNonce(bytes: Data(wire[52..<84]))
        var responses = [ClockSampleResponse]()
        responses.reserveCapacity(count)
        for index in 0..<count {
            let start = 152 + index * 152
            responses.append(try ClockSampleResponse.fromWire(Data(wire[start..<(start + 152)]), pinnedServerIdentity: identity, crypto: crypto))
        }
        guard responses.allSatisfy({ $0.challenge.pairingID == pairingID && $0.challenge.clientNonce == clientNonce }) else {
            throw PhoneClientError.timeRelationError("handshake clock responses do not match the request")
        }
        return try CompanionHandshakeRequest(
            pairingID: pairingID,
            pinnedServerIdentity: identity,
            clientNonce: clientNonce,
            clientEphemeralPublicKey: Data(wire[84..<116]),
            codeProof: Data(wire[116..<148]),
            clockResponses: responses
        )
    }

    fileprivate var transcript: Data {
        var transcript = pairingProofDomain
        transcript.append(pairingID.bytes)
        transcript.append(pinnedServerIdentity.bytes)
        transcript.append(clientNonce.bytes)
        transcript.append(clientEphemeralPublicKey)
        for response in clockResponses { transcript.append(response.toWire()) }
        return transcript
    }
}

/// Signed Host handshake response carrying the phone-to-Host clock relation.
public struct CompanionHandshakeResponse: Equatable, Sendable {
    public let sessionID: Data
    public let clockRelation: PhoneTimeRelation
    public let serverProof: Data

    public init(sessionID: Data, clockRelation: PhoneTimeRelation, serverProof: Data) throws {
        guard sessionID.count == 16, serverProof.count == 64 else {
            throw PhoneClientError.malformedWire("handshake response fields have the wrong length")
        }
        self.sessionID = sessionID
        self.clockRelation = clockRelation
        self.serverProof = serverProof
    }

    public static func fromWire(_ wire: Data) throws -> CompanionHandshakeResponse {
        guard wire.count == 148, wire.prefix(4) == Data("WSK1".utf8) else {
            throw PhoneClientError.malformedWire("handshake response has the wrong length or magic")
        }
        return try CompanionHandshakeResponse(
            sessionID: Data(wire[4..<20]),
            clockRelation: decodePhoneRelation(Data(wire[20..<84])),
            serverProof: Data(wire[84..<148])
        )
    }

    public func toWire() -> Data {
        var wire = Data("WSK1".utf8)
        wire.append(sessionID)
        wire.append(encodePhoneRelation(clockRelation))
        wire.append(serverProof)
        return wire
    }
}

/// Client state waiting for the signed Host handshake response.
public struct PendingCompanionConnection: Sendable {
    fileprivate let pairingID: PairingID
    fileprivate let serverIdentity: CompanionServerIdentity
    fileprivate let clientNonce: ClientNonce
    fileprivate let pairingCode: PairingCode
    fileprivate let sharedSecret: Data
    fileprivate let clientEphemeralPublicKey: Data
    fileprivate let crypto: any CompanionCrypto

    fileprivate init(pairingID: PairingID, serverIdentity: CompanionServerIdentity, clientNonce: ClientNonce, pairingCode: PairingCode, sharedSecret: Data, clientEphemeralPublicKey: Data, crypto: any CompanionCrypto) {
        self.pairingID = pairingID
        self.serverIdentity = serverIdentity
        self.clientNonce = clientNonce
        self.pairingCode = pairingCode
        self.sharedSecret = sharedSecret
        self.clientEphemeralPublicKey = clientEphemeralPublicKey
        self.crypto = crypto
    }

    /// Verifies the pinned Host response and constructs an encrypted phone session.
    public func complete(_ response: CompanionHandshakeResponse) throws -> CompanionConnection {
        let transcript = connectionTranscript(server: serverIdentity, pairingID: pairingID, sessionID: response.sessionID, clientNonce: clientNonce, clientEphemeralPublicKey: clientEphemeralPublicKey, relation: response.clockRelation)
        try crypto.verifyEd25519(publicKey: serverIdentity.bytes, message: transcript, signature: response.serverProof)
        var info = sessionKeyDomain
        info.append(pairingID.bytes)
        info.append(serverIdentity.bytes)
        info.append(clientEphemeralPublicKey)
        info.append(response.sessionID)
        info.append(clientNonce.bytes)
        info.append(encodePhoneRelation(response.clockRelation))
        let key = try hkdfSHA256(inputKeyMaterial: sharedSecret, salt: pairingCode.bytes, info: info, outputByteCount: 32)
        return CompanionConnection(pairingID: pairingID, sessionID: response.sessionID, key: key, serverIdentity: serverIdentity, clockRelation: response.clockRelation, clientNonce: clientNonce, clientEphemeralPublicKey: clientEphemeralPublicKey, serverProof: response.serverProof, crypto: crypto)
    }
}

/// Established client half of a paired encrypted companion session.
public struct CompanionConnection: Sendable {
    public let pairingID: PairingID
    public let sessionID: Data
    public let serverIdentity: CompanionServerIdentity
    public let clockRelation: PhoneTimeRelation
    fileprivate let key: Data
    fileprivate let clientNonce: ClientNonce
    fileprivate let clientEphemeralPublicKey: Data
    fileprivate let serverProof: Data
    fileprivate let crypto: any CompanionCrypto

    fileprivate init(pairingID: PairingID, sessionID: Data, key: Data, serverIdentity: CompanionServerIdentity, clockRelation: PhoneTimeRelation, clientNonce: ClientNonce, clientEphemeralPublicKey: Data, serverProof: Data, crypto: any CompanionCrypto) {
        self.pairingID = pairingID
        self.sessionID = sessionID
        self.key = key
        self.serverIdentity = serverIdentity
        self.clockRelation = clockRelation
        self.clientNonce = clientNonce
        self.clientEphemeralPublicKey = clientEphemeralPublicKey
        self.serverProof = serverProof
        self.crypto = crypto
    }

    /// Encrypts exact sealed artifact bytes into deterministic resumable WSC1 chunks.
    public func sealUpload(uploadID: UploadID, sealedBytes: Data, chunkBytes: Int = 64 * 1024) throws -> [CompanionChunk] {
        guard !sealedBytes.isEmpty, (1...64 * 1024).contains(chunkBytes) else {
            throw PhoneClientError.limitExceeded("upload and chunk sizes must be non-zero and bounded")
        }
        let chunkCount = (sealedBytes.count + chunkBytes - 1) / chunkBytes
        guard chunkCount <= 1_024 else { throw PhoneClientError.limitExceeded("companion upload chunk limit exceeded") }
        let digest = SHA256Digest.hash(sealedBytes)
        let totalBytes = UInt64(sealedBytes.count)
        var chunks = [CompanionChunk]()
        chunks.reserveCapacity(chunkCount)
        for index in 0..<chunkCount {
            let start = index * chunkBytes
            let end = min(start + chunkBytes, sealedBytes.count)
            let plaintext = Data(sealedBytes[start..<end])
            let nonce = chunkNonce(sessionID: sessionID, uploadID: uploadID, chunkBytes: UInt32(chunkBytes), chunkCount: UInt32(chunkCount), totalBytes: totalBytes, index: UInt32(index))
            let aad = chunkAAD(serverIdentity: serverIdentity, uploadID: uploadID, index: UInt32(index), chunkBytes: UInt32(chunkBytes), chunkCount: UInt32(chunkCount), totalBytes: totalBytes, digest: digest)
            let uploadKey = try hkdfSHA256(inputKeyMaterial: key, salt: digest, info: uploadKeyInfo(uploadID: uploadID, digest: digest, chunkBytes: UInt32(chunkBytes), chunkCount: UInt32(chunkCount), totalBytes: totalBytes), outputByteCount: 32)
            let ciphertext = try crypto.encryptAESGCM(key: uploadKey, nonce: nonce, plaintext: plaintext, authenticatedData: aad)
            chunks.append(try CompanionChunk(sessionID: sessionID, uploadID: uploadID, index: UInt32(index), chunkCount: UInt32(chunkCount), chunkPlaintextBytes: UInt32(chunkBytes), totalBytes: totalBytes, fullDigest: digest, ciphertext: ciphertext))
        }
        return chunks
    }
}

/// One independently authenticated encrypted upload chunk.
public struct CompanionChunk: Equatable, Sendable {
    public let sessionID: Data
    public let uploadID: UploadID
    public let index: UInt32
    public let chunkCount: UInt32
    public let chunkPlaintextBytes: UInt32
    public let totalBytes: UInt64
    public let fullDigest: Data
    public let ciphertext: Data

    public init(sessionID: Data, uploadID: UploadID, index: UInt32, chunkCount: UInt32, chunkPlaintextBytes: UInt32, totalBytes: UInt64, fullDigest: Data, ciphertext: Data) throws {
        guard sessionID.count == 16, fullDigest.count == 32,
              (1...1_024).contains(chunkCount), index < chunkCount,
              (1...(64 * 1024)).contains(chunkPlaintextBytes),
              totalBytes > 0, totalBytes <= 16 * 1024 * 1024,
              UInt64(chunkCount) == (totalBytes + UInt64(chunkPlaintextBytes) - 1) / UInt64(chunkPlaintextBytes),
              ciphertext.count == Int(min(UInt64(chunkPlaintextBytes), totalBytes - UInt64(index) * UInt64(chunkPlaintextBytes))) + 16 else {
            throw PhoneClientError.malformedWire("companion chunk fields have the wrong length")
        }
        self.sessionID = sessionID
        self.uploadID = uploadID
        self.index = index
        self.chunkCount = chunkCount
        self.chunkPlaintextBytes = chunkPlaintextBytes
        self.totalBytes = totalBytes
        self.fullDigest = fullDigest
        self.ciphertext = ciphertext
    }

    /// Encodes the canonical WSC1 transport frame.
    public func toWire() -> Data {
        var wire = Data("WSC1".utf8)
        wire.append(sessionID)
        wire.append(uploadID.bytes)
        wire.appendUInt32LE(index)
        wire.appendUInt32LE(chunkCount)
        wire.appendUInt32LE(chunkPlaintextBytes)
        wire.appendUInt64LE(totalBytes)
        wire.append(fullDigest)
        wire.appendUInt32LE(UInt32(ciphertext.count))
        wire.append(ciphertext)
        return wire
    }

    /// Parses a WSC1 frame without decrypting it.
    public static func fromWire(_ wire: Data, maxArtifactBytes: Int = 16 * 1024 * 1024) throws -> CompanionChunk {
        let maximumChunk = min(maxArtifactBytes, 64 * 1024)
        guard maxArtifactBytes > 0, maximumChunk > 0,
              wire.count >= 92, wire.count <= maximumChunk + 108,
              wire.prefix(4) == Data("WSC1".utf8) else {
            throw PhoneClientError.malformedWire("companion chunk frame is malformed")
        }
        let ciphertextLength = Int(wire.readUInt32LE(at: 88))
        let chunkPlaintextBytes = wire.readUInt32LE(at: 44)
        let chunkCount = wire.readUInt32LE(at: 40)
        let index = wire.readUInt32LE(at: 36)
        let totalBytes = wire.readUInt64LE(at: 48)
        guard wire.count == 92 + ciphertextLength,
              (1...1_024).contains(chunkCount), index < chunkCount,
              (1...(64 * 1024)).contains(chunkPlaintextBytes), totalBytes > 0,
              totalBytes <= UInt64(maxArtifactBytes),
              UInt64(chunkCount) == (totalBytes + UInt64(chunkPlaintextBytes) - 1) / UInt64(chunkPlaintextBytes),
              ciphertextLength == Int(min(UInt64(chunkPlaintextBytes), totalBytes - UInt64(index) * UInt64(chunkPlaintextBytes))) + 16 else {
            throw PhoneClientError.malformedWire("companion chunk frame length is invalid")
        }
        return try CompanionChunk(
            sessionID: Data(wire[4..<20]),
            uploadID: UploadID(bytes: Data(wire[20..<36])),
            index: wire.readUInt32LE(at: 36),
            chunkCount: wire.readUInt32LE(at: 40),
            chunkPlaintextBytes: wire.readUInt32LE(at: 44),
            totalBytes: wire.readUInt64LE(at: 48),
            fullDigest: Data(wire[56..<88]),
            ciphertext: Data(wire[92..<wire.count])
        )
    }
}

/// A resumable upload plan whose acknowledged chunks can be persisted independently of transport.
public struct ResumableUpload: Sendable {
    public let uploadID: UploadID
    public let chunks: [CompanionChunk]
    private var acknowledged: Set<UInt32>

    public init(uploadID: UploadID, chunks: [CompanionChunk], acknowledged: Set<UInt32> = []) {
        self.uploadID = uploadID
        self.chunks = chunks
        self.acknowledged = acknowledged
    }

    public var pendingChunks: [CompanionChunk] {
        chunks.filter { !acknowledged.contains($0.index) }
    }

    public var isComplete: Bool { acknowledged.count == chunks.count }

    public mutating func acknowledge(index: UInt32) throws {
        guard chunks.contains(where: { $0.index == index }) else {
            throw PhoneClientError.uploadConflict
        }
        acknowledged.insert(index)
    }
}

/// Minimal transport boundary used by the upload coordinator.
public protocol CompanionByteTransport: Sendable {
    func send(_ frame: Data) async throws -> Data
}

/// Uploads only missing chunks and leaves the plan intact when transport fails.
public struct CompanionUploadCoordinator: Sendable {
    public init() {}

    public func upload(_ plan: inout ResumableUpload, through transport: any CompanionByteTransport) async throws {
        for chunk in plan.pendingChunks {
            _ = try await transport.send(chunk.toWire())
            try plan.acknowledge(index: chunk.index)
        }
    }
}

/// Disk-backed cache of encrypted WSC1 chunks for offline resume.
public actor FileUploadCache {
    public let directory: URL

    public init(directory: URL) throws {
        self.directory = directory.standardizedFileURL
        try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true)
    }

    /// Stores one frame atomically. Replacing a different frame at the same index is rejected.
    public func store(_ chunk: CompanionChunk) throws {
        let url = fileURL(uploadID: chunk.uploadID, index: chunk.index)
        let frame = chunk.toWire()
        if FileManager.default.fileExists(atPath: url.path) {
            let existing = try Data(contentsOf: url)
            guard existing == frame else { throw PhoneClientError.uploadConflict }
            return
        }
        #if os(iOS)
        try frame.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
        #else
        try frame.write(to: url, options: [.atomic])
        #endif
    }

    /// Reads all cached chunks for one upload in index order.
    public func load(uploadID: UploadID, maxArtifactBytes: Int = 16 * 1024 * 1024) throws -> [CompanionChunk] {
        let prefix = "\(uploadID.bytes.map { String(format: "%02x", $0) }.joined())-"
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
            .filter { $0.hasPrefix(prefix) && $0.hasSuffix(".wsc1") }
            .sorted()
        var chunks = [CompanionChunk]()
        chunks.reserveCapacity(names.count)
        for name in names {
            let chunk = try CompanionChunk.fromWire(Data(contentsOf: directory.appendingPathComponent(name)), maxArtifactBytes: maxArtifactBytes)
            guard chunk.uploadID == uploadID else { throw PhoneClientError.uploadConflict }
            chunks.append(chunk)
        }
        return chunks.sorted { $0.index < $1.index }
    }

    /// Removes one upload's cached encrypted chunks after a committed receipt.
    public func remove(uploadID: UploadID) throws {
        let prefix = "\(uploadID.bytes.map { String(format: "%02x", $0) }.joined())-"
        for name in try FileManager.default.contentsOfDirectory(atPath: directory.path) where name.hasPrefix(prefix) && name.hasSuffix(".wsc1") {
            try FileManager.default.removeItem(at: directory.appendingPathComponent(name))
        }
    }

    private func fileURL(uploadID: UploadID, index: UInt32) -> URL {
        let identifier = uploadID.bytes.map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent("\(identifier)-\(index).wsc1", isDirectory: false)
    }
}

// MARK: - Companion wire helpers

private func encodePhoneRelation(_ relation: PhoneTimeRelation) -> Data {
    var output = Data()
    output.append(relation.relationID)
    output.appendInt64LE(relation.offsetAtReference)
    output.appendInt64LE(relation.driftPartsPerBillion)
    output.appendUInt64LE(relation.referencePhoneTime)
    output.appendUInt64LE(relation.maximumError)
    output.appendUInt64LE(relation.validFromPhoneTime)
    output.appendUInt64LE(relation.validUntilPhoneTime)
    return output
}

private func decodePhoneRelation(_ bytes: Data) throws -> PhoneTimeRelation {
    guard bytes.count == 64 else { throw PhoneClientError.timeRelationError("clock relation has the wrong length") }
    return try PhoneTimeRelation(relationID: Data(bytes[0..<16]), offsetAtReference: bytes.readInt64LE(at: 16), driftPartsPerBillion: bytes.readInt64LE(at: 24), referencePhoneTime: bytes.readUInt64LE(at: 32), maximumError: bytes.readUInt64LE(at: 40), validFromPhoneTime: bytes.readUInt64LE(at: 48), validUntilPhoneTime: bytes.readUInt64LE(at: 56))
}

private func connectionTranscript(server: CompanionServerIdentity, pairingID: PairingID, sessionID: Data, clientNonce: ClientNonce, clientEphemeralPublicKey: Data, relation: PhoneTimeRelation) -> Data {
    var output = sessionSignatureDomain
    output.append(server.bytes)
    output.append(pairingID.bytes)
    output.append(sessionID)
    output.append(clientNonce.bytes)
    output.append(clientEphemeralPublicKey)
    output.append(encodePhoneRelation(relation))
    return output
}

private func uploadKeyInfo(uploadID: UploadID, digest: Data, chunkBytes: UInt32, chunkCount: UInt32, totalBytes: UInt64) -> Data {
    var output = uploadKeyDomain
    output.append(uploadID.bytes)
    output.append(digest)
    output.appendUInt32LE(chunkBytes)
    output.appendUInt32LE(chunkCount)
    output.appendUInt64LE(totalBytes)
    return output
}

private func chunkNonce(sessionID: Data, uploadID: UploadID, chunkBytes: UInt32, chunkCount: UInt32, totalBytes: UInt64, index: UInt32) -> Data {
    var input = chunkNonceDomain
    input.append(sessionID)
    input.append(uploadID.bytes)
    input.appendUInt32LE(chunkBytes)
    input.appendUInt32LE(chunkCount)
    input.appendUInt64LE(totalBytes)
    input.appendUInt32LE(index)
    return SHA256Digest.hash(input).prefix(12)
}

private func chunkAAD(serverIdentity: CompanionServerIdentity, uploadID: UploadID, index: UInt32, chunkBytes: UInt32, chunkCount: UInt32, totalBytes: UInt64, digest: Data) -> Data {
    var output = chunkAADDomain
    output.append(serverIdentity.bytes)
    output.append(uploadID.bytes)
    output.appendUInt32LE(index)
    output.appendUInt32LE(chunkBytes)
    output.appendUInt32LE(chunkCount)
    output.appendUInt64LE(totalBytes)
    output.append(digest)
    return output
}
