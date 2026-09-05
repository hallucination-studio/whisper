import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// Cryptographic operations required by the companion wire contract.
///
/// The protocol is injectable so wire/state tests can run without a live Host. Production phone
/// builds use `SystemCompanionCrypto`, which delegates platform primitives to CryptoKit.
public protocol CompanionCrypto: Sendable {
    func verifyEd25519(publicKey: Data, message: Data, signature: Data) throws
    func x25519PublicKey(privateKey: Data) throws -> Data
    func x25519SharedSecret(privateKey: Data, publicKey: Data) throws -> Data
    func encryptAESGCM(key: Data, nonce: Data, plaintext: Data, authenticatedData: Data) throws -> Data
}

/// CryptoKit-backed companion cryptography on Apple platforms.
public struct SystemCompanionCrypto: CompanionCrypto, Sendable {
    public init() {}

    public func verifyEd25519(publicKey: Data, message: Data, signature: Data) throws {
        #if canImport(CryptoKit)
        guard publicKey.count == 32, signature.count == 64 else {
            throw PhoneClientError.authenticationFailed("Ed25519 key or signature has the wrong length")
        }
        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        } catch {
            throw PhoneClientError.authenticationFailed("Ed25519 public key is invalid")
        }
        guard key.isValidSignature(signature, for: message) else {
            throw PhoneClientError.authenticationFailed("Ed25519 signature is invalid")
        }
        #else
        _ = (publicKey, message, signature)
        throw PhoneClientError.unsupportedPlatform("CryptoKit is required for companion signatures")
        #endif
    }

    public func x25519SharedSecret(privateKey: Data, publicKey: Data) throws -> Data {
        #if canImport(CryptoKit)
        guard privateKey.count == 32, publicKey.count == 32, privateKey.contains(where: { $0 != 0 }) else {
            throw PhoneClientError.authenticationFailed("X25519 key has the wrong length")
        }
        do {
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            let shared = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            return shared.withUnsafeBytes { Data($0) }
        } catch {
            throw PhoneClientError.authenticationFailed("X25519 key agreement failed")
        }
        #else
        _ = (privateKey, publicKey)
        throw PhoneClientError.unsupportedPlatform("CryptoKit is required for companion key agreement")
        #endif
    }

    public func x25519PublicKey(privateKey: Data) throws -> Data {
        #if canImport(CryptoKit)
        guard privateKey.count == 32, privateKey.contains(where: { $0 != 0 }) else {
            throw PhoneClientError.authenticationFailed("X25519 private key has the wrong length")
        }
        do {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
        } catch {
            throw PhoneClientError.authenticationFailed("X25519 private key is invalid")
        }
        #else
        _ = privateKey
        throw PhoneClientError.unsupportedPlatform("CryptoKit is required for companion key agreement")
        #endif
    }

    public func encryptAESGCM(key: Data, nonce: Data, plaintext: Data, authenticatedData: Data) throws -> Data {
        #if canImport(CryptoKit)
        guard key.count == 32, nonce.count == 12 else {
            throw PhoneClientError.authenticationFailed("AES-GCM key or nonce has the wrong length")
        }
        do {
            let sealed = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: AES.GCM.Nonce(data: nonce),
                authenticating: authenticatedData
            )
            var result = Data(sealed.ciphertext)
            result.append(sealed.tag)
            return result
        } catch {
            throw PhoneClientError.authenticationFailed("AES-GCM encryption failed")
        }
        #else
        _ = (key, nonce, plaintext, authenticatedData)
        throw PhoneClientError.unsupportedPlatform("CryptoKit is required for companion encryption")
        #endif
    }
}

/// Computes HMAC-SHA256 without tying the canonical wire contract to one platform library.
func hmacSHA256(key: Data, message: Data) -> Data {
    let blockSize = 64
    var normalized = Array(key)
    if normalized.count > blockSize {
        normalized = Array(SHA256Digest.hash(Data(normalized)))
    }
    normalized += Array(repeating: 0, count: blockSize - normalized.count)
    var inner = Data(capacity: blockSize + message.count)
    var outer = Data(capacity: blockSize + 32)
    for byte in normalized {
        inner.append(byte ^ 0x36)
        outer.append(byte ^ 0x5c)
    }
    inner.append(message)
    outer.append(SHA256Digest.hash(inner))
    return SHA256Digest.hash(outer)
}

/// Computes HKDF-SHA256 with the RFC 5869 extract-and-expand construction.
func hkdfSHA256(inputKeyMaterial: Data, salt: Data, info: Data, outputByteCount: Int) throws -> Data {
    guard outputByteCount >= 0, outputByteCount <= 255 * 32 else {
        throw PhoneClientError.limitExceeded("HKDF output length is unsupported")
    }
    let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
    let pseudorandomKey = hmacSHA256(key: effectiveSalt, message: inputKeyMaterial)
    if outputByteCount == 0 { return Data() }
    var output = Data(capacity: outputByteCount)
    var previous = Data()
    var counter: UInt8 = 1
    while output.count < outputByteCount {
        var input = Data(capacity: previous.count + info.count + 1)
        input.append(previous)
        input.append(info)
        input.append(counter)
        previous = hmacSHA256(key: pseudorandomKey, message: input)
        output.append(previous)
        counter += 1
    }
    return output.prefix(outputByteCount)
}
