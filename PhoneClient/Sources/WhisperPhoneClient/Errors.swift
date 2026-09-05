import Foundation

/// Errors raised while collecting, validating, encoding, or transporting a phone artifact.
public enum PhoneClientError: Error, Equatable, Sendable, LocalizedError {
    case invalidArtifact(String)
    case invalidInput(String)
    case invalidState(String)
    case limitExceeded(String)
    case trackingResetRequiresRelocalization
    case transformError(String)
    case timeRelationError(String)
    case invitationExpired
    case measuredRegistrationRequired
    case companionRelationRequired
    case exportPrerequisitesMissing
    case unknownRFIdentity(String)
    case errorBudgetExceeded
    case malformedWire(String)
    case serverIdentityMismatch
    case authenticationFailed(String)
    case uploadConflict
    case uploadRejected(String)
    case uploadUnavailable
    case persistence(String)
    case unsupportedPlatform(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidArtifact(message): return "invalid artifact: \(message)"
        case let .invalidInput(message): return "invalid input: \(message)"
        case let .invalidState(message): return "invalid state: \(message)"
        case let .limitExceeded(message): return "limit exceeded: \(message)"
        case .trackingResetRequiresRelocalization:
            return "tracking reset requires relocalization before capture can resume"
        case let .transformError(message): return "coordinate transform error: \(message)"
        case let .timeRelationError(message): return "time relation error: \(message)"
        case .invitationExpired: return "companion invitation has expired"
        case .measuredRegistrationRequired: return "measured RF registration is required before export"
        case .companionRelationRequired: return "an authenticated companion clock relation is required before capture export"
        case .exportPrerequisitesMissing: return "capture export prerequisites are incomplete"
        case let .unknownRFIdentity(identity): return "unknown RF identity: \(identity)"
        case .errorBudgetExceeded: return "spatial and time uncertainty exceeds the position budget"
        case let .malformedWire(message): return "malformed companion wire data: \(message)"
        case .serverIdentityMismatch: return "companion server identity does not match the pin"
        case let .authenticationFailed(message): return "companion authentication failed: \(message)"
        case .uploadConflict: return "companion upload conflicts with retained content"
        case let .uploadRejected(message): return "companion upload was rejected: \(message)"
        case .uploadUnavailable: return "companion upload is unavailable"
        case let .persistence(message): return "phone artifact persistence failed: \(message)"
        case let .unsupportedPlatform(message): return "unsupported phone platform: \(message)"
        }
    }
}

@inline(__always)
func requireText(_ value: String, field: String) throws {
    guard !value.isEmpty else {
        throw PhoneClientError.invalidArtifact("\(field) must not be empty")
    }
}

@inline(__always)
func requireFinite(_ value: Double, field: String) throws {
    guard value.isFinite else {
        throw PhoneClientError.invalidArtifact("\(field) must be finite")
    }
}

@inline(__always)
func requireNonnegativeFinite(_ value: Double, field: String) throws {
    guard value.isFinite, value >= 0 else {
        throw PhoneClientError.invalidArtifact("\(field) must be finite and non-negative")
    }
}

@inline(__always)
func requireUnitInterval(_ value: Double, field: String) throws {
    guard value.isFinite, (0...1).contains(value) else {
        throw PhoneClientError.invalidArtifact("\(field) must be finite and between zero and one")
    }
}

@inline(__always)
func requireFiniteVector(_ value: [Double], field: String) throws {
    guard value.allSatisfy(\.isFinite) else {
        throw PhoneClientError.invalidArtifact("\(field) must contain only finite values")
    }
}
