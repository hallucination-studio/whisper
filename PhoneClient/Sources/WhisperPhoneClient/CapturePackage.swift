import Foundation

/// A bounded RGB or depth payload referenced by a supervision sample.
public struct CaptureMedia: Codable, Equatable, Sendable {
    public let reference: String
    public let kind: CaptureMediaKind
    public let phoneTime: UInt64
    public let bytes: Data

    public init(reference: String, kind: CaptureMediaKind, phoneTime: UInt64, bytes: Data) throws {
        guard !reference.isEmpty, !bytes.isEmpty, bytes.count <= 8 * 1024 * 1024 else {
            throw PhoneClientError.invalidInput("capture media reference or bounded payload is invalid")
        }
        self.reference = reference
        self.kind = kind
        self.phoneTime = phoneTime
        self.bytes = bytes
    }
}

/// Media kind retained for one aligned camera observation.
public enum CaptureMediaKind: UInt8, Codable, Equatable, Sendable {
    case rgb = 1
    case depth = 2
}

/// A retained camera keyframe needed to replay scene-coordinate supervision.
public struct CameraKeyframe: Codable, Equatable, Sendable {
    public let reference: String
    public let phoneTime: UInt64
    public let pose: CoordinateTransform
    public let trackingEpoch: UInt32
    public let trackingQuality: TrackingQuality
    public let depthQuality: DepthQuality

    public init(reference: String, phoneTime: UInt64, pose: CoordinateTransform, trackingEpoch: UInt32, trackingQuality: TrackingQuality, depthQuality: DepthQuality) {
        self.reference = reference
        self.phoneTime = phoneTime
        self.pose = pose
        self.trackingEpoch = trackingEpoch
        self.trackingQuality = trackingQuality
        self.depthQuality = depthQuality
    }

    func validate(worldCoordinateSystem: String) throws {
        try requireText(reference, field: "camera keyframe reference")
        try pose.validate()
        guard pose.targetCoordinateSystem == worldCoordinateSystem else {
            throw PhoneClientError.transformError("camera keyframe target does not match the scene")
        }
    }
}

/// Authenticated prerequisites required before a phone capture can be exported.
public struct PhoneExportPrerequisites: Equatable, Sendable {
    public let measuredRegistration: MeasuredRFRegistrationInput
    public let verifiedCompanionRelation: VerifiedCompanionTimeRelation

    public init(
        measuredRegistration: MeasuredRFRegistrationInput,
        verifiedCompanionRelation: VerifiedCompanionTimeRelation
    ) throws {
        _ = try measuredRegistration.registration()
        self.measuredRegistration = measuredRegistration
        self.verifiedCompanionRelation = verifiedCompanionRelation
    }
}

/// The complete local export consisting of three Host-importable artifacts and display assets.
public struct PhoneCapturePackage: Equatable, Sendable {
    public let scene: SceneSnapshot
    public let calibration: CalibrationBundle
    public let supervision: SupervisionSegment
    /// Required RoomPlan USDZ bytes; structured scene geometry remains authoritative.
    public let usdzData: Data
    /// Bounded RGB/depth payloads referenced by supervision samples.
    public let media: [CaptureMedia]
    public let keyframes: [CameraKeyframe]
    public let limits: ArtifactLimits

    public init(
        scene: SceneSnapshot,
        calibration: CalibrationBundle,
        supervision: SupervisionSegment,
        usdzData: Data,
        keyframes: [CameraKeyframe],
        media: [CaptureMedia],
        exportPrerequisites: PhoneExportPrerequisites,
        limits: ArtifactLimits = ArtifactLimits(),
        knownRFIdentities: Set<String>
    ) throws {
        try validatePackage(scene: scene, calibration: calibration, supervision: supervision, usdzData: usdzData, keyframes: keyframes, media: media, limits: limits, knownRFIdentities: knownRFIdentities, exportPrerequisites: exportPrerequisites)
        self.scene = scene
        self.calibration = calibration
        self.supervision = supervision
        self.usdzData = usdzData
        self.media = media
        self.keyframes = keyframes
        self.limits = limits
    }

    private init(
        parsedScene scene: SceneSnapshot,
        calibration: CalibrationBundle,
        supervision: SupervisionSegment,
        usdzData: Data,
        keyframes: [CameraKeyframe],
        media: [CaptureMedia],
        limits: ArtifactLimits,
        knownRFIdentities: Set<String>
    ) throws {
        try validatePackage(scene: scene, calibration: calibration, supervision: supervision, usdzData: usdzData, keyframes: keyframes, media: media, limits: limits, knownRFIdentities: knownRFIdentities, exportPrerequisites: nil)
        self.scene = scene
        self.calibration = calibration
        self.supervision = supervision
        self.usdzData = usdzData
        self.media = media
        self.keyframes = keyframes
        self.limits = limits
    }

    /// Returns the exact three WSA1 artifacts to upload or import through the Host.
    public func sealedArtifacts() throws -> [SealedArtifact] {
        [try .seal(.scene(scene)), try .seal(.calibration(calibration)), try .seal(.supervision(supervision))]
    }

    /// Encodes a deterministic local recovery archive; transport still sends WSA1 artifacts.
    public func encoded() throws -> Data {
        let artifacts = try sealedArtifacts()
        var payload = Data()
        for artifact in artifacts {
            guard artifact.bytes.count <= UInt32.max else {
                throw PhoneClientError.limitExceeded("embedded artifact length exceeds the package format")
            }
            payload.appendUInt32LE(UInt32(artifact.bytes.count))
            payload.append(artifact.bytes)
        }
        guard usdzData.count <= limits.maxArtifactBytes, usdzData.count <= UInt32.max else {
            throw PhoneClientError.limitExceeded("USDZ display asset exceeds the package byte limit")
        }
        payload.append(1)
        payload.appendUInt32LE(UInt32(usdzData.count))
        payload.append(usdzData)
        guard media.count <= 100_000 else { throw PhoneClientError.limitExceeded("capture media count exceeds the package limit") }
        payload.appendUInt32LE(UInt32(media.count))
        for item in media {
            try encodeMedia(&payload, item, limits: limits)
        }
        guard keyframes.count <= 100_000 else { throw PhoneClientError.limitExceeded("camera keyframe limit exceeded") }
        guard payload.count <= UInt32.max else {
            throw PhoneClientError.limitExceeded("phone export payload exceeds the package format")
        }
        payload.appendUInt32LE(UInt32(keyframes.count))
        for keyframe in keyframes {
            try encodeKeyframe(&payload, keyframe)
        }
        var archive = Data("WSP1".utf8)
        archive.appendUInt16LE(2)
        archive.appendUInt16LE(0)
        archive.appendUInt32LE(UInt32(payload.count))
        archive.append(payload)
        archive.append(SHA256Digest.hash(archive))
        guard archive.count <= limits.maxArtifactBytes else {
            throw PhoneClientError.limitExceeded("phone export package exceeds the byte limit")
        }
        return archive
    }

    /// Digest of the complete deterministic local export archive.
    public func digest() throws -> ArtifactDigest {
        try ArtifactDigest(bytes: SHA256Digest.hash(encoded()))
    }

    /// Parses an archive and validates all embedded artifact relationships.
    public static func parse(_ archive: Data, knownRFIdentities: Set<String>, limits: ArtifactLimits = ArtifactLimits()) throws -> PhoneCapturePackage {
        try limits.validate()
        guard archive.count >= 20, archive.count <= limits.maxArtifactBytes, archive.prefix(4) == Data("WSP1".utf8), archive.readUInt16LE(at: 4) == 2, archive.readUInt16LE(at: 6) == 0 else {
            throw PhoneClientError.invalidArtifact("phone export archive header is invalid")
        }
        let payloadLength = Int(archive.readUInt32LE(at: 8))
        guard payloadLength == archive.count - 12 - 32 else {
            throw PhoneClientError.invalidArtifact("phone export archive length is invalid")
        }
        let digestOffset = archive.count - 32
        guard SHA256Digest.hash(archive.prefix(digestOffset)) == archive.suffix(32) else {
            throw PhoneClientError.invalidArtifact("phone export archive digest does not match")
        }
        var reader = BinaryReader(Data(archive[12..<digestOffset]))
        var artifacts = [SealedArtifact]()
        for _ in 0..<3 {
            let length = Int(try reader.u32())
            guard length <= limits.maxArtifactBytes else { throw PhoneClientError.limitExceeded("embedded artifact exceeds the byte limit") }
            artifacts.append(try SealedArtifact.parse(try reader.take(length)))
        }
        let hasUSDZ = try reader.u8()
        let usdzLength = Int(try reader.u32())
        let usdzData: Data
        switch hasUSDZ {
        case 1:
            guard usdzLength > 0, usdzLength <= limits.maxArtifactBytes else { throw PhoneClientError.limitExceeded("USDZ display asset exceeds the byte limit") }
            usdzData = try reader.take(usdzLength)
        default:
            throw PhoneClientError.invalidArtifact("USDZ asset is required")
        }
        let mediaCount = try reader.count()
        var media = [CaptureMedia]()
        media.reserveCapacity(mediaCount)
        for _ in 0..<mediaCount {
            media.append(try decodeMedia(&reader, limits: limits))
        }
        let keyframeCount = try reader.count()
        var keyframes = [CameraKeyframe]()
        keyframes.reserveCapacity(keyframeCount)
        for _ in 0..<keyframeCount { keyframes.append(try decodeKeyframe(&reader)) }
        guard reader.isEmpty else { throw PhoneClientError.invalidArtifact("phone export archive has trailing bytes") }
        guard artifacts.count == 3 else { throw PhoneClientError.invalidArtifact("phone export archive is incomplete") }
        guard case let .scene(scene) = try artifacts[0].decode(),
              case let .calibration(calibration) = try artifacts[1].decode(),
              case let .supervision(supervision) = try artifacts[2].decode() else {
            throw PhoneClientError.invalidArtifact("phone export artifacts are not scene/calibration/supervision")
        }
        return try PhoneCapturePackage(parsedScene: scene, calibration: calibration, supervision: supervision, usdzData: usdzData, keyframes: keyframes, media: media, limits: limits, knownRFIdentities: knownRFIdentities)
    }
}

/// Builds a candidate package while applying Host-compatible RF identity and error budgets.
public struct PhoneArtifactExporter: Sendable {
    public let limits: ArtifactLimits
    public let knownRFIdentities: Set<String>
    public let exportPrerequisites: PhoneExportPrerequisites

    public init(
        limits: ArtifactLimits = ArtifactLimits(),
        knownRFIdentities: Set<String>,
        exportPrerequisites: PhoneExportPrerequisites
    ) throws {
        try limits.validate()
        self.limits = limits
        self.knownRFIdentities = knownRFIdentities
        self.exportPrerequisites = exportPrerequisites
    }

    public func makePackage(scene: SceneSnapshot, calibration: CalibrationBundle, supervision: SupervisionSegment, usdzData: Data, keyframes: [CameraKeyframe], media: [CaptureMedia]) throws -> PhoneCapturePackage {
        try PhoneCapturePackage(scene: scene, calibration: calibration, supervision: supervision, usdzData: usdzData, keyframes: keyframes, media: media, exportPrerequisites: exportPrerequisites, limits: limits, knownRFIdentities: knownRFIdentities)
    }
}

private func validatePackage(scene: SceneSnapshot, calibration: CalibrationBundle, supervision: SupervisionSegment, usdzData: Data, keyframes: [CameraKeyframe], media: [CaptureMedia], limits: ArtifactLimits, knownRFIdentities: Set<String>, exportPrerequisites: PhoneExportPrerequisites?) throws {
    try limits.validate()
    try scene.validate()
    try calibration.validate()
    try supervision.validate()
    guard scene.geometry.count <= limits.maxGeometryElements,
          supervision.samples.count <= limits.maxSupervisionSamples else {
        throw PhoneClientError.limitExceeded("spatial artifact collection limit exceeded")
    }
    guard calibration.arrayGeometry.elements.count == Int(calibration.arrayCondition.physicalElementCount) else {
        throw PhoneClientError.invalidArtifact("calibration geometry differs from the declared physical element count")
    }
    guard supervision.maximumPersonVelocityMPS >= limits.minimumPersonVelocityMPS else {
        throw PhoneClientError.errorBudgetExceeded
    }
    guard knownRFIdentities.contains(calibration.rfDeviceIdentity) else {
        throw PhoneClientError.unknownRFIdentity(calibration.rfDeviceIdentity)
    }
    if let exportPrerequisites {
        guard calibration.rfDeviceIdentity == exportPrerequisites.measuredRegistration.rfDeviceIdentity,
              supervision.timeRelation == exportPrerequisites.verifiedCompanionRelation.relation else {
            throw PhoneClientError.exportPrerequisitesMissing
        }
    }
    guard calibration.worldTransform.targetCoordinateSystem == scene.worldCoordinateSystem else {
        throw PhoneClientError.transformError("calibration target does not match the scene")
    }
    let sceneDigest = try SealedArtifact.seal(.scene(scene)).digest
    guard calibration.sceneDigest == sceneDigest, supervision.sceneDigest == sceneDigest else {
        throw PhoneClientError.invalidArtifact("calibration and supervision must reference this scene digest")
    }
    let combinedCalibrationError = scene.mapErrorM + calibration.worldTransform.maxErrorM + calibration.arrayGeometry.deviceToArray.maxErrorM + calibration.arrayGeometry.maximumPositionErrorM + calibration.maxErrorM
    guard combinedCalibrationError <= limits.maxPositionErrorM else { throw PhoneClientError.errorBudgetExceeded }
    for sample in supervision.samples {
        guard sample.cameraToWorld.targetCoordinateSystem == scene.worldCoordinateSystem else {
            throw PhoneClientError.transformError("camera pose target does not match the scene")
        }
        guard let relationError = supervision.timeRelation.error(at: sample.poseTime) else {
            throw PhoneClientError.timeRelationError("sample is outside the phone clock relation")
        }
        let temporalErrorM = Double(relationError + sample.maximumTimeError) / 1_000_000_000 * supervision.maximumPersonVelocityMPS
        let individualError: Double
        switch sample.label {
        case let .visibleSet(people): individualError = people.map(\.maxErrorM).max() ?? 0
        case .unknown, .wholeRoomEmpty: individualError = 0
        }
        let total = scene.mapErrorM + supervision.sharedPositionErrorM + sample.cameraToWorld.maxErrorM + sample.jointErrorM + individualError + temporalErrorM
        guard total <= limits.maxPositionErrorM else { throw PhoneClientError.errorBudgetExceeded }
    }
    guard !usdzData.isEmpty, usdzData.count <= limits.maxArtifactBytes else {
        throw PhoneClientError.limitExceeded("USDZ display asset is required and bounded")
    }
    guard scene.usdzDisplayReference?.isEmpty == false else {
        throw PhoneClientError.invalidArtifact("scene must name the required USDZ asset")
    }
    guard !keyframes.isEmpty else { throw PhoneClientError.invalidArtifact("supervision requires camera keyframes") }
    guard !media.isEmpty else { throw PhoneClientError.invalidArtifact("supervision requires bounded RGB/depth media") }
    var mediaByReference = [String: CaptureMedia]()
    var mediaBytes = 0
    for item in media {
        guard mediaByReference.updateValue(item, forKey: item.reference) == nil else {
            throw PhoneClientError.invalidArtifact("capture media references must be unique")
        }
        guard item.bytes.count <= limits.maxMediaBytes,
              mediaBytes <= limits.maxMediaBytes - item.bytes.count else {
            throw PhoneClientError.limitExceeded("referenced capture media exceeds its byte budget")
        }
        mediaBytes += item.bytes.count
    }
    var previousTime: UInt64?
    var keyframesByReference = [String: CameraKeyframe]()
    for keyframe in keyframes {
        try keyframe.validate(worldCoordinateSystem: scene.worldCoordinateSystem)
        guard keyframesByReference.updateValue(keyframe, forKey: keyframe.reference) == nil else {
            throw PhoneClientError.invalidArtifact("camera keyframe references must be unique")
        }
        if let previousTime, keyframe.phoneTime < previousTime { throw PhoneClientError.invalidArtifact("camera keyframes are not time ordered") }
        previousTime = keyframe.phoneTime
    }
    var referencedMedia = Set<String>()
    var referencedKeyframes = Set<String>()
    for sample in supervision.samples {
        guard let rgb = mediaByReference[sample.rgbReference], rgb.kind == .rgb, rgb.phoneTime == sample.rgbTime else {
            throw PhoneClientError.invalidArtifact("supervision RGB reference is incomplete")
        }
        referencedMedia.insert(sample.rgbReference)
        if let depthReference = sample.depthReference {
            guard let depth = mediaByReference[depthReference], depth.kind == .depth, depth.phoneTime == sample.depthTime else {
                throw PhoneClientError.invalidArtifact("supervision depth reference is incomplete")
            }
            referencedMedia.insert(depthReference)
        }
        guard let keyframe = keyframesByReference[sample.poseReference], keyframe.phoneTime == sample.poseTime, keyframe.trackingEpoch == sample.trackingEpoch else {
            throw PhoneClientError.invalidArtifact("supervision pose keyframe reference is incomplete")
        }
        referencedKeyframes.insert(sample.poseReference)
    }
    guard referencedMedia == Set(mediaByReference.keys), referencedKeyframes == Set(keyframesByReference.keys) else {
        throw PhoneClientError.invalidArtifact("package contains unreferenced media or keyframes")
    }
}

private func encodeMedia(_ output: inout Data, _ media: CaptureMedia, limits: ArtifactLimits) throws {
    let reference = Data(media.reference.utf8)
    guard reference.count <= 100_000, media.bytes.count <= limits.maxMediaBytes, media.bytes.count <= UInt32.max else {
        throw PhoneClientError.limitExceeded("capture media reference or bytes exceed the package limit")
    }
    output.append(media.kind.rawValue)
    output.appendUInt32LE(UInt32(reference.count))
    output.append(reference)
    output.appendUInt64LE(media.phoneTime)
    output.appendUInt32LE(UInt32(media.bytes.count))
    output.append(media.bytes)
}

private func decodeMedia(_ reader: inout BinaryReader, limits: ArtifactLimits) throws -> CaptureMedia {
    guard let kind = CaptureMediaKind(rawValue: try reader.u8()) else {
        throw PhoneClientError.invalidArtifact("capture media kind is unsupported")
    }
    let reference = try reader.string()
    let phoneTime = try reader.u64()
    let length = Int(try reader.u32())
    guard length <= limits.maxMediaBytes else { throw PhoneClientError.limitExceeded("capture media exceeds the package limit") }
    return try CaptureMedia(reference: reference, kind: kind, phoneTime: phoneTime, bytes: reader.take(length))
}

private func encodeKeyframe(_ output: inout Data, _ keyframe: CameraKeyframe) throws {
    let bytes = Data(keyframe.reference.utf8)
    guard bytes.count <= 100_000 else { throw PhoneClientError.limitExceeded("camera keyframe reference is too large") }
    output.appendUInt32LE(UInt32(bytes.count))
    output.append(bytes)
    output.appendUInt64LE(keyframe.phoneTime)
    output.appendUInt32LE(keyframe.trackingEpoch)
    output.append(keyframe.trackingQuality.rawValue)
    output.append(keyframe.depthQuality.rawValue)
    guard keyframe.pose.matrix.count == 16 else { throw PhoneClientError.transformError("camera keyframe matrix must contain sixteen values") }
    let source = Data(keyframe.pose.sourceCoordinateSystem.utf8)
    let target = Data(keyframe.pose.targetCoordinateSystem.utf8)
    guard source.count <= 100_000, target.count <= 100_000 else {
        throw PhoneClientError.limitExceeded("camera keyframe coordinate identity is too large")
    }
    output.appendUInt32LE(UInt32(source.count))
    output.append(source)
    output.appendUInt32LE(UInt32(target.count))
    output.append(target)
    for value in keyframe.pose.matrix { output.appendDoubleLE(value) }
    output.appendDoubleLE(keyframe.pose.maxErrorM)
}

private func decodeKeyframe(_ reader: inout BinaryReader) throws -> CameraKeyframe {
    let reference = try reader.string()
    let phoneTime = try reader.u64()
    let epoch = try reader.u32()
    guard let trackingQuality = TrackingQuality(rawValue: try reader.u8()), let depthQuality = DepthQuality(rawValue: try reader.u8()) else {
        throw PhoneClientError.invalidArtifact("camera keyframe quality is unsupported")
    }
    let source = try reader.string()
    let target = try reader.string()
    var matrix = [Double]()
    matrix.reserveCapacity(16)
    for _ in 0..<16 { matrix.append(try reader.f64()) }
    return CameraKeyframe(reference: reference, phoneTime: phoneTime, pose: CoordinateTransform(sourceCoordinateSystem: source, targetCoordinateSystem: target, matrix: matrix, maxErrorM: try reader.f64()), trackingEpoch: epoch, trackingQuality: trackingQuality, depthQuality: depthQuality)
}
