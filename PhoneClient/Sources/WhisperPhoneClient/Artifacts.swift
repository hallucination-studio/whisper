import Foundation

// MARK: - Shared artifact values

/// A stable source identity carried in artifact provenance and sample metadata.
public struct SourceIdentity: Codable, Equatable, Hashable, Sendable {
    public let namespace: String
    public let identity: String

    public init(namespace: String, identity: String) {
        self.namespace = namespace
        self.identity = identity
    }

    func validate() throws {
        try requireText(namespace, field: "source namespace")
        try requireText(identity, field: "source identity")
    }
}

/// Immutable identity and provenance shared by every spatial artifact.
public struct ArtifactMetadata: Codable, Equatable, Hashable, Sendable {
    public let artifactID: String
    public let revision: UInt32
    public let provenance: [SourceIdentity]

    public init(artifactID: String, revision: UInt32, provenance: [SourceIdentity]) {
        self.artifactID = artifactID
        self.revision = revision
        self.provenance = provenance
    }

    func validate() throws {
        try requireText(artifactID, field: "artifact ID")
        guard !provenance.isEmpty else {
            throw PhoneClientError.invalidArtifact("artifact provenance must not be empty")
        }
        for source in provenance {
            try source.validate()
        }
    }
}

/// A bounded transform between two explicitly named coordinate systems.
public struct CoordinateTransform: Codable, Equatable, Sendable {
    public let sourceCoordinateSystem: String
    public let targetCoordinateSystem: String
    /// Row-major homogeneous four-by-four matrix.
    public let matrix: [Double]
    public let maxErrorM: Double

    public init(
        sourceCoordinateSystem: String,
        targetCoordinateSystem: String,
        matrix: [Double],
        maxErrorM: Double
    ) {
        self.sourceCoordinateSystem = sourceCoordinateSystem
        self.targetCoordinateSystem = targetCoordinateSystem
        self.matrix = matrix
        self.maxErrorM = maxErrorM
    }

    /// Returns the transformed point when this matrix is a valid affine transform.
    public func applying(to point: [Double]) throws -> [Double] {
        try validate()
        guard point.count == 3, point.allSatisfy(\.isFinite) else {
            throw PhoneClientError.transformError("points must contain three finite coordinates")
        }
        return [
            matrix[0] * point[0] + matrix[1] * point[1] + matrix[2] * point[2] + matrix[3],
            matrix[4] * point[0] + matrix[5] * point[1] + matrix[6] * point[2] + matrix[7],
            matrix[8] * point[0] + matrix[9] * point[1] + matrix[10] * point[2] + matrix[11],
        ]
    }

    func validate() throws {
        try requireText(sourceCoordinateSystem, field: "transform source coordinate system")
        try requireText(targetCoordinateSystem, field: "transform target coordinate system")
        try requireNonnegativeFinite(maxErrorM, field: "transform error")
        guard matrix.count == 16, matrix.allSatisfy(\.isFinite) else {
            throw PhoneClientError.transformError("matrix must contain sixteen finite values")
        }
        guard matrix[12] == 0, matrix[13] == 0, matrix[14] == 0, matrix[15] == 1 else {
            throw PhoneClientError.transformError("matrix must be affine homogeneous")
        }
        let scale = [matrix[0], matrix[1], matrix[2], matrix[4], matrix[5], matrix[6], matrix[8], matrix[9], matrix[10]]
            .map(abs)
            .max() ?? 0
        guard scale.isFinite, scale > 0 else {
            throw PhoneClientError.transformError("matrix must be non-singular")
        }
        let a = matrix[0] / scale
        let b = matrix[1] / scale
        let c = matrix[2] / scale
        let d = matrix[4] / scale
        let e = matrix[5] / scale
        let f = matrix[6] / scale
        let g = matrix[8] / scale
        let h = matrix[9] / scale
        let i = matrix[10] / scale
        let determinant = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)
        guard determinant.isFinite, abs(determinant) > Double.ulpOfOne else {
            throw PhoneClientError.transformError("matrix must be non-singular")
        }
    }
}

/// Structure represented by a RoomPlan scene element.
public enum GeometryKind: UInt8, Codable, Equatable, Sendable {
    case wall = 1
    case door = 2
    case furniture = 3
}

/// One structured wall, door, or furniture element in scene coordinates.
public struct GeometryElement: Codable, Equatable, Sendable {
    public let kind: GeometryKind
    public let verticesM: [[Double]]

    public init(kind: GeometryKind, verticesM: [[Double]]) {
        self.kind = kind
        self.verticesM = verticesM
    }

    func validate() throws {
        guard !verticesM.isEmpty else {
            throw PhoneClientError.invalidArtifact("geometry elements must contain vertices")
        }
        for vertex in verticesM {
            guard vertex.count == 3, vertex.allSatisfy(\.isFinite) else {
                throw PhoneClientError.invalidArtifact("geometry vertices must contain three finite coordinates")
            }
        }
    }
}

/// One world-coordinate coverage cell, including explicitly unobserved cells.
public struct CoverageCell: Codable, Equatable, Sendable {
    public let positionM: [Double]
    public let covered: Bool

    public init(positionM: [Double], covered: Bool) {
        self.positionM = positionM
        self.covered = covered
    }

    func validate() throws {
        guard positionM.count == 3, positionM.allSatisfy(\.isFinite) else {
            throw PhoneClientError.invalidArtifact("coverage positions must contain three finite coordinates")
        }
    }
}

/// Versioned RoomPlan geometry, coverage, and uncertainty in one stable world frame.
public struct SceneSnapshot: Codable, Equatable, Sendable {
    public let metadata: ArtifactMetadata
    public let worldCoordinateSystem: String
    public let geometry: [GeometryElement]
    public let geometryValidityMask: [Bool]
    public let coverageMask: [CoverageCell]
    public let scanCoverage: Double
    public let mapErrorM: Double
    /// Optional display-only USDZ reference; structured geometry remains authoritative.
    public let usdzDisplayReference: String?

    public init(
        metadata: ArtifactMetadata,
        worldCoordinateSystem: String,
        geometry: [GeometryElement],
        geometryValidityMask: [Bool],
        coverageMask: [CoverageCell],
        scanCoverage: Double,
        mapErrorM: Double,
        usdzDisplayReference: String?
    ) {
        self.metadata = metadata
        self.worldCoordinateSystem = worldCoordinateSystem
        self.geometry = geometry
        self.geometryValidityMask = geometryValidityMask
        self.coverageMask = coverageMask
        self.scanCoverage = scanCoverage
        self.mapErrorM = mapErrorM
        self.usdzDisplayReference = usdzDisplayReference
    }

    public func validate() throws {
        try metadata.validate()
        try requireText(worldCoordinateSystem, field: "world coordinate system")
        try requireUnitInterval(scanCoverage, field: "scan coverage")
        try requireNonnegativeFinite(mapErrorM, field: "scene map error")
        guard !geometry.isEmpty, geometryValidityMask.count == geometry.count, !coverageMask.isEmpty else {
            throw PhoneClientError.invalidArtifact("scene geometry and coverage must not be empty")
        }
        for element in geometry {
            try element.validate()
        }
        for cell in coverageMask {
            try cell.validate()
        }
        if let usdzDisplayReference {
            try requireText(usdzDisplayReference, field: "USDZ display reference")
        }
    }
}

/// Explicit direction of a calibrated RF path.
public enum SignalDirection: UInt8, Codable, Equatable, Sendable {
    case transmit = 1
    case receive = 2
}

/// Mapping from a logical RF path to its physical device antenna.
public struct SignalPathCondition: Codable, Equatable, Sendable {
    public let logicalPath: String
    public let direction: SignalDirection
    public let deviceChain: String
    public let antennaIdentity: String

    public init(logicalPath: String, direction: SignalDirection, deviceChain: String, antennaIdentity: String) {
        self.logicalPath = logicalPath
        self.direction = direction
        self.deviceChain = deviceChain
        self.antennaIdentity = antennaIdentity
    }
}

/// One physical antenna phase-centre position in array coordinates.
public struct ArrayElementGeometry: Codable, Equatable, Sendable {
    public let antennaIdentity: String
    public let positionM: [Double]

    public init(antennaIdentity: String, positionM: [Double]) {
        self.antennaIdentity = antennaIdentity
        self.positionM = positionM
    }
}

/// Device and physical array geometry with an explicit validity interval.
public struct DeviceArrayGeometry: Codable, Equatable, Sendable {
    public let source: SourceIdentity
    public let applicability: String
    public let minimumFrequencyHz: UInt64
    public let maximumFrequencyHz: UInt64
    public let deviceToArray: CoordinateTransform
    public let elements: [ArrayElementGeometry]
    public let maximumPositionErrorM: Double
    public let validFromUTC: UInt64
    public let validUntilUTC: UInt64
    public let epoch: UInt32

    public init(
        source: SourceIdentity,
        applicability: String,
        minimumFrequencyHz: UInt64,
        maximumFrequencyHz: UInt64,
        deviceToArray: CoordinateTransform,
        elements: [ArrayElementGeometry],
        maximumPositionErrorM: Double,
        validFromUTC: UInt64,
        validUntilUTC: UInt64,
        epoch: UInt32
    ) {
        self.source = source
        self.applicability = applicability
        self.minimumFrequencyHz = minimumFrequencyHz
        self.maximumFrequencyHz = maximumFrequencyHz
        self.deviceToArray = deviceToArray
        self.elements = elements
        self.maximumPositionErrorM = maximumPositionErrorM
        self.validFromUTC = validFromUTC
        self.validUntilUTC = validUntilUTC
        self.epoch = epoch
    }
}

/// Scope over which RF phase coherence was qualified.
public enum CoherenceScope: UInt8, Codable, Equatable, Sendable {
    case none = 0
    case packet = 1
    case captureInterval = 2
}

/// Independently qualified phase relation.
public struct PhaseRelation: Codable, Equatable, Sendable {
    public let source: SourceIdentity
    public let scope: CoherenceScope
    public let maximumErrorRadians: Double
    public let validFromUTC: UInt64
    public let validUntilUTC: UInt64
    public let epoch: UInt32

    public init(source: SourceIdentity, scope: CoherenceScope, maximumErrorRadians: Double, validFromUTC: UInt64, validUntilUTC: UInt64, epoch: UInt32) {
        self.source = source
        self.scope = scope
        self.maximumErrorRadians = maximumErrorRadians
        self.validFromUTC = validFromUTC
        self.validUntilUTC = validUntilUTC
        self.epoch = epoch
    }
}

/// Independently qualified RF sampling-time relation.
public struct RfTimeRelation: Codable, Equatable, Sendable {
    public let source: SourceIdentity
    public let offset: Int64
    public let maximumError: UInt64
    public let validFromUTC: UInt64
    public let validUntilUTC: UInt64
    public let epoch: UInt32

    public init(source: SourceIdentity, offset: Int64, maximumError: UInt64, validFromUTC: UInt64, validUntilUTC: UInt64, epoch: UInt32) {
        self.source = source
        self.offset = offset
        self.maximumError = maximumError
        self.validFromUTC = validFromUTC
        self.validUntilUTC = validUntilUTC
        self.epoch = epoch
    }
}

/// Declared physical array identity and element count.
public struct ArrayCondition: Codable, Equatable, Sendable {
    public let arrayIdentity: String
    public let physicalElementCount: UInt16

    public init(arrayIdentity: String, physicalElementCount: UInt16) {
        self.arrayIdentity = arrayIdentity
        self.physicalElementCount = physicalElementCount
    }
}

/// RF device, antenna, transform, path, and relation calibration.
public struct CalibrationBundle: Codable, Equatable, Sendable {
    public let metadata: ArtifactMetadata
    public let sceneDigest: ArtifactDigest
    public let rfDeviceIdentity: String
    public let antennaReference: String
    public let worldTransform: CoordinateTransform
    public let signalPaths: [SignalPathCondition]
    public let arrayCondition: ArrayCondition
    public let arrayGeometry: DeviceArrayGeometry
    public let phaseRelation: PhaseRelation
    public let timeRelation: RfTimeRelation
    public let maxErrorM: Double
    public let validFromUTC: UInt64
    public let validUntilUTC: UInt64

    public init(
        metadata: ArtifactMetadata,
        sceneDigest: ArtifactDigest,
        rfDeviceIdentity: String,
        antennaReference: String,
        worldTransform: CoordinateTransform,
        signalPaths: [SignalPathCondition],
        arrayCondition: ArrayCondition,
        arrayGeometry: DeviceArrayGeometry,
        phaseRelation: PhaseRelation,
        timeRelation: RfTimeRelation,
        maxErrorM: Double,
        validFromUTC: UInt64,
        validUntilUTC: UInt64
    ) {
        self.metadata = metadata
        self.sceneDigest = sceneDigest
        self.rfDeviceIdentity = rfDeviceIdentity
        self.antennaReference = antennaReference
        self.worldTransform = worldTransform
        self.signalPaths = signalPaths
        self.arrayCondition = arrayCondition
        self.arrayGeometry = arrayGeometry
        self.phaseRelation = phaseRelation
        self.timeRelation = timeRelation
        self.maxErrorM = maxErrorM
        self.validFromUTC = validFromUTC
        self.validUntilUTC = validUntilUTC
    }

    public func validate() throws {
        try metadata.validate()
        try requireText(rfDeviceIdentity, field: "RF device identity")
        try requireText(antennaReference, field: "antenna reference")
        try worldTransform.validate()
        try requireNonnegativeFinite(maxErrorM, field: "calibration error")
        guard validFromUTC < validUntilUTC else {
            throw PhoneClientError.invalidArtifact("calibration validity interval is empty")
        }
        guard !signalPaths.isEmpty else {
            throw PhoneClientError.invalidArtifact("calibration signal paths must not be empty")
        }
        try requireText(arrayCondition.arrayIdentity, field: "array identity")
        guard arrayCondition.physicalElementCount > 0 else {
            throw PhoneClientError.invalidArtifact("array physical element count must be non-zero")
        }
        try arrayGeometry.validate(worldSource: worldTransform.sourceCoordinateSystem, signalPaths: signalPaths)
        try phaseRelation.source.validate()
        try requireNonnegativeFinite(phaseRelation.maximumErrorRadians, field: "phase error")
        try timeRelation.source.validate()
        guard phaseRelation.validFromUTC < phaseRelation.validUntilUTC,
              timeRelation.validFromUTC < timeRelation.validUntilUTC,
              validFromUTC >= phaseRelation.validFromUTC,
              validUntilUTC <= phaseRelation.validUntilUTC,
              validFromUTC >= timeRelation.validFromUTC,
              validUntilUTC <= timeRelation.validUntilUTC,
              validFromUTC >= arrayGeometry.validFromUTC,
              validUntilUTC <= arrayGeometry.validUntilUTC else {
            throw PhoneClientError.invalidArtifact("calibration exceeds a relation validity interval")
        }
    }
}

extension DeviceArrayGeometry {
    func validate(worldSource: String, signalPaths: [SignalPathCondition]) throws {
        try source.validate()
        try requireText(applicability, field: "array applicability")
        guard minimumFrequencyHz > 0, minimumFrequencyHz <= maximumFrequencyHz else {
            throw PhoneClientError.invalidArtifact("array geometry frequency range is invalid")
        }
        try deviceToArray.validate()
        try requireNonnegativeFinite(maximumPositionErrorM, field: "array position error")
        guard validFromUTC < validUntilUTC else {
            throw PhoneClientError.invalidArtifact("array geometry validity interval is empty")
        }
        guard deviceToArray.targetCoordinateSystem == worldSource else {
            throw PhoneClientError.transformError("device-to-array and array-to-world coordinates do not join")
        }
        guard !elements.isEmpty else {
            throw PhoneClientError.invalidArtifact("array geometry must contain physical elements")
        }
        var antennas = Set<String>()
        for element in elements {
            try requireText(element.antennaIdentity, field: "antenna identity")
            guard element.positionM.count == 3, element.positionM.allSatisfy(\.isFinite), antennas.insert(element.antennaIdentity).inserted else {
                throw PhoneClientError.invalidArtifact("array elements must be unique with finite geometry")
            }
        }
        var paths = Set<String>()
        for path in signalPaths {
            try requireText(path.logicalPath, field: "logical RF path")
            try requireText(path.deviceChain, field: "RF device chain")
            try requireText(path.antennaIdentity, field: "RF path antenna identity")
            guard antennas.contains(path.antennaIdentity) else {
                throw PhoneClientError.invalidArtifact("signal paths must reference physical antennas")
            }
            let key = "\(path.direction.rawValue):\(path.logicalPath)"
            guard paths.insert(key).inserted else {
                throw PhoneClientError.invalidArtifact("signal paths must be unique")
            }
        }
    }
}

/// Camera tracking quality associated with one supervision sample.
public enum TrackingQuality: UInt8, Codable, Equatable, Sendable {
    case normal = 1
    case limited = 2
}

/// Depth observation quality associated with one supervision sample.
public enum DepthQuality: UInt8, Codable, Equatable, Sendable {
    case measured = 1
    case estimated = 2
    case missing = 3
}

/// Spatial scope within which a label is authoritative.
public enum LabelScope: UInt8, Codable, Equatable, Sendable {
    case locallyVisible = 1
    case wholeRoom = 2
}

/// One visible person's station, pose, position, and individual error.
public struct PersonLabel: Codable, Equatable, Sendable {
    public let station: String
    public let pose: String
    public let positionM: [Double]
    public let maxErrorM: Double

    public init(station: String, pose: String, positionM: [Double], maxErrorM: Double) {
        self.station = station
        self.pose = pose
        self.positionM = positionM
        self.maxErrorM = maxErrorM
    }
}

/// A joint label that never turns a partial view into an empty-room claim.
public enum JointLabel: Codable, Equatable, Sendable {
    case unknown
    case visibleSet([PersonLabel])
    case wholeRoomEmpty
}

/// One aligned RGB/depth/pose sample and its uncertainty metadata.
public struct SupervisionSample: Codable, Equatable, Sendable {
    public let rgbReference: String
    public let depthReference: String?
    public let poseReference: String
    public let rgbTime: UInt64
    public let depthTime: UInt64
    public let poseTime: UInt64
    public let maximumTimeError: UInt64
    public let trackingEpoch: UInt32
    public let relocalized: Bool
    public let trackingQuality: TrackingQuality
    public let depthQuality: DepthQuality
    public let scope: LabelScope
    public let personVisibility: [Double]
    public let label: JointLabel
    public let cameraToWorld: CoordinateTransform
    public let sampleSource: SourceIdentity
    public let jointErrorM: Double

    public init(
        rgbReference: String,
        depthReference: String?,
        poseReference: String,
        rgbTime: UInt64,
        depthTime: UInt64,
        poseTime: UInt64,
        maximumTimeError: UInt64,
        trackingEpoch: UInt32,
        relocalized: Bool,
        trackingQuality: TrackingQuality,
        depthQuality: DepthQuality,
        scope: LabelScope,
        personVisibility: [Double],
        label: JointLabel,
        cameraToWorld: CoordinateTransform,
        sampleSource: SourceIdentity,
        jointErrorM: Double
    ) {
        self.rgbReference = rgbReference
        self.depthReference = depthReference
        self.poseReference = poseReference
        self.rgbTime = rgbTime
        self.depthTime = depthTime
        self.poseTime = poseTime
        self.maximumTimeError = maximumTimeError
        self.trackingEpoch = trackingEpoch
        self.relocalized = relocalized
        self.trackingQuality = trackingQuality
        self.depthQuality = depthQuality
        self.scope = scope
        self.personVisibility = personVisibility
        self.label = label
        self.cameraToWorld = cameraToWorld
        self.sampleSource = sampleSource
        self.jointErrorM = jointErrorM
    }
}

/// A time-ordered sequence of camera-derived labels in one phone clock domain.
public struct SupervisionSegment: Codable, Equatable, Sendable {
    public let metadata: ArtifactMetadata
    public let sceneDigest: ArtifactDigest
    public let cameraIntrinsics: [Double]
    public let samples: [SupervisionSample]
    public let sharedPositionErrorM: Double
    public let timeRelation: PhoneTimeRelation
    public let maximumPersonVelocityMPS: Double

    public init(
        metadata: ArtifactMetadata,
        sceneDigest: ArtifactDigest,
        cameraIntrinsics: [Double],
        samples: [SupervisionSample],
        sharedPositionErrorM: Double,
        timeRelation: PhoneTimeRelation,
        maximumPersonVelocityMPS: Double
    ) {
        self.metadata = metadata
        self.sceneDigest = sceneDigest
        self.cameraIntrinsics = cameraIntrinsics
        self.samples = samples
        self.sharedPositionErrorM = sharedPositionErrorM
        self.timeRelation = timeRelation
        self.maximumPersonVelocityMPS = maximumPersonVelocityMPS
    }

    public func validate() throws {
        try metadata.validate()
        guard cameraIntrinsics.count == 9, cameraIntrinsics.allSatisfy(\.isFinite) else {
            throw PhoneClientError.invalidArtifact("camera intrinsics must contain nine finite values")
        }
        try requireNonnegativeFinite(sharedPositionErrorM, field: "shared supervision error")
        try requireNonnegativeFinite(maximumPersonVelocityMPS, field: "maximum person velocity")
        guard !samples.isEmpty else {
            throw PhoneClientError.invalidArtifact("supervision samples must not be empty")
        }
        var previousPoseTime: UInt64?
        var previousEpoch: UInt32?
        for sample in samples {
            try sample.validate(timeRelation: timeRelation, previousPoseTime: previousPoseTime, previousEpoch: previousEpoch)
            previousPoseTime = sample.poseTime
            previousEpoch = sample.trackingEpoch
        }
    }
}

extension SupervisionSample {
    func validate(timeRelation: PhoneTimeRelation, previousPoseTime: UInt64?, previousEpoch: UInt32?) throws {
        try requireText(rgbReference, field: "RGB reference")
        try requireText(poseReference, field: "pose reference")
        switch (depthQuality, depthReference) {
        case (.missing, nil): break
        case (.measured, .some), (.estimated, .some):
            try requireText(depthReference ?? "", field: "depth reference")
        default:
            throw PhoneClientError.invalidArtifact("depth reference and quality are inconsistent")
        }
        try sampleSource.validate()
        try requireNonnegativeFinite(jointErrorM, field: "joint sample error")
        try cameraToWorld.validate()
        guard timeRelation.error(at: rgbTime) != nil,
              timeRelation.error(at: depthTime) != nil,
              timeRelation.error(at: poseTime) != nil else {
            throw PhoneClientError.timeRelationError("sample time is outside the phone relation")
        }
        let minimum = min(rgbTime, depthTime, poseTime)
        let maximum = max(rgbTime, depthTime, poseTime)
        guard maximum - minimum <= maximumTimeError else {
            throw PhoneClientError.timeRelationError("sample timestamps exceed their error bound")
        }
        if let previousPoseTime, poseTime < previousPoseTime {
            throw PhoneClientError.invalidArtifact("supervision samples are not time ordered")
        }
        if let previousEpoch, previousEpoch != trackingEpoch, !relocalized {
            throw PhoneClientError.trackingResetRequiresRelocalization
        }
        for visibility in personVisibility {
            try requireUnitInterval(visibility, field: "person visibility")
        }
        switch label {
        case .unknown:
            guard personVisibility.isEmpty else {
                throw PhoneClientError.invalidArtifact("unknown labels cannot name visible people")
            }
        case let .visibleSet(people):
            guard people.count == personVisibility.count else {
                throw PhoneClientError.invalidArtifact("person labels and visibility masks differ")
            }
            for person in people {
                try requireText(person.station, field: "person station")
                try requireText(person.pose, field: "person pose")
                guard person.positionM.count == 3, person.positionM.allSatisfy(\.isFinite) else {
                    throw PhoneClientError.invalidArtifact("person position must contain three finite coordinates")
                }
                try requireNonnegativeFinite(person.maxErrorM, field: "person error")
            }
        case .wholeRoomEmpty:
            guard scope == .wholeRoom, personVisibility.isEmpty else {
                throw PhoneClientError.invalidArtifact("empty-room labels require whole-room scope")
            }
        }
    }
}

// MARK: - Clock relation and artifact identity

/// A bounded affine mapping from phone monotonic time to Host monotonic time.
public struct PhoneTimeRelation: Codable, Equatable, Hashable, Sendable {
    public let relationID: Data
    public let offsetAtReference: Int64
    public let driftPartsPerBillion: Int64
    public let referencePhoneTime: UInt64
    public let maximumError: UInt64
    public let validFromPhoneTime: UInt64
    public let validUntilPhoneTime: UInt64

    public init(
        relationID: Data,
        offsetAtReference: Int64,
        driftPartsPerBillion: Int64,
        referencePhoneTime: UInt64,
        maximumError: UInt64,
        validFromPhoneTime: UInt64,
        validUntilPhoneTime: UInt64
    ) throws {
        guard relationID.count == 16 else {
            throw PhoneClientError.timeRelationError("relation identity must contain sixteen bytes")
        }
        guard validFromPhoneTime < validUntilPhoneTime,
              referencePhoneTime >= validFromPhoneTime,
              referencePhoneTime <= validUntilPhoneTime,
              driftPartsPerBillion.magnitude <= 10_000_000 else {
            throw PhoneClientError.timeRelationError("relation range or drift is invalid")
        }
        self.relationID = relationID
        self.offsetAtReference = offsetAtReference
        self.driftPartsPerBillion = driftPartsPerBillion
        self.referencePhoneTime = referencePhoneTime
        self.maximumError = maximumError
        self.validFromPhoneTime = validFromPhoneTime
        self.validUntilPhoneTime = validUntilPhoneTime
    }

    /// Returns the conservative clock error at one phone timestamp, or nil outside validity.
    public func error(at phoneTime: UInt64) -> UInt64? {
        guard phoneTime >= validFromPhoneTime, phoneTime <= validUntilPhoneTime else { return nil }
        let elapsed = phoneTime >= referencePhoneTime ? phoneTime - referencePhoneTime : referencePhoneTime - phoneTime
        let (product, overflow) = elapsed.multipliedReportingOverflow(by: driftPartsPerBillion.magnitude)
        guard !overflow else { return nil }
        let driftError = product / 1_000_000_000 + (product % 1_000_000_000 == 0 ? 0 : 1)
        let (total, additionOverflow) = maximumError.addingReportingOverflow(driftError)
        return additionOverflow ? nil : total
    }

    /// Maps phone time into the Host monotonic domain when the signed result fits Int64.
    public func hostTime(for phoneTime: UInt64) -> Int64? {
        guard error(at: phoneTime) != nil else { return nil }
        let elapsed = phoneTime >= referencePhoneTime ? phoneTime - referencePhoneTime : referencePhoneTime - phoneTime
        let signedElapsed: Int64
        if elapsed > UInt64(Int64.max) {
            return nil
        } else {
            signedElapsed = Int64(elapsed) * (phoneTime >= referencePhoneTime ? 1 : -1)
        }
        let driftAdjustment = (Double(signedElapsed) * Double(driftPartsPerBillion)) / 1_000_000_000
        guard driftAdjustment.isFinite, driftAdjustment >= Double(Int64.min), driftAdjustment <= Double(Int64.max) else { return nil }
        let result = Double(offsetAtReference) + Double(signedElapsed) + driftAdjustment
        guard result >= Double(Int64.min), result <= Double(Int64.max) else { return nil }
        return Int64(result.rounded())
    }
}

/// SHA-256 digest of one exact sealed artifact or export package.
public struct ArtifactDigest: Codable, Equatable, Hashable, Sendable, CustomStringConvertible {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 32 else {
            throw PhoneClientError.invalidArtifact("digest must contain thirty-two bytes")
        }
        self.bytes = bytes
    }

    public var description: String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

/// One sealed canonical artifact and its deterministic digest.
public struct SealedArtifact: Equatable, Sendable {
    public let bytes: Data
    public let digest: ArtifactDigest

    public init(bytes: Data, digest: ArtifactDigest) {
        self.bytes = bytes
        self.digest = digest
    }

    /// Encodes and validates one artifact using the Host's WSA1 format.
    public static func seal(_ artifact: Artifact) throws -> SealedArtifact {
        let payload = try CanonicalArtifactCodec.encodePayload(artifact)
        guard payload.count <= UInt32.max else {
            throw PhoneClientError.limitExceeded("artifact payload exceeds the format limit")
        }
        var envelope = Data("WSA1".utf8)
        envelope.appendUInt16LE(1)
        envelope.append(artifact.kind)
        envelope.append(0)
        envelope.appendUInt32LE(UInt32(payload.count))
        envelope.append(payload)
        let digest = try ArtifactDigest(bytes: SHA256Digest.hash(envelope))
        envelope.append(digest.bytes)
        guard envelope.count <= 16 * 1024 * 1024 else {
            throw PhoneClientError.limitExceeded("artifact exceeds the format byte limit")
        }
        return SealedArtifact(bytes: envelope, digest: digest)
    }

    /// Parses canonical WSA1 bytes and rejects non-canonical or digest-mismatched data.
    public static func parse(_ bytes: Data) throws -> SealedArtifact {
        guard bytes.count <= 16 * 1024 * 1024, bytes.count >= 44 else {
            throw PhoneClientError.invalidArtifact("artifact envelope length is invalid")
        }
        guard bytes.prefix(4) == Data("WSA1".utf8), bytes.readUInt16LE(at: 4) == 1, bytes[7] == 0 else {
            throw PhoneClientError.invalidArtifact("artifact schema or envelope is unsupported")
        }
        let payloadLength = Int(bytes.readUInt32LE(at: 8))
        guard payloadLength <= bytes.count - 44, bytes.count == 12 + payloadLength + 32 else {
            throw PhoneClientError.invalidArtifact("artifact envelope length is invalid")
        }
        let digestOffset = bytes.count - 32
        let computed = try ArtifactDigest(bytes: SHA256Digest.hash(bytes.prefix(digestOffset)))
        guard bytes.suffix(32) == computed.bytes else {
            throw PhoneClientError.invalidArtifact("artifact digest does not match its bytes")
        }
        let candidate = SealedArtifact(bytes: bytes, digest: computed)
        let artifact = try candidate.decode()
        let canonical = try seal(artifact)
        guard canonical.bytes == bytes else {
            throw PhoneClientError.invalidArtifact("artifact encoding is not canonical")
        }
        return candidate
    }

    /// Decodes the validated artifact payload.
    public func decode() throws -> Artifact {
        guard bytes.count >= 44 else { throw PhoneClientError.invalidArtifact("artifact envelope is truncated") }
        let payloadEnd = bytes.count - 32
        var reader = BinaryReader(Data(bytes[12..<payloadEnd]))
        let artifact: Artifact
        switch bytes[6] {
        case 1: artifact = .scene(try CanonicalArtifactCodec.decodeScene(&reader))
        case 2: artifact = .calibration(try CanonicalArtifactCodec.decodeCalibration(&reader))
        case 3: artifact = .supervision(try CanonicalArtifactCodec.decodeSupervision(&reader))
        default: throw PhoneClientError.invalidArtifact("artifact kind is unsupported")
        }
        guard reader.isEmpty else { throw PhoneClientError.invalidArtifact("artifact payload has trailing bytes") }
        try artifact.validate()
        return artifact
    }
}

/// One decoded spatial artifact kind.
public enum Artifact: Equatable, Sendable {
    case scene(SceneSnapshot)
    case calibration(CalibrationBundle)
    case supervision(SupervisionSegment)

    var kind: UInt8 {
        switch self {
        case .scene: return 1
        case .calibration: return 2
        case .supervision: return 3
        }
    }

    /// Validates the artifact without importing it into a Host.
    public func validate() throws {
        switch self {
        case let .scene(scene): try scene.validate()
        case let .calibration(calibration): try calibration.validate()
        case let .supervision(supervision): try supervision.validate()
        }
    }
}

/// Import/resource limits shared by the phone exporter and Host contract.
public struct ArtifactLimits: Equatable, Sendable {
    public var maxArtifactBytes: Int
    public var maxGeometryElements: Int
    public var maxSupervisionSamples: Int
    public var maxPositionErrorM: Double
    public var minimumPersonVelocityMPS: Double

    public init(
        maxArtifactBytes: Int = 16 * 1024 * 1024,
        maxGeometryElements: Int = 100_000,
        maxSupervisionSamples: Int = 100_000,
        maxPositionErrorM: Double = 0.75,
        minimumPersonVelocityMPS: Double = 12
    ) {
        self.maxArtifactBytes = maxArtifactBytes
        self.maxGeometryElements = maxGeometryElements
        self.maxSupervisionSamples = maxSupervisionSamples
        self.maxPositionErrorM = maxPositionErrorM
        self.minimumPersonVelocityMPS = minimumPersonVelocityMPS
    }

    public func validate() throws {
        guard maxArtifactBytes > 0, maxGeometryElements > 0, maxSupervisionSamples > 0 else {
            throw PhoneClientError.limitExceeded("artifact limits must be non-zero")
        }
        try requireNonnegativeFinite(maxPositionErrorM, field: "position error limit")
        try requireNonnegativeFinite(minimumPersonVelocityMPS, field: "velocity limit")
    }
}
