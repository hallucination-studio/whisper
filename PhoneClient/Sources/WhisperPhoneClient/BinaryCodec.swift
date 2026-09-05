import Foundation

// MARK: - Canonical little-endian codec

extension Data {
    mutating func appendUInt16LE(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value))
        append(UInt8(truncatingIfNeeded: value >> 8))
    }

    mutating func appendUInt32LE(_ value: UInt32) {
        append(UInt8(truncatingIfNeeded: value))
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value >> 16))
        append(UInt8(truncatingIfNeeded: value >> 24))
    }

    mutating func appendUInt64LE(_ value: UInt64) {
        for shift in stride(from: 0, through: 56, by: 8) {
            append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    mutating func appendInt64LE(_ value: Int64) {
        appendUInt64LE(UInt64(bitPattern: value))
    }

    mutating func appendDoubleLE(_ value: Double) {
        appendUInt64LE(value.bitPattern)
    }

    func readUInt16LE(at offset: Int) -> UInt16 {
        UInt16(self[offset]) | (UInt16(self[offset + 1]) << 8)
    }

    func readUInt32LE(at offset: Int) -> UInt32 {
        UInt32(self[offset])
            | (UInt32(self[offset + 1]) << 8)
            | (UInt32(self[offset + 2]) << 16)
            | (UInt32(self[offset + 3]) << 24)
    }

    func readUInt64LE(at offset: Int) -> UInt64 {
        var result: UInt64 = 0
        for index in 0..<8 {
            result |= UInt64(self[offset + index]) << UInt64(index * 8)
        }
        return result
    }

    func readInt64LE(at offset: Int) -> Int64 {
        Int64(bitPattern: readUInt64LE(at: offset))
    }
}

struct BinaryReader {
    private let data: Data
    private(set) var offset: Int = 0

    init(_ data: Data) {
        self.data = data
    }

    var isEmpty: Bool { offset == data.count }

    mutating func take(_ count: Int) throws -> Data {
        guard count >= 0, count <= data.count - offset else {
            throw PhoneClientError.invalidArtifact("artifact payload is truncated")
        }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    mutating func u8() throws -> UInt8 {
        try take(1)[0]
    }

    mutating func bool() throws -> Bool {
        switch try u8() {
        case 0: return false
        case 1: return true
        default: throw PhoneClientError.invalidArtifact("artifact boolean marker is invalid")
        }
    }

    mutating func u16() throws -> UInt16 {
        let value = try take(2)
        return value.readUInt16LE(at: 0)
    }

    mutating func u32() throws -> UInt32 {
        let value = try take(4)
        return value.readUInt32LE(at: 0)
    }

    mutating func u64() throws -> UInt64 {
        let value = try take(8)
        var result: UInt64 = 0
        for byte in value.enumerated() {
            result |= UInt64(byte.element) << UInt64(byte.offset * 8)
        }
        return result
    }

    mutating func i64() throws -> Int64 {
        Int64(bitPattern: try u64())
    }

    mutating func f64() throws -> Double {
        Double(bitPattern: try u64())
    }

    mutating func count() throws -> Int {
        let value = try u32()
        let count = Int(value)
        guard count <= 100_000, count <= data.count - offset else {
            throw PhoneClientError.limitExceeded("artifact collection length exceeds its bound")
        }
        return count
    }

    mutating func string() throws -> String {
        let bytes = try take(try count())
        guard let value = String(data: bytes, encoding: .utf8) else {
            throw PhoneClientError.invalidArtifact("artifact text is not UTF-8")
        }
        return value
    }

    mutating func digest() throws -> ArtifactDigest {
        try ArtifactDigest(bytes: take(32))
    }
}

enum CanonicalArtifactCodec {
    static func encodePayload(_ artifact: Artifact) throws -> Data {
        try artifact.validate()
        var output = Data()
        switch artifact {
        case let .scene(scene): try encodeScene(&output, scene)
        case let .calibration(calibration): try encodeCalibration(&output, calibration)
        case let .supervision(supervision): try encodeSupervision(&output, supervision)
        }
        return output
    }

    static func decodeScene(_ reader: inout BinaryReader) throws -> SceneSnapshot {
        let metadata = try decodeMetadata(&reader)
        let worldCoordinateSystem = try reader.string()
        let geometryCount = try reader.count()
        var geometry = [GeometryElement]()
        geometry.reserveCapacity(geometryCount)
        for _ in 0..<geometryCount {
            guard let kind = GeometryKind(rawValue: try reader.u8()) else {
                throw PhoneClientError.invalidArtifact("scene geometry kind is unsupported")
            }
            let vertexCount = try reader.count()
            var vertices = [[Double]]()
            vertices.reserveCapacity(vertexCount)
            for _ in 0..<vertexCount {
                vertices.append([try reader.f64(), try reader.f64(), try reader.f64()])
            }
            geometry.append(GeometryElement(kind: kind, verticesM: vertices))
        }
        let validityCount = try reader.count()
        var validity = [Bool]()
        validity.reserveCapacity(validityCount)
        for _ in 0..<validityCount { validity.append(try reader.bool()) }
        let coverageCount = try reader.count()
        var coverage = [CoverageCell]()
        coverage.reserveCapacity(coverageCount)
        for _ in 0..<coverageCount {
            coverage.append(CoverageCell(positionM: [try reader.f64(), try reader.f64(), try reader.f64()], covered: try reader.bool()))
        }
        let scanCoverage = try reader.f64()
        let mapErrorM = try reader.f64()
        let usdzDisplayReference: String?
        switch try reader.u8() {
        case 0: usdzDisplayReference = nil
        case 1: usdzDisplayReference = try reader.string()
        default: throw PhoneClientError.invalidArtifact("scene display reference marker is invalid")
        }
        return SceneSnapshot(
            metadata: metadata,
            worldCoordinateSystem: worldCoordinateSystem,
            geometry: geometry,
            geometryValidityMask: validity,
            coverageMask: coverage,
            scanCoverage: scanCoverage,
            mapErrorM: mapErrorM,
            usdzDisplayReference: usdzDisplayReference
        )
    }

    static func decodeCalibration(_ reader: inout BinaryReader) throws -> CalibrationBundle {
        let metadata = try decodeMetadata(&reader)
        let sceneDigest = try reader.digest()
        let rfDeviceIdentity = try reader.string()
        let antennaReference = try reader.string()
        let worldTransform = try decodeTransform(&reader)
        let arrayCondition = ArrayCondition(arrayIdentity: try reader.string(), physicalElementCount: try reader.u16())
        let geometrySource = try decodeSource(&reader)
        let applicability = try reader.string()
        let minimumFrequency = try reader.u64()
        let maximumFrequency = try reader.u64()
        let deviceToArray = try decodeTransform(&reader)
        let elementCount = try reader.count()
        var elements = [ArrayElementGeometry]()
        elements.reserveCapacity(elementCount)
        for _ in 0..<elementCount {
            elements.append(ArrayElementGeometry(antennaIdentity: try reader.string(), positionM: [try reader.f64(), try reader.f64(), try reader.f64()]))
        }
        let arrayGeometry = DeviceArrayGeometry(
            source: geometrySource,
            applicability: applicability,
            minimumFrequencyHz: minimumFrequency,
            maximumFrequencyHz: maximumFrequency,
            deviceToArray: deviceToArray,
            elements: elements,
            maximumPositionErrorM: try reader.f64(),
            validFromUTC: try reader.u64(),
            validUntilUTC: try reader.u64(),
            epoch: try reader.u32()
        )
        let pathCount = try reader.count()
        var paths = [SignalPathCondition]()
        paths.reserveCapacity(pathCount)
        for _ in 0..<pathCount {
            let logicalPath = try reader.string()
            guard let direction = SignalDirection(rawValue: try reader.u8()) else {
                throw PhoneClientError.invalidArtifact("calibration signal direction is unsupported")
            }
            paths.append(SignalPathCondition(logicalPath: logicalPath, direction: direction, deviceChain: try reader.string(), antennaIdentity: try reader.string()))
        }
        let phaseSource = try decodeSource(&reader)
        guard let phaseScope = CoherenceScope(rawValue: try reader.u8()) else {
            throw PhoneClientError.invalidArtifact("calibration coherence scope is unsupported")
        }
        let phaseRelation = PhaseRelation(
            source: phaseSource,
            scope: phaseScope,
            maximumErrorRadians: try reader.f64(),
            validFromUTC: try reader.u64(),
            validUntilUTC: try reader.u64(),
            epoch: try reader.u32()
        )
        let timeRelation = RfTimeRelation(
            source: try decodeSource(&reader),
            offset: try reader.i64(),
            maximumError: try reader.u64(),
            validFromUTC: try reader.u64(),
            validUntilUTC: try reader.u64(),
            epoch: try reader.u32()
        )
        return CalibrationBundle(
            metadata: metadata,
            sceneDigest: sceneDigest,
            rfDeviceIdentity: rfDeviceIdentity,
            antennaReference: antennaReference,
            worldTransform: worldTransform,
            signalPaths: paths,
            arrayCondition: arrayCondition,
            arrayGeometry: arrayGeometry,
            phaseRelation: phaseRelation,
            timeRelation: timeRelation,
            maxErrorM: try reader.f64(),
            validFromUTC: try reader.u64(),
            validUntilUTC: try reader.u64()
        )
    }

    static func decodeSupervision(_ reader: inout BinaryReader) throws -> SupervisionSegment {
        let metadata = try decodeMetadata(&reader)
        let sceneDigest = try reader.digest()
        var intrinsics = [Double]()
        intrinsics.reserveCapacity(9)
        for _ in 0..<9 { intrinsics.append(try reader.f64()) }
        let sampleCount = try reader.count()
        var samples = [SupervisionSample]()
        samples.reserveCapacity(sampleCount)
        for _ in 0..<sampleCount {
            let rgbReference = try reader.string()
            let depthReference: String?
            switch try reader.u8() {
            case 0: depthReference = nil
            case 1: depthReference = try reader.string()
            default: throw PhoneClientError.invalidArtifact("depth reference marker is invalid")
            }
            let poseReference = try reader.string()
            let rgbTime = try reader.u64()
            let depthTime = try reader.u64()
            let poseTime = try reader.u64()
            let maximumTimeError = try reader.u64()
            let trackingEpoch = try reader.u32()
            let relocalized = try reader.bool()
            guard let trackingQuality = TrackingQuality(rawValue: try reader.u8()) else {
                throw PhoneClientError.invalidArtifact("tracking quality is unsupported")
            }
            guard let depthQuality = DepthQuality(rawValue: try reader.u8()) else {
                throw PhoneClientError.invalidArtifact("depth quality is unsupported")
            }
            guard let scope = LabelScope(rawValue: try reader.u8()) else {
                throw PhoneClientError.invalidArtifact("label scope is unsupported")
            }
            let visibilityCount = try reader.count()
            var visibility = [Double]()
            visibility.reserveCapacity(visibilityCount)
            for _ in 0..<visibilityCount { visibility.append(try reader.f64()) }
            let label: JointLabel
            switch try reader.u8() {
            case 0: label = .unknown
            case 1:
                let peopleCount = try reader.count()
                var people = [PersonLabel]()
                people.reserveCapacity(peopleCount)
                for _ in 0..<peopleCount {
                    people.append(PersonLabel(station: try reader.string(), pose: try reader.string(), positionM: [try reader.f64(), try reader.f64(), try reader.f64()], maxErrorM: try reader.f64()))
                }
                label = .visibleSet(people)
            case 2: label = .wholeRoomEmpty
            default: throw PhoneClientError.invalidArtifact("joint label kind is unsupported")
            }
            samples.append(SupervisionSample(
                rgbReference: rgbReference,
                depthReference: depthReference,
                poseReference: poseReference,
                rgbTime: rgbTime,
                depthTime: depthTime,
                poseTime: poseTime,
                maximumTimeError: maximumTimeError,
                trackingEpoch: trackingEpoch,
                relocalized: relocalized,
                trackingQuality: trackingQuality,
                depthQuality: depthQuality,
                scope: scope,
                personVisibility: visibility,
                label: label,
                cameraToWorld: try decodeTransform(&reader),
                sampleSource: try decodeSource(&reader),
                jointErrorM: try reader.f64()
            ))
        }
        return SupervisionSegment(
            metadata: metadata,
            sceneDigest: sceneDigest,
            cameraIntrinsics: intrinsics,
            samples: samples,
            sharedPositionErrorM: try reader.f64(),
            timeRelation: try decodePhoneTimeRelation(&reader),
            maximumPersonVelocityMPS: try reader.f64()
        )
    }

    private static func encodeScene(_ output: inout Data, _ scene: SceneSnapshot) throws {
        try encodeMetadata(&output, scene.metadata)
        try putString(&output, scene.worldCoordinateSystem)
        try putCount(&output, scene.geometry.count)
        for element in scene.geometry {
            output.append(element.kind.rawValue)
            try putCount(&output, element.verticesM.count)
            for vertex in element.verticesM {
                for coordinate in vertex { output.appendDoubleLE(coordinate) }
            }
        }
        try putCount(&output, scene.geometryValidityMask.count)
        for valid in scene.geometryValidityMask { output.append(valid ? 1 : 0) }
        try putCount(&output, scene.coverageMask.count)
        for cell in scene.coverageMask {
            for coordinate in cell.positionM { output.appendDoubleLE(coordinate) }
            output.append(cell.covered ? 1 : 0)
        }
        output.appendDoubleLE(scene.scanCoverage)
        output.appendDoubleLE(scene.mapErrorM)
        if let reference = scene.usdzDisplayReference {
            output.append(1)
            try putString(&output, reference)
        } else {
            output.append(0)
        }
    }

    private static func encodeCalibration(_ output: inout Data, _ calibration: CalibrationBundle) throws {
        try encodeMetadata(&output, calibration.metadata)
        output.append(calibration.sceneDigest.bytes)
        try putString(&output, calibration.rfDeviceIdentity)
        try putString(&output, calibration.antennaReference)
        try encodeTransform(&output, calibration.worldTransform)
        try putString(&output, calibration.arrayCondition.arrayIdentity)
        output.appendUInt16LE(calibration.arrayCondition.physicalElementCount)
        try encodeSource(&output, calibration.arrayGeometry.source)
        try putString(&output, calibration.arrayGeometry.applicability)
        output.appendUInt64LE(calibration.arrayGeometry.minimumFrequencyHz)
        output.appendUInt64LE(calibration.arrayGeometry.maximumFrequencyHz)
        try encodeTransform(&output, calibration.arrayGeometry.deviceToArray)
        try putCount(&output, calibration.arrayGeometry.elements.count)
        for element in calibration.arrayGeometry.elements {
            try putString(&output, element.antennaIdentity)
            for coordinate in element.positionM { output.appendDoubleLE(coordinate) }
        }
        output.appendDoubleLE(calibration.arrayGeometry.maximumPositionErrorM)
        output.appendUInt64LE(calibration.arrayGeometry.validFromUTC)
        output.appendUInt64LE(calibration.arrayGeometry.validUntilUTC)
        output.appendUInt32LE(calibration.arrayGeometry.epoch)
        try putCount(&output, calibration.signalPaths.count)
        for path in calibration.signalPaths {
            try putString(&output, path.logicalPath)
            output.append(path.direction.rawValue)
            try putString(&output, path.deviceChain)
            try putString(&output, path.antennaIdentity)
        }
        try encodeSource(&output, calibration.phaseRelation.source)
        output.append(calibration.phaseRelation.scope.rawValue)
        output.appendDoubleLE(calibration.phaseRelation.maximumErrorRadians)
        output.appendUInt64LE(calibration.phaseRelation.validFromUTC)
        output.appendUInt64LE(calibration.phaseRelation.validUntilUTC)
        output.appendUInt32LE(calibration.phaseRelation.epoch)
        try encodeSource(&output, calibration.timeRelation.source)
        output.appendInt64LE(calibration.timeRelation.offset)
        output.appendUInt64LE(calibration.timeRelation.maximumError)
        output.appendUInt64LE(calibration.timeRelation.validFromUTC)
        output.appendUInt64LE(calibration.timeRelation.validUntilUTC)
        output.appendUInt32LE(calibration.timeRelation.epoch)
        output.appendDoubleLE(calibration.maxErrorM)
        output.appendUInt64LE(calibration.validFromUTC)
        output.appendUInt64LE(calibration.validUntilUTC)
    }

    private static func encodeSupervision(_ output: inout Data, _ supervision: SupervisionSegment) throws {
        try encodeMetadata(&output, supervision.metadata)
        output.append(supervision.sceneDigest.bytes)
        for value in supervision.cameraIntrinsics { output.appendDoubleLE(value) }
        try putCount(&output, supervision.samples.count)
        for sample in supervision.samples {
            try putString(&output, sample.rgbReference)
            if let depthReference = sample.depthReference {
                output.append(1)
                try putString(&output, depthReference)
            } else {
                output.append(0)
            }
            try putString(&output, sample.poseReference)
            output.appendUInt64LE(sample.rgbTime)
            output.appendUInt64LE(sample.depthTime)
            output.appendUInt64LE(sample.poseTime)
            output.appendUInt64LE(sample.maximumTimeError)
            output.appendUInt32LE(sample.trackingEpoch)
            output.append(sample.relocalized ? 1 : 0)
            output.append(sample.trackingQuality.rawValue)
            output.append(sample.depthQuality.rawValue)
            output.append(sample.scope.rawValue)
            try putCount(&output, sample.personVisibility.count)
            for visibility in sample.personVisibility { output.appendDoubleLE(visibility) }
            switch sample.label {
            case .unknown:
                output.append(0)
            case let .visibleSet(people):
                output.append(1)
                try putCount(&output, people.count)
                for person in people {
                    try putString(&output, person.station)
                    try putString(&output, person.pose)
                    for coordinate in person.positionM { output.appendDoubleLE(coordinate) }
                    output.appendDoubleLE(person.maxErrorM)
                }
            case .wholeRoomEmpty:
                output.append(2)
            }
            try encodeTransform(&output, sample.cameraToWorld)
            try encodeSource(&output, sample.sampleSource)
            output.appendDoubleLE(sample.jointErrorM)
        }
        output.appendDoubleLE(supervision.sharedPositionErrorM)
        try encodePhoneTimeRelation(&output, supervision.timeRelation)
        output.appendDoubleLE(supervision.maximumPersonVelocityMPS)
    }

    private static func encodeMetadata(_ output: inout Data, _ metadata: ArtifactMetadata) throws {
        try putString(&output, metadata.artifactID)
        output.appendUInt32LE(metadata.revision)
        try putCount(&output, metadata.provenance.count)
        for source in metadata.provenance { try encodeSource(&output, source) }
    }

    private static func decodeMetadata(_ reader: inout BinaryReader) throws -> ArtifactMetadata {
        let artifactID = try reader.string()
        let revision = try reader.u32()
        let count = try reader.count()
        var sources = [SourceIdentity]()
        sources.reserveCapacity(count)
        for _ in 0..<count { sources.append(try decodeSource(&reader)) }
        return ArtifactMetadata(artifactID: artifactID, revision: revision, provenance: sources)
    }

    private static func encodeTransform(_ output: inout Data, _ transform: CoordinateTransform) throws {
        try putString(&output, transform.sourceCoordinateSystem)
        try putString(&output, transform.targetCoordinateSystem)
        for value in transform.matrix { output.appendDoubleLE(value) }
        output.appendDoubleLE(transform.maxErrorM)
    }

    private static func decodeTransform(_ reader: inout BinaryReader) throws -> CoordinateTransform {
        let source = try reader.string()
        let target = try reader.string()
        var matrix = [Double]()
        matrix.reserveCapacity(16)
        for _ in 0..<16 { matrix.append(try reader.f64()) }
        return CoordinateTransform(sourceCoordinateSystem: source, targetCoordinateSystem: target, matrix: matrix, maxErrorM: try reader.f64())
    }

    private static func encodeSource(_ output: inout Data, _ source: SourceIdentity) throws {
        try putString(&output, source.namespace)
        try putString(&output, source.identity)
    }

    private static func decodeSource(_ reader: inout BinaryReader) throws -> SourceIdentity {
        SourceIdentity(namespace: try reader.string(), identity: try reader.string())
    }

    private static func encodePhoneTimeRelation(_ output: inout Data, _ relation: PhoneTimeRelation) throws {
        output.append(relation.relationID)
        output.appendInt64LE(relation.offsetAtReference)
        output.appendInt64LE(relation.driftPartsPerBillion)
        output.appendUInt64LE(relation.referencePhoneTime)
        output.appendUInt64LE(relation.maximumError)
        output.appendUInt64LE(relation.validFromPhoneTime)
        output.appendUInt64LE(relation.validUntilPhoneTime)
    }

    private static func decodePhoneTimeRelation(_ reader: inout BinaryReader) throws -> PhoneTimeRelation {
        let relationID = try reader.take(16)
        let offset = try reader.i64()
        let drift = try reader.i64()
        let reference = try reader.u64()
        let maximumError = try reader.u64()
        let validFrom = try reader.u64()
        let validUntil = try reader.u64()
        return try PhoneTimeRelation(
            relationID: relationID,
            offsetAtReference: offset,
            driftPartsPerBillion: drift,
            referencePhoneTime: reference,
            maximumError: maximumError,
            validFromPhoneTime: validFrom,
            validUntilPhoneTime: validUntil
        )
    }

    private static func putCount(_ output: inout Data, _ count: Int) throws {
        guard (0...100_000).contains(count), count <= Int(UInt32.max) else {
            throw PhoneClientError.limitExceeded("artifact collection exceeds the format limit")
        }
        output.appendUInt32LE(UInt32(count))
    }

    private static func putString(_ output: inout Data, _ value: String) throws {
        let bytes = Data(value.utf8)
        try putCount(&output, bytes.count)
        output.append(bytes)
    }
}

// MARK: - SHA-256

/// Small dependency-free SHA-256 implementation used for canonical digests on every platform.
enum SHA256Digest {
    private static let constants: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    static func hash(_ input: Data) -> Data {
        var bytes = Array(input)
        let bitLength = UInt64(bytes.count) * 8
        bytes.append(0x80)
        while bytes.count % 64 != 56 { bytes.append(0) }
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: bitLength >> UInt64(shift)))
        }

        var state: [UInt32] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ]
        for chunkStart in stride(from: 0, to: bytes.count, by: 64) {
            var schedule = Array(repeating: UInt32(0), count: 64)
            for index in 0..<16 {
                let start = chunkStart + index * 4
                schedule[index] = UInt32(bytes[start]) << 24
                    | UInt32(bytes[start + 1]) << 16
                    | UInt32(bytes[start + 2]) << 8
                    | UInt32(bytes[start + 3])
            }
            for index in 16..<64 {
                let value = schedule[index - 15]
                let sigma0 = rotateRight(value, by: 7) ^ rotateRight(value, by: 18) ^ (value >> 3)
                let prior = schedule[index - 2]
                let sigma1 = rotateRight(prior, by: 17) ^ rotateRight(prior, by: 19) ^ (prior >> 10)
                schedule[index] = schedule[index - 16] &+ sigma0 &+ schedule[index - 7] &+ sigma1
            }
            var working = state
            for index in 0..<64 {
                let e = working[4]
                let choose = (e & working[5]) ^ (~e & working[6])
                let sum1 = rotateRight(e, by: 6) ^ rotateRight(e, by: 11) ^ rotateRight(e, by: 25)
                let temp1 = working[7] &+ sum1 &+ choose &+ constants[index] &+ schedule[index]
                let a = working[0]
                let majority = (a & working[1]) ^ (a & working[2]) ^ (working[1] & working[2])
                let sum0 = rotateRight(a, by: 2) ^ rotateRight(a, by: 13) ^ rotateRight(a, by: 22)
                let temp2 = sum0 &+ majority
                working = [temp1 &+ temp2, working[0], working[1], working[2], working[3] &+ temp1, working[4], working[5], working[6]]
            }
            for index in 0..<8 { state[index] = state[index] &+ working[index] }
        }

        var output = Data(capacity: 32)
        for value in state {
            output.append(UInt8(truncatingIfNeeded: value >> 24))
            output.append(UInt8(truncatingIfNeeded: value >> 16))
            output.append(UInt8(truncatingIfNeeded: value >> 8))
            output.append(UInt8(truncatingIfNeeded: value))
        }
        return output
    }
}

@inline(__always)
private func rotateRight(_ value: UInt32, by amount: UInt32) -> UInt32 {
    (value >> amount) | (value << (32 - amount))
}
