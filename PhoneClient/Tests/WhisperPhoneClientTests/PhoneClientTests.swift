import Foundation
import XCTest
@testable import WhisperPhoneClient

final class PhoneClientTests: XCTestCase {
    func testCanonicalSceneRoundTripIsDeterministic() throws {
        let scene = makeScene()
        let first = try SealedArtifact.seal(.scene(scene))
        let second = try SealedArtifact.seal(.scene(scene))

        XCTAssertEqual(first.bytes, second.bytes)
        XCTAssertEqual(first.digest, second.digest)
        XCTAssertEqual(try SealedArtifact.parse(first.bytes).decode(), .scene(scene))
    }

    func testTrackingResetBlocksCaptureUntilRelocalized() throws {
        var coordinator = RoomScanCoordinator()
        try coordinator.startScan()
        let frame = makeFrame(epoch: 1)
        try coordinator.accept(frame: frame)
        try coordinator.requestConfirmation()
        try coordinator.confirmDimensions()
        try coordinator.confirmDoors()
        try coordinator.registerRF(makeRegistration())
        try coordinator.confirmPhoneFixed()
        try coordinator.trackingDidReset(to: 2)
        XCTAssertEqual(coordinator.phase, .awaitingRelocalization)
        XCTAssertThrowsError(try coordinator.resume()) { error in
            XCTAssertEqual(error as? PhoneClientError, .trackingResetRequiresRelocalization)
        }
        try coordinator.relocalized(frame: makeFrame(epoch: 2))
        XCTAssertEqual(coordinator.phase, .capturingSupervision)
    }

    func testPartialVisibilityCannotBecomeWholeRoomEmpty() throws {
        let relation = try makePhoneRelation()
        let sample = SupervisionSample(
            rgbReference: "rgb/1",
            depthReference: nil,
            poseReference: "pose/1",
            rgbTime: 500,
            depthTime: 500,
            poseTime: 500,
            maximumTimeError: 0,
            trackingEpoch: 1,
            relocalized: true,
            trackingQuality: .normal,
            depthQuality: .missing,
            scope: .locallyVisible,
            personVisibility: [],
            label: .wholeRoomEmpty,
            cameraToWorld: makeTransform(source: "camera", target: "arkit-world", error: 0.01),
            sampleSource: SourceIdentity(namespace: "phone", identity: "capture-1"),
            jointErrorM: 0.01
        )
        let supervision = SupervisionSegment(
            metadata: ArtifactMetadata(artifactID: "labels", revision: 1, provenance: [SourceIdentity(namespace: "phone", identity: "capture")]),
            sceneDigest: try SealedArtifact.seal(.scene(makeScene())).digest,
            cameraIntrinsics: [1, 0, 0, 0, 1, 0, 0, 0, 1],
            samples: [sample],
            sharedPositionErrorM: 0.01,
            timeRelation: relation,
            maximumPersonVelocityMPS: 12
        )
        XCTAssertThrowsError(try supervision.validate())
    }

    func testCoordinateAndClockValidationRejectsUnsafeFrames() throws {
        let singular = CoordinateTransform(
            sourceCoordinateSystem: "camera",
            targetCoordinateSystem: "arkit-world",
            matrix: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1],
            maxErrorM: 0.01
        )
        XCTAssertThrowsError(try singular.applying(to: [0, 0, 0]))

        let mismatchedFrame = ScanFrame(
            worldCoordinateSystem: "arkit-world",
            geometry: makeScene().geometry,
            geometryValidityMask: [true],
            coverageMask: makeScene().coverageMask,
            scanCoverage: 0.96,
            mapErrorM: 0.1,
            cameraToWorld: makeTransform(source: "camera", target: "other-world", error: 0.01),
            trackingEpoch: 1,
            trackingQuality: .normal,
            depthQuality: .measured
        )
        XCTAssertThrowsError(try mismatchedFrame.validate())

        let relation = try makePhoneRelation()
        XCTAssertEqual(relation.error(at: 500), 5)
        XCTAssertNil(relation.error(at: 1_000_001))
    }

    func testExporterRejectsUnknownRFAndRoundTripsOfflinePackage() throws {
        let scene = makeScene()
        let sceneDigest = try SealedArtifact.seal(.scene(scene)).digest
        let calibration = makeCalibration(sceneDigest: sceneDigest)
        let supervision = makeSupervision(sceneDigest: sceneDigest)
        let unknownExporter = try PhoneArtifactExporter(knownRFIdentities: ["other-rf"])
        XCTAssertThrowsError(try unknownExporter.makePackage(scene: scene, calibration: calibration, supervision: supervision)) { error in
            XCTAssertEqual(error as? PhoneClientError, .unknownRFIdentity("rf-1"))
        }

        let exporter = try PhoneArtifactExporter(knownRFIdentities: ["rf-1"])
        let package = try exporter.makePackage(
            scene: scene,
            calibration: calibration,
            supervision: supervision,
            usdzData: Data([0x55, 0x53, 0x44, 0x5a]),
            keyframes: [CameraKeyframe(reference: "pose/1", phoneTime: 500, pose: makeTransform(source: "camera", target: "arkit-world", error: 0.01), trackingEpoch: 1, trackingQuality: .normal, depthQuality: .missing)]
        )
        let archive = try package.encoded()
        let restored = try PhoneCapturePackage.parse(archive, knownRFIdentities: ["rf-1"])
        XCTAssertEqual(restored, package)
        XCTAssertEqual(try package.digest(), try ArtifactDigest(bytes: SHA256Digest.hash(archive)))
    }

    func testCompanionPairingClockAndUploadWireContract() throws {
        let crypto = DeterministicCrypto()
        let pairingID = try PairingID(bytes: Data(repeating: 1, count: 16))
        let identity = try CompanionServerIdentity(bytes: Data(repeating: 2, count: 32))
        let invitation = try CompanionInvitation(
            pairingID: pairingID,
            serverIdentity: identity,
            expiresAtUTC: 10_000,
            serverEphemeralPublicKey: Data(repeating: 3, count: 32),
            serverProof: Data(repeating: 4, count: 64)
        )
        let parsedInvitation = try CompanionInvitation.fromWire(invitation.toWire(), pinnedServerIdentity: identity, crypto: crypto)
        let nonce = try ClientNonce(bytes: Data(repeating: 5, count: 32))
        var challenges = [ClockSampleChallenge]()
        for index in 0..<3 {
            challenges.append(try ClockSampleChallenge(
                pairingID: pairingID,
                clientNonce: nonce,
                clientSend: UInt64(100 + index * 100),
                hostReceive: UInt64(110 + index * 100),
                hostSend: UInt64(111 + index * 100),
                serverProof: Data(repeating: 6, count: 64)
            ))
        }
        let responses = challenges.map { ClockSampleResponse(challenge: $0, clientReceive: $0.clientSend + 20) }
        let code = try PairingCode(bytes: Data(repeating: 7, count: 16))
        let secret = try ClientEphemeralSecret(bytes: Data(repeating: 8, count: 32))
        let (request, pending) = try parsedInvitation.beginHandshake(pairingCode: code, clientNonce: nonce, clientEphemeralSecret: secret, clockResponses: responses, crypto: crypto)
        XCTAssertEqual(request.toWire().count, 152 + 3 * 152)
        let decodedRequest = try CompanionHandshakeRequest.fromWire(request.toWire(), crypto: crypto)
        let relation = try makePhoneRelation()
        let handshake = try CompanionHandshakeResponse(sessionID: Data(repeating: 9, count: 16), clockRelation: relation, serverProof: Data(repeating: 10, count: 64))
        let connection = try pending.complete(try CompanionHandshakeResponse.fromWire(handshake.toWire()))
        let uploadID = try UploadID(bytes: Data(repeating: 11, count: 16))
        let chunks = try connection.sealUpload(uploadID: uploadID, sealedBytes: Data(repeating: 12, count: 10), chunkBytes: 4)
        XCTAssertEqual(chunks.count, 3)
        XCTAssertEqual(try CompanionHandshakeRequest.fromWire(decodedRequest.toWire(), crypto: crypto), decodedRequest)
        for chunk in chunks {
            XCTAssertEqual(try CompanionChunk.fromWire(chunk.toWire()), chunk)
        }
    }

    func testResumableUploadLeavesOnlyMissingChunksAfterRetry() throws {
        let uploadID = try UploadID(bytes: Data(repeating: 7, count: 16))
        let chunks = try (0..<3).map { index in
            let plaintextBytes = index == 2 ? 2 : 4
            return try CompanionChunk(sessionID: Data(repeating: 1, count: 16), uploadID: uploadID, index: UInt32(index), chunkCount: 3, chunkPlaintextBytes: 4, totalBytes: 10, fullDigest: Data(repeating: 2, count: 32), ciphertext: Data(repeating: UInt8(index), count: plaintextBytes + 16))
        }
        var plan = ResumableUpload(uploadID: uploadID, chunks: chunks)
        try plan.acknowledge(index: 0)
        XCTAssertEqual(plan.pendingChunks.map(\.index), [1, 2])
        try plan.acknowledge(index: 1)
        XCTAssertFalse(plan.isComplete)
        try plan.acknowledge(index: 2)
        XCTAssertTrue(plan.isComplete)
        XCTAssertThrowsError(try plan.acknowledge(index: 99))
    }

    func testOfflineCacheAndTransportRetryPreserveExactChunks() async throws {
        let uploadID = try UploadID(bytes: Data(repeating: 8, count: 16))
        let chunks = try (0..<3).map { index in
            let plaintextBytes = index == 2 ? 2 : 4
            return try CompanionChunk(
                sessionID: Data(repeating: 3, count: 16),
                uploadID: uploadID,
                index: UInt32(index),
                chunkCount: 3,
                chunkPlaintextBytes: 4,
                totalBytes: 10,
                fullDigest: Data(repeating: 4, count: 32),
                ciphertext: Data(repeating: UInt8(index), count: plaintextBytes + 16)
            )
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let cache = try FileUploadCache(directory: directory)
        defer { try? FileManager.default.removeItem(at: directory) }
        for chunk in chunks { try await cache.store(chunk) }
        XCTAssertEqual(try await cache.load(uploadID: uploadID), chunks)

        var plan = ResumableUpload(uploadID: uploadID, chunks: chunks)
        try plan.acknowledge(index: 0)
        let transport = RetryTransport()
        do {
            try await CompanionUploadCoordinator().upload(&plan, through: transport)
            XCTFail("the first transport attempt should fail")
        } catch {
            XCTAssertEqual(error as? PhoneClientError, .uploadUnavailable)
        }
        await transport.allowSends()
        try await CompanionUploadCoordinator().upload(&plan, through: transport)
        XCTAssertTrue(plan.isComplete)
        let frames = await transport.frames()
        XCTAssertEqual(frames.count, 3)
        for frame in frames {
            XCTAssertEqual(try CompanionChunk.fromWire(frame), chunks[Int(frame.readUInt32LE(at: 36))])
        }
        try await cache.remove(uploadID: uploadID)
        let cachedAfterRemove = try await cache.load(uploadID: uploadID)
        XCTAssertTrue(cachedAfterRemove.isEmpty)
    }
}

private actor RetryTransport: CompanionByteTransport {
    private var shouldFail = true
    private var sentFrames: [Data] = []

    func send(_ frame: Data) async throws -> Data {
        sentFrames.append(frame)
        if shouldFail {
            throw PhoneClientError.uploadUnavailable
        }
        return Data()
    }

    func allowSends() {
        shouldFail = false
    }

    func frames() -> [Data] {
        sentFrames
    }
}

private struct DeterministicCrypto: CompanionCrypto {
    func verifyEd25519(publicKey: Data, message: Data, signature: Data) throws {
        _ = (publicKey, message, signature)
    }

    func x25519PublicKey(privateKey: Data) throws -> Data {
        _ = privateKey
        return Data(repeating: 13, count: 32)
    }

    func x25519SharedSecret(privateKey: Data, publicKey: Data) throws -> Data {
        _ = (privateKey, publicKey)
        return Data(repeating: 14, count: 32)
    }

    func encryptAESGCM(key: Data, nonce: Data, plaintext: Data, authenticatedData: Data) throws -> Data {
        _ = (key, nonce, authenticatedData)
        var output = plaintext
        output.append(Data(repeating: 15, count: 16))
        return output
    }
}

private func makeScene() -> SceneSnapshot {
    SceneSnapshot(
        metadata: ArtifactMetadata(artifactID: "scene-a", revision: 1, provenance: [SourceIdentity(namespace: "phone-roomplan", identity: "scan-1")]),
        worldCoordinateSystem: "arkit-world",
        geometry: [GeometryElement(kind: .wall, verticesM: [[0, 0, 0], [4, 0, 0]])],
        geometryValidityMask: [true],
        coverageMask: [CoverageCell(positionM: [1, 1, 0], covered: true)],
        scanCoverage: 0.96,
        mapErrorM: 0.1,
        usdzDisplayReference: "room-a.usdz"
    )
}

private func makeTransform(source: String, target: String, error: Double) -> CoordinateTransform {
    CoordinateTransform(sourceCoordinateSystem: source, targetCoordinateSystem: target, matrix: [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1], maxErrorM: error)
}

private func makeFrame(epoch: UInt32) -> ScanFrame {
    ScanFrame(worldCoordinateSystem: "arkit-world", geometry: makeScene().geometry, geometryValidityMask: [true], coverageMask: makeScene().coverageMask, scanCoverage: 0.96, mapErrorM: 0.1, cameraToWorld: makeTransform(source: "camera", target: "arkit-world", error: 0.01), trackingEpoch: epoch, trackingQuality: .normal, depthQuality: .measured)
}

private func makeRegistration() -> RFDeviceRegistration {
    RFDeviceRegistration(rfDeviceIdentity: "rf-1", markerIdentity: "marker-1", antennaReference: "marker-to-array", markerToAntenna: makeTransform(source: "marker-1", target: "marker-to-array", error: 0.01), errorM: 0.01, source: SourceIdentity(namespace: "phone", identity: "registration-1"))
}

private func makePhoneRelation() throws -> PhoneTimeRelation {
    try PhoneTimeRelation(relationID: Data(repeating: 9, count: 16), offsetAtReference: 20, driftPartsPerBillion: 10, referencePhoneTime: 500, maximumError: 5, validFromPhoneTime: 0, validUntilPhoneTime: 1_000_000)
}

private func makeCalibration(sceneDigest: ArtifactDigest) -> CalibrationBundle {
    CalibrationBundle(
        metadata: ArtifactMetadata(artifactID: "calibration-a", revision: 1, provenance: [SourceIdentity(namespace: "phone", identity: "calibration")]),
        sceneDigest: sceneDigest,
        rfDeviceIdentity: "rf-1",
        antennaReference: "marker-to-array",
        worldTransform: makeTransform(source: "array", target: "arkit-world", error: 0.05),
        signalPaths: [SignalPathCondition(logicalPath: "rx-0", direction: .receive, deviceChain: "chain-0", antennaIdentity: "element-0")],
        arrayCondition: ArrayCondition(arrayIdentity: "array-1", physicalElementCount: 1),
        arrayGeometry: DeviceArrayGeometry(source: SourceIdentity(namespace: "metrology", identity: "run-1"), applicability: "test", minimumFrequencyHz: 5_150_000_000, maximumFrequencyHz: 5_850_000_000, deviceToArray: makeTransform(source: "device", target: "array", error: 0.02), elements: [ArrayElementGeometry(antennaIdentity: "element-0", positionM: [0, 0, 0])], maximumPositionErrorM: 0.01, validFromUTC: 0, validUntilUTC: 1_000_000, epoch: 1),
        phaseRelation: PhaseRelation(source: SourceIdentity(namespace: "metrology", identity: "phase-1"), scope: .packet, maximumErrorRadians: 0.05, validFromUTC: 0, validUntilUTC: 1_000_000, epoch: 1),
        timeRelation: RfTimeRelation(source: SourceIdentity(namespace: "metrology", identity: "time-1"), offset: 2, maximumError: 10, validFromUTC: 0, validUntilUTC: 1_000_000, epoch: 1),
        maxErrorM: 0.02,
        validFromUTC: 100,
        validUntilUTC: 900_000
    )
}

private func makeSupervision(sceneDigest: ArtifactDigest) -> SupervisionSegment {
    SupervisionSegment(
        metadata: ArtifactMetadata(artifactID: "labels-a", revision: 1, provenance: [SourceIdentity(namespace: "phone", identity: "labels")]),
        sceneDigest: sceneDigest,
        cameraIntrinsics: [1, 0, 0, 0, 1, 0, 0, 0, 1],
        samples: [SupervisionSample(rgbReference: "rgb/1", depthReference: nil, poseReference: "pose/1", rgbTime: 500, depthTime: 500, poseTime: 500, maximumTimeError: 5, trackingEpoch: 1, relocalized: true, trackingQuality: .normal, depthQuality: .missing, scope: .locallyVisible, personVisibility: [0.8], label: .visibleSet([PersonLabel(station: "station-a", pose: "standing", positionM: [1, 1, 0], maxErrorM: 0.05)]), cameraToWorld: makeTransform(source: "camera", target: "arkit-world", error: 0.01), sampleSource: SourceIdentity(namespace: "phone", identity: "capture-1"), jointErrorM: 0.01)],
        sharedPositionErrorM: 0.02,
        timeRelation: try! makePhoneRelation(),
        maximumPersonVelocityMPS: 12
    )
}
