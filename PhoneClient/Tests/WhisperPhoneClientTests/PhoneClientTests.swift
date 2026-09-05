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
        XCTAssertThrowsError(try coordinator.relocalized(frame: makeFrame(epoch: 2, trackingQuality: .limited))) { error in
            XCTAssertEqual(error as? PhoneClientError, .trackingResetRequiresRelocalization)
        }
        try coordinator.relocalized(frame: makeFrame(epoch: 2))
        XCTAssertEqual(coordinator.phase, .capturingSupervision)
    }

    func testSupervisionPauseResumeKeepsAcceptingSharedRoomPlanFrames() throws {
        var coordinator = RoomScanCoordinator()
        try coordinator.startScan()
        try coordinator.accept(frame: makeFrame(epoch: 1))
        try coordinator.requestConfirmation()
        try coordinator.confirmDimensions()
        try coordinator.confirmDoors()
        try coordinator.registerRF(makeRegistration())
        try coordinator.confirmPhoneFixed()
        try coordinator.accept(frame: makeFrame(epoch: 1))
        try coordinator.pause()
        XCTAssertEqual(coordinator.phase, .paused)
        try coordinator.resume()
        try coordinator.accept(frame: makeFrame(epoch: 1))
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
        let supervision = makeSupervision(sceneDigest: sceneDigest, depthReference: "depth/1")
        let usdzData = Data([0x55, 0x53, 0x44, 0x5a])
        let keyframes = [CameraKeyframe(reference: "pose/1", phoneTime: 500, pose: makeTransform(source: "camera", target: "arkit-world", error: 0.01), trackingEpoch: 1, trackingQuality: .normal, depthQuality: .missing)]
        let media = [try makeRGBMedia(), try makeDepthMedia()]
        let unknownExporter = try PhoneArtifactExporter(knownRFIdentities: ["other-rf"])
        XCTAssertThrowsError(try unknownExporter.makePackage(scene: scene, calibration: calibration, supervision: supervision, usdzData: usdzData, keyframes: keyframes, media: media)) { error in
            XCTAssertEqual(error as? PhoneClientError, .unknownRFIdentity("rf-1"))
        }

        let exporter = try PhoneArtifactExporter(knownRFIdentities: ["rf-1"])
        let package = try exporter.makePackage(
            scene: scene,
            calibration: calibration,
            supervision: supervision,
            usdzData: usdzData,
            keyframes: keyframes,
            media: media
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
        let wallClock = FixedWallClock(value: 9_999)
        let parsedInvitation = try CompanionInvitation.fromWire(invitation.toWire(), pinnedServerIdentity: identity, crypto: crypto, wallClock: wallClock)
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
        let (request, pending) = try parsedInvitation.beginHandshake(pairingCode: code, clientNonce: nonce, clientEphemeralSecret: secret, clockResponses: responses, crypto: crypto, wallClock: wallClock)
        XCTAssertEqual(request.toWire().count, 152 + 3 * 152)
        let decodedRequest = try CompanionHandshakeRequest.fromWire(request.toWire(), crypto: crypto)
        let relation = try makePhoneRelation()
        let handshake = try CompanionHandshakeResponse(sessionID: Data(repeating: 9, count: 16), clockRelation: relation, serverProof: Data(repeating: 10, count: 64))
        let handshakeResponse = try CompanionHandshakeResponse.fromWire(handshake.toWire())
        let connection = try pending.complete(handshakeResponse, wallClock: wallClock)
        XCTAssertThrowsError(try pending.complete(handshakeResponse, wallClock: FixedWallClock(value: 10_000))) { error in
            XCTAssertEqual(error as? PhoneClientError, .invitationExpired)
        }
        let uploadID = try UploadID(bytes: Data(repeating: 11, count: 16))
        let chunks = try connection.sealUpload(uploadID: uploadID, sealedBytes: Data(repeating: 12, count: 10), chunkBytes: 4)
        XCTAssertEqual(chunks.count, 3)
        XCTAssertEqual(try CompanionHandshakeRequest.fromWire(decodedRequest.toWire(), crypto: crypto), decodedRequest)
        for chunk in chunks {
            XCTAssertEqual(try CompanionChunk.fromWire(chunk.toWire()), chunk)
        }
        XCTAssertThrowsError(try CompanionInvitation.fromWire(invitation.toWire(), pinnedServerIdentity: identity, crypto: crypto, wallClock: FixedWallClock(value: 10_000))) { error in
            XCTAssertEqual(error as? PhoneClientError, .invitationExpired)
        }
        XCTAssertThrowsError(try parsedInvitation.beginHandshake(pairingCode: code, clientNonce: nonce, clientEphemeralSecret: secret, clockResponses: responses, crypto: crypto, wallClock: FixedWallClock(value: 10_000))) { error in
            XCTAssertEqual(error as? PhoneClientError, .invitationExpired)
        }
    }

    func testResumableUploadLeavesOnlyMissingChunksAfterRetry() throws {
        let uploadID = try UploadID(bytes: Data(repeating: 7, count: 16))
        let chunks = try (0..<3).map { index in
            let plaintextBytes = index == 2 ? 2 : 4
            return try CompanionChunk(sessionID: Data(repeating: 1, count: 16), uploadID: uploadID, index: UInt32(index), chunkCount: 3, chunkPlaintextBytes: 4, totalBytes: 10, fullDigest: Data(repeating: 2, count: 32), ciphertext: Data(repeating: UInt8(index), count: plaintextBytes + 16))
        }
        var plan = try ResumableUpload(uploadID: uploadID, chunks: chunks)
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
        let chunks = try makeChunks(uploadID: uploadID, sessionByte: 3, digestByte: 4)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let cache = try FileUploadCache(directory: directory)
        defer { try? FileManager.default.removeItem(at: directory) }
        var plan = try ResumableUpload(uploadID: uploadID, chunks: chunks)
        try plan.acknowledge(index: 0)
        try await cache.save(plan)
        var restoredPlan = try await cache.loadPlan(uploadID: uploadID)
        XCTAssertEqual(restoredPlan.acknowledgedIndices, Set<UInt32>([0]))
        XCTAssertEqual(restoredPlan.chunks, chunks)

        let transport = RetryTransport()
        do {
            try await CompanionUploadCoordinator().upload(&restoredPlan, through: transport, cache: cache)
            XCTFail("the first transport attempt should fail")
        } catch {
            XCTAssertEqual(error as? PhoneClientError, .uploadUnavailable)
        }
        await transport.allowSends()
        try await CompanionUploadCoordinator().upload(&restoredPlan, through: transport, cache: cache)
        XCTAssertTrue(restoredPlan.isComplete)
        let frames = await transport.frames()
        XCTAssertEqual(frames.count, 3)
        XCTAssertEqual(try frames.map { try CompanionChunk.fromWire($0).index }, [1, 1, 2])
        for frame in frames {
            let chunk = try CompanionChunk.fromWire(frame)
            XCTAssertEqual(chunk, chunks[Int(chunk.index)])
        }
        let completedPlan = try await cache.loadPlan(uploadID: uploadID)
        XCTAssertTrue(completedPlan.isComplete)
        try await cache.remove(uploadID: uploadID)
        let cachedAfterRemove = try await cache.load(uploadID: uploadID)
        XCTAssertTrue(cachedAfterRemove.isEmpty)
    }

    func testResumableUploadRejectsInvalidLayoutsAndHostReceipts() throws {
        let uploadID = try UploadID(bytes: Data(repeating: 21, count: 16))
        let chunks = try makeChunks(uploadID: uploadID, sessionByte: 22, digestByte: 23)
        XCTAssertThrowsError(try ResumableUpload(uploadID: uploadID, chunks: [chunks[0], chunks[0], chunks[2]]))
        XCTAssertThrowsError(try ResumableUpload(uploadID: uploadID, chunks: Array(chunks.dropLast())))
        var mixed = chunks
        mixed[1] = try CompanionChunk(sessionID: Data(repeating: 24, count: 16), uploadID: uploadID, index: 1, chunkCount: 3, chunkPlaintextBytes: 4, totalBytes: 10, fullDigest: Data(repeating: 23, count: 32), ciphertext: Data(repeating: 1, count: 20))
        XCTAssertThrowsError(try ResumableUpload(uploadID: uploadID, chunks: mixed))
        XCTAssertThrowsError(try ResumableUpload(uploadID: uploadID, chunks: chunks, acknowledged: [99]))
        XCTAssertThrowsError(try CompanionUploadProgress(sessionID: Data(repeating: 22, count: 16), uploadID: uploadID, chunkCount: 3, chunkPlaintextBytes: 4, totalBytes: 10, fullDigest: Data(repeating: 23, count: 32), receivedIndices: [1, 1]))
        let pendingProgress = try CompanionUploadProgress(sessionID: Data(repeating: 22, count: 16), uploadID: uploadID, chunkCount: 3, chunkPlaintextBytes: 4, totalBytes: 10, fullDigest: Data(repeating: 23, count: 32), receivedIndices: [0])
        let pending = CompanionUploadReply.pending(pendingProgress)
        XCTAssertEqual(try CompanionUploadReply.fromWire(pending.toWire()), pending)
        XCTAssertThrowsError(try CompanionUploadReceipt(progress: pendingProgress, artifactDigest: try ArtifactDigest(bytes: Data(repeating: 23, count: 32)), artifactKind: 1, artifactID: "scene-a", revision: 1))
        let completeProgress = try CompanionUploadProgress(sessionID: Data(repeating: 22, count: 16), uploadID: uploadID, chunkCount: 3, chunkPlaintextBytes: 4, totalBytes: 10, fullDigest: Data(repeating: 23, count: 32), receivedIndices: [0, 1, 2])
        let receipt = try CompanionUploadReceipt(progress: completeProgress, artifactDigest: try ArtifactDigest(bytes: Data(repeating: 23, count: 32)), artifactKind: 1, artifactID: "scene-a", revision: 1)
        XCTAssertEqual(try CompanionUploadReply.fromWire(CompanionUploadReply.committed(receipt).toWire()), .committed(receipt))
    }

    func testUploadCoordinatorRejectsHostResponseWithoutAcknowledging() async throws {
        let uploadID = try UploadID(bytes: Data(repeating: 31, count: 16))
        let chunks = try makeChunks(uploadID: uploadID, sessionByte: 32, digestByte: 33)
        var plan = try ResumableUpload(uploadID: uploadID, chunks: chunks)
        let progress = try CompanionUploadProgress(sessionID: Data(repeating: 32, count: 16), uploadID: uploadID, chunkCount: 3, chunkPlaintextBytes: 4, totalBytes: 10, fullDigest: Data(repeating: 33, count: 32), receivedIndices: [])
        let rejection = CompanionUploadReply.rejected(progress: progress, reason: .artifactRejected)
        XCTAssertEqual(try CompanionUploadReply.fromWire(rejection.toWire()), rejection)
        do {
            try await CompanionUploadCoordinator().upload(&plan, through: RejectingTransport(response: rejection.toWire()))
            XCTFail("the Host rejection must stop the upload")
        } catch {
            XCTAssertEqual(error as? PhoneClientError, .uploadRejected("artifact rejected"))
        }
        XCTAssertTrue(plan.acknowledgedIndices.isEmpty)
    }

    func testCoverageSummaryUsesWorldPositionsAndKeepsRangesSeparate() {
        let visual = [CoverageCell(positionM: [10, 0, 20], covered: true), CoverageCell(positionM: [12, 0, 22], covered: false)]
        let rf = [CoverageCell(positionM: [30, 0, 40], covered: true)]
        let calibration = [CoverageCell(positionM: [50, 0, 60], covered: false)]
        let ranges = MapCoverageRanges(visualScan: visual, rfExpectedObservable: rf, fieldCalibration: calibration)
        let summaries = [
            CoverageMapSummary(title: "Visual scan", cells: ranges.visualScan),
            CoverageMapSummary(title: "RF expected", cells: ranges.rfExpectedObservable),
            CoverageMapSummary(title: "Field calibration", cells: ranges.fieldCalibration),
        ]
        XCTAssertEqual(summaries.map(\.title), ["Visual scan", "RF expected", "Field calibration"])
        XCTAssertEqual(summaries.map(\.coveredCount), [1, 1, 0])
        XCTAssertEqual(summaries[0].points, [CoverageMapPoint(x: 0, y: 0, covered: true), CoverageMapPoint(x: 1, y: 1, covered: false)])
        XCTAssertNotEqual(summaries[0].points, summaries[1].points)
    }

    func testRustAndSwiftSceneFixturesRoundTripThroughTheSameWSA1Codec() throws {
        for fixtureName in ["rust-scene-wsa1", "swift-scene-wsa1"] {
            let bytes = try fixture(named: fixtureName)
            let sealed = try SealedArtifact.parse(bytes)
            guard case let .scene(scene) = try sealed.decode() else {
                XCTFail("fixture must contain a scene artifact")
                continue
            }
            XCTAssertEqual(try SealedArtifact.seal(.scene(scene)).bytes, bytes)
            XCTAssertEqual(scene.metadata.artifactID, fixtureName == "rust-scene-wsa1" ? "room-a" : "swift-room-b")
            XCTAssertEqual(scene.worldCoordinateSystem, "arkit-world-42")
        }
    }

    func testPackageRejectsMissingOrUnreferencedCaptureAssets() throws {
        let scene = makeScene()
        let sceneDigest = try SealedArtifact.seal(.scene(scene)).digest
        let calibration = makeCalibration(sceneDigest: sceneDigest)
        let supervision = makeSupervision(sceneDigest: sceneDigest, depthReference: "depth/1")
        let usdz = Data([0x55, 0x53, 0x44, 0x5a])
        let keyframe = CameraKeyframe(reference: "pose/1", phoneTime: 500, pose: makeTransform(source: "camera", target: "arkit-world", error: 0.01), trackingEpoch: 1, trackingQuality: .normal, depthQuality: .missing)
        let media = [try makeRGBMedia()]
        let exporter = try PhoneArtifactExporter(knownRFIdentities: ["rf-1"])
        XCTAssertThrowsError(try exporter.makePackage(scene: scene, calibration: calibration, supervision: supervision, usdzData: Data(), keyframes: [keyframe], media: media))
        XCTAssertThrowsError(try exporter.makePackage(scene: scene, calibration: calibration, supervision: supervision, usdzData: usdz, keyframes: [], media: media))
        XCTAssertThrowsError(try exporter.makePackage(scene: scene, calibration: calibration, supervision: supervision, usdzData: usdz, keyframes: [keyframe], media: []))
        XCTAssertThrowsError(try exporter.makePackage(scene: scene, calibration: calibration, supervision: makeSupervision(sceneDigest: sceneDigest, depthReference: "depth/1"), usdzData: usdz, keyframes: [keyframe], media: [try makeRGBMedia()]))
        XCTAssertThrowsError(try exporter.makePackage(scene: scene, calibration: calibration, supervision: makeSupervision(sceneDigest: sceneDigest, rgbReference: "missing-rgb"), usdzData: usdz, keyframes: [keyframe], media: media))
        XCTAssertThrowsError(try exporter.makePackage(scene: scene, calibration: calibration, supervision: supervision, usdzData: usdz, keyframes: [keyframe], media: media + [try CaptureMedia(reference: "unreferenced", kind: .rgb, phoneTime: 500, bytes: Data([9]))]))
    }
}

private func fixture(named name: String) throws -> Data {
    #if SWIFT_PACKAGE
    guard let url = Bundle.module.url(forResource: name, withExtension: "hex", subdirectory: "Fixtures") else {
        throw PhoneClientError.persistence("fixture \(name) is missing")
    }
    #else
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures").appendingPathComponent("\(name).hex")
    #endif
    let hex = try String(contentsOf: url, encoding: .utf8)
        .filter { !$0.isWhitespace }
    guard hex.count.isMultiple(of: 2) else { throw PhoneClientError.malformedWire("fixture hex has odd length") }
    var bytes = Data(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let end = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<end], radix: 16) else {
            throw PhoneClientError.malformedWire("fixture hex contains a non-byte")
        }
        bytes.append(byte)
        index = end
    }
    return bytes
}

private actor RetryTransport: CompanionByteTransport {
    private var shouldFail = true
    private var sentFrames: [Data] = []
    private var acceptedIndices = Set<UInt32>()

    func send(_ frame: Data) async throws -> Data {
        sentFrames.append(frame)
        let chunk = try CompanionChunk.fromWire(frame)
        acceptedIndices.insert(chunk.index)
        if shouldFail {
            throw PhoneClientError.uploadUnavailable
        }
        let progress = try CompanionUploadProgress(sessionID: chunk.sessionID, uploadID: chunk.uploadID, chunkCount: chunk.chunkCount, chunkPlaintextBytes: chunk.chunkPlaintextBytes, totalBytes: chunk.totalBytes, fullDigest: chunk.fullDigest, receivedIndices: Array(acceptedIndices))
        if acceptedIndices.count == Int(chunk.chunkCount) {
            let receipt = try CompanionUploadReceipt(progress: progress, artifactDigest: try ArtifactDigest(bytes: chunk.fullDigest), artifactKind: 1, artifactID: "scene-a", revision: 1)
            return CompanionUploadReply.committed(receipt).toWire()
        }
        return CompanionUploadReply.pending(progress).toWire()
    }

    func allowSends() {
        shouldFail = false
    }

    func frames() -> [Data] {
        sentFrames
    }
}

private struct FixedWallClock: CompanionWallClock {
    let value: UInt64

    func nowUTC() -> UInt64 { value }
}

private struct RejectingTransport: CompanionByteTransport {
    let response: Data

    func send(_ frame: Data) async throws -> Data {
        _ = frame
        return response
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

private func makeChunks(uploadID: UploadID, sessionByte: UInt8, digestByte: UInt8) throws -> [CompanionChunk] {
    try (0..<3).map { index in
        let plaintextBytes = index == 2 ? 2 : 4
        return try CompanionChunk(
            sessionID: Data(repeating: sessionByte, count: 16),
            uploadID: uploadID,
            index: UInt32(index),
            chunkCount: 3,
            chunkPlaintextBytes: 4,
            totalBytes: 10,
            fullDigest: Data(repeating: digestByte, count: 32),
            ciphertext: Data(repeating: UInt8(index), count: plaintextBytes + 16)
        )
    }
}

private func makeRGBMedia() throws -> CaptureMedia {
    try CaptureMedia(reference: "rgb/1", kind: .rgb, phoneTime: 500, bytes: Data([1, 2, 3]))
}

private func makeDepthMedia() throws -> CaptureMedia {
    try CaptureMedia(reference: "depth/1", kind: .depth, phoneTime: 500, bytes: Data([4, 5, 6]))
}

private func makeTransform(source: String, target: String, error: Double) -> CoordinateTransform {
    CoordinateTransform(sourceCoordinateSystem: source, targetCoordinateSystem: target, matrix: [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1], maxErrorM: error)
}

private func makeFrame(epoch: UInt32, trackingQuality: TrackingQuality = .normal) -> ScanFrame {
    ScanFrame(worldCoordinateSystem: "arkit-world", geometry: makeScene().geometry, geometryValidityMask: [true], coverageMask: makeScene().coverageMask, scanCoverage: 0.96, mapErrorM: 0.1, cameraToWorld: makeTransform(source: "camera", target: "arkit-world", error: 0.01), trackingEpoch: epoch, trackingQuality: trackingQuality, depthQuality: .measured)
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

private func makeSupervision(sceneDigest: ArtifactDigest, rgbReference: String = "rgb/1", depthReference: String? = nil, poseReference: String = "pose/1") -> SupervisionSegment {
    SupervisionSegment(
        metadata: ArtifactMetadata(artifactID: "labels-a", revision: 1, provenance: [SourceIdentity(namespace: "phone", identity: "labels")]),
        sceneDigest: sceneDigest,
        cameraIntrinsics: [1, 0, 0, 0, 1, 0, 0, 0, 1],
        samples: [SupervisionSample(rgbReference: rgbReference, depthReference: depthReference, poseReference: poseReference, rgbTime: 500, depthTime: 500, poseTime: 500, maximumTimeError: 5, trackingEpoch: 1, relocalized: true, trackingQuality: .normal, depthQuality: depthReference == nil ? .missing : .measured, scope: .locallyVisible, personVisibility: [0.8], label: .visibleSet([PersonLabel(station: "station-a", pose: "standing", positionM: [1, 1, 0], maxErrorM: 0.05)]), cameraToWorld: makeTransform(source: "camera", target: "arkit-world", error: 0.01), sampleSource: SourceIdentity(namespace: "phone", identity: "capture-1"), jointErrorM: 0.01)],
        sharedPositionErrorM: 0.02,
        timeRelation: try! makePhoneRelation(),
        maximumPersonVelocityMPS: 12
    )
}
