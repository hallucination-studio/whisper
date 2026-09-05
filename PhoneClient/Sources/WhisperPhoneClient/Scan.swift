import Foundation

/// Ordered states in the phone's installation and supervision workflow.
public enum ScanPhase: String, Codable, Equatable, Sendable {
    case idle
    case scanning
    case awaitingDimensionConfirmation
    case awaitingDoorConfirmation
    case registeringRF
    case readyToCapture
    case capturingSupervision
    case paused
    case awaitingRelocalization
    case finished
}

/// A RoomPlan/ARKit frame retained as structured capture input, not as an RF observation.
public struct ScanFrame: Codable, Equatable, Sendable {
    public let worldCoordinateSystem: String
    public let geometry: [GeometryElement]
    public let geometryValidityMask: [Bool]
    public let coverageMask: [CoverageCell]
    public let scanCoverage: Double
    public let mapErrorM: Double
    public let cameraToWorld: CoordinateTransform
    public let trackingEpoch: UInt32
    public let trackingQuality: TrackingQuality
    public let depthQuality: DepthQuality

    public init(
        worldCoordinateSystem: String,
        geometry: [GeometryElement],
        geometryValidityMask: [Bool],
        coverageMask: [CoverageCell],
        scanCoverage: Double,
        mapErrorM: Double,
        cameraToWorld: CoordinateTransform,
        trackingEpoch: UInt32,
        trackingQuality: TrackingQuality,
        depthQuality: DepthQuality
    ) {
        self.worldCoordinateSystem = worldCoordinateSystem
        self.geometry = geometry
        self.geometryValidityMask = geometryValidityMask
        self.coverageMask = coverageMask
        self.scanCoverage = scanCoverage
        self.mapErrorM = mapErrorM
        self.cameraToWorld = cameraToWorld
        self.trackingEpoch = trackingEpoch
        self.trackingQuality = trackingQuality
        self.depthQuality = depthQuality
    }

    public func validate() throws {
        let scene = SceneSnapshot(
            metadata: ArtifactMetadata(artifactID: "scan-frame", revision: 1, provenance: [SourceIdentity(namespace: "phone", identity: "scan")]),
            worldCoordinateSystem: worldCoordinateSystem,
            geometry: geometry,
            geometryValidityMask: geometryValidityMask,
            coverageMask: coverageMask,
            scanCoverage: scanCoverage,
            mapErrorM: mapErrorM,
            usdzDisplayReference: nil
        )
        try scene.validate()
        try cameraToWorld.validate()
        guard cameraToWorld.targetCoordinateSystem == worldCoordinateSystem else {
            throw PhoneClientError.transformError("camera pose target does not match the scan world coordinate system")
        }
    }
}

/// Registered fixed RF identity and marker-to-antenna offset.
public struct RFDeviceRegistration: Codable, Equatable, Sendable {
    public let rfDeviceIdentity: String
    public let markerIdentity: String
    public let antennaReference: String
    public let markerToAntenna: CoordinateTransform
    public let errorM: Double
    public let source: SourceIdentity

    public init(rfDeviceIdentity: String, markerIdentity: String, antennaReference: String, markerToAntenna: CoordinateTransform, errorM: Double, source: SourceIdentity) {
        self.rfDeviceIdentity = rfDeviceIdentity
        self.markerIdentity = markerIdentity
        self.antennaReference = antennaReference
        self.markerToAntenna = markerToAntenna
        self.errorM = errorM
        self.source = source
    }

    public func validate() throws {
        try requireText(rfDeviceIdentity, field: "RF device identity")
        try requireText(markerIdentity, field: "marker identity")
        try requireText(antennaReference, field: "antenna reference")
        try markerToAntenna.validate()
        guard markerToAntenna.sourceCoordinateSystem == markerIdentity,
              markerToAntenna.targetCoordinateSystem == antennaReference else {
            throw PhoneClientError.transformError("marker-to-antenna transform coordinates do not match the registration")
        }
        try requireNonnegativeFinite(errorM, field: "RF registration error")
        try source.validate()
    }
}

/// Separate map ranges shown by the UI for visual scan, RF observability, and field calibration.
public struct MapCoverageRanges: Codable, Equatable, Sendable {
    public let visualScan: [CoverageCell]
    public let rfExpectedObservable: [CoverageCell]
    public let fieldCalibration: [CoverageCell]

    public init(visualScan: [CoverageCell], rfExpectedObservable: [CoverageCell], fieldCalibration: [CoverageCell]) {
        self.visualScan = visualScan
        self.rfExpectedObservable = rfExpectedObservable
        self.fieldCalibration = fieldCalibration
    }
}

/// Human-readable label row data retaining source, quality, visibility, scope, and uncertainty.
public struct LabelRow: Codable, Equatable, Sendable {
    public let source: SourceIdentity
    public let phoneTime: UInt64
    public let trackingQuality: TrackingQuality
    public let depthQuality: DepthQuality
    public let visibility: [Double]
    public let errorM: Double
    public let scope: LabelScope
    public let people: [PersonLabel]
    public let isUnknown: Bool

    public init(source: SourceIdentity, phoneTime: UInt64, trackingQuality: TrackingQuality, depthQuality: DepthQuality, visibility: [Double], errorM: Double, scope: LabelScope, people: [PersonLabel], isUnknown: Bool) {
        self.source = source
        self.phoneTime = phoneTime
        self.trackingQuality = trackingQuality
        self.depthQuality = depthQuality
        self.visibility = visibility
        self.errorM = errorM
        self.scope = scope
        self.people = people
        self.isUnknown = isUnknown
    }

    /// Builds a display row while preserving unknown/partially visible labels.
    public init(sample: SupervisionSample) {
        let people: [PersonLabel]
        let isUnknown: Bool
        switch sample.label {
        case .unknown:
            people = []
            isUnknown = true
        case let .visibleSet(value):
            people = value
            isUnknown = false
        case .wholeRoomEmpty:
            people = []
            isUnknown = false
        }
        self.init(source: sample.sampleSource, phoneTime: sample.poseTime, trackingQuality: sample.trackingQuality, depthQuality: sample.depthQuality, visibility: sample.personVisibility, errorM: sample.jointErrorM, scope: sample.scope, people: people, isUnknown: isUnknown)
    }
}

/// A stateful installation workflow with explicit pause and relocalization gates.
public struct RoomScanCoordinator: Sendable {
    public private(set) var phase: ScanPhase = .idle
    public private(set) var currentFrame: ScanFrame?
    public private(set) var registration: RFDeviceRegistration?
    public private(set) var dimensionsConfirmed = false
    public private(set) var doorsConfirmed = false
    public private(set) var phoneFixed = false
    public private(set) var trackingEpoch: UInt32 = 0
    public private(set) var requiresRelocalization = false

    public init() {}

    public mutating func startScan() throws {
        guard phase == .idle else { throw PhoneClientError.invalidState("a scan is already active") }
        phase = .scanning
    }

    public mutating func accept(frame: ScanFrame) throws {
        guard phase == .scanning || phase == .awaitingDimensionConfirmation || phase == .awaitingDoorConfirmation else {
            throw PhoneClientError.invalidState("RoomPlan frames are only accepted during scanning")
        }
        try frame.validate()
        guard !requiresRelocalization else { throw PhoneClientError.trackingResetRequiresRelocalization }
        currentFrame = frame
        trackingEpoch = frame.trackingEpoch
    }

    public mutating func requestConfirmation() throws {
        guard phase == .scanning, currentFrame != nil else {
            throw PhoneClientError.invalidState("a valid RoomPlan frame is required before confirmation")
        }
        phase = .awaitingDimensionConfirmation
    }

    public mutating func confirmDimensions() throws {
        guard phase == .awaitingDimensionConfirmation else { throw PhoneClientError.invalidState("room dimensions are not awaiting confirmation") }
        dimensionsConfirmed = true
        phase = .awaitingDoorConfirmation
    }

    public mutating func confirmDoors() throws {
        guard phase == .awaitingDoorConfirmation, dimensionsConfirmed else { throw PhoneClientError.invalidState("room dimensions must be confirmed first") }
        doorsConfirmed = true
        phase = .registeringRF
    }

    public mutating func registerRF(_ registration: RFDeviceRegistration) throws {
        guard phase == .registeringRF, doorsConfirmed else { throw PhoneClientError.invalidState("door confirmation must precede RF registration") }
        try registration.validate()
        self.registration = registration
        phase = .readyToCapture
    }

    public mutating func confirmPhoneFixed() throws {
        guard phase == .readyToCapture, registration != nil else { throw PhoneClientError.invalidState("RF registration must precede fixed-phone capture") }
        phoneFixed = true
        phase = .capturingSupervision
    }

    public mutating func pause() throws {
        guard phase == .capturingSupervision else { throw PhoneClientError.invalidState("only active supervision capture can be paused") }
        phase = .paused
    }

    public mutating func resume() throws {
        switch phase {
        case .paused where !requiresRelocalization:
            phase = .capturingSupervision
        case .paused, .awaitingRelocalization:
            throw PhoneClientError.trackingResetRequiresRelocalization
        default:
            throw PhoneClientError.invalidState("capture is not paused")
        }
    }

    /// Records a tracking reset; no sample may be captured until relocalization succeeds.
    public mutating func trackingDidReset(to epoch: UInt32) throws {
        guard epoch != trackingEpoch else { return }
        trackingEpoch = epoch
        requiresRelocalization = true
        phase = .awaitingRelocalization
    }

    public mutating func relocalized(frame: ScanFrame) throws {
        guard phase == .awaitingRelocalization, requiresRelocalization else {
            throw PhoneClientError.invalidState("no tracking reset is awaiting relocalization")
        }
        guard frame.trackingEpoch == trackingEpoch else {
            throw PhoneClientError.invalidState("relocalized frame belongs to a different tracking epoch")
        }
        try frame.validate()
        guard let prior = currentFrame, prior.worldCoordinateSystem == frame.worldCoordinateSystem else {
            throw PhoneClientError.transformError("relocalized frame does not use the existing world coordinate system")
        }
        currentFrame = frame
        requiresRelocalization = false
        phase = phoneFixed ? .capturingSupervision : .readyToCapture
    }

    public mutating func finish() throws -> SceneSnapshot {
        guard phase == .capturingSupervision, phoneFixed, !requiresRelocalization, let frame = currentFrame else {
            throw PhoneClientError.invalidState("capture cannot finish before fixed-phone supervision is complete")
        }
        phase = .finished
        return SceneSnapshot(
            metadata: ArtifactMetadata(artifactID: "scene-\(frame.worldCoordinateSystem)", revision: 1, provenance: [SourceIdentity(namespace: "phone-roomplan", identity: frame.worldCoordinateSystem)]),
            worldCoordinateSystem: frame.worldCoordinateSystem,
            geometry: frame.geometry,
            geometryValidityMask: frame.geometryValidityMask,
            coverageMask: frame.coverageMask,
            scanCoverage: frame.scanCoverage,
            mapErrorM: frame.mapErrorM,
            usdzDisplayReference: nil
        )
    }
}

/// Durable checkpoint for restoring the phone workflow after an app interruption.
public struct RoomScanCheckpoint: Codable, Equatable, Sendable {
    public let phase: ScanPhase
    public let currentFrame: ScanFrame?
    public let registration: RFDeviceRegistration?
    public let dimensionsConfirmed: Bool
    public let doorsConfirmed: Bool
    public let phoneFixed: Bool
    public let trackingEpoch: UInt32
    public let requiresRelocalization: Bool

    public init(phase: ScanPhase, currentFrame: ScanFrame?, registration: RFDeviceRegistration?, dimensionsConfirmed: Bool, doorsConfirmed: Bool, phoneFixed: Bool, trackingEpoch: UInt32, requiresRelocalization: Bool) {
        self.phase = phase
        self.currentFrame = currentFrame
        self.registration = registration
        self.dimensionsConfirmed = dimensionsConfirmed
        self.doorsConfirmed = doorsConfirmed
        self.phoneFixed = phoneFixed
        self.trackingEpoch = trackingEpoch
        self.requiresRelocalization = requiresRelocalization
    }
}

extension RoomScanCoordinator {
    /// Returns a bounded value suitable for local checkpoint persistence.
    public var checkpoint: RoomScanCheckpoint {
        RoomScanCheckpoint(phase: phase, currentFrame: currentFrame, registration: registration, dimensionsConfirmed: dimensionsConfirmed, doorsConfirmed: doorsConfirmed, phoneFixed: phoneFixed, trackingEpoch: trackingEpoch, requiresRelocalization: requiresRelocalization)
    }

    /// Restores an interrupted workflow and preserves the relocalization gate.
    public init(checkpoint: RoomScanCheckpoint) throws {
        guard checkpoint.trackingEpoch == checkpoint.currentFrame?.trackingEpoch || checkpoint.currentFrame == nil else {
            throw PhoneClientError.invalidState("scan checkpoint tracking epoch does not match its frame")
        }
        self.init()
        phase = checkpoint.phase
        currentFrame = checkpoint.currentFrame
        registration = checkpoint.registration
        dimensionsConfirmed = checkpoint.dimensionsConfirmed
        doorsConfirmed = checkpoint.doorsConfirmed
        phoneFixed = checkpoint.phoneFixed
        trackingEpoch = checkpoint.trackingEpoch
        requiresRelocalization = checkpoint.requiresRelocalization
    }
}

/// Incremental supervision builder that preserves sample ordering and tracking epochs.
public struct SupervisionCapture: Sendable {
    public let sceneDigest: ArtifactDigest
    public let cameraIntrinsics: [Double]
    public let sharedPositionErrorM: Double
    public let timeRelation: PhoneTimeRelation
    public let maximumPersonVelocityMPS: Double
    private var samples: [SupervisionSample] = []
    private var lastEpoch: UInt32?

    public init(sceneDigest: ArtifactDigest, cameraIntrinsics: [Double], sharedPositionErrorM: Double, timeRelation: PhoneTimeRelation, maximumPersonVelocityMPS: Double) throws {
        self.sceneDigest = sceneDigest
        self.cameraIntrinsics = cameraIntrinsics
        self.sharedPositionErrorM = sharedPositionErrorM
        self.timeRelation = timeRelation
        self.maximumPersonVelocityMPS = maximumPersonVelocityMPS
        guard cameraIntrinsics.count == 9, cameraIntrinsics.allSatisfy(\.isFinite) else {
            throw PhoneClientError.invalidInput("camera intrinsics must contain nine finite values")
        }
        try requireNonnegativeFinite(sharedPositionErrorM, field: "shared supervision error")
        try requireNonnegativeFinite(maximumPersonVelocityMPS, field: "maximum person velocity")
    }

    public var sampleCount: Int { samples.count }

    public mutating func append(_ sample: SupervisionSample) throws {
        try sample.validate(timeRelation: timeRelation, previousPoseTime: samples.last?.poseTime, previousEpoch: lastEpoch)
        samples.append(sample)
        lastEpoch = sample.trackingEpoch
    }

    public func finish(metadata: ArtifactMetadata) throws -> SupervisionSegment {
        let segment = SupervisionSegment(metadata: metadata, sceneDigest: sceneDigest, cameraIntrinsics: cameraIntrinsics, samples: samples, sharedPositionErrorM: sharedPositionErrorM, timeRelation: timeRelation, maximumPersonVelocityMPS: maximumPersonVelocityMPS)
        try segment.validate()
        return segment
    }
}

// MARK: - Apple session adapter

#if os(iOS) && canImport(ARKit)
import ARKit

/// ARWorldTracking session retained after RoomPlan capture for aligned RGB/depth/pose samples.
@available(iOS 16.0, *)
public final class ARKitSessionController: NSObject, ARSessionDelegate {
    public let session: ARSession

    public override init() {
        session = ARSession()
        super.init()
        session.delegate = self
    }

    /// Starts world tracking with scene-depth capture when the device supports it.
    public func start() {
        let configuration = ARWorldTrackingConfiguration()
        if ARWorldTrackingConfiguration.supportsFrameSemantics(.sceneDepth) {
            configuration.frameSemantics.insert(.sceneDepth)
        }
        session.run(configuration)
    }

    /// Pauses capture without discarding the retained ARSession or world-coordinate identity.
    public func pause() {
        session.pause()
    }

    public func session(_ session: ARSession, didFailWithError error: Error) {
        _ = (session, error)
    }
}
#endif

#if canImport(SwiftUI)
import SwiftUI

/// SwiftUI summary that keeps visual, RF-expected, and field-calibration coverage distinct.
@available(iOS 16.0, macOS 13.0, *)
public struct CoverageMapView: View {
    public let ranges: MapCoverageRanges

    public init(ranges: MapCoverageRanges) {
        self.ranges = ranges
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            coverageRow("Visual scan", ranges.visualScan)
            coverageRow("RF expected", ranges.rfExpectedObservable)
            coverageRow("Field calibration", ranges.fieldCalibration)
        }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private func coverageRow(_ title: String, _ cells: [CoverageCell]) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text("\(cells.filter(\.covered).count)/\(cells.count)")
                .monospacedDigit()
        }
    }
}

/// SwiftUI rows for labels that retain provenance and display unknown coverage explicitly.
@available(iOS 16.0, macOS 13.0, *)
public struct SupervisionLabelListView: View {
    public let rows: [LabelRow]

    public init(rows: [LabelRow]) {
        self.rows = rows
    }

    public var body: some View {
        List(rows.indices, id: \.self) { index in
            let row = rows[index]
            VStack(alignment: .leading) {
                Text(row.isUnknown ? "Unknown / not observed" : row.scope == .wholeRoom && row.people.isEmpty ? "Whole-room empty" : "\(row.people.count) visible")
                ForEach(row.people.indices, id: \.self) { personIndex in
                    let person = row.people[personIndex]
                    Text("\(person.station) · \(person.pose)")
                }
                let visibility = row.visibility.map { String(format: "%.2f", $0) }.joined(separator: ",")
                Text("\(row.source.namespace):\(row.source.identity) · t=\(row.phoneTime) · ±\(row.errorM, specifier: "%.3f") m · visibility=[\(visibility)]")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("tracking=\(row.trackingQuality.rawValue) · depth=\(row.depthQuality.rawValue) · scope=\(row.scope.rawValue)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
#endif

#if os(iOS) && canImport(RoomPlan)
import RoomPlan

/// RoomPlan capture adapter that deliberately keeps the AR session alive after stopping capture.
@available(iOS 16.0, *)
public final class RoomPlanCaptureController {
    public let captureSession: RoomCaptureSession

    public init() {
        captureSession = RoomCaptureSession()
    }

    public func start() {
        captureSession.run(configuration: RoomCaptureSession.Configuration())
    }

    /// Stops RoomPlan extraction while retaining AR tracking for RGB/depth/pose supervision.
    public func stopWithoutPausingARSession() {
        captureSession.stop(pauseARSession: false)
    }
}
#endif
