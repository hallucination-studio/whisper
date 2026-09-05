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

/// Measured fixed-device registration input collected from a survey/marker workflow.
///
/// The phone client does not synthesize the marker transform, uncertainty, or provenance. A
/// caller must provide all of them from a measurement source before this input can become a
/// `RFDeviceRegistration` or satisfy the export gate.
public struct MeasuredRFRegistrationInput: Codable, Equatable, Sendable {
    public let rfDeviceIdentity: String
    public let markerIdentity: String
    public let antennaReference: String
    public let markerToAntenna: CoordinateTransform
    public let errorM: Double
    public let measurementSource: SourceIdentity

    public init(
        rfDeviceIdentity: String,
        markerIdentity: String,
        antennaReference: String,
        markerToAntenna: CoordinateTransform,
        errorM: Double,
        measurementSource: SourceIdentity
    ) throws {
        guard errorM.isFinite, errorM > 0, markerToAntenna.maxErrorM.isFinite, markerToAntenna.maxErrorM > 0 else {
            throw PhoneClientError.measuredRegistrationRequired
        }
        try requireText(rfDeviceIdentity, field: "RF device identity")
        try requireText(markerIdentity, field: "marker identity")
        try requireText(antennaReference, field: "antenna reference")
        try markerToAntenna.validate()
        guard markerToAntenna.sourceCoordinateSystem == markerIdentity,
              markerToAntenna.targetCoordinateSystem == antennaReference else {
            throw PhoneClientError.transformError("measured marker-to-antenna coordinates do not match the registration")
        }
        try measurementSource.validate()
        self.rfDeviceIdentity = rfDeviceIdentity
        self.markerIdentity = markerIdentity
        self.antennaReference = antennaReference
        self.markerToAntenna = markerToAntenna
        self.errorM = errorM
        self.measurementSource = measurementSource
    }

    /// Converts measured input into the canonical registration only after validation.
    public func registration() throws -> RFDeviceRegistration {
        let registration = RFDeviceRegistration(
            rfDeviceIdentity: rfDeviceIdentity,
            markerIdentity: markerIdentity,
            antennaReference: antennaReference,
            markerToAntenna: markerToAntenna,
            errorM: errorM,
            source: measurementSource
        )
        try registration.validate()
        return registration
    }
}

/// Export readiness derived from measured registration and authenticated Host time.
public struct PhoneExportReadiness: Equatable, Sendable {
    public let hasMeasuredRegistration: Bool
    public let hasVerifiedCompanionRelation: Bool

    public init(
        measuredRegistration: MeasuredRFRegistrationInput?,
        verifiedCompanionRelation: VerifiedCompanionTimeRelation?
    ) {
        hasMeasuredRegistration = measuredRegistration != nil
        hasVerifiedCompanionRelation = verifiedCompanionRelation != nil
    }

    public var canExport: Bool {
        hasMeasuredRegistration && hasVerifiedCompanionRelation
    }

    /// Fails closed until both physical and authenticated timing prerequisites exist.
    public func requireReady() throws {
        guard hasMeasuredRegistration else { throw PhoneClientError.measuredRegistrationRequired }
        guard hasVerifiedCompanionRelation else { throw PhoneClientError.companionRelationRequired }
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

/// A normalized floor-plan point used by the coverage renderer and behavior tests.
/// `x` is the world X coordinate and `y` is the world Z coordinate; the world Y
/// height is intentionally ignored because coverage is shown in a top-down map.
public struct CoverageMapPoint: Codable, Equatable, Sendable {
    public let x: Double
    public let y: Double
    public let covered: Bool

    public init(x: Double, y: Double, covered: Bool) {
        self.x = x
        self.y = y
        self.covered = covered
    }
}

/// Coverage summary with spatial positions retained for each independently
/// qualified visual, RF-expected, and field-calibration range.
public struct CoverageMapSummary: Codable, Equatable, Sendable {
    public let title: String
    public let points: [CoverageMapPoint]
    public let coveredCount: Int
    public let totalCount: Int

    public init(title: String, cells: [CoverageCell]) {
        let validCells = cells.filter { cell in
            cell.positionM.count == 3 && cell.positionM.allSatisfy(\.isFinite)
        }
        self.title = title
        self.totalCount = validCells.count
        self.coveredCount = validCells.filter(\.covered).count
        guard !validCells.isEmpty else {
            self.points = []
            return
        }
        let xValues = validCells.map { $0.positionM[0] }
        let zValues = validCells.map { $0.positionM[2] }
        let minX = xValues.min() ?? 0
        let maxX = xValues.max() ?? minX
        let minZ = zValues.min() ?? 0
        let maxZ = zValues.max() ?? minZ
        let spanX = maxX - minX
        let spanZ = maxZ - minZ
        self.points = validCells.map { cell in
            CoverageMapPoint(
                x: spanX > 0 ? (cell.positionM[0] - minX) / spanX : 0.5,
                y: spanZ > 0 ? (cell.positionM[2] - minZ) / spanZ : 0.5,
                covered: cell.covered
            )
        }
    }

    /// Alias retained for the SwiftUI renderer's point-oriented vocabulary.
    public var normalizedPoints: [CoverageMapPoint] { points }
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
        guard phase == .scanning || phase == .awaitingDimensionConfirmation || phase == .awaitingDoorConfirmation || phase == .registeringRF || phase == .readyToCapture || phase == .capturingSupervision else {
            throw PhoneClientError.invalidState("RoomPlan frames are not accepted in the current workflow phase")
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
        guard frame.trackingQuality == .normal else {
            throw PhoneClientError.trackingResetRequiresRelocalization
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

/// One adapter-produced observation sharing the RoomPlan/ARKit world coordinate system.
public struct PhoneCaptureObservation: Codable, Equatable, Sendable {
    public let scanFrame: ScanFrame
    public let keyframe: CameraKeyframe
    public let cameraIntrinsics: [Double]
    public let media: [CaptureMedia]

    public init(scanFrame: ScanFrame, keyframe: CameraKeyframe, cameraIntrinsics: [Double], media: [CaptureMedia]) throws {
        guard cameraIntrinsics.count == 9,
              cameraIntrinsics.allSatisfy(\.isFinite),
              media.contains(where: { $0.kind == .rgb }),
              Set(media.map(\.reference)).count == media.count else {
            throw PhoneClientError.invalidInput("a capture observation requires unique camera intrinsics and RGB media")
        }
        try scanFrame.validate()
        try keyframe.validate(worldCoordinateSystem: scanFrame.worldCoordinateSystem)
        guard keyframe.trackingEpoch == scanFrame.trackingEpoch else {
            throw PhoneClientError.invalidInput("camera keyframe and scan frame tracking epochs differ")
        }
        self.scanFrame = scanFrame
        self.keyframe = keyframe
        self.cameraIntrinsics = cameraIntrinsics
        self.media = media
    }
}

/// Human-entered supervision intent converted by the adapter into a canonical sample.
public struct SupervisionLabelInput: Codable, Equatable, Sendable {
    public let scope: LabelScope
    public let visibility: [Double]
    public let label: JointLabel
    public let jointErrorM: Double

    public init(scope: LabelScope, visibility: [Double], label: JointLabel, jointErrorM: Double) throws {
        self.scope = scope
        self.visibility = visibility
        self.label = label
        self.jointErrorM = jointErrorM
        for value in visibility { try requireUnitInterval(value, field: "person visibility") }
        try requireNonnegativeFinite(jointErrorM, field: "joint sample error")
    }

    public static func unknown(jointErrorM: Double = 0) throws -> SupervisionLabelInput {
        try SupervisionLabelInput(scope: .locallyVisible, visibility: [], label: .unknown, jointErrorM: jointErrorM)
    }
}

// MARK: - Apple session adapter

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
            coverageRow("Visual scan", ranges.visualScan, color: .blue)
            coverageRow("RF expected", ranges.rfExpectedObservable, color: .orange)
            coverageRow("Field calibration", ranges.fieldCalibration, color: .green)
        }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private func coverageRow(_ title: String, _ cells: [CoverageCell], color: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(title)
                Spacer()
                Text("\(cells.filter(\.covered).count)/\(cells.count)")
                    .monospacedDigit()
            }
            GeometryReader { geometry in
                let points = CoverageMapSummary(title: title, cells: cells).normalizedPoints
                Canvas { context, size in
                    for point in points {
                        let x = point.x * max(size.width - 12, 1) + 6
                        let y = (1 - point.y) * max(size.height - 12, 1) + 6
                        let radius: CGFloat = 5
                        let rect = CGRect(x: x - radius, y: y - radius, width: radius * 2, height: radius * 2)
                        context.fill(Path(ellipseIn: rect), with: .color(point.covered ? color : color.opacity(0.2)))
                    }
                }
                .frame(width: geometry.size.width, height: geometry.size.height)
                .accessibilityLabel("\(title) spatial coverage")
            }
            .frame(height: 64)
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

#if os(iOS) && canImport(ARKit) && canImport(RoomPlan)
import ARKit
import RoomPlan
import CoreVideo
import simd

/// RoomPlan/ARKit adapter that owns one shared session and turns delegate frames into artifacts.
@available(iOS 17.0, *)
@MainActor
public final class RoomPlanCaptureController: NSObject, RoomCaptureSessionDelegate, ARSessionDelegate {
    /// The one AR session supplied to RoomPlan and retained for RGB/depth/pose capture.
    public let session: ARSession
    /// RoomPlan uses `session`; no second ARSession is created for supervision.
    public let captureSession: RoomCaptureSession
    public private(set) var coordinator = RoomScanCoordinator()
    public private(set) var latestSceneFrame: ScanFrame?
    public private(set) var latestScene: SceneSnapshot?
    public private(set) var latestObservation: PhoneCaptureObservation?
    public private(set) var observations: [PhoneCaptureObservation] = []
    public private(set) var usdzData: Data?
    public private(set) var measuredRegistration: MeasuredRFRegistrationInput?
    public private(set) var verifiedCompanionRelation: VerifiedCompanionTimeRelation?
    public var onObservation: ((PhoneCaptureObservation) -> Void)?
    public var onError: ((Error) -> Void)?
    private var latestRoom: CapturedRoom?
    private var trackingEpoch: UInt32 = 1
    private var wasTrackingNormally = false
    private let worldCoordinateSystem = "roomplan-arkit-world"

    public override init() {
        let session = ARSession()
        self.session = session
        captureSession = RoomCaptureSession(arSession: session)
        super.init()
        captureSession.delegate = self
        session.delegate = self
    }

    /// Starts the complete scan workflow and retains the same AR session afterward.
    public func start() throws {
        try coordinator.startScan()
        captureSession.run(configuration: RoomCaptureSession.Configuration())
    }

    /// Requests RoomPlan to process the current scan while keeping AR tracking alive.
    public func stopWithoutPausingARSession() {
        captureSession.stop(pauseARSession: false)
    }

    /// Pauses supervision while retaining the shared session and checkpoint.
    public func pause() throws {
        try coordinator.pause()
        session.pause()
    }

    /// Resumes RoomPlan and AR sampling after a user-confirmed pause.
    public func resume() throws {
        try coordinator.resume()
        captureSession.run(configuration: RoomCaptureSession.Configuration())
    }

    public func requestDimensionConfirmation() throws { try coordinator.requestConfirmation() }
    public func confirmDimensions() throws { try coordinator.confirmDimensions() }
    public func confirmDoors() throws { try coordinator.confirmDoors() }
    /// Registers only a caller-supplied measured marker survey; no transform or error is guessed.
    public func registerMeasuredRF(_ input: MeasuredRFRegistrationInput) throws {
        try coordinator.registerRF(input.registration())
        measuredRegistration = input
    }

    /// Installs the clock relation only after the companion handshake has verified the Host.
    public func attachCompanionConnection(_ connection: CompanionConnection) {
        verifiedCompanionRelation = connection.verifiedTimeRelation
    }

    public var exportReadiness: PhoneExportReadiness {
        PhoneExportReadiness(measuredRegistration: measuredRegistration, verifiedCompanionRelation: verifiedCompanionRelation)
    }

    public func confirmPhoneFixed() throws { try coordinator.confirmPhoneFixed() }

    /// Completes a tracking reset only after ARKit reports a normal camera state.
    public func relocalize() throws {
        guard let frame = latestSceneFrame else { throw PhoneClientError.invalidState("no relocalized AR frame is available") }
        guard frame.trackingQuality == .normal else { throw PhoneClientError.trackingResetRequiresRelocalization }
        try coordinator.relocalized(frame: frame)
    }

    /// Converts one captured observation into a canonical supervision sample.
    public func makeSupervisionSample(input: SupervisionLabelInput, verifiedTimeRelation: VerifiedCompanionTimeRelation) throws -> SupervisionSample {
        guard let observation = latestObservation else { throw PhoneClientError.invalidState("no RGB/depth/pose observation is available") }
        let timestamp = observation.keyframe.phoneTime
        guard verifiedTimeRelation.relation.error(at: timestamp) != nil else {
            throw PhoneClientError.companionRelationRequired
        }
        guard let rgb = observation.media.first(where: { $0.kind == .rgb }) else {
            throw PhoneClientError.invalidArtifact("capture observation has no RGB media")
        }
        let depthReference = observation.media.first(where: { $0.kind == .depth })?.reference
        let depthTime = observation.media.first(where: { $0.kind == .depth })?.phoneTime ?? timestamp
        return SupervisionSample(
            rgbReference: rgb.reference,
            depthReference: depthReference,
            poseReference: observation.keyframe.reference,
            rgbTime: timestamp,
            depthTime: depthTime,
            poseTime: timestamp,
            maximumTimeError: verifiedTimeRelation.relation.error(at: timestamp) ?? 0,
            trackingEpoch: observation.keyframe.trackingEpoch,
            relocalized: observation.keyframe.trackingQuality == .normal,
            trackingQuality: observation.keyframe.trackingQuality,
            depthQuality: depthReference == nil ? .missing : .measured,
            scope: input.scope,
            personVisibility: input.visibility,
            label: input.label,
            cameraToWorld: observation.keyframe.pose,
            sampleSource: SourceIdentity(namespace: "phone-arkit", identity: observation.keyframe.reference),
            jointErrorM: input.jointErrorM
        )
    }

    // MARK: RoomCaptureSessionDelegate

    public func captureSession(_ session: RoomCaptureSession, didUpdate room: CapturedRoom) {
        guard session === captureSession else { return }
        latestRoom = room
        if let frame = session.arSession.currentFrame {
            emitObservation(room: room, frame: frame)
        }
    }

    public func captureSession(_ session: RoomCaptureSession, didEndWith data: CapturedRoomData, error: Error?) {
        guard session === captureSession else { return }
        if let error {
            onError?(error)
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let room = try await RoomBuilder(options: []).capturedRoom(from: data)
                self.latestRoom = room
                self.latestScene = try self.makeScene(room: room)
                self.usdzData = try self.exportUSDZ(room)
                if let frame = self.session.currentFrame {
                    self.emitObservation(room: room, frame: frame)
                }
            } catch {
                self.onError?(error)
            }
        }
    }

    // MARK: ARSessionDelegate

    public func session(_ session: ARSession, didUpdate frame: ARFrame) {
        guard session === self.session, let room = latestRoom else { return }
        emitObservation(room: room, frame: frame)
    }

    public func session(_ session: ARSession, cameraDidChangeTrackingState camera: ARCamera) {
        guard session === self.session else { return }
        let normal: Bool
        switch camera.trackingState {
        case .normal: normal = true
        case .limited, .notAvailable: normal = false
        }
        if wasTrackingNormally && !normal {
            trackingEpoch &+= 1
            try? coordinator.trackingDidReset(to: trackingEpoch)
        }
        wasTrackingNormally = normal
    }

    public func session(_ session: ARSession, didFailWithError error: Error) {
        guard session === self.session else { return }
        onError?(error)
    }

    private func emitObservation(room: CapturedRoom, frame: ARFrame) {
        let trackingQuality: TrackingQuality
        switch frame.camera.trackingState {
        case .normal: trackingQuality = .normal
        case .limited, .notAvailable: trackingQuality = .limited
        }
        guard let rgb = try? CaptureMedia(reference: "rgb-\(frameNanoseconds(frame))", kind: .rgb, phoneTime: frameNanoseconds(frame), bytes: copyPixelBuffer(frame.capturedImage)) else { return }
        let depth: CaptureMedia?
        if let depthMap = frame.sceneDepth?.depthMap {
            depth = try? CaptureMedia(reference: "depth-\(frameNanoseconds(frame))", kind: .depth, phoneTime: frameNanoseconds(frame), bytes: copyPixelBuffer(depthMap))
        } else {
            depth = nil
        }
        guard let scanFrame = try? makeScanFrame(room: room, frame: frame, trackingQuality: trackingQuality),
              let pose = try? transform(frame.camera.transform, source: "camera", target: worldCoordinateSystem, error: trackingQuality == .normal ? 0.1 : 0.75) else { return }
        let timestamp = frameNanoseconds(frame)
        let keyframe = CameraKeyframe(reference: "pose-\(timestamp)", phoneTime: timestamp, pose: pose, trackingEpoch: trackingEpoch, trackingQuality: trackingQuality, depthQuality: depth == nil ? .missing : .measured)
        let media = [rgb] + (depth.map { [$0] } ?? [])
        guard let observation = try? PhoneCaptureObservation(scanFrame: scanFrame, keyframe: keyframe, cameraIntrinsics: intrinsicValues(frame.camera.intrinsics), media: media) else { return }
        guard coordinatorAccepts(scanFrame) else {
            // Keep the newest frame available for the explicit relocalize action;
            // it is not emitted as a supervision observation until that gate succeeds.
            if coordinator.requiresRelocalization {
                latestSceneFrame = scanFrame
                latestObservation = observation
            }
            return
        }
        latestSceneFrame = scanFrame
        latestObservation = observation
        observations.append(observation)
        if observations.count > 100_000 { observations.removeFirst(observations.count - 100_000) }
        onObservation?(observation)
    }

    private func coordinatorAccepts(_ frame: ScanFrame) -> Bool {
        do {
            try coordinator.accept(frame: frame)
            return true
        } catch {
            if case .trackingResetRequiresRelocalization = error as? PhoneClientError {
                return false
            }
            onError?(error)
            return false
        }
    }

    private func makeScanFrame(room: CapturedRoom, frame: ARFrame, trackingQuality: TrackingQuality) throws -> ScanFrame {
        let elements = roomGeometry(room)
        guard !elements.isEmpty else { throw PhoneClientError.invalidArtifact("RoomPlan did not produce structured geometry") }
        let pose = try transform(frame.camera.transform, source: "camera", target: worldCoordinateSystem, error: trackingQuality == .normal ? 0.1 : 0.75)
        let cells = elements.map { CoverageCell(positionM: $0.0.verticesM[0], covered: true) }
        let validity = elements.map { $0.1 }
        let geometry = elements.map { $0.0 }
        return ScanFrame(worldCoordinateSystem: worldCoordinateSystem, geometry: geometry, geometryValidityMask: validity, coverageMask: cells, scanCoverage: Double(cells.filter(\.covered).count) / Double(cells.count), mapErrorM: trackingQuality == .normal ? 0.1 : 0.75, cameraToWorld: pose, trackingEpoch: trackingEpoch, trackingQuality: trackingQuality, depthQuality: frame.sceneDepth == nil ? .missing : .measured)
    }

    private func makeScene(room: CapturedRoom) throws -> SceneSnapshot {
        let elements = roomGeometry(room)
        guard !elements.isEmpty else { throw PhoneClientError.invalidArtifact("RoomPlan did not produce structured geometry") }
        let geometry = elements.map { $0.0 }
        let cells = geometry.map { CoverageCell(positionM: $0.verticesM[0], covered: true) }
        let scene = SceneSnapshot(metadata: ArtifactMetadata(artifactID: "room-\(room.identifier.uuidString)", revision: 1, provenance: [SourceIdentity(namespace: "roomplan", identity: room.identifier.uuidString)]), worldCoordinateSystem: worldCoordinateSystem, geometry: geometry, geometryValidityMask: elements.map { $0.1 }, coverageMask: cells, scanCoverage: 1, mapErrorM: 0.1, usdzDisplayReference: "Room.usdz")
        try scene.validate()
        return scene
    }

    private func exportUSDZ(_ room: CapturedRoom) throws -> Data {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Room.usdz")
        defer { try? FileManager.default.removeItem(at: url) }
        try room.export(to: url, exportOptions: .mesh)
        return try Data(contentsOf: url)
    }
}

private func frameNanoseconds(_ frame: ARFrame) -> UInt64 {
    UInt64(max(0, frame.timestamp * 1_000_000_000))
}

private func intrinsicValues(_ matrix: simd_float3x3) -> [Double] {
    (0..<3).flatMap { row in (0..<3).map { column in Double(matrix[column][row]) } }
}

private func transform(_ matrix: simd_float4x4, source: String, target: String, error: Double) throws -> CoordinateTransform {
    let values = (0..<4).flatMap { row in (0..<4).map { column in Double(matrix[column][row]) } }
    let transform = CoordinateTransform(sourceCoordinateSystem: source, targetCoordinateSystem: target, matrix: values, maxErrorM: error)
    try transform.validate()
    return transform
}

private func copyPixelBuffer(_ buffer: CVPixelBuffer) -> Data {
    CVPixelBufferLockBaseAddress(buffer, .readOnly)
    defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
    var output = Data()
    let planeCount = CVPixelBufferGetPlaneCount(buffer)
    if planeCount == 0 {
        if let address = CVPixelBufferGetBaseAddress(buffer) {
            output.append(Data(bytes: address, count: CVPixelBufferGetBytesPerRow(buffer) * CVPixelBufferGetHeight(buffer)))
        }
    } else {
        for plane in 0..<planeCount {
            if let address = CVPixelBufferGetBaseAddressOfPlane(buffer, plane) {
                output.append(Data(bytes: address, count: CVPixelBufferGetBytesPerRowOfPlane(buffer, plane) * CVPixelBufferGetHeightOfPlane(buffer, plane)))
            }
        }
    }
    return output
}

private func roomGeometry(_ room: CapturedRoom) -> [(GeometryElement, Bool)] {
    var result = [(GeometryElement, Bool)]()
    let surfaces = room.floors + room.walls + room.doors + room.openings + room.windows
    for surface in surfaces {
        let kind: GeometryKind
        switch surface.category {
        case .door: kind = .door
        default: kind = .wall
        }
        result.append((GeometryElement(kind: kind, verticesM: boxVertices(transform: surface.transform, dimensions: surface.dimensions)), surface.confidence != .low))
    }
    for object in room.objects {
        result.append((GeometryElement(kind: .furniture, verticesM: boxVertices(transform: object.transform, dimensions: object.dimensions)), object.confidence != .low))
    }
    return result
}

private func boxVertices(transform: simd_float4x4, dimensions: simd_float3) -> [[Double]] {
    let half = dimensions * 0.5
    let corners: [simd_float3] = [
        [-half.x, -half.y, -half.z], [half.x, -half.y, -half.z], [half.x, half.y, -half.z], [-half.x, half.y, -half.z],
        [-half.x, -half.y, half.z], [half.x, -half.y, half.z], [half.x, half.y, half.z], [-half.x, half.y, half.z],
    ]
    return corners.map { corner in
        let point = transform * SIMD4<Float>(corner.x, corner.y, corner.z, 1)
        return [Double(point.x), Double(point.y), Double(point.z)]
    }
}
#endif
