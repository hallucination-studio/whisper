#if os(iOS) && canImport(SwiftUI) && canImport(RoomPlan) && canImport(RealityKit)
import SwiftUI
import UIKit
import RealityKit
import RoomPlan
import WhisperPhoneClient

@main
struct WhisperPhoneClientApp: App {
    var body: some Scene {
        WindowGroup {
            PhoneCaptureRootView()
        }
    }
}

@available(iOS 16.0, *)
struct PhoneCaptureRootView: View {
    @StateObject private var model = PhoneCaptureViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("RoomPlan phone client")
                        .font(.title2.bold())
                    Text("The camera, depth map, poses, and RoomPlan scene share one ARSession world.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    RoomPlanCameraView(session: model.controller.session)
                        .frame(height: 260)
                        .clipShape(RoundedRectangle(cornerRadius: 12))

                    GroupBox("Workflow") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Phase: \(model.phase.rawValue)")
                                .monospaced()
                            workflowControls
                        }
                    }

                    GroupBox("Fixed RF registration") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Measured registration only")
                                .font(.headline)
                            TextField("RF device identity", text: $model.rfDeviceIdentity)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            TextField("Visible marker identity", text: $model.markerIdentity)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            TextField("Antenna reference", text: $model.antennaReference)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            TextField("Measurement source namespace", text: $model.measurementSourceNamespace)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            TextField("Measurement source identity", text: $model.measurementSourceIdentity)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            TextField("Measured marker-to-antenna matrix (16 values)", text: $model.markerToAntennaMatrix)
                                .autocorrectionDisabled()
                            TextField("Measured registration error in metres", text: $model.markerToAntennaErrorM)
                                .keyboardType(.decimalPad)
                            Button("Register measured fixed RF device") { model.registerRF() }
                                .buttonStyle(.borderedProminent)
                            Text(model.exportReadiness.hasMeasuredRegistration ? "Measured registration accepted" : "Export requires measured marker geometry and uncertainty")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    GroupBox("Spatial coverage") {
                        CoverageMapView(ranges: model.coverageRanges)
                    }

                    GroupBox("Supervision") {
                        VStack(alignment: .leading, spacing: 8) {
                            Button("Capture unknown / not observed") { model.captureUnknownLabel() }
                                .buttonStyle(.bordered)
                            Text("Unknown labels preserve partial visibility; they never assert an empty room.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            SupervisionLabelListView(rows: model.labelRows)
                                .frame(minHeight: model.labelRows.isEmpty ? 0 : 120)
                        }
                    }

                    GroupBox("Candidate export") {
                        Text(model.exportReadiness.canExport
                             ? "Export is enabled after measured RF registration and authenticated Host time."
                             : "Export disabled until measured RF registration and an authenticated Host time relation are present.")
                            .font(.callout)
                            .foregroundStyle(model.exportReadiness.canExport ? .green : .secondary)
                    }

                    if let error = model.errorMessage {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.callout)
                    }
                }
                .padding()
            }
            .navigationTitle("Phone capture")
        }
    }

    @ViewBuilder
    private var workflowControls: some View {
        HStack {
            if model.phase == .idle {
                Button("Start scan") { model.startScan() }
                    .buttonStyle(.borderedProminent)
            }
            if model.phase == .scanning {
                Button("Stop scan") { model.stopScan() }
                Button("Prepare confirmation") { model.prepareConfirmation() }
            }
            if model.phase == .awaitingDimensionConfirmation {
                Button("Confirm dimensions") { model.confirmDimensions() }
            }
            if model.phase == .awaitingDoorConfirmation {
                Button("Confirm doors") { model.confirmDoors() }
            }
            if model.phase == .registeringRF {
                Text("Register the visible fixed marker below")
                    .font(.caption)
            }
            if model.phase == .readyToCapture {
                Button("Confirm phone fixed") { model.confirmPhoneFixed() }
            }
            if model.phase == .capturingSupervision {
                Button("Pause") { model.pause() }
            }
            if model.phase == .paused {
                Button("Resume") { model.resume() }
            }
            if model.phase == .awaitingRelocalization {
                Button("Relocalize") { model.relocalize() }
            }
        }
        .buttonStyle(.bordered)
    }
}

/// Displays the same ARSession that RoomCaptureSession owns, keeping the camera
/// preview and RoomPlan's coordinate frame connected.
@available(iOS 16.0, *)
private struct RoomPlanCameraView: UIViewRepresentable {
    let session: ARSession

    func makeUIView(context: Context) -> ARView {
        let view = ARView(frame: .zero)
        view.automaticallyConfigureSession = false
        view.session = session
        return view
    }

    func updateUIView(_ view: ARView, context: Context) {
        if view.session !== session {
            view.session = session
        }
    }
}

@available(iOS 16.0, *)
@MainActor
final class PhoneCaptureViewModel: ObservableObject {
    @Published var phase: ScanPhase = .idle
    @Published var labelRows: [LabelRow] = []
    @Published var errorMessage: String?
    @Published var rfDeviceIdentity = ""
    @Published var markerIdentity = ""
    @Published var antennaReference = ""
    @Published var measurementSourceNamespace = ""
    @Published var measurementSourceIdentity = ""
    @Published var markerToAntennaMatrix = ""
    @Published var markerToAntennaErrorM = ""

    let controller: RoomPlanCaptureController

    init() {
        let controller = RoomPlanCaptureController()
        self.controller = controller
        controller.onObservation = { [weak self] _ in
            self?.phase = controller.coordinator.phase
        }
        controller.onError = { [weak self] error in
            self?.errorMessage = error.localizedDescription
            self?.phase = controller.coordinator.phase
        }
    }

    var coverageRanges: MapCoverageRanges {
        let visual = controller.latestSceneFrame?.coverageMask ?? []
        let unobserved = visual.map { CoverageCell(positionM: $0.positionM, covered: false) }
        return MapCoverageRanges(visualScan: visual, rfExpectedObservable: unobserved, fieldCalibration: unobserved)
    }

    var exportReadiness: PhoneExportReadiness {
        controller.exportReadiness
    }

    func startScan() {
        perform { try controller.start() }
    }

    func stopScan() {
        controller.stopWithoutPausingARSession()
        phase = controller.coordinator.phase
    }

    func prepareConfirmation() {
        perform { try controller.requestDimensionConfirmation() }
    }

    func confirmDimensions() {
        perform { try controller.confirmDimensions() }
    }

    func confirmDoors() {
        perform { try controller.confirmDoors() }
    }

    func registerRF() {
        perform {
            guard let errorM = Double(markerToAntennaErrorM), errorM > 0 else {
                throw PhoneClientError.measuredRegistrationRequired
            }
            let matrix = markerToAntennaMatrix
                .split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" || $0 == "\t" })
                .compactMap { Double($0) }
            guard matrix.count == 16, matrix.allSatisfy(\.isFinite) else {
                throw PhoneClientError.measuredRegistrationRequired
            }
            let input = try MeasuredRFRegistrationInput(
                rfDeviceIdentity: rfDeviceIdentity,
                markerIdentity: markerIdentity,
                antennaReference: antennaReference,
                markerToAntenna: CoordinateTransform(
                    sourceCoordinateSystem: markerIdentity,
                    targetCoordinateSystem: antennaReference,
                    matrix: matrix,
                    maxErrorM: errorM
                ),
                errorM: errorM,
                measurementSource: SourceIdentity(namespace: measurementSourceNamespace, identity: measurementSourceIdentity)
            )
            try controller.registerMeasuredRF(input)
        }
    }

    func confirmPhoneFixed() {
        perform { try controller.confirmPhoneFixed() }
    }

    func pause() {
        perform { try controller.pause() }
    }

    func resume() {
        perform { try controller.resume() }
    }

    func relocalize() {
        perform { try controller.relocalize() }
    }

    /// Called by the companion transport after it completes the authenticated Host handshake.
    func attachCompanionConnection(_ connection: CompanionConnection) {
        controller.attachCompanionConnection(connection)
        phase = controller.coordinator.phase
    }

    func captureUnknownLabel() {
        perform {
            guard let observation = controller.latestObservation else {
                throw PhoneClientError.invalidState("scan one RGB/depth/pose observation before labeling")
            }
            guard let relation = controller.verifiedCompanionRelation else {
                throw PhoneClientError.companionRelationRequired
            }
            _ = observation
            let sample = try controller.makeSupervisionSample(input: try .unknown(), verifiedTimeRelation: relation)
            labelRows.append(LabelRow(sample: sample))
        }
    }

    private func perform(_ action: () throws -> Void) {
        do {
            errorMessage = nil
            try action()
            phase = controller.coordinator.phase
        } catch {
            errorMessage = error.localizedDescription
            phase = controller.coordinator.phase
        }
    }
}
#else
import Foundation

/// Package fallback entry point for macOS/CI hosts without the iOS frameworks.
@main
struct WhisperPhoneClientApp {
    static func main() {}
}
#endif
