#if os(iOS) && canImport(ARKit) && canImport(RoomPlan)
import ARKit
import RoomPlan
import XCTest
@testable import WhisperPhoneClient

@available(iOS 17.0, *)
@MainActor
final class RoomPlanAdapterTests: XCTestCase {
    func testRoomPlanAndARKitRetainOneSharedSession() {
        let controller = RoomPlanCaptureController()

        XCTAssertTrue(controller.session === controller.captureSession.arSession)
        XCTAssertTrue(controller.captureSession.arSession === controller.session)
        XCTAssertTrue(controller.session.delegate === controller)
        XCTAssertTrue(controller.captureSession.delegate === controller)
    }
}
#endif
