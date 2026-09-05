# Phone client capture and export

The `PhoneClient` Swift package is the phone-side candidate-artifact boundary and includes the
runnable `WhisperPhoneClientApp` iOS target. It supports LiDAR-capable iPhone/iPad builds with
RoomPlan and one shared `ARSession`: `RoomCaptureSession(arSession:)` owns the same session used
for RGB, depth, and camera-pose delegates, so every retained observation remains in the RoomPlan
world coordinate system.

The workflow requires room dimensions and door confirmation, caller-supplied measured marker RF
registration, fixed-phone confirmation, and explicit relocalization after every tracking epoch
reset. Export remains disabled until that measured registration and an authenticated Host clock
relation are both present. The calibration must also be bound to that exact measured registration;
the binding covers the registration transform, uncertainty, provenance, and every calibration field
carried by WSA1. The app never synthesizes a transform, uncertainty, or time relation. A
partial camera view produces an unknown or visible-set label, never a whole-room empty label. The
map and SwiftUI summaries keep visual scan coverage, RF-expected coverage, and field-calibration
coverage separate.

`WhisperPhoneClientApp` supplies the connected scan preview and controls for stop/confirmation,
fixed-device registration, fixed-phone confirmation, supervision pause/resume, and relocalization.
The preview is backed by `RoomPlanCaptureController.session`, the exact session passed to
`RoomCaptureSession`, rather than a second camera session.

`SealedArtifact` emits the Host `WSA1` canonical scene, calibration, and supervision bytes. A
`PhoneCapturePackage` is a deterministic version-2 `WSP1` local recovery archive containing those
three artifacts, required RoomPlan USDZ bytes, every referenced camera keyframe, and bounded RGB /
depth media. Package construction rejects duplicate, missing, or unreferenced media and poses.
Companion upload uses the existing Host `WSO1`/`WSH1`/`WSR1`/`WSQ1`/`WSK1`/`WSC1` encrypted chunk
contract plus the authenticated `WSU1` cumulative-progress/receipt response. A sent chunk is not
acknowledged until a valid response is parsed; the file cache persists Host progress and retries
only missing chunks after restart. The companion channel imports candidate artifacts and has no
world-state query or model-activation authority.

The `WSU1` reply body is deterministic and cumulative: magic, status, reason, origin, session ID,
upload ID, chunk count, canonical plaintext chunk size, total bytes, full digest, received-index
count and indexes, artifact digest, revision, and artifact-ID length/value. `pending` replies carry
only progress; `committed` replies require every index plus the Host artifact receipt (`origin=1`);
`rejected` replies carry a bounded `CompanionRejectReason` and no receipt fields. The phone binds
every reply to its retained session, upload ID, layout, and digest before changing its checkpoint.

Build and run the package tests with:

```sh
swift test --package-path PhoneClient
```

On a Command Line Tools-only host, the checked-in source gate remains available:

```sh
make check-phone-source
```

The package tests are part of `make check` when Swift Package Manager is available. The required
iOS-only adapter and UI paths are verified by the fixed-destination Xcode gate:

```sh
make check-phone-xcode
```

That command requires full Xcode and an iOS simulator named `iPhone 16` on iOS `18.5`; it is run
in `.github/workflows/phone-client-ios.yml`. On a Command Line Tools-only host, `swift test` and
source type-checking do not compile the `#if os(iOS)` adapter, so the Xcode gate is explicitly
CI-only evidence until full Xcode is installed. Physical LiDAR capture, RF accuracy, and phone-away
qualification remain separate hardware acceptance work.
