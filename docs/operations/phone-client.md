# Phone client capture and export

The `PhoneClient` Swift package is the phone-side candidate-artifact boundary. It supports
LiDAR-capable iPhone/iPad builds with RoomPlan and an `ARWorldTrackingConfiguration`; the AR
session remains available after RoomPlan extraction so RGB, depth, and camera pose samples stay in
one scene coordinate system.

The workflow requires room dimensions and door confirmation, visible-marker RF registration,
fixed-phone confirmation, and explicit relocalization after every tracking epoch reset. A partial
camera view produces an unknown or visible-set label, never a whole-room empty label. The map and
SwiftUI summaries keep visual scan coverage, RF-expected coverage, and field-calibration coverage
separate.

`SealedArtifact` emits the Host `WSA1` canonical scene, calibration, and supervision bytes. A
`PhoneCapturePackage` is a deterministic `WSP1` local recovery archive containing those three
artifacts plus optional USDZ display bytes and bounded camera keyframe references. Companion upload
uses the existing Host `WSO1`/`WSH1`/`WSR1`/`WSQ1`/`WSK1`/`WSC1` contract; only missing chunks are
sent again after an interruption. The companion channel imports candidate artifacts and has no
world-state query or model-activation authority.

Build and run the package tests with:

```sh
swift test --package-path PhoneClient
```

The package tests are part of `make check`. Physical LiDAR capture, RF accuracy, and phone-away
qualification remain separate hardware acceptance work.
