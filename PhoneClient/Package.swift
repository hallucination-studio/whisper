// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "WhisperPhoneClient",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "WhisperPhoneClient",
            targets: ["WhisperPhoneClient"]
        ),
    ],
    targets: [
        .target(
            name: "WhisperPhoneClient",
            path: "Sources/WhisperPhoneClient"
        ),
        .testTarget(
            name: "WhisperPhoneClientTests",
            dependencies: ["WhisperPhoneClient"],
            path: "Tests/WhisperPhoneClientTests"
        ),
    ]
)
