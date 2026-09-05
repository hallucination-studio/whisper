// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "WhisperPhoneClient",
    platforms: [
        .iOS(.v17),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "WhisperPhoneClient",
            targets: ["WhisperPhoneClient"]
        ),
        .executable(
            name: "WhisperPhoneClientApp",
            targets: ["WhisperPhoneClientApp"]
        ),
    ],
    targets: [
        .target(
            name: "WhisperPhoneClient",
            path: "Sources/WhisperPhoneClient"
        ),
        .executableTarget(
            name: "WhisperPhoneClientApp",
            dependencies: ["WhisperPhoneClient"],
            path: "Sources/WhisperPhoneClientApp"
        ),
        .testTarget(
            name: "WhisperPhoneClientTests",
            dependencies: ["WhisperPhoneClient"],
            path: "Tests/WhisperPhoneClientTests",
            resources: [.copy("Fixtures")]
        ),
    ]
)
