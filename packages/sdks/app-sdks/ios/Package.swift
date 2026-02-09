// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "Vault",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "Vault",
            targets: ["Vault"]
        ),
    ],
    dependencies: [
        // No external dependencies - keeping it lightweight
    ],
    targets: [
        .target(
            name: "Vault",
            dependencies: [],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "VaultTests",
            dependencies: ["Vault"]
        ),
    ]
)
