// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "VaultAuth",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "VaultAuth",
            targets: ["VaultAuth"]
        ),
    ],
    dependencies: [
        // No external dependencies for core functionality
    ],
    targets: [
        .target(
            name: "VaultAuth",
            dependencies: [],
            path: "Sources/VaultAuth"
        ),
        .testTarget(
            name: "VaultAuthTests",
            dependencies: ["VaultAuth"],
            path: "Tests/VaultAuthTests"
        ),
    ],
    swiftLanguageVersions: [.v5]
)
