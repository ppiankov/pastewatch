// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "Pastewatch",
    platforms: [
        .macOS(.v14)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", "1.3.0"..<"1.5.0")
    ],
    targets: [
        .target(
            name: "PastewatchCore",
            path: "Sources/PastewatchCore"
        ),
        .executableTarget(
            name: "Pastewatch",
            dependencies: ["PastewatchCore"],
            path: "Sources/Pastewatch",
            resources: [
                .copy("Resources/AppIcon.icns")
            ]
        ),
        .executableTarget(
            name: "PastewatchCLI",
            dependencies: [
                "PastewatchCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ],
            path: "Sources/PastewatchCLI"
        ),
        .testTarget(
            name: "PastewatchTests",
            dependencies: ["PastewatchCore"],
            path: "Tests/PastewatchTests"
        )
    ]
)
