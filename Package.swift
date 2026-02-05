// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "Pastewatch",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "pastewatch", targets: ["Pastewatch"])
    ],
    targets: [
        .executableTarget(
            name: "Pastewatch",
            path: "Sources/Pastewatch",
            resources: [
                .copy("Resources/AppIcon.icns")
            ]
        ),
        .testTarget(
            name: "PastewatchTests",
            dependencies: ["Pastewatch"],
            path: "Tests/PastewatchTests"
        )
    ]
)
