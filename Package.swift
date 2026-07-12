// swift-tools-version: 5.9

import PackageDescription

var targets: [Target] = [
    .target(
        name: "PastewatchCore",
        dependencies: [
            .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))
        ],
        path: "Sources/PastewatchCore"
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
        dependencies: ["PastewatchCore", "PastewatchCLI"],
        path: "Tests/PastewatchTests"
    )
]

#if os(macOS)
targets.append(
    .executableTarget(
        name: "Pastewatch",
        dependencies: ["PastewatchCore"],
        path: "Sources/Pastewatch",
        resources: [
            .copy("Resources/AppIcon.icns")
        ]
    )
)
#endif

let package = Package(
    name: "Pastewatch",
    platforms: [
        .macOS(.v14)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", "1.3.0"..<"2.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0")
    ],
    targets: targets
)
