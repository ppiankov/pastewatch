import XCTest
@testable import PastewatchCore

final class PastewatchSharedPatternsTests: XCTestCase {
    func testSharedPatternArtifactRedactsThroughFileIO() throws {
        let syntheticValue = "PW" + "SHARED-" + syntheticSuffix()
        let artifactURL = try writeSharedPatternArtifact(
            regex: "PW" + #"SHARED-[A-F0-9]{12}"#
        )
        defer { try? FileManager.default.removeItem(at: artifactURL) }

        var config = PastewatchConfig.defaultConfig
        config.sharedPatternFiles = [artifactURL.path]

        let tmpFile = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-shared-\(UUID().uuidString).txt")
        try ("shared marker " + syntheticValue).write(to: tmpFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let content = try String(contentsOf: tmpFile, encoding: .utf8)
        let matches = DirectoryScanner.scanFileContent(
            content: content,
            ext: "txt",
            relativePath: tmpFile.lastPathComponent,
            config: config
        )
        let sharedMatches = matches.filter { $0.customRuleName == "wo124_synthetic_shared" }

        XCTAssertEqual(sharedMatches.count, 1)
        XCTAssertEqual(sharedMatches.first?.filePath, tmpFile.lastPathComponent)

        let store = RedactionStore()
        let (redacted, entries) = store.redact(content: content, matches: matches, filePath: tmpFile.path)

        XCTAssertFalse(redacted.contains(syntheticValue))
        XCTAssertTrue(redacted.contains("__PW_CREDENTIAL_1__"))
        XCTAssertEqual(entries.first?.type, "wo124_synthetic_shared")
    }

    func testSharedOnlyPatternRequiresArtifact() {
        let syntheticValue = "PW" + "SHARED-" + syntheticSuffix()
        let matches = DetectionRules.scanFileIO("token: " + syntheticValue, config: .defaultConfig)

        XCTAssertFalse(matches.contains { $0.value == syntheticValue })
    }

    func testRuntimeConstructedGitHubOAuthFixtureStillRedacts() {
        let token = "gh" + "o_" + String(repeating: "x", count: 36)
        let content = "token: " + token
        let matches = DetectionRules.scanFileIO(content, config: .defaultConfig)

        XCTAssertTrue(matches.contains { $0.value == token && $0.type == .genericApiKey })

        let store = RedactionStore()
        let (redacted, _) = store.redact(content: content, matches: matches, filePath: "/tmp/gh-fixture.txt")

        XCTAssertFalse(redacted.contains(token))
        XCTAssertTrue(redacted.contains("__PW_API_KEY_1__"))
    }

    private func writeSharedPatternArtifact(regex: String) throws -> URL {
        let artifactURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-shared-patterns-\(UUID().uuidString).json")
        let patterns = [
            SharedSecretPatternConfig(
                name: "wo124_synthetic_shared",
                type: "github_token",
                regex: regex,
                policy: "redact"
            )
        ]
        let data = try JSONEncoder().encode(patterns)
        try data.write(to: artifactURL)
        return artifactURL
    }

    private func syntheticSuffix() -> String {
        String(UUID().uuidString.replacingOccurrences(of: "-", with: "").uppercased().prefix(12))
    }
}
