import XCTest
@testable import PastewatchCore

final class PastewatchSharedPatternsTests: XCTestCase {
    private let githubTokenBodyLength = 36

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

    func testNRManifestGitHubOAuthPatternRedactsThroughFileIO() throws {
        let token = "gh" + "o_" + String(repeating: "A", count: githubTokenBodyLength)
        let artifactURL = try writeSharedPatternManifest(patterns: [
            SharedSecretPatternConfig(
                name: "github_oauth_token",
                type: "github_token",
                regex: #"\bgho_[0-9a-zA-Z]{36}\b"#,
                policy: "redact"
            )
        ])
        defer { try? FileManager.default.removeItem(at: artifactURL) }

        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.removeAll { $0 == SensitiveDataType.genericApiKey.rawValue }
        config.sharedPatternFiles = [artifactURL.path]

        let matches = DirectoryScanner.scanFileContent(
            content: "oauth token " + token,
            ext: "txt",
            relativePath: "nr-manifest.txt",
            config: config
        )
        let sharedMatches = matches.filter { $0.customRuleName == "github_oauth_token" }

        XCTAssertEqual(sharedMatches.count, 1)
        XCTAssertEqual(sharedMatches.first?.value, token)
    }

    func testSharedOnlyPatternRequiresArtifact() {
        let syntheticValue = "PW" + "SHARED-" + syntheticSuffix()
        let matches = DetectionRules.scanFileIO("token: " + syntheticValue, config: .defaultConfig)

        XCTAssertFalse(matches.contains { $0.value == syntheticValue })
    }

    func testRuntimeConstructedGitHubOAuthFixtureStillRedacts() {
        let token = "gh" + "o_" + String(repeating: "x", count: githubTokenBodyLength)
        let content = "token: " + token
        let matches = DetectionRules.scanFileIO(content, config: .defaultConfig)

        XCTAssertTrue(matches.contains { $0.value == token && $0.type == .genericApiKey })

        let store = RedactionStore()
        let (redacted, _) = store.redact(content: content, matches: matches, filePath: "/tmp/gh-fixture.txt")

        XCTAssertFalse(redacted.contains(token))
        XCTAssertTrue(redacted.contains("__PW_API_KEY_1__"))
    }

    func testPlaceholderDriftMapPreservesProxyCompatibleEnvelope() throws {
        let placeholder = Obfuscator.makeMCPPlaceholder(type: .email, number: 1)
        let regex = try NSRegularExpression(pattern: Obfuscator.mcpPlaceholderPattern)

        XCTAssertEqual(placeholder, "__PW_EMAIL_1__")
        XCTAssertNotNil(regex.firstMatch(
            in: placeholder,
            range: NSRange(placeholder.startIndex..., in: placeholder)
        ))

        let nrBraceEnvelope = "__PW{EMAIL_1}"
        XCTAssertNil(regex.firstMatch(
            in: nrBraceEnvelope,
            range: NSRange(nrBraceEnvelope.startIndex..., in: nrBraceEnvelope)
        ))
        XCTAssertTrue(AgentSetup.claudeSnippet.contains("__PW_TYPE_N__"))
        XCTAssertTrue(AgentSetup.clineHookScript(severity: "high").contains(
            #"__PW_[A-Z][A-Z0-9_]*_[0-9]+__"#
        ))
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

    private func writeSharedPatternManifest(patterns: [SharedSecretPatternConfig]) throws -> URL {
        let artifactURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-shared-manifest-\(UUID().uuidString).json")
        let manifest = SharedSecretPatternManifest(
            manifestVersion: "1",
            source: "neurorouter-pro/WO-1019",
            generatedFrom: "internal/neurorouter/protect.go",
            patterns: patterns
        )
        let data = try JSONEncoder().encode(manifest)
        try data.write(to: artifactURL)
        return artifactURL
    }

    private func syntheticSuffix() -> String {
        String(UUID().uuidString.replacingOccurrences(of: "-", with: "").uppercased().prefix(12))
    }
}
