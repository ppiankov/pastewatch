import XCTest
@testable import PastewatchCore

// WO-714@v3: workflow syntax must receive the same credential verdict before and after YAML parsing.
final class WorkflowCredentialTests: XCTestCase {
    // WO-714@v3: the exact permission key has a closed non-secret value vocabulary.
    func testPermissionValuesAreNotCredentialsOnBothPaths() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            for permission in ["read", "write", "none"] {
                for suffix in ["", "  # Required for signing", "\t# workflow permission"] {
                    try assertCredentialCount(key: "id-" + "token", value: permission + suffix, expected: 0)
                }
            }
        }
    }

    // WO-714@v3: only a complete hyphen or underscore segment identifies a placeholder.
    func testPlaceholderSegmentsAreNotCredentialsOnBothPaths() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let values = ["generation-only-" + "placeholder", "generation_only_" + "PLACEHOLDER",
                          "placeholder" + "-generation-only", "generation-" + "PlAcEhOlDeR" + "-only"]
            for key in ["HOMEBREW_TAP_" + "TOKEN", "SCOOP_BUCKET_" + "TOKEN"] {
                for value in values {
                    try assertCredentialCount(key: key, value: value, expected: 0)
                    try assertCredentialCount(key: key, value: "\"" + value + "\"", expected: 0)
                }
            }
        }
    }

    // WO-714@v3: other keys, real-looking values and longer lookalike segments retain critical recognition.
    func testRealValuesAndLongerSegmentsRemainCriticalOnBothPaths() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = "vendor_" + ["Q7mN", "4rZ9", "T2xV", "8bD5"].joined()
            for key in ["id-" + "token", "BUILD_" + "TOKEN"] {
                try assertCredentialCount(key: key, value: value, expected: 1)
            }
            for suffix in ["placeholder" + "x", "no" + "placeholder"] {
                try assertCredentialCount(key: "BUILD_" + "TOKEN", value: "generation-only-" + suffix, expected: 1)
            }
            try assertCredentialCount(key: "BUILD_" + "TOKEN", value: "write-fixture-" + "42", expected: 1)
        }
    }

    // WO-714@v3: existing workflow expression references remain non-values.
    func testWorkflowExpressionRemainsCleanOnBothPaths() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let expression = "${{ github." + "token }}"
            try assertCredentialCount(key: "GITHUB_" + "TOKEN", value: expression, expected: 0)
        }
    }

    // WO-714@v3: assertions expose only the path kind, count and severity, never candidate values.
    private func assertCredentialCount(key: String, value: String, expected: Int) throws {
        let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
        let content = "  " + key + ": " + value + "\n"
        let raw = DetectionRules.scan(content, config: config).filter { $0.type == .credential }
        let parsed = try DirectoryScanner.scanFileContentOrThrow(
            content: content, ext: "yaml", relativePath: "fixture.yaml", config: config
        ).filter { $0.type == .credential }
        XCTAssertEqual(raw.count, expected, "raw Credential count")
        XCTAssertEqual(parsed.count, expected, "YAML Credential count")
        XCTAssertTrue(raw.allSatisfy { $0.effectiveSeverity == .critical })
        XCTAssertTrue(parsed.allSatisfy { $0.effectiveSeverity == .critical })
    }
}
