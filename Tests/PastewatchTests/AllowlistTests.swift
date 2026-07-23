import XCTest
@testable import PastewatchCore

final class AllowlistTests: XCTestCase {
    // WO-529: Use a config with obfuscate entries for email testing.
    // Ambiguous classes (email, host, etc.) are opt-in via the obfuscate config.
    let config: PastewatchConfig = {
        var config = PastewatchConfig.defaultConfig
        // Enable email detection (ambiguous class, opt-in)
        if !config.enabledTypes.contains(SensitiveDataType.email.rawValue) {
            config.enabledTypes.append(SensitiveDataType.email.rawValue)
        }
        config.obfuscate = [
            ObfuscateEntry(type: "email", pattern: "@corp.com"),
            ObfuscateEntry(type: "email", pattern: "@example.com"),
            ObfuscateEntry(type: "email", pattern: "@test.com"),
            ObfuscateEntry(type: "email", pattern: "@safe.com")
        ]
        return config
    }()

    func testFiltersSuppressedValues() {
        let content = "Contact admin@corp.com and test@example.com"
        let matches = DetectionRules.scan(content, config: config)
        let allowlist = Allowlist(values: ["test@example.com"])
        let filtered = allowlist.filter(matches)
        XCTAssertEqual(filtered.count, 1)
        XCTAssertEqual(filtered[0].value, "admin@corp.com")
    }

    func testEmptyAllowlistPassesAll() {
        let content = "Contact admin@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        let allowlist = Allowlist()
        let filtered = allowlist.filter(matches)
        XCTAssertEqual(filtered.count, matches.count)
    }

    func testMergeAllowlists() {
        let a = Allowlist(values: ["a@test.com"])
        let b = Allowlist(values: ["b@test.com"])
        let merged = a.merged(with: b)
        XCTAssertTrue(merged.contains("a@test.com"))
        XCTAssertTrue(merged.contains("b@test.com"))
    }

    func testFromConfig() {
        var config = PastewatchConfig.defaultConfig
        config.allowedValues = ["known@safe.com"]
        let allowlist = Allowlist.fromConfig(config)
        XCTAssertTrue(allowlist.contains("known@safe.com"))
    }

    func testLoadFromFile() throws {
        let path = NSTemporaryDirectory() + "test-allowlist-\(UUID().uuidString).txt"
        try "# comment\nallowed@test.com\n\nother@test.com\n".write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let allowlist = try Allowlist.load(from: path)
        XCTAssertEqual(allowlist.values.count, 2)
        XCTAssertTrue(allowlist.contains("allowed@test.com"))
        XCTAssertTrue(allowlist.contains("other@test.com"))
    }

    func testScanWithAllowlist() {
        let content = "Contact admin@corp.com and test@example.com"
        let allowlist = Allowlist(values: ["test@example.com"])
        let matches = DetectionRules.scan(content, config: config, allowlist: allowlist)
        XCTAssertEqual(matches.count, 1)
        XCTAssertEqual(matches[0].value, "admin@corp.com")
    }

    // MARK: - Allowed Patterns (regex)

    func testPatternSuppressesMatchingValue() throws {
        let content = "key=sk_test_abc123def456ghi789"
        let pattern = try NSRegularExpression(pattern: "^(sk_test_.*)$")
        let allowlist = Allowlist(values: [], patterns: [pattern])
        let matches = DetectionRules.scan(content, config: config)
        let filtered = allowlist.filter(matches)
        let apiKeyMatches = filtered.filter { $0.type == .genericApiKey }
        XCTAssertEqual(apiKeyMatches.count, 0, "sk_test_ pattern should suppress test API keys")
    }

    func testPatternDoesNotSuppressNonMatching() throws {
        let content = "Contact admin@corp.com"
        let pattern = try NSRegularExpression(pattern: "^(sk_test_.*)$")
        let allowlist = Allowlist(values: [], patterns: [pattern])
        let matches = DetectionRules.scan(content, config: config)
        let filtered = allowlist.filter(matches)
        XCTAssertEqual(filtered.count, matches.count, "pattern should not suppress non-matching values")
    }

    func testMultiplePatternsWorkTogether() throws {
        let content = "key1=sk_test_abc123 email=test@example.com"
        let p1 = try NSRegularExpression(pattern: "^(sk_test_.*)$")
        let p2 = try NSRegularExpression(pattern: "^(test@.*)$")
        let allowlist = Allowlist(values: [], patterns: [p1, p2])
        let matches = DetectionRules.scan(content, config: config)
        let filtered = allowlist.filter(matches)
        // WO-529: email is now opt-in, so only the API key match is present
        // and it gets filtered by the pattern
        XCTAssertEqual(filtered.count, 0, "both patterns should suppress their matches")
    }

    func testAllowedPatternsFromConfig() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.allowedPatterns = ["sk_test_.*"]
        let allowlist = Allowlist.fromConfig(customConfig)
        XCTAssertEqual(allowlist.patterns.count, 1)
    }
}
