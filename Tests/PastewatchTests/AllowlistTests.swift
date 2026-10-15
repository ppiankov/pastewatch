import XCTest
@testable import PastewatchCore

final class AllowlistTests: XCTestCase {
    // WO-529@v3: Use a config with obfuscate entries for email testing.
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

    // WO-676@v4: remedy exact values suppress naturally emitted advisory Phone matches only.
    func testFiltersSuppressedValues() {
        let first = ["+", "65", " ", "6123", " ", "4567"].joined()
        let second = ["+", "1", " ", "415", " ", "555", " ", "0132"].joined()
        let content = first + "; " + second
        let matches = DetectionRules.scan(content, config: TestConfigHelper.configWithAmbiguousAdvisories([.phone]))
        XCTAssertEqual(matches.count, 2)
        XCTAssertTrue(matches.allSatisfy { $0.type == .phone && $0.mutationAuthorizationSources.isEmpty })
        let allowlist = Allowlist(values: Set(matches.dropFirst().map(\.value)))
        let filtered = allowlist.filter(matches)
        XCTAssertEqual(filtered.count, 1)
        XCTAssertTrue(filtered.first?.value == matches.first?.value)
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

    // WO-676@v4: the scan control uses actual Phone matches, not synthetic advisory Email.
    func testScanWithAllowlist() {
        let first = ["+", "65", " ", "6123", " ", "4567"].joined()
        let second = ["+", "1", " ", "415", " ", "555", " ", "0132"].joined()
        let content = first + "; " + second
        let advisoryConfig = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
        let detected = DetectionRules.scan(content, config: advisoryConfig)
        XCTAssertEqual(detected.count, 2)
        let allowlist = Allowlist(values: Set(detected.dropFirst().map(\.value)))
        let matches = DetectionRules.scan(content, config: advisoryConfig, allowlist: allowlist)
        XCTAssertEqual(matches.count, 1)
        XCTAssertTrue(matches.first?.value == detected.first?.value)
    }

    // MARK: - Allowed Patterns (regex)

    // WO-676@v4: remedy patterns cannot substitute for exact advisory entries.
    func testPatternSuppressesMatchingValue() throws {
        let content = ["admin", "@corp.com"].joined()
        let pattern = try NSRegularExpression(pattern: ".*")
        let allowlist = Allowlist(values: [], patterns: [pattern])
        let matches = DetectionRules.scan(content, config: config)
        let filtered = allowlist.filter(matches)
        XCTAssertFalse(matches.isEmpty)
        XCTAssertEqual(filtered.count, matches.count)
    }

    func testPatternDoesNotSuppressNonMatching() throws {
        let content = "Contact admin@corp.com"
        let pattern = try NSRegularExpression(pattern: "^(sk_test_.*)$")
        let allowlist = Allowlist(values: [], patterns: [pattern])
        let matches = DetectionRules.scan(content, config: config)
        let filtered = allowlist.filter(matches)
        XCTAssertEqual(filtered.count, matches.count, "pattern should not suppress non-matching values")
    }

    // WO-676@v4: multiple remedy patterns cannot suppress findings either.
    func testMultiplePatternsWorkTogether() throws {
        let content = ["test", "@example.com"].joined()
        let p1 = try NSRegularExpression(pattern: ".*")
        let p2 = try NSRegularExpression(pattern: "^(test@.*)$")
        let allowlist = Allowlist(values: [], patterns: [p1, p2])
        let matches = DetectionRules.scan(content, config: config)
        let filtered = allowlist.filter(matches)
        XCTAssertFalse(matches.isEmpty)
        XCTAssertEqual(filtered.count, matches.count)
    }

    func testAllowedPatternsFromConfig() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.allowedPatterns = ["sk_test_.*"]
        let allowlist = Allowlist.fromConfig(customConfig)
        XCTAssertEqual(allowlist.patterns.count, 1)
    }
}
