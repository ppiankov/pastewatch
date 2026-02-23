import XCTest
@testable import PastewatchCore

final class CustomRuleTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

    func testCustomRuleDetection() throws {
        let rules = try CustomRule.compile([
            CustomRuleConfig(name: "Ticket ID", pattern: "MYCO-[0-9]{6}")
        ])
        let content = "See ticket MYCO-123456 for details"
        let matches = DetectionRules.scan(content, config: config, customRules: rules)
        let customMatches = matches.filter { $0.customRuleName != nil }
        XCTAssertEqual(customMatches.count, 1)
        XCTAssertEqual(customMatches[0].value, "MYCO-123456")
        XCTAssertEqual(customMatches[0].customRuleName, "Ticket ID")
        XCTAssertEqual(customMatches[0].displayName, "Ticket ID")
    }

    func testCustomRuleNoOverlapWithBuiltin() throws {
        let rules = try CustomRule.compile([
            CustomRuleConfig(name: "Broad Email", pattern: "[a-z]+@[a-z]+\\.[a-z]+")
        ])
        let content = "Contact admin@corp.com"
        let matches = DetectionRules.scan(content, config: config, customRules: rules)
        // Built-in email rule should match first, custom should be skipped (overlap)
        XCTAssertEqual(matches.count, 1)
        XCTAssertNil(matches[0].customRuleName)
    }

    func testInvalidRegexThrows() {
        XCTAssertThrowsError(try CustomRule.compile([
            CustomRuleConfig(name: "Bad", pattern: "[invalid")
        ]))
    }

    func testLoadFromFile() throws {
        let path = NSTemporaryDirectory() + "test-rules-\(UUID().uuidString).json"
        let json = "[{\"name\": \"Test\", \"pattern\": \"TEST-[0-9]+\"}]"
        try json.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let rules = try CustomRule.load(from: path)
        XCTAssertEqual(rules.count, 1)
        XCTAssertEqual(rules[0].name, "Test")
    }

    func testCustomRuleWithAllowlist() throws {
        let rules = try CustomRule.compile([
            CustomRuleConfig(name: "Ticket", pattern: "MYCO-[0-9]{6}")
        ])
        let allowlist = Allowlist(values: ["MYCO-123456"])
        let content = "See MYCO-123456 and MYCO-654321"
        let matches = DetectionRules.scan(content, config: config, allowlist: allowlist, customRules: rules)
        let customMatches = matches.filter { $0.customRuleName != nil }
        XCTAssertEqual(customMatches.count, 1)
        XCTAssertEqual(customMatches[0].value, "MYCO-654321")
    }

    func testEmptyCustomRules() {
        let content = "admin@corp.com"
        let matches = DetectionRules.scan(content, config: config, customRules: [])
        XCTAssertGreaterThan(matches.count, 0)
    }

    func testCustomRuleWithSeverity() throws {
        let json = #"[{"name": "Ticket", "pattern": "MYCO-[0-9]{6}", "severity": "low"}]"#
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("test-rules-sev.json")
        try json.write(to: url, atomically: true, encoding: .utf8)
        let rules = try CustomRule.load(from: url.path)
        XCTAssertEqual(rules[0].severity, .low)
    }

    func testCustomRuleDefaultSeverity() throws {
        let json = #"[{"name": "Ticket", "pattern": "MYCO-[0-9]{6}"}]"#
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("test-rules-def.json")
        try json.write(to: url, atomically: true, encoding: .utf8)
        let rules = try CustomRule.load(from: url.path)
        XCTAssertEqual(rules[0].severity, .high)
    }

    func testCustomRuleInvalidSeverityUsesDefault() throws {
        let json = #"[{"name": "Ticket", "pattern": "MYCO-[0-9]{6}", "severity": "extreme"}]"#
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("test-rules-inv.json")
        try json.write(to: url, atomically: true, encoding: .utf8)
        let rules = try CustomRule.load(from: url.path)
        XCTAssertEqual(rules[0].severity, .high)
    }

    func testEffectiveSeverityOverridesType() {
        let match = DetectedMatch(
            type: .credential,
            value: "test",
            range: "test".startIndex..<"test".endIndex,
            customRuleName: "MyRule",
            customSeverity: .low
        )
        XCTAssertEqual(match.type.severity, .critical)
        XCTAssertEqual(match.effectiveSeverity, .low)
    }
}
