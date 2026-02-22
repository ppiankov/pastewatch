import XCTest
@testable import PastewatchCore

final class AllowlistTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

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
}
