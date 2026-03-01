import XCTest
@testable import PastewatchCore

final class ConfigCheckTests: XCTestCase {
    func testValidDefaultConfig() throws {
        // Write a known-good config to a temp file instead of relying on user config
        let config = PastewatchConfig.defaultConfig
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(config)
        let path = "/tmp/pastewatch-test-default-config.json"
        try data.write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }

        let result = ConfigValidator.validate(path: path)
        XCTAssertTrue(result.isValid)
    }

    func testFileNotFound() {
        let result = ConfigValidator.validate(path: "/tmp/nonexistent-pastewatch-config.json")
        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.first?.contains("file not found") ?? false)
    }

    func testInvalidJSON() throws {
        let path = "/tmp/pastewatch-test-invalid.json"
        try "not json at all".write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let result = ConfigValidator.validate(path: path)
        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.first?.contains("invalid JSON") ?? false)
    }

    func testUnknownType() throws {
        let json = """
        {
            "enabled": true,
            "enabledTypes": ["Email", "FakeType"],
            "showNotifications": true,
            "soundEnabled": false
        }
        """
        let path = "/tmp/pastewatch-test-unknown-type.json"
        try json.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let result = ConfigValidator.validate(path: path)
        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains("FakeType") })
    }

    func testInvalidCustomRuleRegex() throws {
        let json = """
        {
            "enabled": true,
            "enabledTypes": ["Email"],
            "showNotifications": true,
            "soundEnabled": false,
            "customRules": [{"name": "bad", "pattern": "[invalid"}]
        }
        """
        let path = "/tmp/pastewatch-test-bad-regex.json"
        try json.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let result = ConfigValidator.validate(path: path)
        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains("invalid regex") })
    }
}
