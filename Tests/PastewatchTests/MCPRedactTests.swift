import XCTest
@testable import PastewatchCore

final class MCPRedactTests: XCTestCase {

    func testReadFileRedactsContent() throws {
        let tmpFile = NSTemporaryDirectory() + "mcp_read_test.txt"
        try "contact: user@example.com".write(toFile: tmpFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let store = RedactionStore()
        let content = try String(contentsOfFile: tmpFile, encoding: .utf8)
        let matches = DetectionRules.scan(content, config: .defaultConfig)
        let (redacted, entries) = store.redact(content: content, matches: matches, filePath: tmpFile)

        XCTAssertFalse(redacted.contains("user@example.com"))
        XCTAssertTrue(redacted.contains("__PW_EMAIL_1__"))
        XCTAssertEqual(entries.count, 1)
    }

    func testWriteFileResolvesPlaceholders() throws {
        let tmpFile = NSTemporaryDirectory() + "mcp_write_test.txt"
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let store = RedactionStore()
        let original = "key: user@example.com"
        let matches = DetectionRules.scan(original, config: .defaultConfig)
        let (redacted, _) = store.redact(content: original, matches: matches, filePath: tmpFile)

        // Simulate agent modifying the redacted content (adding a comment)
        let agentOutput = redacted + " # email field"
        let resolved = store.resolveAll(content: agentOutput)

        try resolved.content.write(toFile: tmpFile, atomically: true, encoding: .utf8)
        let written = try String(contentsOfFile: tmpFile, encoding: .utf8)

        XCTAssertTrue(written.contains("user@example.com"))
        XCTAssertFalse(written.contains("__PW_EMAIL_1__"))
        XCTAssertTrue(written.hasSuffix("# email field"))
        XCTAssertEqual(resolved.resolved, 1)
    }

    func testRoundTripPreservesContent() throws {
        let tmpFile = NSTemporaryDirectory() + "mcp_roundtrip_test.txt"
        let original = "db_host: 192.168.1.100\nemail: admin@corp.com\nport: 5432"
        try original.write(toFile: tmpFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let store = RedactionStore()
        let content = try String(contentsOfFile: tmpFile, encoding: .utf8)
        let matches = DetectionRules.scan(content, config: .defaultConfig)
        let (redacted, _) = store.redact(content: content, matches: matches, filePath: tmpFile)

        // Agent reads redacted, makes no changes, writes back
        let resolved = store.resolve(content: redacted, filePath: tmpFile)

        XCTAssertEqual(resolved.content, original)
        XCTAssertEqual(resolved.unresolved, 0)
    }

    func testCheckOutputDetectsSecrets() {
        let text = "config = user@example.com"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        XCTAssertFalse(matches.isEmpty)
    }

    func testCheckOutputCleanText() {
        let text = "config = __PW_EMAIL_1__"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        XCTAssertTrue(matches.isEmpty)
    }

    func testCleanFilePassesThrough() throws {
        let tmpFile = NSTemporaryDirectory() + "mcp_clean_test.txt"
        try "nothing sensitive here".write(toFile: tmpFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let store = RedactionStore()
        let content = try String(contentsOfFile: tmpFile, encoding: .utf8)
        let matches = DetectionRules.scan(content, config: .defaultConfig)

        XCTAssertTrue(matches.isEmpty)
        XCTAssertFalse(store.hasMappings(for: tmpFile))
    }

    // MARK: - Severity Filtering

    func testSeverityFilteringHighDefault() {
        let content = "contact: user@corp.com server: 192.168.1.50"
        let allMatches = DetectionRules.scan(content, config: .defaultConfig)
        let filtered = allMatches.filter { $0.effectiveSeverity >= .high }

        // Email is high severity — kept. IP is medium — dropped.
        let emailMatches = filtered.filter { $0.type == .email }
        let ipMatches = filtered.filter { $0.type == .ipAddress }
        XCTAssertGreaterThanOrEqual(emailMatches.count, 1)
        XCTAssertEqual(ipMatches.count, 0)
    }

    func testSeverityFilteringCriticalOnly() {
        let content = "email: user@corp.com"
        let allMatches = DetectionRules.scan(content, config: .defaultConfig)
        let filtered = allMatches.filter { $0.effectiveSeverity >= .critical }

        // Email is high, not critical — filtered out
        XCTAssertTrue(filtered.isEmpty)
    }

    func testSeverityFilteringLow() {
        let content = "contact: user@corp.com server: 192.168.1.50"
        let allMatches = DetectionRules.scan(content, config: .defaultConfig)
        let filtered = allMatches.filter { $0.effectiveSeverity >= .low }

        // Low threshold keeps everything
        XCTAssertEqual(filtered.count, allMatches.count)
    }

    func testReadmeWithBadgesNotRedacted() throws {
        let tmpFile = NSTemporaryDirectory() + "mcp_readme_test.md"
        let readme = "# My Project\n[![Build](https://img.shields.io/badge/build-passing-green)](https://github.com/user/repo)\n[![Coverage](https://codecov.io/gh/user/repo/badge.svg)](https://codecov.io/gh/user/repo)"
        try readme.write(toFile: tmpFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let store = RedactionStore()
        let content = try String(contentsOfFile: tmpFile, encoding: .utf8)
        let allMatches = DetectionRules.scan(content, config: .defaultConfig)
        let matches = allMatches.filter { $0.effectiveSeverity >= .high }

        // No high+ severity findings in a typical README with badges
        XCTAssertTrue(matches.isEmpty)

        let (redacted, entries) = store.redact(content: content, matches: matches, filePath: tmpFile)
        XCTAssertEqual(redacted, content)
        XCTAssertTrue(entries.isEmpty)
    }
}
