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
        XCTAssertTrue(redacted.contains("__PW{EMAIL_1}__"))
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
        XCTAssertFalse(written.contains("__PW{EMAIL_1}__"))
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
        let text = "config = __PW{EMAIL_1}__"
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
}
