import XCTest
@testable import PastewatchCore

final class MCPAuditLogTests: XCTestCase {

    private func tempLogPath() -> String {
        NSTemporaryDirectory() + "pastewatch-audit-test-\(UUID().uuidString).log"
    }

    func testAuditLogCreatesFile() {
        let path = tempLogPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let logger = MCPAuditLogger(path: path)
        _ = logger // keep alive

        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    func testAuditLogWritesTimestampAndMessage() throws {
        let path = tempLogPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let logger = MCPAuditLogger(path: path)
        logger.log("READ  /app/config.yml  redacted=3 [AWS Key, Credential, Email]")

        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }

        // First line: startup message, second line: our log
        XCTAssertEqual(lines.count, 2)
        XCTAssertTrue(lines[1].contains("READ  /app/config.yml  redacted=3"))
        XCTAssertTrue(lines[1].contains("[AWS Key, Credential, Email]"))
        // Check ISO 8601 timestamp prefix
        XCTAssertTrue(lines[1].contains("T"))
        XCTAssertTrue(lines[1].contains("Z"))
    }

    func testAuditLogAppendsMultipleEntries() throws {
        let path = tempLogPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let logger = MCPAuditLogger(path: path)
        logger.log("READ  /a.yml  redacted=1 [Email]")
        logger.log("WRITE /a.yml  resolved=1 unresolved=0")
        logger.log("CHECK (inline)  clean=true")

        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }

        // 1 startup + 3 entries
        XCTAssertEqual(lines.count, 4)
        XCTAssertTrue(lines[1].contains("READ"))
        XCTAssertTrue(lines[2].contains("WRITE"))
        XCTAssertTrue(lines[3].contains("CHECK"))
    }

    func testAuditLogNeverContainsSecretValues() throws {
        let path = tempLogPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let logger = MCPAuditLogger(path: path)
        // Log messages should only contain metadata, never secret values
        logger.log("READ  /app/.env  redacted=2 [Credential, AWS Key]")

        let content = try String(contentsOfFile: path, encoding: .utf8)

        // Should not contain any actual secret-looking values
        XCTAssertFalse(content.contains("password"))
        XCTAssertFalse(content.contains("AKIA"))
        // Should contain the metadata
        XCTAssertTrue(content.contains("redacted=2"))
    }
}
