import XCTest
@testable import PastewatchCore

final class SessionReportTests: XCTestCase {

    // MARK: - Empty / Minimal

    func testParseEmptyLog() {
        let report = SessionReportBuilder.build(content: "", logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.filesRead, 0)
        XCTAssertEqual(report.summary.filesWritten, 0)
        XCTAssertEqual(report.summary.secretsRedacted, 0)
        XCTAssertTrue(report.secretsByType.isEmpty)
        XCTAssertTrue(report.filesAccessed.isEmpty)
        XCTAssertTrue(report.verdict.contains("Zero secrets leaked"))
    }

    func testParseStartLineOnly() {
        let log = "2026-03-02T10:00:00Z MCP audit log started"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.filesRead, 0)
        XCTAssertEqual(report.periodStart, "2026-03-02T10:00:00Z")
        XCTAssertEqual(report.periodEnd, "2026-03-02T10:00:00Z")
    }

    // MARK: - READ Parsing

    func testParseReadClean() {
        let log = "2026-03-02T10:01:00Z READ  config.yml  clean"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.filesRead, 1)
        XCTAssertEqual(report.summary.secretsRedacted, 0)
        XCTAssertEqual(report.filesAccessed.count, 1)
        XCTAssertEqual(report.filesAccessed.first?.file, "config.yml")
        XCTAssertEqual(report.filesAccessed.first?.reads, 1)
    }

    func testParseReadRedacted() {
        let log = "2026-03-02T10:01:00Z READ  .env  redacted=3 [AWS Key, Credential, Email]"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.filesRead, 1)
        XCTAssertEqual(report.summary.secretsRedacted, 3)
        XCTAssertEqual(report.secretsByType.count, 3)

        let awsType = report.secretsByType.first { $0.type == "AWS Key" }
        XCTAssertEqual(awsType?.count, 1)
        XCTAssertEqual(awsType?.severity, "critical")

        let emailType = report.secretsByType.first { $0.type == "Email" }
        XCTAssertEqual(emailType?.count, 1)
        XCTAssertEqual(emailType?.severity, "high")
        // WO-540: legacy logs without structured receipts must not infer coverage.
        XCTAssertNil(report.obfuscationCoverage)
    }

    // MARK: - WRITE Parsing

    func testParseWriteResolved() {
        let log = "2026-03-02T10:02:00Z WRITE .env  resolved=3 unresolved=0"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.filesWritten, 1)
        XCTAssertEqual(report.summary.placeholdersResolved, 3)
        XCTAssertEqual(report.summary.unresolvedPlaceholders, 0)
        XCTAssertTrue(report.verdict.contains("Zero secrets leaked"))
    }

    func testParseWriteUnresolved() {
        let log = "2026-03-02T10:02:00Z WRITE .env  resolved=2 unresolved=1"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.unresolvedPlaceholders, 1)
        XCTAssertTrue(report.verdict.contains("WARNING"))
        XCTAssertTrue(report.verdict.contains("unresolved"))
    }

    // MARK: - CHECK Parsing

    func testParseCheckClean() {
        let log = "2026-03-02T10:03:00Z CHECK (inline)  clean=true"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.outputChecks, 1)
        XCTAssertEqual(report.summary.outputChecksDirty, 0)
    }

    func testParseCheckDirty() {
        let log = "2026-03-02T10:03:00Z CHECK (inline)  clean=false"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.outputChecks, 1)
        XCTAssertEqual(report.summary.outputChecksDirty, 1)
        XCTAssertTrue(report.verdict.contains("WARNING"))
        XCTAssertTrue(report.verdict.contains("output check"))
    }

    // MARK: - SCAN Parsing

    func testParseScanFindings() {
        let log = """
        2026-03-02T10:04:00Z SCAN  src/app.py  findings=2
        2026-03-02T10:05:00Z SCAN  (inline)  findings=0
        2026-03-02T10:06:00Z SCAN  ./src  files=12 findings=5
        """
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertEqual(report.summary.scans, 3)
        XCTAssertEqual(report.summary.scanFindings, 7)
    }

    // MARK: - Filtering

    func testSinceFiltering() {
        let log = """
        2026-03-02T10:00:00Z READ  old.txt  clean
        2026-03-02T12:00:00Z READ  new.txt  redacted=1 [Email]
        """
        let df = ISO8601DateFormatter()
        df.formatOptions = [.withInternetDateTime]
        let since = df.date(from: "2026-03-02T11:00:00Z")

        let report = SessionReportBuilder.build(
            content: log, logPath: "/tmp/test.log", since: since
        )
        XCTAssertEqual(report.summary.filesRead, 1)
        XCTAssertEqual(report.filesAccessed.first?.file, "new.txt")
    }

    // MARK: - Aggregation

    func testMultiFileAggregation() {
        let log = """
        2026-03-02T10:01:00Z READ  .env  redacted=2 [AWS Key, Credential]
        2026-03-02T10:02:00Z READ  .env  redacted=2 [AWS Key, Credential]
        2026-03-02T10:03:00Z WRITE .env  resolved=4 unresolved=0
        2026-03-02T10:04:00Z READ  config.yml  clean
        """
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")

        XCTAssertEqual(report.summary.filesRead, 2)
        XCTAssertEqual(report.summary.secretsRedacted, 4)

        let envAccess = report.filesAccessed.first { $0.file == ".env" }
        XCTAssertEqual(envAccess?.reads, 2)
        XCTAssertEqual(envAccess?.writes, 1)
        XCTAssertEqual(envAccess?.secretsRedacted, 4)
    }

    func testTypeCounts() {
        let log = """
        2026-03-02T10:01:00Z READ  a.env  redacted=2 [AWS Key, Email]
        2026-03-02T10:02:00Z READ  b.env  redacted=3 [AWS Key, Credential, Email]
        """
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")

        let awsCount = report.secretsByType.first { $0.type == "AWS Key" }
        XCTAssertEqual(awsCount?.count, 2)

        let emailCount = report.secretsByType.first { $0.type == "Email" }
        XCTAssertEqual(emailCount?.count, 2)

        let credCount = report.secretsByType.first { $0.type == "Credential" }
        XCTAssertEqual(credCount?.count, 1)
    }

    // MARK: - Verdict

    func testVerdictClean() {
        let log = """
        2026-03-02T10:01:00Z READ  .env  redacted=3 [AWS Key, Credential, Email]
        2026-03-02T10:02:00Z WRITE .env  resolved=3 unresolved=0
        2026-03-02T10:03:00Z CHECK (inline)  clean=true
        """
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        XCTAssertTrue(report.verdict.contains("Zero secrets leaked"))
    }

    // MARK: - Formatters

    func testFormatMarkdownContainsTables() {
        let log = "2026-03-02T10:01:00Z READ  .env  redacted=1 [AWS Key]"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        let md = SessionReportBuilder.formatMarkdown(report)

        XCTAssertTrue(md.contains("# Agent Session Report"))
        XCTAssertTrue(md.contains("## Summary"))
        XCTAssertTrue(md.contains("## Secrets by Type"))
        XCTAssertTrue(md.contains("## Files Accessed"))
        XCTAssertTrue(md.contains("## Verdict"))
        XCTAssertTrue(md.contains("| AWS Key |"))
        XCTAssertTrue(md.contains("| .env |"))
    }

    func testFormatJSONDecodable() {
        let log = "2026-03-02T10:01:00Z READ  .env  redacted=1 [AWS Key]"
        let report = SessionReportBuilder.build(content: log, logPath: "/tmp/test.log")
        let jsonStr = SessionReportBuilder.formatJSON(report)

        // Verify it's valid JSON that decodes back to SessionReport
        let data = jsonStr.data(using: .utf8)!
        let decoded = try? JSONDecoder().decode(SessionReport.self, from: data)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.summary.secretsRedacted, 1)
    }

    // WO-540: text, JSON, and Markdown must mirror the same structured coverage receipts.
    func testCoverageReceiptsAggregateAcrossSourcesWithoutMatchedValues() throws {
        let events = [
            ObfuscationCoverageEvent(
                tier: .intrinsic,
                type: SensitiveDataType.awsKey.rawValue,
                count: 2,
                source: .request
            ),
            ObfuscationCoverageEvent(
                tier: .configured,
                type: SensitiveDataType.email.rawValue,
                ruleIdentifier: "email[0]",
                source: .request
            ),
            ObfuscationCoverageEvent(
                tier: .advisory,
                type: SensitiveDataType.ipAddress.rawValue,
                source: .response
            ),
            ObfuscationCoverageEvent(
                tier: .observed,
                type: SensitiveDataType.email.rawValue,
                count: 2,
                source: .response,
                domainBucket: "@corp.example"
            ),
            ObfuscationCoverageEvent(
                tier: .observed,
                type: SensitiveDataType.hostname.rawValue,
                source: .toolCall,
                domainBucket: ".internal.example"
            )
        ]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let lines = try events.enumerated().map { index, event -> String in
            let data = try encoder.encode(event)
            let json = try XCTUnwrap(String(data: data, encoding: .utf8))
            return "[2026-03-02T10:0\(index):00Z] PROXY COVERAGE \(json)"
        }

        let report = SessionReportBuilder.build(
            content: lines.joined(separator: "\n"),
            logPath: "/tmp/test.log"
        )
        let coverage = try XCTUnwrap(report.obfuscationCoverage)
        XCTAssertEqual(coverage.tier1Intrinsic.first?.count, 2)
        XCTAssertEqual(coverage.tier1Intrinsic.first?.source, .request)
        XCTAssertEqual(coverage.tier2OptIn.first?.ruleIdentifier, "email[0]")
        XCTAssertEqual(coverage.advisory.first?.type, SensitiveDataType.ipAddress.rawValue)
        XCTAssertEqual(coverage.seenButNotConfigured.map(\.count).reduce(0, +), 3)
        XCTAssertEqual(
            Set(coverage.seenButNotConfigured.map(\.domain)),
            Set(["@corp.example", ".internal.example"])
        )

        let text = SessionReportBuilder.formatText(report)
        let markdown = SessionReportBuilder.formatMarkdown(report)
        let json = SessionReportBuilder.formatJSON(report)
        for rendered in [text, markdown, json] {
            XCTAssertTrue(rendered.contains("email[0]"))
            XCTAssertTrue(rendered.contains("@corp.example"))
            XCTAssertFalse(rendered.contains("alice@corp.example"))
        }
    }

    // MARK: - Helper

    func testExtractInt() {
        XCTAssertEqual(SessionReportBuilder.extractInt(from: "redacted=3 [AWS Key]", key: "redacted"), 3)
        XCTAssertEqual(SessionReportBuilder.extractInt(from: "resolved=12 unresolved=0", key: "resolved"), 12)
        XCTAssertEqual(SessionReportBuilder.extractInt(from: "resolved=12 unresolved=0", key: "unresolved"), 0)
        XCTAssertNil(SessionReportBuilder.extractInt(from: "clean", key: "redacted"))
    }
}
