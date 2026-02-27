import XCTest
@testable import PastewatchCore

/// Tests for guard-read / guard-write scan logic.
/// Both commands share the same scan path: format-aware scanning via
/// DirectoryScanner.scanFileContent() + Allowlist.filterInlineAllow().
final class GuardReadWriteTests: XCTestCase {

    private var testDir: String!
    private let config = PastewatchConfig.defaultConfig

    override func setUp() {
        super.setUp()
        testDir = NSTemporaryDirectory() + "pastewatch-guard-rw-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: testDir)
        super.tearDown()
    }

    // MARK: - Helpers

    /// Run the same scan logic used by guard-read and guard-write.
    private func scanFile(
        at path: String,
        failOnSeverity: Severity = .high,
        config: PastewatchConfig = PastewatchConfig.defaultConfig
    ) -> [DetectedMatch] {
        guard FileManager.default.fileExists(atPath: path),
              let content = try? String(contentsOfFile: path, encoding: .utf8),
              !content.isEmpty else {
            return []
        }

        let fileName = URL(fileURLWithPath: path).lastPathComponent
        let isEnvFile = fileName == ".env" || fileName.hasSuffix(".env")
        let ext = isEnvFile ? "env" : URL(fileURLWithPath: path).pathExtension.lowercased()

        var matches = DirectoryScanner.scanFileContent(
            content: content, ext: ext,
            relativePath: path, config: config
        )
        matches = Allowlist.filterInlineAllow(matches: matches, content: content)

        let configAllowlist = Allowlist.fromConfig(config)
        matches = configAllowlist.filter(matches)

        return matches.filter { $0.effectiveSeverity >= failOnSeverity }
    }

    // MARK: - Tests

    func testCleanFileNoFindings() throws {
        let path = testDir + "/clean.txt"
        try "Hello world, nothing sensitive".write(toFile: path, atomically: true, encoding: .utf8)
        let findings = scanFile(at: path)
        XCTAssertTrue(findings.isEmpty)
    }

    func testFileWithDBConnectionString() throws {
        let path = testDir + "/config.yml"
        let dbUrl = ["postgres://user:", "pass@host:5432/mydb"].joined()
        try "database_url: \(dbUrl)".write(
            toFile: path, atomically: true, encoding: .utf8)
        let findings = scanFile(at: path)
        XCTAssertFalse(findings.isEmpty, "DB connection string should be detected")
        XCTAssertTrue(findings.contains { $0.type == .dbConnectionString })
    }

    func testSecretBelowSeverityThreshold() throws {
        let path = testDir + "/hosts.txt"
        // IP address is medium severity — below default high threshold
        try "server: 10.0.1.50".write(toFile: path, atomically: true, encoding: .utf8)
        let findings = scanFile(at: path, failOnSeverity: .high)
        XCTAssertTrue(findings.isEmpty, "Medium severity should not trigger at high threshold")
    }

    func testEnvFileFormatAwareScanning() throws {
        let path = testDir + "/.env"
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        try "AWS_KEY=\(key)".write(toFile: path, atomically: true, encoding: .utf8)
        let findings = scanFile(at: path)
        XCTAssertFalse(findings.isEmpty, ".env file should detect secrets in values")
        XCTAssertTrue(findings.contains { $0.type == .awsKey })
    }

    func testJSONFileFormatAwareScanning() throws {
        let path = testDir + "/config.json"
        let dbUrl = ["postgres://admin:", "secret@db.internal:5432/prod"].joined()
        let content = """
        {
            "database": "\(dbUrl)"
        }
        """
        try content.write(toFile: path, atomically: true, encoding: .utf8)
        let findings = scanFile(at: path)
        XCTAssertFalse(findings.isEmpty, "JSON file should detect secrets in values")
        XCTAssertTrue(findings.contains { $0.type == .dbConnectionString })
    }

    func testNonExistentFileNoFindings() {
        let findings = scanFile(at: testDir + "/does-not-exist.txt")
        XCTAssertTrue(findings.isEmpty, "Non-existent file should return no findings")
    }

    func testInlineAllowSuppressesFinding() throws {
        let path = testDir + "/config.env"
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        try "AWS_KEY=\(key) # pastewatch:allow".write(
            toFile: path, atomically: true, encoding: .utf8)
        let findings = scanFile(at: path)
        XCTAssertTrue(findings.isEmpty, "Inline allow should suppress the finding")
    }

    func testLowSeverityThresholdCatchesMore() throws {
        let path = testDir + "/data.txt"
        // IP address is medium severity
        try "server: 10.0.1.50".write(toFile: path, atomically: true, encoding: .utf8)
        let findings = scanFile(at: path, failOnSeverity: .low)
        XCTAssertFalse(findings.isEmpty, "Low threshold should catch medium severity findings")
    }
}
