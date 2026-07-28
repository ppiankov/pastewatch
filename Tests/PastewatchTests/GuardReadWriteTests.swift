import ArgumentParser
import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

/// Tests for guard-read / guard-write scan logic.
/// Both commands share the same format-aware scan and guard-decision path.
final class GuardReadWriteTests: XCTestCase {

    private var testDir: String!
    private var originalGuardValue: String?
    private let config = PastewatchConfig.defaultConfig

    override func setUp() {
        super.setUp()
        // WO-588@v2: exercise production guard behavior even under PW_GUARD=0 test shells.
        originalGuardValue = ProcessInfo.processInfo.environment["PW_GUARD"]
        setenv("PW_GUARD", "1", 1)
        testDir = NSTemporaryDirectory() + "pastewatch-guard-rw-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
    }

    // WO-588@v2: restore the guard environment after unreadable-input checks.
    override func tearDown() {
        try? FileManager.default.removeItem(atPath: testDir)
        if let originalGuardValue {
            setenv("PW_GUARD", originalGuardValue, 1)
        } else {
            unsetenv("PW_GUARD")
        }
        super.tearDown()
    }

    // MARK: - Helpers

    /// Run the same scan logic used by guard-read and guard-write.
    private func scanFile(
        at path: String,
        failOnSeverity: Severity = .high,
        config: PastewatchConfig = PastewatchConfig.defaultConfig
    ) throws -> [DetectedMatch] {
        guard FileManager.default.fileExists(atPath: path),
              let content = try? String(contentsOfFile: path, encoding: .utf8),
              !content.isEmpty else {
            return []
        }

        let fileName = URL(fileURLWithPath: path).lastPathComponent
        let isEnvFile = DotenvClassifier.isDotenvFile(fileName)
        let ext = isEnvFile ? "env" : URL(fileURLWithPath: path).pathExtension.lowercased()

        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: content, ext: ext,
            relativePath: path, config: config
        )
        return GuardDecision.evaluate(
            matches: matches,
            content: content,
            config: config,
            contentTrust: .trustedFile,
            minimumSeverity: failOnSeverity
        ).actionableMatches
    }

    // MARK: - Tests

    func testCleanFileNoFindings() throws {
        let path = testDir + "/clean.txt"
        try "Hello world, nothing sensitive".write(toFile: path, atomically: true, encoding: .utf8)
        let findings = try scanFile(at: path)
        XCTAssertTrue(findings.isEmpty)
    }

    func testFileWithDBConnectionString() throws {
        let path = testDir + "/config.yml"
        let dbUrl = ["postgres://user:", "pass@host:5432/mydb"].joined()
        try "database_url: \(dbUrl)".write(
            toFile: path, atomically: true, encoding: .utf8)
        // WO-542: preserve the ambiguous DB fixture through explicit test opt-in.
        let findings = try scanFile(
            at: path,
            config: TestConfigHelper.configWithAmbiguousAdvisories([.dbConnectionString])
        )
        XCTAssertFalse(findings.isEmpty, "DB connection string should be detected")
        XCTAssertTrue(findings.contains { $0.type == .dbConnectionString })
    }

    func testSecretBelowSeverityThreshold() throws {
        let path = testDir + "/hosts.txt"
        // IP address is medium severity — below default high threshold
        try "server: 10.0.1.50".write(toFile: path, atomically: true, encoding: .utf8)
        let findings = try scanFile(at: path, failOnSeverity: .high)
        XCTAssertTrue(findings.isEmpty, "Medium severity should not trigger at high threshold")
    }

    func testEnvFileFormatAwareScanning() throws {
        let path = testDir + "/.env"
        let key = "AKIA" + "QWERTYUIOPASDFGH"
        try "AWS_KEY=\(key)".write(toFile: path, atomically: true, encoding: .utf8)
        let findings = try scanFile(at: path)
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
        // WO-542: preserve structured DB detection through explicit test opt-in.
        let findings = try scanFile(
            at: path,
            config: TestConfigHelper.configWithAmbiguousAdvisories([.dbConnectionString])
        )
        XCTAssertFalse(findings.isEmpty, "JSON file should detect secrets in values")
        XCTAssertTrue(findings.contains { $0.type == .dbConnectionString })
    }

    func testNonExistentFileNoFindings() throws {
        let findings = try scanFile(at: testDir + "/does-not-exist.txt")
        XCTAssertTrue(findings.isEmpty, "Non-existent file should return no findings")
    }

    // WO-588@v2: missing paths and valid empty files retain their allow behavior.
    func testFileGuardAllowsMissingAndValidEmptyFiles() throws {
        let missingPath = testDir + "/missing.txt"
        let emptyPath = testDir + "/empty.txt"
        try Data().write(to: URL(fileURLWithPath: emptyPath))

        for operation in [FileGuard.Operation.read, .write] {
            XCTAssertNoThrow(
                try FileGuard.check(
                    filePath: missingPath,
                    failOnSeverity: .high,
                    operation: operation
                )
            )
            XCTAssertNoThrow(
                try FileGuard.check(
                    filePath: emptyPath,
                    failOnSeverity: .high,
                    operation: operation
                )
            )
        }
    }

    // WO-588@v2: invalid lead and embedded UTF-8 sequences block both operations.
    func testFileGuardBlocksInvalidUTF8ForReadAndWrite() throws {
        let invalidLeadPath = testDir + "/invalid-lead.txt"
        let embeddedInvalidPath = testDir + "/embedded-invalid.txt"
        try Data([0xFF, 0x61]).write(to: URL(fileURLWithPath: invalidLeadPath))
        try Data([0x61, 0xC3, 0x28, 0x62]).write(to: URL(fileURLWithPath: embeddedInvalidPath))

        for operation in [FileGuard.Operation.read, .write] {
            assertFileGuardBlocks(path: invalidLeadPath, operation: operation)
            assertFileGuardBlocks(path: embeddedInvalidPath, operation: operation)
        }
    }

    // WO-588@v2: an existing path that cannot be read as file content fails closed.
    func testFileGuardBlocksReadFailureForReadAndWrite() {
        let directoryPath = testDir + "/not-a-file"
        try? FileManager.default.createDirectory(
            atPath: directoryPath,
            withIntermediateDirectories: false
        )

        for operation in [FileGuard.Operation.read, .write] {
            assertFileGuardBlocks(path: directoryPath, operation: operation)
        }
    }

    func testInlineAllowSuppressesFinding() throws {
        let path = testDir + "/config.env"
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        try "AWS_KEY=\(key) # pastewatch:allow".write(
            toFile: path, atomically: true, encoding: .utf8)
        let findings = try scanFile(at: path)
        XCTAssertTrue(findings.isEmpty, "Inline allow should suppress the finding")
    }

    func testConfigAllowlistSuppressesFinding() throws {
        let path = testDir + "/config.env"
        let key = "AKIA" + "QWERTYUIOPASDFGH"
        try "AWS_KEY=\(key)".write(toFile: path, atomically: true, encoding: .utf8)
        var allowedConfig = config
        allowedConfig.allowedValues = [key]

        let findings = try scanFile(at: path, config: allowedConfig)

        XCTAssertTrue(findings.isEmpty, "config allowlist should suppress the finding")
    }

    func testKnownTestCredentialIsConsistentlySuppressed() throws {
        let path = testDir + "/config.env"
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        try "AWS_KEY=\(key)".write(toFile: path, atomically: true, encoding: .utf8)

        let findings = try scanFile(at: path)

        XCTAssertTrue(findings.isEmpty, "known examples should not block file access")
    }

    func testLowSeverityThresholdCatchesMore() throws {
        let path = testDir + "/data.txt"
        // IP address is medium severity
        try "server: 10.0.1.50".write(toFile: path, atomically: true, encoding: .utf8)
        // WO-542: preserve severity behavior through explicit IP opt-in.
        let findings = try scanFile(
            at: path,
            failOnSeverity: .low,
            config: TestConfigHelper.configWithAmbiguousAdvisories([.ipAddress])
        )
        XCTAssertFalse(findings.isEmpty, "Low threshold should catch medium severity findings")
    }

    func testWorkledgerKeyDetectedByGuardScan() throws {
        let path = testDir + "/key.txt"
        let key = "wl_sk_" + String(repeating: "X", count: 44)
        try "API_KEY=\(key)".write(toFile: path, atomically: true, encoding: .utf8)
        let findings = try scanFile(at: path)
        XCTAssertFalse(findings.isEmpty, "Workledger key should be detected by guard scan")
        XCTAssertTrue(findings.contains { $0.type == .workledgerKey })
    }

    // WO-128: guard scan logic must fail closed when shared patterns cannot load.
    func testGuardScanFailsClosedForMissingSharedPatternFile() throws {
        let path = testDir + "/clean.txt"
        try "clean=true\n".write(toFile: path, atomically: true, encoding: .utf8)

        var scanConfig = config
        scanConfig.sharedPatternFiles = [testDir + "/missing-shared-patterns.json"]

        XCTAssertThrowsError(try scanFile(at: path, config: scanConfig)) { error in
            XCTAssertTrue(error.localizedDescription.contains("sharedPatternFiles"))
            XCTAssertTrue(error.localizedDescription.contains("could not read"))
        }
    }

    func testPathProtectionBlocksOpenClawDir() {
        let config = PastewatchConfig.defaultConfig
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        XCTAssertTrue(config.isPathProtected(home + "/.openclaw/workledger.key"),
                      "Guard should block access to ~/.openclaw/ by default")
    }

    // WO-588@v2: both file guard operations must use the same blocked exit contract.
    private func assertFileGuardBlocks(path: String, operation: FileGuard.Operation) {
        XCTAssertThrowsError(
            try FileGuard.check(
                filePath: path,
                failOnSeverity: .high,
                operation: operation
            )
        ) { error in
            XCTAssertEqual((error as? ExitCode)?.rawValue, GuardExitContract.blocked)
        }
    }
}
