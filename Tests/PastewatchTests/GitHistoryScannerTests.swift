import XCTest
@testable import PastewatchCore

final class GitHistoryScannerTests: XCTestCase {

    // WO-529@v3: Config with credential type enabled for git history tests.
    let credentialConfig: PastewatchConfig = {
        var config = PastewatchConfig.defaultConfig
        if !config.enabledTypes.contains(SensitiveDataType.credential.rawValue) {
            config.enabledTypes.append(SensitiveDataType.credential.rawValue)
        }
        return config
    }()

    // MARK: - Commit chunk parsing

    func testParseCommitChunksSimple() {
        let output = """
        PWCOMMIT abc1234 user@test.com 2025-01-15T12:00:00+00:00
        diff --git a/file.py b/file.py
        new file mode 100644
        --- /dev/null
        +++ b/file.py
        @@ -0,0 +1,3 @@
        +import os
        +SECRET = "hunter2"
        +print("hello")
        """
        let chunks = GitHistoryScanner.parseCommitChunks(output)
        XCTAssertEqual(chunks.count, 1)
        XCTAssertEqual(chunks[0].hash, "abc1234")
        XCTAssertEqual(chunks[0].author, "user@test.com")
        XCTAssertEqual(chunks[0].date, "2025-01-15T12:00:00+00:00")
        XCTAssertTrue(chunks[0].diffContent.contains("diff --git"))
    }

    func testParseCommitChunksMultiple() {
        let output = """
        PWCOMMIT aaa1111 alice@test.com 2025-01-10T10:00:00+00:00
        diff --git a/a.py b/a.py
        --- /dev/null
        +++ b/a.py
        @@ -0,0 +1 @@
        +x = 1
        PWCOMMIT bbb2222 bob@test.com 2025-01-11T11:00:00+00:00
        diff --git a/b.py b/b.py
        --- /dev/null
        +++ b/b.py
        @@ -0,0 +1 @@
        +y = 2
        """
        let chunks = GitHistoryScanner.parseCommitChunks(output)
        XCTAssertEqual(chunks.count, 2)
        XCTAssertEqual(chunks[0].hash, "aaa1111")
        XCTAssertEqual(chunks[1].hash, "bbb2222")
        XCTAssertEqual(chunks[1].author, "bob@test.com")
    }

    func testParseCommitChunksEmpty() {
        let chunks = GitHistoryScanner.parseCommitChunks("")
        XCTAssertTrue(chunks.isEmpty)
    }

    func testParseCommitChunksNoDiff() {
        // Commit with no file changes (e.g., merge commit with no diff)
        let output = """
        PWCOMMIT ccc3333 charlie@test.com 2025-01-12T12:00:00+00:00
        """
        let chunks = GitHistoryScanner.parseCommitChunks(output)
        XCTAssertEqual(chunks.count, 1)
        XCTAssertTrue(chunks[0].diffContent.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    }

    // MARK: - Integration tests (require temp git repo)

    func testScanRepoWithSecretInHistory() throws {
        let tempDir = try createTempGitRepo()
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        let confPath = tempDir + "/config.txt"
        let secret = ["password=hunter", "2inhistory"].joined()

        // Commit 1: add secret
        try secret.write(toFile: confPath, atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "add config"])

        // Commit 2: remove secret
        try "password=REDACTED".write(toFile: confPath, atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "redact"])

        // Save CWD and change to temp dir
        let originalDir = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tempDir)
        defer { FileManager.default.changeCurrentDirectoryPath(originalDir) }

        // WO-542: history fixtures explicitly enable generic credential detection.
        let config = credentialConfig
        let result = try GitHistoryScanner.scan(config: config)

        XCTAssertEqual(result.commitsScanned, 2)
        XCTAssertFalse(result.findings.isEmpty, "Should find secret in first commit")

        // The secret should be attributed to the first commit
        let finding = result.findings[0]
        XCTAssertEqual(finding.filePath, "config.txt")
        XCTAssertTrue(finding.matches.contains(where: { $0.type == .credential }))
    }

    func testScanRepoDeduplicatesAcrossCommits() throws {
        let tempDir = try createTempGitRepo()
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        let confPath = tempDir + "/config.txt"
        let secret = ["api_key=sk_live_", "test1234567890abcdef"].joined()

        // Commit 1: add secret
        try secret.write(toFile: confPath, atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "add key"])

        // Commit 2: add another line but keep same secret
        try (secret + "\ndebug=true").write(toFile: confPath, atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "add debug"])

        let originalDir = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tempDir)
        defer { FileManager.default.changeCurrentDirectoryPath(originalDir) }

        // WO-542: dedup coverage uses the same explicit credential policy.
        let config = credentialConfig
        let result = try GitHistoryScanner.scan(config: config)

        // Same secret should appear only once (from first commit)
        let credentialFindings = result.findings.flatMap { $0.matches }
            .filter { $0.type == .credential }
        XCTAssertEqual(credentialFindings.count, 1, "Same secret should be deduplicated")
    }

    func testScanWithRangeFilter() throws {
        let tempDir = try createTempGitRepo()
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        let confPath = tempDir + "/config.txt"
        let secret1 = ["password=hunter", "2old123456"].joined()
        let secret2 = ["auth_key=hunter", "2new123456"].joined()

        // Commit 1: old secret
        try secret1.write(toFile: confPath, atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "old secret"])

        // Commit 2: add new secret on separate line
        try (secret1 + "\n" + secret2).write(toFile: confPath, atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "new secret"])

        let originalDir = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tempDir)
        defer { FileManager.default.changeCurrentDirectoryPath(originalDir) }

        // WO-542: range filtering uses the explicit credential fixture policy.
        let config = credentialConfig

        // Scan only last commit
        let result = try GitHistoryScanner.scan(range: "HEAD~1..HEAD", config: config)
        XCTAssertEqual(result.commitsScanned, 1)

        // Should find the new secret from the last commit
        XCTAssertFalse(result.findings.isEmpty, "Should find secret from last commit")
    }

    func testScanBailStopsEarly() throws {
        let tempDir = try createTempGitRepo()
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        let secret1 = ["password=hunter", "2first12345"].joined()
        let secret2 = ["auth_key=hunter", "2second12345"].joined()

        // Commit 1
        try secret1.write(toFile: tempDir + "/config.txt", atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "first"])

        // Commit 2 (different file)
        try secret2.write(toFile: tempDir + "/secrets.txt", atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "secrets.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "second"])

        let originalDir = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tempDir)
        defer { FileManager.default.changeCurrentDirectoryPath(originalDir) }

        // WO-542: bail behavior uses the explicit credential fixture policy.
        let config = credentialConfig
        let result = try GitHistoryScanner.scan(config: config, bail: true)

        // Bail: should stop after first finding
        XCTAssertEqual(result.findings.count, 1)
    }

    func testScanCleanRepoReturnsEmpty() throws {
        let tempDir = try createTempGitRepo()
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        // Commit with no secrets
        try "debug=true".write(toFile: tempDir + "/config.txt", atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "clean"])

        let originalDir = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tempDir)
        defer { FileManager.default.changeCurrentDirectoryPath(originalDir) }

        // WO-542: clean history stays empty with the explicit credential policy.
        let config = credentialConfig
        let result = try GitHistoryScanner.scan(config: config)

        XCTAssertTrue(result.findings.isEmpty)
        XCTAssertEqual(result.commitsScanned, 1)
    }

    // WO-128: git history scans must fail closed when shared patterns cannot load.
    func testScanFailsClosedForMissingSharedPatternFile() throws {
        let tempDir = try createTempGitRepo()
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        try "clean=true\n".write(toFile: tempDir + "/config.txt", atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "clean"])

        let originalDir = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tempDir)
        defer { FileManager.default.changeCurrentDirectoryPath(originalDir) }

        var config = PastewatchConfig.defaultConfig
        config.sharedPatternFiles = [tempDir + "/missing-shared-patterns.json"]

        XCTAssertThrowsError(try GitHistoryScanner.scan(config: config)) { error in
            XCTAssertTrue(error.localizedDescription.contains("sharedPatternFiles"))
            XCTAssertTrue(error.localizedDescription.contains("could not read"))
        }
    }

    // MARK: - Helpers

    private func createTempGitRepo() throws -> String {
        let tempDir = NSTemporaryDirectory() + "pw-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
        try runShell("git", args: ["-C", tempDir, "init"])
        try runShell("git", args: ["-C", tempDir, "config", "user.email", "test@test.com"])
        try runShell("git", args: ["-C", tempDir, "config", "user.name", "Test"])
        return tempDir
    }

    @discardableResult
    private func runShell(_ cmd: String, args: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/\(cmd)")
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "shell", code: Int(process.terminationStatus))
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
