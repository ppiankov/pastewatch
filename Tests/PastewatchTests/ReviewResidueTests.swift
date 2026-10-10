import XCTest
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-675@v2: pin coverage diagnostics and shared directory consumers without changing detector policy.
final class ReviewResidueTests: XCTestCase {
    private struct CommandResult {
        let status: Int32
        let output: Data
        let errors: Data
    }

    // WO-675@v2: a value accumulator records skips without emitting process output.
    func testStatisticsAccumulatorHasNoOutput() throws {
        var statistics = DirectoryScanStatistics()
        let diagnostic = try captureError {
            statistics.recordOverLimit(path: "long.jsonl", error: .lineBytes(line: 1, actual: 33, maximum: 32))
        }
        XCTAssertEqual(statistics.skippedOverLimit, 1)
        XCTAssertTrue(diagnostic.isEmpty)
    }

    // WO-675@v2: a directory caller emits one path-only diagnostic for each over-limit skip.
    func testDirectorySkipDiagnosticOnce() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try writeLongLine(in: root)
            var skipped = 0
            let diagnostic = try captureError {
                let report = try DirectoryScanner.scanWithStatistics(directory: root.path, config: .defaultConfig, limits: smallLimits())
                skipped = report.statistics.skippedOverLimit
            }
            XCTAssertEqual(skipped, 1)
            assertOneSkip(diagnostic)
        }
    }

    // WO-675@v2: staged scanning keeps one diagnostic after separating counting from output.
    func testGitDiffSkipDiagnosticOnce() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try makeGitFixture(root)
            try writeLongLine(in: root)
            XCTAssertEqual(try git(["add", "long.jsonl"], root: root).status, 0)
            var skipped = 0
            let diagnostic = try captureError {
                skipped = try GitDiffScanner.scanWithStatistics(config: .defaultConfig, limits: smallLimits()).statistics.skippedOverLimit
            }
            XCTAssertEqual(skipped, 1)
            assertOneSkip(diagnostic)
        }
    }

    // WO-675@v2: history scanning reports a skipped blob once without exposing its bytes.
    func testGitHistorySkipDiagnosticOnce() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try makeGitFixture(root)
            try writeLongLine(in: root)
            XCTAssertEqual(try git(["add", "long.jsonl"], root: root).status, 0)
            try commitFixture(root)
            let diagnostic = try captureError {
                _ = try GitHistoryScanner.scan(config: .defaultConfig, limits: smallLimits())
            }
            assertOneSkip(diagnostic)
        }
    }

    // WO-675@v2: the production watcher diagnostic remains single and counted without polling.
    func testWatcherSkipDiagnosticOnce() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let watcher = FileWatcher(directory: root.path, config: .defaultConfig)
            let diagnostic = try captureError {
                watcher.reportOverLimit(relativePath: "long.jsonl", error: .lineBytes(line: 1, actual: 33, maximum: 32))
            }
            assertOneSkip(diagnostic)
            XCTAssertTrue(diagnostic.contains("skippedOverLimit=1"))
        }
    }

    // WO-675@v2: unsupported binary assets are not counted as unsupported text.
    func testUnsupportedBinaryGetsOwnCounter() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try Data([0, 65, 66]).write(to: root.appendingPathComponent("asset.png"))
            try "ordinary text".write(to: root.appendingPathComponent("source.unknown"), atomically: true, encoding: .utf8)
            let report = try DirectoryScanner.scanWithStatistics(directory: root.path, config: .defaultConfig)
            XCTAssertEqual(report.statistics.skippedBinary, 1)
            XCTAssertEqual(report.statistics.skippedUnsupported, 1)
            XCTAssertEqual(report.statistics.filesScanned, 0)
        }
    }

    // WO-675@v2: a findings-free staged scan still reports its measured coverage on stderr.
    func testGitDiffCoverageSummaryForCleanStagedFile() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try makeGitFixture(root)
            try "ordinary text\n".write(to: root.appendingPathComponent("clean.md"), atomically: true, encoding: .utf8)
            XCTAssertEqual(try git(["add", "clean.md"], root: root).status, 0)
            let result = try cli(["scan", "--git-diff", "--staged", "--check"], root: root)
            XCTAssertEqual(result.status, 0)
            XCTAssertTrue(result.output.isEmpty)
            let diagnostics = try text(result.errors)
            XCTAssertTrue(diagnostics.contains("Scanned 1 files. Found 0 findings."))
            XCTAssertEqual(diagnostics.components(separatedBy: "Scanned ").count - 1, 1)
        }
    }

    // WO-675@v2: keep the explicit staged alias and document its default semantics in CLI help.
    func testStagedFlagDocumentsDefault() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let result = try cli(["scan", "--help"], root: root)
            XCTAssertEqual(result.status, 0)
            XCTAssertTrue(try text(result.output).contains("Scan staged changes (the default; requires --git-diff)"))
        }
    }

    // WO-675@v2: guard size advice distinguishes raw-file measurement from the MCP placeholder view.
    func testReadWindowHintStatesRawSize() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let value = "AKIA" + String(repeating: "Q", count: 16)
            let content = value + "\n" + String(repeating: "x", count: MCPReadDecision.unrangedResponseLimitBytes)
            let path = root.appendingPathComponent("large.txt")
            try content.write(to: path, atomically: true, encoding: .utf8)
            let result = try cli(["guard-read", path.path], root: root)
            XCTAssertEqual(result.status, 2)
            let output = try text(result.output)
            XCTAssertTrue(output.contains("raw file bytes"))
            XCTAssertTrue(output.contains("placeholder view"))
            XCTAssertFalse(output.contains(value))
        }
    }

    // WO-675@v2: remediation planning processes a Kotlin finding through the existing directory API.
    func testFixHandlesKotlinFinding() throws {
        try withKotlinFixture { root, input in
            let result = try cli(["fix", "--dir", input.path, "--dry-run"], root: root)
            XCTAssertEqual(result.status, 0)
            let diagnostics = try text(result.errors)
            XCTAssertTrue(diagnostics.contains("Main.kt:1  AWS Key"))
            XCTAssertTrue(diagnostics.contains("1 secrets -> 1 env vars."))
        }
    }

    // WO-675@v2: baseline creation records Kotlin findings without printing their values.
    func testBaselineHandlesKotlinFinding() throws {
        try withKotlinFixture { root, input in
            let path = root.appendingPathComponent("baseline.json")
            let result = try cli(["baseline", "create", "--dir", input.path, "--output", path.path], root: root)
            XCTAssertEqual(result.status, 0)
            let baseline = try BaselineFile.load(from: path.path)
            XCTAssertEqual(baseline.entries.count, 1)
            XCTAssertEqual(baseline.entries.first?.filePath, "Main.kt")
        }
    }

    // WO-675@v2: inventory output retains a Kotlin finding in the existing report schema.
    func testInventoryHandlesKotlinFinding() throws {
        try withKotlinFixture { root, input in
            let result = try cli(["inventory", "--dir", input.path, "--format", "json"], root: root)
            XCTAssertEqual(result.status, 0)
            let report = try JSONDecoder().decode(InventoryReport.self, from: result.output)
            XCTAssertEqual(report.totalFindings, 1)
            XCTAssertEqual(report.filesAffected, 1)
            XCTAssertEqual(report.entries.first?.filePath, "Main.kt")
        }
    }

    // WO-675@v2: posture runs the real repository scanner while injecting only remote cloning and emission.
    func testPostureHandlesKotlinFinding() throws {
        try withKotlinFixture { _, input in
            let command = try Posture.parse(["--repos", "fixture/source"])
            var report: PostureReport?
            _ = try captureError {
                try command.run(config: .defaultConfig, cloneRepo: { _, _, _ in input.path }, scanRepo: {
                    try PostureScanner.scanRepo(at: $0, name: $1, config: $2)
                }, emitReport: { report = $0 })
            }
            XCTAssertEqual(report?.totalFindings, 1)
            XCTAssertEqual(report?.repositories.first?.filesAffected, 1)
            XCTAssertEqual(report?.repositories.first?.hotSpots.first?.filePath, "Main.kt")
        }
    }

    // WO-675@v2: small injected limits make skip diagnostics independent of machine load.
    private func smallLimits() -> ScanInputLimits {
        ScanInputLimits(maximumFileBytes: 4096, maximumLineBytes: 32)
    }

    // WO-675@v2: the over-limit fixture contains no secret and stays out of test diagnostics.
    private func writeLongLine(in root: URL) throws {
        try String(repeating: "x", count: 33).write(to: root.appendingPathComponent("long.jsonl"), atomically: true, encoding: .utf8)
    }

    // WO-675@v2: path-only diagnostic assertions never print the scanned content on failure.
    private func assertOneSkip(_ diagnostic: String) {
        XCTAssertEqual(diagnostic.components(separatedBy: "Skipped over-limit file long.jsonl:").count - 1, 1)
        XCTAssertFalse(diagnostic.contains(String(repeating: "x", count: 33)))
    }

    // WO-675@v2: all command consumers share the same isolated runtime-built intrinsic fixture.
    private func withKotlinFixture(_ body: (URL, URL) throws -> Void) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let input = root.appendingPathComponent("input", isDirectory: true)
            try FileManager.default.createDirectory(at: input, withIntermediateDirectories: true)
            let value = "AKIA" + String(repeating: "Q", count: 16)
            try ("val value = \"" + value + "\"\n").write(to: input.appendingPathComponent("Main.kt"), atomically: true, encoding: .utf8)
            try body(root, input)
        }
    }

    // WO-675@v2: synthetic Git history uses only a test-owned repository and real commit objects.
    private func makeGitFixture(_ root: URL) throws {
        try TestConfigHelper.ensureProjectConfig(in: root)
        XCTAssertEqual(try git(["init", "--quiet"], root: root).status, 0)
        try "ordinary text\n".write(to: root.appendingPathComponent("README.md"), atomically: true, encoding: .utf8)
        XCTAssertEqual(try git(["add", "README.md"], root: root).status, 0)
        try commitFixture(root)
    }

    // WO-675@v2: fixture commits bypass neither product hooks nor any operator repository.
    private func commitFixture(_ root: URL) throws {
        let tree = try text(git(["write-tree"], root: root).output).trimmingCharacters(in: .whitespacesAndNewlines)
        var arguments = ["commit-tree", tree, "-m", "fixture"]
        let parent = try git(["rev-parse", "--verify", "HEAD"], root: root)
        if parent.status == 0 { arguments += ["-p", try text(parent.output).trimmingCharacters(in: .whitespacesAndNewlines)] }
        let commit = try git(arguments, root: root)
        XCTAssertEqual(commit.status, 0)
        let identifier = try text(commit.output).trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(try git(["update-ref", "HEAD", identifier], root: root).status, 0)
    }

    // WO-675@v2: command tests pin enforcement instead of inheriting a disabled guard environment.
    private func cli(_ arguments: [String], root: URL) throws -> CommandResult {
        let executable = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
        return try run(executable, arguments, root: root)
    }

    // WO-675@v2: Git fixture operations use the system executable without searching operator PATH entries.
    private func git(_ arguments: [String], root: URL) throws -> CommandResult {
        try run(URL(fileURLWithPath: "/usr/bin/git"), arguments, root: root)
    }

    // WO-675@v2: captured subprocess output is assertion input only, never test log output.
    private func run(_ executable: URL, _ arguments: [String], root: URL) throws -> CommandResult {
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.currentDirectoryURL = root
        process.environment = TestConfigHelper.subprocessEnvironment([
            "PATH": "/usr/bin:/bin", "PW_GUARD": "1",
            "GIT_AUTHOR_NAME": "ppiankov", "GIT_AUTHOR_EMAIL": "103106369+ppiankov@users.noreply.github.com",
            "GIT_COMMITTER_NAME": "ppiankov", "GIT_COMMITTER_EMAIL": "103106369+ppiankov@users.noreply.github.com"
        ])
        process.standardOutput = output
        process.standardError = errors
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let diagnostics = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, output: data, errors: diagnostics)
    }

    // WO-675@v2: UTF-8 decoding errors fail a fixture without printing captured bytes.
    private func text(_ data: Data) throws -> String {
        try XCTUnwrap(String(data: data, encoding: .utf8))
    }

    // WO-675@v2: descriptor capture restores stderr on throws and avoids asynchronous watch timing.
    private func captureError(_ body: () throws -> Void) throws -> String {
        let pipe = Pipe()
        fflush(stderr)
        let saved = dup(STDERR_FILENO)
        guard saved >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(saved) }
        guard dup2(pipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO) >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { dup2(saved, STDERR_FILENO) }
        try body()
        fflush(stderr)
        dup2(saved, STDERR_FILENO)
        try pipe.fileHandleForWriting.close()
        return try text(pipe.fileHandleForReading.readDataToEndOfFile())
    }
}
