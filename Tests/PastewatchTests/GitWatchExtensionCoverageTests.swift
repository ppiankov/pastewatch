import XCTest
@testable import PastewatchCore

// WO-662@v3: shared extension coverage reaches staged scans, history and the live watcher.
final class GitWatchExtensionCoverageTests: XCTestCase {
    // WO-662@v3: subprocess status is kept separate from captured diagnostics.
    private struct CommandResult {
        let status: Int32
        let output: Data
        let errors: Data
    }

    // WO-662@v3: staged Kotlin findings must reach the pre-commit scan surface.
    func testStagedKotlinIntrinsicFinding() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try makeGitFixture(root)
            try kotlinContent().write(to: root.appendingPathComponent("Main.kt"), atomically: true, encoding: .utf8)
            XCTAssertEqual(try git(["add", "Main.kt"], root: root).status, 0)
            let response = try command(executable(), ["scan", "--git-diff", "--staged", "--check"], root: root)
            XCTAssertEqual(response.status, 6)
            let diagnostics = try XCTUnwrap(String(data: response.errors, encoding: .utf8))
            XCTAssertTrue(diagnostics.contains("Main.kt"))
            XCTAssertTrue(diagnostics.contains("AWS Key"))
            let defaultResponse = try command(executable(), ["scan", "--git-diff", "--check"], root: root)
            XCTAssertEqual(defaultResponse.status, response.status)
            XCTAssertEqual(defaultResponse.errors, response.errors)
        }
    }

    // WO-662@v3: committed Kotlin findings must reach the history scan surface.
    func testCommittedKotlinIntrinsicFinding() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try makeGitFixture(root)
            try kotlinContent().write(to: root.appendingPathComponent("Main.kt"), atomically: true, encoding: .utf8)
            XCTAssertEqual(try git(["add", "Main.kt"], root: root).status, 0)
            try commitFixture(root)
            let response = try command(executable(), ["scan", "--git-log", "--check", "--format", "json"], root: root)
            XCTAssertEqual(response.status, 6)
            let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: response.output) as? [String: Any])
            let findings = try XCTUnwrap(payload["findings"] as? [[String: Any]])
            XCTAssertEqual(findings.count, 1)
            XCTAssertEqual(findings.first?["file"] as? String, "Main.kt")
            let matches = try XCTUnwrap(findings.first?["matches"] as? [[String: Any]])
            XCTAssertEqual(matches.count, 1)
            XCTAssertEqual(matches.first?["type"] as? String, "AWS Key")
        }
    }

    // WO-662@v3: the shared classifier includes transcript formats as well as Kotlin source.
    func testGitGateUsesAddedExtensions() {
        for ext in ["kt", "kts", "gradle", "jsonl", "ndjson"] {
            XCTAssertTrue(GitScanHelpers.shouldScanFile("nested/source." + ext))
            XCTAssertTrue(GitScanHelpers.shouldScanFile("nested/source." + ext.uppercased()))
        }
        XCTAssertFalse(GitScanHelpers.shouldScanFile("nested/source.unsupported"))
    }

    // WO-662@v3: staged and historical source blobs share Latin-1 detection and counted long-line skips.
    func testStagedAndHistoryLatin1AndLongLineCoverage() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try makeGitFixture(root)
            let key = "AKIA" + String(repeating: "Q", count: 16)
            var bytes = Data([0xE9, 0x0A])
            bytes.append(Data((key + "\n").utf8))
            let source = root.appendingPathComponent("source.sql")
            try bytes.write(to: source)
            try Data([0xE9, 0x0A]).write(to: root.appendingPathComponent("clean.c"))
            try Data(repeating: 0x78, count: 1_500_000).write(to: root.appendingPathComponent("long.jsonl"))
            XCTAssertEqual(try git(["add", "source.sql", "clean.c", "long.jsonl"], root: root).status, 0)
            let staged = try command(executable(), ["scan", "--git-diff", "--staged", "--check"], root: root)
            XCTAssertEqual(staged.status, 6)
            let diagnostics = try XCTUnwrap(String(data: staged.errors, encoding: .utf8))
            XCTAssertTrue(diagnostics.contains("source.sql"))
            XCTAssertTrue(diagnostics.contains("long.jsonl"))
            XCTAssertTrue(diagnostics.contains("skippedOverLimit=1"))
            try commitFixture(root)
            let history = try command(executable(), ["scan", "--git-log", "--check"], root: root)
            XCTAssertEqual(history.status, 6)
            XCTAssertTrue(try XCTUnwrap(String(data: history.errors, encoding: .utf8)).contains("skippedOverLimit=1"))
            try FileManager.default.removeItem(at: source)
            XCTAssertEqual(try git(["add", "source.sql"], root: root).status, 0)
            let clean = try command(executable(), ["scan", "--git-diff", "--staged", "--check"], root: root)
            XCTAssertEqual(clean.status, 0)
        }
    }

    // WO-662@v3: clean staged Latin-1 source and an overlong transcript do not abort the scan.
    func testCleanStagedLatin1AndOverlongTranscript() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try makeGitFixture(root)
            try Data([0xE9, 0x0A]).write(to: root.appendingPathComponent("clean.c"))
            try Data(repeating: 0x78, count: 1_500_000).write(to: root.appendingPathComponent("long.jsonl"))
            XCTAssertEqual(try git(["add", "clean.c", "long.jsonl"], root: root).status, 0)
            let response = try command(executable(), ["scan", "--git-diff", "--staged", "--check"], root: root)
            XCTAssertEqual(response.status, 0)
            let diagnostics = try XCTUnwrap(String(data: response.errors, encoding: .utf8))
            XCTAssertTrue(diagnostics.contains("long.jsonl"))
            XCTAssertTrue(diagnostics.contains("skippedOverLimit=1"))
        }
    }

    // WO-674@v2: the sole live watch smoke changes its fixture only after snapshot readiness.
    func testWatcherReportsKotlinChange() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let input = root.appendingPathComponent("input", isDirectory: true)
            try FileManager.default.createDirectory(at: input, withIntermediateDirectories: true)
            let file = input.appendingPathComponent("Main.kt")
            try "// clean\n".write(to: file, atomically: true, encoding: .utf8)
            let process = Process()
            let diagnostics = Pipe()
            process.executableURL = executable()
            process.arguments = ["watch", "--dir", input.path]
            process.currentDirectoryURL = root
            // WO-672@v1: child scans cannot load the operator's global configuration.
            process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin", "PW_GUARD": "1"])
            process.standardOutput = FileHandle.nullDevice
            process.standardError = diagnostics
            // WO-674@v2: distinguish completed initialization from a subsequent reported event.
            let ready = expectation(description: "Watcher completed the initial snapshot")
            let reported = expectation(description: "Kotlin change produces an intrinsic finding")
            let observation = WatchObservation(ready: ready, reported: reported)
            diagnostics.fileHandleForReading.readabilityHandler = { handle in observation.receive(handle.availableData) }
            try process.run()
            // WO-674@v2: fixture cleanup and process shutdown run even if readiness fails.
            defer {
                if process.isRunning { process.terminate() }
                process.waitUntilExit()
                diagnostics.fileHandleForReading.readabilityHandler = nil
                try? diagnostics.fileHandleForReading.close()
            }
            // WO-674@v2: the timeout is a smoke-test watchdog, not a repeated-touch scheduling assumption.
            wait(for: [ready], timeout: 20)
            try kotlinContent().write(to: file, atomically: true, encoding: .utf8)
            let fixtureEpoch: TimeInterval = 2_000_000_000
            try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: fixtureEpoch)],
                                                  ofItemAtPath: file.path)
            wait(for: [reported], timeout: 20)
        }
    }

    // WO-674@v2: readiness and finding observations retain metadata only across fragmented reads.
    private final class WatchObservation {
        private let reported: XCTestExpectation
        private let ready: XCTestExpectation // WO-674@v2: initialization must precede the fixture edit.
        private let lock = NSLock()
        private var pending = Data()
        private var found = false
        private var isReady = false // WO-674@v2: fragmented readiness diagnostics fulfill once.

        // WO-674@v2: the smoke test separates startup synchronization from event delivery.
        init(ready: XCTestExpectation, reported: XCTestExpectation) {
            self.ready = ready
            self.reported = reported
        }

        // WO-674@v2: recognize complete readiness and type-only finding lines without elapsed-time polling.
        func receive(_ data: Data) {
            lock.lock()
            defer { lock.unlock() }
            guard !data.isEmpty, !found else { return }
            pending.append(data)
            while let newline = pending.firstIndex(of: 0x0A) {
                let line = String(data: pending[..<newline], encoding: .utf8)
                pending.removeSubrange(...newline)
                // WO-674@v2: the earlier CLI banner is not the snapshot-completion handshake.
                if !isReady, line?.hasPrefix("watching ") == true, line?.hasSuffix(" ready") == true {
                    isReady = true
                    ready.fulfill()
                }
                if line?.contains("Main.kt:1 AWS Key:") == true {
                    found = true
                    reported.fulfill()
                    return
                }
            }
        }
    }

    // WO-662@v3: intrinsic fixtures are assembled only in test-owned memory.
    private func kotlinContent() -> String {
        "val value = \"" + "AKIA" + String(repeating: "Q", count: 16) + "\"\n"
    }

    // WO-662@v3: subprocess fixtures select project policy before any global fallback.
    private func makeGitFixture(_ root: URL) throws {
        try TestConfigHelper.ensureProjectConfig(in: root)
        XCTAssertEqual(try git(["init", "--quiet"], root: root).status, 0)
        try "// clean\n".write(to: root.appendingPathComponent("README.md"), atomically: true, encoding: .utf8)
        XCTAssertEqual(try git(["add", "README.md"], root: root).status, 0)
        try commitFixture(root)
    }

    // WO-662@v3: synthetic history uses real Git commit objects without bypassing repository hooks.
    private func commitFixture(_ root: URL) throws {
        let tree = try git(["write-tree"], root: root)
        XCTAssertEqual(tree.status, 0)
        let treeID = try XCTUnwrap(String(data: tree.output, encoding: .utf8)).trimmingCharacters(in: .whitespacesAndNewlines)
        let commit = try git(["commit-tree", treeID, "-m", "fixture"], root: root)
        XCTAssertEqual(commit.status, 0)
        let commitID = try XCTUnwrap(String(data: commit.output, encoding: .utf8)).trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(try git(["update-ref", "HEAD", commitID], root: root).status, 0)
    }

    // WO-662@v3: fixture Git operations never inherit an operator identity or credentials.
    private func git(_ arguments: [String], root: URL) throws -> CommandResult {
        try command(URL(fileURLWithPath: "/usr/bin/git"), arguments, root: root)
    }

    // WO-662@v3: command capture keeps all fixture content out of test output.
    // WO-672@v1: environment pinning cannot discard the DEBUG configuration seam.
    private func command(_ executable: URL, _ arguments: [String], root: URL) throws -> CommandResult {
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-672@v1: preserve the fixture global path when pinning subprocess environment.
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

    // WO-662@v3: executable lookup is independent of fixture CWD.
    private func executable() -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
    }
}
