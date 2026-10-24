import XCTest
// WO-726@v1: child CPU accounting and bounded teardown must work on both supported platforms.
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
@testable import PastewatchCore

// WO-662@v3: shared extension coverage reaches staged scans, history and the live watcher.
final class GitWatchExtensionCoverageTests: XCTestCase {
    // WO-726@v1: allow several unchanged poll periods while bounding a silently stalled watcher.
    private static let runLoopWatchdog: TimeInterval = 15
    private static let idleObservationSeconds: TimeInterval = 5
    private static let idleCPUAllowance: TimeInterval = 0.5
    private static let microsecondsPerSecond: Double = 1_000_000

    // WO-726@v1: Git completion after readiness exercises the child-process path that needs a live main run loop.
    func testWatchGitChildScanKeepsMainRunLoopAlive() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let input = try makeRunLoopFixture(root)
            let home = root.appendingPathComponent("git-home", isDirectory: true)
            try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            let trace = root.appendingPathComponent("git-events.trace")
            try ("[trace2]\n\teventTarget = " + trace.path + "\n").write(
                to: home.appendingPathComponent(".gitconfig"), atomically: true, encoding: .utf8)
            let ready = expectation(description: "Git-aware watcher ready")
            let reported = expectation(description: "Changed Git-backed file reported")
            let observation = WatchObservation(ready: ready, reported: reported)
            let session = RunLoopWatchSession(executable: executable(), root: root, input: input,
                                              observation: observation, environment: ["HOME": home.path])
            try session.start()
            defer { try? session.stop() }
            guard XCTWaiter().wait(for: [ready], timeout: Self.runLoopWatchdog) == .completed else {
                return XCTFail(watchFailure("readiness", process: session.process, observation: observation))
            }
            try Data().write(to: trace)
            let file = input.appendingPathComponent("Main.kt")
            try kotlinContent().write(to: file, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 2_000_000_000)],
                                                  ofItemAtPath: file.path)
            let completed = XCTWaiter().wait(for: [reported], timeout: Self.runLoopWatchdog) == .completed
            try session.stop()
            XCTAssertTrue(completed, watchFailure("finding report", process: session.process, observation: observation))
            XCTAssertFalse(session.diagnostics.mainThreadExited, "Watcher must retain its main run-loop thread")
            let events = try String(contentsOf: trace, encoding: .utf8)
            XCTAssertTrue(events.contains("rev-parse"), "Changed-file scan launched the Git child")
            XCTAssertTrue(events.contains("\"event\":\"exit\""), "Changed-file Git child completed")
            XCTAssertEqual(session.process.terminationStatus, 0, "SIGINT handling remains unchanged")
        }
    }

    // WO-726@v1: lifetime child CPU is a conservative upper bound on the five-second idle window.
    func testIdleWatchUsesLessThanHalfASecondOfCPU() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let input = try makeRunLoopFixture(root)
            let ready = expectation(description: "Idle watcher ready")
            let reported = expectation(description: "No changed file during idle observation")
            reported.isInverted = true
            let observation = WatchObservation(ready: ready, reported: reported)
            let session = RunLoopWatchSession(executable: executable(), root: root, input: input, observation: observation)
            let before = try childCPUSeconds()
            try session.start()
            defer { try? session.stop() }
            guard XCTWaiter().wait(for: [ready], timeout: Self.runLoopWatchdog) == .completed else {
                return XCTFail(watchFailure("readiness", process: session.process, observation: observation))
            }
            XCTAssertEqual(XCTWaiter().wait(for: [reported], timeout: Self.idleObservationSeconds), .completed)
            XCTAssertTrue(session.process.isRunning, "Idle watch must remain active")
            try session.stop()
            let cpu = try childCPUSeconds() - before
            print(String(format: "WO726_IDLE_CPU_SECONDS=%.6f", cpu))
            XCTAssertLessThan(cpu, Self.idleCPUAllowance, "Idle main run loop must block, not spin")
            XCTAssertFalse(session.diagnostics.mainThreadExited)
            XCTAssertEqual(session.process.terminationStatus, 0, "SIGINT handling remains unchanged")
        }
    }

    // WO-726@v1: both live probes use a real repository and a clean initial snapshot.
    private func makeRunLoopFixture(_ root: URL) throws -> URL {
        try makeGitFixture(root)
        let input = root.appendingPathComponent("input", isDirectory: true)
        try FileManager.default.createDirectory(at: input, withIntermediateDirectories: true)
        try "// clean\n".write(to: input.appendingPathComponent("Main.kt"), atomically: true, encoding: .utf8)
        return input
    }

    // WO-726@v1: only the watcher runs between samples; reaped descendants make this bound conservative.
    private func childCPUSeconds() throws -> TimeInterval {
        var usage = rusage()
        #if os(Linux)
        let status = getrusage(Int32(RUSAGE_CHILDREN.rawValue), &usage)
        #else
        let status = getrusage(RUSAGE_CHILDREN, &usage)
        #endif
        guard status == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        return Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) +
            Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / Self.microsecondsPerSecond
    }

    // WO-726@v1: inspect every stderr fragment, including output after the first finding, without retaining values.
    private final class RunLoopDiagnostics {
        private let lock = NSLock()
        private var pending = Data()
        private var exited = false

        // WO-726@v1: the assertion also covers an unterminated final diagnostic.
        var mainThreadExited: Bool {
            lock.lock()
            defer { lock.unlock() }
            return exited || String(data: pending, encoding: .utf8)?.contains("main thread has exited") == true
        }

        // WO-726@v1: complete lines are reduced to one diagnostic flag instead of exposing matched values.
        func receive(_ data: Data) {
            lock.lock()
            defer { lock.unlock() }
            pending.append(data)
            while let newline = pending.firstIndex(of: 0x0A) {
                if String(data: pending[..<newline], encoding: .utf8)?.contains("main thread has exited") == true {
                    exited = true
                }
                pending.removeSubrange(...newline)
            }
        }
    }

    // WO-726@v1: live regressions need a bounded lifetime even when the worker hangs after readiness.
    private final class RunLoopWatchSession {
        let process = Process()
        let diagnostics = RunLoopDiagnostics()
        private let pipe = Pipe()
        private let finished = DispatchSemaphore(value: 0)
        private let drained = DispatchGroup()
        private let observation: WatchObservation
        private var started = false
        private var stopped = false
        private static let stopGrace: TimeInterval = 3
        private static let killGrace: TimeInterval = 1

        // WO-726@v1: DEBUG config isolation remains independent of the fixture-owned Git home.
        init(executable: URL, root: URL, input: URL, observation: WatchObservation,
             environment: [String: String] = [:]) {
            self.observation = observation
            process.executableURL = executable
            process.arguments = ["watch", "--dir", input.path]
            process.currentDirectoryURL = root
            process.environment = TestConfigHelper.subprocessEnvironment(
                ["PATH": "/usr/bin:/bin"].merging(environment) { _, value in value })
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = pipe
            let finished = self.finished
            process.terminationHandler = { _ in finished.signal() }
        }

        // WO-726@v1: record CPU only after fixture setup and before launching this one child.
        func start() throws {
            try process.run()
            started = true
            let handle = pipe.fileHandleForReading
            let diagnostics = self.diagnostics
            let observation = self.observation
            let drained = self.drained
            drained.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { drained.leave() }
                while true {
                    let data = handle.availableData
                    guard !data.isEmpty else { return }
                    diagnostics.receive(data)
                    observation.receive(data)
                }
            }
        }

        // WO-726@v1: SIGINT must keep its existing exit contract, with forced cleanup only on a failed probe.
        func stop() throws {
            guard started, !stopped else { return }
            defer {
                stopped = true
                try? pipe.fileHandleForReading.close()
            }
            if process.isRunning { process.interrupt() }
            if finished.wait(timeout: .now() + Self.stopGrace) == .timedOut {
                if kill(process.processIdentifier, SIGKILL) != 0 && errno != ESRCH {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                guard finished.wait(timeout: .now() + Self.killGrace) == .success else {
                    throw POSIXError(.ETIMEDOUT)
                }
                throw POSIXError(.ETIMEDOUT)
            }
            process.waitUntilExit()
            guard drained.wait(timeout: .now() + Self.killGrace) == .success else {
                throw POSIXError(.ETIMEDOUT)
            }
        }
    }

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
    func testLiveWatchSmokeReportsChange() throws {
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
            // WO-687@v2: live watch fixtures need no guard environment switch.
            process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
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
            // WO-700@v1: this is a hang watchdog, not a scheduling assumption; raising it is acceptable only because
            // the deterministic Kotlin test now carries the regression rather than this live smoke.
            let smokeHangWatchdogSeconds: TimeInterval = 120
            // WO-674@v2: the timeout is a smoke-test watchdog, not a repeated-touch scheduling assumption.
            // WO-700@v2: a watchdog expiry reports the watcher's own evidence so a lost event is diagnosable.
            guard XCTWaiter().wait(for: [ready], timeout: smokeHangWatchdogSeconds) == .completed else {
                return XCTFail(watchFailure("readiness", process: process, observation: observation))
            }
            try kotlinContent().write(to: file, atomically: true, encoding: .utf8)
            let fixtureEpoch: TimeInterval = 2_000_000_000
            try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: fixtureEpoch)],
                                                  ofItemAtPath: file.path)
            if XCTWaiter().wait(for: [reported], timeout: smokeHangWatchdogSeconds) != .completed {
                XCTFail(watchFailure("finding report", process: process, observation: observation))
            }
        }
    }

    // WO-700@v2: failure text carries process state and stderr metadata, never scanned values.
    private func watchFailure(_ stage: String, process: Process, observation: WatchObservation) -> String {
        let state: String
        if process.isRunning {
            state = "still running"
        } else {
            let reason = process.terminationReason == .uncaughtSignal ? "signal" : "exit"
            state = "terminated by \(reason) \(process.terminationStatus)"
        }
        let transcript = observation.transcript()
        let lines = transcript.isEmpty ? "(no stderr lines)" : transcript.joined(separator: "\n")
        return "watch smoke timed out waiting for \(stage); watcher \(state); stderr:\n\(lines)"
    }

    // WO-700@v1: Kotlin event coverage must not depend on delivery of a filesystem notification.
    func testWatcherDecisionReportsKotlinFinding() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            // WO-700@v1: fixture scans cannot load the operator's global configuration.
            try TestConfigHelper.ensureProjectConfig(in: root)
            let input = root.appendingPathComponent("input", isDirectory: true)
            try FileManager.default.createDirectory(at: input, withIntermediateDirectories: true)
            let file = input.appendingPathComponent("Main.kt")
            try "// clean\n".write(to: file, atomically: true, encoding: .utf8)
            // WO-700@v1: initialize the same watcher decision used by real change events.
            let config = PastewatchConfig.defaultConfig
            let watcher = FileWatcher(directory: input.path, config: config)
            let content = kotlinContent()
            try content.write(to: file, atomically: true, encoding: .utf8)
            // WO-700@v1: the shared extension gate keeps disabled Kotlin coverage observable in this regression.
            let matches = try DirectoryScanner.scan(directory: input.path, config: config).flatMap(\.matches)
            let decision = watcher.fileDecision(matches: matches, content: content, filePath: file.path)
            // WO-700@v1: inspect the event outcome directly rather than waiting for its stderr delivery.
            XCTAssertEqual(decision.actionableMatches.filter { $0.type == .awsKey && $0.line == 1 }.count, 1,
                           "Kotlin change produces an intrinsic finding")
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
        private var lines: [String] = [] // WO-700@v2: failure evidence, finding values elided.
        // WO-700@v2: bounds failure text if a misbehaving watcher floods stderr.
        private static let transcriptLineLimit = 50
        private static let findingSeverities = Set(Severity.allCases.map { $0.rawValue.uppercased() })

        // WO-674@v2: the smoke test separates startup synchronization from event delivery.
        init(ready: XCTestExpectation, reported: XCTestExpectation) {
            self.ready = ready
            self.reported = reported
        }

        // WO-700@v2: complete lines plus any unterminated tail, so a stalled write is visible too.
        func transcript() -> [String] {
            lock.lock()
            defer { lock.unlock() }
            guard !pending.isEmpty else { return lines }
            let tail = String(data: pending, encoding: .utf8).map(Self.elideValue) ?? "<non-UTF-8 bytes>"
            return lines + ["(unterminated) " + tail]
        }

        // WO-700@v2: finding lines end in the matched value; keep the location and type only.
        private static func elideValue(_ line: String) -> String {
            let fields = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: false)
            guard fields.count == 4, findingSeverities.contains(String(fields[1])),
                  let colon = fields[3].firstIndex(of: ":") else { return line }
            return fields[..<3].joined(separator: " ") + " " + fields[3][..<colon] + ": <value elided>"
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
                if lines.count < Self.transcriptLineLimit {
                    lines.append(line.map(Self.elideValue) ?? "<non-UTF-8 bytes>")
                }
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
            // WO-687@v2: fixture Git identity remains unchanged without guard toggles.
            "PATH": "/usr/bin:/bin",
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
