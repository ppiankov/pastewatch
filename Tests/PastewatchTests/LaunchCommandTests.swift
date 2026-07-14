import Foundation
@testable import PastewatchCLI
import XCTest
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class LaunchCommandTests: XCTestCase {
    private let fixtureContextProbeEnvironmentKey = "PW_LAUNCH_FIXTURE_CONTEXT_PROBE"
    private let fixtureContextProbeMarker = "pastewatch-startup-sweep-fixture-context"
    private var tempRoots: [URL] = []

    override func tearDownWithError() throws {
        for root in tempRoots {
            try? FileManager.default.removeItem(at: root)
        }
        tempRoots.removeAll()
        try super.tearDownWithError()
    }

    // WO-134: launch help variants must exit before sweep/proxy side effects.
    func testLaunchHelpVariantsDoNotRunStartupSweepOrProxy() throws {
        let variants = [
            ["launch", "--help"],
            ["launch", "--help", "--no-startup-sweep"],
            ["launch", "--no-startup-sweep", "--help"],
            ["launch", "-h", "--no-startup-sweep"],
            ["launch", "--no-startup-sweep", "-h"],
        ]

        for arguments in variants {
            let result = try runCLI(arguments: arguments)

            XCTAssertEqual(result.status, 0, "expected help success for \(arguments), stderr: \(result.stderr)")
            XCTAssertTrue(result.stdout.contains("OVERVIEW: Start the proxy"), "missing help text for \(arguments)")
            XCTAssertTrue(result.stdout.contains("--no-startup-sweep"), "missing startup sweep flag for \(arguments)")
            XCTAssertFalse(result.stderr.contains("startup sweep"), "help ran startup sweep for \(arguments)")
            XCTAssertFalse(result.stderr.contains("proxy listening"), "help started proxy for \(arguments)")
            XCTAssertFalse(result.stderr.contains("failed to start proxy"), "help attempted proxy startup for \(arguments)")
        }
    }

    // WO-135: passthrough help reaches only fixture startup files if sweep runs.
    func testLaunchPassthroughHelpUsesFixtureStartupSweepHome() throws {
        let result = try runCLI(arguments: ["launch", "--quiet", "--port", "65435", "--", "--help"])
        let fixturePath = result.home.appendingPathComponent(".zshrc").path

        XCTAssertTrue(result.stderr.contains(fixturePath), "missing fixture warning path: \(result.stderr)")
        XCTAssertFalse(result.stdout.contains("OVERVIEW: Start the proxy"), "passthrough help became launch help")
        XCTAssertFalse(result.stderr.contains(FileManager.default.homeDirectoryForCurrentUser.path))
        XCTAssertFalse(result.stderr.contains("user:pass"))
    }

    // WO-409/WO-416: a proxy-routed agent receives the local proxy URL without
    // needing a bind-then-close port reservation in the test.
    func testLaunchClaudeAgentSetsAnthropicBaseURL() throws {
        try withEnvironmentVariable("ANTHROPIC_BASE_URL", nil) {
            Launch.configureProxyEnv(agentBinary: "claude", port: 49_152)

            XCTAssertEqual(environmentValue("ANTHROPIC_BASE_URL"), "http://127.0.0.1:49152")
        }
    }

    // WO-409: a non-Anthropic agent (codex) launches WITHOUT ANTHROPIC_BASE_URL, plus a warning.
    func testLaunchNonAnthropicAgentSkipsBaseURLAndWarns() throws {
        let fixture = try makeLaunchFixture()
        let agent = try writeEnvEchoAgent(named: "codex", in: fixture.cwd)
        let result = try runCLIProcess(
            arguments: ["launch", "--no-startup-sweep", "--port", "65435", "--", agent.path],
            cwd: fixture.cwd,
            environment: fixture.environment
        )
        XCTAssertTrue(
            result.stdout.contains("ANTHROPIC_BASE_URL=UNSET"),
            "codex must not be wired to the proxy; stdout: \(result.stdout) stderr: \(result.stderr)"
        )
        XCTAssertTrue(
            result.stderr.contains("redaction is not wired for agent 'codex'"),
            "codex should warn about missing proxy interposition; stderr: \(result.stderr)"
        )
        XCTAssertTrue(
            result.stderr.contains("Protect non-routed agents with configured pastewatch hooks and MCP tools where available."),
            "warning should avoid blanket coverage claims; stderr: \(result.stderr)"
        )
        XCTAssertFalse(result.stderr.contains("remain covered"), "warning must not overclaim coverage: \(result.stderr)")
        XCTAssertTrue(result.stderr.contains("launching: "), "non-quiet launch should announce command")
    }

    // WO-418: remote/team gateway URLs are operator intent, not stale local proxy state.
    func testLaunchNonAnthropicAgentPreservesNonLocalBaseURL() throws {
        let fixture = try makeLaunchFixture()
        let agent = try writeEnvEchoAgent(named: "codex", in: fixture.cwd)
        var environment = fixture.environment
        environment["ANTHROPIC_BASE_URL"] = "https://gateway.example.com/anthropic"

        let result = try runCLIProcess(
            arguments: ["launch", "--no-startup-sweep", "--port", "65435", "--", agent.path],
            cwd: fixture.cwd,
            environment: environment
        )

        XCTAssertEqual(result.status, 0, "launch should preserve remote gateway; stderr: \(result.stderr)")
        XCTAssertTrue(result.stdout.contains("ANTHROPIC_BASE_URL=https://gateway.example.com/anthropic"), result.stdout)
        XCTAssertTrue(result.stderr.contains("preserving existing ANTHROPIC_BASE_URL"), result.stderr)
        XCTAssertTrue(
            result.stderr.contains("Protect non-routed agents with configured pastewatch hooks and MCP tools where available."),
            "warning should avoid blanket coverage claims; stderr: \(result.stderr)"
        )
        XCTAssertFalse(result.stderr.contains("remain covered"), "warning must not overclaim coverage: \(result.stderr)")
        XCTAssertFalse(result.stderr.contains("gateway.example.com"), "warning must not echo gateway URL values")
        XCTAssertFalse(result.stderr.contains("ANTHROPIC_BASE_URL not set"), result.stderr)
        XCTAssertTrue(result.stderr.contains("launching: "), "non-quiet launch should announce command")
    }

    // WO-418: stale local pastewatch proxy URLs are cleared for unsupported agents.
    func testLaunchNonAnthropicAgentClearsLocalBaseURL() throws {
        let fixture = try makeLaunchFixture()
        let agent = try writeEnvEchoAgent(named: "codex", in: fixture.cwd)
        var environment = fixture.environment
        environment["ANTHROPIC_BASE_URL"] = "http://127.0.0.1:8443"

        let result = try runCLIProcess(
            arguments: ["launch", "--no-startup-sweep", "--port", "65435", "--", agent.path],
            cwd: fixture.cwd,
            environment: environment
        )

        XCTAssertEqual(result.status, 0, "launch should clear stale local proxy URL; stderr: \(result.stderr)")
        XCTAssertTrue(result.stdout.contains("ANTHROPIC_BASE_URL=UNSET"), result.stdout)
        XCTAssertTrue(result.stderr.contains("ANTHROPIC_BASE_URL not set"), result.stderr)
        XCTAssertTrue(result.stderr.contains("launching: "), "non-quiet launch should announce command")
    }

    // WO-434: audit logs are a proxy artifact; non-routed launches must fail explicitly.
    func testLaunchNonAnthropicAgentWithAuditLogFailsBeforeRunningAgent() throws {
        let fixture = try makeLaunchFixture()
        let agent = try writeEnvEchoAgent(named: "codex", in: fixture.cwd)
        let auditPath = fixture.cwd.appendingPathComponent("pastewatch-audit.log")

        let result = try runCLIProcess(
            arguments: [
                "launch", "--quiet", "--no-startup-sweep", "--port", "65435",
                "--audit-log", auditPath.path, "--", agent.path,
            ],
            cwd: fixture.cwd,
            environment: fixture.environment
        )

        XCTAssertEqual(result.status, 1, "non-routed --audit-log must fail; stderr: \(result.stderr)")
        XCTAssertEqual(result.stdout, "", "agent should not run when audit logging cannot be honored")
        XCTAssertTrue(result.stderr.contains("--audit-log is not supported for non-routed agent 'codex'"), result.stderr)
        XCTAssertFalse(FileManager.default.fileExists(atPath: auditPath.path), "proxy audit log should not be created")
    }

    // WO-423: classify stale local proxy URL spellings directly, not only via process launch.
    func testShouldClearExistingAnthropicBaseURLLoopbackTable() {
        let shouldClear = [
            nil,
            "",
            "http://127.0.0.1:8443",
            "http://127.0.0.2:8443",
            "http://127.255.255.255:8443",
            "http://127.1:8443",
            "http://127.0.1:8443",
            "http://0177.0.0.1:8443",
            "0177.0.0.1:8443",
            "http://0.0.0.0:8443",
            "http://0:8443",
            "http://localhost:8443",
            "http://[::1]:8443",
            "http://[::ffff:127.0.0.1]:8443",
            "127.0.0.1:8443",
            "localhost:8443",
        ]
        let shouldPreserve = [
            "https://gateway.example.com/anthropic",
            "http://127.0.0.1.evil.com:8443",
            "http://08.0.0.1:8443",
            "https://api.anthropic.com",
            "gateway.example.com/anthropic",
        ]

        for value in shouldClear {
            XCTAssertTrue(Launch.shouldClearExistingAnthropicBaseURL(value), "expected clear for \(value ?? "nil")")
        }
        for value in shouldPreserve {
            XCTAssertFalse(Launch.shouldClearExistingAnthropicBaseURL(value), "expected preserve for \(value)")
        }
    }

    // WO-414: unsupported agents must not start an unused proxy or fail on its port.
    func testLaunchNonAnthropicAgentDoesNotRequireProxyPort() throws {
        let fixture = try makeLaunchFixture()
        let agent = try writeEnvEchoAgent(named: "codex", in: fixture.cwd)
        let occupied = try occupyLoopbackPort()
        defer { close(occupied.fd) }

        let result = try runCLIProcess(
            arguments: ["launch", "--quiet", "--no-startup-sweep", "--port", "\(occupied.port)", "--", agent.path],
            cwd: fixture.cwd,
            environment: fixture.environment
        )

        XCTAssertEqual(result.status, 0, "launch should not touch occupied proxy port; stderr: \(result.stderr)")
        XCTAssertTrue(result.stdout.contains("ANTHROPIC_BASE_URL=UNSET"), result.stdout)
        XCTAssertFalse(result.stderr.contains("failed to start proxy"), result.stderr)
        XCTAssertEqual(result.stderr, "", "--quiet should suppress non-routed advisory stderr")
    }

    // WO-438: SIGTERM should take the normal child-exit path so the proxy defer runs.
    func testSIGTERMTerminatesAgentAndProxy() throws {
        let fixture = try makeLaunchFixture()
        let agent = try writeTermTrapAgent(named: "claude", in: fixture.cwd)
        let proxyPort = try reserveEphemeralLoopbackPort()
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = [
            "launch", "--quiet", "--no-startup-sweep", "--port", "\(proxyPort)", "--", agent.script.path,
        ]
        process.currentDirectoryURL = fixture.cwd
        process.environment = fixture.environment
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        defer {
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
                process.waitUntilExit()
            }
            if let agentPid = readPID(from: agent.pidFile), processIsRunning(agentPid) {
                kill(agentPid, SIGKILL)
            }
        }

        XCTAssertTrue(waitForFile(agent.pidFile, timeoutSeconds: 5), "agent did not start")
        XCTAssertTrue(waitUntil(timeoutSeconds: 5) { self.canConnectToLoopbackPort(proxyPort) }, "proxy did not listen")

        kill(process.processIdentifier, SIGTERM)
        XCTAssertTrue(waitForProcessExit(process, timeoutSeconds: 5), "launch did not exit after SIGTERM")
        XCTAssertTrue(waitForFile(agent.termFile, timeoutSeconds: 2), "agent did not receive SIGTERM")
        XCTAssertTrue(
            waitUntil(timeoutSeconds: 5) { !self.canConnectToLoopbackPort(proxyPort) },
            "proxy still accepts connections after launch SIGTERM"
        )

        let out = String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let err = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        XCTAssertEqual(out, "", "quiet launch should not write stdout: \(out)")
        XCTAssertEqual(err, "", "quiet launch should not write stderr: \(err)")
    }

    // WO-137: seam-unavailable probe fallback must not reach startup sweep or proxy.
    func testLaunchFixtureContextProbeUnavailablePathIsSweepSafe() throws {
        let fixture = try makeLaunchFixture()
        let result = try runCLIProcess(
            arguments: ["launch", "--no-startup-sweep"],
            cwd: fixture.cwd,
            environment: fixture.environment
        )
        let fixturePath = fixture.home.appendingPathComponent(".zshrc").path

        XCTAssertEqual(result.status, 2, "expected no-command failure when probe is unavailable")
        XCTAssertFalse(result.stdout.contains(fixtureContextProbeMarker))
        XCTAssertFalse(result.stderr.contains(fixturePath), "probe fallback read fixture startup file")
        XCTAssertFalse(result.stderr.contains("startup sweep"), "probe fallback ran startup sweep")
        XCTAssertFalse(result.stderr.contains("proxy listening"), "probe fallback started proxy")
        XCTAssertFalse(result.stderr.contains("failed to start proxy"), "probe fallback attempted proxy startup")
    }

    // WO-137: failed probe validation must abort before the real launch runner can start.
    func testLaunchFixtureContextProbeFailuresStopBeforeRealLaunch() throws {
        let testCases: [(name: String, makeProbeResult: (URL, [String: String]) -> ProcessResult)] = [
            (
                name: "non-zero status",
                makeProbeResult: { _, _ in ProcessResult(status: 2, stdout: "", stderr: "") }
            ),
            (
                name: "absent marker",
                makeProbeResult: { _, environment in
                    ProcessResult(
                        status: 0,
                        stdout: "home=\(environment["HOME"] ?? "")\ncwd=/tmp/missing-marker\n",
                        stderr: ""
                    )
                }
            ),
            (
                name: "wrong fixture home",
                makeProbeResult: { _, _ in
                    ProcessResult(
                        status: 0,
                        stdout: "\(self.fixtureContextProbeMarker)\nhome=/tmp/wrong-home\ncwd=/tmp/wrong-cwd\n",
                        stderr: ""
                    )
                }
            ),
            (
                name: "wrong fixture cwd",
                makeProbeResult: { cwd, environment in
                    ProcessResult(
                        status: 0,
                        stdout: """
                        \(self.fixtureContextProbeMarker)
                        home=\(environment["HOME"] ?? "")
                        cwd=\(self.expectedProcessCwdPath(cwd))-wrong

                        """,
                        stderr: ""
                    )
                }
            ),
        ]

        for testCase in testCases {
            var invocations: [[String]] = []

            XCTAssertThrowsError(
                try runCLI(
                    arguments: ["launch", "--quiet", "--port", "65435", "--", "--help"],
                    processRunner: { arguments, cwd, environment in
                        invocations.append(arguments)
                        return testCase.makeProbeResult(cwd, environment)
                    }
                ),
                "expected \(testCase.name) probe failure to abort launch"
            ) { error in
                XCTAssertTrue(error is LaunchFixtureProbeError)
            }

            XCTAssertEqual(
                invocations,
                [["launch", "--no-startup-sweep"]],
                "\(testCase.name) probe failure reached the real launch runner"
            )
        }
    }

    private struct CLIResult {
        let status: Int32
        let stdout: String
        let stderr: String
        let home: URL
    }

    private struct LaunchFixture {
        let home: URL
        let cwd: URL
        let environment: [String: String]
    }

    private struct TermTrapAgent {
        let script: URL
        let pidFile: URL
        let termFile: URL
    }

    private struct ProcessResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    private enum LaunchFixtureProbeError: Error {
        case unexpectedStatus
        case missingMarker
        case mismatchedHome
        case mismatchedCwd
        case unsafeSideEffect
    }

    private typealias CLIProcessRunner = (
        _ arguments: [String],
        _ cwd: URL,
        _ environment: [String: String]
    ) throws -> ProcessResult

    private func runCLI(arguments: [String]) throws -> CLIResult {
        try runCLI(arguments: arguments) { arguments, cwd, environment in
            try runCLIProcess(arguments: arguments, cwd: cwd, environment: environment)
        }
    }

    private func runCLI(arguments: [String], processRunner: CLIProcessRunner) throws -> CLIResult {
        let fixture = try makeLaunchFixture()
        try requireLaunchFixtureContextProbe(fixture, processRunner: processRunner)
        let result = try processRunner(arguments, fixture.cwd, fixture.environment)

        return CLIResult(
            status: result.status,
            stdout: result.stdout,
            stderr: result.stderr,
            home: fixture.home
        )
    }

    private func makeLaunchFixture() throws -> LaunchFixture {
        let root = try makeTempDirectory()
        let home = root.appendingPathComponent("home", isDirectory: true)
        let cwd = root.appendingPathComponent("work", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
        var environment = ProcessInfo.processInfo.environment
        environment["HOME"] = home.path
        environment.removeValue(forKey: "PW_GUARD")
        // WO-418: launch env tests must not inherit an operator gateway from the parent shell.
        environment.removeValue(forKey: "ANTHROPIC_BASE_URL")
        environment.removeValue(forKey: fixtureContextProbeEnvironmentKey)
        try writeFixtureStartupFile(in: home)

        return LaunchFixture(home: home, cwd: cwd, environment: environment)
    }

    private func requireLaunchFixtureContextProbe(_ fixture: LaunchFixture, processRunner: CLIProcessRunner) throws {
        var environment = fixture.environment
        environment[fixtureContextProbeEnvironmentKey] = "1"

        let result = try processRunner(["launch", "--no-startup-sweep"], fixture.cwd, environment)
        try validateLaunchFixtureContextProbe(result, fixture: fixture)
    }

    // WO-137: throwing validation is the preflight gate before sweep-capable launch tests.
    private func validateLaunchFixtureContextProbe(_ result: ProcessResult, fixture: LaunchFixture) throws {
        guard result.status == 0 else {
            throw LaunchFixtureProbeError.unexpectedStatus
        }
        guard probeOutput(result.stdout, containsLine: fixtureContextProbeMarker) else {
            throw LaunchFixtureProbeError.missingMarker
        }
        guard probeOutput(result.stdout, containsLine: "home=\(fixture.home.path)") else {
            throw LaunchFixtureProbeError.mismatchedHome
        }
        let expectedCwdPath = expectedProcessCwdPath(fixture.cwd)
        guard probeOutput(result.stdout, containsLine: "cwd=\(expectedCwdPath)") else {
            throw LaunchFixtureProbeError.mismatchedCwd
        }
        guard !result.stderr.contains("startup sweep"),
              !result.stderr.contains("proxy listening"),
              !result.stderr.contains("failed to start proxy") else {
            throw LaunchFixtureProbeError.unsafeSideEffect
        }
    }

    private func probeOutput(_ output: String, containsLine expectedLine: String) -> Bool {
        output.split(separator: "\n", omittingEmptySubsequences: false).contains { line in
            String(line) == expectedLine
        }
    }

    private func expectedProcessCwdPath(_ url: URL) -> String {
        let path = url.path
        #if os(macOS)
        if path.hasPrefix("/var/") || path.hasPrefix("/tmp/") {
            return "/private\(path)"
        }
        #endif
        return url.resolvingSymlinksInPath().path
    }

    private func runCLIProcess(arguments: [String], cwd: URL, environment: [String: String]) throws -> ProcessResult {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = arguments
        process.currentDirectoryURL = cwd
        process.environment = environment

        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()

        return ProcessResult(
            status: process.terminationStatus,
            stdout: String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
            stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
    }

    private func makeTempDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-launch-help-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        tempRoots.append(root)
        return root
    }

    private func reserveEphemeralLoopbackPort() throws -> UInt16 {
        let occupied = try occupyLoopbackPort()
        close(occupied.fd)
        return occupied.port
    }

    // WO-414: keep the listener open to prove non-routed launches skip proxy startup.
    private func occupyLoopbackPort() throws -> (fd: Int32, port: UInt16) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw LaunchPortError.socketFailed }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                #if canImport(Darwin)
                return Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                #else
                return Glibc.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                #endif
            }
        }
        guard bindResult == 0 else {
            close(fd)
            throw LaunchPortError.bindFailed
        }
        let singlePendingConnectionBacklog: Int32 = 1
        guard listen(fd, singlePendingConnectionBacklog) == 0 else {
            close(fd)
            throw LaunchPortError.bindFailed
        }
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        guard nameResult == 0 else {
            close(fd)
            throw LaunchPortError.bindFailed
        }
        return (fd, UInt16(bigEndian: bound.sin_port))
    }

    private enum LaunchPortError: Error { case socketFailed, bindFailed }

    // WO-409: a dummy agent that prints whether ANTHROPIC_BASE_URL was set in its env,
    // then exits so the parent launch runner tears down the proxy and returns.
    private func writeEnvEchoAgent(named name: String, in dir: URL) throws -> URL {
        let script = dir.appendingPathComponent(name)
        try "#!/bin/sh\necho \"ANTHROPIC_BASE_URL=${ANTHROPIC_BASE_URL:-UNSET}\"\n".write(
            to: script, atomically: true, encoding: .utf8
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
        return script
    }

    private func writeTermTrapAgent(named name: String, in dir: URL) throws -> TermTrapAgent {
        let script = dir.appendingPathComponent(name)
        let pidFile = dir.appendingPathComponent("\(name).pid")
        let termFile = dir.appendingPathComponent("\(name).term")
        let body = """
        #!/bin/sh
        printf '%s\\n' "$$" > '\(pidFile.path)'
        trap 'printf term > "\(termFile.path)"; exit 0' TERM
        while :; do sleep 1; done
        """
        try body.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
        return TermTrapAgent(script: script, pidFile: pidFile, termFile: termFile)
    }

    private func writeFixtureStartupFile(in home: URL) throws {
        let fixtureValue = "postgres" + "://user:pass@host:5432/db"
        let path = home.appendingPathComponent(".zshrc")
        try "DATABASE_URL=\(fixtureValue)\n".write(to: path, atomically: true, encoding: .utf8)
    }

    private func environmentValue(_ key: String) -> String? {
        guard let raw = getenv(key) else { return nil }
        return String(cString: raw)
    }

    private func withEnvironmentVariable(_ key: String, _ value: String?, run body: () throws -> Void) throws {
        let original = environmentValue(key)
        setEnvironmentValue(key, value)
        defer { setEnvironmentValue(key, original) }
        try body()
    }

    private func setEnvironmentValue(_ key: String, _ value: String?) {
        if let value {
            setenv(key, value, 1)
        } else {
            unsetenv(key)
        }
    }

    private func pastewatchCLIURL() -> URL {
        let productsDirectory = Bundle.main.bundleURL.deletingLastPathComponent()
        let bundled = productsDirectory.appendingPathComponent("PastewatchCLI")
        if FileManager.default.fileExists(atPath: bundled.path) {
            return bundled
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".build/debug/PastewatchCLI")
    }

    private func waitForFile(_ url: URL, timeoutSeconds: TimeInterval) -> Bool {
        waitUntil(timeoutSeconds: timeoutSeconds) {
            FileManager.default.fileExists(atPath: url.path)
        }
    }

    private func waitForProcessExit(_ process: Process, timeoutSeconds: TimeInterval) -> Bool {
        waitUntil(timeoutSeconds: timeoutSeconds) {
            !process.isRunning
        }
    }

    private func waitUntil(timeoutSeconds: TimeInterval, predicate: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            if predicate() { return true }
            usleep(50_000)
        }
        return predicate()
    }

    private func canConnectToLoopbackPort(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = port.bigEndian
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }

    private func readPID(from url: URL) -> Int32? {
        guard let contents = try? String(contentsOf: url, encoding: .utf8),
              let value = Int32(contents.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            return nil
        }
        return value
    }

    private func processIsRunning(_ pid: Int32) -> Bool {
        kill(pid, 0) == 0
    }
}
