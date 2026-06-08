import Foundation
import XCTest

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

    private struct ProcessResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    private func runCLI(arguments: [String]) throws -> CLIResult {
        let fixture = try makeLaunchFixture()
        try assertLaunchFixtureContextProbe(fixture)
        let result = try runCLIProcess(arguments: arguments, cwd: fixture.cwd, environment: fixture.environment)

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
        try writeFixtureStartupFile(in: home)

        return LaunchFixture(home: home, cwd: cwd, environment: environment)
    }

    private func assertLaunchFixtureContextProbe(_ fixture: LaunchFixture) throws {
        var environment = fixture.environment
        environment[fixtureContextProbeEnvironmentKey] = "1"

        let result = try runCLIProcess(
            arguments: ["launch", "--no-startup-sweep"],
            cwd: fixture.cwd,
            environment: environment
        )

        XCTAssertEqual(result.status, 0, "fixture context probe failed; stderr: \(result.stderr)")
        XCTAssertTrue(result.stdout.contains(fixtureContextProbeMarker), "missing fixture context probe marker")
        XCTAssertTrue(result.stdout.contains("home=\(fixture.home.path)"), "probe did not use fixture HOME")
        let expectedCwdPath = expectedProcessCwdPath(fixture.cwd)
        XCTAssertTrue(
            result.stdout.contains("cwd=\(expectedCwdPath)"),
            "probe did not use fixture cwd; stdout: \(result.stdout)"
        )
        XCTAssertFalse(result.stderr.contains("startup sweep"), "fixture context probe ran startup sweep")
        XCTAssertFalse(result.stderr.contains("proxy listening"), "fixture context probe started proxy")
        XCTAssertFalse(result.stderr.contains("failed to start proxy"), "fixture context probe attempted proxy startup")
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

    private func writeFixtureStartupFile(in home: URL) throws {
        let fixtureValue = "postgres" + "://user:pass@host:5432/db"
        let path = home.appendingPathComponent(".zshrc")
        try "DATABASE_URL=\(fixtureValue)\n".write(to: path, atomically: true, encoding: .utf8)
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
}
