import Foundation
import XCTest

final class LaunchCommandTests: XCTestCase {
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

    private struct CLIResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    private func runCLI(arguments: [String]) throws -> CLIResult {
        let root = try makeTempDirectory()
        let home = root.appendingPathComponent("home", isDirectory: true)
        let cwd = root.appendingPathComponent("work", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
        try writeFixtureStartupFile(in: home)

        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = arguments
        process.currentDirectoryURL = cwd
        var environment = ProcessInfo.processInfo.environment
        environment["HOME"] = home.path
        environment.removeValue(forKey: "PW_GUARD")
        process.environment = environment

        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()

        return CLIResult(
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
