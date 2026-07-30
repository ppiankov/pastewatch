import XCTest
@testable import PastewatchCore

final class AmbiguousGuardDefaultsTests: XCTestCase {
    // WO-596: default configuration keeps every ambiguous detector out of the CLI guard path.
    func testDefaultConfigKeepsAmbiguousClassesGuardClean() throws {
        let entropyValue = ["Z9aB8cD7", "eF6gH5iJ", "4kL3mN2p", "Q1rS0tU"].joined()
        let cases = [
            ["operator", "@", "private.example"].joined(),
            "db-primary.prod.private.example",
            "10.23.45.67",
            ["/home/", "operator/.ssh/config"].joined(),
            "+44 20 7946 0958",
            ["postgres", "://user:pass@db.private/app"].joined(),
            ["jdbc:postgresql", "://db.private/app"].joined(),
            ["token_", entropyValue].joined(),
            ["password=", entropyValue].joined(),
            "550e8400-e29b-41d4-a716-446655440000",
            "<user>deployadmin</user>",
            "<host>node.private</host>",
            entropyValue,
        ]

        for input in cases {
            let result = try runScan(input: input)
            XCTAssertEqual(result.status, ScanExitContract.clean, result.stderr)
        }
    }

    // WO-596: exercise the isolated CLI process with production defaults.
    private func runScan(input: String) throws -> (status: Int32, stderr: String) {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-ambiguous-home-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }

        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = [
            "scan",
            "--check",
            "--fail-on-severity", "high",
            "--stdin-filename", "fixture.txt",
        ]
        process.currentDirectoryURL = home
        var environment = ProcessInfo.processInfo.environment
        environment["HOME"] = home.path
        environment["CFFIXED_USER_HOME"] = home.path
        environment["PW_GUARD"] = "1"
        process.environment = environment

        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        stdin.fileHandleForWriting.write(Data(input.utf8))
        stdin.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        _ = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(
            data: stderr.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        return (process.terminationStatus, errorText)
    }

    // WO-596: resolve the built CLI used by the defaults regression fixture.
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
