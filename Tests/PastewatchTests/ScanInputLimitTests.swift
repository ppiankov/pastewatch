import XCTest
@testable import PastewatchCore

final class ScanInputLimitTests: XCTestCase {
    // WO-595@v2: CLI file scans reject size overruns before detector work.
    func testCLIFileScanRejectsConfiguredFileLimit() throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-size-limit-\(UUID().uuidString).txt")
        defer { try? FileManager.default.removeItem(at: file) }
        let content = String(repeating: "x", count: 32)
        try content.write(to: file, atomically: true, encoding: .utf8)

        let result = try runScan(
            file: file,
            environment: [
                ScanInputLimits.fileBytesEnvironmentKey: "16",
                ScanInputLimits.lineBytesEnvironmentKey: "64",
            ]
        )

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
        XCTAssertTrue(result.stderr.contains(ScanInputLimits.fileBytesEnvironmentKey))
        XCTAssertFalse(result.stderr.contains(content))
    }

    // WO-595@v2: CLI file scans reject long lines and name only the tripped policy.
    func testCLIFileScanRejectsConfiguredLineLimit() throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-line-limit-\(UUID().uuidString).txt")
        defer { try? FileManager.default.removeItem(at: file) }
        try "123456".write(to: file, atomically: true, encoding: .utf8)

        let result = try runScan(
            file: file,
            environment: [
                ScanInputLimits.fileBytesEnvironmentKey: "64",
                ScanInputLimits.lineBytesEnvironmentKey: "5",
            ]
        )

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
        XCTAssertTrue(result.stderr.contains(ScanInputLimits.lineBytesEnvironmentKey))
        XCTAssertTrue(result.stderr.contains("line 1"))
        XCTAssertFalse(result.stderr.contains("123456"))
    }

    // WO-595@v2: operator overrides can intentionally admit a bounded clean file.
    func testCLIFileScanHonorsHigherLimits() throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-limit-override-\(UUID().uuidString).txt")
        defer { try? FileManager.default.removeItem(at: file) }
        try "clean input".write(to: file, atomically: true, encoding: .utf8)

        let result = try runScan(
            file: file,
            environment: [
                ScanInputLimits.fileBytesEnvironmentKey: "64",
                ScanInputLimits.lineBytesEnvironmentKey: "64",
            ]
        )

        XCTAssertEqual(result.status, ScanExitContract.clean)
        XCTAssertTrue(result.stderr.isEmpty)
    }

    // WO-595@v2: stdin is capped while bytes are read, before String allocation.
    func testCLIStdinRejectsConfiguredFileLimit() throws {
        let content = "123456"
        let result = try runScan(
            input: Data(content.utf8),
            environment: [
                ScanInputLimits.fileBytesEnvironmentKey: "5",
                ScanInputLimits.lineBytesEnvironmentKey: "64",
            ]
        )

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
        XCTAssertTrue(result.stderr.contains(ScanInputLimits.fileBytesEnvironmentKey))
        XCTAssertFalse(result.stderr.contains(content))
    }

    // WO-595@v2: run the production CLI against deterministic input-limit fixtures.
    private func runScan(
        file: URL? = nil,
        input: Data = Data(),
        environment overrides: [String: String]
    ) throws -> (status: Int32, stderr: String) {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["scan", "--check"] + (file.map { ["--file", $0.path] } ?? [])
        var environment = ProcessInfo.processInfo.environment
        environment["PW_GUARD"] = "1"
        for (key, value) in overrides {
            environment[key] = value
        }
        process.environment = environment

        let stdin = Pipe()
        let output = Pipe()
        let error = Pipe()
        process.standardInput = stdin
        process.standardOutput = output
        process.standardError = error
        try process.run()
        stdin.fileHandleForWriting.write(input)
        try stdin.fileHandleForWriting.close()
        process.waitUntilExit()

        _ = output.fileHandleForReading.readDataToEndOfFile()
        let stderr = String(
            data: error.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        return (process.terminationStatus, stderr)
    }

    // WO-595@v2: resolve the production binary for boundary behavior tests.
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
