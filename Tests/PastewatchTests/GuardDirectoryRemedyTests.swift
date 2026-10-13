import XCTest
@testable import PastewatchCore

final class GuardDirectoryRemedyTests: XCTestCase {
    // WO-677@v1: recursive readers remain blocked and receive a remedy that accepts a directory.
    func testDirectoryBlockNamesApplicableRemedy() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try JSONEncoder().encode(PastewatchConfig.defaultConfig)
                .write(to: root.appendingPathComponent(".pastewatch.json"))
            let directory = root.appendingPathComponent("tree", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let link = root.appendingPathComponent("tree-link")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory)
            for target in [directory, link] {
                for reader in ["grep -rn foo", "cat"] {
                    let result = try guardCommand(reader + " " + target.path, root: root)
                    XCTAssertEqual(result.status, 2)
                    XCTAssertTrue(result.errors.contains("is a directory"))
                    XCTAssertTrue(result.errors.contains("pastewatch-cli scan --dir"))
                    XCTAssertTrue(result.errors.contains("run the command yourself"))
                    XCTAssertFalse(result.errors.contains("allow-binary"))
                }
            }
        }
    }

    // WO-677@v1: the binary-file hint stays available for regular files, including symlink targets.
    func testBinaryRegularFileKeepsOperatorRemedy() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try JSONEncoder().encode(PastewatchConfig.defaultConfig)
                .write(to: root.appendingPathComponent(".pastewatch.json"))
            let binary = root.appendingPathComponent("bundle.dat")
            try Data([0x00, 0xFF, 0xFE, 0x01]).write(to: binary)
            let link = root.appendingPathComponent("bundle-link.dat")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: binary)
            for target in [binary, link] {
                let result = try guardCommand("cat " + target.path, root: root)
                XCTAssertEqual(result.status, 2)
                XCTAssertTrue(result.errors.contains("Operator: run pastewatch-cli allow-binary"))
                XCTAssertFalse(result.errors.contains("is a directory"))
            }
        }
    }

    // WO-677@v1: executable probes isolate both config tiers and explicitly enable guard enforcement.
    private func guardCommand(_ command: String, root: URL) throws -> GuardProbe {
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = ["guard", command]
        process.currentDirectoryURL = root
        // WO-687@v2: directory refusals always run without an enable switch.
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        let stderr = Pipe()
        process.standardError = stderr
        try process.run()
        let errors = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return GuardProbe(status: process.terminationStatus, errors: try XCTUnwrap(String(data: errors, encoding: .utf8)))
    }

    // WO-677@v1: assertions inspect status and remedy text without exposing file contents.
    private struct GuardProbe {
        let status: Int32
        let errors: String
    }
}
