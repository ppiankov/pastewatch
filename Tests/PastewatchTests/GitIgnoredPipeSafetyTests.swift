import XCTest
@testable import PastewatchCore
#if os(Linux)
import Glibc
#else
import Darwin
#endif

// WO-669@v1: non-git scans and early-exit Git children must not terminate the caller.
final class GitIgnoredPipeSafetyTests: XCTestCase {
    // WO-669@v1: repository absence is determined before a child with stdin is launched.
    func testNonRepositoryProbeNeverStartsInputWriter() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let stub = root.appendingPathComponent("git-stub")
            try "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.calls\"\nexit 1\n".write(to: stub, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stub.path)
            let ignored = DirectoryScanner.gitIgnoredFiles(
                in: root.path, paths: ["one.txt"], limits: .current(), gitExecutable: stub
            )
            XCTAssertTrue(ignored.isEmpty)
            let calls = try String(contentsOf: URL(fileURLWithPath: stub.path + ".calls"), encoding: .utf8)
            XCTAssertTrue(calls.contains("rev-parse"))
            XCTAssertFalse(calls.contains("--stdin"))
            XCTAssertFalse(calls.contains("check-ignore"))
        }
    }

    // WO-669@v1: enough input to fill the pipe forces EPIPE even if the first write wins the scheduling race.
    func testEarlyExitChildContainsPipeSignalWithDefaultDisposition() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let stub = root.appendingPathComponent("git-stub")
            let script = "#!/bin/sh\nif [ \"$3\" = rev-parse ]; then printf 'true\\n'; exit 0; fi\nexec 0<&-\nexit 0\n"
            try script.write(to: stub, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stub.path)
            let previous = signal(SIGPIPE, SIG_DFL)
            defer { signal(SIGPIPE, previous) }
            let paths = Array(repeating: String(repeating: "x", count: 1_024), count: 1_000)
            for _ in 0..<5 {
                let ignored = DirectoryScanner.gitIgnoredFiles(in: root.path, paths: paths, limits: .current(), gitExecutable: stub)
                XCTAssertTrue(ignored.isEmpty)
            }
            // The child writer must not globally ignore SIGPIPE and alter stdout pipeline behavior.
            let after = signal(SIGPIPE, SIG_DFL)
            XCTAssertNil(after)
        }
    }

    // WO-669@v1: the actual CLI and one persistent MCP session repeatedly scan non-git finding directories.
    // WO-672@v1: transport-liveness fixtures isolate both configuration tiers.
    func testNonGitFindingScansKeepCLIAndMCPAlive() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let input = root.appendingPathComponent("input", isDirectory: true)
            try FileManager.default.createDirectory(at: input, withIntermediateDirectories: true)
            let key = "AKIA" + String(repeating: "Q", count: 16)
            for number in 0..<40 {
                try key.write(to: input.appendingPathComponent("source\(number).txt"), atomically: true, encoding: .utf8)
            }
            let executable = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: executable)
            defer { session.close() }
            for number in 0..<5 {
                let process = Process()
                process.executableURL = executable
                process.arguments = ["scan", "--dir", input.path, "--check"]
                process.currentDirectoryURL = root
                // WO-672@v1: process-liveness probes keep all configuration fixture-owned.
                process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin", "PW_GUARD": "1"])
                process.standardOutput = FileHandle.nullDevice
                process.standardError = FileHandle.nullDevice
                try process.run()
                process.waitUntilExit()
                XCTAssertEqual(process.terminationReason, .exit)
                XCTAssertEqual(process.terminationStatus, 6)
                let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(number), method: "tools/call", params: .object([
                    "name": .string("pastewatch_scan_dir"), "arguments": .object(["path": .string(input.path)])
                ]))
                try session.send(try JSONEncoder().encode(request) + Data([0x0A]))
                let response = try XCTUnwrap(session.response())
                guard case .object(let result) = response.result,
                      case .array(let content) = result["content"], case .object(let block) = content.first,
                      case .string(let text) = block["text"] else { return XCTFail("Missing scan metadata") }
                XCTAssertTrue(text.contains("Scanned 40 files."))
                XCTAssertTrue(text.contains("Found 40 findings."))
            }
        }
    }
}
