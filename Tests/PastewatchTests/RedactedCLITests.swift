import Foundation
import XCTest
@testable import PastewatchCore

// WO-658@v2: exercise the non-MCP remedies through the real CLI with isolated project policy.
final class RedactedCLITests: XCTestCase {
    // WO-658@v2: the CLI carries a redacted-view token across secret-only changes without restoring stale values.
    func testViewTokenAllowsSecretOnlyChangesAndRejectsLegacyFlag() throws {
        try fixture { root, executable in
            let path = root.appendingPathComponent("fixture.env")
            let original = "key=" + intrinsicFixture() + "\ntitle=before\n"
            try Data(original.utf8).write(to: path)
            let first = try run(["read", path.path], root: root, executable: executable)
            let token = try viewTokenFrom(first.stderr)
            let secondSecret = ["AKIA", String(repeating: "R", count: 16)].joined()
            let changed = "key=" + secondSecret + "\ntitle=before\n"
            try Data(changed.utf8).write(to: path)
            let second = try run(["read", path.path], root: root, executable: executable)
            XCTAssertTrue(first.stdout.utf8.elementsEqual(second.stdout.utf8))
            XCTAssertTrue(token == (try viewTokenFrom(second.stderr)))
            XCTAssertFalse(first.stderr.contains("sha256="))
            let legacy = try run(["edit", path.path, "--old", "title=before", "--new", "title=after",
                                  "--expect-sha256", token], root: root, executable: executable)
            XCTAssertEqual(legacy.status, 2)
            let edited = try run(["edit", path.path, "--old", "title=before", "--new", "title=after",
                                  "--expect-view-token", token], root: root, executable: executable)
            XCTAssertEqual(edited.status, 0)
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(changed.replacingOccurrences(
                of: "title=before", with: "title=after").utf8)))
        }
    }

    // WO-658@v2: blocked native Read can be followed by a lossless redacted CLI read/edit round trip.
    func testReadEditRoundTripWithoutMCP() throws {
        try fixture { root, executable in
            let secret = intrinsicFixture()
            let original = "key=" + secret + "\ntitle=before\nfooter=keep\n"
            let path = root.appendingPathComponent("fixture.env")
            try Data(original.utf8).write(to: path)
            XCTAssertEqual(try run(["guard-read", path.path], root: root, executable: executable).status, 2)
            let read = try run(["read", path.path], root: root, executable: executable)
            XCTAssertEqual(read.status, 0)
            XCTAssertFalse(read.stdout.contains(secret))
            XCTAssertFalse(read.stderr.contains(secret))
            XCTAssertTrue(read.stdout.contains("__PW_"))
            let digest = try viewTokenFrom(read.stderr)
            let changed = read.stdout.replacingOccurrences(of: "title=before", with: "title=after")
            let edited = try run(["edit", path.path, "--old", read.stdout, "--new", changed,
                                  "--expect-view-token", digest], root: root, executable: executable)
            XCTAssertEqual(edited.status, 0)
            XCTAssertFalse(edited.stdout.contains(secret))
            XCTAssertFalse(edited.stderr.contains(secret))
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(original.replacingOccurrences(
                of: "title=before", with: "title=after").utf8)))
        }
    }

    // WO-658@v2: required whole-view tokens reject stale edits without changing the destination.
    func testMissingViewTokenAndStaleViewTokenRefuse() throws {
        try fixture { root, executable in
            let path = root.appendingPathComponent("fixture.txt")
            try Data("title=before\n".utf8).write(to: path)
            let read = try run(["read", path.path], root: root, executable: executable)
            let digest = try viewTokenFrom(read.stderr)
            let missing = try run(["edit", path.path, "--old", "title=before", "--new", "title=after"],
                                  root: root, executable: executable)
            XCTAssertEqual(missing.status, 2)
            try Data("title=changed\n".utf8).write(to: path)
            let stale = try run(["edit", path.path, "--old", "title=changed", "--new", "title=after",
                                 "--expect-view-token", digest], root: root, executable: executable)
            XCTAssertEqual(stale.status, 1)
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data("title=changed\n".utf8)))
        }
    }

    // WO-658@v2: ambiguous, missing and newly authored intrinsic values refuse with value-free diagnostics.
    func testUnsafeEditsRefuseWithoutValues() throws {
        try fixture { root, executable in
            let path = root.appendingPathComponent("fixture.env")
            try Data("title=before\ntitle=before\n".utf8).write(to: path)
            let digest = try viewTokenFrom(try run(["read", path.path], root: root, executable: executable).stderr)
            let secret = intrinsicFixture()
            for (old, new, expected) in [("title=before", "title=after", "2 locations"),
                                         ("missing", "change", "not found")] {
                let result = try run(["edit", path.path, "--old", old, "--new", new, "--expect-view-token", digest],
                                     root: root, executable: executable)
                XCTAssertEqual(result.status, 1)
                XCTAssertTrue(result.stderr.contains(expected))
                XCTAssertFalse(result.stderr.contains(old))
            }
            try Data("title=before\n".utf8).write(to: path)
            let current = try viewTokenFrom(try run(["read", path.path], root: root, executable: executable).stderr)
            let refused = try run(["edit", path.path, "--old", "title=before", "--new", "key=" + secret,
                                   "--expect-view-token", current], root: root, executable: executable)
            XCTAssertEqual(refused.status, 1)
            XCTAssertTrue(refused.stderr.contains("AWS Key"))
            XCTAssertTrue(refused.stderr.contains("line 1"))
            XCTAssertFalse(refused.stdout.contains(secret))
            XCTAssertFalse(refused.stderr.contains(secret))
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data("title=before\n".utf8)))
        }
    }

    // WO-658@v2: multiline payload files and line windows share the same whole-file edit engine.
    func testLineWindowAndFilePayloadEdit() throws {
        try fixture { root, executable in
            let secret = intrinsicFixture()
            let original = "key=" + secret + "\ntitle=before\nfooter=keep\n"
            let path = root.appendingPathComponent("fixture.env")
            try Data(original.utf8).write(to: path)
            let read = try run(["read", path.path, "--start-line", "2", "--line-count", "1"],
                               root: root, executable: executable)
            XCTAssertEqual(read.status, 0)
            XCTAssertEqual(read.stdout, "title=before\n")
            let old = root.appendingPathComponent("old.txt")
            let new = root.appendingPathComponent("new.txt")
            try Data(read.stdout.utf8).write(to: old)
            try Data("title=after\n".utf8).write(to: new)
            let result = try run(["edit", path.path, "--old-file", old.path, "--new-file", new.path,
                                  "--expect-view-token", try viewTokenFrom(read.stderr)], root: root, executable: executable)
            XCTAssertEqual(result.status, 0)
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(original.replacingOccurrences(
                of: "title=before", with: "title=after").utf8)))
        }
    }

    // WO-658@v2: parser-level usage errors must neither echo secret-bearing arguments nor return EX_USAGE.
    func testUsageErrorsAreValueFreeAndExitTwo() throws {
        try fixture { root, executable in
            let secret = intrinsicFixture()
            for arguments in [["read"], ["edit"], ["read", "fixture", "--line-count", secret],
                               ["edit", "fixture", "--unknown", secret],
                               ["edit", "fixture", "--old", "before", "--old-file", "old", "--new", "after",
                                "--expect-view-token", String(repeating: "0", count: 64)]] {
                let result = try run(arguments, root: root, executable: executable)
                XCTAssertEqual(result.status, 2)
                XCTAssertFalse(result.stdout.contains(secret))
                XCTAssertFalse(result.stderr.contains(secret))
            }
        }
    }

    // WO-658@v2: helpers carry only metadata outside the locally captured redacted view.
    private struct CLIResult {
        let status: Int32 // WO-658@v2: distinguish success, refusal and usage.
        let stdout: String // WO-658@v2: inspected locally and never printed by the tests.
        let stderr: String // WO-658@v2: diagnostics are checked for absence of values.
    }

    // WO-658@v2: child processes always select an init-generated fixture config before user policy.
    // WO-672@v1: edit and read child environments preserve fixture-owned global policy.
    private func run(_ arguments: [String], root: URL, executable: URL) throws -> CLIResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-672@v1: mutation probes cannot consume operator policy through the global tier.
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "PW_GUARD": "1"])
        let stdout = Pipe()
        let stderr = Pipe()
        let stdin = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        stdin.fileHandleForWriting.closeFile()
        process.waitUntilExit()
        return CLIResult(status: process.terminationStatus,
                         stdout: String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
                         stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
    }

    // WO-658@v2: the redacted-view token is extracted without ever including file content in an error.
    private func viewTokenFrom(_ diagnostics: String) throws -> String {
        let line = try XCTUnwrap(diagnostics.split(separator: "\n").first { $0.hasPrefix("view-token=") })
        let digest = String(line.dropFirst("view-token=".count))
        XCTAssertEqual(digest.count, 64)
        return digest
    }

    // WO-658@v2: test intrinsic values are assembled at runtime rather than committed as literals.
    private func intrinsicFixture() -> String {
        ["AKIA", String(repeating: "Q", count: 16)].joined()
    }

    // WO-658@v2: retain the executable path before the isolation helper changes CWD.
    private func fixture(_ body: (URL, URL) throws -> Void) throws {
        let directory = Bundle.main.bundleURL.deletingLastPathComponent()
        let bundled = directory.appendingPathComponent("PastewatchCLI")
        let executable = FileManager.default.fileExists(atPath: bundled.path) ? bundled
            : URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build/debug/PastewatchCLI")
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            XCTAssertEqual(try run(["init"], root: root, executable: executable).status, 0)
            try body(root, executable)
        }
    }
}
