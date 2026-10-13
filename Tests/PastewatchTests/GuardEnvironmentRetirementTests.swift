import XCTest
@testable import PastewatchCore

final class GuardEnvironmentRetirementTests: XCTestCase {
    // WO-687@v2: retirement advice is value-free and has one exact CLI-only spelling.
    private let notice = "PW_GUARD is not supported (removed in 0.43.0); to turn the guard off, disable the agent hook. See docs/exemptions.md"

    // WO-687@v2: inherited zero must no longer bypass any guard or the check-mode scanner.
    func testZeroCannotBypassAnyGuardOrScanCheck() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = intrinsicContent()
            let target = root.appendingPathComponent("fixture.txt")
            try Data(content.utf8).write(to: target)
            for fixture in try commandCases(target: target, content: content) {
                let result = try command(fixture.arguments, root: root, input: fixture.input, guardValue: "0")
                XCTAssertEqual(result.status, fixture.expectedStatus, fixture.name)
                assertNotice(result, expected: true)
            }
        }
    }

    // WO-687@v2: every set value is diagnostic-only, including empty and formerly enabling values.
    func testAnySetValuePrintsOneNoticeAndUnsetPrintsNone() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = intrinsicContent()
            let target = root.appendingPathComponent("fixture.txt")
            try Data(content.utf8).write(to: target)
            for value in ["1", "", "retired", nil] as [String?] {
                for fixture in try commandCases(target: target, content: content) {
                    let result = try command(fixture.arguments, root: root, input: fixture.input, guardValue: value)
                    XCTAssertEqual(result.status, fixture.expectedStatus, fixture.name)
                    assertNotice(result, expected: value != nil)
                }
            }
        }
    }

    // WO-687@v2: hooks stay silent on clean inputs even when obsolete environment settings are inherited.
    func testCleanInputsNeverPrintNotice() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = "ordinary text\n"
            let target = root.appendingPathComponent("fixture.txt")
            try Data(content.utf8).write(to: target)
            for value in ["0", "1", "", "retired"] {
                for fixture in try commandCases(target: target, content: content, expectedStatus: 0) {
                    let result = try command(fixture.arguments, root: root, input: fixture.input, guardValue: value)
                    XCTAssertEqual(result.status, 0, fixture.name)
                    assertNotice(result, expected: false)
                }
            }
        }
    }

    // WO-687@v2: one command with multiple files still emits only one stderr notice in every output mode.
    func testCommandAndScanFormatsKeepNoticeOnStderrOnce() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = intrinsicContent()
            let first = root.appendingPathComponent("first.txt")
            let second = root.appendingPathComponent("second.txt")
            try Data(content.utf8).write(to: first)
            try Data(content.utf8).write(to: second)
            for options in [[], ["--json"], ["--quiet"]] {
                let result = try command(["guard", "cat first.txt second.txt"] + options, root: root, guardValue: "0")
                XCTAssertEqual(result.status, 2)
                assertNotice(result, expected: true)
            }
            for format in ["text", "json", "sarif", "markdown"] {
                for options in [["--file", first.path], ["--dir", root.path]] {
                    let result = try command(["scan", "--check", "--format", format] + options, root: root, guardValue: "0")
                    XCTAssertEqual(result.status, 6)
                    assertNotice(result, expected: true)
                }
            }
            let stdin = try command(["scan", "--check"], root: root, input: Data(content.utf8), guardValue: "0")
            XCTAssertEqual(stdin.status, 6)
            assertNotice(stdin, expected: true)
        }
    }

    // WO-687@v2: finding-bound diagnostics cover staged and historical scans without consulting a decision switch.
    func testGitScanModesPrintOneNotice() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let target = root.appendingPathComponent("fixture.txt")
            try Data(intrinsicContent().utf8).write(to: target)
            try git(["init", "--quiet"], root: root)
            try git(["add", "fixture.txt"], root: root)
            let staged = try command(["scan", "--check", "--git-diff", "--staged"], root: root, guardValue: "0")
            XCTAssertEqual(staged.status, 6)
            assertNotice(staged, expected: true)
            try git(["-c", "user.name=ppiankov", "-c", "user.email=103106369+ppiankov@users.noreply.github.com",
                "commit", "--quiet", "-m", "test: add scanner fixture"], root: root)
            let history = try command(["scan", "--check", "--git-log"], root: root, guardValue: "0")
            XCTAssertEqual(history.status, 6)
            assertNotice(history, expected: true)
        }
    }

    // WO-687@v2: MCP remains unaffected and never mixes CLI migration advice into either stream.
    func testMCPNeverPrintsNotice() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = intrinsicContent()
            let target = root.appendingPathComponent("fixture.txt")
            try Data(content.utf8).write(to: target)
            let request: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": ["name": "pastewatch_read_file", "arguments": ["path": target.path]]]
            var input = try JSONSerialization.data(withJSONObject: request)
            input.append(0x0A)
            let result = try command(["mcp"], root: root, input: input, guardValue: "0")
            XCTAssertEqual(result.status, 0)
            assertNotice(result, expected: false)
            let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [String: Any])
            let response = try XCTUnwrap(envelope["result"] as? [String: Any])
            XCTAssertNil(response["isError"])
            let blocks = try XCTUnwrap(response["content"] as? [[String: Any]])
            let text = try XCTUnwrap(blocks.first?["text"] as? String)
            let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
            XCTAssertEqual((payload["redactions"] as? [Any])?.count, 3)
            XCTAssertFalse(text.contains(content.components(separatedBy: "\n")[0]))
        }
    }

    // WO-687@v2: fixture keys exist only at runtime, with distinct values to exercise notice deduplication.
    private func intrinsicContent() -> String {
        ["A", "B", "C"].map { "AIza" + String(repeating: $0, count: 35) }.joined(separator: "\n") + "\n"
    }

    // WO-687@v2: the same fixture covers structured write decisions and each native read/write guard.
    private func commandCases(target: URL, content: String, expectedStatus: Int32? = nil) throws -> [CommandCase] {
        let payload: [String: Any] = ["tool_name": "Write", "tool_input": ["file_path": target.path, "content": "updated text\n"]]
        return [
            CommandCase(name: "guard", arguments: ["guard", "cat \(target.path)"], expectedStatus: expectedStatus ?? 2),
            CommandCase(name: "guard-read", arguments: ["guard-read", target.path], expectedStatus: expectedStatus ?? 2),
            CommandCase(name: "guard-write", arguments: ["guard-write", target.path], expectedStatus: expectedStatus ?? 2),
            CommandCase(name: "guard-mutation", arguments: ["guard-mutation"], input: try JSONSerialization.data(withJSONObject: payload),
                expectedStatus: expectedStatus ?? 2),
            CommandCase(name: "scan --check", arguments: ["scan", "--check", "--file", target.path], expectedStatus: expectedStatus ?? 6)
        ]
    }

    // WO-687@v2: only notice lines enter equality diagnostics, never the captured fixture contents.
    private func assertNotice(_ result: CommandResult, expected: Bool, file: StaticString = #filePath, line: UInt = #line) {
        let notices = (String(data: result.errors, encoding: .utf8) ?? "").components(separatedBy: "\n")
            .filter { $0.contains("PW_GUARD is not supported") }
        XCTAssertEqual(notices, expected ? [notice] : [], file: file, line: line)
        XCTAssertFalse(String(data: result.output, encoding: .utf8)?.contains(notice) == true, file: file, line: line)
    }

    // WO-687@v2: only retirement regressions set the removed variable; fixture policy stays isolated.
    private func command(_ arguments: [String], root: URL, input: Data = Data(), guardValue: String?) throws -> CommandResult {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        var environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
        environment["PW_GUARD"] = guardValue
        process.environment = environment
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        stdin.fileHandleForWriting.write(input)
        try stdin.fileHandleForWriting.close()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let errors = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, output: output, errors: errors)
    }

    // WO-687@v2: fixture repositories never consume the operator's Git config or hooks.
    private func git(_ arguments: [String], root: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = arguments
        process.currentDirectoryURL = root
        process.environment = ["PATH": "/usr/bin:/bin", "HOME": root.path]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
    }

    // WO-687@v2: named fixture fields avoid exposing checked values through tuple diagnostics.
    private struct CommandCase {
        let name: String
        let arguments: [String]
        var input = Data()
        let expectedStatus: Int32
    }

    // WO-687@v2: subprocess output is captured privately and assertions inspect only metadata.
    private struct CommandResult {
        let status: Int32
        let output: Data
        let errors: Data
    }
}
