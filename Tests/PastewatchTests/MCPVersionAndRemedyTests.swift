import Foundation
import XCTest
@testable import PastewatchCore

// WO-671@v2: exercise version and span-edit remedies through the actual guarded transport.
final class MCPVersionAndRemedyTests: XCTestCase {
    // WO-671@v2: initialization and both successful and refused tool results identify the serving binary.
    func testInitializationAndEveryToolResultReportServerVersion() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: cliURL(), maximumLineBytes: 65_536)
            defer { session.close() }
            let initialized = try request(session, method: "initialize")
            guard case .object(let info) = initialized["serverInfo"] else {
                return XCTFail("Missing server version metadata")
            }
            XCTAssertEqual(info["version"], .string(AppVersion.current))
            let file = session.directory.appendingPathComponent("note.txt")
            try Data("title=before\n".utf8).write(to: file)
            let calls: [(String, [String: JSONValue])] = [
                ("pastewatch_scan", ["text": .string("hello")]),
                ("pastewatch_scan_file", ["path": .string(file.path)]),
                ("pastewatch_scan_dir", ["path": .string(session.directory.path)]),
                ("pastewatch_read_file", ["path": .string(file.path)]),
                ("pastewatch_write_file", ["path": .string(file.path), "content": .string("title=before\n")]),
                ("pastewatch_edit_file", ["path": .string(file.path), "old_string": .string("before"),
                                          "new_string": .string("after")]),
                ("pastewatch_check_output", ["text": .string("hello")]),
            ]
            for (name, arguments) in calls {
                let success = try call(session, name: name, arguments: arguments)
                XCTAssertNil(success["isError"], "Valid fixture tool request must succeed")
                assertVersion(success)
                let refused = try call(session, name: name, arguments: [:])
                XCTAssertEqual(refused["isError"], .bool(true))
                assertVersion(refused)
            }
        }
    }

    // WO-671@v2: editing a small span must preserve an opaque data URI and an advisory phone byte-for-byte.
    func testSpanEditPreservesLargeOpaqueContentAndPhoneAdvisory() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: cliURL(), maximumLineBytes: 65_536,
                                                            config: config)
            defer { session.close() }
            let image = Data(repeating: 0x61, count: 6_600).base64EncodedString()
            XCTAssertGreaterThanOrEqual(image.utf8.count, 8_192)
            let phone = ["+1", "415", "555", "0132"].joined(separator: " ")
            let original = "<img src=\"data:image/png;base64," + image + "\">\n" +
                "<p>" + phone + "</p>\n<h1>before</h1>\n"
            let file = session.directory.appendingPathComponent("index.html")
            try Data(original.utf8).write(to: file)
            let read = try payload(call(session, name: "pastewatch_read_file", arguments: ["path": .string(file.path)]))
            XCTAssertTrue((read["content"] as? String)?.utf8.elementsEqual(original.utf8) == true)
            XCTAssertEqual((read["redactions"] as? [[String: Any]])?.count, 0)
            XCTAssertTrue((read["advisories"] as? [[String: Any]])?.contains {
                $0["type"] as? String == "Phone"
            } == true)
            let edited = try call(session, name: "pastewatch_edit_file", arguments: [
                "path": .string(file.path), "old_string": .string("<h1>before</h1>"),
                "new_string": .string("<h1>after</h1>")
            ])
            XCTAssertNil(edited["isError"])
            let expected = original.replacingOccurrences(of: "<h1>before</h1>", with: "<h1>after</h1>")
            XCTAssertTrue(try Data(contentsOf: file).elementsEqual(Data(expected.utf8)),
                          "Only the requested span may change bytes")
        }
    }

    // WO-671@v2: read and write refusals lead with small edits, including protected and unscannable paths.
    func testFileGuardMessagesNameSpanEditBeforeWholeFileReplacement() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let file = root.appendingPathComponent("fixture.env")
            let secret = ["AK", "IA", String(repeating: "Q", count: 16)].joined()
            try Data(("key=" + secret + "\n").utf8).write(to: file)
            let binary = root.appendingPathComponent("opaque.txt")
            try Data([0xFF, 0x61]).write(to: binary)
            for name in ["guard-read", "guard-write"] {
                for path in [file, binary] {
                    let result = try runGuard([name, path.path], directory: root)
                    XCTAssertEqual(result.status, 2)
                    assertRemedy(result.stdout)
                    XCTAssertFalse((result.stdout + result.stderr).contains(secret))
                }
            }
            var protected = PastewatchConfig.defaultConfig
            protected.protectedPaths = [file.path]
            try JSONEncoder().encode(protected).write(to: root.appendingPathComponent(".pastewatch.json"))
            for name in ["guard-read", "guard-write"] {
                let result = try runGuard([name, file.path], directory: root)
                XCTAssertEqual(result.status, 2)
                assertRemedy(result.stdout)
            }
        }
    }

    // WO-671@v2: structured mutation refusals share the span-first remedy without exposing the input.
    func testMutationGuardMessageNamesSpanEditBeforeWholeFileReplacement() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let file = root.appendingPathComponent("fixture.env")
            let secret = ["AK", "IA", String(repeating: "Q", count: 16)].joined()
            try Data(("key=" + secret + "\n").utf8).write(to: file)
            let input = try JSONSerialization.data(withJSONObject: [
                "tool_name": "Edit", "tool_input": ["file_path": file.path, "old_string": secret,
                                                      "new_string": "replacement"]
            ])
            let result = try runGuard(["guard-mutation"], directory: root, input: input)
            XCTAssertEqual(result.status, 2)
            assertRemedy(result.stdout)
            XCTAssertFalse((result.stdout + result.stderr).contains(secret))
        }
    }

    // WO-671@v2: metadata assertions never include a tool's content in a failure message.
    private func assertVersion(_ result: [String: JSONValue]) {
        guard case .object(let metadata) = result["_meta"] else {
            return XCTFail("Missing tool-result metadata")
        }
        XCTAssertEqual(metadata["server_version"], .string(AppVersion.current))
    }

    // WO-671@v2: narrow remedies and the reconnect instruction precede whole-file replacement advice.
    private func assertRemedy(_ output: String) {
        let edit = output.range(of: "pastewatch_edit_file")
        let write = output.range(of: "pastewatch_write_file")
        XCTAssertNotNil(edit)
        XCTAssertNotNil(write)
        if let edit, let write { XCTAssertTrue(edit.lowerBound < write.lowerBound) }
        XCTAssertTrue(output.contains("old_string/new_string"))
        XCTAssertTrue(output.contains("pastewatch-cli edit"))
        XCTAssertTrue(output.contains("if pastewatch_edit_file is missing, reconnect your MCP server"))
    }

    // WO-671@v2: all tool calls use the persistent server whose version is being inspected.
    private func call(
        _ session: MCPProtocolTests.LiveMCPSession, name: String, arguments: [String: JSONValue]
    ) throws -> [String: JSONValue] {
        try request(session, method: "tools/call", params: .object([
            "name": .string(name), "arguments": .object(arguments)
        ]))
    }

    // WO-671@v2: keep framing open so the regression cannot mask server liveness failures with EOF.
    private func request(
        _ session: MCPProtocolTests.LiveMCPSession, method: String, params: JSONValue? = nil
    ) throws -> [String: JSONValue] {
        let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: method, params: params)
        try session.send(JSONEncoder().encode(request) + Data([0x0A]))
        let response = try XCTUnwrap(session.response())
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result else {
            throw CocoaError(.coderInvalidValue)
        }
        return result
    }

    // WO-671@v2: only test-owned JSON is decoded; assertions never print its values.
    private func payload(_ result: [String: JSONValue]) throws -> [String: Any] {
        guard case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"],
              let payload = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            throw CocoaError(.coderInvalidValue)
        }
        return payload
    }

    // WO-671@v2: separate metadata diagnostics from tool content in subprocess checks.
    private struct GuardOutput {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    // WO-671@v2: subprocess probes retain fixture global policy and pass mutation data through stdin only.
    private func runGuard(_ arguments: [String], directory: URL, input: Data = Data()) throws -> GuardOutput {
        let process = Process()
        process.executableURL = cliURL()
        process.arguments = arguments
        process.currentDirectoryURL = directory
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin", "PW_GUARD": "1"])
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        try stdin.fileHandleForWriting.write(contentsOf: input)
        try stdin.fileHandleForWriting.close()
        process.waitUntilExit()
        return GuardOutput(status: process.terminationStatus,
                           stdout: String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
                           stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
    }

    // WO-671@v2: resolve the freshly built executable rather than an installed stale server.
    private func cliURL() -> URL {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let bundled = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("PastewatchCLI")
        return FileManager.default.fileExists(atPath: bundled.path) ? bundled :
            root.appendingPathComponent(".build/debug/PastewatchCLI")
    }
}
