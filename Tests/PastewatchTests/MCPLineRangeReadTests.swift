import XCTest
@testable import PastewatchCore

// WO-630@v2: line windows must be plain text from whole-file redaction, not raw file slices.
final class MCPLineRangeReadTests: XCTestCase {
    // WO-630@v2: named expectations keep line-window continuation fixtures explicit.
    private struct WindowCase {
        let content: String
        let arguments: [String: JSONValue]
        let expected: String
        let returned: Int
        let total: Int
        let more: Bool
    }

    // WO-630@v2: expose the old ignored-argument behaviour with a persistent real MCP read.
    func testReadLineWindowReturnsOnlyRequestedRedactedLines() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try Self.makeSession()
            defer { session.close() }
            let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
            let content = "first\n" + value + "\nthird\n"
            let file = session.directory.appendingPathComponent("lines.txt")
            try Data(content.utf8).write(to: file)
            let response = try read(session, arguments: ["path": .string(file.path),
                                                       "start_line": .number(2), "line_count": .number(1)])
            let payload = try payload(response)
            let redacted = try XCTUnwrap(payload["content"] as? String)
            let entries = try XCTUnwrap(payload["redactions"] as? [[String: Any]])
            let marker = try XCTUnwrap(entries.first?["placeholder"] as? String)
            XCTAssertTrue(redacted == marker + "\n")
            XCTAssertFalse(redacted.contains(value))
            XCTAssertNil(payload["encoding"])
        }
    }

    // WO-630@v2: defaults, EOF clamping and very large integers retain deterministic continuation.
    func testLineRangeDefaultsAndEOFClamping() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try Self.makeSession()
            defer { session.close() }
            let file = session.directory.appendingPathComponent("defaults.txt")
            let rows: [WindowCase] = [
                .init(content: "first\nsecond\nthird", arguments: ["start_line": .number(2)],
                      expected: "second\nthird", returned: 2, total: 3, more: false),
                .init(content: "first\nsecond\n", arguments: ["line_count": .number(1)],
                      expected: "first\n", returned: 1, total: 2, more: true),
                .init(content: "first\nsecond\n", arguments: ["start_line": .number(2), "line_count": .number(99)],
                      expected: "second\n", returned: 1, total: 2, more: false),
                .init(content: "first\n", arguments: ["start_line": .number(1e300), "line_count": .number(1e300)],
                      expected: "", returned: 0, total: 1, more: false),
                .init(content: "", arguments: ["start_line": .number(1)], expected: "", returned: 0, total: 0, more: false),
                .init(content: "\n\n", arguments: ["start_line": .number(2), "line_count": .number(1)],
                      expected: "\n", returned: 1, total: 2, more: false)
            ]
            for row in rows {
                try Data(row.content.utf8).write(to: file)
                var arguments = row.arguments
                arguments["path"] = .string(file.path)
                let result = try payload(read(session, arguments: arguments))
                XCTAssertTrue((result["content"] as? String) == row.expected)
                XCTAssertEqual(result["line_count"] as? Int, row.returned)
                XCTAssertEqual(result["total_lines"] as? Int, row.total)
                XCTAssertEqual(result["has_more"] as? Bool, row.more)
                XCTAssertNil(result["encoding"])
            }
        }
    }

    // WO-630@v2: line boundaries preserve CRLF and multi-byte UTF-8 without character-offset arithmetic.
    func testLineWindowsPreserveUnicodeAndCRLFBytes() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try Self.makeSession()
            defer { session.close() }
            let file = session.directory.appendingPathComponent("unicode.txt")
            let lines = ["\u{1F511} first\r\n", "e\u{0301} second\r\n", "\u{00E9} last"]
            try Data(lines.joined().utf8).write(to: file)
            var reconstructed = Data()
            for index in lines.indices {
                let result = try payload(read(session, arguments: ["path": .string(file.path),
                    "start_line": .number(Double(index + 1)), "line_count": .number(1)]))
                let text = try XCTUnwrap(result["content"] as? String)
                XCTAssertTrue(Data(text.utf8) == Data(lines[index].utf8))
                reconstructed.append(Data(text.utf8))
            }
            XCTAssertTrue(reconstructed == Data(lines.joined().utf8))
        }
    }

    // WO-630@v2: a tiny output window still scans and redacts secrets elsewhere in the file.
    func testWholeFileIsRedactedBeforeSelectingWindow() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try Self.makeSession()
            defer { session.close() }
            let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
            let file = session.directory.appendingPathComponent("outside.txt")
            try Data(("first\n" + value + "\nlast\n").utf8).write(to: file)
            let result = try payload(read(session, arguments: ["path": .string(file.path), "line_count": .number(1)]))
            XCTAssertTrue((result["content"] as? String) == "first\n")
            XCTAssertEqual((result["redactions"] as? [[String: Any]])?.count, 1)
            XCTAssertEqual(result["clean"] as? Bool, false)
        }
    }

    // WO-630@v2: an authorized multi-line value is removed before any selected line can expose it.
    func testSpanningSecretIsReplacedBeforeLineWindow() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["Opaque", "Span", "9Q", "\n", "Second", "7Z"].joined()
            var config = PastewatchConfig.defaultConfig
            config.customRules = [.init(name: "Spanning fixture", pattern: NSRegularExpression.escapedPattern(for: value))]
            let session = try Self.makeSession(config: config)
            defer { session.close() }
            let file = session.directory.appendingPathComponent("spanning.txt")
            try Data(("first\n" + value + "\nlast\n").utf8).write(to: file)
            let result = try payload(read(session, arguments: ["path": .string(file.path),
                "start_line": .number(2), "line_count": .number(1)]))
            let entries = try XCTUnwrap(result["redactions"] as? [[String: Any]])
            let marker = try XCTUnwrap(entries.first?["placeholder"] as? String)
            XCTAssertEqual(entries.count, 1)
            XCTAssertTrue((result["content"] as? String) == marker + "\n")
            XCTAssertEqual(result["total_lines"] as? Int, 3)
        }
    }

    // WO-630@v2: line-window placeholders retain the same write restoration as full-file reads.
    func testWindowPlaceholdersRestoreDuringWholeFileWrite() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try Self.makeSession()
            defer { session.close() }
            let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
            let original = "before\n" + value + "\nafter\n"
            let file = session.directory.appendingPathComponent("restore.txt")
            try Data(original.utf8).write(to: file)
            let window = try payload(read(session, arguments: ["path": .string(file.path),
                "start_line": .number(2), "line_count": .number(1)]))
            let redacted = try XCTUnwrap(window["content"] as? String)
            let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(2), method: "tools/call", params: .object([
                "name": .string("pastewatch_write_file"), "arguments": .object([
                    "path": .string(file.path), "content": .string("edited\n" + redacted + "after\n")
                ])
            ]))
            try session.send(JSONEncoder().encode(request) + Data([0x0A]))
            _ = try payload(XCTUnwrap(session.response()))
            XCTAssertTrue(try Data(contentsOf: file) == Data(original.replacingOccurrences(of: "before", with: "edited").utf8))
        }
    }

    // WO-630@v2: invalid line arguments and mixed byte/line modes return tool errors, never content.
    func testInvalidLineRangesAndMixedModesFailClosed() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try Self.makeSession()
            defer { session.close() }
            let file = session.directory.appendingPathComponent("invalid.txt")
            try Data("first\nsecond\n".utf8).write(to: file)
            let invalid: [JSONValue] = [.number(0), .number(-1), .number(1.5), .string("2"), .bool(true), .null]
            var windows = invalid.flatMap { value in [["start_line": value], ["line_count": value]] }
            windows += [["start_line": .number(1), "byte_offset": .number(0)],
                        ["line_count": .number(1), "byte_length": .number(1)]]
            for window in windows {
                var arguments = window
                arguments["path"] = .string(file.path)
                let response = try read(session, arguments: arguments)
                guard case .object(let result) = response.result else { return XCTFail("MCP tool error required") }
                XCTAssertEqual(result["isError"], .bool(true))
                let text = try XCTUnwrap(String(data: JSONEncoder().encode(response), encoding: .utf8))
                XCTAssertFalse(text.contains("first"))
                XCTAssertFalse(text.contains("second"))
            }
            let valid = try payload(read(session, arguments: ["path": .string(file.path), "line_count": .number(1)]))
            XCTAssertTrue((valid["content"] as? String) == "first\n")
        }
    }

    // WO-630@v2: the MCP schema exposes one-based text ranges with a positive minimum.
    func testToolSchemaDeclaresLineRangeArguments() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try Self.makeSession()
            defer { session.close() }
            let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/list", params: nil)
            try session.send(JSONEncoder().encode(request) + Data([0x0A]))
            let response = try XCTUnwrap(session.response())
            guard case .object(let result) = response.result, case .array(let tools) = result["tools"],
                  let read = tools.first(where: { value in
                      guard case .object(let tool) = value else { return false }
                      return tool["name"] == .string("pastewatch_read_file")
                  }), case .object(let tool) = read, case .object(let schema) = tool["inputSchema"],
                  case .object(let properties) = schema["properties"] else {
                return XCTFail("read schema required")
            }
            for name in ["start_line", "line_count"] {
                guard case .object(let property) = properties[name] else { return XCTFail("line property required") }
                XCTAssertEqual(property["type"], .string("integer"))
                XCTAssertEqual(property["minimum"], .number(1))
            }
        }
    }

    // WO-630@v2: selecting one output line never bypasses the existing whole-file read bound.
    func testLineWindowCannotBypassWholeFileByteCap() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try Self.makeSession(maximumFileBytes: 256)
            defer { session.close() }
            let file = session.directory.appendingPathComponent("bounded.txt")
            try Data(("first\n" + String(repeating: "x", count: 256)).utf8).write(to: file)
            let response = try read(session, arguments: ["path": .string(file.path), "line_count": .number(1)])
            guard case .object(let result) = response.result else { return XCTFail("MCP tool error required") }
            XCTAssertEqual(result["isError"], .bool(true))
            let text = try XCTUnwrap(String(data: JSONEncoder().encode(response), encoding: .utf8))
            XCTAssertTrue(text.contains("Read limit exceeded"))
            XCTAssertFalse(text.contains("first"))
        }
    }

    // WO-630@v2: use a project-only fixture policy and the existing open-pipe test transport.
    static func makeSession(
        config: PastewatchConfig = .defaultConfig, maximumFileBytes: Int = ScanInputLimits.defaultMaximumFileBytes
    ) throws -> MCPProtocolTests.LiveMCPSession {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let bundled = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("PastewatchCLI")
        let cli = FileManager.default.fileExists(atPath: bundled.path) ? bundled :
            root.appendingPathComponent(".build/debug/PastewatchCLI")
        return try MCPProtocolTests.LiveMCPSession(executableURL: cli, maximumLineBytes: 65_536,
                                                 maximumFileBytes: maximumFileBytes, config: config)
    }

    // WO-630@v2: parse only response metadata so failing assertions never print fixture values.
    private func read(
        _ session: MCPProtocolTests.LiveMCPSession, arguments: [String: JSONValue]
    ) throws -> JSONRPCResponse {
        let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/call", params: .object([
            "name": .string("pastewatch_read_file"), "arguments": .object(arguments)
        ]))
        try session.send(JSONEncoder().encode(request) + Data([0x0A]))
        return try XCTUnwrap(session.response(), "MCP response deadline expired")
    }

    // WO-630@v2: tool errors are asserted separately from decoded read payloads.
    private func payload(_ response: JSONRPCResponse) throws -> [String: Any] {
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result, result["isError"] == nil,
              case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"],
              let payload = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            throw NSError(domain: "MCPLineRangeReadTests", code: 1)
        }
        return payload
    }
}
