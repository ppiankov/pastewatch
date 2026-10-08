import XCTest
@testable import PastewatchCore

// WO-665@v1: oversized default reads use the existing lossless byte-window protocol.
final class MCPAutomaticReadWindowTests: XCTestCase {
    private static let limit = 24 * 1_024 // WO-665@v1: cap automatic output before the client's token limit.

    // WO-665@v1: no-range requests receive a bounded first window and an exact continuation hint.
    func testLargeUnrangedReadUsesBoundedWindowAndContinuation() throws {
        let session = try makeSession()
        defer { session.close() }
        let content = String(repeating: "x", count: Self.limit - 1) + "\u{1F680}\n"
            + String(repeating: "ordinary text\n", count: 5_000)
        let path = try fixture(content, session: session)
        let first = try read(session, path: path)
        let bytes = Data(content.utf8)
        XCTAssertEqual(first["encoding"], .string("base64"))
        XCTAssertEqual(first["total_bytes"], .number(Double(bytes.count)))
        XCTAssertEqual(first["byte_offset"], .number(0))
        XCTAssertEqual(first["byte_length"], .number(Double(Self.limit)))
        XCTAssertEqual(first["has_more"], .bool(true))
        let hint = try string(first["continuation_hint"])
        XCTAssertTrue(hint.contains("byte_offset=\(Self.limit)"))
        XCTAssertTrue(hint.contains("byte_length"))
        XCTAssertTrue(try decode(first) == bytes.prefix(Self.limit))
        let encoded = try JSONEncoder().encode(JSONValue.object(first))
        XCTAssertLessThan(encoded.count, 70 * 1_024)
        var collected = try decode(first)
        while collected.count < bytes.count {
            let window = try read(session, path: path, arguments: [
                "byte_offset": .number(Double(collected.count)), "byte_length": .number(Double(Self.limit))
            ])
            let fragment = try decode(window)
            XCTAssertFalse(fragment.isEmpty)
            collected.append(fragment)
        }
        XCTAssertTrue(collected == bytes)
    }

    // WO-665@v1: output expansion, not raw file size, selects automatic windowing.
    func testWindowThresholdMeasuresRedactedOutput() throws {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [CustomRuleConfig(name: "Window fixture", pattern: "QX")]
        let session = try MCPProtocolTests.LiveMCPSession(executableURL: executable(),
                                                        maximumLineBytes: ScanInputLimits.defaultMaximumLineBytes, config: config)
        defer { session.close() }
        let original = String(repeating: "x", count: Self.limit - 3) + "\n" + "Q" + "X"
        XCTAssertEqual(original.utf8.count, Self.limit)
        XCTAssertEqual(MCPReadDecision.unrangedResponseLimitBytes, Self.limit)
        let payload = try read(session, path: fixture(original, session: session))
        XCTAssertNil(payload["encoding"])
        XCTAssertEqual(payload["start_line"], .number(1))
        XCTAssertEqual(payload["end_line"], .number(1))
        XCTAssertEqual(payload["total_lines"], .number(2))
        XCTAssertEqual(payload["has_more"], .bool(true))
    }

    // WO-665@v1: the exact threshold and smaller files retain identical serialized plain-text payloads.
    func testSmallAndThresholdResponsesAreByteIdentical() throws {
        let session = try makeSession()
        defer { session.close() }
        let decision = MCPReadDecision.evaluate(matches: [], content: "", config: .defaultConfig,
                                              minimumSeverity: .high, filePath: nil)
        for content in ["ordinary \"text\" \\ \u{00E9}\n", String(repeating: "x", count: Self.limit - 3) + "\u{20AC}"] {
            let path = try fixture(content, session: session)
            let actual = try responseText(session, path: path)
            let expected = try decision.encodePayload(.object([
                "content": .string(content), "clean": .bool(true), "redactions": .array([]), "advisories": .array([])
            ]))
            XCTAssertTrue(actual.utf8.elementsEqual(expected.utf8), "Small-read response bytes changed")
        }
    }

    // WO-665@v1: automatic slicing happens after whole-file authorization and placeholder replacement.
    func testAutomaticWindowUsesOnlyRedactedBytes() throws {
        let session = try makeSession()
        defer { session.close() }
        let secret = "hv" + "s." + String(repeating: "Ab7Cd9Ef1Gh3", count: 4)
        let original = secret + "\n" + String(repeating: "ordinary text\n", count: 5_000) + secret + "\n"
        let path = try fixture(original, session: session)
        let first = try read(session, path: path)
        var collected = Data(try string(first["content"]).utf8)
        guard case .array(let entries) = first["redactions"] else {
            return XCTFail("Missing window metadata")
        }
        XCTAssertEqual(entries.count, 2)
        let explicit = try read(session, path: path, arguments: ["byte_length": .number(Double(original.utf8.count))])
        let complete = try decode(explicit)
        XCTAssertNotEqual(complete.count, original.utf8.count)
        while collected.count < complete.count {
            let next = try read(session, path: path, arguments: [
                "byte_offset": .number(Double(collected.count)), "byte_length": .number(Double(Self.limit))
            ])
            let fragment = try decode(next)
            XCTAssertFalse(fragment.isEmpty)
            collected.append(fragment)
        }
        XCTAssertNil(collected.range(of: Data(secret.utf8)))
        XCTAssertTrue(collected == complete)
    }

    // WO-665@v1: large-file guard guidance names the real MCP arguments without exposing file bytes.
    func testLargeGuardBlockNamesByteArguments() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let secret = "AKIA" + String(repeating: "Q", count: 16)
            let path = root.appendingPathComponent("input.txt")
            try (String(repeating: "ordinary text\n", count: 5_000) + secret).write(to: path, atomically: true, encoding: .utf8)
            let process = Process()
            let output = Pipe()
            let errors = Pipe()
            process.executableURL = executable()
            process.arguments = ["guard-read", path.path]
            process.currentDirectoryURL = root
            process.environment = ["PATH": "/usr/bin:/bin", "PW_GUARD": "1"]
            process.standardOutput = output
            process.standardError = errors
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            let diagnostics = errors.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let text = try XCTUnwrap(String(data: data + diagnostics, encoding: .utf8))
            XCTAssertEqual(process.terminationStatus, 2)
            XCTAssertTrue(text.contains("byte_offset"))
            XCTAssertTrue(text.contains("byte_length"))
            XCTAssertTrue(text.contains("start_line"))
            XCTAssertTrue(text.contains("line_count"))
            XCTAssertFalse(text.contains(secret))
        }
    }

    // WO-665@v1: ordinary large files return whole plain-text lines with arithmetic continuation.
    func testLargeUnrangedReadUsesWholeLineWindow() throws {
        let session = try makeSession()
        defer { session.close() }
        let line = "ordinary \u{00E9} text\r\n"
        let content = String(repeating: line, count: 5_000)
        let path = try fixture(content, session: session)
        let payload = try read(session, path: path)
        let count = Self.limit / line.utf8.count
        XCTAssertNil(payload["encoding"])
        XCTAssertEqual(payload["start_line"], .number(1))
        XCTAssertEqual(payload["end_line"], .number(Double(count)))
        XCTAssertEqual(payload["line_count"], .number(Double(count)))
        XCTAssertEqual(payload["total_lines"], .number(5_000))
        XCTAssertEqual(payload["has_more"], .bool(true))
        XCTAssertTrue(try string(payload["content"]).utf8.elementsEqual(String(repeating: line, count: count).utf8))
        XCTAssertTrue(try string(payload["continuation_hint"]).contains("start_line=\(count + 1)"))
        let next = try read(session, path: path, arguments: ["start_line": .number(Double(count + 1)), "line_count": .number(1)])
        XCTAssertTrue(try string(next["content"]).utf8.elementsEqual(line.utf8))
    }

    // WO-665@v1: sessions resolve fixture policy, with line limits large enough for response-boundary cases.
    private func makeSession() throws -> MCPProtocolTests.LiveMCPSession {
        try MCPProtocolTests.LiveMCPSession(executableURL: executable(), maximumLineBytes: ScanInputLimits.defaultMaximumLineBytes)
    }

    // WO-665@v1: binary lookup remains stable when config isolation changes CWD.
    private func executable() -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
    }

    // WO-665@v1: each read owns its test file and never touches operator data.
    private func fixture(_ content: String, session: MCPProtocolTests.LiveMCPSession) throws -> String {
        let path = session.directory.appendingPathComponent("input.txt")
        try content.write(to: path, atomically: true, encoding: .utf8)
        return path.path
    }

    // WO-665@v1: keep request pipes open while examining actual MCP response bytes.
    private func responseText(
        _ session: MCPProtocolTests.LiveMCPSession, path: String, arguments: [String: JSONValue] = [:]
    ) throws -> String {
        var arguments = arguments
        arguments["path"] = .string(path)
        let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/call", params: .object([
            "name": .string("pastewatch_read_file"), "arguments": .object(arguments)
        ]))
        try session.send(try JSONEncoder().encode(request) + Data([0x0A]))
        let response = try XCTUnwrap(session.response())
        guard case .object(let result) = response.result, result["isError"] != .bool(true),
              case .array(let blocks) = result["content"], case .object(let first) = blocks.first,
              case .string(let text) = first["text"] else { throw CocoaError(.coderInvalidValue) }
        return text
    }

    // WO-665@v1: decode the existing payload envelope without printing its content.
    private func read(
        _ session: MCPProtocolTests.LiveMCPSession, path: String, arguments: [String: JSONValue] = [:]
    ) throws -> [String: JSONValue] {
        let text = try responseText(session, path: path, arguments: arguments)
        guard case .object(let payload) = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8)) else {
            throw CocoaError(.coderInvalidValue)
        }
        return payload
    }

    // WO-665@v1: arbitrary byte slices must be decoded as bytes, not lossy UTF-8 strings.
    private func decode(_ payload: [String: JSONValue]) throws -> Data {
        try XCTUnwrap(Data(base64Encoded: string(payload["content"])))
    }

    // WO-665@v1: missing fields fail with metadata-only diagnostics.
    private func string(_ value: JSONValue?) throws -> String {
        guard case .string(let text) = value else { throw CocoaError(.coderInvalidValue) }
        return text
    }
}
