import XCTest
@testable import PastewatchCore

// WO-627@v2: byte ranges must be lossless windows of the redacted MCP output.
final class MCPReadRangeTests: XCTestCase {
    // WO-627@v2: advertise optional byte arguments without changing required inputs.
    func testReadSchemaDeclaresOptionalByteRanges() throws {
        let session = try makeSession()
        defer { session.close() }
        let result = try call(session, method: "tools/list", params: nil)
        guard case .array(let tools) = result["tools"],
              let tool = tools.first(where: {
                  guard case .object(let value) = $0 else { return false }
                  return value["name"] == .string("pastewatch_read_file")
              }),
              case .object(let value) = tool,
              case .object(let schema) = value["inputSchema"],
              case .object(let properties) = schema["properties"] else {
            return XCTFail("Missing read schema")
        }
        XCTAssertEqual(schema["required"], .array([.string("path")]))
        for key in ["byte_offset", "byte_length"] {
            guard case .object(let property) = properties[key] else {
                return XCTFail("Missing range property")
            }
            XCTAssertEqual(property["type"], .string("integer"))
        }
    }

    // WO-627@v2: F2 pins the old plain-content payload for clean and redacted reads.
    func testUnrangedResponseRemainsUnchanged() throws {
        let session = try makeSession()
        defer { session.close() }
        let clean = "ordinary text\nsecond line\n"
        let path = try fixture(clean, session: session)
        let payload = try readPayload(session, path: path)
        XCTAssertTrue(payload["content"] == .string(clean))
        XCTAssertEqual(Set(payload.keys), ["content", "redactions", "advisories", "clean"])
        XCTAssertEqual(payload["clean"], .bool(true))
        XCTAssertEqual(payload["redactions"], .array([]))
        XCTAssertEqual(payload["advisories"], .array([]))

        let secret = vaultFixture()
        let secretPath = try fixture(secret, session: session, name: "sensitive.txt")
        let redacted = try readPayload(session, path: secretPath)
        XCTAssertEqual(Set(redacted.keys), ["content", "redactions", "advisories", "clean", "pastewatch_note"])
        XCTAssertEqual(redacted["clean"], .bool(false))
        XCTAssertFalse(try plainContent(redacted).contains(secret))
        guard case .array(let entries) = redacted["redactions"] else {
            return XCTFail("Missing redaction metadata")
        }
        XCTAssertEqual(entries.count, 1)
    }

    // WO-627@v2: F1 proves one long physical line is retrievable in bounded pieces.
    func testLongLineReassemblesFromBoundedWindows() throws {
        let session = try makeSession()
        defer { session.close() }
        let content = String(repeating: "ordinary text ", count: 2_500)
        let path = try fixture(content, session: session)
        let full = try readPayload(session, path: path)
        let bytes = Data(try plainContent(full).utf8)
        let collected = try collectWindows(session, path: path, expected: bytes, length: 4_096)
        XCTAssertTrue(collected == bytes)
    }

    // WO-627@v2: F4 deliberately bisects UTF-8 sequences, including a four-byte scalar.
    func testOneByteUnicodeWindowsReassembleWithoutRealignment() throws {
        let session = try makeSession()
        defer { session.close() }
        let content = "A\u{00E9}\u{4E2D}\u{1F680}e\u{0301}Z"
        let path = try fixture(content, session: session)
        let full = try readPayload(session, path: path)
        let bytes = Data(try plainContent(full).utf8)
        let middle = try readPayload(session, path: path, range: [
            "byte_offset": .number(2), "byte_length": .number(1)
        ])
        let fragment = try decodedWindow(middle)
        XCTAssertEqual(fragment.count, 1)
        // WO-627: a one-byte window inside a multi-byte character is a raw UTF-8
        // continuation byte (0x80–0xBF). Assert that directly rather than probing
        // String(data:encoding:) on a lone continuation byte — Foundation's
        // handling of that is platform-dependent (nil on macOS, U+FFFD on Linux CI),
        // which is not what this test is proving. The contract is byte-exactness.
        XCTAssertEqual(fragment.first.map { $0 & 0xC0 }, 0x80)
        XCTAssertTrue(fragment == bytes.subdata(in: 2..<3))
        XCTAssertTrue(try collectWindows(session, path: path, expected: bytes, length: 1) == bytes)
    }

    // WO-627@v2: F5 compares decoded windows to redacted, not on-disk, byte offsets.
    func testSecretsAreRedactedBeforeSelectingAnyWindow() throws {
        let session = try makeSession()
        defer { session.close() }
        let secret = vaultFixture()
        let original = "prefix " + secret + " suffix\n"
        let path = try fixture(original, session: session)
        let full = try readPayload(session, path: path)
        let bytes = Data(try plainContent(full).utf8)
        XCTAssertFalse(bytes.range(of: Data(secret.utf8)) != nil)
        XCTAssertNotEqual(bytes.count, original.utf8.count)
        let middle = try readPayload(session, path: path, range: [
            "byte_offset": .number(9), "byte_length": .number(5)
        ])
        XCTAssertTrue(try decodedWindow(middle) == bytes.subdata(in: 9..<14))
        for key in ["redactions", "advisories", "clean", "pastewatch_note"] {
            XCTAssertTrue(middle[key] == full[key], "Ranged reads must preserve existing metadata")
        }
        let collected = try collectWindows(session, path: path, expected: bytes, length: 5)
        XCTAssertTrue(collected == bytes)
        XCTAssertNil(collected.range(of: Data(secret.utf8)))
    }

    // WO-627@v2: F3 pins independent optional arguments and EOF arithmetic.
    func testRangeDefaultsAndEndOfFile() throws {
        let session = try makeSession()
        defer { session.close() }
        let bytes = Data("abcdefghij".utf8)
        let path = try fixture("abcdefghij", session: session)
        let prefix = try readPayload(session, path: path, range: ["byte_length": .number(3)])
        XCTAssertEqual(prefix["byte_offset"], .number(0))
        XCTAssertTrue(try decodedWindow(prefix) == bytes.prefix(3))
        XCTAssertEqual(prefix["has_more"], .bool(true))
        let suffix = try readPayload(session, path: path, range: ["byte_offset": .number(8)])
        XCTAssertTrue(try decodedWindow(suffix) == bytes.suffix(2))
        XCTAssertEqual(suffix["byte_length"], .number(2))
        XCTAssertEqual(suffix["has_more"], .bool(false))
        // WO-627@v2: even offsets beyond native Int capacity are valid terminal windows.
        for offset in [10, 11, 1_000_000, Double.greatestFiniteMagnitude] {
            let empty = try readPayload(session, path: path, range: ["byte_offset": .number(Double(offset))])
            XCTAssertTrue(try decodedWindow(empty).isEmpty)
            XCTAssertEqual(empty["byte_offset"], .number(Double(offset)))
            XCTAssertEqual(empty["byte_length"], .number(0))
            XCTAssertEqual(empty["total_bytes"], .number(10))
            XCTAssertEqual(empty["has_more"], .bool(false))
        }
    }

    // WO-627@v2: malformed numbers and JSON types cannot silently become an unranged read.
    func testInvalidRangesReturnToolErrorsWithoutContent() throws {
        let session = try makeSession()
        defer { session.close() }
        let path = try fixture("ordinary text", session: session)
        let invalid: [[String: JSONValue]] = [
            ["byte_offset": .number(-1)], ["byte_length": .number(0)],
            ["byte_length": .number(-1)], ["byte_offset": .number(0.5)],
            ["byte_length": .number(1.5)], ["byte_offset": .string("0")],
            ["byte_length": .string("1")], ["byte_offset": .null],
            ["byte_length": .null], ["byte_offset": .bool(true)],
            ["byte_length": .bool(false)], ["byte_offset": .array([])],
            ["byte_length": .object([:])]
        ]
        for range in invalid {
            let result = try readResult(session, path: path, range: range)
            XCTAssertEqual(result["isError"], .bool(true))
            let text = try responseText(result)
            XCTAssertTrue(text.contains("byte_offset") || text.contains("byte_length"))
            XCTAssertFalse(text.contains("ordinary text"))
        }
    }

    // WO-627@v2: clamp before integer conversion; even huge lengths remain bounded after expansion.
    func testRequestedAndDefaultLengthsRespectExistingReadCap() throws {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [CustomRuleConfig(name: "Range fixture", pattern: "QX")]
        let cap = 4
        let session = try makeSession(maximumFileBytes: cap, config: config)
        defer { session.close() }
        let path = try fixture("Q" + "X", session: session)
        let full = try readPayload(session, path: path)
        let bytes = Data(try plainContent(full).utf8)
        XCTAssertGreaterThan(bytes.count, cap)
        for range: [String: JSONValue] in [
            ["byte_offset": .number(0)],
            ["byte_length": .number(1_000)],
            ["byte_length": .number(Double.greatestFiniteMagnitude)]
        ] {
            let window = try readPayload(session, path: path, range: range)
            XCTAssertEqual(try decodedWindow(window).count, cap)
            XCTAssertTrue(try decodedWindow(window) == bytes.prefix(cap))
            XCTAssertEqual(window["byte_length"], .number(Double(cap)))
            XCTAssertEqual(window["total_bytes"], .number(Double(bytes.count)))
            XCTAssertEqual(window["has_more"], .bool(true))
        }
    }

    // WO-627@v2: a tiny requested window cannot bypass full-input size or decoding checks.
    func testRangesStillEnforceWholeInputReadChecks() throws {
        let session = try makeSession(maximumFileBytes: 16)
        defer { session.close() }
        let path = try fixture(String(repeating: "a", count: 17), session: session)
        let oversized = try readResult(session, path: path, range: ["byte_length": .number(1)])
        XCTAssertEqual(oversized["isError"], .bool(true))
        let invalid = session.directory.appendingPathComponent("invalid.txt")
        try Data([0xFF]).write(to: invalid)
        let undecodable = try readResult(session, path: invalid.path, range: ["byte_length": .number(1)])
        XCTAssertEqual(undecodable["isError"], .bool(true))
    }

    // WO-627@v2: empty input is a terminal, zero-length Base64 window, not a special error.
    func testEmptyFileRange() throws {
        let session = try makeSession()
        defer { session.close() }
        let path = try fixture("", session: session)
        let payload = try readPayload(session, path: path, range: ["byte_length": .number(1)])
        XCTAssertTrue(try decodedWindow(payload).isEmpty)
        XCTAssertEqual(payload["total_bytes"], .number(0))
        XCTAssertEqual(payload["byte_length"], .number(0))
        XCTAssertEqual(payload["has_more"], .bool(false))
    }

    // WO-627@v2: exercise actual MCP framing and policy with no operator HOME inheritance.
    private func makeSession(
        maximumFileBytes: Int = ScanInputLimits.defaultMaximumFileBytes,
        config: PastewatchConfig? = nil
    ) throws -> MCPProtocolTests.LiveMCPSession {
        let bundled = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("PastewatchCLI")
        let binary = FileManager.default.fileExists(atPath: bundled.path) ? bundled
            : URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build/debug/PastewatchCLI")
        return try MCPProtocolTests.LiveMCPSession(
            executableURL: binary,
            maximumLineBytes: ScanInputLimits.defaultMaximumLineBytes,
            maximumFileBytes: maximumFileBytes,
            config: config
        )
    }

    // WO-627@v2: synthetic sensitive values are assembled only inside the test fixture.
    private func vaultFixture() -> String {
        "hv" + "s." + String(repeating: "Ab7Cd9Ef1Gh3", count: 4)
    }

    // WO-627@v2: each subprocess owns its fixtures and cleanup lifetime.
    private func fixture(_ content: String, session: MCPProtocolTests.LiveMCPSession, name: String = "input.txt") throws -> String {
        let url = session.directory.appendingPathComponent(name)
        try content.write(to: url, atomically: true, encoding: .utf8)
        return url.path
    }

    // WO-627@v2: response assertions never include file content or matched values in diagnostics.
    private func call(_ session: MCPProtocolTests.LiveMCPSession, method: String, params: JSONValue?) throws -> [String: JSONValue] {
        let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: method, params: params)
        try session.send(JSONEncoder().encode(request) + Data([0x0A]))
        let response = try XCTUnwrap(session.response(), "MCP response deadline expired")
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result else {
            throw NSError(domain: "MCPReadRangeTests", code: 1)
        }
        return result
    }

    // WO-627@v2: requests share the same live redaction store across all windows.
    private func readResult(_ session: MCPProtocolTests.LiveMCPSession, path: String, range: [String: JSONValue]) throws -> [String: JSONValue] {
        var arguments = range
        arguments["path"] = .string(path)
        return try call(session, method: "tools/call", params: .object([
            "name": .string("pastewatch_read_file"), "arguments": .object(arguments)
        ]))
    }

    // WO-627@v2: unwrap the existing MCP text envelope before examining range metadata.
    private func readPayload(_ session: MCPProtocolTests.LiveMCPSession, path: String, range: [String: JSONValue] = [:]) throws -> [String: JSONValue] {
        let result = try readResult(session, path: path, range: range)
        XCTAssertNotEqual(result["isError"], .bool(true), "Read returned a tool error")
        let text = try responseText(result)
        guard case .object(let payload) = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8)) else {
            throw NSError(domain: "MCPReadRangeTests", code: 2)
        }
        return payload
    }

    // WO-627@v2: only the text-block shape, not its potentially sensitive value, is diagnostic.
    private func responseText(_ result: [String: JSONValue]) throws -> String {
        guard case .array(let blocks) = result["content"], let first = blocks.first,
              case .object(let block) = first, case .string(let text) = block["text"] else {
            throw NSError(domain: "MCPReadRangeTests", code: 3)
        }
        return text
    }

    // WO-627@v2: distinguish legacy plain content from Base64 windows explicitly.
    private func plainContent(_ payload: [String: JSONValue]) throws -> String {
        guard case .string(let text) = payload["content"] else {
            throw NSError(domain: "MCPReadRangeTests", code: 4)
        }
        return text
    }

    // WO-627@v2: validate the encoding flag and actual decoded byte length together.
    private func decodedWindow(_ payload: [String: JSONValue]) throws -> Data {
        XCTAssertEqual(payload["encoding"], .string("base64"))
        let bytes = try XCTUnwrap(Data(base64Encoded: plainContent(payload)), "Invalid Base64 window")
        XCTAssertEqual(payload["byte_length"], .number(Double(bytes.count)))
        return bytes
    }

    // WO-627@v2: bounded iteration follows returned lengths, detecting missing or stalled continuation.
    private func collectWindows(_ session: MCPProtocolTests.LiveMCPSession, path: String, expected: Data, length: Int) throws -> Data {
        var collected = Data()
        for _ in 0...(expected.count / length) {
            let offset = collected.count
            let payload = try readPayload(session, path: path, range: [
                "byte_offset": .number(Double(offset)), "byte_length": .number(Double(length))
            ])
            let bytes = try decodedWindow(payload)
            XCTAssertLessThanOrEqual(bytes.count, length)
            XCTAssertEqual(payload["total_bytes"], .number(Double(expected.count)))
            XCTAssertEqual(payload["byte_offset"], .number(Double(offset)))
            let end = min(offset + length, expected.count)
            XCTAssertTrue(bytes == expected.subdata(in: offset..<end))
            collected.append(bytes)
            XCTAssertEqual(payload["has_more"], .bool(collected.count < expected.count))
            if payload["has_more"] == .bool(false) { return collected }
            guard !bytes.isEmpty, collected.count <= expected.count else { break }
        }
        XCTFail("Continuation did not reach EOF within the expected window count")
        return collected
    }
}
