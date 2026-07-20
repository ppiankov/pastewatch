import XCTest
@testable import PastewatchCore

final class MCPProtocolTests: XCTestCase {

    // MARK: - JSONValue encoding/decoding

    func testJSONValueStringEncodingDecoding() throws {
        let value = JSONValue.string("hello")
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    func testJSONValueNumberEncodingDecoding() throws {
        let value = JSONValue.number(42.5)
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    func testJSONValueBoolEncodingDecoding() throws {
        let trueValue = JSONValue.bool(true)
        let trueData = try JSONEncoder().encode(trueValue)
        let trueDecoded = try JSONDecoder().decode(JSONValue.self, from: trueData)
        XCTAssertEqual(trueDecoded, trueValue)

        let falseValue = JSONValue.bool(false)
        let falseData = try JSONEncoder().encode(falseValue)
        let falseDecoded = try JSONDecoder().decode(JSONValue.self, from: falseData)
        XCTAssertEqual(falseDecoded, falseValue)
    }

    func testJSONValueNullEncodingDecoding() throws {
        let value = JSONValue.null
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    func testJSONValueArrayEncodingDecoding() throws {
        let value = JSONValue.array([
            .string("a"),
            .number(1),
            .bool(true),
            .null
        ])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    func testJSONValueObjectEncodingDecoding() throws {
        let value = JSONValue.object([
            "name": .string("test"),
            "count": .number(3),
            "active": .bool(false)
        ])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    // MARK: - JSONRPCRequest decoding

    func testJSONRPCRequestDecoding() throws {
        let json = """
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            }
        }
        """
        let data = Data(json.utf8)
        let request = try JSONDecoder().decode(JSONRPCRequest.self, from: data)

        XCTAssertEqual(request.jsonrpc, "2.0")
        XCTAssertEqual(request.id, .int(1))
        XCTAssertEqual(request.method, "initialize")

        guard case .object(let params) = request.params else {
            XCTFail("Expected object params")
            return
        }
        XCTAssertEqual(params["protocolVersion"], .string("2024-11-05"))
    }

    // MARK: - JSONRPCResponse encoding

    func testJSONRPCResponseEncoding() throws {
        let response = JSONRPCResponse(
            jsonrpc: "2.0",
            id: .int(1),
            result: .object([
                "protocolVersion": .string("2024-11-05"),
                "serverInfo": .object([
                    "name": .string("pastewatch-cli"),
                    "version": .string("0.4.0")
                ])
            ]),
            error: nil
        )

        let data = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(JSONRPCResponse.self, from: data)

        XCTAssertEqual(decoded.jsonrpc, "2.0")
        XCTAssertEqual(decoded.id, .int(1))
        XCTAssertNil(decoded.error)

        guard case .object(let result) = decoded.result else {
            XCTFail("Expected object result")
            return
        }
        XCTAssertEqual(result["protocolVersion"], .string("2024-11-05"))
    }

    // MARK: - JSONRPCId variants

    func testJSONRPCIdIntDecoding() throws {
        let json = Data("""
        {"jsonrpc":"2.0","id":42,"method":"test","params":null}
        """.utf8)
        let request = try JSONDecoder().decode(JSONRPCRequest.self, from: json)
        XCTAssertEqual(request.id, .int(42))
    }

    func testJSONRPCIdStringDecoding() throws {
        let json = Data("""
        {"jsonrpc":"2.0","id":"req-1","method":"test","params":null}
        """.utf8)
        let request = try JSONDecoder().decode(JSONRPCRequest.self, from: json)
        XCTAssertEqual(request.id, .string("req-1"))
    }

    // WO-129: MCP scan_file must consume configured sharedPatternFiles.
    func testScanFileUsesSharedPatternFiles() throws {
        let secretValue = "PW" + "MCP-" + syntheticSuffix()
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let artifactURL = tempDir.appendingPathComponent("shared-patterns.json")
        let patterns = [
            SharedSecretPatternConfig(
                name: "wo129_mcp_shared",
                type: "github_token",
                regex: "PW" + #"MCP-[A-F0-9]{12}"#,
                policy: "redact"
            )
        ]
        try JSONEncoder().encode(patterns).write(to: artifactURL)

        var config = PastewatchConfig.defaultConfig
        config.sharedPatternFiles = [artifactURL.path]
        try JSONEncoder().encode(config).write(to: tempDir.appendingPathComponent(".pastewatch.json"))

        let fileURL = tempDir.appendingPathComponent("scan.txt")
        try "marker \(secretValue)\n".write(to: fileURL, atomically: true, encoding: .utf8)

        let response = try callMCPTool(
            name: "pastewatch_scan_file",
            arguments: ["path": .string(fileURL.path)],
            currentDirectory: tempDir
        )

        XCTAssertNil(response.error)
        let responseText = try joinedMCPContentText(response)
        XCTAssertTrue(responseText.contains(secretValue))
        XCTAssertTrue(responseText.contains("Found 1 finding(s)."))
    }

    // WO-521: MCP reads explain restorable markers and only nag when explicitly enabled.
    func testReadFileExplainsRestorableMarkersAndOperatorNoticeIsOptIn() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-notice-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let secretValue = "PWNOTICE-" + syntheticSuffix()
        let fileURL = tempDir.appendingPathComponent("notice.txt")
        try secretValue.write(to: fileURL, atomically: true, encoding: .utf8)

        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "Notice fixture", pattern: "PWNOTICE-[A-F0-9]{12}")
        ]
        let configURL = tempDir.appendingPathComponent(".pastewatch.json")
        try JSONEncoder().encode(config).write(to: configURL)

        let defaultResult = try callMCPToolWithDiagnostics(
            name: "pastewatch_read_file",
            arguments: ["path": .string(fileURL.path)],
            currentDirectory: tempDir
        )
        let responseText = try joinedMCPContentText(defaultResult.response)
        XCTAssertTrue(responseText.contains("__PW_TYPE_n__"), responseText)
        XCTAssertTrue(responseText.contains("two-way"), responseText)
        XCTAssertTrue(responseText.contains("pastewatch_write_file"), responseText)
        XCTAssertTrue(responseText.contains("not corruption"), responseText)
        XCTAssertTrue(responseText.contains("malformed"), responseText)
        XCTAssertFalse(defaultResult.stderr.contains("MCP REDACTED"), defaultResult.stderr)

        config.operatorRedactionNotices = true
        config.placeholderPrefix = "SAFE_MARKER_"
        try JSONEncoder().encode(config).write(to: configURL)
        let enabledResult = try callMCPToolWithDiagnostics(
            name: "pastewatch_read_file",
            arguments: ["path": .string(fileURL.path)],
            currentDirectory: tempDir
        )
        // WO-522@v3: the note must name the custom format that appears in this session.
        let customPrefixText = try joinedMCPContentText(enabledResult.response)
        XCTAssertTrue(customPrefixText.contains("SAFE_MARKER_001"), customPrefixText)
        XCTAssertFalse(customPrefixText.contains("__PW_TYPE_n__"), customPrefixText)
        XCTAssertTrue(enabledResult.stderr.contains("MCP REDACTED 1 secret(s)"), enabledResult.stderr)
        XCTAssertFalse(enabledResult.stderr.contains(secretValue), enabledResult.stderr)
    }

    private struct MCPCallResult {
        let response: JSONRPCResponse
        let stderr: String
    }

    // WO-521: retain the response-only helper for existing protocol tests.
    private func callMCPTool(
        name: String,
        arguments: [String: JSONValue],
        currentDirectory: URL
    ) throws -> JSONRPCResponse {
        try callMCPToolWithDiagnostics(
            name: name,
            arguments: arguments,
            currentDirectory: currentDirectory
        ).response
    }

    // WO-521: expose stderr so tests can prove operator notices are opt-in.
    private func callMCPToolWithDiagnostics(
        name: String,
        arguments: [String: JSONValue],
        currentDirectory: URL
    ) throws -> MCPCallResult {
        let request = JSONRPCRequest(
            jsonrpc: "2.0",
            id: .int(1),
            method: "tools/call",
            params: .object([
                "name": .string(name),
                "arguments": .object(arguments)
            ])
        )
        let requestData = try JSONEncoder().encode(request)

        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["mcp"]
        process.currentDirectoryURL = currentDirectory

        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        stdin.fileHandleForWriting.write(requestData)
        stdin.fileHandleForWriting.write(Data("\n".utf8))
        stdin.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        // WO-521: capture stderr after exit without exposing it unless an assertion fails.
        let errorOutput = String(
            data: stderr.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        XCTAssertEqual(process.terminationStatus, 0)
        let output = String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard let line = output.split(separator: "\n").first else {
            XCTFail("Expected MCP response, stderr: \(errorOutput)")
            throw NSError(domain: "MCPProtocolTests", code: 1)
        }
        // WO-521: return response and diagnostics from the same subprocess invocation.
        let response = try JSONDecoder().decode(JSONRPCResponse.self, from: Data(line.utf8))
        return MCPCallResult(response: response, stderr: errorOutput)
    }

    private func joinedMCPContentText(_ response: JSONRPCResponse) throws -> String {
        guard case .object(let result) = response.result,
              case .array(let content) = result["content"] else {
            XCTFail("Expected MCP content array")
            throw NSError(domain: "MCPProtocolTests", code: 2)
        }

        return content.compactMap { item in
            guard case .object(let object) = item,
                  case .string(let text) = object["text"] else {
                return nil
            }
            return text
        }.joined(separator: "\n")
    }

    private func pastewatchCLIURL() -> URL {
        let productsDirectory = Bundle.main.bundleURL.deletingLastPathComponent()
        let bundled = productsDirectory.appendingPathComponent("PastewatchCLI")
        if FileManager.default.fileExists(atPath: bundled.path) {
            return bundled
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".build/debug/PastewatchCLI")
    }

    private func syntheticSuffix() -> String {
        String(UUID().uuidString.replacingOccurrences(of: "-", with: "").uppercased().prefix(12))
    }
}
