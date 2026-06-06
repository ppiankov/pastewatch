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

    private func callMCPTool(
        name: String,
        arguments: [String: JSONValue],
        currentDirectory: URL
    ) throws -> JSONRPCResponse {
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

        XCTAssertEqual(process.terminationStatus, 0)
        let output = String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard let line = output.split(separator: "\n").first else {
            let errorOutput = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            XCTFail("Expected MCP response, stderr: \(errorOutput)")
            throw NSError(domain: "MCPProtocolTests", code: 1)
        }
        return try JSONDecoder().decode(JSONRPCResponse.self, from: Data(line.utf8))
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
