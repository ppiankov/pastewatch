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

    // WO-603@v2: oversized transport records are discarded and framing recovers.
    func testMCPRejectsOversizedLineAndProcessesNextRequest() throws {
        let request = JSONRPCRequest(
            jsonrpc: "2.0",
            id: .int(7),
            method: "initialize",
            params: nil
        )
        var input = Data(repeating: 0x78, count: 128)
        input.append(0x0A)
        input.append(try JSONEncoder().encode(request))
        input.append(0x0A)

        let result = try runRawMCP(input: input, maximumLineBytes: 64)

        XCTAssertEqual(result.responses.count, 2)
        XCTAssertEqual(result.responses[0].error?.code, -32700)
        XCTAssertNil(result.responses[0].id)
        XCTAssertEqual(result.responses[1].id, .int(7))
        XCTAssertNil(result.responses[1].error)
        XCTAssertFalse(result.stderr.contains(String(repeating: "x", count: 16)))
    }

    // WO-603@v2: empty, CRLF, and final unterminated records preserve MCP framing.
    func testMCPBoundedReaderPreservesValidFramingVariants() throws {
        let first = JSONRPCRequest(
            jsonrpc: "2.0",
            id: .int(8),
            method: "initialize",
            params: nil
        )
        let second = JSONRPCRequest(
            jsonrpc: "2.0",
            id: .int(9),
            method: "initialize",
            params: nil
        )
        var input = Data("\n".utf8)
        input.append(try JSONEncoder().encode(first))
        input.append(Data("\r\n".utf8))
        input.append(try JSONEncoder().encode(second))

        let result = try runRawMCP(input: input, maximumLineBytes: 1_024)

        XCTAssertEqual(result.responses.map(\.id), [.int(8), .int(9)])
        XCTAssertTrue(result.responses.allSatisfy { $0.error == nil })
    }

    // WO-584@v2: MCP schema values and documentation derive from Severity ownership.
    func testToolsListSeveritySchemaUsesCanonicalCasesAndDefault() throws {
        let request = JSONRPCRequest(
            jsonrpc: "2.0",
            id: .int(1),
            method: "tools/list",
            params: nil
        )
        let response = try callMCPRequest(
            request,
            currentDirectory: FileManager.default.temporaryDirectory
        )

        guard case .object(let result) = response.result,
              case .array(let tools) = result["tools"],
              let readTool = tools.first(where: {
                  guard case .object(let tool) = $0 else { return false }
                  return tool["name"] == .string("pastewatch_read_file")
              }),
              case .object(let readToolObject) = readTool,
              case .object(let schema) = readToolObject["inputSchema"],
              case .object(let properties) = schema["properties"],
              case .object(let severity) = properties["min_severity"],
              case .array(let cases) = severity["enum"],
              case .string(let description) = severity["description"] else {
            XCTFail("Expected pastewatch_read_file min_severity schema")
            return
        }

        XCTAssertEqual(cases, Severity.allCases.map { .string($0.rawValue) })
        XCTAssertTrue(description.contains(
            "default: \(Severity.defaultGuardThreshold.rawValue)"
        ))
    }

    // WO-597@v2: write schema exposes one mutually exclusive local payload-file input.
    func testWriteFileSchemaOffersContentPathAsExclusivePayloadSource() throws {
        let request = JSONRPCRequest(
            jsonrpc: "2.0",
            id: .int(1),
            method: "tools/list",
            params: nil
        )
        let response = try callMCPRequest(
            request,
            currentDirectory: FileManager.default.temporaryDirectory
        )

        guard case .object(let result) = response.result,
              case .array(let tools) = result["tools"],
              let writeTool = tools.first(where: {
                  guard case .object(let tool) = $0 else { return false }
                  return tool["name"] == .string("pastewatch_write_file")
              }),
              case .object(let writeToolObject) = writeTool,
              case .object(let schema) = writeToolObject["inputSchema"],
              case .object(let properties) = schema["properties"],
              case .object = properties["contentPath"],
              case .array(let alternatives) = schema["oneOf"] else {
            XCTFail("Expected pastewatch_write_file contentPath schema")
            return
        }

        XCTAssertEqual(alternatives.count, 2)
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
        // WO-577@v3: diagnostic evidence must never echo the matched bytes.
        XCTAssertFalse(responseText.contains(secretValue), responseText)
        XCTAssertTrue(responseText.contains("Found 1 finding(s)."))
    }

    // WO-577@v3: every MCP diagnostic endpoint returns metadata without plaintext.
    func testDiagnosticScanEndpointsNeverSerializeMatchedValues() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-diagnostics-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let value = "PWDIAG-" + syntheticSuffix()
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "Diagnostic fixture", pattern: "PWDIAG-[A-F0-9]{12}")
        ]
        try JSONEncoder().encode(config).write(
            to: tempDir.appendingPathComponent(".pastewatch.json")
        )
        let fileURL = tempDir.appendingPathComponent("fixture.txt")
        try value.write(to: fileURL, atomically: true, encoding: .utf8)

        let calls: [(String, [String: JSONValue])] = [
            ("pastewatch_scan", ["text": .string(value)]),
            ("pastewatch_scan_file", ["path": .string(fileURL.path)]),
            ("pastewatch_scan_dir", ["path": .string(tempDir.path)]),
            ("pastewatch_check_output", ["text": .string(value)])
        ]

        for (name, arguments) in calls {
            let response = try callMCPTool(
                name: name,
                arguments: arguments,
                currentDirectory: tempDir
            )
            let encoded = try JSONEncoder().encode(response)
            let responseText = try XCTUnwrap(String(data: encoded, encoding: .utf8))
            XCTAssertFalse(responseText.contains(value), "\(name): \(responseText)")
            XCTAssertTrue(responseText.contains("Diagnostic fixture"), "\(name): \(responseText)")
        }
    }

    // WO-577@v3: guard policy suppresses explicit allowlist values on every scan surface.
    func testDiagnosticScanEndpointsHonorConfiguredAllowlist() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-allowlist-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let value = "PWALLOW-" + syntheticSuffix()
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "Allowlist fixture", pattern: "PWALLOW-[A-F0-9]{12}")
        ]
        config.allowedValues = [value]
        try JSONEncoder().encode(config).write(
            to: tempDir.appendingPathComponent(".pastewatch.json")
        )
        let fileURL = tempDir.appendingPathComponent("fixture.txt")
        try value.write(to: fileURL, atomically: true, encoding: .utf8)

        for (name, arguments) in [
            ("pastewatch_scan", ["text": JSONValue.string(value)]),
            ("pastewatch_scan_file", ["path": JSONValue.string(fileURL.path)]),
            ("pastewatch_scan_dir", ["path": JSONValue.string(tempDir.path)]),
            ("pastewatch_check_output", ["text": JSONValue.string(value)])
        ] {
            let response = try callMCPTool(
                name: name,
                arguments: arguments,
                currentDirectory: tempDir
            )
            let text = try joinedMCPContentText(response)
            XCTAssertFalse(text.contains("Allowlist fixture"), "\(name): \(text)")
        }
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

    // WO-549@v2: structured advisory evidence remains visible without mutation.
    func testReadFileSurfacesStructuredCredentialEvidenceAsAdvisory() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-structured-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let value = "CredentialValueWithEntropy123456789"
        let fileURL = tempDir.appendingPathComponent("config.json")
        try #"{"apiKey":"\#(value)"}"#.write(to: fileURL, atomically: true, encoding: .utf8)

        let response = try callMCPTool(
            name: "pastewatch_read_file",
            arguments: ["path": .string(fileURL.path)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)
        XCTAssertTrue(text.contains("\"clean\" : false"), text)
        XCTAssertTrue(text.contains("\"advisories\""), text)
        XCTAssertTrue(text.contains("\"Credential\""), text)
    }

    // WO-549@v2: agent-authored plaintext cannot bypass placeholder restoration.
    func testWriteFileBlocksAgentAuthoredPlaintextSecret() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-write-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "Write fixture", pattern: "PWWRITE-[A-F0-9]{12}")
        ]
        try JSONEncoder().encode(config).write(to: tempDir.appendingPathComponent(".pastewatch.json"))
        let target = tempDir.appendingPathComponent("output.txt")
        let value = "PWWRITE-" + syntheticSuffix()

        let response = try callMCPTool(
            name: "pastewatch_write_file",
            arguments: ["path": .string(target.path), "content": .string(value)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)
        XCTAssertTrue(text.contains("Write blocked"), text)
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    // WO-597@v2: the incident marker must never replace an existing target.
    func testWriteFileRejectsFileReferenceSentinelWithoutChangingTarget() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-mcp-sentinel-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let target = tempDir.appendingPathComponent("target.txt")
        let original = String(repeating: "preserved\n", count: 256)
        try original.write(to: target, atomically: true, encoding: .utf8)
        let payload = tempDir.appendingPathComponent("payload.txt")
        try "replacement".write(to: payload, atomically: true, encoding: .utf8)
        let marker = "@@FILE:" + payload.path + "@@"

        let response = try callMCPTool(
            name: "pastewatch_write_file",
            arguments: ["path": .string(target.path), "content": .string(marker)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)

        XCTAssertTrue(text.contains("Unsupported file-reference marker"), text)
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), original)
    }

    // WO-597@v2: local payload files use the normal write pipeline.
    func testWriteFileAcceptsCleanContentPath() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-mcp-content-path-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let payload = tempDir.appendingPathComponent("payload.txt")
        let target = tempDir.appendingPathComponent("target.txt")
        try "clean replacement\n".write(to: payload, atomically: true, encoding: .utf8)

        let response = try callMCPTool(
            name: "pastewatch_write_file",
            arguments: ["path": .string(target.path), "contentPath": .string(payload.path)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)

        XCTAssertTrue(text.contains("\"written\" : true"), text)
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "clean replacement\n")
    }

    // WO-597@v2: contentPath preserves the two-way placeholder contract in one MCP session.
    func testWriteFileContentPathResolvesReadPlaceholder() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-mcp-content-roundtrip-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let target = tempDir.appendingPathComponent("target.txt")
        let payload = tempDir.appendingPathComponent("payload.txt")
        let credential = "AIza" + String(repeating: "R", count: 35)
        try credential.write(to: target, atomically: true, encoding: .utf8)
        try "__PW_GOOGLE_API_KEY_1__".write(to: payload, atomically: true, encoding: .utf8)

        let responses = try callMCPRequests([
            toolRequest(
                id: 1,
                name: "pastewatch_read_file",
                arguments: ["path": .string(target.path)]
            ),
            toolRequest(
                id: 2,
                name: "pastewatch_write_file",
                arguments: ["path": .string(target.path), "contentPath": .string(payload.path)]
            ),
        ], currentDirectory: tempDir)

        XCTAssertEqual(responses.count, 2)
        XCTAssertTrue(try joinedMCPContentText(responses[0]).contains("__PW_GOOGLE_API_KEY_1__"))
        XCTAssertTrue(try joinedMCPContentText(responses[1]).contains("\"resolved\" : 1"))
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), credential)
    }

    // WO-597@v2: ambiguous payload selection fails before any target mutation.
    func testWriteFileRequiresExactlyOnePayloadSource() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-mcp-payload-choice-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let payload = tempDir.appendingPathComponent("payload.txt")
        let target = tempDir.appendingPathComponent("target.txt")
        try "payload".write(to: payload, atomically: true, encoding: .utf8)
        try "original".write(to: target, atomically: true, encoding: .utf8)

        let payloadCases: [[String: JSONValue]] = [
            ["path": .string(target.path)],
            [
                "path": .string(target.path),
                "content": .string("inline"),
                "contentPath": .string(payload.path),
            ],
        ]
        for arguments in payloadCases {
            let response = try callMCPTool(
                name: "pastewatch_write_file",
                arguments: arguments,
                currentDirectory: tempDir
            )
            let text = try joinedMCPContentText(response)
            XCTAssertTrue(text.contains("exactly one payload source"), text)
            XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "original")
        }
    }

    // WO-597@v2: invalid local payload files fail before the existing target changes.
    func testWriteFileRejectsInvalidContentPathsWithoutChangingTarget() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-mcp-invalid-content-path-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let target = tempDir.appendingPathComponent("target.txt")
        try "original".write(to: target, atomically: true, encoding: .utf8)
        let nonUTF8 = tempDir.appendingPathComponent("binary.txt")
        try Data([0xFF, 0xFE, 0xFD]).write(to: nonUTF8)
        let longLine = tempDir.appendingPathComponent("long-line.txt")
        try String(repeating: "x", count: ScanInputLimits.defaultMaximumLineBytes + 1)
            .write(to: longLine, atomically: true, encoding: .utf8)
        let invalidPaths = [
            tempDir.appendingPathComponent("missing.txt").path,
            tempDir.path,
            nonUTF8.path,
            longLine.path,
        ]

        for contentPath in invalidPaths {
            let response = try callMCPTool(
                name: "pastewatch_write_file",
                arguments: ["path": .string(target.path), "contentPath": .string(contentPath)],
                currentDirectory: tempDir
            )
            let text = try joinedMCPContentText(response)
            XCTAssertFalse(text.contains("\"written\" : true"), text)
            XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "original")
        }
    }

    // WO-597@v2: local payload mode cannot bypass plaintext-secret blocking.
    func testWriteFileContentPathBlocksPlaintextSecret() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-mcp-content-secret-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let payload = tempDir.appendingPathComponent("payload.txt")
        let target = tempDir.appendingPathComponent("target.txt")
        let credential = "AIza" + String(repeating: "R", count: 35)
        try credential.write(to: payload, atomically: true, encoding: .utf8)

        let response = try callMCPTool(
            name: "pastewatch_write_file",
            arguments: ["path": .string(target.path), "contentPath": .string(payload.path)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)

        XCTAssertTrue(text.contains("Write blocked"), text)
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        XCTAssertFalse(text.contains(credential), text)
    }

    // WO-595@v2: MCP scan_file returns a bounded error for a pathological line.
    func testScanFileRejectsLineOverDefaultLimit() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-mcp-line-limit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let file = tempDir.appendingPathComponent("long.txt")
        let content = String(repeating: "x", count: ScanInputLimits.defaultMaximumLineBytes + 1)
        try content.write(to: file, atomically: true, encoding: .utf8)

        let response = try callMCPTool(
            name: "pastewatch_scan_file",
            arguments: ["path": .string(file.path)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)

        XCTAssertTrue(text.contains("Scan limit exceeded"), text)
        XCTAssertTrue(text.contains(ScanInputLimits.lineBytesEnvironmentKey), text)
        XCTAssertFalse(text.contains(String(repeating: "x", count: 64)), text)
    }

    // WO-595@v2: MCP scan_dir propagates member limits instead of reporting a partial clean scan.
    func testScanDirectoryRejectsMemberOverDefaultLineLimit() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-mcp-dir-limit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let file = tempDir.appendingPathComponent("long.txt")
        let content = String(repeating: "x", count: ScanInputLimits.defaultMaximumLineBytes + 1)
        try content.write(to: file, atomically: true, encoding: .utf8)

        let response = try callMCPTool(
            name: "pastewatch_scan_dir",
            arguments: ["path": .string(tempDir.path)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)

        XCTAssertTrue(text.contains("Scan limit exceeded"), text)
        XCTAssertTrue(text.contains(ScanInputLimits.lineBytesEnvironmentKey), text)
        XCTAssertFalse(text.contains(String(repeating: "x", count: 64)), text)
    }

    // WO-549@v2: source-range rebasing must retain configured mutation authorization.
    func testReadFileRedactsConfiguredStructuredMatch() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-configured-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let value = ["operator", "@", "example.com"].joined()
        var config = PastewatchConfig.defaultConfig
        config.obfuscate = [ObfuscateEntry(type: "email", pattern: "@example.com")]
        try JSONEncoder().encode(config).write(to: tempDir.appendingPathComponent(".pastewatch.json"))
        let fileURL = tempDir.appendingPathComponent("configured.json")
        try #"{"contact":"\#(value)"}"#.write(to: fileURL, atomically: true, encoding: .utf8)

        let response = try callMCPTool(
            name: "pastewatch_read_file",
            arguments: ["path": .string(fileURL.path)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)
        XCTAssertFalse(text.contains(value), text)
        XCTAssertTrue(text.contains("__PW_EMAIL_1__"), text)
    }

    // WO-550@v2: malformed JSON must retain the raw fail-closed security scan.
    func testReadFileRedactsSecretInMalformedJSON() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-malformed-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let credential = "AIza" + String(repeating: "R", count: 35)
        let fileURL = tempDir.appendingPathComponent("broken.json")
        try #"{"token":"\#(credential)""#.write(to: fileURL, atomically: true, encoding: .utf8)

        let response = try callMCPTool(
            name: "pastewatch_read_file",
            arguments: ["path": .string(fileURL.path)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)
        XCTAssertFalse(text.contains(credential), text)
        XCTAssertTrue(text.contains("__PW_GOOGLE_API_KEY_1__"), text)
    }

    // WO-550@v2: malformed structured writes use the same raw fail-closed fallback.
    func testWriteFileBlocksSecretInMalformedJSON() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-mcp-malformed-write-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let credential = "AIza" + String(repeating: "R", count: 35)
        let target = tempDir.appendingPathComponent("broken.json")
        let content = #"{"token":"\#(credential)""#

        let response = try callMCPTool(
            name: "pastewatch_write_file",
            arguments: ["path": .string(target.path), "content": .string(content)],
            currentDirectory: tempDir
        )
        let text = try joinedMCPContentText(response)
        XCTAssertTrue(text.contains("Write blocked"), text)
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    private struct MCPCallResult {
        let response: JSONRPCResponse
        let stderr: String
    }

    // WO-603@v2: subprocess results keep transport diagnostics separate from protocol output.
    private struct MCPProcessResult {
        let responses: [JSONRPCResponse]
        let stderr: String
    }

    // WO-603@v2: feed raw framed input to the bounded MCP transport.
    private func runRawMCP(
        input: Data,
        maximumLineBytes: Int
    ) throws -> MCPProcessResult {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["mcp"]
        process.currentDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory())
        var environment = ProcessInfo.processInfo.environment
        environment[ScanInputLimits.lineBytesEnvironmentKey] = String(maximumLineBytes)
        process.environment = environment

        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        stdin.fileHandleForWriting.write(input)
        stdin.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        let errorOutput = String(
            data: stderr.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        XCTAssertEqual(process.terminationStatus, 0, errorOutput)
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let outputText = try XCTUnwrap(String(bytes: output, encoding: .utf8))
        let responses = try outputText
            .split(separator: "\n")
            .map { try JSONDecoder().decode(JSONRPCResponse.self, from: Data($0.utf8)) }
        return MCPProcessResult(responses: responses, stderr: errorOutput)
    }

    // WO-597@v2: construct write requests for content-path and sentinel coverage.
    private func toolRequest(
        id: Int,
        name: String,
        arguments: [String: JSONValue]
    ) -> JSONRPCRequest {
        JSONRPCRequest(
            jsonrpc: "2.0",
            id: .int(id),
            method: "tools/call",
            params: .object([
                "name": .string(name),
                "arguments": .object(arguments),
            ])
        )
    }

    // WO-603@v2: exercise multiple framed requests in one transport session.
    private func callMCPRequests(
        _ requests: [JSONRPCRequest],
        currentDirectory: URL
    ) throws -> [JSONRPCResponse] {
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
        for request in requests {
            stdin.fileHandleForWriting.write(try JSONEncoder().encode(request))
            stdin.fileHandleForWriting.write(Data("\n".utf8))
        }
        stdin.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        let errorOutput = String(
            data: stderr.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        XCTAssertEqual(process.terminationStatus, 0, errorOutput)
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let outputText = try XCTUnwrap(String(bytes: output, encoding: .utf8))
        return try outputText
            .split(separator: "\n")
            .map { try JSONDecoder().decode(JSONRPCResponse.self, from: Data($0.utf8)) }
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
        return try callMCPRequestWithDiagnostics(request, currentDirectory: currentDirectory)
    }

    // WO-584@v2: protocol tests exercise non-tool MCP requests through the real process.
    private func callMCPRequest(
        _ request: JSONRPCRequest,
        currentDirectory: URL
    ) throws -> JSONRPCResponse {
        try callMCPRequestWithDiagnostics(
            request,
            currentDirectory: currentDirectory
        ).response
    }

    // WO-577@v3: capture diagnostics separately to prove matched values never serialize.
    private func callMCPRequestWithDiagnostics(
        _ request: JSONRPCRequest,
        currentDirectory: URL
    ) throws -> MCPCallResult {
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
