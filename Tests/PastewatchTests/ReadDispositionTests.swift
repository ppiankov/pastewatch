import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-707@v3: metadata must describe the bytes returned, not imply protection from severity alone.
final class ReadDispositionTests: XCTestCase {
    // WO-707@v3: the real suggestion and MCP paths prove promotion without changing scanner policy.
    func testSuggestedRulePromotesPlaintextAdvisoryAndRestoresBytes() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var config = PastewatchConfig.defaultConfig
            try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
            let value = ["fixture", "phrase", "7"].joined()
            let key = ["store", "Pass", "word"].joined()
            let source = key + "=" + value + "\n"
            let file = root.appendingPathComponent("key.properties")
            try Data(source.utf8).write(to: file)
            let before = try read(server(root: root, config: config), file: file)
            XCTAssertTrue(try content(before).utf8.elementsEqual(source.utf8))
            let advisories = try entries(before, key: "advisories")
            XCTAssertEqual(advisories.count, 1)
            XCTAssertEqual(advisories.first?["disposition"], .string("advisory_unmasked"))
            XCTAssertEqual(advisories.first?["severity"], .string("critical"))
            try assertNotice(before, value: value, file: file, line: 1)

            let suggestion = try suggest(root: root, file: file)
            XCTAssertEqual(suggestion.status, 0)
            XCTAssertFalse(suggestion.output.range(of: Data(value.utf8)) != nil)
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: suggestion.output) as? [String: Any])
            let rule = try XCTUnwrap(object["rule"] as? [String: Any])
            config.customRules = [try JSONDecoder().decode(CustomRuleConfig.self,
                from: JSONSerialization.data(withJSONObject: rule))]
            try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
            let effective = try ConfigValidator.resolveValidated().config
            let session = server(root: root, config: effective)
            let after = try read(session, file: file)
            let masked = try content(after)
            XCTAssertFalse(masked.contains(value))
            XCTAssertEqual(try entries(after, key: "redactions").count, 1)
            XCTAssertEqual(try entries(after, key: "redactions").first?["disposition"], .string("masked"))
            XCTAssertNil(after["notice"])
            XCTAssertTrue(try entries(after, key: "advisories").isEmpty)
            let written = try call(session, tool: "pastewatch_write_file", arguments: [
                "path": .string(file.path), "content": .string(masked)
            ])
            XCTAssertNil(written["isError"])
            XCTAssertEqual(try payload(written)["written"], .bool(true))
            XCTAssertTrue(try Data(contentsOf: file).elementsEqual(source.utf8))
        }
    }

    // WO-707@v3: clean and wholly masked reads must not carry an advisory plaintext notice.
    func testCleanAndIntrinsicReadMetadataDoesNotChangeContentShape() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let session = server(root: root, config: .defaultConfig)
            let file = root.appendingPathComponent("fixture.txt")
            let clean = "ordinary text\n"
            try Data(clean.utf8).write(to: file)
            let first = try read(session, file: file)
            XCTAssertEqual(Set(first.keys), ["content", "redactions", "advisories", "clean"])
            XCTAssertTrue(try content(first).utf8.elementsEqual(clean.utf8))
            let value = ["AK", "IA", String(repeating: "Q", count: 16)].joined()
            try Data((value + "\n").utf8).write(to: file)
            let masked = try read(session, file: file)
            XCTAssertNil(masked["notice"])
            XCTAssertFalse(try content(masked).contains(value))
            let entry = try XCTUnwrap(try entries(masked, key: "redactions").first)
            XCTAssertEqual(Set(entry.keys), ["type", "severity", "line", "placeholder", "disposition"])
            XCTAssertEqual(entry["disposition"], .string("masked"))
            XCTAssertEqual(entry["severity"], .string("critical"))
        }
    }

    // WO-707@v3: advisory metadata remains whole-file metadata for both line and byte windows.
    func testReadWindowsKeepDispositionAndNoticeOutsideContent() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let value = ["fixture", "phrase", "7"].joined()
            let source = "ordinary text\n" + ["store", "Pass", "word"].joined() + "=" + value + "\n"
            let file = root.appendingPathComponent("key.properties")
            try Data(source.utf8).write(to: file)
            let session = server(root: root, config: .defaultConfig)
            let full = try read(session, file: file)
            try assertNotice(full, value: value, file: file, line: 2)
            for range in [
                ["start_line": JSONValue.number(1), "line_count": .number(1)],
                ["byte_offset": .number(0), "byte_length": .number(14)]
            ] {
                let window = try read(session, file: file, range: range)
                XCTAssertTrue(window["notice"] == full["notice"])
                XCTAssertTrue(window["advisories"] == full["advisories"])
                if case .string("base64") = window["encoding"] {
                    let bytes = try XCTUnwrap(Data(base64Encoded: content(window)))
                    XCTAssertTrue(bytes.elementsEqual(source.utf8.prefix(14)))
                } else {
                    XCTAssertTrue(try content(window).utf8.elementsEqual("ordinary text\n".utf8))
                }
            }
        }
    }

    // WO-707@v3: every type exercises the production responder with default and each operator-authorized source.
    func testEverySensitiveDataTypeHasTruthfulReadDisposition() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["fixture", "phrase", "7"].joined()
            let source = "before " + value + " after\n"
            let range = try XCTUnwrap(source.range(of: value))
            for type in SensitiveDataType.allCases {
                let variants = [
                    DetectedMatch(type: type, value: value, range: range),
                    DetectedMatch(type: type, value: value, range: range, customRuleName: "operator-fixture"),
                    DetectedMatch(type: type, value: value, range: range, mutationAuthorizationSources: [.exactKnownSecret]),
                    DetectedMatch(type: type, value: value, range: range, mutationAuthorizationSources: [.configuredObfuscate])
                ]
                for match in variants {
                    let decision = MCPReadDecision.evaluate(matches: [match], content: source, config: .defaultConfig,
                                                            minimumSeverity: .low, filePath: nil)
                    let result = try respond(decision, content: source)
                    let view = try content(result)
                    let masked = try entries(result, key: "redactions")
                    let advisory = try entries(result, key: "advisories")
                    XCTAssertEqual(masked.count + advisory.count, 1, type.rawValue)
                    for entry in masked + advisory {
                        let disposition = try XCTUnwrap(entry["disposition"], type.rawValue)
                        XCTAssertTrue([JSONValue.string("masked"), .string("advisory_unmasked")].contains(disposition))
                        XCTAssertEqual(disposition == .string("masked"), !view.contains(value), type.rawValue)
                        XCTAssertEqual(entry["severity"], .string(match.effectiveSeverity.rawValue), type.rawValue)
                    }
                    let partition = partitionMutationMatches([match], site: .cliScan, minAdvisorySeverity: .low)
                    let authority = partition.authorized.isEmpty ? "advisory" : "mutate"
                    XCTAssertEqual(Finding(match).authority, authority, type.rawValue)
                    XCTAssertEqual(GitLogMatchOutput(match).authority, authority, type.rawValue)
                    XCTAssertEqual(result["notice"] == nil, advisory.isEmpty, type.rawValue)
                }
            }
        }
    }

    // WO-707@v3: callers must learn the plaintext boundary before invoking a file read.
    func testReadToolDescriptionExplainsAuthorityAndPlaintextAdvisories() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let response = try XCTUnwrap(server(root: root, config: .defaultConfig).handleRequest(JSONRPCRequest(
                jsonrpc: "2.0", id: .int(1), method: "tools/list", params: nil
            )))
            guard case .object(let result) = response.result, case .array(let tools) = result["tools"],
                  let tool = tools.first(where: {
                      guard case .object(let tool) = $0 else { return false }
                      return tool["name"] == .string("pastewatch_read_file")
                  }), case .object(let definition) = tool, case .string(let description) = definition["description"] else {
                return XCTFail("Missing read tool description")
            }
            for phrase in ["intrinsic formats", "exact known values", "customRules", "PLAINTEXT",
                           "not protected", "advisory_unmasked", "disposition=masked", "suggest-rule"] {
                XCTAssertTrue(description.contains(phrase), phrase)
            }
        }
    }

    // WO-707@v3: overlap suppression follows actual replacement spans, not equal values elsewhere in the file.
    func testCoveredAdvisoryDoesNotHideAnotherPlaintextOccurrence() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["fixture", "phrase", "7"].joined()
            let source = value + "\n" + value + "\n"
            let first = try XCTUnwrap(source.range(of: value))
            let second = try XCTUnwrap(source.range(of: value, range: first.upperBound..<source.endIndex))
            let protected = DetectedMatch(type: .credential, value: value, range: first, customRuleName: "operator-fixture")
            let covered = DetectedMatch(type: .credential, value: value, range: first)
            let unmasked = DetectedMatch(type: .credential, value: value, range: second, line: 2)
            let decision = MCPReadDecision(authorized: [protected], reportedAdvisories: [covered, unmasked])
            let result = try respond(decision, content: source)
            XCTAssertEqual(try entries(result, key: "redactions").count, 1)
            let advisories = try entries(result, key: "advisories")
            XCTAssertEqual(advisories.count, 1)
            XCTAssertEqual(advisories.first?["line"], .number(2))
            XCTAssertEqual(advisories.first?["disposition"], .string("advisory_unmasked"))
            XCTAssertTrue(try content(result).hasSuffix(value + "\n"))
            try assertNotice(result, value: value, file: URL(fileURLWithPath: "/tmp/fixture.txt"), line: 2)
        }
    }

    // WO-707@v3: exhaustive fixtures use the same checked rewrite, metadata and encoding as the read handler.
    private func respond(_ decision: MCPReadDecision, content: String) throws -> [String: JSONValue] {
        let path = "/tmp/fixture.txt"
        let (response, _) = decision.response(request: (id: .int(1), filePath: path), content: content,
            store: RedactionStore(), encode: { view, entries in
                var result = decision.findingMetadata(entries: entries, content: content, filePath: path)
                result["content"] = .string(view)
                return try decision.encodePayload(.object(result))
            }, onFailure: { _ in
                XCTFail("Read responder refused a valid fixture")
                return JSONRPCResponse(jsonrpc: "2.0", id: .int(1), result: .object(["isError": .bool(true)]), error: nil)
            })
        guard case .object(let result) = response.result else { throw CocoaError(.coderInvalidValue) }
        return try payload(result)
    }

    // WO-707@v3: diagnostics contain only finding metadata and the quoted file/line remedy.
    private func assertNotice(_ payload: [String: JSONValue], value: String, file: URL, line: Int) throws {
        guard case .string(let notice) = payload["notice"] else { return XCTFail("Missing plaintext notice") }
        XCTAssertTrue(notice.contains("PLAINTEXT"))
        XCTAssertTrue(notice.lowercased().contains("not protected"))
        XCTAssertTrue(notice.contains("Credential") && notice.contains("line \(line)"))
        XCTAssertTrue(notice.lowercased().contains("pastewatch passes when unsure"))
        XCTAssertTrue(notice.contains("pastewatch-cli suggest-rule --file "))
        XCTAssertTrue(notice.contains(file.path) && notice.contains("--line \(line)"))
        XCTAssertFalse(notice.contains(value))
        XCTAssertFalse(notice.contains("length") || notice.contains("hash") || notice.contains("fingerprint"))
    }

    // WO-707@v3: subprocess output stays in memory and uses only the fixture-owned configuration.
    private struct CommandResult {
        let status: Int32
        let output: Data
    }

    // WO-707@v3: AC5 consumes the actual command's JSON snippet rather than reproducing rule derivation.
    private func suggest(root: URL, file: URL) throws -> CommandResult {
        let process = Process(), stdout = Pipe(), stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = ["suggest-rule", "--file", file.path, "--line", "1", "--format", "json"]
        process.currentDirectoryURL = root
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let errors = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertTrue(errors.isEmpty)
        return CommandResult(status: process.terminationStatus, output: output)
    }

    // WO-707@v3: injected executable identity keeps protocol tests independent of installed binaries.
    private func server(root: URL, config: PastewatchConfig) -> MCPServer {
        let identity = MCPExecutableIdentity(realPath: root.appendingPathComponent("executable").path,
                                             inode: 1, device: 1, modifiedAt: Date(timeIntervalSince1970: 1_000))
        return MCPServer(config: config, executableFreshness: MCPExecutableFreshness(
            invokedPath: identity.realPath, lookup: { _ in identity }
        ))
    }

    // WO-707@v3: reads use the real handler and retain its single JSON text block.
    private func read(_ server: MCPServer, file: URL, range: [String: JSONValue] = [:]) throws -> [String: JSONValue] {
        var arguments = range
        arguments["path"] = .string(file.path)
        let result = try call(server, tool: "pastewatch_read_file", arguments: arguments)
        XCTAssertNil(result["isError"])
        guard case .array(let blocks) = result["content"] else { throw CocoaError(.coderInvalidValue) }
        XCTAssertEqual(blocks.count, 1)
        return try payload(result)
    }

    // WO-707@v3: protocol helpers never render content or fixture values in diagnostics.
    private func call(_ server: MCPServer, tool: String, arguments: [String: JSONValue]) throws -> [String: JSONValue] {
        let response = try XCTUnwrap(server.handleRequest(JSONRPCRequest(
            jsonrpc: "2.0", id: .int(1), method: "tools/call",
            params: .object(["name": .string(tool), "arguments": .object(arguments)])
        )))
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result else { throw CocoaError(.coderInvalidValue) }
        return result
    }

    // WO-707@v3: nested JSON is decoded without printing content on malformed-response failures.
    private func payload(_ result: [String: JSONValue]) throws -> [String: JSONValue] {
        guard case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"],
              case .object(let payload) = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8)) else {
            throw CocoaError(.coderInvalidValue)
        }
        return payload
    }

    // WO-707@v3: failures identify only missing metadata, never its content.
    private func content(_ payload: [String: JSONValue]) throws -> String {
        guard case .string(let content) = payload["content"] else { throw CocoaError(.coderInvalidValue) }
        return content
    }

    // WO-707@v3: manifest entries are compared as metadata rather than secret-bearing payloads.
    private func entries(_ payload: [String: JSONValue], key: String) throws -> [[String: JSONValue]] {
        guard case .array(let entries) = payload[key] else { throw CocoaError(.coderInvalidValue) }
        return try entries.map {
            guard case .object(let entry) = $0 else { throw CocoaError(.coderInvalidValue) }
            return entry
        }
    }
}
