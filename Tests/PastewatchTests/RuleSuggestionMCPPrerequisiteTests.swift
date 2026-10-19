import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-713@v1: operator key anchors must remain visible to the real structured-file scanner.
final class RuleSuggestionMCPPrerequisiteTests: XCTestCase {
    // WO-713@v1: synthetic fixture values stay in test memory and out of failure diagnostics.
    private struct Fixture {
        let fileName: String
        let prefix: String
        let anchor: String
        let value: String
        let suffix: String
        let valuePattern: String

        // WO-713@v1: the original formatting is the byte-for-byte preservation oracle.
        var content: String { prefix + anchor + value + suffix + "\n" }
    }

    // WO-713@v1: read and write must share the same in-memory placeholder mappings.
    private struct ReadSession {
        let server: MCPServer
        let file: URL
        let payload: [String: JSONValue]
    }

    // WO-713@v1: compare detector metadata without exposing matched values in XCTest failures.
    private struct MatchLocation: Hashable {
        let type: SensitiveDataType
        let line: Int
        let lowerByte: Int
        let upperByte: Int
    }

    // WO-713@v1: compiling on the full line is insufficient if structured scans discard the key context.
    func testKeyAnchoredRulesMaskStructuredMCPReads() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in fixtures() {
                let content = fixture.content
                let rule = anchoredRule(fixture)
                let compiled = try CustomRule.compile([rule])
                XCTAssertFalse(DetectionRules.isTestCredential(fixture.value), fixture.fileName)
                XCTAssertEqual(compiled[0].regex.numberOfMatches(in: content,
                    range: NSRange(content.startIndex..., in: content)), 1, fixture.fileName)
                let session = try read(content, fileName: fixture.fileName, rules: [rule], root: root)
                let result = session.payload
                guard case .array(let redactions) = result["redactions"],
                      case .string(let view) = result["content"] else { throw CocoaError(.coderInvalidValue) }
                XCTAssertEqual(redactions.count, 1, fixture.fileName)
                XCTAssertFalse(view.contains(fixture.value), fixture.fileName)
                let marker = Obfuscator.makeMCPPlaceholder(type: .credential, number: 1)
                let expected = fixture.prefix + fixture.anchor + marker + fixture.suffix + "\n"
                XCTAssertTrue(Data(view.utf8).elementsEqual(Data(expected.utf8)), fixture.fileName)
            }
        }
    }

    // WO-713@v1: a valid masked view must remain writable through the server that produced its mappings.
    func testKeyAnchoredMCPReadWriteRoundTrip() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in fixtures() {
                let session = try read(fixture.content, fileName: fixture.fileName,
                                       rules: [anchoredRule(fixture)], root: root)
                guard case .string(let view) = session.payload["content"] else { throw CocoaError(.coderInvalidValue) }
                let written = try call(session.server, name: "pastewatch_write_file", arguments: [
                    "path": .string(session.file.path), "content": .string(view)
                ])
                XCTAssertNil(written["isError"], fixture.fileName)
                if written["isError"] != .bool(true) {
                    XCTAssertEqual(try payload(written)["written"], .bool(true), fixture.fileName)
                }
                XCTAssertTrue(try Data(contentsOf: session.file).elementsEqual(Data(fixture.content.utf8)), fixture.fileName)
            }
        }
    }

    // WO-713@v1: editing benign text cannot make known placeholders look like newly supplied plaintext.
    func testKeyAnchoredMCPEditRetainsResolvableView() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try XCTUnwrap(fixtures().first { $0.fileName == "fixture.env" })
            let content = "mode=before\n" + fixture.content
            let session = try read(content, fileName: fixture.fileName, rules: [anchoredRule(fixture)], root: root)
            let edited = try call(session.server, name: "pastewatch_edit_file", arguments: [
                "path": .string(session.file.path), "old_string": .string("mode=before"), "new_string": .string("mode=after")
            ])
            XCTAssertNil(edited["isError"])
            let expected = Data(("mode=after\n" + fixture.content).utf8)
            XCTAssertTrue(try Data(contentsOf: session.file).elementsEqual(expected))
        }
    }

    // WO-713@v1: literal matches found by the parsed pass must not be duplicated by the raw pass.
    func testLiteralRulesMaskTheSameMCPFixtures() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in fixtures() {
                let content = fixture.content
                let rule = CustomRuleConfig(name: "literal-control",
                                            pattern: NSRegularExpression.escapedPattern(for: fixture.value))
                _ = try CustomRule.compile([rule])
                let config = configuration([rule])
                let matches = try DirectoryScanner.scanFileContentOrThrow(content: content,
                    ext: URL(fileURLWithPath: fixture.fileName).pathExtension, relativePath: fixture.fileName, config: config)
                XCTAssertEqual(matches.filter { $0.customRuleName != nil }.count, 1, fixture.fileName)
                let result = try read(content, fileName: fixture.fileName, rules: [rule], root: root).payload
                guard case .array(let redactions) = result["redactions"],
                      case .string(let view) = result["content"] else { throw CocoaError(.coderInvalidValue) }
                XCTAssertEqual(redactions.count, 1, fixture.fileName)
                XCTAssertFalse(view.contains(fixture.value), fixture.fileName)
            }
        }
    }

    // WO-713@v1: overlapping source-only rules cannot duplicate custom spans already found in parsed values.
    func testRawCustomOverlapKeepsSingleParsedMatch() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in fixtures() {
                let partial = CustomRuleConfig(name: "source-partial",
                    pattern: "(?<=" + NSRegularExpression.escapedPattern(for: fixture.anchor) + ")[A-Za-z]+")
                let literal = CustomRuleConfig(name: "literal-control",
                    pattern: NSRegularExpression.escapedPattern(for: fixture.value))
                let config = configuration([partial, literal])
                let matches = try DirectoryScanner.scanFileContentOrThrow(content: fixture.content,
                    ext: URL(fileURLWithPath: fixture.fileName).pathExtension, relativePath: fixture.fileName, config: config)
                XCTAssertEqual(matches.filter { $0.customRuleName != nil }.count, 1, fixture.fileName)
                let result = try read(fixture.content, fileName: fixture.fileName,
                                      rules: [partial, literal], root: root).payload
                guard case .array(let redactions) = result["redactions"] else { throw CocoaError(.coderInvalidValue) }
                XCTAssertEqual(redactions.count, 1, fixture.fileName)
            }
        }
    }

    // WO-713@v1: a source-context rule cannot change existing JSON or XML built-in locations.
    func testBuiltInLocationsRemainUnchanged() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let key = "AKIA" + String(repeating: "Q", count: 16)
            let value = ["fixture", "phrase", "7"].joined()
            let json = "{\n  \"note\": \"a\\\\b\\n\\u0063\",\n  \"access\": \"" + key + "\",\n  \"label\": \"" + value + "\"\n}\n"
            let tag = ["pass", "word"].joined()
            let xml = "<config>\n<" + tag + ">" + value + "</" + tag + ">\n<note>" + value + "</note>\n</config>\n"
            for ext in ["json", "xml"] {
                let content = ext == "json" ? json : xml
                let pattern = ext == "json" ? "(?<=\"label\": \")[^\"\\r\\n]+(?=\")" : "(?<=<note>)[^<]+(?=</note>)"
                let baseline = try DirectoryScanner.scanFileContentOrThrow(content: content, ext: ext,
                    relativePath: "fixture." + ext, config: configuration([]))
                let configured = try DirectoryScanner.scanFileContentOrThrow(content: content, ext: ext,
                    relativePath: "fixture." + ext, config: configuration([.init(name: "context", pattern: pattern)]))
                XCTAssertTrue(baseline.contains { $0.type == (ext == "json" ? .awsKey : .xmlCredential) }, ext)
                XCTAssertEqual(locations(baseline, in: content), locations(configured, in: content), ext)
            }
        }
    }

    // WO-713@v1: CLI JSON must report the configured source finding once at its original line.
    func testScanJSONReportsCustomRuleOnceAtSourceLine() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try XCTUnwrap(fixtures().first { $0.fileName.hasSuffix(".properties") })
            let file = root.appendingPathComponent(fixture.fileName)
            try Data(("# heading\n" + fixture.content).utf8).write(to: file)
            try JSONEncoder().encode(configuration([anchoredRule(fixture)]))
                .write(to: root.appendingPathComponent(".pastewatch.json"))
            let process = Process()
            let output = Pipe()
            let errors = Pipe()
            process.executableURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
            process.arguments = ["scan", "--file", file.path, "--format", "json"]
            process.currentDirectoryURL = root
            process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
            process.standardOutput = output
            process.standardError = errors
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            _ = errors.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 6)
            let response = try JSONDecoder().decode(ScanOutput.self, from: data)
            let custom = response.findings.filter { !$0.projectExemptible }
            XCTAssertEqual(custom.count, 1)
            XCTAssertTrue(custom.allSatisfy { $0.type == SensitiveDataType.credential.rawValue })
            XCTAssertEqual(custom.first?.line, 2)
        }
    }

    // WO-713@v1: raw text isolates the context loss from rule compilation and mutation authorization.
    private func fixtures() -> [Fixture] {
        let key = ["pass", "word"].joined()
        let value = ["fixture", "phrase", "7"].joined()
        let spaced = ["fixture", "phrase", "7"].joined(separator: " ")
        return [
            Fixture(fileName: "raw.txt", prefix: "", anchor: key + "=", value: value, suffix: "", valuePattern: "[^\\s#\\r\\n]+"),
            Fixture(fileName: "fixture.properties", prefix: "", anchor: "store" + "Pass" + "word=", value: value,
                    suffix: "", valuePattern: "[^\\r\\n]*[^\\s\\r\\n]"),
            Fixture(fileName: "fixture.env", prefix: "", anchor: key + "=", value: value, suffix: "", valuePattern: "[^\\s#\\r\\n]+"),
            Fixture(fileName: "quoted.env", prefix: "", anchor: key + "=\"", value: spaced,
                    suffix: "\"", valuePattern: "[^\"\\r\\n]+(?=\")"),
            Fixture(fileName: "fixture.yaml", prefix: "", anchor: key + ": \"", value: value,
                    suffix: "\"  # comment", valuePattern: "[^\"\\r\\n]+(?=\")"),
            Fixture(fileName: "fixture.json", prefix: "{\n  ", anchor: "\"" + key + "\": \"", value: value,
                    suffix: "\"\n}", valuePattern: "[^\"\\r\\n]+(?=\")")
        ]
    }

    // WO-713@v1: source-context patterns are ordinary operator rules with the standard severity.
    private func anchoredRule(_ fixture: Fixture) -> CustomRuleConfig {
        CustomRuleConfig(name: "source-context", pattern: "(?<=" + NSRegularExpression.escapedPattern(for: fixture.anchor) +
                         ")" + fixture.valuePattern, severity: Severity.defaultCustomRuleSeverity.rawValue)
    }

    // WO-713@v1: advisory credential recognition remains separate from custom-rule authorization.
    private func configuration(_ rules: [CustomRuleConfig]) -> PastewatchConfig {
        var config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
        config.customRules = rules
        return config
    }

    // WO-713@v1: byte coordinates compare source ranges independently of String storage identity.
    private func locations(_ matches: [DetectedMatch], in content: String) -> Set<MatchLocation> {
        Set(matches.filter { $0.customRuleName == nil }.map {
            MatchLocation(type: $0.type, line: $0.line,
                lowerByte: content.utf8.distance(from: content.utf8.startIndex, to: $0.range.lowerBound),
                upperByte: content.utf8.distance(from: content.utf8.startIndex, to: $0.range.upperBound))
        })
    }

    // WO-713@v1: actual MCP dispatch uses isolated config and an injected stable executable identity.
    private func read(
        _ content: String, fileName: String, rules: [CustomRuleConfig], root: URL
    ) throws -> ReadSession {
        let file = root.appendingPathComponent(fileName)
        try Data(content.utf8).write(to: file)
        let identity = MCPExecutableIdentity(realPath: root.appendingPathComponent("executable").path,
                                             inode: 1, device: 1, modifiedAt: Date(timeIntervalSince1970: 1_000))
        let server = MCPServer(config: configuration(rules), executableFreshness: MCPExecutableFreshness(
            invokedPath: identity.realPath, lookup: { _ in identity }
        ))
        let result = try call(server, name: "pastewatch_read_file", arguments: ["path": .string(file.path)])
        XCTAssertNil(result["isError"])
        return ReadSession(server: server, file: file, payload: try payload(result))
    }

    // WO-713@v1: protocol helpers never print captured content or original values.
    private func call(_ server: MCPServer, name: String, arguments: [String: JSONValue]) throws -> [String: JSONValue] {
        let response = try XCTUnwrap(server.handleRequest(JSONRPCRequest(jsonrpc: "2.0", id: .int(1),
            method: "tools/call", params: .object(["name": .string(name), "arguments": .object(arguments)]))))
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result else { throw CocoaError(.coderInvalidValue) }
        return result
    }

    // WO-713@v1: unwrap the existing nested JSON payload without changing the MCP surface.
    private func payload(_ result: [String: JSONValue]) throws -> [String: JSONValue] {
        guard case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"] else {
            throw CocoaError(.coderInvalidValue)
        }
        let decoded = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8))
        guard case .object(let payload) = decoded else { throw CocoaError(.coderInvalidValue) }
        return payload
    }
}
