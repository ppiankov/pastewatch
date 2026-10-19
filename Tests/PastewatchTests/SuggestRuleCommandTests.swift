import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-711@v1: command diagnostics must never become a second disclosure channel for advisory values.
final class SuggestRuleCommandTests: XCTestCase {
    // WO-711@v1: source formatting is independent of the low-entropy values assembled in test memory.
    private struct Fixture {
        let fileName: String
        let prefix: String
        let key: String
        let separator: String
        let quote: String
        let value: String
        let suffix: String

        // WO-711@v1: original source bytes are the round-trip oracle, not a reserialization.
        var content: String { "# heading \u{1F512}\n" + prefix + key + separator + quote + value + quote + suffix + "\n" }
    }

    // WO-711@v1: captured output is inspected without printing checked values on assertion failure.
    private struct Result {
        let status: Int32
        let output: Data
        let errors: Data
    }

    // WO-711@v1: bounded derivation handles scanner context without changing any scanner or parser result.
    func testAdvisorySourceSpanDerivation() throws {
        try isolated { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for fixture in fixtures() {
                let suggestion = try RuleSuggestion.generate(content: fixture.content, config: config,
                    filePath: fixture.fileName, line: 2)
                try assertPattern(suggestion.rule, matchesOnly: fixture.value, in: fixture.content)
            }
            for fixture in fixtures().filter({ $0.quote.isEmpty }) {
                let line = fixture.key + fixture.separator + fixture.value
                let suggestion = try RuleSuggestion.generate(content: line, config: config, filePath: nil, line: 1)
                try assertPattern(suggestion.rule, matchesOnly: fixture.value, in: line)
                XCTAssertEqual(suggestion.rule.name, "suggested-" + fixture.key.lowercased())
            }
        }
    }

    // WO-711@v1: generated rules must preserve syntax through the actual MCP masking and restoration paths.
    func testGeneratedRulesMaskOnlyValuesAndRestoreOriginalBytes() throws {
        try isolated { root in
            for fixture in fixtures() {
                var config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
                let suggestion = try RuleSuggestion.generate(content: fixture.content, config: config,
                                                              filePath: fixture.fileName, line: 2)
                config.customRules = [suggestion.rule]
                let file = root.appendingPathComponent(fixture.fileName)
                try Data(fixture.content.utf8).write(to: file)
                let server = server(root: root, config: config)
                try assertRoundTrip(server, file: file, content: fixture.content, value: fixture.value, number: 1)
                let rotated = ["rotated", "phrase", "8"].joined(separator: fixture.value.contains(" ") ? " " : "")
                let next = fixture.content.replacingOccurrences(of: fixture.value, with: rotated)
                try Data(next.utf8).write(to: file)
                try assertRoundTrip(server, file: file, content: next, value: rotated, number: 2)
            }
        }
    }

    // WO-711@v1: a literal rule matching a second source occurrence cannot be presented as value-only proof.
    func testSelfVerificationRefusesSecondExactOccurrence() throws {
        try isolated { root in
            let fixture = try XCTUnwrap(fixtures().first { $0.fileName == "fixture.env" })
            let file = root.appendingPathComponent("duplicate.txt")
            let source = fixture.key + "=\"" + fixture.value + "\" # note " + fixture.value + "\n"
            try Data(source.utf8).write(to: file)
            let result = try run(root: root, arguments: ["--file", file.path, "--line", "1", "--exact", "--format", "json"])
            XCTAssertEqual(result.status, 1)
            XCTAssertTrue(result.output.isEmpty)
            let message = try output(result)
            XCTAssertTrue(message.contains("cannot derive a value-only rule for "))
            XCTAssertTrue(message.contains(file.path + ":1; use --exact"))
            XCTAssertFalse(message.contains(fixture.value))
        }
    }

    // WO-711@v1: an escaped quote exposes a default class's narrower span, which self-verification must reject.
    func testSelfVerificationRefusesTruncatedQuotedPattern() throws {
        try isolated { root in
            let file = root.appendingPathComponent("escaped.env")
            let key = ["pass", "word"].joined()
            let value = "fixture" + "\\\"" + "phrase7"
            try Data((key + "=\"" + value + "\"\n").utf8).write(to: file)
            let result = try run(root: root, arguments: ["--file", file.path, "--line", "1", "--format", "json"])
            XCTAssertEqual(result.status, 1)
            XCTAssertTrue(result.output.isEmpty)
            XCTAssertTrue(try output(result).contains("cannot derive a value-only rule"))
            XCTAssertFalse(try output(result).contains(value))
        }
    }

    // WO-711@v1: pinned quote escapes are parsed locally, while unsupported default classes fail verification.
    func testEscapedQuotesAndDoubledSingleQuotesUseVerifiedExactRules() throws {
        try isolated { _ in
            let key = ["pass", "word"].joined()
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for quote in ["\"", "'"] {
                let escape = quote == "\"" ? "\\\"" : "''"
                let value = "fixture" + escape + "phrase7"
                let source = key + ": " + quote + value + quote + " # comment\n"
                XCTAssertThrowsError(try RuleSuggestion.generate(content: source, config: config,
                    filePath: "fixture.yaml", line: 1)) { error in
                    XCTAssertTrue(error is RuleSuggestionError)
                }
                let suggestion = try RuleSuggestion.generate(content: source, config: config,
                    filePath: "fixture.yaml", line: 1, exact: true)
                try assertPattern(suggestion.rule, matchesOnly: value, in: source)
            }
        }
    }

    // WO-711@v1: comment stripping does not discard escaped hashes or trailing whitespace from the surrounding source.
    func testUnquotedCommentAndEscapedHashDerivation() throws {
        try isolated { _ in
            let key = ["pass", "word"].joined()
            let value = "fixture" + "phrase7"
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for whitespace in [" ", "\t"] {
                let source = key + ": " + value + whitespace + "# comment\n"
                let suggestion = try RuleSuggestion.generate(content: source, config: config,
                    filePath: "fixture.yaml", line: 1)
                try assertPattern(suggestion.rule, matchesOnly: value, in: source)
            }
            let escaped = value + " \\#tail"
            let source = key + ": " + escaped + " # comment\n"
            let suggestion = try RuleSuggestion.generate(content: source, config: config,
                filePath: "fixture.yaml", line: 1, exact: true)
            try assertPattern(suggestion.rule, matchesOnly: escaped, in: source)
        }
    }

    // WO-711@v1: incomplete quoting and comment-only candidates never produce a usable snippet.
    func testUnclosedQuoteAndCommentOnlyValuesAreRefused() throws {
        try isolated { root in
            let file = root.appendingPathComponent("invalid.yaml")
            let key = ["pass", "word"].joined()
            let value = ["fixture", "phrase", "7"].joined()
            for source in [key + ": \"" + value + "\n", key + ": # " + value + "\n"] {
                try Data(source.utf8).write(to: file)
                let result = try run(root: root, arguments: ["--file", file.path, "--line", "1", "--format", "json"])
                XCTAssertEqual(result.status, 1)
                XCTAssertTrue(result.output.isEmpty)
                XCTAssertFalse(try output(result).contains(value))
            }
        }
    }

    // WO-711@v1: assignment-looking bytes inside an already parsed value belong to the value, not a second key.
    func testParsedValueDoesNotLoseAnAssignmentLookingPrefix() throws {
        try isolated { _ in
            let key = ["pass", "word"].joined()
            let value = "fixture=" + "phrase7"
            let source = key + "=" + value + "\n"
            let suggestion = try RuleSuggestion.generate(content: source,
                config: TestConfigHelper.configWithAmbiguousAdvisories([.credential]), filePath: "fixture.env", line: 1)
            try assertPattern(suggestion.rule, matchesOnly: value, in: source)
        }
    }

    // WO-711@v1: verification scans the complete line so a protected source key cannot leak through its anchor.
    func testIntrinsicAssignmentKeyNeverAppearsInSuggestion() throws {
        try isolated { root in
            let intrinsic = "AKIA" + String(repeating: "Q", count: 16)
            let key = intrinsic + "." + ["pass", "word"].joined()
            let value = ["fixture", "phrase", "7"].joined()
            let file = root.appendingPathComponent("intrinsic-key.properties")
            try Data((key + "=" + value + "\n").utf8).write(to: file)
            let result = try run(root: root, arguments: ["--file", file.path, "--line", "1", "--format", "json"])
            XCTAssertEqual(result.status, 1)
            XCTAssertTrue(result.output.isEmpty)
            XCTAssertFalse(try output(result).contains(intrinsic))
            XCTAssertFalse(try output(result).contains(value))
        }
    }

    // WO-711@v1: default snippets expose only the key anchor across all supported quoting forms.
    func testFileSuggestionsNeverDiscloseValues() throws {
        try isolated { root in
            let configFile = root.appendingPathComponent(".pastewatch.json")
            let originalConfig = try Data(contentsOf: configFile)
            for fixture in fixtures() {
                let file = root.appendingPathComponent(fixture.fileName)
                try Data(fixture.content.utf8).write(to: file)
                for format in ["text", "json"] {
                    let result = try run(root: root, arguments: [
                        "--file", file.path, "--line", "2", "--format", format
                    ])
                    XCTAssertEqual(result.status, 0, fixture.fileName)
                    let output = try output(result)
                    XCTAssertFalse(output.contains(fixture.value), fixture.fileName)
                    XCTAssertFalse(output.contains(String(fixture.value.utf8.count)), fixture.fileName)
                    XCTAssertFalse(output.contains("maskedShape") || output.contains("sha256"), fixture.fileName)
                    guard result.status == 0, format == "json" else { continue }
                    let object = try object(result.output)
                    XCTAssertEqual(Set(object.keys), ["rule", "placement", "warnings"])
                    let rule = try XCTUnwrap(object["rule"] as? [String: Any])
                    XCTAssertEqual(Set(rule.keys), ["name", "pattern", "severity"])
                    XCTAssertEqual(rule["severity"] as? String, Severity.defaultCustomRuleSeverity.rawValue)
                    let pattern = try XCTUnwrap(rule["pattern"] as? String)
                    XCTAssertTrue(pattern.hasPrefix("(?<="))
                    XCTAssertFalse(pattern.contains(fixture.value))
                }
            }
            XCTAssertTrue(try Data(contentsOf: configFile).elementsEqual(originalConfig))
        }
    }

    // WO-711@v1: stdin is the only value channel; parser errors cannot echo a rejected argument.
    func testStdinAndArgumentRefusalNeverEchoValues() throws {
        try isolated { root in
            let fixture = try XCTUnwrap(fixtures().first { $0.fileName == "fixture.env" })
            let line = fixture.key + fixture.separator + fixture.value + "\n"
            let valid = try run(root: root, arguments: ["--stdin", "--format", "json"], input: line)
            XCTAssertEqual(valid.status, 0)
            XCTAssertFalse(try output(valid).contains(fixture.value))
            for arguments in [
                [fixture.value], ["--stdin", fixture.value], ["--value", fixture.value],
                ["--stdin", "--line", fixture.value], ["--stdin", "--format", fixture.value]
            ] {
                let result = try run(root: root, arguments: arguments, input: line)
                XCTAssertEqual(result.status, 64)
                XCTAssertFalse(try output(result).contains(fixture.value))
            }
        }
    }

    // WO-711@v1: literal disclosure is explicit, confined to the pattern, and paired with a rotation warning.
    func testExactOutputWarnsAndLimitsDisclosureToPattern() throws {
        try isolated { root in
            let fixture = try XCTUnwrap(fixtures().first { $0.fileName == "fixture.env" })
            let file = root.appendingPathComponent(fixture.fileName)
            try Data(fixture.content.utf8).write(to: file)
            let result = try run(root: root, arguments: [
                "--file", file.path, "--line", "2", "--exact", "--name", "chosen-name", "--format", "json"
            ])
            XCTAssertEqual(result.status, 0)
            guard result.status == 0 else { return }
            var object = try object(result.output)
            var rule = try XCTUnwrap(object["rule"] as? [String: Any])
            XCTAssertEqual(rule["name"] as? String, "chosen-name")
            let pattern = try XCTUnwrap(rule["pattern"] as? String)
            XCTAssertTrue(pattern.contains(fixture.value))
            let warnings = try XCTUnwrap(object["warnings"] as? [String]).joined(separator: " ").lowercased()
            XCTAssertTrue(warnings.contains("plaintext") && warnings.contains("rotation"))
            rule["pattern"] = ""
            object["rule"] = rule
            let withoutPattern = try JSONSerialization.data(withJSONObject: object)
            XCTAssertFalse(try XCTUnwrap(String(data: withoutPattern, encoding: .utf8)).contains(fixture.value))
        }
    }

    // WO-711@v1: absence and existing proof produce no suggestion rather than changing masking policy.
    func testMissingAndAlreadyMaskedFindingsEmitNoRule() throws {
        try isolated { root in
            let file = root.appendingPathComponent("fixture.txt")
            try Data("ordinary notes\n".utf8).write(to: file)
            let missing = try run(root: root, arguments: ["--file", file.path, "--line", "1"])
            XCTAssertEqual(missing.status, 1)
            XCTAssertTrue(try output(missing).lowercased().contains("no advisory finding"))
            XCTAssertTrue(missing.output.isEmpty)
            let intrinsic = "AKIA" + String(repeating: "Q", count: 16)
            try Data((intrinsic + "\n").utf8).write(to: file)
            let masked = try run(root: root, arguments: ["--file", file.path, "--line", "1"])
            XCTAssertEqual(masked.status, 1)
            XCTAssertTrue(try output(masked).lowercased().contains("already masked"))
            XCTAssertFalse(try output(masked).contains(intrinsic))
            XCTAssertTrue(masked.output.isEmpty)
        }
    }

    // WO-711@v1: a keyless advisory cannot silently become a plaintext literal rule.
    func testKeylessAdvisoryRequiresExactMode() throws {
        try isolated { root in
            let value = ["+1", "212", "643", "7891"].joined(separator: " ")
            let result = try run(root: root, arguments: ["--stdin"], input: value + "\n")
            XCTAssertEqual(result.status, 1)
            XCTAssertTrue(try output(result).contains("--exact"))
            XCTAssertFalse(try output(result).contains(value))
            XCTAssertTrue(result.output.isEmpty)
            let literal = try run(root: root, arguments: ["--stdin", "--exact", "--format", "json"], input: value + "\n")
            XCTAssertEqual(literal.status, 0)
            guard literal.status == 0 else { return }
            let rule = try XCTUnwrap(try object(literal.output)["rule"] as? [String: Any])
            let pattern = try XCTUnwrap(rule["pattern"] as? String)
            XCTAssertFalse(pattern.hasPrefix("^") || pattern.hasSuffix("$"))
        }
    }

    // WO-711@v1: exactly one source and a positive file line are required without reflecting rejected input.
    func testInputModesAreExclusiveAndLineIsRequired() throws {
        try isolated { root in
            let fixture = try XCTUnwrap(fixtures().first)
            let file = root.appendingPathComponent(fixture.fileName)
            try Data(fixture.content.utf8).write(to: file)
            for arguments in [
                [], ["--file", file.path], ["--stdin", "--line", "1"],
                ["--file", file.path, "--line", "0"], ["--file", file.path, "--line", "2", "--stdin"]
            ] {
                let result = try run(root: root, arguments: arguments)
                XCTAssertEqual(result.status, 64)
                XCTAssertFalse(try output(result).contains(fixture.value))
            }
        }
    }

    // WO-711@v1: only the first stdin line participates in recognition and output.
    func testStdinConsumesOneLine() throws {
        try isolated { root in
            let fixture = try XCTUnwrap(fixtures().first { $0.fileName == "fixture.env" })
            let first = fixture.key + fixture.separator + fixture.value + "\n"
            let second = "AKIA" + String(repeating: "R", count: 16)
            let result = try run(root: root, arguments: ["--stdin", "--format", "json"], input: first + second + "\n")
            XCTAssertEqual(result.status, 0)
            XCTAssertFalse(try output(result).contains(fixture.value))
            XCTAssertFalse(try output(result).contains(second))
        }
    }

    // WO-711@v1: test credentials are assembled at runtime and retain only their source-format labels in failures.
    private func fixtures() -> [Fixture] {
        let key = ["pass", "word"].joined()
        let value = ["fixture", "phrase", "7"].joined()
        return [
            Fixture(fileName: "fixture.properties", prefix: "", key: "store" + "Pass" + "word", separator: "=",
                    quote: "", value: value, suffix: "   "),
            Fixture(fileName: "fixture.env", prefix: "", key: key, separator: "=", quote: "", value: value, suffix: ""),
            Fixture(fileName: "quoted.env", prefix: "  export ", key: key, separator: " = ", quote: "\"",
                    value: ["fixture", "phrase", "7"].joined(separator: " "), suffix: ""),
            Fixture(fileName: "fixture.yaml", prefix: "  ", key: key, separator: ": ", quote: "\"",
                    value: value, suffix: "  # comment"),
            Fixture(fileName: "single.env", prefix: "", key: key, separator: "=", quote: "'", value: value, suffix: "")
        ]
    }

    // WO-711@v1: both global tiers and the child process are isolated from operator configuration.
    private func isolated(_ body: (URL) throws -> Void) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential, .phone])
            try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
            try body(root)
        }
    }

    // WO-711@v1: tests run the actual executable while retaining all input and output in memory.
    private func run(root: URL, arguments: [String], input: String = "") throws -> Result {
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        let stdin = Pipe()
        process.executableURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = ["suggest-rule"] + arguments
        process.currentDirectoryURL = root
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
        process.standardOutput = output
        process.standardError = errors
        // WO-711@v1: retain the parent reader so an early usage-error exit cannot race the small fixture write.
        process.standardInput = stdin.fileHandleForReading
        try process.run()
        try stdin.fileHandleForWriting.write(contentsOf: Data(input.utf8))
        try stdin.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let errorData = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Result(status: process.terminationStatus, output: data, errors: errorData)
    }

    // WO-711@v1: failed assertions compare booleans and metadata rather than rendering captured values.
    private func output(_ result: Result) throws -> String {
        try XCTUnwrap(String(data: result.output + result.errors, encoding: .utf8))
    }

    // WO-711@v1: structured success fields can be checked without logging their contents.
    private func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // WO-711@v1: compiled patterns must identify the bare value without relying on a printed snippet.
    private func assertPattern(_ rule: CustomRuleConfig, matchesOnly value: String, in content: String) throws {
        let compiled = try XCTUnwrap(try CustomRule.compile([rule]).first)
        let matches = compiled.regex.matches(in: content, range: NSRange(content.startIndex..., in: content))
        XCTAssertEqual(matches.count, 1)
        let match = try XCTUnwrap(matches.first)
        let range = try XCTUnwrap(Range(match.range, in: content))
        XCTAssertTrue(content[range].utf8.elementsEqual(value.utf8))
    }

    // WO-711@v1: independent test servers use injected executable identity and isolated effective config.
    private func server(root: URL, config: PastewatchConfig) -> MCPServer {
        let identity = MCPExecutableIdentity(realPath: root.appendingPathComponent("executable").path,
                                             inode: 1, device: 1, modifiedAt: Date(timeIntervalSince1970: 1_000))
        return MCPServer(config: config, executableFreshness: MCPExecutableFreshness(
            invokedPath: identity.realPath, lookup: { _ in identity }
        ))
    }

    // WO-711@v1: one read/write server proves both source preservation and rotation-safe restoration.
    private func assertRoundTrip(
        _ server: MCPServer, file: URL, content: String, value: String, number: Int
    ) throws {
        let result = try call(server, tool: "pastewatch_read_file", arguments: ["path": .string(file.path)])
        XCTAssertNil(result["isError"])
        let payload = try payload(result)
        guard case .string(let view) = payload["content"], case .array(let entries) = payload["redactions"] else {
            throw CocoaError(.coderInvalidValue)
        }
        XCTAssertEqual(entries.count, 1)
        XCTAssertFalse(view.contains(value))
        let marker = Obfuscator.makeMCPPlaceholder(type: .credential, number: number)
        let expected = content.replacingOccurrences(of: value, with: marker)
        XCTAssertTrue(Data(view.utf8).elementsEqual(expected.utf8))
        let written = try call(server, tool: "pastewatch_write_file", arguments: [
            "path": .string(file.path), "content": .string(view)
        ])
        XCTAssertNil(written["isError"])
        XCTAssertTrue(try Data(contentsOf: file).elementsEqual(content.utf8))
    }

    // WO-711@v1: protocol helpers never serialize responses to test diagnostics.
    private func call(_ server: MCPServer, tool: String, arguments: [String: JSONValue]) throws -> [String: JSONValue] {
        let response = try XCTUnwrap(server.handleRequest(JSONRPCRequest(
            jsonrpc: "2.0", id: .int(1), method: "tools/call",
            params: .object(["name": .string(tool), "arguments": .object(arguments)])
        )))
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result else { throw CocoaError(.coderInvalidValue) }
        return result
    }

    // WO-711@v1: nested JSON is decoded in memory without disclosing masked or restored values.
    private func payload(_ result: [String: JSONValue]) throws -> [String: JSONValue] {
        guard case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"],
              case .object(let payload) = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8)) else {
            throw CocoaError(.coderInvalidValue)
        }
        return payload
    }
}
