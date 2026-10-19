import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-715@v1: issued placeholders must restore without authorizing new plaintext.
final class CustomRulePlaceholderGateTests: XCTestCase {
    // WO-715@v1: fixture values stay in memory and failed comparisons never render them.
    private struct Fixture {
        let root: URL
        let file: URL
        let original: Data
        let value: String
        let config: PastewatchConfig
    }

    // WO-715@v1: broad source rules may recognize both original values and their issued markers.
    func testIssuedPlaceholderWriteRestoresOriginalBytes() throws {
        for prefix in [nil, "SAFE_MARKER_"] as [String?] {
            try withFixture(prefix: prefix) { fixture in
                let writer = server(fixture)
                let view = try read(writer, fixture: fixture)
                let result = try call(writer, tool: "pastewatch_write_file", arguments: [
                    "path": .string(fixture.file.path), "content": .string(view)
                ])
                XCTAssertNil(result["isError"])
                guard result["isError"] == nil else { return }
                XCTAssertEqual(try payload(result)["written"], .bool(true))
                XCTAssertEqual(try payload(result)["unresolved"], .number(0))
                XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(fixture.original))
                try assertNoValue(result, fixture: fixture)
            }
        }
    }

    // WO-715@v1: benign edits must not mistake the untouched issued marker for agent-authored plaintext.
    func testIssuedPlaceholderEditRestoresOriginalBytes() throws {
        try withFixture { fixture in
            let editor = server(fixture)
            _ = try read(editor, fixture: fixture)
            let result = try edit(editor, fixture: fixture, old: "mode=before", new: "mode=after")
            XCTAssertNil(result["isError"])
            // WO-715@v1: invalid fixture bytes must fail the test rather than be repaired during decoding.
            let expected = try XCTUnwrap(String(data: fixture.original, encoding: .utf8))
                .replacingOccurrences(of: "mode=before", with: "mode=after")
            XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(expected.utf8))
            try assertNoValue(result, fixture: fixture)
        }
    }

    // WO-715@v1: actual custom-rule plaintext is rejected on both write surfaces.
    func testTypedPlaintextIsRefusedByWriteAndEdit() throws {
        try withFixture { fixture in
            let writer = server(fixture)
            let view = try read(writer, fixture: fixture)
            let marker = try marker(in: view, fixture: fixture)
            let replacement = "another" + "phrase" + "8"
            let result = try call(writer, tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path),
                "content": .string(view.replacingOccurrences(of: marker, with: replacement))
            ])
            try assertRefused(result, fixture: fixture)
            try assertRefused(edit(writer, fixture: fixture, old: marker, new: replacement), fixture: fixture)
        }
    }

    // WO-715@v1: any unmatched plaintext bytes inside a custom span prevent the exemption.
    func testPlaceholderWithAppendedPlaintextIsRefused() throws {
        try withFixture { fixture in
            let writer = server(fixture)
            let view = try read(writer, fixture: fixture)
            let marker = try marker(in: view, fixture: fixture)
            let appended = marker + "extra"
            let result = try call(writer, tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path),
                "content": .string(view.replacingOccurrences(of: marker, with: appended))
            ])
            try assertRefused(result, fixture: fixture)
            try assertRefused(edit(writer, fixture: fixture, old: marker, new: appended), fixture: fixture)
        }
    }

    // WO-715@v1: a fresh server must not accept a previous server's marker just because it matches a rule.
    func testFreshServerPlaceholderIsRefused() throws {
        try withFixture { fixture in
            let view = try read(server(fixture), fixture: fixture)
            let result = try call(server(fixture), tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(view)
            ])
            try assertRefused(result, fixture: fixture)
            let unknown = Obfuscator.makeMCPPlaceholder(type: .credential, number: 99)
            try assertRefused(edit(server(fixture), fixture: fixture, old: "mode=before", new: "mode=" + unknown),
                              fixture: fixture)
        }
    }

    // WO-715@v1: prefix changes cannot turn foreign placeholder syntax into an issued mapping.
    func testForeignPrefixPlaceholderIsRefused() throws {
        try withFixture(prefix: "SAFE_MARKER_") { fixture in
            let writer = server(fixture)
            let view = try read(writer, fixture: fixture)
            let marker = try marker(in: view, fixture: fixture)
            let foreign = Obfuscator.makeMCPPlaceholder(type: .credential, number: 1)
            let result = try call(writer, tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path),
                "content": .string(view.replacingOccurrences(of: marker, with: foreign))
            ])
            try assertRefused(result, fixture: fixture)
            try assertRefused(edit(writer, fixture: fixture, old: marker, new: foreign), fixture: fixture)
        }
    }

    // WO-715@v1: issued markers do not authorize neighboring built-in intrinsic findings.
    func testIntrinsicPlaintextBesidePlaceholderIsRefused() throws {
        try withFixture { fixture in
            let writer = server(fixture)
            let view = try read(writer, fixture: fixture)
            let intrinsic = "AKIA" + String(repeating: "Q", count: 16)
            let result = try call(writer, tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(view + intrinsic + "\n")
            ])
            try assertRefused(result, fixture: fixture)
            try assertRefused(edit(writer, fixture: fixture, old: "mode=before", new: "mode=before\n" + intrinsic),
                              fixture: fixture)
            XCTAssertFalse(try text(result).contains(intrinsic))
        }
    }

    // WO-715@v1: contiguous issued ranges may cover a custom span, but gaps and stale ranges never do.
    func testCoverageUsesVerifiedUTF8RangesAndMappingScope() throws {
        let store = RedactionStore(placeholderPrefix: "SAFE_MARKER_")
        let original = "fixture" + "phrase" + "7"
        let match = try customMatch(original, in: original)
        let (marker, _) = store.redact(content: original, matches: [match], filePath: "source.txt")
        let view = "\u{1F512} " + marker + marker
        let covered = try customMatch(marker + marker, in: view)
        XCTAssertTrue(store.plaintextRejectionMatches([covered], in: view).isEmpty)
        XCTAssertTrue(store.plaintextRejectionMatches([covered], in: view, filePath: "source.txt").isEmpty)
        XCTAssertEqual(store.plaintextRejectionMatches([covered], in: view, filePath: "other.txt").count, 1)

        let insideMarker = String(marker.dropFirst(3).dropLast(3))
        let partial = try customMatch(insideMarker, in: view)
        XCTAssertTrue(store.plaintextRejectionMatches([partial], in: view).isEmpty)
        let gapView = "\u{1F512} " + marker + " " + marker
        let gap = try customMatch(marker + " " + marker, in: gapView)
        XCTAssertEqual(store.plaintextRejectionMatches([gap], in: gapView).count, 1)
        let stale = DetectedMatch(type: .credential, value: "different", range: covered.range, customRuleName: "fixture")
        XCTAssertEqual(store.plaintextRejectionMatches([stale], in: view).count, 1)
        store.clear()
        XCTAssertEqual(store.plaintextRejectionMatches([covered], in: view).count, 1)
    }

    // WO-715@v1: the existing resolver treats adjacent structured markers as one unknown token, so coverage must too.
    func testUnresolvableAdjacentStructuredMarkersAreRefused() throws {
        let store = RedactionStore()
        let original = "fixture" + "phrase" + "7"
        let (marker, _) = store.redact(content: original, matches: [try customMatch(original, in: original)],
                                       filePath: "source.txt")
        let view = marker + marker
        XCTAssertGreaterThan(store.resolveAll(content: view).unresolved, 0)
        XCTAssertEqual(store.plaintextRejectionMatches([try customMatch(view, in: view)], in: view).count, 1)
    }

    // WO-715@v1: placeholder coverage cannot exempt independently authorized built-in or intrinsic evidence.
    func testBuiltinAndIntrinsicEvidenceIsNeverExempted() throws {
        let store = RedactionStore()
        let original = "fixture" + "phrase" + "7"
        let (marker, _) = store.redact(content: original, matches: [try customMatch(original, in: original)],
                                       filePath: "source.txt")
        let range = marker.startIndex..<marker.endIndex
        let builtin = DetectedMatch(type: .credential, value: marker, range: range,
                                    mutationAuthorizationSources: [.configuredObfuscate])
        let intrinsic = DetectedMatch(type: .awsKey, value: marker, range: range, customRuleName: "fixture")
        let exact = DetectedMatch(type: .credential, value: marker, range: range, customRuleName: "fixture",
                                  mutationAuthorizationSources: [.exactKnownSecret])
        XCTAssertEqual(store.plaintextRejectionMatches([builtin, intrinsic, exact], in: marker).count, 3)
    }

    // WO-715@v1: synthetic source spans let coverage tests exercise offsets without another recognition path.
    private func customMatch(_ value: String, in content: String) throws -> DetectedMatch {
        let range = try XCTUnwrap(content.range(of: value))
        return DetectedMatch(type: .credential, value: value, range: range, customRuleName: "fixture")
    }

    // WO-715@v1: all fixture configuration is isolated from operator and administrator files.
    private func withFixture(prefix: String? = nil, _ body: (Fixture) throws -> Void) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let key = "fixture" + "Value"
            let value = "fixture" + "phrase" + "7"
            var config = PastewatchConfig.defaultConfig
            config.placeholderPrefix = prefix
            config.customRules = [CustomRuleConfig(
                name: "fixture-rule", pattern: "(?<=" + NSRegularExpression.escapedPattern(for: key + "=") + ")[^\\r\\n]+"
            )]
            let original = Data(("heading \u{1F512}\n" + key + "=" + value + "\nmode=before\n").utf8)
            let file = root.appendingPathComponent("fixture.txt")
            try original.write(to: file)
            try body(Fixture(root: root, file: file, original: original, value: value, config: config))
        }
    }

    // WO-715@v1: injected executable identity keeps the tests independent of installed binaries.
    private func server(_ fixture: Fixture) -> MCPServer {
        let identity = MCPExecutableIdentity(realPath: fixture.root.appendingPathComponent("executable").path,
                                             inode: 1, device: 1, modifiedAt: Date(timeIntervalSince1970: 1_000))
        return MCPServer(config: fixture.config, executableFreshness: MCPExecutableFreshness(
            invokedPath: identity.realPath, lookup: { _ in identity }
        ))
    }

    // WO-715@v1: actual MCP dispatch exercises both shared-helper callers and their error envelopes.
    private func call(_ server: MCPServer, tool: String, arguments: [String: JSONValue]) throws -> [String: JSONValue] {
        let response = try XCTUnwrap(server.handleRequest(JSONRPCRequest(
            jsonrpc: "2.0", id: .int(1), method: "tools/call",
            params: .object(["name": .string(tool), "arguments": .object(arguments)])
        )))
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result else { throw CocoaError(.coderInvalidValue) }
        return result
    }

    // WO-715@v1: tests obtain markers only from the production read path.
    private func read(_ server: MCPServer, fixture: Fixture) throws -> String {
        let result = try call(server, tool: "pastewatch_read_file", arguments: ["path": .string(fixture.file.path)])
        XCTAssertNil(result["isError"])
        guard case .string(let content) = try payload(result)["content"] else { throw CocoaError(.coderInvalidValue) }
        XCTAssertFalse(content.contains(fixture.value))
        return content
    }

    // WO-715@v1: the compiled operator rule identifies the exact source span, not a second placeholder regex.
    private func marker(in view: String, fixture: Fixture) throws -> String {
        let rule = try XCTUnwrap(try CustomRule.compile(fixture.config.customRules).first)
        let match = try XCTUnwrap(rule.regex.firstMatch(in: view, range: NSRange(view.startIndex..., in: view)))
        let range = try XCTUnwrap(Range(match.range, in: view))
        return String(view[range])
    }

    // WO-715@v1: edits run the same production protocol path as clients.
    private func edit(_ server: MCPServer, fixture: Fixture, old: String, new: String) throws -> [String: JSONValue] {
        try call(server, tool: "pastewatch_edit_file", arguments: [
            "path": .string(fixture.file.path), "old_string": .string(old), "new_string": .string(new)
        ])
    }

    // WO-715@v1: response extraction never logs the tool payload.
    private func text(_ result: [String: JSONValue]) throws -> String {
        guard case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"] else { throw CocoaError(.coderInvalidValue) }
        return text
    }

    // WO-715@v1: decode the nested MCP result without displaying plaintext-bearing test inputs.
    private func payload(_ result: [String: JSONValue]) throws -> [String: JSONValue] {
        guard case .object(let payload) = try JSONDecoder().decode(JSONValue.self, from: Data(text(result).utf8)) else {
            throw CocoaError(.coderInvalidValue)
        }
        return payload
    }

    // WO-715@v1: failures assert only status and byte equality, so XCTest cannot render fixture values.
    private func assertRefused(_ result: [String: JSONValue], fixture: Fixture) throws {
        XCTAssertEqual(result["isError"], .bool(true))
        XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(fixture.original))
        try assertNoValue(result, fixture: fixture)
    }

    // WO-715@v1: the complete encoded response must not disclose restored originals.
    private func assertNoValue(_ result: [String: JSONValue], fixture: Fixture) throws {
        let encoded = try JSONEncoder().encode(JSONValue.object(result))
        // WO-715@v1: malformed response encoding must fail instead of substituting replacement characters.
        let text = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        XCTAssertFalse(text.contains(fixture.value))
    }
}
