import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-719@v2: literal examples remain editable without admitting new unresolved occurrences.
final class MCPWriteLiteralMarkerTests: XCTestCase {
    // WO-719@v2: both placeholder formats use the production store parser.
    private struct Fixture {
        let root: URL
        let file: URL
        let config: PastewatchConfig
        let marker: String
        let otherMarker: String
        let original: Data
    }

    // WO-719@v2: case (i) preserves existing literal text and all surrounding bytes.
    func testWritePreservesPreExistingLiteralMarkerBytes() throws {
        try withFixtures { fixture in
            let result = try call(server(fixture), tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(try source(fixture))
            ])
            XCTAssertNil(result["isError"])
            XCTAssertEqual(try payload(result)["written"], .bool(true))
            XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(fixture.original))
        }
    }

    // WO-719@v2: case (ii) requires occurrence counts, not membership in a set of disk tokens.
    func testWriteRefusesAdditionalLiteralMarkerOccurrence() throws {
        try withFixtures { fixture in
            let result = try call(server(fixture), tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(try source(fixture) + fixture.marker + "\n")
            ])
            try assertRefused(result, fixture: fixture)
        }
    }

    // WO-719@v2: case (iii) gives a missing destination no literal-token budget.
    func testNewDestinationRejectsLiteralMarker() throws {
        try withFixtures { fixture in
            let target = fixture.root.appendingPathComponent("new.txt")
            let result = try call(server(fixture), tool: "pastewatch_write_file", arguments: [
                "path": .string(target.path), "content": .string(fixture.marker + "\n")
            ])
            XCTAssertEqual(result["isError"], .bool(true))
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
            XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(fixture.original))
        }
    }

    // WO-719@v2: case (iv) restores issued mappings while preserving unrelated literal examples.
    func testIssuedPlaceholderResolvesBesideLiteralMarker() throws {
        try withFixtures { fixture in
            let secret = ["AK", "IA", String(repeating: "Q", count: 16)].joined()
            let original = Data(("key=" + secret + "\n").utf8) + fixture.original
            try original.write(to: fixture.file)
            let session = server(fixture)
            let read = try payload(call(session, tool: "pastewatch_read_file", arguments: ["path": .string(fixture.file.path)]))
            guard case .string(let view) = read["content"] else { throw CocoaError(.coderInvalidValue) }
            XCTAssertFalse(view.contains(secret))
            XCTAssertTrue(view.contains(fixture.marker))
            let written = try call(session, tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(view)
            ])
            XCTAssertNil(written["isError"])
            XCTAssertEqual(try payload(written)["resolved"], .number(1))
            XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(original))
            XCTAssertFalse(try responseText(written).contains(secret))
        }
    }

    // WO-719@v2: case (v) compares against the edit's original bytes, not a later disk read.
    func testEditKeepsPreExistingLiteralMarkerBytes() throws {
        try withFixtures { fixture in
            let result = try call(server(fixture), tool: "pastewatch_edit_file", arguments: [
                "path": .string(fixture.file.path), "old_string": .string("label=before"),
                "new_string": .string("label=after")
            ])
            XCTAssertNil(result["isError"])
            let expected = try source(fixture).replacingOccurrences(of: "label=before", with: "label=after")
            XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(expected.utf8))
        }
    }

    // WO-719@v2: case (vi) prevents an edit from multiplying an existing literal marker.
    func testEditRefusesAdditionalLiteralMarkerOccurrence() throws {
        try withFixtures { fixture in
            let result = try call(server(fixture), tool: "pastewatch_edit_file", arguments: [
                "path": .string(fixture.file.path), "old_string": .string("label=before"),
                "new_string": .string("label=" + fixture.marker)
            ])
            try assertRefused(result, fixture: fixture)
        }
    }

    // WO-719@v2: a disk token cannot authorize another token with the same sensitive-data type.
    func testWriteRefusesDifferentLiteralMarkerOfSameType() throws {
        try withFixtures { fixture in
            let result = try call(server(fixture), tool: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(fixture.otherMarker + "\n")
            ])
            try assertRefused(result, fixture: fixture)
        }
    }

    // WO-719@v2: custom token prefixes must not borrow counts from a longer numeric token.
    func testCustomPrefixCountsWholeTokens() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var config = PastewatchConfig.defaultConfig
            let prefix = ["EXAMPLE", "MARKER", ""].joined(separator: "_")
            config.placeholderPrefix = prefix
            let short = Obfuscator.makeCustomPlaceholder(prefix: prefix, number: 100)
            let long = Obfuscator.makeCustomPlaceholder(prefix: prefix, number: 1001)
            let file = root.appendingPathComponent("fixture.txt")
            let original = Data((long + "\n").utf8)
            try original.write(to: file)
            let fixture = Fixture(root: root, file: file, config: config, marker: long,
                                  otherMarker: short, original: original)
            let result = try call(server(fixture), tool: "pastewatch_write_file", arguments: [
                "path": .string(file.path), "content": .string(short + "\n")
            ])
            try assertRefused(result, fixture: fixture)
        }
    }

    // WO-719@v2: inability to inspect an existing target must never turn into permission to write.
    func testUnreadableTargetRefusesBeforeWrite() throws {
        try withFixtures { fixture in
            let target = fixture.root.appendingPathComponent("directory.txt")
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
            let result = try call(server(fixture), tool: "pastewatch_write_file", arguments: [
                "path": .string(target.path), "content": .string(fixture.marker + "\n")
            ])
            XCTAssertEqual(result["isError"], .bool(true))
            XCTAssertTrue(try responseText(result).contains("Write refused"))
            let contents = try FileManager.default.contentsOfDirectory(atPath: target.path)
            XCTAssertTrue(contents.isEmpty)
        }
    }

    // WO-719@v2: missing, unreadable or invalid snapshots cannot grant an unresolved-token budget.
    func testValidatorSnapshotErrorsFailClosedWithoutReadingForResolvedContent() throws {
        let store = RedactionStore()
        let marker = Obfuscator.makeMCPPlaceholder(type: .awsKey, number: 90)
        let unresolved = store.resolveAll(content: marker)
        XCTAssertFalse(store.permitsUnresolvedPlaceholders(unresolved, existingBytes: {
            throw CocoaError(.fileReadNoPermission)
        }))
        XCTAssertFalse(store.permitsUnresolvedPlaceholders(unresolved, existingBytes: { Data() }))
        XCTAssertFalse(store.permitsUnresolvedPlaceholders(unresolved, existingBytes: { Data([0xFF]) }))
        let clean = store.resolveAll(content: "ordinary text")
        XCTAssertTrue(store.permitsUnresolvedPlaceholders(clean, existingBytes: {
            XCTFail("Resolved writes must not require an existing file")
            throw CocoaError(.fileReadNoSuchFile)
        }))
    }

    // WO-719@v2: all marker and secret-shaped strings are assembled in isolated fixture memory.
    private func withFixtures(_ body: (Fixture) throws -> Void) throws {
        for custom in [false, true] {
            try TestConfigHelper.withIsolatedGlobalConfig { root in
                var config = PastewatchConfig.defaultConfig
                let marker: String
                let other: String
                if custom {
                    let prefix = ["EXAMPLE", "MARKER", ""].joined(separator: "_")
                    config.placeholderPrefix = prefix
                    marker = Obfuscator.makeCustomPlaceholder(prefix: prefix, number: 90)
                    other = Obfuscator.makeCustomPlaceholder(prefix: prefix, number: 91)
                } else {
                    marker = Obfuscator.makeMCPPlaceholder(type: .awsKey, number: 90)
                    other = Obfuscator.makeMCPPlaceholder(type: .awsKey, number: 91)
                }
                try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
                let file = root.appendingPathComponent("fixture.txt")
                let original = Data(("heading \u{1F512}\nexample=" + marker + "\nlabel=before\n").utf8)
                try original.write(to: file)
                try body(Fixture(root: root, file: file, config: config, marker: marker,
                                 otherMarker: other, original: original))
            }
        }
    }

    // WO-719@v2: real MCP dispatch uses an injected identity rather than any installed executable.
    private func server(_ fixture: Fixture) -> MCPServer {
        let identity = MCPExecutableIdentity(realPath: fixture.root.appendingPathComponent("executable").path,
                                             inode: 1, device: 1, modifiedAt: Date(timeIntervalSince1970: 1_000))
        return MCPServer(config: fixture.config, executableFreshness: MCPExecutableFreshness(
            invokedPath: identity.realPath, lookup: { _ in identity }
        ))
    }

    // WO-719@v2: refusal assertions never display source bytes or marker contents.
    private func assertRefused(_ result: [String: JSONValue], fixture: Fixture) throws {
        XCTAssertEqual(result["isError"], .bool(true))
        XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(fixture.original))
        XCTAssertTrue(try responseText(result).contains("unresolved placeholder"))
    }

    // WO-719@v2: byte-preservation assertions use the original fixture, not a reserialized format.
    private func source(_ fixture: Fixture) throws -> String {
        try XCTUnwrap(String(data: fixture.original, encoding: .utf8))
    }

    // WO-719@v2: tool responses stay in memory and out of failure diagnostics.
    private func call(_ server: MCPServer, tool: String, arguments: [String: JSONValue]) throws -> [String: JSONValue] {
        let response = try XCTUnwrap(server.handleRequest(JSONRPCRequest(
            jsonrpc: "2.0", id: .int(1), method: "tools/call",
            params: .object(["name": .string(tool), "arguments": .object(arguments)])
        )))
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result else { throw CocoaError(.coderInvalidValue) }
        return result
    }

    // WO-719@v2: nested response decoding never prints values on a malformed payload.
    private func payload(_ result: [String: JSONValue]) throws -> [String: JSONValue] {
        let text = try responseText(result)
        guard case .object(let payload) = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8)) else {
            throw CocoaError(.coderInvalidValue)
        }
        return payload
    }

    // WO-719@v2: only metadata assertions inspect error text, never stdout logging.
    private func responseText(_ result: [String: JSONValue]) throws -> String {
        guard case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"] else { throw CocoaError(.coderInvalidValue) }
        return text
    }
}
