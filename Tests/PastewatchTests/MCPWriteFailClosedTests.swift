import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-710@v1: protocol-level restoration failures must never change file bytes or disclose restored values.
final class MCPWriteFailClosedTests: XCTestCase {
    // WO-710@v1: keep synthetic plaintext in test memory and compare file bytes without printing them.
    private struct Fixture {
        let root: URL
        let file: URL
        let original: Data
        let secret: String
    }

    // WO-710@v1: a new server has no mappings from a previous read session.
    func testRestartedWriteRefusesAndPreservesBytes() throws {
        try withFixture { fixture in
            let reader = server(fixture)
            let content = try readContent(reader, file: fixture.file)
            XCTAssertFalse(content.contains(fixture.secret))
            let audit = fixture.root.appendingPathComponent("write-audit.log")
            let writer = server(fixture, auditLogger: MCPAuditLogger(path: audit.path))
            let result = try call(writer, name: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(content)
            ])
            try assertRefused(result, fixture: fixture, count: 1)
            let log = try String(contentsOf: audit, encoding: .utf8)
            XCTAssertTrue(log.contains("WRITE-REFUSED " + fixture.file.path + " unresolved=1"))
            XCTAssertFalse(log.contains(fixture.secret))
            XCTAssertFalse(log.contains("WRITE " + fixture.file.path))
        }
    }

    // WO-710@v1: resolving some tokens cannot authorize a partial or placeholder-bearing write.
    func testMixedWriteRefusesWithoutPartialRestoration() throws {
        try withFixture { fixture in
            let writer = server(fixture)
            let content = try readContent(writer, file: fixture.file)
            let unknown = Obfuscator.makeMCPPlaceholder(type: .awsKey, number: 99)
            let result = try call(writer, name: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(content + unknown + "\n")
            ])
            try assertRefused(result, fixture: fixture, count: 1)
        }
    }

    // WO-710@v1: custom-prefix restoration uses the store's existing unresolved count too.
    func testCustomPrefixRestartedWriteRefuses() throws {
        try withFixture { fixture in
            var config = PastewatchConfig.defaultConfig
            config.placeholderPrefix = "SAFE_MARKER_"
            let reader = server(fixture, config: config)
            let content = try readContent(reader, file: fixture.file)
            XCTAssertTrue(content.contains(Obfuscator.makeCustomPlaceholder(prefix: "SAFE_MARKER_", number: 1)))
            let writer = server(fixture, config: config)
            let result = try call(writer, name: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(content)
            ])
            try assertRefused(result, fixture: fixture, count: 1)
        }
    }

    // WO-710@v1: refusal diagnostics count unresolved occurrences, including repeated tokens.
    func testRefusalCountsEveryUnresolvedOccurrence() throws {
        try withFixture { fixture in
            let content = try readContent(server(fixture), file: fixture.file)
            let result = try call(server(fixture), name: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(content + content)
            ])
            try assertRefused(result, fixture: fixture, count: 2)
        }
    }

    // WO-710@v1: an unresolved write cannot create a new target either.
    func testUnresolvedWriteDoesNotCreateDestination() throws {
        try withFixture { fixture in
            let content = try readContent(server(fixture), file: fixture.file)
            let destination = fixture.root.appendingPathComponent("new.txt")
            let result = try call(server(fixture), name: "pastewatch_write_file", arguments: [
                "path": .string(destination.path), "content": .string(content)
            ])
            try assertRefused(result, fixture: fixture, count: 1)
            XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        }
    }

    // WO-710@v1: successful restoration preserves both the original bytes and the established response keys.
    func testResolvableWritePreservesResponseAndBytes() throws {
        try withFixture { fixture in
            let writer = server(fixture)
            let content = try readContent(writer, file: fixture.file)
            try Data("temporary contents\n".utf8).write(to: fixture.file)
            let result = try call(writer, name: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(content)
            ])
            XCTAssertEqual(Set(result.keys), ["content", "_meta"])
            let payload = try payload(result)
            XCTAssertEqual(Set(payload.keys), ["written", "path", "resolved", "unresolved"])
            XCTAssertEqual(payload["written"], .bool(true))
            XCTAssertEqual(payload["path"], .string(fixture.file.path))
            XCTAssertEqual(payload["resolved"], .number(1))
            XCTAssertEqual(payload["unresolved"], .number(0))
            XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(fixture.original))
            XCTAssertFalse(try text(result).contains(fixture.secret))
        }
    }

    // WO-710@v1: advisory warnings remain additive on otherwise fully restorable writes.
    func testResolvableWritePreservesAdvisoryWarningResponse() throws {
        try withFixture { fixture in
            let advisory = ["10", "23", "45", "67"].joined(separator: ".")
            let original = fixture.original + Data(("contact: " + advisory + "\n").utf8)
            try original.write(to: fixture.file)
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.ipAddress])
            XCTAssertFalse(DetectionRules.isTestCredential(advisory))
            XCTAssertEqual(DetectionRules.scan("contact: " + advisory, config: config).filter {
                $0.type == .ipAddress
            }.count, 1)
            let writer = server(fixture, config: config)
            let content = try readContent(writer, file: fixture.file)
            let result = try call(writer, name: "pastewatch_write_file", arguments: [
                "path": .string(fixture.file.path), "content": .string(content)
            ])
            XCTAssertNil(result["isError"])
            let payload = try payload(result)
            XCTAssertEqual(Set(payload.keys), ["written", "path", "resolved", "unresolved", "plaintextSecretWarnings"])
            XCTAssertEqual(payload["written"], .bool(true))
            XCTAssertEqual(payload["resolved"], .number(1))
            XCTAssertEqual(payload["unresolved"], .number(0))
            XCTAssertEqual(payload["plaintextSecretWarnings"], .number(1))
            XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(original))
        }
    }

    // WO-710@v1: session-specific numbering prevents a fresh edit store from accidentally recreating the stale mapping.
    func testEditRefusesPlaceholderFromRestartedSession() throws {
        try withFixture { fixture in
            let reader = server(fixture)
            let seed = fixture.root.appendingPathComponent("seed.txt")
            let seedValue = "AKIA" + String(repeating: "R", count: 16)
            try Data((seedValue + "\n").utf8).write(to: seed)
            _ = try readContent(reader, file: seed)
            let previousView = try readContent(reader, file: fixture.file)
            let staleMarker = Obfuscator.makeMCPPlaceholder(type: .awsKey, number: 2)
            XCTAssertTrue(previousView.contains(staleMarker))
            let result = try call(server(fixture), name: "pastewatch_edit_file", arguments: [
                "path": .string(fixture.file.path), "old_string": .string("label=before"),
                "new_string": .string("label=" + staleMarker)
            ])
            XCTAssertEqual(result["isError"], .bool(true))
            XCTAssertTrue(try text(result).contains("1 unresolved placeholder"))
            XCTAssertFalse(try text(result).contains(fixture.secret))
            XCTAssertFalse(try text(result).contains(seedValue))
            XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(fixture.original))
        }
    }

    // WO-710@v1: config isolation includes both tiers and all temporary fixture files.
    private func withFixture(_ body: (Fixture) throws -> Void) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let secret = "AKIA" + String(repeating: "Q", count: 16)
            let original = Data(("heading \u{1F512}\nkey=" + secret + "\nlabel=before\n").utf8)
            let file = root.appendingPathComponent("fixture.txt")
            try original.write(to: file)
            try body(Fixture(root: root, file: file, original: original, secret: secret))
        }
    }

    // WO-710@v1: independent server instances own independent stores without inspecting installed binaries.
    private func server(
        _ fixture: Fixture, config: PastewatchConfig = .defaultConfig, auditLogger: MCPAuditLogger? = nil
    ) -> MCPServer {
        let identity = MCPExecutableIdentity(realPath: fixture.root.appendingPathComponent("executable").path,
                                             inode: 1, device: 1, modifiedAt: Date(timeIntervalSince1970: 1_000))
        return MCPServer(auditLogger: auditLogger, config: config, executableFreshness: MCPExecutableFreshness(
            invokedPath: identity.realPath, lookup: { _ in identity }
        ))
    }

    // WO-710@v1: exercise production tool dispatch rather than duplicating the private write handler.
    private func call(_ server: MCPServer, name: String, arguments: [String: JSONValue]) throws -> [String: JSONValue] {
        let response = try XCTUnwrap(server.handleRequest(JSONRPCRequest(
            jsonrpc: "2.0", id: .int(1), method: "tools/call",
            params: .object(["name": .string(name), "arguments": .object(arguments)])
        )))
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result else { throw CocoaError(.coderInvalidValue) }
        return result
    }

    // WO-710@v1: read fixtures obtain their markers from the actual MCP read response.
    private func readContent(_ server: MCPServer, file: URL) throws -> String {
        let result = try call(server, name: "pastewatch_read_file", arguments: ["path": .string(file.path)])
        XCTAssertNil(result["isError"])
        guard case .string(let content) = try payload(result)["content"] else {
            throw CocoaError(.coderInvalidValue)
        }
        return content
    }

    // WO-710@v1: tool text is decoded without logging response bodies or fixture values.
    private func text(_ result: [String: JSONValue]) throws -> String {
        guard case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"] else { throw CocoaError(.coderInvalidValue) }
        return text
    }

    // WO-710@v1: successful tool payloads retain their existing nested JSON contract.
    private func payload(_ result: [String: JSONValue]) throws -> [String: JSONValue] {
        let decoded = try JSONDecoder().decode(JSONValue.self, from: Data(text(result).utf8))
        guard case .object(let payload) = decoded else { throw CocoaError(.coderInvalidValue) }
        return payload
    }

    // WO-710@v1: assert refusal and unchanged bytes without letting XCTest render private content on failure.
    private func assertRefused(
        _ result: [String: JSONValue], fixture: Fixture, count: Int, file: StaticString = #filePath, line: UInt = #line
    ) throws {
        XCTAssertEqual(result["isError"], .bool(true), file: file, line: line)
        let message = try text(result)
        XCTAssertTrue(message.contains("\(count) unresolved placeholder"), file: file, line: line)
        XCTAssertTrue(message.contains("pastewatch_read_file"), file: file, line: line)
        XCTAssertTrue(message.lowercased().contains("re-read"), file: file, line: line)
        XCTAssertTrue(message.contains("restart") && message.contains("reconnect"), file: file, line: line)
        XCTAssertFalse(message.contains(fixture.secret), file: file, line: line)
        let encoded = try JSONEncoder().encode(JSONValue.object(result))
        XCTAssertFalse(String(data: encoded, encoding: .utf8)?.contains(fixture.secret) == true, file: file, line: line)
        XCTAssertTrue(try Data(contentsOf: fixture.file).elementsEqual(fixture.original), file: file, line: line)
    }
}
