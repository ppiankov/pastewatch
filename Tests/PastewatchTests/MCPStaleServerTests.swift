import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-681@v1: executable identity is injected, so no installed binary is replaced during these tests.
final class MCPStaleServerTests: XCTestCase {
    // WO-681@v1: unchanged identity is fresh; inode, mtime, original removal and symlink repointing refuse.
    func testIdentityChangesRefuseWithoutBinaryReplacement() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let invoked = root.appendingPathComponent("invoked").path
            let original = identity(root: root)
            for change in ["inode", "mtime", "removed", "repointed", "device"] {
                var files = [invoked: original, original.realPath: original]
                let freshness = MCPExecutableFreshness(invokedPath: invoked, lookup: { files[$0] })
                XCTAssertFalse(freshness.isStale, change)
                switch change {
                case "inode":
                    files[invoked] = MCPExecutableIdentity(realPath: original.realPath, inode: 2,
                                                         device: original.device, modifiedAt: original.modifiedAt)
                case "mtime":
                    files[original.realPath] = MCPExecutableIdentity(realPath: original.realPath, inode: original.inode,
                                                                    device: original.device,
                                                                    modifiedAt: original.modifiedAt.addingTimeInterval(1))
                case "removed": files[original.realPath] = nil
                case "repointed":
                    files[invoked] = MCPExecutableIdentity(realPath: root.appendingPathComponent("replacement").path,
                                                         inode: original.inode, device: original.device, modifiedAt: original.modifiedAt)
                default:
                    files[invoked] = MCPExecutableIdentity(realPath: original.realPath, inode: original.inode,
                                                         device: 2, modifiedAt: original.modifiedAt)
                }
                XCTAssertTrue(freshness.isStale, change)
            }
            XCTAssertTrue(MCPExecutableFreshness(invokedPath: invoked, lookup: { _ in nil }).isStale)
        }
    }

    // WO-681@v1: every advertised tool refuses before producing a verdict, content or write side effect.
    func testEveryAdvertisedToolFailsClosedWhenExecutableChanges() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let invoked = root.appendingPathComponent("invoked").path
            let original = identity(root: root)
            var files = [invoked: original, original.realPath: original]
            let freshness = MCPExecutableFreshness(invokedPath: invoked, lookup: { files[$0] })
            let server = MCPServer(executableFreshness: freshness)
            let listing = try result(server, method: "tools/list")
            guard case .array(let tools) = listing["tools"] else { return XCTFail("Missing advertised tools") }
            let names = tools.compactMap { value -> String? in
                guard case .object(let tool) = value, case .string(let name) = tool["name"] else { return nil }
                return name
            }
            XCTAssertEqual(names.count, 7)
            let value = ["AK", "IA", String(repeating: "Q", count: 16)].joined()
            let target = root.appendingPathComponent("fixture.env")
            let before = Data(("key=" + value + "\nlabel=before\n").utf8)
            try before.write(to: target)
            files[original.realPath] = nil
            let arguments: [String: JSONValue] = [
                "path": .string(target.path), "text": .string(value), "content": .string("changed"),
                "old_string": .string("before"), "new_string": .string("after")
            ]
            for name in names {
                let response = try result(server, method: "tools/call", params: .object([
                    "name": .string(name), "arguments": .object(arguments)
                ]))
                XCTAssertEqual(Set(response.keys), ["content", "isError", "_meta"], name)
                XCTAssertEqual(response["isError"], .bool(true), name)
                guard case .object(let metadata) = response["_meta"] else { return XCTFail("Missing stale metadata") }
                XCTAssertEqual(metadata["stale"], .bool(true), name)
                XCTAssertEqual(metadata["server_version"], .string(AppVersion.current), name)
                guard case .array(let content) = response["content"], case .object(let block) = content.first,
                      case .string(let message) = block["text"] else { return XCTFail("Missing refusal") }
                XCTAssertTrue(message.hasPrefix("pastewatch MCP server is stale (running " + AppVersion.current), name)
                XCTAssertTrue(message.contains("/mcp reconnect pastewatch"), name)
                let encoded = try JSONEncoder().encode(JSONValue.object(response))
                XCTAssertFalse(String(data: encoded, encoding: .utf8)?.contains(value) == true, name)
                XCTAssertTrue(try Data(contentsOf: target).elementsEqual(before), name)
            }
        }
    }

    // WO-681@v1: a missing startup baseline refuses every tool without claiming the binary changed.
    func testUnavailableStartupIdentityRefusesWithVerificationRemedy() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var availableIdentity: MCPExecutableIdentity?
            let freshness = MCPExecutableFreshness(invokedPath: root.appendingPathComponent("invoked").path,
                                                   lookup: { _ in availableIdentity })
            availableIdentity = identity(root: root)
            let server = MCPServer(executableFreshness: freshness)
            let listing = try result(server, method: "tools/list")
            guard case .array(let tools) = listing["tools"] else { return XCTFail("Missing advertised tools") }
            XCTAssertEqual(tools.count, 7)
            for tool in tools {
                guard case .object(let fields) = tool, case .string(let name) = fields["name"] else {
                    return XCTFail("Missing tool name")
                }
                let response = try result(server, method: "tools/call", params: .object([
                    "name": .string(name), "arguments": .object([:])
                ]))
                XCTAssertEqual(Set(response.keys), ["content", "isError", "_meta"], name)
                XCTAssertEqual(response["isError"], .bool(true), name)
                guard case .array(let content) = response["content"], case .object(let block) = content.first,
                      case .string(let message) = block["text"], case .object(let metadata) = response["_meta"] else {
                    return XCTFail("Missing verification refusal")
                }
                XCTAssertTrue(message.hasPrefix("pastewatch MCP server cannot verify its executable (running " +
                                                AppVersion.current + "): reconnect the pastewatch MCP server"), name)
                XCTAssertTrue(message.contains("/mcp reconnect pastewatch"), name)
                XCTAssertTrue(message.hasSuffix("before trusting any verdict."), name)
                XCTAssertFalse(message.contains("installed binary changed"), name)
                XCTAssertEqual(metadata["stale"], .bool(true), name)
                XCTAssertEqual(metadata["server_version"], .string(AppVersion.current), name)
            }
        }
    }

    // WO-681@v1: fresh dispatch retains the existing tool payload contract and version metadata.
    func testFreshServerPreservesScanAndReadPayloads() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let original = identity(root: root)
            let server = MCPServer(executableFreshness: MCPExecutableFreshness(
                invokedPath: original.realPath, lookup: { _ in original }
            ))
            let scan = try result(server, method: "tools/call", params: .object([
                "name": .string("pastewatch_scan"), "arguments": .object(["text": .string("hello")])
            ]))
            XCTAssertNil(scan["isError"])
            guard case .array(let blocks) = scan["content"], case .object(let block) = blocks.first else {
                return XCTFail("Missing existing scan payload")
            }
            XCTAssertEqual(block["text"], .string("No sensitive data found."))
            guard case .object(let metadata) = scan["_meta"] else { return XCTFail("Missing server metadata") }
            XCTAssertEqual(metadata, ["server_version": .string(AppVersion.current)])
            let file = root.appendingPathComponent("clean.txt")
            try Data("hello\n".utf8).write(to: file)
            let read = try result(server, method: "tools/call", params: .object([
                "name": .string("pastewatch_read_file"), "arguments": .object(["path": .string(file.path)])
            ]))
            XCTAssertNil(read["isError"])
            guard case .array(let readBlocks) = read["content"], case .object(let readBlock) = readBlocks.first,
                  case .string(let text) = readBlock["text"],
                  let payload = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
                return XCTFail("Missing existing read payload")
            }
            XCTAssertEqual(Set(payload.keys), ["content", "redactions", "advisories", "clean"])
            XCTAssertEqual(payload["content"] as? String, "hello\n")
            XCTAssertEqual(payload["clean"] as? Bool, true)
        }
    }

    // WO-681@v1: test identities describe virtual files and never inspect installed binaries.
    private func identity(root: URL) -> MCPExecutableIdentity {
        MCPExecutableIdentity(realPath: root.appendingPathComponent("original").path, inode: 1, device: 1,
                              modifiedAt: Date(timeIntervalSince1970: 1_000))
    }

    // WO-681@v1: in-process protocol requests exercise the production gate without transport-specific test channels.
    private func result(_ server: MCPServer, method: String, params: JSONValue? = nil) throws -> [String: JSONValue] {
        let response = try XCTUnwrap(server.handleRequest(JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: method, params: params)))
        XCTAssertNil(response.error)
        guard case .object(let payload) = response.result else { throw CocoaError(.coderInvalidValue) }
        return payload
    }
}
