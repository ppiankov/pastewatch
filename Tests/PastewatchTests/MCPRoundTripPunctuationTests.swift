import XCTest
@testable import PastewatchCore

// WO-133@v3: real read/write transport must preserve unedited punctuation and bytes.
final class MCPRoundTripPunctuationTests: XCTestCase {
    // WO-133@v3: verify punctuation-adjacent credential spans before changing restoration.
    func testCredentialPunctuationRoundTripsWithUnrelatedEdit() throws {
        let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
        let assignment = ["pass", "word", "=", value].joined()
        for (index, punctuation) in ["\"", "}", "`", "]", ")"].enumerated() {
            let content = "// unrelated before\nlet fixture = " + assignment + punctuation + "\n"
            try assertRoundTrip(content, extension: "go", variant: index)
        }
    }

    // WO-133@v3: JSON string closing quotes and braces must survive the stored range restore.
    func testJSONStringPunctuationRoundTripsWithUnrelatedEdit() throws {
        let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
        let content = "{\n\"note\":\"unrelated before\",\n\"" + ["pass", "word"].joined() +
            "\":\"" + value + "\"\n}\n"
        try assertRoundTrip(content, extension: "json", variant: 0)
    }

    // WO-133@v3: a password-only MCP placeholder must not consume the following at-sign.
    func testDSNPasswordAtSignRoundTripsWithUnrelatedEdit() throws {
        let value = ["Q7m", "N4r", "Z9T", "2xV", "6k"].joined()
        let connection = ["post", "gres", "://", "app:", value, "@db:5432/prod"].joined()
        try assertRoundTrip("unrelated before\n" + connection + "\n", extension: "txt", variant: 0)
    }

    // WO-133@v3: retain the founding Go fixture even when its symbolic reference is not detected.
    func testFoundingGoRawStringRoundTripsWithUnrelatedEdit() throws {
        let reference = "${" + ["EXAMPLE", "_", "TOKEN"].joined() + "}"
        let original = "// unrelated before\n" +
            "result := parseForTest(t, `printf \"%s\" \"prefix " + reference + "\"`)\n" +
            "want := [][]string{{\"printf\", \"prefix " + reference + "\"}}\n"
        try assertRoundTrip(original, extension: "go", variant: 0, requireDetection: false)
    }

    // WO-133@v3: use only an isolated project policy and the actual persistent MCP process.
    private func assertRoundTrip(
        _ original: String, extension ext: String, variant: Int, requireDetection: Bool = true
    ) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential, .dbConnectionString])
            let session = try MCPProtocolTests.LiveMCPSession(
                executableURL: cliURL(), maximumLineBytes: 65_536, config: config
            )
            defer { session.close() }
            let file = session.directory.appendingPathComponent("punctuation-\(variant).\(ext)")
            try Data(original.utf8).write(to: file)
            let payload = try call(session, name: "pastewatch_read_file", arguments: ["path": .string(file.path)])
            let redactions = try XCTUnwrap(payload["redactions"] as? [[String: Any]])
            if requireDetection {
                XCTAssertFalse(redactions.isEmpty, "fixture must exercise a detected secret")
            } else {
                let advisoryCount = (payload["advisories"] as? [[String: Any]])?.count ?? 0
                print("WO-133 founding fixture: detected count=\(redactions.count + advisoryCount)")
            }
            let redacted = try XCTUnwrap(payload["content"] as? String)
            let edited = redacted.replacingOccurrences(of: "unrelated before", with: "unrelated after")
            _ = try call(session, name: "pastewatch_write_file", arguments: [
                "path": .string(file.path), "content": .string(edited)
            ])
            let expected = original.replacingOccurrences(of: "unrelated before", with: "unrelated after")
            XCTAssertTrue(try Data(contentsOf: file) == Data(expected.utf8),
                          "variant \(variant), format \(ext): only the unrelated edit may change bytes")
        }
    }

    // WO-133@v3: inspect protocol metadata without putting secret payloads in assertion output.
    private func call(
        _ session: MCPProtocolTests.LiveMCPSession, name: String, arguments: [String: JSONValue]
    ) throws -> [String: Any] {
        let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/call", params: .object([
            "name": .string(name), "arguments": .object(arguments)
        ]))
        try session.send(JSONEncoder().encode(request) + Data([0x0A]))
        let response = try XCTUnwrap(session.response(), "MCP response deadline expired")
        XCTAssertNil(response.error)
        guard case .object(let result) = response.result,
              result["isError"] == nil,
              case .array(let blocks) = result["content"],
              case .object(let block) = blocks.first,
              case .string(let text) = block["text"],
              let payload = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            throw NSError(domain: "MCPRoundTripPunctuationTests", code: 1)
        }
        return payload
    }

    // WO-133@v3: resolve the built fixture binary without global configuration fallback.
    private func cliURL() -> URL {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let bundled = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("PastewatchCLI")
        return FileManager.default.fileExists(atPath: bundled.path) ? bundled :
            root.appendingPathComponent(".build/debug/PastewatchCLI")
    }
}
