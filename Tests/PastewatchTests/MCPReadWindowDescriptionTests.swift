import XCTest
@testable import PastewatchCore

// WO-665@v1: advertised read limits follow the shared byte threshold on every public surface.
final class MCPReadWindowDescriptionTests: XCTestCase {
    // WO-665@v1: MCP tool and argument descriptions cannot retain a stale numeric limit.
    func testToolDescriptionsUseSharedReadWindowLimit() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: executable(),
                maximumLineBytes: ScanInputLimits.defaultMaximumLineBytes)
            defer { session.close() }
            let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/list", params: nil)
            try session.send(try JSONEncoder().encode(request) + Data([0x0A]))
            let response = try XCTUnwrap(session.response())
            let result = try XCTUnwrap(response.result)
            let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(result)) as? [String: Any])
            let tools = try XCTUnwrap(payload["tools"] as? [[String: Any]])
            let read = try XCTUnwrap(tools.first { $0["name"] as? String == "pastewatch_read_file" })
            let description = try XCTUnwrap(read["description"] as? String)
            let schema = try XCTUnwrap(read["inputSchema"] as? [String: Any])
            let properties = try XCTUnwrap(schema["properties"] as? [String: Any])
            let length = try XCTUnwrap(properties["byte_length"] as? [String: Any])
            let lengthDescription = try XCTUnwrap(length["description"] as? String)
            let size = "\(MCPReadDecision.unrangedResponseLimitBytes / 1_024) KiB"
            XCTAssertEqual(MCPReadDecision.unrangedResponseLimitDescription, size)
            XCTAssertTrue(description.contains("output over \(size)"))
            XCTAssertTrue(description.contains("first line over \(size)"))
            XCTAssertTrue(lengthDescription.contains("at or below \(size)"))
        }
    }

    // WO-665@v1: guard guidance reports the same enforced threshold without exposing fixture content.
    func testGuardHintUsesSharedReadWindowLimit() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let secret = ["gh", "p_", String(repeating: "Ab3dE5", count: 6)].joined()
            let target = root.appendingPathComponent("large.txt")
            let content = String(repeating: "ordinary text\n", count: MCPReadDecision.unrangedResponseLimitBytes) + secret
            try Data(content.utf8).write(to: target)
            let process = Process()
            process.executableURL = executable()
            process.arguments = ["guard-read", target.path]
            process.currentDirectoryURL = root
            process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin", "PW_GUARD": "1"])
            let output = Pipe()
            let errors = Pipe()
            process.standardOutput = output
            process.standardError = errors
            try process.run()
            let bytes = output.fileHandleForReading.readDataToEndOfFile() + errors.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let text = try XCTUnwrap(String(data: bytes, encoding: .utf8))
            XCTAssertEqual(process.terminationStatus, 2)
            XCTAssertTrue(text.contains("whole lines up to \(MCPReadDecision.unrangedResponseLimitDescription)"))
            XCTAssertFalse(text.contains(secret))
        }
    }

    // WO-665@v1: fixture CWD changes cannot redirect the test executable lookup.
    private func executable() -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
    }
}
