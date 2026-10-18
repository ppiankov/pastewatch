import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-706@v1: diagnostics and parser entry points recognize the same complete executable basenames.
final class OwnBinaryNameTests: XCTestCase {
    // WO-706@v1: mixed-case canonical names agree without admitting prefixes or unrelated executables.
    func testBasenamesAgreeAcrossDoctorAndParserEntryPoints() throws {
        let fixtures = [
            ("pastewatch-cli", true), ("PastewatchCLI", true), ("pastewatchcli", true),
            ("PASTEWATCH-CLI", true), ("pastewatch", false), ("pastewatch-cli-old", false)
        ]
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let doctor = Doctor()
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "EEE MMM d HH:mm:ss yyyy"
            for (name, expected) in fixtures {
                let binary = root.appendingPathComponent(name).path
                // WO-706@v1: direct Core recognition and both public consumers must agree on this row.
                XCTAssertEqual(ExecutableIdentityNames.isOwnBinary(binary), expected, name)
                let process = doctor.parseMCPProcess("31 Mon Oct 5 06:30:00 2026 \(binary) mcp", dateFormatter: formatter)
                XCTAssertEqual(process != nil, expected, "process: \(name)")
                let data = try JSONSerialization.data(withJSONObject: ["mcpServers": [
                    "pastewatch": ["command": binary, "args": ["mcp"]] as [String: Any]
                ]])
                let rows = doctor.checkAgentCoverage(home: root, project: root, wireAgents: [], read: { url in
                    url == root.appendingPathComponent(".cursor/mcp.json") ? data : nil
                })
                let row = try XCTUnwrap(rows.first { $0.detail.hasPrefix("cursor:") })
                XCTAssertTrue(row.detail.hasPrefix(expected ? "cursor: MCP advisory;" : "cursor: none;"), name)
                let direct = CommandParser.fileAccess(from: "\(binary) $action fixture.txt", workingDirectory: root.path)
                XCTAssertEqual(direct.invokesBinaryGrant, expected, "direct: \(name)")
                let aliased = CommandParser.fileAccess(from: "alias pw=\(binary); pw $action fixture.txt",
                                                      workingDirectory: root.path)
                XCTAssertEqual(aliased.invokesBinaryGrant, expected, "alias: \(name)")
            }
        }
    }
}
