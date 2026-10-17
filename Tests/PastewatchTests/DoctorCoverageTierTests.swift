import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-697@v1: reported tiers must reflect registrations and existing routing rather than agent capabilities alone.
final class DoctorCoverageTierTests: XCTestCase {
    // WO-702@v1: equals-form ports retain wire coverage rather than falling back to the default listener port.
    func testEqualsFormPortReportsWireCoverage() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let doctor = Doctor()
            let agents = doctor.observedWireAgents(
                environment: ["ANTHROPIC_BASE_URL": "http://127.0.0.1:9000"],
                proxyCommands: { ["pastewatch-cli proxy --port=9000"] }
            )
            XCTAssertEqual(agents, ["claude-code"])
            let evidence = AgentCoverageEvidence(agent: "claude-code", hooks: true, mcp: true,
                                                 wire: agents.contains("claude-code"))
            XCTAssertEqual(doctor.agentCoverageTier(evidence), "hooks+wire")
        }
    }

    // WO-697@v1: one fixture per tier pins the public vocabulary and the existing launch restriction.
    func testCoverageTiersFollowExistingMatrixAndRouting() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let doctor = Doctor()
            let cases: [(AgentCoverageEvidence, String)] = [
                (AgentCoverageEvidence(agent: "claude-code", hooks: true, mcp: true, wire: true), "hooks+wire"),
                (AgentCoverageEvidence(agent: "cursor", hooks: true, mcp: true, wire: false), "hooks+MCP"),
                (AgentCoverageEvidence(agent: "gemini", hooks: false, mcp: true, wire: false), "MCP advisory"),
                (AgentCoverageEvidence(agent: "aider", hooks: false, mcp: false, wire: false), "none"),
                (AgentCoverageEvidence(agent: "cursor", hooks: true, mcp: true, wire: true), "hooks+MCP"),
                (AgentCoverageEvidence(agent: "unknown", hooks: true, mcp: true, wire: true), "none")
            ]
            for (evidence, tier) in cases { XCTAssertEqual(doctor.agentCoverageTier(evidence), tier, evidence.agent) }
        }
    }

    // WO-697@v1: fixture registrations exercise the same collector called by the doctor command.
    func testDoctorCollectsEachTierWithoutOperatorFiles() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var mcp: [String: Any] = [:]
            AgentSetup.mergeMCPServer(into: &mcp, severity: Severity.defaultGuardThreshold.rawValue)
            var hooks: [String: Any] = [:]
            AgentSetup.mergeClaudeCodeHooks(into: &hooks, hookPath: "pastewatch-guard.sh")
            try writeJSON(mcp, path: ".claude.json", root: root)
            try writeJSON(hooks, path: ".claude/settings.json", root: root)
            try writeJSON(mcp, path: ".cursor/mcp.json", root: root)
            try writeJSON(hooks, path: ".cursor/hooks.json", root: root)
            try writeJSON(mcp, path: ".gemini/settings.json", root: root)
            let rows = Doctor().checkAgentCoverage(home: root, project: root, wireAgents: ["claude-code"])
            XCTAssertEqual(rows.count, AgentSetup.mcpSetupMatrix.count)
            for expected in ["claude-code: hooks+wire", "cursor: hooks+MCP", "gemini: MCP advisory", "aider: none"] {
                XCTAssertTrue(rows.contains { $0.detail.hasPrefix(expected + ";") }, expected)
            }
            XCTAssertTrue(rows.allSatisfy { $0.check == "coverage" && $0.detail.contains("not a sandbox") })
        }
    }

    // WO-697@v1: installed scripts and disabled MCP entries are not evidence of active registration.
    func testDisabledAndMentionOnlyConfigurationsDoNotClaimCoverage() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var mcp: [String: Any] = [:]
            AgentSetup.mergeMCPServer(into: &mcp, severity: Severity.defaultGuardThreshold.rawValue, disabled: true)
            try writeJSON(mcp, path: ".cursor/mcp.json", root: root)
            try writeJSON(["description": "pastewatch-guard.sh"], path: ".cursor/hooks.json", root: root)
            let rows = Doctor().checkAgentCoverage(home: root, project: root, wireAgents: [])
            XCTAssertTrue(rows.first { $0.detail.hasPrefix("cursor:") }?.detail.hasPrefix("cursor: none;") == true)
        }
    }

    // WO-697@v1: the collector's complete path inventory stays under injected roots during tests.
    func testCoverageReadsStayInsideFixtureRoots() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var paths: [String] = []
            let rows = Doctor().checkAgentCoverage(home: root, project: root, wireAgents: [], read: { url in
                paths.append(url.path)
                return nil
            })
            XCTAssertFalse(paths.isEmpty)
            XCTAssertTrue(paths.allSatisfy { $0.hasPrefix(root.path + "/") })
            XCTAssertTrue(rows.allSatisfy { $0.detail.contains(": none;") })
        }
    }

    // WO-697@v1: test registrations contain command metadata only and are owned by the isolated fixture.
    private func writeJSON(_ object: [String: Any], path: String, root: URL) throws {
        let url = root.appendingPathComponent(path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONSerialization.data(withJSONObject: object).write(to: url)
    }
}
