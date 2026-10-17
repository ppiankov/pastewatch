import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-705@v1: registration locations are pinned independently of the shared descriptor that now supplies them.
final class AgentHooksPathParityTests: XCTestCase {
    private struct Expected {
        let agent: String
        let paths: [String]
    }

    private let expected = [
        Expected(agent: "claude-code", paths: ["~/.claude/settings.json", ".claude/settings.json"]),
        Expected(agent: "cline", paths: []),
        Expected(agent: "roo-code", paths: ["~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"]),
        Expected(agent: "cursor", paths: ["~/.cursor/hooks.json"]),
        Expected(agent: "windsurf", paths: ["~/.codeium/windsurf/hooks.json"]),
        Expected(agent: "goose", paths: []),
        Expected(agent: "kilo-code", paths: []),
        Expected(agent: "continue", paths: ["~/.continue/settings.json"]),
        Expected(agent: "amazon-q", paths: []),
        Expected(agent: "aider", paths: []),
        Expected(agent: "copilot", paths: [".github/hooks/pastewatch.json"]),
        Expected(agent: "gemini", paths: []),
        Expected(agent: "codex", paths: ["~/.codex/hooks.json"]),
        Expected(agent: "qwen-code", paths: ["~/.qwen/settings.json"])
    ]

    // WO-705@v1: all existing writer paths and the diagnostic reader's matching path remain byte-identical.
    func testWrittenPathsRemainByteIdenticalForEveryAgent() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let home = root.appendingPathComponent("home")
            let project = root.appendingPathComponent("project")
            XCTAssertEqual(expected.map(\.agent), AgentSetup.mcpSetupMatrix.map(\.agent))
            for row in expected {
                let descriptor = try XCTUnwrap(AgentSetup.mcpSetupMatrix.first { $0.agent == row.agent })
                XCTAssertEqual(descriptor.hookConfigPaths, row.paths, row.agent)
                let readPaths = Doctor().agentCoverageFiles(descriptor, home: home, project: project).map(\.path)
                var setup = try Setup.parse([row.agent])
                if row.paths.isEmpty {
                    XCTAssertThrowsError(try setup.hooksConfigPath(home: home.path, projectDirectory: project.path))
                }
                for (index, path) in row.paths.enumerated() {
                    setup.project = index > 0
                    let expectedPath = path.hasPrefix("~/")
                        ? home.path + "/" + path.dropFirst(2) : project.path + "/" + path
                    XCTAssertEqual(try setup.hooksConfigPath(home: home.path, projectDirectory: project.path),
                                   expectedPath, row.agent)
                    XCTAssertTrue(readPaths.contains(expectedPath), row.agent)
                }
            }
        }
    }

    // WO-705@v1: changing descriptor metadata must move both consumers, exposing any reintroduced private table.
    func testBothConsumersFollowInjectedDescriptorPaths() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let home = root.appendingPathComponent("home")
            let project = root.appendingPathComponent("project")
            for original in AgentSetup.mcpSetupMatrix where !original.hookConfigPaths.isEmpty {
                let paths = original.hookConfigPaths.enumerated().map { index, path in
                    (path.hasPrefix("~/") ? "~/" : "") + "fixture-\(original.agent)-\(index).json"
                }
                let descriptor = MCPSetupDescriptor(agent: original.agent, mode: original.mode,
                                                    configPath: original.configPath, hookConfigPaths: paths)
                let reads = Doctor().agentCoverageFiles(descriptor, home: home, project: project)
                var setup = try Setup.parse([original.agent])
                for (index, path) in descriptor.hookConfigURLs(home: home, project: project).enumerated() {
                    setup.project = index > 0
                    XCTAssertEqual(try setup.hooksConfigPath(home: home.path, projectDirectory: project.path,
                                                           descriptor: descriptor), path.path, original.agent)
                    XCTAssertTrue(reads.contains(path), original.agent)
                }
            }
        }
    }
}
