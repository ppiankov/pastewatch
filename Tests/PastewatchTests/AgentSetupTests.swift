import XCTest
@testable import PastewatchCore

final class AgentSetupTests: XCTestCase {

    // MARK: - mergeCodexHooks

    func testMergeCodexHooksCreatesPreToolUseEntry() {
        var json: [String: Any] = [:]
        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        XCTAssertNotNil(entries)
        XCTAssertEqual(entries?.count, 1)
    }

    func testMergeCodexHooksMatcherCoversApplyPatch() {
        var json: [String: Any] = [:]
        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        let matcher = entries?.first?["matcher"] as? String
        XCTAssertTrue(matcher?.contains("apply_patch") == true,
                      "Codex hook matcher must cover apply_patch")
    }

    func testMergeCodexHooksMatcherCoversBash() {
        var json: [String: Any] = [:]
        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        let matcher = entries?.first?["matcher"] as? String
        XCTAssertTrue(matcher?.contains("Bash") == true,
                      "Codex hook matcher must cover Bash")
    }

    func testMergeCodexHooksIsIdempotent() {
        var json: [String: Any] = [:]
        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        XCTAssertEqual(entries?.count, 1, "Idempotent merge must not duplicate entries")
    }

    func testMergeCodexHooksUpdatesExistingEntry() {
        var json: [String: Any] = [:]
        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/old/pastewatch-guard.sh")
        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/new/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        XCTAssertEqual(entries?.count, 1)
        let innerHooks = entries?.first?["hooks"] as? [[String: Any]]
        let command = innerHooks?.first?["command"] as? String
        XCTAssertEqual(command, "/new/pastewatch-guard.sh")
    }

    func testMergeCodexHooksPreservesOtherTopLevelKeys() {
        var json: [String: Any] = ["version": 1]
        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        XCTAssertEqual(json["version"] as? Int, 1)
    }

    // WO-114: Adding Pastewatch must not replace other lifecycle events in the wrapper.
    func testMergeCodexHooksPreservesOtherHookEvents() {
        var json: [String: Any] = [
            "hooks": ["PostToolUse": [["matcher": "Bash"]]],
        ]

        AgentSetup.mergeCodexHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")

        let hooks = json["hooks"] as? [String: Any]
        XCTAssertNotNil(hooks?["PostToolUse"])
        XCTAssertNotNil(hooks?["PreToolUse"])
    }

    // MARK: - mergeQwenCodeHooks

    func testMergeQwenCodeHooksCreatesPreToolUseEntry() {
        var json: [String: Any] = [:]
        AgentSetup.mergeQwenCodeHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        XCTAssertNotNil(entries)
        XCTAssertEqual(entries?.count, 1)
    }

    func testMergeQwenCodeHooksIsIdempotent() {
        var json: [String: Any] = [:]
        AgentSetup.mergeQwenCodeHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        AgentSetup.mergeQwenCodeHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        XCTAssertEqual(entries?.count, 1, "Idempotent merge must not duplicate entries")
    }

    func testMergeQwenCodeHooksUpdatesExistingEntry() {
        var json: [String: Any] = [:]
        AgentSetup.mergeQwenCodeHooks(into: &json, hookPath: "/old/pastewatch-guard.sh")
        AgentSetup.mergeQwenCodeHooks(into: &json, hookPath: "/new/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        XCTAssertEqual(entries?.count, 1)
        let innerHooks = entries?.first?["hooks"] as? [[String: Any]]
        let command = innerHooks?.first?["command"] as? String
        XCTAssertEqual(command, "/new/pastewatch-guard.sh")
    }

    func testMergeQwenCodeHooksPreservesMCPServers() {
        var json: [String: Any] = [:]
        AgentSetup.mergeMCPServer(into: &json, severity: "high")
        AgentSetup.mergeQwenCodeHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        XCTAssertNotNil(json["mcpServers"], "MCP servers must survive hook merge")
    }

    func testMergeQwenCodeHooksMatcherCoversReadWriteEditBash() {
        var json: [String: Any] = [:]
        AgentSetup.mergeQwenCodeHooks(into: &json, hookPath: "/path/to/pastewatch-guard.sh")
        let hooks = json["hooks"] as? [String: Any]
        let entries = hooks?["PreToolUse"] as? [[String: Any]]
        let matcher = entries?.first?["matcher"] as? String
        XCTAssertTrue(matcher?.contains("Read") == true)
        XCTAssertTrue(matcher?.contains("Write") == true)
        XCTAssertTrue(matcher?.contains("Edit") == true)
        XCTAssertTrue(matcher?.contains("Bash") == true)
    }

    // MARK: - codexGuardScript

    func testCodexGuardScriptContainsApplyPatchCase() {
        let script = AgentSetup.codexGuardScript(severity: "high")
        XCTAssertTrue(script.contains("apply_patch"),
                      "Codex guard script must handle apply_patch tool")
    }

    func testCodexGuardScriptContainsBashCase() {
        let script = AgentSetup.codexGuardScript(severity: "high")
        XCTAssertTrue(script.contains("\"Bash\""),
                      "Codex guard script must handle Bash tool")
    }

    func testCodexGuardScriptEmbedsSeverity() {
        let script = AgentSetup.codexGuardScript(severity: "medium")
        XCTAssertTrue(script.contains("medium"), "Codex guard script must embed severity")
    }

    func testCodexGuardScriptHasAllowAndBlockExits() {
        let script = AgentSetup.codexGuardScript(severity: "high")
        XCTAssertTrue(script.contains("exit 0"), "Guard script must have allow exit")
        XCTAssertTrue(script.contains("exit 2"), "Guard script must have block exit")
    }

    func testCodexGuardScriptIsExecutable() {
        let script = AgentSetup.codexGuardScript(severity: "high")
        XCTAssertTrue(script.hasPrefix("#!/bin/bash"), "Guard script must start with shebang")
    }
}
