import XCTest
@testable import PastewatchCore

final class SetupCommandTests: XCTestCase {

    // WO-500: Keep setup coverage exhaustive as agent config formats evolve.
    func testMCPSetupMatrixCoversEverySetupAgent() {
        let expectedAgents = [
            "claude-code", "cline", "roo-code", "cursor", "windsurf",
            "goose", "kilo-code", "continue", "amazon-q", "aider",
            "copilot", "gemini", "codex", "qwen-code",
        ]

        XCTAssertEqual(AgentSetup.mcpSetupMatrix.map(\.agent), expectedAgents)
        XCTAssertEqual(
            AgentSetup.mcpSetupMatrix.filter { $0.mode == .automatic }.count,
            11
        )
        XCTAssertEqual(
            AgentSetup.mcpSetupMatrix.filter { $0.mode == .manual }.map(\.agent),
            ["goose", "codex"]
        )
        XCTAssertEqual(
            AgentSetup.mcpSetupMatrix.filter { $0.mode == .unavailable }.map(\.agent),
            ["aider"]
        )
        XCTAssertTrue(AgentSetup.mcpSetupMatrix.allSatisfy { !$0.configPath.isEmpty })
    }

    // MARK: - MCP Merge Tests

    func testMergeMCPIntoEmpty() {
        var json: [String: Any] = [:]
        AgentSetup.mergeMCPServer(into: &json, severity: "high")

        let mcpServers = json["mcpServers"] as? [String: Any]
        XCTAssertNotNil(mcpServers)

        let pw = mcpServers?["pastewatch"] as? [String: Any]
        XCTAssertNotNil(pw)
        XCTAssertEqual(pw?["command"] as? String, "pastewatch-cli")

        let args = pw?["args"] as? [String]
        XCTAssertEqual(args, ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"])
    }

    func testMergeMCPPreservesExisting() {
        var json: [String: Any] = [
            "mcpServers": [
                "other-tool": ["command": "other-cli", "args": ["serve"]] as [String: Any],
            ] as [String: Any],
            "someKey": "someValue",
        ]
        AgentSetup.mergeMCPServer(into: &json, severity: "high")

        // Pastewatch added
        let mcpServers = json["mcpServers"] as? [String: Any]
        XCTAssertNotNil(mcpServers?["pastewatch"])

        // Other tool preserved
        let other = mcpServers?["other-tool"] as? [String: Any]
        XCTAssertEqual(other?["command"] as? String, "other-cli")

        // Other top-level key preserved
        XCTAssertEqual(json["someKey"] as? String, "someValue")
    }

    func testMergeMCPIdempotent() {
        var json: [String: Any] = [:]
        AgentSetup.mergeMCPServer(into: &json, severity: "high")

        let firstArgs = (json["mcpServers"] as? [String: Any])?["pastewatch"]
            as? [String: Any]

        // Merge again
        AgentSetup.mergeMCPServer(into: &json, severity: "high")

        let secondArgs = (json["mcpServers"] as? [String: Any])?["pastewatch"]
            as? [String: Any]

        // Same result
        XCTAssertEqual(firstArgs?["command"] as? String, secondArgs?["command"] as? String)

        let firstArgsList = firstArgs?["args"] as? [String]
        let secondArgsList = secondArgs?["args"] as? [String]
        XCTAssertEqual(firstArgsList, secondArgsList)
    }

    func testMergeMCPDefaultSeverityOmitsFlag() {
        var json: [String: Any] = [:]
        AgentSetup.mergeMCPServer(into: &json, severity: "high")

        let pw = (json["mcpServers"] as? [String: Any])?["pastewatch"] as? [String: Any]
        let args = pw?["args"] as? [String] ?? []

        // Default severity should NOT include --min-severity
        XCTAssertFalse(args.contains("--min-severity"))
    }

    func testMergeMCPCustomSeverityIncludesFlag() {
        var json: [String: Any] = [:]
        AgentSetup.mergeMCPServer(into: &json, severity: "medium")

        let pw = (json["mcpServers"] as? [String: Any])?["pastewatch"] as? [String: Any]
        let args = pw?["args"] as? [String] ?? []

        XCTAssertTrue(args.contains("--min-severity"))
        if let idx = args.firstIndex(of: "--min-severity") {
            XCTAssertEqual(args[idx + 1], "medium")
        }
    }

    func testMergeMCPDisabledField() {
        var json: [String: Any] = [:]
        AgentSetup.mergeMCPServer(into: &json, severity: "high", disabled: false)

        let pw = (json["mcpServers"] as? [String: Any])?["pastewatch"] as? [String: Any]
        XCTAssertEqual(pw?["disabled"] as? Bool, false)
    }

    // WO-500: Kilo uses an OpenCode-derived schema, not the common mcpServers shape.
    func testMergeKiloMCPPreservesExistingConfig() {
        var json: [String: Any] = [
            "theme": "dark",
            "mcp": ["other": ["type": "remote", "url": "https://example.invalid"]],
        ]

        AgentSetup.mergeKiloMCPServer(into: &json, severity: "medium")

        XCTAssertEqual(json["theme"] as? String, "dark")
        let servers = json["mcp"] as? [String: Any]
        XCTAssertNotNil(servers?["other"])
        let pastewatch = servers?["pastewatch"] as? [String: Any]
        XCTAssertEqual(pastewatch?["type"] as? String, "local")
        XCTAssertEqual(pastewatch?["enabled"] as? Bool, true)
        XCTAssertEqual(
            pastewatch?["command"] as? [String],
            [
                "pastewatch-cli", "mcp", "--audit-log", "/tmp/pastewatch-audit.log",
                "--min-severity", "medium",
            ]
        )
    }

    // WO-500: Continue's standalone block must remain valid and severity-aligned.
    func testContinueMCPConfigIncludesServerAndSeverity() {
        let config = AgentSetup.continueMCPConfig(severity: "low")

        XCTAssertTrue(config.contains("mcpServers:"))
        XCTAssertTrue(config.contains("command: pastewatch-cli"))
        XCTAssertTrue(config.contains("      - --min-severity\n      - low"))
    }

    // MARK: - Hooks Merge Tests

    func testMergeHooksIntoEmpty() {
        var json: [String: Any] = [:]
        AgentSetup.mergeClaudeCodeHooks(into: &json, hookPath: "/test/hook.sh")

        let hooks = json["hooks"] as? [String: Any]
        let preToolUse = hooks?["PreToolUse"] as? [[String: Any]]

        XCTAssertNotNil(preToolUse)
        XCTAssertEqual(preToolUse?.count, 1)

        let entry = preToolUse?.first
        XCTAssertEqual(entry?["matcher"] as? String, "Read|Write|Edit")

        let innerHooks = entry?["hooks"] as? [[String: Any]]
        XCTAssertEqual(innerHooks?.first?["command"] as? String, "/test/hook.sh")
    }

    func testMergeHooksPreservesOtherEntries() {
        var json: [String: Any] = [
            "hooks": [
                "PreToolUse": [
                    [
                        "matcher": "Bash",
                        "hooks": [["type": "command", "command": "/other/hook.sh"]],
                    ] as [String: Any],
                ],
            ] as [String: Any],
        ]

        AgentSetup.mergeClaudeCodeHooks(
            into: &json,
            hookPath: "/home/.claude/hooks/pastewatch-guard.sh"
        )

        let preToolUse = (json["hooks"] as? [String: Any])?["PreToolUse"]
            as? [[String: Any]]

        // Both entries present
        XCTAssertEqual(preToolUse?.count, 2)

        // Bash entry preserved
        let bashEntry = preToolUse?.first { ($0["matcher"] as? String) == "Bash" }
        XCTAssertNotNil(bashEntry)

        // Pastewatch entry added
        let pwEntry = preToolUse?.first { ($0["matcher"] as? String) == "Read|Write|Edit" }
        XCTAssertNotNil(pwEntry)
    }

    func testMergeHooksIdempotent() {
        var json: [String: Any] = [:]
        let hookPath = "/home/.claude/hooks/pastewatch-guard.sh"

        AgentSetup.mergeClaudeCodeHooks(into: &json, hookPath: hookPath)
        AgentSetup.mergeClaudeCodeHooks(into: &json, hookPath: hookPath)

        let preToolUse = (json["hooks"] as? [String: Any])?["PreToolUse"]
            as? [[String: Any]]

        // Should still be exactly one entry, not two
        XCTAssertEqual(preToolUse?.count, 1)
    }

    func testMergeHooksUpdatesExistingPastewatch() {
        var json: [String: Any] = [
            "hooks": [
                "PreToolUse": [
                    [
                        "matcher": "Read|Write|Edit",
                        "hooks": [
                            [
                                "type": "command",
                                "command": "/old/path/pastewatch-guard.sh",
                            ] as [String: Any],
                        ],
                    ] as [String: Any],
                ],
            ] as [String: Any],
        ]

        let newPath = "/new/path/pastewatch-guard.sh"
        AgentSetup.mergeClaudeCodeHooks(into: &json, hookPath: newPath)

        let preToolUse = (json["hooks"] as? [String: Any])?["PreToolUse"]
            as? [[String: Any]]

        // Still one entry
        XCTAssertEqual(preToolUse?.count, 1)

        // Updated to new path
        let innerHooks = preToolUse?.first?["hooks"] as? [[String: Any]]
        XCTAssertEqual(innerHooks?.first?["command"] as? String, newPath)
    }

    // MARK: - Guard Script Template Tests

    func testGuardScriptContainsSeverity() {
        let script = AgentSetup.claudeCodeGuardScript(severity: "medium")
        XCTAssertTrue(script.contains("PW_SEVERITY=\"${PW_SEVERITY:-medium}\""))
    }

    func testGuardScriptDefaultSeverity() {
        let script = AgentSetup.claudeCodeGuardScript(severity: "high")
        XCTAssertTrue(script.contains("PW_SEVERITY=\"${PW_SEVERITY:-high}\""))
    }

    func testGuardScriptContainsSessionCheck() {
        let script = AgentSetup.claudeCodeGuardScript(severity: "high")
        XCTAssertTrue(script.contains("pgrep"))
        XCTAssertTrue(script.contains("pastewatch-cli mcp"))
    }

    func testGuardScriptContainsShebang() {
        let script = AgentSetup.claudeCodeGuardScript(severity: "high")
        XCTAssertTrue(script.hasPrefix("#!/bin/bash"))
    }

    // WO-526@v2: generated hooks use the structured mutation guard by default.
    func testGeneratedMutationHooksAreChangeAware() {
        let claude = AgentSetup.claudeCodeGuardScript(severity: "high")
        let codex = AgentSetup.codexGuardScript(severity: "high")

        for script in [claude, codex] {
            XCTAssertTrue(script.contains("pastewatch-cli guard-mutation --fail-on-severity"))
            XCTAssertTrue(script.contains("printf '%s' \"$input\""))
        }
        XCTAssertTrue(claude.contains("pastewatch-cli scan --check"))
        XCTAssertTrue(codex.contains("apply_patch remain whole-file decisions"))
    }

    func testClineScriptContainsSeverity() {
        let script = AgentSetup.clineHookScript(severity: "medium")
        XCTAssertTrue(script.contains("PW_SEVERITY=\"${PW_SEVERITY:-medium}\""))
    }

    func testClineScriptContainsBashGuard() {
        let script = AgentSetup.clineHookScript(severity: "high")
        XCTAssertTrue(script.contains("execute_command"))
        XCTAssertTrue(script.contains("pastewatch-cli guard"))
    }

    // MARK: - JSON Read/Write Tests

    func testReadWriteJSONRoundtrip() throws {
        let tmpDir = NSTemporaryDirectory() + "pw-setup-test-\(UUID().uuidString)"
        let tmpPath = tmpDir + "/test.json"
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let original: [String: Any] = [
            "key1": "value1",
            "nested": ["a": 1, "b": 2] as [String: Any],
        ]

        try AgentSetup.writeJSON(original, to: tmpPath)

        let loaded = AgentSetup.readJSON(at: tmpPath)
        XCTAssertEqual(loaded["key1"] as? String, "value1")

        let nested = loaded["nested"] as? [String: Any]
        XCTAssertEqual(nested?["a"] as? Int, 1)
        XCTAssertEqual(nested?["b"] as? Int, 2)
    }

    func testReadJSONMissingFileReturnsEmpty() {
        let result = AgentSetup.readJSON(at: "/nonexistent/path/file.json")
        XCTAssertTrue(result.isEmpty)
    }

    // WO-500: Auto-setup must not replace an unreadable existing agent config.
    func testReadJSONForMergeRejectsMalformedExistingFile() throws {
        let tmpPath = NSTemporaryDirectory() + "pw-invalid-config-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }
        try "{ invalid".write(toFile: tmpPath, atomically: true, encoding: .utf8)

        XCTAssertThrowsError(try AgentSetup.readJSONForMerge(at: tmpPath))
    }

    // WO-500: Valid JSON with an incompatible MCP section must not be overwritten.
    func testReadJSONForMergeRejectsInvalidObjectSectionType() throws {
        let tmpPath = NSTemporaryDirectory() + "pw-invalid-mcp-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }
        try AgentSetup.writeJSON(["mcpServers": []], to: tmpPath)

        XCTAssertThrowsError(
            try AgentSetup.readJSONForMerge(
                at: tmpPath,
                requiringObjectPaths: [["mcpServers"]]
            )
        )
    }

    // WO-500: Mixed hook arrays must not be discarded when the typed cast fails.
    func testReadJSONForMergeRejectsInvalidNestedHookEntries() throws {
        let tmpPath = NSTemporaryDirectory() + "pw-invalid-hooks-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }
        try AgentSetup.writeJSON(
            [
                "hooks": [
                    "PreToolUse": [NSNull(), ["matcher": "Bash"]],
                ],
            ],
            to: tmpPath
        )

        XCTAssertThrowsError(
            try AgentSetup.readJSONForMerge(
                at: tmpPath,
                requiringObjectPaths: [["hooks"]],
                requiringObjectArrayPaths: [["hooks", "PreToolUse"]]
            )
        )
    }

    // MARK: - Integration Tests

    func testClaudeCodeSetupCreatesFiles() throws {
        let tmpHome = NSTemporaryDirectory() + "pw-setup-home-\(UUID().uuidString)"
        let claudeDir = tmpHome + "/.claude"
        let hooksDir = claudeDir + "/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"
        let mcpPath = tmpHome + "/.claude.json"
        let settingsPath = claudeDir + "/settings.json"
        defer { try? FileManager.default.removeItem(atPath: tmpHome) }

        try FileManager.default.createDirectory(
            atPath: claudeDir, withIntermediateDirectories: true
        )

        // Simulate what setupClaudeCode does (using the helpers directly)
        // Write hook script
        try FileManager.default.createDirectory(
            atPath: hooksDir, withIntermediateDirectories: true
        )
        let script = AgentSetup.claudeCodeGuardScript(severity: "high")
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: hookPath
        )

        // WO-500: Claude MCP and hooks live in distinct config files.
        var mcpJSON = try AgentSetup.readJSONForMerge(at: mcpPath)
        AgentSetup.mergeMCPServer(into: &mcpJSON, severity: "high")
        try AgentSetup.writeJSON(mcpJSON, to: mcpPath)

        var settingsJSON = try AgentSetup.readJSONForMerge(at: settingsPath)
        AgentSetup.mergeClaudeCodeHooks(into: &settingsJSON, hookPath: hookPath)
        try AgentSetup.writeJSON(settingsJSON, to: settingsPath)

        // Verify hook script exists and is executable
        XCTAssertTrue(FileManager.default.fileExists(atPath: hookPath))
        let attrs = try FileManager.default.attributesOfItem(atPath: hookPath)
        let perms = attrs[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o755)

        // Verify hook script content
        let hookContent = try String(contentsOfFile: hookPath, encoding: .utf8)
        XCTAssertTrue(hookContent.hasPrefix("#!/bin/bash"))
        XCTAssertTrue(hookContent.contains("PW_SEVERITY"))

        // Verify MCP and hooks remain separated.
        let mcpConfig = AgentSetup.readJSON(at: mcpPath)
        let mcpServers = mcpConfig["mcpServers"] as? [String: Any]
        let pw = mcpServers?["pastewatch"] as? [String: Any]
        XCTAssertEqual(pw?["command"] as? String, "pastewatch-cli")

        let settings = AgentSetup.readJSON(at: settingsPath)
        XCTAssertNil(settings["mcpServers"])

        let hooks = settings["hooks"] as? [String: Any]
        let preToolUse = hooks?["PreToolUse"] as? [[String: Any]]
        XCTAssertEqual(preToolUse?.count, 1)
        XCTAssertEqual(preToolUse?.first?["matcher"] as? String, "Read|Write|Edit")
    }

    func testClaudeCodeSetupIdempotent() throws {
        let tmpHome = NSTemporaryDirectory() + "pw-setup-idem-\(UUID().uuidString)"
        let claudeDir = tmpHome + "/.claude"
        let hooksDir = claudeDir + "/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"
        let mcpPath = tmpHome + "/.claude.json"
        let settingsPath = claudeDir + "/settings.json"
        defer { try? FileManager.default.removeItem(atPath: tmpHome) }

        // Run setup twice
        for _ in 0..<2 {
            try FileManager.default.createDirectory(
                atPath: hooksDir, withIntermediateDirectories: true
            )
            let script = AgentSetup.claudeCodeGuardScript(severity: "high")
            try script.write(toFile: hookPath, atomically: true, encoding: .utf8)

            var mcpJSON = try AgentSetup.readJSONForMerge(at: mcpPath)
            AgentSetup.mergeMCPServer(into: &mcpJSON, severity: "high")
            try AgentSetup.writeJSON(mcpJSON, to: mcpPath)

            var settingsJSON = try AgentSetup.readJSONForMerge(at: settingsPath)
            AgentSetup.mergeClaudeCodeHooks(into: &settingsJSON, hookPath: hookPath)
            try AgentSetup.writeJSON(settingsJSON, to: settingsPath)
        }

        // Verify no duplicates
        let settings = AgentSetup.readJSON(at: settingsPath)
        let hooks = settings["hooks"] as? [String: Any]
        let preToolUse = hooks?["PreToolUse"] as? [[String: Any]]
        XCTAssertEqual(preToolUse?.count, 1, "Should have exactly 1 PreToolUse entry, not duplicates")

        XCTAssertNil(settings["mcpServers"])
        let mcpConfig = AgentSetup.readJSON(at: mcpPath)
        let mcpServers = mcpConfig["mcpServers"] as? [String: Any]
        XCTAssertEqual(mcpServers?.count, 1, "Should have exactly 1 MCP server entry")
    }

    // MARK: - CLAUDE.md Snippet Tests

    func testInjectSnippetCreatesNewFile() throws {
        let tmpDir = NSTemporaryDirectory() + "pw-snippet-\(UUID().uuidString)"
        let claudeMdPath = tmpDir + "/CLAUDE.md"
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let (_, action) = try AgentSetup.injectClaudeSnippet(at: claudeMdPath)
        XCTAssertEqual(action, "created")

        let content = try String(contentsOfFile: claudeMdPath, encoding: .utf8)
        XCTAssertTrue(content.contains("## Pastewatch — Secret Redaction"))
        XCTAssertTrue(content.contains("pastewatch_read_file"))
        XCTAssertTrue(content.contains("__PW_CREDENTIAL_1__"))
    }

    func testInjectSnippetAppendsToExisting() throws {
        let tmpDir = NSTemporaryDirectory() + "pw-snippet-\(UUID().uuidString)"
        let claudeMdPath = tmpDir + "/CLAUDE.md"
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        try FileManager.default.createDirectory(
            atPath: tmpDir, withIntermediateDirectories: true
        )
        try "# My Project\n\nExisting content here.\n".write(
            toFile: claudeMdPath, atomically: true, encoding: .utf8
        )

        let (_, action) = try AgentSetup.injectClaudeSnippet(at: claudeMdPath)
        XCTAssertEqual(action, "appended")

        let content = try String(contentsOfFile: claudeMdPath, encoding: .utf8)
        XCTAssertTrue(content.contains("# My Project"))
        XCTAssertTrue(content.contains("Existing content here."))
        XCTAssertTrue(content.contains("## Pastewatch — Secret Redaction"))
    }

    func testInjectSnippetUpdatesExisting() throws {
        let tmpDir = NSTemporaryDirectory() + "pw-snippet-\(UUID().uuidString)"
        let claudeMdPath = tmpDir + "/CLAUDE.md"
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        try FileManager.default.createDirectory(
            atPath: tmpDir, withIntermediateDirectories: true
        )
        // File with old version of snippet
        let existing = """
        # My Project

        ## Pastewatch — Secret Redaction

        Old snippet content that should be replaced.

        ### Old subsection

        More old content.

        ## Other Section

        Keep this.
        """
        try existing.write(toFile: claudeMdPath, atomically: true, encoding: .utf8)

        let (_, action) = try AgentSetup.injectClaudeSnippet(at: claudeMdPath)
        XCTAssertEqual(action, "updated")

        let content = try String(contentsOfFile: claudeMdPath, encoding: .utf8)
        // Old content replaced
        XCTAssertFalse(content.contains("Old snippet content"))
        XCTAssertFalse(content.contains("Old subsection"))
        // New snippet present
        XCTAssertTrue(content.contains("pastewatch_read_file"))
        // Other section preserved
        XCTAssertTrue(content.contains("## Other Section"))
        XCTAssertTrue(content.contains("Keep this."))
        // Header preserved
        XCTAssertTrue(content.contains("# My Project"))
    }

    func testInjectSnippetIdempotent() throws {
        let tmpDir = NSTemporaryDirectory() + "pw-snippet-\(UUID().uuidString)"
        let claudeMdPath = tmpDir + "/CLAUDE.md"
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        // First injection
        try AgentSetup.injectClaudeSnippet(at: claudeMdPath)
        let firstContent = try String(contentsOfFile: claudeMdPath, encoding: .utf8)

        // Second injection
        let (_, action) = try AgentSetup.injectClaudeSnippet(at: claudeMdPath)
        XCTAssertEqual(action, "updated")

        let secondContent = try String(contentsOfFile: claudeMdPath, encoding: .utf8)

        // Content should be equivalent (snippet replaced with same snippet)
        XCTAssertTrue(secondContent.contains("## Pastewatch — Secret Redaction"))
        // Should only contain one instance of the sentinel
        let occurrences = secondContent.components(separatedBy: "## Pastewatch — Secret Redaction").count - 1
        XCTAssertEqual(occurrences, 1)
    }

    func testInjectSnippetAtEndOfFile() throws {
        let tmpDir = NSTemporaryDirectory() + "pw-snippet-\(UUID().uuidString)"
        let claudeMdPath = tmpDir + "/CLAUDE.md"
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        try FileManager.default.createDirectory(
            atPath: tmpDir, withIntermediateDirectories: true
        )
        // File with snippet at the very end (no following ## section)
        let existing = """
        # My Project

        ## Pastewatch — Secret Redaction

        Old content at end of file.
        """
        try existing.write(toFile: claudeMdPath, atomically: true, encoding: .utf8)

        let (_, action) = try AgentSetup.injectClaudeSnippet(at: claudeMdPath)
        XCTAssertEqual(action, "updated")

        let content = try String(contentsOfFile: claudeMdPath, encoding: .utf8)
        XCTAssertFalse(content.contains("Old content at end"))
        XCTAssertTrue(content.contains("pastewatch_read_file"))
    }

    func testSnippetContainsRequiredContent() {
        let snippet = AgentSetup.claudeSnippet
        XCTAssertTrue(snippet.contains("pastewatch_read_file"))
        XCTAssertTrue(snippet.contains("pastewatch_write_file"))
        XCTAssertTrue(snippet.contains("__PW_CREDENTIAL_1__"))
        XCTAssertTrue(snippet.contains("__PW_"))
        XCTAssertTrue(snippet.contains("Round-trip workflow"))
        XCTAssertTrue(snippet.contains("NEVER"))
    }

    func testCursorSetupMergesConfig() throws {
        let tmpHome = NSTemporaryDirectory() + "pw-setup-cursor-\(UUID().uuidString)"
        let cursorDir = tmpHome + "/.cursor"
        let mcpPath = cursorDir + "/mcp.json"
        defer { try? FileManager.default.removeItem(atPath: tmpHome) }

        // Pre-existing cursor config with another MCP server
        try FileManager.default.createDirectory(
            atPath: cursorDir, withIntermediateDirectories: true
        )
        let existing: [String: Any] = [
            "mcpServers": [
                "other": ["command": "other-cli"] as [String: Any],
            ] as [String: Any],
        ]
        try AgentSetup.writeJSON(existing, to: mcpPath)

        // Merge pastewatch
        var json = AgentSetup.readJSON(at: mcpPath)
        AgentSetup.mergeMCPServer(into: &json, severity: "medium")
        try AgentSetup.writeJSON(json, to: mcpPath)

        // Verify both servers present
        let result = AgentSetup.readJSON(at: mcpPath)
        let mcpServers = result["mcpServers"] as? [String: Any]
        XCTAssertEqual(mcpServers?.count, 2)
        XCTAssertNotNil(mcpServers?["other"])
        XCTAssertNotNil(mcpServers?["pastewatch"])

        // Verify severity
        let pw = mcpServers?["pastewatch"] as? [String: Any]
        let args = pw?["args"] as? [String] ?? []
        XCTAssertTrue(args.contains("--min-severity"))
        XCTAssertTrue(args.contains("medium"))
    }
}
