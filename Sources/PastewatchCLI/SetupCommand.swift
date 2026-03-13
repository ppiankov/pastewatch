import ArgumentParser
import Foundation
import PastewatchCore

struct Setup: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Configure AI agent integration (MCP server, hooks, severity)"
    )

    @Argument(help: "Agent to configure: claude-code, cline, cursor")
    var agent: String

    @Option(name: .long, help: "Severity threshold for hook blocking and MCP redaction (default: high)")
    var severity: String = "high"

    @Flag(name: .long, help: "Write to project config instead of global (claude-code only)")
    var project = false

    func validate() throws {
        let validAgents = ["claude-code", "cline", "cursor"]
        guard validAgents.contains(agent) else {
            throw ValidationError(
                "Unknown agent '\(agent)'. Valid: \(validAgents.joined(separator: ", "))"
            )
        }
        let validSeverities = ["critical", "high", "medium", "low"]
        guard validSeverities.contains(severity) else {
            throw ValidationError(
                "Invalid severity '\(severity)'. Valid: \(validSeverities.joined(separator: ", "))"
            )
        }
        if project && agent != "claude-code" {
            throw ValidationError("--project is only supported for claude-code")
        }
    }

    func run() throws {
        switch agent {
        case "claude-code":
            try setupClaudeCode()
        case "cline":
            try setupCline()
        case "cursor":
            try setupCursor()
        default:
            break
        }
    }

    // MARK: - Claude Code

    private func setupClaudeCode() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        let configDir: String
        if project {
            configDir = fm.currentDirectoryPath + "/.claude"
        } else {
            configDir = home + "/.claude"
        }
        let hooksDir = configDir + "/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"
        let settingsPath = configDir + "/settings.json"

        print("setup: claude-code\n")

        // 1. Write hook script
        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.claudeCodeGuardScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 2. Merge settings.json
        var json = AgentSetup.readJSON(at: settingsPath)
        let configExisted = fm.fileExists(atPath: settingsPath)

        AgentSetup.mergeMCPServer(into: &json, severity: severity)
        AgentSetup.mergeClaudeCodeHooks(into: &json, hookPath: hookPath)
        try AgentSetup.writeJSON(json, to: settingsPath)

        // 3. Inject CLAUDE.md snippet
        let claudeMdPath: String
        if project {
            claudeMdPath = fm.currentDirectoryPath + "/CLAUDE.md"
        } else {
            claudeMdPath = home + "/.claude/CLAUDE.md"
        }
        let (_, snippetAction) = try AgentSetup.injectClaudeSnippet(at: claudeMdPath)
        print("  claude   \(claudeMdPath) (\(snippetAction))")

        // 4. Print summary
        var mcpArgs = "pastewatch-cli mcp --audit-log /tmp/pastewatch-audit.log"
        if severity != "high" {
            mcpArgs += " --min-severity \(severity)"
        }
        print("  mcp      \(mcpArgs)")

        let configStatus = configExisted ? "updated" : "created"
        print("  config   \(settingsPath) (\(configStatus))")
        print("  severity \(severity) (hook and MCP aligned)")
        print("\ndone. restart claude code to activate.")

        runDoctor()
    }

    // MARK: - Cline

    private func setupCline() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: cline\n")

        // 1. Merge MCP config
        let mcpPath = home
            + "/Library/Application Support/Code/User/globalStorage"
            + "/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"

        var json = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)
        AgentSetup.mergeMCPServer(into: &json, severity: severity, disabled: false)
        try AgentSetup.writeJSON(json, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")

        // 2. Write hook script
        let hooksDir = home + "/.config/pastewatch/hooks"
        let hookPath = hooksDir + "/cline-hook.sh"

        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.clineHookScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 3. Summary
        print("  severity \(severity) (hook and MCP aligned)")
        print("")
        print("  next: register the hook in Cline settings as a PreToolUse hook.")
        print("  path: \(hookPath)")
        print("\ndone. restart VS Code to activate MCP server.")

        runDoctor()
    }

    // MARK: - Cursor

    private func setupCursor() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: cursor\n")

        // 1. Merge MCP config
        let mcpPath = home + "/.cursor/mcp.json"

        var json = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)
        AgentSetup.mergeMCPServer(into: &json, severity: severity)
        try AgentSetup.writeJSON(json, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")
        print("  severity \(severity)")
        print("")
        print("  note: Cursor has no structural hook enforcement.")
        print("  add to .cursorrules in your project root:")
        print("    When reading or writing files that may contain secrets,")
        print("    use pastewatch MCP tools (pastewatch_read_file, pastewatch_write_file).")
        print("\ndone. restart Cursor to activate MCP server.")

        runDoctor()
    }

    // MARK: - Post-setup checks

    /// Run `pastewatch-cli doctor` as a health check after setup.
    private func runDoctor() {
        print("\n--- health check ---\n")

        let binaryPath = ProcessInfo.processInfo.arguments.first ?? "pastewatch-cli"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        process.arguments = ["doctor"]

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            print("  (skipped: could not run doctor)")
        }

        runCanaryVerify()
    }

    /// Quick canary smoke test — generate canaries, verify all detected.
    private func runCanaryVerify() {
        print("\n--- detection smoke test ---\n")

        let manifest = CanaryGenerator.generate(prefix: "setup-verify")
        let results = CanaryGenerator.verify(manifest: manifest)
        let allPassed = results.allSatisfy { $0.detected }

        if allPassed {
            print("  canary   \(results.count)/\(results.count) detection types verified")
        } else {
            let failed = results.filter { !$0.detected }
            print("  canary   WARNING: \(failed.count) detection type(s) not working:")
            for result in failed {
                print("           - \(result.type)")
            }
        }
    }
}
