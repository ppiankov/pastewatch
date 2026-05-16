import ArgumentParser
import Foundation
import PastewatchCore

struct Setup: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Configure AI agent integration (MCP server, hooks, severity)"
    )

    @Argument(help: "Agent to configure (run without args to see list)")
    var agent: String

    @Option(name: .long, help: "Severity threshold for hook blocking and MCP redaction (default: high)")
    var severity: String = "high"

    @Flag(name: .long, help: "Write to project config instead of global (claude-code only)")
    var project = false

    func validate() throws {
        let validAgents = [
            "claude-code", "cline", "cursor", "roo-code", "windsurf",
            "goose", "kilo-code", "continue", "amazon-q", "aider",
            "copilot", "gemini", "codex", "qwen-code",
        ]
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
        case "roo-code":
            try setupRooCode()
        case "cursor":
            try setupCursor()
        case "windsurf":
            try setupWindsurf()
        case "goose":
            try setupGoose()
        case "kilo-code":
            try setupKiloCode()
        case "continue":
            try setupContinue()
        case "amazon-q":
            try setupAmazonQ()
        case "aider":
            try setupAider()
        case "copilot":
            try setupCopilot()
        case "gemini":
            try setupGemini()
        case "codex":
            try setupCodex()
        case "qwen-code":
            try setupQwenCode()
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

    // MARK: - Roo Code

    private func setupRooCode() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: roo-code\n")

        // 1. Merge MCP config
        let mcpPath = home
            + "/Library/Application Support/Code/User/globalStorage"
            + "/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"

        var json = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)
        AgentSetup.mergeMCPServer(into: &json, severity: severity, disabled: false)
        try AgentSetup.writeJSON(json, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")

        // 2. Write hook script (reuse Cline protocol — Roo Code is a Cline fork)
        let hooksDir = home + "/.config/pastewatch/hooks"
        let hookPath = hooksDir + "/roo-code-hook.sh"

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
        print("  next: register the hook in Roo Code settings as a PreToolUse hook.")
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

        var mcpJson = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)
        AgentSetup.mergeMCPServer(into: &mcpJson, severity: severity)
        try AgentSetup.writeJSON(mcpJson, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")

        // 2. Write hook script
        let hooksDir = home + "/.cursor/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"

        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.cursorGuardScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 3. Merge hooks.json
        let hooksJsonPath = home + "/.cursor/hooks.json"
        var hooksJson = AgentSetup.readJSON(at: hooksJsonPath)
        let hooksExisted = fm.fileExists(atPath: hooksJsonPath)
        AgentSetup.mergeCursorHooks(into: &hooksJson, hookPath: hookPath)
        try AgentSetup.writeJSON(hooksJson, to: hooksJsonPath)

        let hooksStatus = hooksExisted ? "updated" : "created"
        print("  hooks    \(hooksJsonPath) (\(hooksStatus))")
        print("  severity \(severity) (hook and MCP aligned)")
        print("\ndone. restart Cursor to activate.")

        runDoctor()
    }

    // MARK: - Windsurf

    private func setupWindsurf() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: windsurf\n")

        // 1. Merge MCP config
        let mcpPath = home + "/.codeium/windsurf/mcp_config.json"

        var json = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)
        AgentSetup.mergeMCPServer(into: &json, severity: severity)
        try AgentSetup.writeJSON(json, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")

        // 2. Write hook script
        let hooksDir = home + "/.codeium/windsurf/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"

        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.windsurfGuardScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 3. Merge hooks.json
        let hooksJsonPath = home + "/.codeium/windsurf/hooks.json"
        var hooksJson = AgentSetup.readJSON(at: hooksJsonPath)
        let hooksExisted = fm.fileExists(atPath: hooksJsonPath)
        AgentSetup.mergeWindsurfHooks(into: &hooksJson, hookPath: hookPath)
        try AgentSetup.writeJSON(hooksJson, to: hooksJsonPath)

        let hooksStatus = hooksExisted ? "updated" : "created"
        print("  hooks    \(hooksJsonPath) (\(hooksStatus))")
        print("  severity \(severity) (hook and MCP aligned)")
        print("\ndone. restart Windsurf to activate.")

        runDoctor()
    }

    // MARK: - Goose

    private func setupGoose() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: goose\n")

        // Goose uses YAML config — we can only set up MCP, no hooks available
        let configPath = home + "/.config/goose/config.yaml"

        print("  config   \(configPath)")
        print("")
        print("  add this to your config.yaml under 'extensions:'")
        print("")
        print("  extensions:")
        print("    pastewatch:")
        print("      cmd: pastewatch-cli")
        print("      args:")
        print("        - mcp")
        print("        - --audit-log")
        print("        - /tmp/pastewatch-audit.log")
        if severity != "high" {
            print("        - --min-severity")
            print("        - \(severity)")
        }
        print("      type: stdio")
        print("      enabled: true")
        print("")
        print("  note: Goose has no hook support — enforcement is advisory.")
        print("  use 'pastewatch-cli launch -- goose' for proxy-level protection.")
        print("")
        print("  upstream: https://github.com/block/goose/issues")

        runDoctor()
    }

    // MARK: - Kilo Code

    private func setupKiloCode() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: kilo-code\n")

        // 1. Merge MCP config
        let mcpPath = home
            + "/Library/Application Support/Code/User/globalStorage"
            + "/kilocode.Kilo-Code/settings/mcp_settings.json"

        var json = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)
        AgentSetup.mergeMCPServer(into: &json, severity: severity, disabled: false)
        try AgentSetup.writeJSON(json, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")
        print("  severity \(severity)")
        print("")
        print("  note: Kilo Code has no hook support — enforcement is advisory.")
        print("  use 'pastewatch-cli launch' for proxy-level protection.")
        print("")
        print("  upstream: https://github.com/Kilo-Org/kilocode/issues")
        print("\ndone. restart VS Code to activate MCP server.")

        runDoctor()
    }

    // MARK: - Continue

    private func setupContinue() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: continue\n")

        // 1. Write MCP config as YAML file in .continue/mcpServers/
        let mcpDir = home + "/.continue/mcpServers"
        let mcpPath = mcpDir + "/pastewatch.yaml"

        if !fm.fileExists(atPath: mcpDir) {
            try fm.createDirectory(atPath: mcpDir, withIntermediateDirectories: true)
        }

        var mcpArgs = """
        name: pastewatch
        version: 0.0.1
        schema: v1
        mcpServers:
          - name: pastewatch
            command: pastewatch-cli
            args:
              - mcp
              - --audit-log
              - /tmp/pastewatch-audit.log
        """
        if severity != "high" {
            mcpArgs += """

                  - --min-severity
                  - \(severity)
            """
        }

        try mcpArgs.write(toFile: mcpPath, atomically: true, encoding: .utf8)
        print("  mcp      \(mcpPath) (created)")

        // 2. Write hook script (reuse Claude Code protocol — Continue is compatible)
        let hooksDir = home + "/.continue/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"

        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.claudeCodeGuardScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 3. Merge hooks into settings.json
        let settingsPath = home + "/.continue/settings.json"
        var json = AgentSetup.readJSON(at: settingsPath)
        let configExisted = fm.fileExists(atPath: settingsPath)
        AgentSetup.mergeClaudeCodeHooks(into: &json, hookPath: hookPath)
        try AgentSetup.writeJSON(json, to: settingsPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  hooks    \(settingsPath) (\(configStatus))")
        print("  severity \(severity) (hook and MCP aligned)")
        print("\ndone. restart Continue to activate.")

        runDoctor()
    }

    // MARK: - Amazon Q

    private func setupAmazonQ() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: amazon-q\n")

        // 1. Merge MCP config
        let mcpPath = home + "/.aws/amazonq/mcp.json"

        var json = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)
        AgentSetup.mergeMCPServer(into: &json, severity: severity)
        try AgentSetup.writeJSON(json, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")

        // 2. Write hook script (reuse Claude Code protocol — Amazon Q is compatible)
        let hooksDir = home + "/.aws/amazonq/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"

        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.claudeCodeGuardScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 3. Print hook registration instructions
        print("  severity \(severity) (hook and MCP aligned)")
        print("")
        print("  next: add to your Amazon Q config (~/.aws/amazonq/mcp.json):")
        print("    \"hooks\": {")
        print("      \"preToolUse\": [")
        print("        { \"matcher\": \"fs_*\", \"command\": \"\(hookPath)\" }")
        print("      ]")
        print("    }")
        print("\ndone. restart Amazon Q to activate.")

        runDoctor()
    }

    // MARK: - Aider

    private func setupAider() throws {
        print("setup: aider\n")

        print("  note: Aider CLI has no native MCP or hook support.")
        print("")
        print("  use 'pastewatch-cli launch -- aider' for proxy-level protection.")
        print("  the proxy catches all outbound secrets at the network boundary.")
        print("")
        print("  upstream: https://github.com/aider-ai/aider/issues/4506 (MCP support)")

        runDoctor()
    }

    // MARK: - GitHub Copilot

    private func setupCopilot() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: copilot\n")

        // 1. Merge MCP config for CLI
        let mcpPath = home + "/.copilot/mcp-config.json"

        var json = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)

        // Copilot CLI uses "mcpServers" key like most agents
        AgentSetup.mergeMCPServer(into: &json, severity: severity)
        try AgentSetup.writeJSON(json, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")

        // 2. Write hook script (reuse Claude Code protocol — Copilot is compatible)
        let hooksDir = home + "/.copilot/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"

        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.claudeCodeGuardScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 3. Print hook registration instructions
        print("  severity \(severity) (hook and MCP aligned)")
        print("")
        print("  next: add hook config to .github/hooks/pastewatch.json in your repo:")
        print("    {")
        print("      \"version\": 1,")
        print("      \"hooks\": {")
        print("        \"preToolUse\": [{")
        print("          \"type\": \"command\",")
        print("          \"bash\": \"\(hookPath)\"")
        print("        }]")
        print("      }")
        print("    }")
        print("\ndone. restart Copilot to activate MCP server.")

        runDoctor()
    }

    // MARK: - Gemini Code Assist

    private func setupGemini() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: gemini\n")

        // 1. Merge MCP config — Gemini uses ~/.gemini/settings.json
        let mcpPath = home + "/.gemini/settings.json"

        var json = AgentSetup.readJSON(at: mcpPath)
        let configExisted = fm.fileExists(atPath: mcpPath)
        // Gemini warns: do NOT use underscores in server names
        AgentSetup.mergeMCPServer(into: &json, severity: severity)
        try AgentSetup.writeJSON(json, to: mcpPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  mcp      \(mcpPath) (\(configStatus))")
        print("  severity \(severity)")
        print("")
        print("  note: Gemini Code Assist has no hook support — enforcement is advisory.")
        print("  use 'pastewatch-cli launch' for proxy-level protection.")
        print("  enable Agent mode in Gemini for MCP tools to be available.")
        print("\ndone. restart VS Code to activate MCP server.")

        runDoctor()
    }

    // MARK: - Codex CLI

    private func setupCodex() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: codex\n")

        // 1. Write hook script
        let hooksDir = home + "/.codex/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"

        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.codexGuardScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 2. Merge hooks.json (Codex hooks config — top-level event keys)
        let hooksJsonPath = home + "/.codex/hooks.json"
        var hooksJson = AgentSetup.readJSON(at: hooksJsonPath)
        let hooksExisted = fm.fileExists(atPath: hooksJsonPath)
        AgentSetup.mergeCodexHooks(into: &hooksJson, hookPath: hookPath)
        try AgentSetup.writeJSON(hooksJson, to: hooksJsonPath)

        let hooksStatus = hooksExisted ? "updated" : "created"
        print("  hooks    \(hooksJsonPath) (\(hooksStatus))")
        print("  severity \(severity) (hook blocking threshold)")
        print("")
        print("  note: for MCP, add to ~/.codex/config.toml:")
        print("    [mcp_servers.pastewatch]")
        print("    command = \"pastewatch-cli\"")
        print("    args = [\"mcp\", \"--audit-log\", \"/tmp/pastewatch-audit.log\"]")
        print("    enabled = true")
        print("\ndone. restart Codex to activate.")

        runDoctor()
    }

    // MARK: - Qwen Code

    private func setupQwenCode() throws {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        print("setup: qwen-code\n")

        // 1. Write hook script (Qwen Code uses the same protocol as Claude Code)
        let hooksDir = home + "/.qwen/hooks"
        let hookPath = hooksDir + "/pastewatch-guard.sh"

        if !fm.fileExists(atPath: hooksDir) {
            try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
        }

        let script = AgentSetup.claudeCodeGuardScript(severity: severity)
        try script.write(toFile: hookPath, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        print("  hook     \(hookPath) (created)")

        // 2. Merge settings.json (MCP server + PreToolUse hooks)
        let settingsPath = home + "/.qwen/settings.json"
        var json = AgentSetup.readJSON(at: settingsPath)
        let configExisted = fm.fileExists(atPath: settingsPath)

        AgentSetup.mergeMCPServer(into: &json, severity: severity)
        AgentSetup.mergeQwenCodeHooks(into: &json, hookPath: hookPath)
        try AgentSetup.writeJSON(json, to: settingsPath)

        let configStatus = configExisted ? "updated" : "created"
        print("  config   \(settingsPath) (\(configStatus))")
        print("  severity \(severity) (hook and MCP aligned)")
        print("\ndone. restart Qwen Code to activate.")

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
