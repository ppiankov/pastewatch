import Foundation

// WO-500: Setup behavior is explicit so unsupported formats cannot look configured.
public enum MCPSetupMode: String, Equatable {
    case automatic
    case manual
    case unavailable
}

// WO-500: One production matrix drives setup coverage and user-facing documentation.
public struct MCPSetupDescriptor: Equatable {
    public let agent: String
    public let mode: MCPSetupMode
    public let configPath: String

    public init(agent: String, mode: MCPSetupMode, configPath: String) {
        self.agent = agent
        self.mode = mode
        self.configPath = configPath
    }
}

// WO-500: Existing config parse failures abort setup instead of erasing user state.
public enum AgentSetupError: LocalizedError {
    case invalidJSONObject(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidJSONObject(path):
            return "Agent config is not a JSON object: \(path)"
        }
    }
}

/// Reusable logic for agent auto-setup: JSON config merging, hook script generation.
public enum AgentSetup {

    // WO-500: Keep this in the same order as the setup command's accepted agents.
    public static let mcpSetupMatrix = [
        MCPSetupDescriptor(agent: "claude-code", mode: .automatic, configPath: "~/.claude.json or .mcp.json"),
        MCPSetupDescriptor(agent: "cline", mode: .automatic, configPath: "~/.cline/data/settings/cline_mcp_settings.json"),
        MCPSetupDescriptor(agent: "roo-code", mode: .automatic, configPath: "VS Code globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"),
        MCPSetupDescriptor(agent: "cursor", mode: .automatic, configPath: "~/.cursor/mcp.json"),
        MCPSetupDescriptor(agent: "windsurf", mode: .automatic, configPath: "~/.codeium/windsurf/mcp_config.json"),
        MCPSetupDescriptor(agent: "goose", mode: .manual, configPath: "~/.config/goose/config.yaml"),
        MCPSetupDescriptor(agent: "kilo-code", mode: .automatic, configPath: "~/.config/kilo/kilo.json"),
        MCPSetupDescriptor(agent: "continue", mode: .automatic, configPath: "~/.continue/mcpServers/pastewatch.yaml"),
        MCPSetupDescriptor(agent: "amazon-q", mode: .automatic, configPath: "~/.aws/amazonq/mcp.json"),
        MCPSetupDescriptor(agent: "aider", mode: .unavailable, configPath: "N/A"),
        MCPSetupDescriptor(agent: "copilot", mode: .automatic, configPath: "~/.copilot/mcp-config.json"),
        MCPSetupDescriptor(agent: "gemini", mode: .automatic, configPath: "~/.gemini/settings.json"),
        MCPSetupDescriptor(agent: "codex", mode: .manual, configPath: "~/.codex/config.toml"),
        MCPSetupDescriptor(agent: "qwen-code", mode: .automatic, configPath: "~/.qwen/settings.json"),
    ]

    // MARK: - JSON Helpers

    /// Read JSON from file path, returning empty dict if file doesn't exist.
    public static func readJSON(at path: String) -> [String: Any] {
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return json
    }

    // WO-500: Setup writes require a strict read so malformed files are never replaced.
    public static func readJSONForMerge(at path: String) throws -> [String: Any] {
        guard FileManager.default.fileExists(atPath: path) else { return [:] }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AgentSetupError.invalidJSONObject(path)
        }
        return json
    }

    /// Write JSON to file path, creating parent directories as needed.
    public static func writeJSON(_ json: [String: Any], to path: String) throws {
        let dir = (path as NSString).deletingLastPathComponent
        let fm = FileManager.default
        if !fm.fileExists(atPath: dir) {
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }
        let data = try JSONSerialization.data(
            withJSONObject: json,
            options: [.prettyPrinted, .sortedKeys]
        )
        try data.write(to: URL(fileURLWithPath: path))
    }

    // MARK: - Config Merge

    /// Merge pastewatch MCP server entry into JSON config.
    public static func mergeMCPServer(
        into json: inout [String: Any],
        severity: String,
        disabled: Bool? = nil
    ) {
        var mcpServers = json["mcpServers"] as? [String: Any] ?? [:]
        var args: [String] = ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
        if severity != "high" {
            args.append(contentsOf: ["--min-severity", severity])
        }
        var entry: [String: Any] = [
            "command": "pastewatch-cli",
            "args": args,
        ]
        if let disabled = disabled {
            entry["disabled"] = disabled
        }
        mcpServers["pastewatch"] = entry
        json["mcpServers"] = mcpServers
    }

    // WO-500: Kilo's current OpenCode-derived config uses an argv array under mcp.
    public static func mergeKiloMCPServer(
        into json: inout [String: Any],
        severity: String
    ) {
        var servers = json["mcp"] as? [String: Any] ?? [:]
        var command = ["pastewatch-cli", "mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
        if severity != "high" {
            command.append(contentsOf: ["--min-severity", severity])
        }
        servers["pastewatch"] = [
            "type": "local",
            "command": command,
            "enabled": true,
        ] as [String: Any]
        json["mcp"] = servers
    }

    // WO-500: Continue loads one self-contained YAML block per MCP server.
    public static func continueMCPConfig(severity: String) -> String {
        var config = """
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
            config += """

                  - --min-severity
                  - \(severity)
            """
        }
        return config
    }

    /// Merge pastewatch PreToolUse hook entry into Claude Code settings JSON.
    public static func mergeClaudeCodeHooks(into json: inout [String: Any], hookPath: String) {
        var hooks = json["hooks"] as? [String: Any] ?? [:]
        var preToolUse = hooks["PreToolUse"] as? [[String: Any]] ?? []

        let newEntry: [String: Any] = [
            "matcher": "Read|Write|Edit",
            "hooks": [
                ["type": "command", "command": hookPath] as [String: Any],
            ],
        ]

        // Find existing pastewatch entry by hook command containing "pastewatch-guard"
        if let idx = preToolUse.firstIndex(where: { entry in
            guard let innerHooks = entry["hooks"] as? [[String: Any]] else { return false }
            return innerHooks.contains {
                ($0["command"] as? String)?.contains("pastewatch-guard") == true
            }
        }) {
            preToolUse[idx] = newEntry
        } else {
            preToolUse.append(newEntry)
        }

        hooks["PreToolUse"] = preToolUse
        json["hooks"] = hooks
    }

    /// Merge pastewatch preToolUse hook entry into Cursor hooks.json.
    public static func mergeCursorHooks(into json: inout [String: Any], hookPath: String) {
        let version = json["version"] as? Int ?? 1
        var hooks = json["hooks"] as? [String: Any] ?? [:]
        var preToolUse = hooks["preToolUse"] as? [[String: Any]] ?? []

        let newEntry: [String: Any] = [
            "matcher": "Read|Write",
            "command": hookPath,
        ]

        // Find existing pastewatch entry by command containing "pastewatch-guard"
        if let idx = preToolUse.firstIndex(where: { entry in
            (entry["command"] as? String)?.contains("pastewatch-guard") == true
        }) {
            preToolUse[idx] = newEntry
        } else {
            preToolUse.append(newEntry)
        }

        hooks["preToolUse"] = preToolUse
        json["hooks"] = hooks
        json["version"] = version
    }

    /// Merge pastewatch hook entries into Windsurf hooks.json.
    /// Windsurf uses separate hook events: pre_read_code, pre_write_code, pre_run_command.
    public static func mergeWindsurfHooks(into json: inout [String: Any], hookPath: String) {
        var hooks = json["hooks"] as? [String: Any] ?? [:]

        let hookEvents = ["pre_read_code", "pre_write_code", "pre_run_command"]
        for event in hookEvents {
            var entries = hooks[event] as? [[String: Any]] ?? []

            let newEntry: [String: Any] = [
                "command": hookPath,
                "show_output": true,
            ]

            // Find existing pastewatch entry
            if let idx = entries.firstIndex(where: { entry in
                (entry["command"] as? String)?.contains("pastewatch-guard") == true
            }) {
                entries[idx] = newEntry
            } else {
                entries.append(newEntry)
            }

            hooks[event] = entries
        }

        json["hooks"] = hooks
    }

    // MARK: - CLAUDE.md Snippet

    /// The pastewatch snippet to inject into CLAUDE.md files.
    public static let claudeSnippet = """
    ## Pastewatch — Secret Redaction

    This project uses [pastewatch](https://github.com/ppiankov/pastewatch) to prevent secrets from reaching AI APIs.

    ### When hooks block you

    If a pastewatch hook blocks `Read`, `Write`, or `Edit`:
    - Use `pastewatch_read_file` MCP tool to read the file (secrets are replaced with `__PW_TYPE_N__` placeholders)
    - Use `pastewatch_write_file` MCP tool to write back (placeholders are resolved to real values locally)
    - NEVER use `cat`, `head`, `python3`, or any Bash workaround to read blocked files
    - NEVER delete or rename files to bypass the hook

    ### Round-trip workflow

    1. Read: `pastewatch_read_file` → you see `password: __PW_CREDENTIAL_1__`
    2. Edit: work with placeholders in your code changes
    3. Write: `pastewatch_write_file` → real values restored on disk

    ### Rules

    - Same secret always maps to the same placeholder within a session
    - Placeholders are in-memory only — they die when the MCP server stops
    - If you see `__PW_` prefixed values, those are redacted secrets — do not treat them as real values
    - When writing files that contain `__PW_` placeholders, always use `pastewatch_write_file` — native Write will be blocked

    ### NEVER echo or store credentials

    - NEVER run `echo $VAR`, `printenv`, or `env | grep` on env vars containing secrets
    - NEVER store plaintext passwords, tokens, or keys in memory files, context files, or documentation
    - When referencing credentials, use vault paths (`vault/secret/data/...`), env var names (`$WORKLEDGER_DSN`), or secret manager references — never the actual value
    - Use `password=` or `secret=` keywords (not `pw=`, `pass=`, `key:`) so pastewatch detection can match them
    - If a credential accidentally appears in output, IMMEDIATELY warn: "CREDENTIAL LEAKED — rotate immediately"
    - To verify a credential exists without exposing it: `echo "${VAR:0:5}"` (first 5 chars only)
    """

    /// Sentinel line used to detect existing snippet in CLAUDE.md.
    private static let snippetSentinel = "## Pastewatch — Secret Redaction"

    /// Inject the pastewatch snippet into a CLAUDE.md file.
    /// Creates the file if it doesn't exist, appends if no existing snippet, replaces if found.
    /// Returns (path, action) where action is "created", "updated", or "already present".
    @discardableResult
    public static func injectClaudeSnippet(at path: String) throws -> (String, String) {
        let fm = FileManager.default
        let dir = (path as NSString).deletingLastPathComponent
        if !dir.isEmpty && !fm.fileExists(atPath: dir) {
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }

        if fm.fileExists(atPath: path),
           let existing = try? String(contentsOfFile: path, encoding: .utf8) {
            if existing.contains(snippetSentinel) {
                // Replace existing snippet (everything from sentinel to next ## or end)
                let lines = existing.components(separatedBy: "\n")
                var result: [String] = []
                var inSnippet = false
                for line in lines {
                    if line.hasPrefix(snippetSentinel) {
                        inSnippet = true
                        continue
                    }
                    if inSnippet {
                        // Next top-level heading ends the snippet
                        if line.hasPrefix("## ") && !line.hasPrefix("### ") {
                            inSnippet = false
                            result.append(claudeSnippet)
                            result.append("")
                            result.append(line)
                        }
                        continue
                    }
                    result.append(line)
                }
                // If snippet was at end of file
                if inSnippet {
                    result.append(claudeSnippet)
                    result.append("")
                }
                let updated = result.joined(separator: "\n")
                try updated.write(toFile: path, atomically: true, encoding: .utf8)
                return (path, "updated")
            } else {
                // Append snippet
                var content = existing
                if !content.hasSuffix("\n") {
                    content += "\n"
                }
                content += "\n" + claudeSnippet + "\n"
                try content.write(toFile: path, atomically: true, encoding: .utf8)
                return (path, "appended")
            }
        } else {
            // Create new file
            let content = claudeSnippet + "\n"
            try content.write(toFile: path, atomically: true, encoding: .utf8)
            return (path, "created")
        }
    }

    // MARK: - Embedded Templates

    /// Generate Claude Code guard script with configured severity.
    public static func claudeCodeGuardScript(severity: String) -> String {
        return """
        #!/bin/bash
        # Claude Code PreToolUse hook: enforce pastewatch MCP tools for files with secrets
        #
        # Protocol: exit 0 = allow, exit 2 = block
        #   stdout = message shown to Claude
        #   stderr = notification shown to the human
        #
        # Configuration:
        #   PW_SEVERITY — severity threshold for blocking (default: "\(severity)")
        #   Must match the --min-severity flag on your MCP server registration.

        PW_SEVERITY="${PW_SEVERITY:-\(severity)}"

        # --- Session check ---
        # Only enforce if pastewatch MCP is running in THIS Claude Code session.
        # Hooks and MCP are both children of the same Claude process.
        # If MCP is not running, allow native tools (fail-open).
        _claude_pid=${PPID:-0}
        pgrep -P "$_claude_pid" -qf 'pastewatch-cli mcp' 2>/dev/null || exit 0

        input=$(cat)
        tool=$(echo "$input" | jq -r '.tool_name // empty')
        file_path=$(echo "$input" | jq -r '.tool_input.file_path // .tool_input.filePath // empty')

        # Only check Read, Write, Edit tools
        case "$tool" in
          Read|Write|Edit) ;;
          *) exit 0 ;;
        esac

        # Skip if no file path
        [ -z "$file_path" ] && exit 0

        # Skip binary/non-text files
        case "$file_path" in
          *.png|*.jpg|*.jpeg|*.gif|*.ico|*.bmp|*.webp|*.svg) exit 0 ;;
          *.woff|*.woff2|*.ttf|*.eot|*.otf) exit 0 ;;
          *.zip|*.tar|*.gz|*.bz2|*.xz|*.7z|*.rar) exit 0 ;;
          *.exe|*.dll|*.so|*.dylib|*.a|*.o|*.class|*.pyc) exit 0 ;;
          *.pdf|*.doc|*.docx|*.xls|*.xlsx) exit 0 ;;
          *.mp3|*.mp4|*.wav|*.avi|*.mov|*.mkv) exit 0 ;;
          *.sqlite|*.db) exit 0 ;;
        esac

        # Skip .git internals
        echo "$file_path" | grep -qF '/.git/' && exit 0

        # --- WRITE: Check for pastewatch placeholders in content ---
        if [ "$tool" = "Write" ]; then
          content=$(echo "$input" | jq -r '.tool_input.content // empty')
          if [ -n "$content" ] && echo "$content" | grep -qE '__PW_[A-Z][A-Z0-9_]*_[0-9]+__'; then
            echo "BLOCKED: content contains pastewatch placeholders (__PW_...__). Use pastewatch_write_file to resolve placeholders back to real values."
            echo "Blocked: pastewatch placeholders in Write" >&2
            exit 2
          fi
        fi

        # --- READ/WRITE/EDIT: Scan the file on disk for secrets ---
        # Only scan existing files (new files won't have secrets on disk)
        [ ! -f "$file_path" ] && exit 0

        # Fail-open if pastewatch-cli not installed
        command -v pastewatch-cli &>/dev/null || exit 0

        # Scan file at configured severity threshold
        pastewatch-cli scan --check --fail-on-severity "$PW_SEVERITY" --file "$file_path" >/dev/null 2>&1
        scan_exit=$?

        if [ "$scan_exit" -eq 6 ]; then
          case "$tool" in
            Read)
              echo "BLOCKED: $file_path contains secrets. You MUST use pastewatch_read_file instead. Do NOT use python3, cat, or any workaround."
              echo "Blocked: secrets in Read target — use pastewatch_read_file" >&2
              ;;
            Write)
              echo "BLOCKED: $file_path contains secrets on disk. You MUST use pastewatch_write_file instead. Do NOT delete the file or use python3 as a workaround."
              echo "Blocked: secrets in Write target — use pastewatch_write_file" >&2
              ;;
            Edit)
              echo "BLOCKED: $file_path contains secrets. You MUST use pastewatch_read_file to read, then pastewatch_write_file to write back. Do NOT use any workaround."
              echo "Blocked: secrets in Edit target — use pastewatch_read_file + pastewatch_write_file" >&2
              ;;
          esac
          exit 2
        fi

        # Clean file or scan error — allow native tool
        exit 0
        """
    }

    /// Generate Windsurf guard script with configured severity.
    /// Windsurf uses separate hook events (pre_read_code, pre_write_code, pre_run_command)
    /// and passes input as JSON via stdin. Exit 2 blocks the action.
    public static func windsurfGuardScript(severity: String) -> String {
        return """
        #!/bin/bash
        # Windsurf hook: enforce pastewatch MCP tools for files with secrets
        #
        # Registered for: pre_read_code, pre_write_code, pre_run_command
        # Protocol: exit 0 = allow, exit 2 = block
        #
        # Configuration:
        #   PW_SEVERITY — severity threshold for blocking (default: "\(severity)")

        PW_SEVERITY="${PW_SEVERITY:-\(severity)}"

        # Fail-open if pastewatch-cli not installed
        command -v pastewatch-cli &>/dev/null || exit 0

        input=$(cat)
        action=$(echo "$input" | jq -r '.agent_action_name // empty')

        case "$action" in
          pre_read_code|pre_write_code)
            file_path=$(echo "$input" | jq -r '.file_path // empty')
            [ -z "$file_path" ] && exit 0

            # Skip binary files
            case "$file_path" in
              *.png|*.jpg|*.jpeg|*.gif|*.ico|*.bmp|*.webp|*.svg) exit 0 ;;
              *.woff|*.woff2|*.ttf|*.eot|*.otf) exit 0 ;;
              *.zip|*.tar|*.gz|*.bz2|*.xz|*.7z|*.rar) exit 0 ;;
              *.exe|*.dll|*.so|*.dylib|*.a|*.o|*.class|*.pyc) exit 0 ;;
              *.pdf|*.doc|*.docx|*.xls|*.xlsx) exit 0 ;;
              *.mp3|*.mp4|*.wav|*.avi|*.mov|*.mkv) exit 0 ;;
              *.sqlite|*.db) exit 0 ;;
            esac

            # Skip .git internals
            echo "$file_path" | grep -qF '/.git/' && exit 0

            # Write: check for pastewatch placeholders
            if [ "$action" = "pre_write_code" ]; then
              content=$(echo "$input" | jq -r '.content // empty')
              if [ -n "$content" ] && echo "$content" | grep -qE '__PW_[A-Z][A-Z0-9_]*_[0-9]+__'; then
                echo "BLOCKED: content contains pastewatch placeholders. Use pastewatch_write_file MCP tool." >&2
                exit 2
              fi
            fi

            # Scan file on disk
            [ ! -f "$file_path" ] && exit 0

            pastewatch-cli scan --check --fail-on-severity "$PW_SEVERITY" --file "$file_path" >/dev/null 2>&1
            if [ $? -eq 6 ]; then
              echo "BLOCKED: $file_path contains secrets. Use pastewatch_read_file or pastewatch_write_file MCP tool instead." >&2
              exit 2
            fi
            ;;
          pre_run_command)
            command_str=$(echo "$input" | jq -r '.command // empty')
            [ -z "$command_str" ] && exit 0

            pastewatch-cli guard "$command_str" >/dev/null 2>&1
            if [ $? -ne 0 ]; then
              echo "BLOCKED: command may expose secrets. Use pastewatch MCP tools for safe file access." >&2
              exit 2
            fi
            ;;
        esac

        exit 0
        """
    }

    /// Generate Cursor guard script with configured severity.
    public static func cursorGuardScript(severity: String) -> String {
        return """
        #!/bin/bash
        # Cursor preToolUse hook: enforce pastewatch MCP tools for files with secrets
        #
        # Protocol: exit 0 = allow, exit 2 = block
        #   stdout JSON: {"permission": "allow"} or {"permission": "deny", "agent_message": "..."}
        #
        # Configuration:
        #   PW_SEVERITY — severity threshold for blocking (default: "\(severity)")
        #   Must match the --min-severity flag on your MCP server registration.

        PW_SEVERITY="${PW_SEVERITY:-\(severity)}"

        deny() {
          local msg="$1"
          printf '{"permission": "deny", "agent_message": "%s"}\\n' "$msg"
          exit 2
        }

        # Fail-open if pastewatch-cli not installed
        command -v pastewatch-cli &>/dev/null || exit 0

        input=$(cat)
        tool=$(echo "$input" | jq -r '.tool_name // empty')
        file_path=$(echo "$input" | jq -r '.tool_input.file_path // .tool_input.filePath // empty')

        # Only check Read, Write tools
        case "$tool" in
          Read|Write) ;;
          *) exit 0 ;;
        esac

        # Skip if no file path
        [ -z "$file_path" ] && exit 0

        # Skip binary/non-text files
        case "$file_path" in
          *.png|*.jpg|*.jpeg|*.gif|*.ico|*.bmp|*.webp|*.svg) exit 0 ;;
          *.woff|*.woff2|*.ttf|*.eot|*.otf) exit 0 ;;
          *.zip|*.tar|*.gz|*.bz2|*.xz|*.7z|*.rar) exit 0 ;;
          *.exe|*.dll|*.so|*.dylib|*.a|*.o|*.class|*.pyc) exit 0 ;;
          *.pdf|*.doc|*.docx|*.xls|*.xlsx) exit 0 ;;
          *.mp3|*.mp4|*.wav|*.avi|*.mov|*.mkv) exit 0 ;;
          *.sqlite|*.db) exit 0 ;;
        esac

        # Skip .git internals
        echo "$file_path" | grep -qF '/.git/' && exit 0

        # --- WRITE: Check for pastewatch placeholders in content ---
        if [ "$tool" = "Write" ]; then
          content=$(echo "$input" | jq -r '.tool_input.content // empty')
          if [ -n "$content" ] && echo "$content" | grep -qE '__PW_[A-Z][A-Z0-9_]*_[0-9]+__'; then
            deny "BLOCKED: content contains pastewatch placeholders (__PW_...__). Use pastewatch_write_file to resolve placeholders back to real values."
          fi
        fi

        # --- READ/WRITE: Scan the file on disk for secrets ---
        [ ! -f "$file_path" ] && exit 0

        pastewatch-cli scan --check --fail-on-severity "$PW_SEVERITY" --file "$file_path" >/dev/null 2>&1
        scan_exit=$?

        if [ "$scan_exit" -eq 6 ]; then
          case "$tool" in
            Read)
              deny "BLOCKED: $file_path contains secrets. You MUST use pastewatch_read_file instead. Do NOT use cat or any workaround."
              ;;
            Write)
              deny "BLOCKED: $file_path contains secrets on disk. You MUST use pastewatch_write_file instead."
              ;;
          esac
        fi

        # Clean file or scan error — allow
        exit 0
        """
    }

    /// Merge pastewatch PreToolUse hook entry into Codex CLI hooks.json.
    /// Codex hooks.json nests lifecycle events under a top-level "hooks" key.
    public static func mergeCodexHooks(into json: inout [String: Any], hookPath: String) {
        // WO-114: Codex ignores root-level events; preserve the surrounding config while nesting them.
        var hooks = json["hooks"] as? [String: Any] ?? [:]
        var preToolUse = hooks["PreToolUse"] as? [[String: Any]] ?? []

        let newEntry: [String: Any] = [
            "matcher": "Read|Write|Edit|apply_patch|Bash",
            "hooks": [
                ["type": "command", "command": hookPath] as [String: Any],
            ],
        ]

        if let idx = preToolUse.firstIndex(where: { entry in
            guard let innerHooks = entry["hooks"] as? [[String: Any]] else { return false }
            return innerHooks.contains {
                ($0["command"] as? String)?.contains("pastewatch-guard") == true
            }
        }) {
            preToolUse[idx] = newEntry
        } else {
            preToolUse.append(newEntry)
        }

        hooks["PreToolUse"] = preToolUse
        json["hooks"] = hooks
    }

    /// Merge pastewatch PreToolUse hook entry into Qwen Code settings.json.
    /// Qwen Code uses the same hooks format as Claude Code.
    public static func mergeQwenCodeHooks(into json: inout [String: Any], hookPath: String) {
        var hooks = json["hooks"] as? [String: Any] ?? [:]
        var preToolUse = hooks["PreToolUse"] as? [[String: Any]] ?? []

        let newEntry: [String: Any] = [
            "matcher": "Read|Write|Edit|Bash",
            "hooks": [
                ["type": "command", "command": hookPath] as [String: Any],
            ],
        ]

        if let idx = preToolUse.firstIndex(where: { entry in
            guard let innerHooks = entry["hooks"] as? [[String: Any]] else { return false }
            return innerHooks.contains {
                ($0["command"] as? String)?.contains("pastewatch-guard") == true
            }
        }) {
            preToolUse[idx] = newEntry
        } else {
            preToolUse.append(newEntry)
        }

        hooks["PreToolUse"] = preToolUse
        json["hooks"] = hooks
    }

    /// Generate Codex CLI guard script with configured severity.
    /// Extends the Claude Code guard to also handle apply_patch and Bash.
    public static func codexGuardScript(severity: String) -> String {
        return """
        #!/bin/bash
        # Codex CLI PreToolUse hook: enforce pastewatch MCP tools for files with secrets
        #
        # Protocol: exit 0 = allow, exit 2 = block (stdout shown to Codex)
        #
        # Configuration:
        #   PW_SEVERITY — severity threshold for blocking (default: "\(severity)")

        PW_SEVERITY="${PW_SEVERITY:-\(severity)}"

        # Fail-open if pastewatch-cli not installed
        command -v pastewatch-cli &>/dev/null || exit 0

        input=$(cat)
        tool=$(echo "$input" | jq -r '.tool_name // empty')

        # Only check file-access and shell tools
        case "$tool" in
          Read|Write|Edit|apply_patch|Bash) ;;
          *) exit 0 ;;
        esac

        # Bash: scan command for dangerous patterns
        if [ "$tool" = "Bash" ]; then
          command_str=$(echo "$input" | jq -r '.tool_input.command // empty')
          [ -z "$command_str" ] && exit 0
          pastewatch-cli guard "$command_str" >/dev/null 2>&1
          if [ $? -ne 0 ]; then
            echo "BLOCKED: command may expose secrets. Use pastewatch MCP tools for safe file access."
            exit 2
          fi
          exit 0
        fi

        # File tools: extract path (apply_patch uses .tool_input.path)
        if [ "$tool" = "apply_patch" ]; then
          file_path=$(echo "$input" | jq -r '.tool_input.path // empty')
        else
          file_path=$(echo "$input" | jq -r '.tool_input.file_path // .tool_input.filePath // empty')
        fi

        [ -z "$file_path" ] && exit 0

        # Skip binary/non-text files
        case "$file_path" in
          *.png|*.jpg|*.jpeg|*.gif|*.ico|*.bmp|*.webp|*.svg) exit 0 ;;
          *.woff|*.woff2|*.ttf|*.eot|*.otf) exit 0 ;;
          *.zip|*.tar|*.gz|*.bz2|*.xz|*.7z|*.rar) exit 0 ;;
          *.exe|*.dll|*.so|*.dylib|*.a|*.o|*.class|*.pyc) exit 0 ;;
          *.pdf|*.doc|*.docx|*.xls|*.xlsx) exit 0 ;;
          *.mp3|*.mp4|*.wav|*.avi|*.mov|*.mkv) exit 0 ;;
          *.sqlite|*.db) exit 0 ;;
        esac

        # Skip .git internals
        echo "$file_path" | grep -qF '/.git/' && exit 0

        # Write / apply_patch: check for pastewatch placeholders in content
        if [ "$tool" = "Write" ] || [ "$tool" = "apply_patch" ]; then
          content=$(echo "$input" | jq -r '.tool_input.content // .tool_input.patch // empty')
          if [ -n "$content" ] && echo "$content" | grep -qE '__PW_[A-Z][A-Z0-9_]*_[0-9]+__'; then
            echo "BLOCKED: content contains pastewatch placeholders (__PW_...__). Use pastewatch_write_file to resolve placeholders back to real values."
            exit 2
          fi
        fi

        # Scan file on disk for secrets
        [ ! -f "$file_path" ] && exit 0

        pastewatch-cli scan --check --fail-on-severity "$PW_SEVERITY" --file "$file_path" >/dev/null 2>&1
        scan_exit=$?

        if [ "$scan_exit" -eq 6 ]; then
          case "$tool" in
            Read)
              echo "BLOCKED: $file_path contains secrets. You MUST use pastewatch_read_file instead. Do NOT use any workaround."
              ;;
            Write|apply_patch)
              echo "BLOCKED: $file_path contains secrets on disk. You MUST use pastewatch_write_file instead."
              ;;
            Edit)
              echo "BLOCKED: $file_path contains secrets. You MUST use pastewatch_read_file then pastewatch_write_file."
              ;;
          esac
          exit 2
        fi

        exit 0
        """
    }

    /// Generate Cline hook script with configured severity.
    public static func clineHookScript(severity: String) -> String {
        return """
        #!/bin/bash
        # Cline PreToolUse hook: enforce pastewatch MCP tools for files with secrets
        #
        # Protocol: JSON stdout
        #   {"cancel": true, "errorMessage": "..."} = block
        #   {"cancel": false} = allow
        #   Non-zero exit without valid JSON = allow (fail-open)
        #
        # Configuration:
        #   PW_SEVERITY — severity threshold for blocking (default: "\(severity)")
        #   Must match the --min-severity flag on your MCP server registration.

        PW_SEVERITY="${PW_SEVERITY:-\(severity)}"

        block() {
          local msg="$1"
          printf '{\"cancel\": true, \"errorMessage\": \"%s\"}\\n' "$msg"
          exit 0
        }

        input=$(cat)
        tool_name=$(echo "$input" | jq -r '.preToolUse.toolName // empty')

        # --- Session check ---
        # Only enforce if pastewatch MCP is running in THIS Cline session.
        _pw_mcp_ok=false
        _cline_pid=${PPID:-0}
        if command -v pastewatch-cli &>/dev/null && pgrep -P "$_cline_pid" -qf 'pastewatch-cli mcp' 2>/dev/null; then
          _pw_mcp_ok=true
        fi

        # If MCP not available, allow everything (fail-open)
        $_pw_mcp_ok || { echo '{\"cancel\": false}'; exit 0; }

        # ====== BASH GUARD (execute_command) ======
        if [ "$tool_name" = "execute_command" ]; then
          command=$(echo "$input" | jq -r '.preToolUse.parameters.command // empty')
          [ -z "$command" ] && { echo '{\"cancel\": false}'; exit 0; }

          guard_output=$(pastewatch-cli guard "$command" 2>&1)
          if [ $? -ne 0 ]; then
            block "$guard_output"
          fi
        fi

        # ====== FILE GUARD (read_file, write_to_file, edit_file) ======
        if [ "$tool_name" = "read_file" ] || [ "$tool_name" = "write_to_file" ] || [ "$tool_name" = "edit_file" ]; then
          pw_path=$(echo "$input" | jq -r '.preToolUse.parameters.path // empty')

          if [ -n "$pw_path" ]; then
            # Skip binary files
            case "$pw_path" in
              *.png|*.jpg|*.jpeg|*.gif|*.ico|*.bmp|*.webp|*.svg|*.woff|*.woff2|*.ttf|\\
              *.zip|*.tar|*.gz|*.bz2|*.exe|*.dll|*.so|*.dylib|*.pdf|*.mp3|*.mp4|\\
              *.sqlite|*.db|*.pyc|*.o|*.a|*.class)
                ;;  # skip binary — fall through to allow
              *)
                # Check for placeholder leak in write content
                if [ "$tool_name" = "write_to_file" ]; then
                  pw_content=$(echo "$input" | jq -r '.preToolUse.parameters.content // empty')
                  # WO-124: block pastewatch's active proxy-compatible placeholder envelope.
                  if [ -n "$pw_content" ] && echo "$pw_content" | grep -qE '__PW_[A-Z][A-Z0-9_]*_[0-9]+__'; then
                    block "BLOCKED: content contains pastewatch placeholders. Use pastewatch_write_file to resolve them."
                  fi
                fi

                # Scan file on disk for secrets
                if [ -f "$pw_path" ] && command -v pastewatch-cli &>/dev/null; then
                  if ! echo "$pw_path" | grep -qF '/.git/'; then
                    pastewatch-cli scan --check --fail-on-severity "$PW_SEVERITY" --file "$pw_path" >/dev/null 2>&1
                    if [ $? -eq 6 ]; then
                      case "$tool_name" in
                        read_file) block "BLOCKED: $pw_path contains secrets. You MUST use pastewatch_read_file instead. Do NOT use any workaround." ;;
                        write_to_file) block "BLOCKED: $pw_path contains secrets. You MUST use pastewatch_write_file instead. Do NOT delete the file or use any workaround." ;;
                        edit_file) block "BLOCKED: $pw_path contains secrets. You MUST use pastewatch_read_file then pastewatch_write_file. Do NOT use any workaround." ;;
                      esac
                    fi
                  fi
                fi
                ;;
            esac
          fi
        fi

        # Allow by default
        echo '{\"cancel\": false}'
        exit 0
        """
    }
}
