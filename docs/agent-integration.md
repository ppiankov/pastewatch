# Agent Integration Reference

Consolidated reference for integrating pastewatch with AI coding agents. Covers the API proxy, enforcement levels, hook configuration, MCP setup, and anti-workaround measures.

**Install first:**
```bash
brew install ppiankov/tap/pastewatch
```

---

## 1. API Proxy — Layer 0

The proxy is the default and recommended way to run any agent. It sits between the agent and the cloud API, scanning and redacting secrets from **all** outbound requests — including subagents, tool calls, and anything else that bypasses hooks or MCP.

```bash
# One command — starts proxy, launches agent, cleans up on exit
pastewatch-cli launch claude

# Any agent
pastewatch-cli launch -- codex --full-auto

# With corporate proxy chaining
pastewatch-cli launch --forward-proxy http://proxy.corp:8080 -- claude
```

Shell alias for zero-friction protected sessions:

```bash
alias claude='pastewatch-cli launch claude'
```

The proxy catches what hooks and MCP cannot — it is the network boundary. MCP tools and hooks below add defense in depth.

---

## 2. Enforcement Matrix

| Agent | Read/Write/Edit | Bash Commands | Enforcement | Hook Format |
|-------|----------------|---------------|-------------|-------------|
| Claude Code | Structural | Structural | PreToolUse hooks | exit 0 = allow, exit 2 = block; stdout → agent |
| Cline | Structural | Structural | PreToolUse hooks | JSON `{"cancel": true}` response |
| Roo Code | Structural | Structural | PreToolUse hooks | JSON `{"cancel": true}` response (Cline fork) |
| Cursor | Structural | Structural | preToolUse hooks | exit 2 + JSON `{"permission": "deny"}` |
| Windsurf | Structural | Structural | pre_read/write/run hooks | exit 2 blocks action |
| OpenCode | Advisory | Advisory | Instructions only | [Hook support pending](https://github.com/anomalyco/opencode/issues/12472) |
| Goose | Advisory | Advisory | MCP only | No hook support |
| Kilo Code | Advisory | Advisory | MCP only | No hook support |
| Codex CLI | Advisory | Advisory | Instructions only | [Hook support pending](https://github.com/openai/codex/issues/14754) |
| Qwen Code | Advisory | Advisory | Instructions only | No hook support yet |

**Structural** means the agent cannot bypass the check - hooks run outside the agent's control. **Advisory** means the agent is told to use pastewatch tools but is not forced.

---

## 3. MCP Setup Per Agent

All agents use the same MCP server command. Only the config file location and format differ.

### Claude Code

Register via CLI:
```bash
claude mcp add pastewatch -- pastewatch-cli mcp --audit-log /tmp/pastewatch-audit.log
```

Or add to `~/.claude/settings.json` (global) or `.claude/settings.json` (per-project):
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
    }
  }
}
```

### Claude Desktop

Config: `~/Library/Application Support/Claude/claude_desktop_config.json`
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
    }
  }
}
```

### Cline (VS Code)

Config: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"],
      "disabled": false
    }
  }
}
```

Requires pastewatch >= 0.7.1 (fixes JSON-RPC notification response).

### Cursor

Config: `~/.cursor/mcp.json`
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
    }
  }
}
```

### OpenCode

Config: `~/.config/opencode/opencode.json`
```json
{
  "mcp": {
    "pastewatch": {
      "type": "local",
      "command": ["pastewatch-cli", "mcp", "--audit-log", "/tmp/pastewatch-audit.log"],
      "enabled": true
    }
  }
}
```

### Codex CLI

Config: `~/.codex/config.toml`
```toml
[mcp_servers.pastewatch]
command = "pastewatch-cli"
args = ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
enabled = true
```

### Qwen Code

Config: `~/.qwen/settings.json`
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
    }
  }
}
```

---

## 4. Hook Configuration

Hooks make enforcement structural. Without hooks, MCP tools are opt-in and agents can bypass redaction using native Read/Write or Bash commands.

### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          { "type": "command", "command": "pastewatch-cli guard-read \"$FILE_PATH\"" }
        ]
      },
      {
        "matcher": "Write|Edit",
        "hooks": [
          { "type": "command", "command": "pastewatch-cli guard-write \"$FILE_PATH\"" }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "pastewatch-cli guard \"$COMMAND\"" }
        ]
      }
    ]
  }
}
```

**Hook protocol:**
- `guard-read` / `guard-write`: exit 0 = allow, exit 2 = block. Stdout is shown to the agent ("You MUST use pastewatch_read_file instead"). Stderr is shown to the human.
- `guard`: exit 0 = allow, exit 1 = block. Parses shell commands to extract file paths, scans those files.

### Cline

Cline uses a JSON cancel protocol instead of exit codes. The hook script must output `{"cancel": true, "message": "..."}` to block.

Add guard logic to your `hooks/PreToolUse` script that wraps pastewatch-cli and translates exit codes to JSON responses.

### Cursor

Cursor supports `preToolUse` hooks with the same exit code protocol as Claude Code (exit 0 = allow, exit 2 = block). Configure in `.cursor/hooks/pretooluse.sh`.

---

## 5. Anti-Workaround Enforcement

Agents are creative about bypassing restrictions. These measures close known bypass paths.

### Bash command guard

The `guard` subcommand parses shell commands and scans referenced files:

```bash
pastewatch-cli guard "cat .env"
# BLOCKED: .env contains 3 secret(s) (2 critical, 1 high)

pastewatch-cli guard "python3 -c 'open(\".env\").read()'"
# BLOCKED: detects python3/ruby/node scripting workarounds
```

Commands detected:
- **File readers:** `cat`, `head`, `tail`, `less`, `more`, `bat`, `tac`, `nl`
- **File writers:** `sed`, `awk`
- **File searchers:** `grep`, `egrep`, `fgrep`, `rg`, `ag`
- **Source commands:** `source`, `.`
- **Scripting interpreters:** `python3`, `python`, `ruby`, `node`, `perl`, `php`, `lua`
- **File transfer tools:** `scp`, `rsync`, `ssh`, `ssh-keygen`
- **Infrastructure tools:** `ansible-playbook`, `ansible`, `ansible-vault`, `terraform`, `docker-compose`, `docker`, `kubectl`, `helm`
- **Database CLIs:** `psql`, `mysql`, `mongosh`, `mongo`, `redis-cli`, `sqlite3` - extracts file flags and scans inline connection strings/passwords
- **Pipe chains:** `|`, `&&`, `||`, `;` - each segment is parsed independently
- **Redirect operators:** `>`, `>>`, `2>`, `&>`, `<` - stripped from commands; input redirects (`<`) scanned as file access
- **Subshells:** `$(...)` and backticks - inner commands extracted and scanned

### Read/Write/Edit guard

The `guard-read` and `guard-write` subcommands use format-aware scanning (`.env`, `.json`, `.yml` parsers) for accurate detection:

```bash
pastewatch-cli guard-read /path/to/.env
# Exit 2 + message: "You MUST use pastewatch_read_file instead of Read"

pastewatch-cli guard-write /path/to/config.yml
# Exit 2 + message: "You MUST use pastewatch_write_file instead of Write"
```

### Directive language in hook messages

Hook stdout messages use imperative language that agents follow:
- "You **MUST** use pastewatch_read_file instead of Read for files containing secrets."
- "You **MUST** use pastewatch_write_file instead of Write for files containing secrets."

### Agent instruction files

For advisory-only agents (no hooks), add explicit rules to agent config files:

```markdown
## Pastewatch - Secret Redaction - CRITICAL

When the pastewatch-guard hook blocks Read/Write/Edit, you MUST use the pastewatch MCP tool:
- Read blocked → use `pastewatch_read_file`
- Write blocked → use `pastewatch_write_file`
- Edit blocked → use `pastewatch_read_file` then `pastewatch_write_file`

NEVER work around a pastewatch block:
- NEVER use python3/ruby/perl/node to read or write files that pastewatch blocked
- NEVER use cat/head/tail/sed/awk via Bash to read files that pastewatch blocked
- NEVER delete a file to bypass the guard, then recreate it
- NEVER copy file contents through environment variables or temp files to avoid scanning
```

Add to `CLAUDE.md`, `AGENTS.md`, `.clinerules`, or equivalent per-agent instruction file.

---

## 6. PW_GUARD Escape Hatch

`PW_GUARD=0` disables all guard subcommands. When set, `guard`, `guard-read`, `guard-write`, and `scan --check` exit 0 immediately.

```bash
export PW_GUARD=0    # disable for current shell session
unset PW_GUARD       # re-enable (or restart shell)
```

**Agent-proof by design:** The guard runs in the hook's process, not the agent's shell. The agent cannot set `PW_GUARD=0` - only the human can, before starting the agent session.

**When to use:**
- Editing detection rule source files (DetectionRules.swift)
- Working with test fixtures that contain intentional secret-like patterns
- Debugging hook behavior

---

## 7. Upstream Hook Support Requests

Agents without hook support can only use advisory enforcement (instruction files). When these agents add hook support, they upgrade to structural enforcement.

| Agent | Issue | Status | Assignee |
|-------|-------|--------|----------|
| OpenCode | [anomalyco/opencode#12472](https://github.com/anomalyco/opencode/issues/12472) | Open — [PR #19519](https://github.com/anomalyco/opencode/pull/19519) submitted | thdxr |
| Qwen Code | [QwenLM/qwen-code#268](https://github.com/QwenLM/qwen-code/issues/268) | P2 | Mingholy |
| Codex CLI | [openai/codex#14754](https://github.com/openai/codex/issues/14754) | Open | - |
| Cursor | Supported | Implemented | - |
| Windsurf | Supported | Implemented | - |
| Goose | [block/goose#8184](https://github.com/block/goose/issues/8184) | Open | - |
| Kilo Code | [Kilo-Org/kilocode#7859](https://github.com/Kilo-Org/kilocode/issues/7859) | Open | - |

When hooks land for OpenCode, Qwen Code, Goose, and Kilo Code, add guard hooks following the Claude Code pattern.

---

## 8. Configuration Files

Pastewatch config resolves from the agent's working directory. When an agent runs `pastewatch-cli scan` or uses MCP tools, it picks up the project's `.pastewatch.json` automatically.

### Config files

| File | Location | Purpose | Created By |
|------|----------|---------|------------|
| `.pastewatch.json` | Project root (`$CWD`) | Project-level config | `pastewatch-cli init` |
| `~/.config/pastewatch/config.json` | Home | User-level defaults | Manual / GUI app |
| `.pastewatch-allow` | Project root | Value allowlist (one per line) | `pastewatch-cli init` |
| `.pastewatchignore` | Project root | Path exclusion patterns (glob) | Manual |
| `.pastewatch-baseline.json` | Project root | Known findings baseline | `pastewatch-cli baseline create` |

Resolution cascade: CWD `.pastewatch.json` > `~/.config/pastewatch/config.json` > built-in defaults.

### `.pastewatch.json` schema

```json
{
  "enabled": true,
  "enabledTypes": ["Email", "AWS Key", "API Key", "Credential", "High Entropy"],
  "showNotifications": true,
  "soundEnabled": false,
  "allowedValues": ["test@example.com"],
  "allowedPatterns": ["sk_test_.*", "EXAMPLE_.*"],
  "customRules": [
    {"name": "Internal ID", "pattern": "MYCO-[0-9]{6}", "severity": "medium"}
  ],
  "safeHosts": [".internal.company.com"],
  "sensitiveHosts": [".local", "secrets.vault.internal.net"],
  "sensitiveIPPrefixes": ["172.16.", "10."],
  "mcpMinSeverity": "high"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable/disable scanning globally |
| `enabledTypes` | string[] | Detection types to activate (default: all except High Entropy) |
| `allowedValues` | string[] | Exact values to suppress (merged with `.pastewatch-allow`) |
| `allowedPatterns` | string[] | Regex patterns for value suppression (wrapped in `^(...)$`) |
| `customRules` | object[] | Additional regex patterns with name, pattern, optional severity |
| `safeHosts` | string[] | Hostnames excluded from detection (leading dot = suffix match) |
| `sensitiveHosts` | string[] | Hostnames always detected (overrides safe hosts, catches 2-segment hosts like `.local`) |
| `sensitiveIPPrefixes` | string[] | IP prefixes always detected (overrides built-in exclude list) |
| `mcpMinSeverity` | string | Default severity for MCP redacted reads (default: `high`) |

For the full command reference, see [SKILL.md](SKILL.md).

---

## Verification

After configuring MCP and hooks for any agent:

1. Start the agent - pastewatch should appear in the MCP/tools panel with 6 tools
2. Create a test file with a fake secret (e.g., `password=hunter2`)
3. Ask the agent to read the test file with native Read - hook should block and redirect to `pastewatch_read_file`
4. Ask the agent to use `pastewatch_read_file` - verify the secret is replaced with a `__PW_...__` placeholder
5. Check `/tmp/pastewatch-audit.log` for the read entry

### Troubleshooting

- **"command not found"**: ensure `pastewatch-cli` is on PATH (`brew install ppiankov/tap/pastewatch`)
- **JSON validation errors in Cline**: upgrade to pastewatch >= 0.7.1
- **No tools visible**: restart the agent after config change; verify config file JSON syntax
- **Audit log empty**: check the `--audit-log` path is writable
- **Hook not blocking**: verify hook is registered for the correct tool matcher; check `PW_GUARD` is not set to `0`

---

## Available MCP Tools

Once configured, the agent has access to:

| Tool | Purpose |
|------|---------|
| `pastewatch_scan` | Scan file or directory for secrets |
| `pastewatch_read_file` | Read file with secrets replaced by `__PW_...__` placeholders |
| `pastewatch_write_file` | Write file, resolving placeholders back to real values locally |
| `pastewatch_check_output` | Verify text contains no raw secrets before returning |
| `pastewatch_scan_diff` | Scan git diff for secrets in changed lines |
| `pastewatch_inventory` | Generate secret posture report for a directory |

Secrets never leave your machine. Only placeholders reach the AI provider's API.
