# Agent Setup

Per-agent instructions for protecting AI coding sessions with pastewatch. The recommended setup is the API proxy via `launch` — it catches **all** outbound secrets including from subagents and tools that bypass hooks and MCP.

**Install first:**
```bash
brew install ppiankov/tap/pastewatch
```

---

## Recommended: API Proxy via Launch

The proxy sits between your agent and the cloud API, scanning and redacting every outbound request. This is the default way to run any agent with pastewatch:

```bash
# One command — starts proxy, launches agent, cleans up on exit
pastewatch-cli launch claude

# Any agent
pastewatch-cli launch -- codex --full-auto

# With corporate proxy
pastewatch-cli launch --forward-proxy http://proxy.corp:8080 -- claude
```

For persistent setup, add a shell alias:

```bash
# .zshrc / .bashrc
alias claude='pastewatch-cli launch claude'
```

The proxy is Layer 0 — it catches secrets that bypass hooks, MCP tools, and agent instructions. MCP and hooks below add defense in depth but the proxy is the foundation.

---

## MCP Server Registration

Register the MCP server for redacted read/write and scanning tools. Once configured, the agent has 6 tools. Secrets stay on your machine — only placeholders reach the AI provider.

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

Toggle: `/mcp` in-session or `claude mcp remove pastewatch`

---

## Claude Desktop

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

Toggle: remove the `pastewatch` key and restart.

---

## Cline (VS Code)

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

Toggle: set `"disabled": true` or use Cline UI MCP panel.

**Note:** Requires pastewatch >= 0.7.1. Earlier versions respond to JSON-RPC notifications, which Cline's validator rejects.

---

## Roo Code (VS Code)

Roo Code is a Cline fork — same MCP config format and hook protocol.

Config: `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json`

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

Or auto-setup:

```bash
pastewatch-cli setup roo-code
```

Toggle: set `"disabled": true` or use Roo Code UI MCP panel.

---

## Cursor

MCP config: `~/.cursor/mcp.json`
Hooks config: `~/.cursor/hooks.json`

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

Or auto-setup (configures MCP + hooks):

```bash
pastewatch-cli setup cursor
```

---

## Windsurf

MCP config: `~/.codeium/windsurf/mcp_config.json`
Hooks config: `~/.codeium/windsurf/hooks.json`

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

Or auto-setup (configures MCP + hooks):

```bash
pastewatch-cli setup windsurf
```

---

## Goose

Config: `~/.config/goose/config.yaml`

```yaml
extensions:
  pastewatch:
    cmd: pastewatch-cli
    args:
      - mcp
      - --audit-log
      - /tmp/pastewatch-audit.log
    type: stdio
    enabled: true
```

Or guided setup:

```bash
pastewatch-cli setup goose
```

Note: Goose has no hook support — enforcement is advisory. Use `pastewatch-cli launch -- goose` for proxy-level protection.

---

## Kilo Code (VS Code)

Config: `~/Library/Application Support/Code/User/globalStorage/kilocode.Kilo-Code/settings/mcp_settings.json`

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

Or auto-setup:

```bash
pastewatch-cli setup kilo-code
```

Note: Kilo Code has no hook support — enforcement is advisory. Use `pastewatch-cli launch` for proxy-level protection.

---

## OpenCode

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

Toggle: set `"enabled": false`

---

## Codex CLI

Config: `~/.codex/config.toml`

```toml
[mcp_servers.pastewatch]
command = "pastewatch-cli"
args = ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
enabled = true
```

Toggle: set `enabled = false`

---

## Qwen Code

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

Toggle: remove the `mcpServers.pastewatch` key.

---

## Verification

For all agents:

1. Start the agent - pastewatch should appear in the MCP/tools panel with 6 tools
2. Create a test file with a fake secret (e.g., `password=hunter2`)
3. Ask the agent to use `pastewatch_read_file` on the test file
4. Verify the secret is replaced with a `__PW_...__` placeholder
5. Check `/tmp/pastewatch-audit.log` for the read entry

## Troubleshooting

- **"command not found"**: ensure `pastewatch-cli` is on PATH (`brew install ppiankov/tap/pastewatch`)
- **JSON validation errors in Cline**: upgrade to pastewatch >= 0.7.1 (fixes JSON-RPC notification response)
- **No tools visible**: restart the agent after config change; verify config file JSON syntax
- **Audit log empty**: check the `--audit-log` path is writable; the flag is opt-in

---

## Enforcing Pastewatch via Hooks

MCP tools are opt-in - agents can still use native Read/Write and bypass redaction. To enforce pastewatch usage structurally, add hooks that block native file access when secrets are detected.

### PreToolUse hook for Read/Write/Edit

Intercepts native file tools and blocks them when the target file contains secrets at high+ severity. The agent gets a message telling it to use pastewatch MCP tools instead.

**Claude Code** (`~/.claude/settings.json`):
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Write|Edit",
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/pastewatch-guard.sh" }
        ]
      }
    ]
  }
}
```

**Cline**: add the guard logic to your `hooks/PreToolUse` script (Cline uses JSON `{"cancel": true}` protocol instead of exit codes).

Hook logic:
1. Extract file path from tool input
2. Skip binary files and `.git/` internals
3. For Write: check content for `__PW_...__` placeholders - block if found (must use `pastewatch_write_file`)
4. Run `pastewatch-cli scan --check --fail-on-severity high --file <path>`
5. Exit 6 from scan = secrets found → block with redirect message
6. Exit 0 = clean → allow native tool

### Bash command guard

Agents can also bypass pastewatch by running `cat .env` or `sed -i config.yml` via shell. The `guard` subcommand catches this:

```bash
# In your Bash PreToolUse hook:
if command -v pastewatch-cli &>/dev/null; then
  guard_output=$(pastewatch-cli guard "$command" 2>&1)
  if [ $? -ne 0 ]; then
    echo "$guard_output"
    exit 2  # block
  fi
fi
```

The `guard` subcommand extracts file paths from shell commands (`cat`, `head`, `tail`, `sed`, `grep`, etc.), scans them for secrets, and returns allow/block.

### Escape hatch

Structural guards need a bypass for legitimate cases - editing detection rules, testing patterns, or working with files that contain intentional secret-like strings.

`PW_GUARD=0` is a native feature of pastewatch-cli. When set, `guard` and `scan --check` exit 0 immediately - every hook that calls pastewatch-cli gets the bypass for free, no per-hook logic needed.

```bash
export PW_GUARD=0    # disable for current shell session
unset PW_GUARD       # re-enable (or restart shell)
```

This is agent-proof by design: the guard runs in the hook's process, not the agent's shell. The agent cannot set `PW_GUARD=0` to bypass it - only the human can, before starting the agent session. The bypass requires human action outside the agent's control.

### Enforcement matrix

| Agent | Read/Write/Edit | Bash commands | Mechanism |
|-------|----------------|---------------|-----------|
| Claude Code | Structural | Structural | PreToolUse hooks |
| Cline | Structural | Structural | PreToolUse hooks |
| Roo Code | Structural | Structural | PreToolUse hooks (Cline fork) |
| Cursor | Structural | Structural | preToolUse hooks |
| Windsurf | Structural | Structural | pre_read_code/pre_write_code/pre_run_command hooks |
| OpenCode | Advisory | Advisory | Instructions only ([hook support pending](https://github.com/anomalyco/opencode/issues/12472)) |
| Goose | Advisory | Advisory | MCP only (no hook support) |
| Kilo Code | Advisory | Advisory | MCP only (no hook support) |
| Codex CLI | Advisory | Advisory | Instructions only ([hook support pending](https://github.com/openai/codex/issues/14754)) |
| Qwen Code | Advisory | Advisory | Instructions only (no hook support yet) |
