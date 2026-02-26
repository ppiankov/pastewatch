# Agent MCP Setup

Per-agent instructions for registering pastewatch MCP server. Once configured, the agent has 6 tools for scanning, redacted read/write, and output checking. Secrets stay on your machine — only placeholders reach the AI provider.

**Install first:**
```bash
brew install ppiankov/tap/pastewatch
```

---

## Claude Code

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

## Cursor

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

1. Start the agent — pastewatch should appear in the MCP/tools panel with 6 tools
2. Create a test file with a fake secret (e.g., `password=hunter2`)
3. Ask the agent to use `pastewatch_read_file` on the test file
4. Verify the secret is replaced with a `__PW{...}__` placeholder
5. Check `/tmp/pastewatch-audit.log` for the read entry

## Troubleshooting

- **"command not found"**: ensure `pastewatch-cli` is on PATH (`brew install ppiankov/tap/pastewatch`)
- **JSON validation errors in Cline**: upgrade to pastewatch >= 0.7.1 (fixes JSON-RPC notification response)
- **No tools visible**: restart the agent after config change; verify config file JSON syntax
- **Audit log empty**: check the `--audit-log` path is writable; the flag is opt-in
