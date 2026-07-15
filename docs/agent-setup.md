# Agent Setup

Per-agent instructions for protecting AI coding sessions with pastewatch. For Claude Code, the recommended setup is the API proxy via `launch` — it scans Anthropic-shaped traffic including from subagents and tools that bypass hooks and MCP. Other agents should use their supported hooks, MCP tools, and instructions.

**Install first:**
```bash
brew install ppiankov/tap/pastewatch
```

---

## Recommended: API Proxy via Launch

The proxy sits between Claude Code and the Anthropic API, scanning and redacting Anthropic-shaped requests:

```bash
# One command — starts proxy, launches agent, cleans up on exit
pastewatch-cli launch claude

# With corporate proxy
pastewatch-cli launch --forward-proxy http://proxy.corp:8080 -- claude
```

For persistent setup, add a shell alias:

```bash
# .zshrc / .bashrc
alias claude='pastewatch-cli launch claude'
```

The proxy is Layer 0 for Claude Code — it catches Anthropic-shaped requests that bypass hooks, MCP tools, and agent instructions. Use the MCP tools and hooks below as defense in depth, and for agents not routed through the proxy where those integrations are available.

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

## Continue (VS Code / JetBrains)

MCP config: `~/.continue/mcpServers/pastewatch.yaml`
Hooks config: `~/.continue/settings.json`

Continue uses Claude Code-compatible PreToolUse hooks (exit 2 blocks).

```yaml
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
```

Or auto-setup (configures MCP + hooks):

```bash
pastewatch-cli setup continue
```

---

## Amazon Q Developer

MCP config: `~/.aws/amazonq/mcp.json`

Amazon Q supports preToolUse hooks with exit code 2 blocking, matching the Claude Code protocol.

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
pastewatch-cli setup amazon-q
```

---

## GitHub Copilot

CLI config: `~/.copilot/mcp-config.json`
Hooks config: `.github/hooks/pastewatch.json` (per repo)

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

Hook registration (`.github/hooks/pastewatch.json`):

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "~/.copilot/hooks/pastewatch-guard.sh"
      }
    ]
  }
}
```

Or auto-setup (configures MCP + hook script):

```bash
pastewatch-cli setup copilot
```

---

## Gemini Code Assist

Config: `~/.gemini/settings.json`

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

Or auto-setup:

```bash
pastewatch-cli setup gemini
```

Note: Gemini has no hook support — enforcement is advisory. Enable Agent mode for MCP tools. Gemini-shaped API traffic is not supported by the proxy.

---

## Aider

Aider CLI has no native MCP or hook support. Pastewatch does not currently provide an automatic local protection layer for Aider; the proxy accepts Anthropic-shaped traffic only and `launch` wires only Claude Code.

Upstream: [aider-ai/aider#4506](https://github.com/aider-ai/aider/issues/4506) (MCP support requested)

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

Auto-setup (hooks only — writes `~/.codex/hooks.json` and guard script):

```bash
pastewatch-cli setup codex
```

Hook config written to `~/.codex/hooks.json`:

```json
{
  "PreToolUse": [
    {
      "matcher": "Read|Write|Edit|apply_patch|Bash",
      "hooks": [{"type": "command", "command": "~/.codex/hooks/pastewatch-guard.sh"}]
    }
  ]
}
```

MCP config (manual — add to `~/.codex/config.toml`):

```toml
[mcp_servers.pastewatch]
command = "pastewatch-cli"
args = ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
enabled = true
```

Toggle hooks: set `enabled = false` in config.toml; set `PW_GUARD=0` in shell to bypass for a session.

---

## Qwen Code

Auto-setup (writes `~/.qwen/settings.json` with MCP + PreToolUse hooks):

```bash
pastewatch-cli setup qwen-code
```

Config written to `~/.qwen/settings.json`:

```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log"]
    }
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Write|Edit|Bash",
        "hooks": [{"type": "command", "command": "~/.qwen/hooks/pastewatch-guard.sh"}]
      }
    ]
  }
}
```

Toggle: remove `mcpServers.pastewatch` or `hooks.PreToolUse` entry and restart.

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
| Continue | Structural | Structural | PreToolUse hooks (Claude Code-compatible) |
| Amazon Q | Structural | Structural | preToolUse hooks |
| Copilot | Structural | Structural | preToolUse hooks (`.github/hooks/`) |
| Codex CLI | Structural | Structural | PreToolUse hooks (exit 2) |
| Qwen Code | Structural | Structural | PreToolUse hooks (exit 2) |
| OpenCode | Advisory | Advisory | MCP only (hook PR closed without merge) |
| Goose | Advisory | Advisory | MCP only (no hook support) |
| Kilo Code | Advisory | Advisory | MCP only ([hooks declined](https://github.com/Kilo-Org/kilocode/issues/7859)) |
| Aider | Not covered | Not covered | No automatic local layer ([no MCP yet](https://github.com/aider-ai/aider/issues/4506)) |
| Gemini | Advisory | Advisory | MCP only (no hook support) |
