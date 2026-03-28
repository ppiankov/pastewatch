# Agent Integration Examples

Ready-to-use configurations for enforcing pastewatch secret redaction with AI coding agents.

**Install first:**
```bash
brew install ppiankov/tap/pastewatch
```

---

## Quick Setup

| Agent | Hook Support | Config Files |
|-------|-------------|--------------|
| [Claude Code](#claude-code) | Structural (PreToolUse) | [settings.json](claude-code/settings.json) + [pastewatch-guard.sh](claude-code/pastewatch-guard.sh) |
| [Cline](#cline) | Structural (PreToolUse) | [mcp-config.json](cline/mcp-config.json) + [pastewatch-hook.sh](cline/pastewatch-hook.sh) |
| [Roo Code](#roo-code) | Structural (PreToolUse) | [mcp-config.json](roo-code/mcp-config.json) + [pastewatch-hook.sh](roo-code/pastewatch-hook.sh) |
| [Cursor](#cursor) | Structural (preToolUse) | [mcp.json](cursor/mcp.json) + [pastewatch-guard.sh](cursor/pastewatch-guard.sh) |

**Structural** = hooks block native file access and redirect to MCP tools. The agent cannot bypass the check.
**MCP only** = agent can use MCP tools but is not forced to. Add instructions to `.cursorrules` to request MCP usage.

---

## Claude Code

### 1. Register MCP server

```bash
claude mcp add pastewatch -- pastewatch-cli mcp --audit-log /tmp/pastewatch-audit.log
```

### 2. Install the hook

```bash
cp docs/examples/claude-code/pastewatch-guard.sh ~/.claude/hooks/pastewatch-guard.sh
chmod +x ~/.claude/hooks/pastewatch-guard.sh
```

### 3. Add hook to settings

Merge into `~/.claude/settings.json` (global) or `.claude/settings.json` (per-project):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/pastewatch-guard.sh"
          }
        ]
      }
    ]
  }
}
```

See [claude-code/settings.json](claude-code/settings.json) for the complete example with MCP registration included.

### How it works

1. Claude tries native Read/Write/Edit on a file with secrets
2. Hook scans the file, finds secrets at or above the severity threshold
3. Hook blocks (exit 2) with a message: "You MUST use pastewatch_read_file instead"
4. Claude automatically retries with the MCP tool - secrets are redacted

---

## Cline

### 1. Register MCP server

Add to Cline MCP settings (`~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`):

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

See [cline/mcp-config.json](cline/mcp-config.json).

### 2. Install the hook

Copy [cline/pastewatch-hook.sh](cline/pastewatch-hook.sh) to your Cline hooks directory and make executable.

The hook handles both bash commands (`execute_command` via `pastewatch-cli guard`) and file operations (`read_file`/`write_to_file`/`edit_file` via file scanning).

### 3. Reduce approval noise

With hooks enabled, each file with secrets triggers two steps: hook blocks native read, then Cline falls back to the MCP tool. To reduce manual approvals:

- **Auto-approve MCP tools**: In Cline settings, auto-approve `pastewatch_read_file` and `pastewatch_write_file`. These are safety tools (not destructive) - auto-approving them means reads go through redaction automatically without confirmation.
- **Auto-approve read-only tools**: If your Cline version supports it, enable auto-approve for MCP read operations to cut approvals in half.

The hook block itself shows as a notification - Cline should automatically retry with the MCP tool without asking for approval on the block.

---

## Roo Code

Roo Code is a Cline fork — same MCP config format and hook protocol.

### 1. Register MCP server

Add to Roo Code MCP settings (`~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json`):

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

See [roo-code/mcp-config.json](roo-code/mcp-config.json).

### 2. Install the hook

Copy [roo-code/pastewatch-hook.sh](roo-code/pastewatch-hook.sh) to your hooks directory and make executable. Same protocol as Cline — register as a PreToolUse hook in Roo Code settings.

### Or auto-setup

```bash
pastewatch-cli setup roo-code
```

---

## Cursor

### 1. Register MCP server

Add to `~/.cursor/mcp.json`:

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

See [cursor/mcp.json](cursor/mcp.json).

### 2. Install the hook

Copy [cursor/pastewatch-guard.sh](cursor/pastewatch-guard.sh) to `~/.cursor/hooks/` and make executable. Then add to `~/.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "matcher": "Read|Write",
        "command": "~/.cursor/hooks/pastewatch-guard.sh"
      }
    ]
  }
}
```

### Or auto-setup

```bash
pastewatch-cli setup cursor
```

---

## Severity Alignment

**This is the most common setup mistake.** Two settings must match:

| Setting | Where | Controls |
|---------|-------|----------|
| Hook `--fail-on-severity` | `pastewatch-guard.sh` / `pastewatch-hook.sh` | Which files trigger a native Read/Write block |
| MCP `--min-severity` | MCP server args in agent config | Which findings get redacted in `pastewatch_read_file` |

If they don't match, secrets leak:

### Misaligned (broken)

Hook blocks at `medium`, but MCP redacts at `high` (default):

```
Hook: --fail-on-severity medium  →  blocks native read (IP is medium)
MCP:  --min-severity high        →  pastewatch_read_file passes IP through (not high enough)

Result: IP address "172.16.161.206" leaks to the API via MCP read
```

### Aligned (correct)

Both at the same severity:

```
Hook: --fail-on-severity medium  →  blocks native read
MCP:  --min-severity medium      →  pastewatch_read_file redacts IP as __PW_IP_1__

Result: IP never leaves your machine
```

### How to set severity

**Default (`high`)** - protects credentials, API keys, emails, phones. IPs and hostnames pass through. Good for most workflows.

**Medium** - also protects IPs, hostnames, file paths. Use when infrastructure identifiers are sensitive.

For hooks, set the `PW_SEVERITY` environment variable or edit the script directly:
```bash
export PW_SEVERITY=medium  # before starting the agent
```

For MCP, add `--min-severity` to the server args:
```json
"args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log", "--min-severity", "medium"]
```

You can also set the default in `.pastewatch.json`:
```json
{
  "mcpMinSeverity": "medium"
}
```

**Precedence:** per-request `min_severity` parameter > `--min-severity` CLI flag > config `mcpMinSeverity` > default (`high`).

---

## Multi-Agent Setup

Different agents can use different severity thresholds. Each agent's MCP registration is independent:

**Claude Code** - default severity (`high`):
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

**Cline** - stricter (`medium`), also catches IPs and hostnames:
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log", "--min-severity", "medium"],
      "disabled": false
    }
  }
}
```

Remember: if Cline's MCP uses `--min-severity medium`, the Cline hook must also use `PW_SEVERITY=medium` (or `--fail-on-severity medium` in the script).

---

## What Gets Redacted

| `min_severity` | Redacted | Passes Through |
|---|---|---|
| `critical` | AWS keys, API keys, DB connections, SSH keys, JWTs, webhooks | Credentials, emails, phones, IPs, hostnames |
| `high` (default) | All critical + credentials, emails, phones | IPs, hostnames, file paths, UUIDs |
| `medium` | All high + IPs, hostnames, file paths | UUIDs, high entropy |
| `low` | Everything | Nothing |

---

## Verification

After setting up any agent, verify the integration works end-to-end:

```bash
# 1. Create a test file with a fake secret
echo 'DB_PASSWORD=SuperSecret123!' > /tmp/pastewatch-test.env

# 2. Start your agent and ask it to read the file:
#    "Read the file /tmp/pastewatch-test.env"
#
#    Expected: hook blocks native read, agent falls back to pastewatch_read_file,
#    you see __PW_CREDENTIAL_1__ instead of the password.

# 3. Check the audit log
cat /tmp/pastewatch-audit.log
# Should show: READ /tmp/pastewatch-test.env redacted=1 [Credential]

# 4. Ask the agent to write the file back:
#    "Write the contents back to /tmp/pastewatch-test-copy.env"
#
#    Expected: agent uses pastewatch_write_file, placeholders resolve to real values.

# 5. Verify real values were restored
cat /tmp/pastewatch-test-copy.env
# Should contain: DB_PASSWORD=SuperSecret123!

# 6. Clean up
rm /tmp/pastewatch-test.env /tmp/pastewatch-test-copy.env
```

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Hook doesn't block | PW_GUARD=0 is set | `unset PW_GUARD` |
| Hook doesn't block | MCP not running | Restart agent, check MCP tools panel |
| MCP reads but doesn't redact | Severity too high for finding type | Lower `--min-severity` to match |
| IPs/hostnames leak through MCP | Severity misalignment | Set both hook and MCP to same level |
| "command not found" | pastewatch-cli not on PATH | `brew install ppiankov/tap/pastewatch` |
| Cline asks for too many approvals | MCP tools not auto-approved | Auto-approve pastewatch MCP tools in Cline settings |
