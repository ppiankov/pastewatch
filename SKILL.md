---
name: pastewatch
description: "Sensitive data scanner — deterministic detection and obfuscation for text content"
user-invocable: false
metadata: {"requires":{"bins":["pastewatch-cli"]}}
---

# pastewatch-cli

Sensitive data scanner. Deterministic regex-based detection and obfuscation for text content. No ML, no network calls.

## Install

```bash
brew install ppiankov/tap/pastewatch
```

## Commands

### pastewatch-cli scan

Scan text for sensitive data patterns. Reports findings or outputs obfuscated text.

**Flags:**
- `--format json` — output as JSON (default: text). Also supports `sarif` for OASIS SARIF 2.1.0
- `--file path` — file to scan (reads from stdin if omitted)
- `--dir path` — directory to scan recursively (mutually exclusive with --file)
- `--check` — check mode: exit code only, no output modification
- `--allowlist path` — path to allowlist file (one value per line, # comments)
- `--rules path` — path to custom rules JSON file
- `--baseline path` — path to baseline file (only report new findings)

**JSON output:**
```json
{
  "count": 2,
  "findings": [
    {"type": "Email", "value": "admin@internal.corp.net"},
    {"type": "AWS Key", "value": "AKIA****************"}
  ],
  "obfuscated": "contact ****@**** about key ****"
}
```

In check mode (`--check`), the `obfuscated` field is null.

**Exit codes:**
- 0: clean — no sensitive data found
- 1: internal error
- 2: invalid arguments (file not found, conflicting flags)
- 6: findings detected

### pastewatch-cli version

Print version information.

**Flags:**
No flags.

**Exit codes:**
- 0: success

### pastewatch-cli init

Generate project configuration files (`.pastewatch.json` and `.pastewatch-allow`).

**Flags:**
- `--force` — overwrite existing files

**Exit codes:**
- 0: success
- 2: files already exist (without --force)

### pastewatch-cli baseline create

Create a baseline of known findings from a directory scan.

**Flags:**
- `--dir path` — directory to scan (required)
- `--output path` / `-o path` — output file path (default: `.pastewatch-baseline.json`)

**Exit codes:**
- 0: success
- 2: directory not found

### pastewatch-cli hook install

Install a pre-commit hook that scans staged changes.

**Flags:**
- `--append` — append to existing hook instead of failing

**Exit codes:**
- 0: success
- 2: hook already exists, or not a git repository

### pastewatch-cli hook uninstall

Remove pastewatch section from pre-commit hook.

**Exit codes:**
- 0: success
- 2: no hook found, or hook has no pastewatch section

### pastewatch-cli mcp

Run as MCP server (JSON-RPC 2.0 over stdio). macOS ARM only.

**Install:**
```bash
brew install ppiankov/tap/pastewatch
```

**MCP config (Claude Desktop, Cursor, etc.):**
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp"]
    }
  }
}
```

If installed to a non-PATH location, use the full path:
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "/opt/homebrew/bin/pastewatch-cli",
      "args": ["mcp"]
    }
  }
}
```

**Tools provided:**

#### pastewatch_scan
Scan a text string for sensitive data.

Input:
```json
{"text": "string (required) — text content to scan"}
```

Response: content array with summary text and JSON findings array. Each finding has `type`, `value`, `line`.

#### pastewatch_scan_file
Scan a single file. Supports format-aware parsing for .env, .json, .yml, .yaml, .properties, .cfg, .ini.

Input:
```json
{"path": "string (required) — absolute file path to scan"}
```

Response: same as pastewatch_scan, with `file` field on each finding.

#### pastewatch_scan_dir
Scan a directory recursively. Skips .git, node_modules, vendor, build directories. Only scans known file extensions (config, source, key files).

Input:
```json
{"path": "string (required) — absolute directory path to scan"}
```

Response: summary of files scanned and findings count, plus JSON findings array with `type`, `value`, `file`, `line`.

**Example responses:**

No findings:
```json
{"content": [{"type": "text", "text": "No sensitive data found."}]}
```

With findings:
```json
{"content": [
  {"type": "text", "text": "Found 2 finding(s)."},
  {"type": "text", "text": "[{\"line\":3,\"type\":\"Email\",\"value\":\"admin@corp.net\"},{\"line\":7,\"type\":\"Credential\",\"value\":\"db_pass=hunter2\"}]"}
]}
```

Errors are returned with `isError: true` in the result object.

## Detection types

| Type | What it matches |
|------|----------------|
| Email | Email addresses |
| Phone | International and local phone numbers (10+ digits) |
| IP | IPv4 addresses (excludes localhost, broadcast) |
| AWS Key | AKIA/ABIA/ACCA/ASIA key IDs and 40-char secret keys |
| API Key | Generic keys (sk-, pk-, api_, token_), GitHub tokens, Stripe keys |
| UUID | Standard UUID v4 format |
| DB Connection | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| SSH Key | RSA, DSA, EC, OPENSSH private key headers |
| JWT | Three-segment base64url tokens (eyJ...) |
| Card | Visa, Mastercard, Amex, Discover with Luhn validation |
| File Path | Infrastructure paths (/home, /var, /etc, /root, /usr, /tmp, /opt) |
| Hostname | Fully qualified domain names (excludes safe public hosts) |
| Credential | Key-value pairs with password, secret, token, api_key keywords |

## What this does NOT do

- Does not use ML or probabilistic scoring — deterministic regex matching only
- Does not make network calls — all detection is local, offline
- Does not modify the clipboard in CLI mode — reads input, writes output
- Does not maintain persistent state — every invocation is stateless
- Does not block or intercept — reports findings, does not prevent actions
- Does not execute or evaluate scanned content

## Parsing examples

```bash
# Check if text is clean
echo "hello world" | pastewatch-cli scan --check && echo "clean" || echo "found sensitive data"

# Get finding count
pastewatch-cli scan --file config.yml --format json | jq '.count'

# List finding types
pastewatch-cli scan --file .env --format json | jq -r '.findings[].type'

# Get obfuscated output
cat debug.log | pastewatch-cli scan --format json | jq -r '.obfuscated'

# Scan directory, check mode
pastewatch-cli scan --dir . --check --format json | jq '.count'
```
