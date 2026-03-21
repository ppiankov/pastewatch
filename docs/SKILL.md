---
name: pastewatch
description: "Sensitive data scanner — deterministic detection and obfuscation for text content"
user-invocable: false
metadata: {"requires":{"bins":["pastewatch-cli"]}}
---

# pastewatch-cli

Sensitive data scanner. Deterministic regex-based detection and obfuscation for text content. No ML, no network calls.

**For AI agent setup with secret redaction**, see [agent-integration.md](agent-integration.md).

## Install

```bash
brew install ppiankov/tap/pastewatch
```

## Configuration

### Config files

| File | Location | Purpose | Created By |
|------|----------|---------|------------|
| `.pastewatch.json` | Project root (`$CWD`) | Project-level config | `pastewatch-cli init` |
| `~/.config/pastewatch/config.json` | Home | User-level defaults | Manual / GUI app |
| `.pastewatch-allow` | Project root | Value allowlist (one per line, `#` comments) | `pastewatch-cli init` |
| `.pastewatchignore` | Project root | Path exclusion patterns (glob, like `.gitignore`) | Manual |
| `.pastewatch-baseline.json` | Project root | Known findings baseline (SHA256 fingerprints) | `pastewatch-cli baseline create` |

### Resolution cascade

CWD `.pastewatch.json` > `~/.config/pastewatch/config.json` > built-in defaults.

### `.pastewatch.json` schema

```json
{
  "enabled": true,
  "enabledTypes": ["Email", "AWS Key", "API Key", "Credential", "High Entropy"],
  "showNotifications": true,
  "soundEnabled": false,
  "allowedValues": ["test@example.com", "192.168.1.1"],
  "allowedPatterns": ["sk_test_.*", "EXAMPLE_.*"],
  "customRules": [
    {"name": "Internal ID", "pattern": "MYCO-[0-9]{6}", "severity": "medium"}
  ],
  "safeHosts": [".internal.company.com", "safe.dev.local"],
  "sensitiveHosts": [".local", "secrets.vault.internal.net"],
  "sensitiveIPPrefixes": ["172.16.", "10."],
  "mcpMinSeverity": "high",
  "placeholderPrefix": "REDACTED_PLACEHOLDER_"
}
```

`sensitiveHosts` supports 2-segment hostnames (e.g., `.local` catches `nas.local`) as well as 3+ segment FQDNs.

### Field reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable scanning globally |
| `enabledTypes` | string[] | All except High Entropy | Which detection types to activate (see Detection Types) |
| `showNotifications` | bool | `true` | System notifications on GUI obfuscation |
| `soundEnabled` | bool | `false` | Sound on GUI obfuscation |
| `allowedValues` | string[] | `[]` | Exact values to suppress (merged with `.pastewatch-allow` file) |
| `allowedPatterns` | string[] | `[]` | Regex patterns for value suppression (wrapped in `^(...)$`) |
| `customRules` | object[] | `[]` | Additional regex detection patterns with name, pattern, optional severity |
| `safeHosts` | string[] | `[]` | Hostnames excluded from detection. Leading dot = suffix match (`.co.com` matches `x.co.com`) |
| `sensitiveHosts` | string[] | `[]` | Hostnames always detected — overrides built-in and user safe hosts. Also catches 2-segment hosts (e.g., `.local` → `nas.local`) |
| `sensitiveIPPrefixes` | string[] | `[]` | IP prefixes always detected — overrides built-in IP exclude list (e.g., `172.16.`, `10.`) |
| `mcpMinSeverity` | string | `"high"` | Default minimum severity for MCP `pastewatch_read_file` redaction (critical, high, medium, low) |
| `placeholderPrefix` | string? | `null` | Custom prefix for MCP placeholders. When set, produces `{prefix}001` instead of `__PW_TYPE_N__` |

## Commands

### pastewatch-cli scan

Scan text for sensitive data patterns. Reports findings or outputs obfuscated text.

**Flags:**
- `--format json` — output as JSON (default: text). Also supports `sarif`, `markdown`
- `--file path` — file to scan (reads from stdin if omitted)
- `--dir path` — directory to scan recursively (mutually exclusive with --file)
- `--check` — check mode: exit code only, no output modification
- `--allowlist path` — path to allowlist file (one value per line, # comments)
- `--rules path` — path to custom rules JSON file
- `--baseline path` — path to baseline file (only report new findings)
- `--stdin-filename name` — filename hint for format-aware stdin parsing (e.g., `.env`, `config.yml`)
- `--fail-on-severity level` — minimum severity for non-zero exit (critical, high, medium, low)
- `--output path` — write report to file instead of stdout
- `--ignore pattern` — glob pattern to ignore (can be repeated)
- `--bail` — stop at first finding and exit immediately (fast gate check)
- `--git-diff` — scan git diff changes (staged by default)
- `--unstaged` — include unstaged changes (requires --git-diff)

**Flag constraints:**
- `--file` and `--dir` are mutually exclusive
- `--git-diff` is mutually exclusive with `--file` and `--dir`
- `--unstaged` requires `--git-diff`
- `--bail` is only valid with `--dir` or `--git-diff`

**JSON output:**
```json
{
  "count": 2,
  "findings": [
    {"type": "Email", "value": "admin@internal.corp.net", "severity": "high"},
    {"type": "AWS Key", "value": "AKIA****************", "severity": "critical"}
  ],
  "obfuscated": "contact ****@**** about key ****"
}
```

In check mode (`--check`), the `obfuscated` field is null.

**Exit codes:**
- 0: clean — no sensitive data found (or below fail-on-severity threshold)
- 2: error (file/directory not found, invalid arguments)
- 6: findings detected at or above severity threshold

### pastewatch-cli fix

Externalize secrets to environment variables. Scans for secrets, generates `.env` file entries, and replaces hardcoded values with language-aware env var references.

**Flags:**
- `--dir path` — directory to fix (required)
- `--dry-run` — show fix plan without applying changes
- `--min-severity level` — minimum severity to fix (default: high)
- `--env-file path` — path for generated .env file (default: `.env`)
- `--ignore pattern` — glob pattern to ignore (can be repeated)

**Language-aware replacement:**

| Language | Replacement |
|----------|-------------|
| Python (.py) | `os.environ["KEY"]` |
| JavaScript/TypeScript (.js/.ts) | `process.env.KEY` |
| Go (.go) | `os.Getenv("KEY")` |
| Ruby (.rb) | `ENV["KEY"]` |
| Swift (.swift) | `ProcessInfo.processInfo.environment["KEY"]` |
| Shell (.sh) | `${KEY}` |

**Exit codes:**
- 0: success
- 2: directory not found

### pastewatch-cli inventory

Generate a structured inventory of all detected secrets in a directory.

**Flags:**
- `--dir path` — directory to scan (required)
- `--format text|json|markdown|csv` — output format (default: text)
- `--output path` — write report to file instead of stdout
- `--compare path` — compare with previous inventory JSON file (show added/removed)
- `--allowlist path` — path to allowlist file
- `--rules path` — path to custom rules JSON file
- `--ignore pattern` — glob pattern to ignore (can be repeated)

**Exit codes:**
- 0: success
- 2: directory not found, compare file not found, invalid inventory file, or write error

### pastewatch-cli guard

Check if a shell command would access files containing secrets. Used as a PreToolUse hook for Bash tool.

**Arguments:**
- `command` — shell command to check (required)

**Flags:**
- `--fail-on-severity level` — minimum severity to block (default: high)
- `--json` — machine-readable JSON output
- `--quiet` — exit code only, no output

**Exit codes:**
- 0: command allowed (no secrets in referenced files)
- 1: command blocked (file contains secrets)

### pastewatch-cli guard-read

Check if a file contains secrets before allowing Read tool access. Used as a PreToolUse hook for Read tool.

**Arguments:**
- `file-path` — file path to check (required)

**Flags:**
- `--fail-on-severity level` — minimum severity to block (default: high)

**Exit codes:**
- 0: file allowed (clean or below threshold)
- 2: file blocked (contains secrets at or above threshold)

### pastewatch-cli guard-write

Check if a file contains secrets before allowing Write tool access. Used as a PreToolUse hook for Write/Edit tools.

**Arguments:**
- `file-path` — file path to check (required)

**Flags:**
- `--fail-on-severity level` — minimum severity to block (default: high)

**Exit codes:**
- 0: file allowed (clean or below threshold)
- 2: file blocked (contains secrets at or above threshold)

### pastewatch-cli init

Generate project configuration files (`.pastewatch.json` and `.pastewatch-allow`).

**Flags:**
- `--force` — overwrite existing files
- `--profile <name>` — configuration profile. Available: `banking`

**Profiles:**
- `banking` — JDBC URL detection, `mcpMinSeverity: medium`, RFC 1918 IP prefixes, example service account and internal URI rules. Replace `YOURBANK` in `sensitiveHosts` with your domain.

**Exit codes:**
- 0: success
- 2: files already exist (without --force), or unknown profile

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

### pastewatch-cli explain

Show detection type details with severity and examples.

**Arguments:**
- `[type-name]` — type name to explain (omit to list all). Case-insensitive.

**Exit codes:**
- 0: success
- 2: unknown type name

### pastewatch-cli config check

Validate configuration files (JSON syntax, type names, regex patterns, severity strings).

**Flags:**
- `--file path` — path to config file (uses resolved config if omitted)

**Exit codes:**
- 0: valid
- 2: validation errors

### pastewatch-cli doctor

Check installation health and show active configuration. Reports CLI version, PATH status, config resolution, hook installation, MCP server processes, and Homebrew formula version.

**Flags:**
- `--json` — output results as JSON

**Checks performed:**

| Check | What it reports |
|-------|----------------|
| cli | Version and binary path |
| path | Whether pastewatch-cli is on PATH |
| config | Which config file is active (project > user > defaults), validation warnings |
| hook | Pre-commit hook installation status |
| allowlist | `.pastewatch-allow` file presence |
| ignore | `.pastewatchignore` file presence |
| baseline | `.pastewatch-baseline.json` file presence |
| mcp | Running MCP server processes and PIDs |
| homebrew | Formula version vs installed version vs current CLI version |

**Exit codes:**
- 0: success

### pastewatch-cli version

Print version information.

**Exit codes:**
- 0: success

### pastewatch-cli mcp

Run as MCP server (JSON-RPC 2.0 over stdio).

**Flags:**
- `--audit-log path` — write audit log of all tool calls to file (append mode). Logs timestamps, tool names, file paths, redaction counts — never logs secret values.
- `--min-severity level` — default minimum severity for redacted reads (critical, high, medium, low). Overrides config `mcpMinSeverity`. Per-request `min_severity` parameter still takes highest precedence.

**MCP config (Claude Desktop, Cursor, etc.):**
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

**Per-agent severity — use `--min-severity` to set different thresholds per agent:**
```json
{
  "mcpServers": {
    "pastewatch": {
      "command": "pastewatch-cli",
      "args": ["mcp", "--audit-log", "/tmp/pastewatch-audit.log", "--min-severity", "medium"]
    }
  }
}
```

**Precedence:** per-request `min_severity` > `--min-severity` flag > config `mcpMinSeverity` > default (`high`).

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
Scan a directory recursively. Skips .git, node_modules, vendor, build directories.

Input:
```json
{"path": "string (required) — absolute directory path to scan"}
```

Response: summary of files scanned and findings count, plus JSON findings array with `type`, `value`, `file`, `line`.

#### pastewatch_scan_diff
Scan git diff for secrets in changed lines only. Staged changes by default.

Input:
```json
{
  "path": "string (required) — git repository path",
  "unstaged": "boolean (optional, default: false) — include unstaged changes"
}
```

Response: findings in added lines only, with accurate file paths and line numbers.

#### pastewatch_read_file
Read a file with sensitive values replaced by `__PW_TYPE_N__` placeholders. Secrets stay local — only placeholders reach the AI. Same value always maps to same placeholder across all files in a session.

Input:
```json
{
  "path": "string (required) — absolute file path to read",
  "min_severity": "string (optional, default: high) — minimum severity to redact"
}
```

Response: JSON object with `content` (redacted text), `redactions` (manifest of type/severity/line/placeholder), `clean` (boolean).

**Severity thresholds:** `high` (default) redacts credentials, API keys, DB connections, emails, phones. IPs, hostnames, and file paths are `medium` — pass through unless `min_severity: "medium"` is set. UUIDs and high entropy are `low`.

#### pastewatch_write_file
Write file contents, resolving `__PW_TYPE_N__` placeholders back to original values locally. Pair with pastewatch_read_file for safe round-trip editing.

Input:
```json
{"path": "string (required) — file path to write", "content": "string (required) — file content with placeholders"}
```

Response: JSON object with `written`, `path`, `resolved` (count), `unresolved` (count), and `unresolvedPlaceholders` (if any).

#### pastewatch_check_output
Check if text contains raw sensitive data. Use before writing or returning code to verify no secrets leak.

Input:
```json
{"text": "string (required) — text to check"}
```

Response: JSON object with `clean` (boolean) and `findings` array (type/severity/line).

#### pastewatch_inventory
Generate a secret posture report for a directory.

Input:
```json
{
  "path": "string (required) — directory path to scan",
  "format": "string (optional, default: json) — output format: text, json, markdown, csv",
  "compare": "string (optional) — path to previous inventory JSON for delta comparison"
}
```

Response: inventory report with severity breakdown, hot spots, type groups, and entries.

**Redacted read/write workflow:**

1. Agent calls `pastewatch_read_file` → gets content with `__PW_EMAIL_1__` style placeholders
2. Agent processes code with placeholders (secrets never reach the API)
3. Agent calls `pastewatch_write_file` → MCP server resolves placeholders locally, writes real values to disk

## Detection types

| Type | What it matches | Severity |
|------|----------------|----------|
| Email | Email addresses | high |
| Phone | International and local phone numbers (10+ digits) | high |
| IP | IPv4 addresses (excludes localhost, broadcast) | medium |
| AWS Key | AKIA/ABIA/ACCA/ASIA key IDs and 40-char secret keys | critical |
| API Key | Generic keys (sk-, pk-, api_, token_), GitHub tokens, Stripe keys | critical |
| UUID | Standard UUID v4 format | low |
| DB Connection | PostgreSQL, MySQL, MongoDB, Redis, ClickHouse connection strings | critical |
| SSH Key | RSA, DSA, EC, OPENSSH private key headers | critical |
| JWT | Three-segment base64url tokens (eyJ...) | critical |
| Card | Visa, Mastercard, Amex, Discover with Luhn validation | critical |
| File Path | Infrastructure paths (/home, /var, /etc, /root, /usr, /tmp, /opt) | medium |
| Hostname | Fully qualified domain names (excludes safe public hosts) | medium |
| Credential | Key-value pairs with password, secret, token, api_key keywords | critical |
| Slack Webhook | Slack incoming webhook URLs | critical |
| Discord Webhook | Discord webhook URLs | critical |
| Azure Connection | Azure Storage connection strings with AccountKey | critical |
| GCP Service Account | GCP service account JSON key files | critical |
| OpenAI Key | OpenAI API keys (sk-proj-, sk-svcacct-) | critical |
| Anthropic Key | Anthropic API keys (sk-ant-api03-, sk-ant-admin01-, sk-ant-oat01-) | critical |
| Hugging Face Token | Hugging Face access tokens (hf_) | critical |
| Groq Key | Groq API keys (gsk_) | critical |
| npm Token | npm access tokens (npm_) | critical |
| PyPI Token | PyPI API tokens (pypi-) | critical |
| RubyGems Token | RubyGems API keys (rubygems_) | critical |
| GitLab Token | GitLab personal access tokens (glpat-) | critical |
| Telegram Bot Token | Telegram bot tokens (numeric ID + AA hash) | critical |
| SendGrid Key | SendGrid API keys (SG. prefix) | critical |
| Shopify Token | Shopify access tokens (shpat_, shpca_, shppa_) | critical |
| DigitalOcean Token | DigitalOcean tokens (dop_v1_, doo_v1_) | critical |
| Perplexity Key | Perplexity AI API keys (pplx- prefix) | critical |
| JDBC URL | JDBC connection URLs (Oracle, DB2, MySQL, PostgreSQL, SQL Server, AS/400) | critical |
| XML Credential | Credentials in XML tags (password, secret, access_key) | critical |
| XML Username | Usernames in XML tags (user, quota_key) | high |
| XML Hostname | Hostnames in XML tags (host, hostname) | medium |
| High Entropy | High-entropy strings (Shannon > 4.0, 20+ chars, mixed classes) — opt-in only | low |

SARIF maps: critical/high → `error`, medium → `warning`, low → `note`.

## Inline allowlist

Add `pastewatch:allow` anywhere on a line to suppress findings on that line:

```
API_KEY=test_12345  # pastewatch:allow
password = "dev"    // pastewatch:allow
```

## What this does NOT do

- Does not use ML or probabilistic scoring — deterministic regex matching only
- Does not make network calls — all detection is local, offline
- Does not rotate or revoke secrets — only detects and externalizes them
- Does not modify the clipboard in CLI mode — reads input, writes output
- Does not maintain persistent state — every invocation is stateless (MCP placeholder mapping is session-scoped, in-memory only)
- Does not block or intercept — reports findings, does not prevent actions (guard subcommands are for agent hooks)
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

# Fast gate check (bail at first finding)
pastewatch-cli scan --dir . --check --bail --fail-on-severity high

# Scan staged git changes
pastewatch-cli scan --git-diff --check

# Generate secret inventory
pastewatch-cli inventory --dir . --format json --output inventory.json

# Compare inventories
pastewatch-cli inventory --dir . --compare inventory.json

# Check installation health
pastewatch-cli doctor

# Get doctor output as JSON
pastewatch-cli doctor --json
```

---

This tool follows the [Agent-Native CLI Convention](https://ancc.dev). Validate with: `ancc validate .`
