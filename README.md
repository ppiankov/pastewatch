# Pastewatch
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

Detects and obfuscates sensitive data before it reaches AI systems - clipboard monitoring (macOS), CLI scanning (macOS/Linux), and MCP server for AI agent integration.

It operates **before paste**, not after submission.

If sensitive data never enters the prompt, the incident does not exist.

---

## Core Principle

**Principiis obsta** - resist the beginnings.

Pastewatch intervenes at the earliest irreversible boundary: the moment data leaves the user's control.

Once pasted into an AI system, data cannot be reliably recalled, audited, or constrained.

Pastewatch refuses that transition.

---

## Why Pastewatch

No other tool does what Pastewatch does. Here's why:

- **Before-paste boundary** - secrets never leave your machine. Nightfall, Prisma, Check Point all intercept downstream. Pastewatch prevents upstream
- **MCP server for AI agents** - no other tool provides redacted read/write at the tool level. The agent works with placeholders, your secrets stay local
- **Bash guard with deep parsing** - pipes, subshells, redirects, database CLIs, infra tools. Every shell command the agent runs is scanned before execution
- **Canary honeypots** - "prove it works" not "trust it works." Plant format-valid fake secrets and verify they're caught
- **Local-only, deterministic, no ML** - no cloud dependency, no probabilistic scoring, no telemetry. Runs offline, gives the same answer every time
- **One-command agent setup** - `pastewatch-cli setup claude-code` and you're protected. MCP server, hooks, severity alignment - all configured in one step

---

## What Pastewatch Does

- Monitors clipboard content locally
- Detects **high-confidence sensitive data**
- Obfuscates detected values **before paste**
- Operates fully offline
- Shows minimal, explicit feedback when changes occur

Nothing more.

---

## What Pastewatch Does Not Do

Pastewatch is not:

- a DLP system
- a compliance product
- a browser extension
- an LLM proxy
- a monitoring or logging tool
- an AI-powered classifier
- a policy engine

Pastewatch does not:

- block paste
- phone home
- store clipboard history
- guess or infer
- act when uncertain

False negatives are preferred over false positives.

---

## How Pastewatch Works

Pastewatch modifies clipboard text locally before it is pasted.

It scans plain text for sensitive patterns and replaces them with
non-sensitive placeholders.

Pastewatch does not hide clipboard contents from the operating system
or applications, and it does not provide a way to restore original values
after paste.

---

## Installation

### From Release (Recommended)

1. Download the latest `.dmg` from [Releases](https://github.com/ppiankov/pastewatch/releases)
2. Open the DMG and drag `Pastewatch.app` to Applications
3. Launch Pastewatch from Applications
4. Grant notification permissions when prompted

### From Source

```bash
git clone https://github.com/ppiankov/pastewatch.git
cd pastewatch
swift build -c release
./.build/release/pastewatch
```

---

## Detection Scope

Pastewatch detects only **deterministic, high-confidence patterns**:

| Type | Examples |
|------|----------|
| Email | `user@company.com` |
| Phone | `+60123456789`, `(555) 123-4567` |
| IP Address | `192.168.1.100` |
| AWS Keys | `AKIAIOSFODNN7EXAMPLE` |
| API Keys | `sk_test_...`, `ghp_...` |
| UUIDs | `550e8400-e29b-41d4-a716-446655440000` |
| JWT Tokens | `eyJhbGciOiJIUzI1NiIs...` |
| DB Connections | `postgres://...`, `clickhouse://...` |
| SSH Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| Credit Cards | `4111111111111111` (Luhn validated) |
| File Paths | `/etc/nginx/nginx.conf`, `/home/deploy/.ssh/id_rsa` |
| Hostnames | `db-primary.internal.corp.net` |
| Credentials | `password=...`, `secret: ...`, `api_key=...` |
| Slack Webhooks | `https://hooks.slack.com/services/...` |
| Discord Webhooks | `https://discord.com/api/webhooks/...` |
| Azure Connections | `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...` |
| GCP Service Accounts | `{"type": "service_account", ...}` |
| OpenAI Keys | `sk-proj-...`, `sk-svcacct-...` |
| Anthropic Keys | `sk-ant-api03-...`, `sk-ant-admin01-...` |
| Hugging Face Tokens | `hf_...` |
| Groq Keys | `gsk_...` |
| npm Tokens | `npm_...` |
| PyPI Tokens | `pypi-...` |
| RubyGems Tokens | `rubygems_...` |
| GitLab Tokens | `glpat-...` |
| Telegram Bot Tokens | `123456789:AA...` |
| SendGrid Keys | `SG....` |
| Shopify Tokens | `shpat_...`, `shpca_...` |
| DigitalOcean Tokens | `dop_v1_...`, `doo_v1_...` |
| Perplexity Keys | `pplx-...` |
| XML Credentials | `<password>`, `<secret_access_key>`, etc. in XML configs |
| XML Usernames | `<user>`, `<quota_key>` in XML configs |
| XML Hostnames | `<host>`, `<hostname>`, `<interserver_http_host>` in XML configs |
| High Entropy Strings | Opt-in Shannon entropy detection (4.0 bits/char threshold) |

Each type has a severity level (critical, high, medium, low) used in SARIF, JSON, and markdown output.

No ML. No probabilistic scoring. No confidence levels.

If detection is ambiguous, Pastewatch does nothing.

---

## Obfuscation Model

Detected values are replaced with stable placeholders **per paste**:

```
john.doe@example.com  →  <EMAIL_1>
AKIAIOSFODNN7EXAMPLE  →  <AWS_KEY_1>
192.168.1.100         →  <IP_1>
```

- Mapping exists only in memory
- Mapping is discarded immediately after paste
- No persistence
- No recovery mechanism

After paste, the system returns to rest.

---

## User Experience

- Default behavior is silent
- When obfuscation occurs, a minimal notification is shown:

  > Pastewatch: Obfuscated: Email (1), API Key (1)

No previews. No animations. No confirmations.

Silence is success.

---

## CLI Mode

Pastewatch includes a CLI tool for scanning text without the GUI:

```bash
# Scan from stdin
echo "password=hunter2" | pastewatch-cli scan

# Scan a file
pastewatch-cli scan --file config.yml

# Scan a directory recursively
pastewatch-cli scan --dir ./project --check

# SARIF output for GitHub code scanning
pastewatch-cli scan --dir . --format sarif > results.sarif

# Suppress known-safe values
pastewatch-cli scan --file app.yml --allowlist .pastewatch-allow

# Custom detection rules
pastewatch-cli scan --file data.txt --rules custom-rules.json

# Baseline: suppress known findings
pastewatch-cli baseline create --dir . --output .pastewatch-baseline.json
pastewatch-cli scan --dir . --baseline .pastewatch-baseline.json --check

# Check mode (exit code only, for CI)
git diff --cached | pastewatch-cli scan --check

# JSON output
pastewatch-cli scan --format json --check < input.txt

# Markdown output (for PR comments)
pastewatch-cli scan --dir . --format markdown --output report.md

# Only fail on critical severity findings
pastewatch-cli scan --dir . --check --fail-on-severity critical

# Write report to file
pastewatch-cli scan --dir . --format sarif --output results.sarif

# Ignore paths
pastewatch-cli scan --dir . --ignore "*.log" --ignore "fixtures/"

# Explain detection types
pastewatch-cli explain
pastewatch-cli explain email

# Validate config
pastewatch-cli config check
```

### MCP Server - Redacted Read/Write

AI coding agents send file contents to cloud APIs. If those files contain secrets, the secrets leave your machine. Pastewatch MCP solves this: **the agent works with placeholders, your secrets stay local.**

```
  Your machine (local only)              Cloud API
  ┌────────────────────────┐
  │  pastewatch MCP server │
  │                        │   __PW{AWS_KEY_1}__
  │  read: scan + redact ──┼──────────────────────► Agent sees placeholders
  │  write: resolve local ◄┼────────────────────── Agent returns placeholders
  │                        │
  │  secrets stay in RAM   │   Secrets never leave.
  └────────────────────────┘
```

**Setup** (Claude Code, Cline, Cursor - any MCP-compatible agent):

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

**Tools:**

| Tool | Purpose |
|------|---------|
| `pastewatch_read_file` | Read file with secrets replaced by `__PW{TYPE_N}__` placeholders |
| `pastewatch_write_file` | Write file, resolving placeholders back to real values locally |
| `pastewatch_check_output` | Verify text contains no raw secrets before returning |
| `pastewatch_scan` | Scan text for sensitive data |
| `pastewatch_scan_file` | Scan a file for sensitive data |
| `pastewatch_scan_dir` | Scan a directory recursively |

The server holds mappings in memory for the session. Same file re-read returns the same placeholders. Mappings die when the server stops.

**Audit logging** - verify what the MCP server did during a session:

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

Logs timestamps, tool calls, file paths, and redaction counts. Never logs secret values.

**What this protects:** API keys, DB credentials, SSH keys, tokens, emails, IPs - secrets never leave your machine. **What this doesn't protect:** prompt content, code structure, business logic - these still reach the API. Pastewatch protects your keys; for protecting your ideas, use a local model.

See [docs/agent-safety.md](docs/agent-safety.md) for the full agent safety guide with setup for Claude Code, Cline, and Cursor.

### Agent Auto-Setup

One-command agent integration - configures MCP server, hooks, and severity alignment:

```bash
pastewatch-cli setup claude-code              # global config
pastewatch-cli setup claude-code --project    # project-level config
pastewatch-cli setup cline
pastewatch-cli setup cursor
pastewatch-cli setup claude-code --severity medium  # align hook + MCP thresholds
```

Idempotent - safe to re-run. Updates existing config without duplication.

### Session Report

Generate compliance artifacts from MCP audit logs:

```bash
pastewatch-cli report --audit-log /tmp/pastewatch-audit.log
pastewatch-cli report --audit-log /tmp/pw.log --format json
pastewatch-cli report --audit-log /tmp/pw.log --format markdown --output session-report.md
pastewatch-cli report --audit-log /tmp/pw.log --since "2026-03-02T10:00:00Z"
```

Aggregates files read/written, secrets redacted, placeholders resolved, output checks, and scan findings. Verdict indicates whether any secrets leaked.

### Canary Secrets

Plant format-valid but non-functional secrets as leak detection tripwires:

```bash
pastewatch-cli canary generate                    # generate 7 canary tokens
pastewatch-cli canary generate --prefix myproject # embed identifier for tracking
pastewatch-cli canary verify                      # confirm all canaries are detected
pastewatch-cli canary check --log /tmp/trail.json # search logs for leaked canaries
```

Covers AWS Key, GitHub Token, OpenAI Key, Anthropic Key, DB Connection, Stripe Key, and generic API Key. If a canary value appears in provider logs, your prevention failed.

### Bash Command Guard

Block shell commands that would read or write files containing secrets:

```bash
pastewatch-cli guard "cat .env"
# BLOCKED: .env contains 3 secret(s) (2 critical, 1 high)

pastewatch-cli guard "echo hello"
# exit 0 (safe - no file access)

pastewatch-cli guard --json "cat config.yml"
# JSON output for programmatic integration
```

Handles pipe chains (`|`), command chaining (`&&`, `||`, `;`), redirect operators, subshell extraction (`$(...)`, backticks), scripting interpreters, file transfer tools, infrastructure tools (terraform, docker, kubectl), and database CLIs (psql, mysql, redis-cli) with inline value scanning.

Integrates with agent hooks (Claude Code, Cline) to intercept Bash tool calls before execution. See [docs/agent-setup.md](docs/agent-setup.md) for hook configuration.

### Secret Externalization (Fix)

Externalize secrets to environment variables with language-aware code patching:

```bash
pastewatch-cli fix --dir .                    # apply fixes
pastewatch-cli fix --dir . --dry-run          # preview fix plan
pastewatch-cli fix --dir . --min-severity high --env-file .env
```

Supports Python (`os.environ`), JS/TS (`process.env`), Go (`os.Getenv`), Ruby (`ENV`), Swift (`ProcessInfo`), and Shell (`${VAR}`).

### Secret Inventory

Generate structured posture reports with severity breakdown and hot spots:

```bash
pastewatch-cli inventory --dir .
pastewatch-cli inventory --dir . --format json --output inventory.json
pastewatch-cli inventory --dir . --compare previous.json  # show added/removed
```

Output formats: text, json, markdown, csv.

### Git History Scanning

Scan commit history for secrets, reporting the first commit that introduced each finding:

```bash
pastewatch-cli scan --git-log
pastewatch-cli scan --git-log --range HEAD~50..HEAD
pastewatch-cli scan --git-log --since 2025-01-01
pastewatch-cli scan --git-log --branch feature/auth --format sarif
```

Deduplicates by fingerprint - same secret across multiple commits is reported once.

### Git Diff Scanning

Scan only added lines in git diff with format-aware parsing:

```bash
pastewatch-cli scan --git-diff              # staged changes (default)
pastewatch-cli scan --git-diff --unstaged   # working tree changes
pastewatch-cli scan --git-diff --check      # CI gate mode
```

### Doctor

Installation health check:

```bash
pastewatch-cli doctor        # text output
pastewatch-cli doctor --json # programmatic output
```

Shows CLI version, config status, hook status, MCP server processes (with per-process `--min-severity` and `--audit-log`), and Homebrew version.

### VS Code Extension

Real-time secret detection in the editor with inline diagnostics, hover tooltips, and quick-fix actions. Install from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=ppiankov.pastewatch).

### Environment Variables

| Variable | Effect |
|----------|--------|
| `PW_GUARD=0` | Disable `guard` and `scan --check` - all commands allowed, no scanning. Set before starting the agent session. |

### Pre-commit Hook

```bash
# Install hook
pastewatch-cli hook install

# Append to existing hook
pastewatch-cli hook install --append

# Remove hook
pastewatch-cli hook uninstall
```

### Baseline Diff

Create a baseline of known findings, then only report new ones:

```bash
pastewatch-cli baseline create --dir . --output .pastewatch-baseline.json
pastewatch-cli scan --dir . --baseline .pastewatch-baseline.json --check
```

### Config Init

Generate project configuration files:

```bash
pastewatch-cli init          # creates .pastewatch.json and .pastewatch-allow
pastewatch-cli init --force  # overwrite existing files
```

Config resolution cascade: CWD `.pastewatch.json` > `~/.config/pastewatch/config.json` > defaults.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean |
| 1 | Internal error |
| 2 | Invalid args |
| 6 | Findings detected |

### Stdin Filename Hint

When piping content via stdin, use `--stdin-filename` to enable format-aware parsing:

```bash
cat .env | pastewatch-cli scan --stdin-filename .env --check
git show HEAD:config.yml | pastewatch-cli scan --stdin-filename config.yml
```

### Inline Allowlist

Suppress findings on a specific line by adding a `pastewatch:allow` comment:

```env
SAFE_API_KEY=test_key_123  # pastewatch:allow
```

Works with any comment style (`#`, `//`, `/* */`).

### Pre-commit Framework (pre-commit.com)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ppiankov/pastewatch
    rev: v0.19.5
    hooks:
      - id: pastewatch
```

Requires `pastewatch-cli` installed via Homebrew.

### Pre-commit Hook (manual)

```bash
#!/bin/sh
git diff --cached --diff-filter=d | pastewatch-cli scan --check
```

### Format-Aware Scanning

When scanning `.env`, `.json`, `.yml`/`.yaml`, `.properties`/`.cfg`/`.ini`, or `.xml` files, pastewatch parses the file structure and scans values only. This reduces false positives from keys, comments, and structural elements.

For XML files, pastewatch extracts values from sensitive tags (`<password>`, `<host>`, `<user>`, etc.) covering ClickHouse, Hadoop, and other XML-based configs. Custom tags can be added via the `xmlSensitiveTags` config field.

### Allowlist

Create a file with one value per line to suppress known-safe findings:

```
test@example.com
192.168.1.1
# Comments start with #
```

### Custom Rules

Define additional patterns in a JSON file:

```json
[
  {"name": "Internal ID", "pattern": "MYCO-[0-9]{6}"},
  {"name": "Internal URL", "pattern": "https://internal\\.corp\\.net/\\S+"}
]
```

---

## Agent Integration

Install via Homebrew:

```bash
brew install ppiankov/tap/pastewatch
```

Or download the binary:

```bash
curl -LO https://github.com/ppiankov/pastewatch/releases/latest/download/pastewatch-cli
chmod +x pastewatch-cli
sudo mv pastewatch-cli /usr/local/bin/
```

**For AI coding agents**: Use MCP redacted read/write to prevent secret leakage - see [docs/agent-safety.md](docs/agent-safety.md) for setup.

**For CI/CD**: Use the CLI scan command or [GitHub Action](https://github.com/ppiankov/pastewatch-action).

Agents: read [`docs/SKILL.md`](docs/SKILL.md) for commands, flags, config files, detection types, and exit codes.

---

## Configuration

### Config files

| File | Location | Purpose | Created By |
|------|----------|---------|------------|
| `.pastewatch.json` | Project root | Project-level config (rules, allowlists, hosts) | `pastewatch-cli init` |
| `~/.config/pastewatch/config.json` | Home | User-level defaults | Manual / GUI app |
| `.pastewatch-allow` | Project root | Value allowlist (one per line, `#` comments) | `pastewatch-cli init` |
| `.pastewatchignore` | Project root | Path exclusion patterns (glob, like `.gitignore`) | Manual |
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
| `showNotifications` | bool | System notifications on GUI obfuscation |
| `soundEnabled` | bool | Sound on GUI obfuscation |
| `allowedValues` | string[] | Exact values to suppress (merged with `.pastewatch-allow`) |
| `allowedPatterns` | string[] | Regex patterns for value suppression (wrapped in `^(...)$`) |
| `customRules` | object[] | Additional regex patterns with name, pattern, optional severity |
| `safeHosts` | string[] | Hostnames excluded from detection (leading dot = suffix match) |
| `sensitiveHosts` | string[] | Hostnames always detected (overrides safe hosts, catches 2-segment hosts like `.local`) |
| `sensitiveIPPrefixes` | string[] | IP prefixes always detected (overrides built-in exclude list, e.g., `172.16.`) |
| `mcpMinSeverity` | string | Default severity threshold for MCP redacted reads (default: `high`) |

GUI settings can also be changed via the menubar dropdown.

---

## Threat Model

Pastewatch assumes:

- Users will paste sensitive data
- AI systems are not trusted with raw secrets
- Prevention is cheaper than remediation

Pastewatch does not attempt to secure downstream systems. It prevents entry entirely.

---

## Design Constraints

- Local-only operation
- Deterministic behavior
- Minimal UI surface
- No background analytics
- No user accounts
- No configuration required for safe defaults

If a feature increases complexity without reducing risk, it is rejected.

---

## Platform Support

| Platform | Component | Status |
|----------|-----------|--------|
| macOS 14+ (Apple Silicon) | GUI + CLI | Supported |
| Linux x86_64 | CLI only | Supported |

Intel-based Macs are not supported and there are no plans to add prebuilt binaries. Intel Mac users can compile from source (`swift build -c release`). The GUI (clipboard monitoring) is macOS-only.

---

## Documentation

- [docs/agent-integration.md](docs/agent-integration.md) - Consolidated agent reference (enforcement matrix, MCP setup, hooks, config)
- [docs/agent-setup.md](docs/agent-setup.md) - Per-agent MCP setup (Claude Code, Claude Desktop, Cline, Cursor, OpenCode, Codex CLI, Qwen Code)
- [docs/agent-safety.md](docs/agent-safety.md) - Agent safety guide (layered defenses for AI coding agents)
- [docs/examples/](docs/examples/) - Ready-to-use agent configs (Claude Code, Cline, Cursor)
- [docs/hard-constraints.md](docs/hard-constraints.md) - Design philosophy and non-negotiable rules
- [docs/status.md](docs/status.md) - Current scope and non-goals

---

## License

[MIT License](LICENSE).

Use it. Fork it. Modify it.

Do not pretend it guarantees compliance or safety.

---

## Project Status

**Status: Stable** · **v0.19.5** · Active development

| Milestone | Status |
|-----------|--------|
| Core detection (30 types) | Complete |
| Clipboard obfuscation | Complete |
| CLI scan mode | Complete |
| macOS menubar app | Complete |
| CI pipeline (test/lint) | Complete |
| SKILL.md agent integration | Complete |
| Homebrew distribution | Complete |
| SARIF 2.1.0 output | Complete |
| Directory scanning | Complete |
| Format-aware parsing | Complete |
| Allowlist / custom rules | Complete |
| MCP server | Complete |
| Baseline diff mode | Complete |
| Pre-commit hook installer | Complete |
| Config init / resolution | Complete |
| Linux CLI binary | Complete |
| Severity levels | Complete |
| Inline allowlist comments | Complete |
| Pre-commit framework | Complete |
| Stdin filename hint | Complete |
| Severity threshold (--fail-on-severity) | Complete |
| File output (--output) | Complete |
| Markdown output format | Complete |
| Cloud credentials (Slack, Discord, Azure, GCP) | Complete |
| Custom rule severity | Complete |
| .pastewatchignore | Complete |
| Explain subcommand | Complete |
| Config check subcommand | Complete |
| MCP redacted read/write | Complete |
| MCP per-agent severity thresholds | Complete |
| MCP audit logging | Complete |
| Bash command guard (pipes, subshells, redirects) | Complete |
| Guard: database CLIs, infra tools, scripting interpreters | Complete |
| Read/Write tool guards | Complete |
| Fix subcommand (secret externalization) | Complete |
| Inventory subcommand (posture reports) | Complete |
| Doctor subcommand (health check) | Complete |
| Setup subcommand (agent auto-setup) | Complete |
| Report subcommand (session reports) | Complete |
| Canary subcommand (leak detection) | Complete |
| Git diff scanning | Complete |
| Git history scanning | Complete |
| Entropy-based detection | Complete |
| VS Code extension | Complete |
| Host/IP config (safeHosts, sensitiveHosts, sensitiveIPPrefixes) | Complete |
