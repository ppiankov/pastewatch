# Pastewatch
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

Local macOS utility that obfuscates sensitive data before it is pasted into AI chat interfaces.

It operates **before paste**, not after submission.

If sensitive data never enters the prompt, the incident does not exist.

---

## Core Principle

**Principiis obsta** — resist the beginnings.

Pastewatch intervenes at the earliest irreversible boundary: the moment data leaves the user's control.

Once pasted into an AI system, data cannot be reliably recalled, audited, or constrained.

Pastewatch refuses that transition.

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
| DB Connections | `postgres://user:pass@host/db` |
| SSH Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| Credit Cards | `4111111111111111` (Luhn validated) |

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
```

### MCP Server

Run pastewatch as an MCP server for AI agent integration:

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

Tools: `pastewatch_scan`, `pastewatch_scan_file`, `pastewatch_scan_dir`.

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

### Pre-commit Hook

```bash
#!/bin/sh
git diff --cached --diff-filter=d | pastewatch-cli scan --check
```

### Format-Aware Scanning

When scanning `.env`, `.json`, `.yml`/`.yaml`, or `.properties`/`.cfg`/`.ini` files, pastewatch parses the file structure and scans values only. This reduces false positives from keys, comments, and structural elements.

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

Install the CLI binary:

```bash
curl -LO https://github.com/ppiankov/pastewatch/releases/latest/download/pastewatch-cli
chmod +x pastewatch-cli
sudo mv pastewatch-cli /usr/local/bin/
```

Or via Homebrew:

```bash
brew install ppiankov/tap/pastewatch
```

Agents: read [`SKILL.md`](SKILL.md) for commands, flags, detection types, and exit codes.

---

## Configuration

Optional configuration file: `~/.config/pastewatch/config.json`

```json
{
  "enabled": true,
  "enabledTypes": ["Email", "Phone", "IP", "AWS Key", "API Key", "UUID", "DB Connection", "SSH Key", "JWT", "Card"],
  "showNotifications": true,
  "soundEnabled": false
}
```

All settings can also be changed via the menubar dropdown.

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

macOS 14+ on Apple Silicon (M1 and newer).

Intel-based Macs are not supported.

---

## Project Family

Pastewatch applies **Principiis obsta** at the clipboard boundary. It is part of a family of tools applying the same principle at different surfaces:

| Project | Boundary | Intervention Point |
|---------|----------|-------------------|
| [Chainwatch](https://github.com/ppiankov/chainwatch) | AI agent execution | Before tool calls |
| **Pastewatch** | Data transmission | Before paste |
| [VaultSpectre](https://github.com/ppiankov/vaultspectre) | Secrets lifecycle | Before exposure |
| [Relay](https://github.com/ppiankov/relay) | Human connection | Before isolation compounds |

Same principle. Different surfaces. Consistent philosophy.

---

## Documentation

- [docs/design-baseline.md](docs/design-baseline.md) — Core philosophy and design priorities
- [docs/hard-constraints.md](docs/hard-constraints.md) — Non-negotiable rules
- [docs/status.md](docs/status.md) — Current scope and non-goals

---

## License

MIT License.

Use it. Fork it. Modify it.

Do not pretend it guarantees compliance or safety.

---

## Project Status

**Status: Stable** · **v0.4.0** · Active development

| Milestone | Status |
|-----------|--------|
| Core detection (13 types) | Complete |
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
