# Pastewatch
[![Stable](https://img.shields.io/badge/status-stable-brightgreen)](https://github.com/ppiankov/pastewatch/releases)
[![Version](https://img.shields.io/badge/version-0.35.2-blue)](https://github.com/ppiankov/pastewatch/releases/tag/v0.35.2)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
[![CI](https://github.com/ppiankov/pastewatch/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/pastewatch/actions/workflows/ci.yml)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

Detects and obfuscates sensitive data before it reaches AI systems — clipboard monitoring, CLI scanner, MCP server, API proxy, shell guard hooks, and VS Code extension.

It operates **before paste**, not after submission.

If sensitive data never enters the prompt, the incident does not exist.

---

## Core Principle

**Principiis obsta** - resist the beginnings.

Pastewatch intervenes at the earliest irreversible boundary: the moment data leaves the user's control.

Once pasted into an AI system, data cannot be reliably recalled, audited, or constrained.

Pastewatch refuses that transition.

---

## Why This Matters

Every AI agent sends your file contents, command outputs, and tool results to a cloud API. If those contain secrets, the secrets leave your machine — silently, irreversibly, and into infrastructure you don't control.

Pastewatch prevents supported secret-leakage paths structurally without breaking agent workflows:

```
  What the agent does                What actually happens
  ──────────────────                 ──────────────────────
  Read a file with secrets     →    MCP returns placeholders, secrets stay in RAM
  Run a bash command with DSN  →    Guard blocks before execution
  Send tool results to API     →    Proxy redacts secrets from the request body
  Write code with placeholders →    MCP resolves originals locally on write-back
```

The agent works normally. It reads files, runs commands, and writes code. Through MCP,
the agent sees reversible placeholders; through the proxy, intrinsically identifiable or
operator-authorized secrets are replaced before supported traffic reaches the cloud.

**No ML and no probabilistic mutation. Authorization comes from secret evidence, not severity.**

## Why Pastewatch

- **Before-paste boundary** — authorized secret matches are rewritten before supported traffic leaves. Nightfall, Prisma, Check Point all intercept downstream. Pastewatch prevents upstream
- **MCP server for AI agents** — no other tool provides redacted read/write at the tool level. Authorized matches become reversible placeholders while the secret map stays local
- **Bash guard with deep parsing** — pipes, subshells, redirects, database CLIs, infra tools. Every shell command the agent runs is scanned before execution
- **API proxy** — catches Anthropic-shaped traffic that bypasses hooks, including from subagents. Last line of defense before the network boundary (refuses unrecognized upstream shapes rather than forward them unscanned)
- **Canary honeypots** — "prove it works" not "trust it works." Plant format-valid fake secrets and verify they're caught
- **Local-only, deterministic, no ML** — no cloud dependency, no probabilistic scoring, no telemetry. Runs offline, gives the same answer every time
- **One command** — `pastewatch-cli launch claude` and every layer is active. No manual setup, no env vars, no second terminal

---

## What Pastewatch Does

Pastewatch started as a clipboard monitor — scan before paste, replace secrets with placeholders. It evolved into a full secret protection stack for AI agent workflows:

| Layer | What it does | How it works |
|-------|-------------|-------------|
| **Clipboard monitor** | Scans before paste | macOS menubar app, replaces secrets in clipboard |
| **CLI scanner** | Scans files, directories, git diffs | `pastewatch-cli scan --dir .` |
| **Startup sweep** | Warns about pre-existing shell config credentials | `pastewatch-cli launch` scans common startup files once per changed finding summary |
| **MCP server** | Redacted read/write for AI agents | Agent sees placeholders, originals stay in RAM |
| **Shell guard** | Blocks secrets in commands and file access | Pre-execution hook for Claude Code, Cline, Cursor, Windsurf, Continue, Amazon Q |
| **API proxy** | Redacts secrets from supported outbound API traffic | Scans Anthropic-shaped requests and refuses unsupported body shapes |
| **VS Code extension** | Real-time detection in the editor | Highlights secrets as you type |

All layers share the same detection engine — 30+ pattern types, deterministic regex, no ML. Every layer operates locally. Nothing phones home.

### Zero false-positive mutation

Pastewatch rewrites your data only when it is **certain** the value is a secret. This is a hard rule, not a tuning knob:

- **Mutated:** intrinsically identifiable secrets such as sourced provider tokens, complete private keys, validated JWTs and cards; exact values supplied by a trusted local source; patterns **you** approve with a custom rule; and email/host values covered by an `obfuscate` entry.
- **Opt-in ambiguity:** intrinsic detectors are enabled by default. Email and host mutation requires an exact or domain-scoped `obfuscate` entry. Unconfigured email/host values are not rewritten or nagged; the proxy records only privacy-safe domain coverage so the operator can decide whether to opt in. Other ambiguous detectors remain advisory-only when explicitly enabled.
- **`--severity` controls how much it nags, never what it rewrites.** Lowering severity surfaces more advisories; it never widens the set of values that get mutated.

The result: false negatives are preferred over false positives, and mutation false positives are driven to ~zero by construction. Pastewatch never breaks a working agent response to redact something it only *might* be.

---

## What Pastewatch is NOT

- Not a DLP system — no policies, no enforcement workflows, no admin console
- Not a compliance product — it does not certify, audit, or generate reports for regulators
- Not an AI classifier — deterministic pattern matching only, no probabilistic scoring
- Not a policy engine — it does not decide what you're allowed to do, it prevents structural leaks

Pastewatch does not:

- phone home or collect telemetry
- require cloud connectivity
- guess, infer, or act when uncertain
- store clipboard history or file contents
- make decisions — it presents evidence and lets you decide

---

## How Pastewatch Works

Pastewatch scans text for sensitive patterns and replaces them with non-sensitive placeholders. The same engine powers all six layers:

1. **Detection** — regex-based pattern matching across 30+ secret types (API keys, DSNs, tokens, credentials, PII)
2. **Authorization** — evidence partitions matches into mutation or advisory-only outcomes
3. **Obfuscation** — authorized values are replaced with typed placeholders (`<AWS_KEY_1>`)
4. **Resolution** — only the MCP server stores originals in local RAM and restores them on write-back

The clipboard monitor scans before paste. The CLI scans files on demand. The MCP server scans on read and resolves on write. The guard scans commands before execution. The proxy scans API requests before they leave the network. Each layer catches what the others miss.

---

## Quick Start

30 seconds from zero to protected AI agent session:

```bash
# 1. Install
brew install ppiankov/tap/pastewatch

# 2. Set up hooks and MCP server for your agent
pastewatch-cli setup claude-code

# 3. Run through the proxy — one command, fully protected
pastewatch-cli launch claude
```

The `launch` command starts the proxy, waits for it to be ready, sets `ANTHROPIC_BASE_URL`, and runs Claude Code. When the agent exits, the proxy stops. The proxy scans Anthropic-shaped API requests and redacts supported secrets before they leave your machine. Protect other agents with configured hooks, MCP tools, and agent instructions where available.

**Important:** The setup step injects credential handling rules into your agent's `CLAUDE.md`. Without these rules, agents may echo passwords in shell output or store plaintext credentials in memory files — formats that bypass regex detection. The rules ensure agents use detectable keywords (`password=`, `secret=`) and never store raw values. See [docs/CLAUDE-SNIPPET.md](docs/CLAUDE-SNIPPET.md) for the full snippet.

For persistent setup, add a shell alias:

```bash
# .zshrc / .bashrc
alias claude='pastewatch-cli launch claude'
```

---

## Installation

### From Release (Recommended)

1. Download the latest `.dmg` from [Releases](https://github.com/ppiankov/pastewatch/releases)
2. Open the DMG and drag `Pastewatch.app` to Applications
3. Launch Pastewatch from Applications
4. Grant notification permissions when prompted

### CLI via Homebrew

```bash
brew install ppiankov/tap/pastewatch
pastewatch-cli doctor    # verify installation
```

### CLI Manual Install (No Homebrew)

For environments where Homebrew is not available (CI runners, restricted workstations):

```bash
# macOS (universal binary — Apple Silicon + Intel)
curl -L -o pastewatch-cli https://github.com/ppiankov/pastewatch/releases/latest/download/pastewatch-cli

# Linux x86_64
curl -L -o pastewatch-cli https://github.com/ppiankov/pastewatch/releases/latest/download/pastewatch-cli-linux-amd64

# Linux arm64
curl -L -o pastewatch-cli https://github.com/ppiankov/pastewatch/releases/latest/download/pastewatch-cli-linux-arm64

chmod +x pastewatch-cli
sudo mv pastewatch-cli /usr/local/bin/
pastewatch-cli doctor
```

Or build from source (requires Swift 5.9+):

```bash
git clone https://github.com/ppiankov/pastewatch.git
cd pastewatch
swift build -c release
sudo cp .build/release/PastewatchCLI /usr/local/bin/pastewatch-cli
```

### From Source (GUI)

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
| JDBC URLs | `jdbc:oracle:thin:@...`, `jdbc:db2://...`, `jdbc:postgresql://...` |
| XML Credentials | `<password>`, `<secret_access_key>`, etc. in XML configs |
| XML Usernames | `<user>`, `<quota_key>` in XML configs |
| XML Hostnames | `<host>`, `<hostname>`, `<interserver_http_host>` in XML configs |
| High Entropy Strings | Opt-in Shannon entropy detection (4.0 bits/char threshold) |

Each type has a severity level (critical, high, medium, low) used in SARIF, JSON, and markdown output.

No ML. No probabilistic scoring. No confidence levels.

If detection is ambiguous, Pastewatch does nothing.

---

## Obfuscation Model

Detected values are replaced with typed, numbered placeholders:

```
AKIAIOSFODNN7EXAMPLE  →  <AWS_KEY_1>
AIza...               →  <GOOGLE_API_KEY_1>
github_pat_...        →  <GITHUB_TOKEN_1>
```

How placeholders work depends on the layer:

| Layer | Placeholder lifetime | Recovery |
|-------|---------------------|----------|
| **Clipboard** | Discarded after paste | None — one-way |
| **CLI scan** | Output only | None — source files are never modified |
| **MCP server** | Stored in RAM for the session | Write-back resolves originals locally |
| **API proxy** | Replaced in-flight | None — redacted before it leaves |

The MCP server is the only layer that maintains a mapping, because it must restore
placeholders locally when the agent writes a file. Clipboard and proxy replacement is
one-way; responses are scanned independently rather than deobfuscated. The MCP mapping
lives in process memory and is lost when the session ends.

---

## User Experience

- **Clipboard/GUI** — silent by default. When obfuscation occurs, a minimal macOS notification: `Pastewatch: Obfuscated: AWS Key (1), Google API Key (1)`
- **CLI** — findings printed to stdout, exit code 6 if secrets found
- **Startup sweep** — one stderr warning per changed shell config finding summary during `launch`; disable with `--no-startup-sweep` ([details](docs/startup-sweep.md))
- **MCP** — transparent to the agent. It reads placeholders and writes them back. No user interaction needed
- **Guard hook** — blocks with a clear message: `BLOCKED: file contains secrets. Use pastewatch_read_file instead`
- **Proxy** — redacts silently. When secrets are caught, injects a `[PASTEWATCH]` alert into the agent's response so it can warn the user

No previews. No animations. No confirmations. Silence is success.

---

## CLI Mode

`pastewatch-cli` provides scanning, guarding, and proxy subcommands for use without the GUI:

```bash
pastewatch-cli scan --dir .              # scan a directory
pastewatch-cli launch claude             # proxy + agent in one step
pastewatch-cli guard "cat .env"          # block secret-leaking commands
pastewatch-cli mcp                        # redacted read/write MCP server
```

**Full command reference:** [docs/cli-reference.md](docs/cli-reference.md) — every subcommand (`scan`, `proxy`, `launch`, `mcp`, `guard`, `fix`, `inventory`, `report`, `canary`, `watch`, `dashboard`, config, and CI integration) with flags and examples.

## Agent Integration

### Agent Safety Matrix

The API proxy (Layer 0) redacts supported **Anthropic-shaped** traffic (`/v1/messages` and `/v1/messages/batches`) and refuses unrecognized upstream body shapes (HTTP 415). `pastewatch-cli launch` wires only Claude Code to this proxy. Other clients need hooks or MCP unless the operator separately configures an Anthropic-compatible client to use `pastewatch-cli proxy`; OpenAI/Gemini-shaped bodies are not redacted.

| Agent | Protection | Hooks | MCP | Setup |
|-------|-----------|-------|-----|-------|
| Claude Code | **Structural** | PreToolUse (exit 2) | Automatic | `pastewatch-cli setup claude-code` |
| Cline | **Structural** | PreToolUse (JSON cancel) | Automatic | `pastewatch-cli setup cline` |
| Roo Code | **Structural** | PreToolUse (JSON cancel) | Automatic | `pastewatch-cli setup roo-code` |
| Cursor | **Structural** | preToolUse (exit 2) | Automatic | `pastewatch-cli setup cursor` |
| Windsurf | **Structural** | pre_read/write/run (exit 2) | Automatic | `pastewatch-cli setup windsurf` |
| Continue | **Structural** | PreToolUse (exit 2) | Automatic | `pastewatch-cli setup continue` |
| Amazon Q | **Structural** | preToolUse (exit 2) | Automatic | `pastewatch-cli setup amazon-q` |
| Copilot | **Structural** | preToolUse (`.github/hooks/`) | Automatic | `pastewatch-cli setup copilot` |
| Codex CLI | **Structural after hook trust** | PreToolUse (exit 2) | Manual TOML | `pastewatch-cli setup codex`, then review with `/hooks` |
| Qwen Code | **Structural** | PreToolUse (exit 2) | Automatic | `pastewatch-cli setup qwen-code` |
| Goose | MCP only | No hooks | Manual YAML | `pastewatch-cli setup goose` |
| Kilo Code | MCP only | [No hooks](https://github.com/Kilo-Org/kilocode/issues/7859) (declined) | Automatic | `pastewatch-cli setup kilo-code` |
| Gemini | MCP only | No hooks | Automatic | `pastewatch-cli setup gemini` |
| Antigravity (agy) | Proxy not applicable + MCP only (voluntary tools; no Structural read blocking) | [No](docs/research/agy-hooks-follow-up.md) - handler registration fails | [Yes](docs/research/agy-hooks-discovery.md) | Not yet supported by `pastewatch-cli setup`; edit `~/.gemini/config/mcp_config.json` manually |
| OpenCode | MCP only | No hooks | Yes | Manual |
| Aider | No automatic local layer | [No MCP yet](https://github.com/aider-ai/aider/issues/4506) | Unavailable | `pastewatch-cli setup aider` explains the limitation |
| Jules | Cloud only | No local config | Cloud UI | N/A (use proxy on local side) |

**Structural** = hooks block native file access before secrets can be read. The agent cannot bypass the check.
**MCP only** = redaction applies only when the agent uses the configured Pastewatch MCP tools. Native file or network access is not intercepted.

### Install

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
  "enabledTypes": ["AWS Key", "SSH Private Key", "JWT Token", "Vault Token"],
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
  "mcpMinSeverity": "high",
  "operatorRedactionNotices": false,
  "obfuscate": [
    {"type": "email", "pattern": "operator@example.com"},
    {"type": "email", "pattern": "@example.com"},
    {"type": "host", "pattern": "gateway.example.com"},
    {"type": "host", "pattern": ".example.com"}
  ],
  "placeholderPrefix": "REDACTED_PLACEHOLDER_"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable/disable scanning globally |
| `enabledTypes` | string[] | Detection types to activate (default: intrinsic detectors only) |
| `showNotifications` | bool | System notifications on GUI obfuscation |
| `soundEnabled` | bool | Sound on GUI obfuscation |
| `allowedValues` | string[] | Exact values to suppress (merged with `.pastewatch-allow`) |
| `allowedPatterns` | string[] | Regex patterns for value suppression (wrapped in `^(...)$`) |
| `customRules` | object[] | Additional regex patterns with name, pattern, optional severity |
| `safeHosts` | string[] | Hostnames excluded from detection (leading dot = suffix match) |
| `sensitiveHosts` | string[] | Hostnames always detected (overrides safe hosts, catches 2-segment hosts like `.local`) |
| `sensitiveIPPrefixes` | string[] | IP prefixes always detected (overrides built-in exclude list, e.g., `172.16.`) |
| `mcpMinSeverity` | string | Default severity threshold for MCP redacted reads (default: `high`) |
| `operatorRedactionNotices` | bool | Emit a metadata-only operator notice for every proxy/MCP mutation, including under `--quiet` (default: `false`) |
| `obfuscate` | object[] | Exact or domain-scoped email/host mutation rules. Email patterns are an address or `@domain`; host patterns are a hostname or `.domain`. Invalid entries fail configuration validation. |
| `placeholderPrefix` | string? | Custom prefix for MCP placeholders (e.g., `REDACTED_` produces `REDACTED_001`). Default: `null` (uses `__PW_TYPE_N__` format) |

GUI settings can also be changed via the menubar dropdown.

---

## Threat Model

Pastewatch assumes:

- Users will paste sensitive data
- AI systems are not trusted with raw secrets
- Prevention is cheaper than remediation

Pastewatch does not attempt to secure downstream systems. It prevents supported, positively identified
secrets from entering configured agent transports; ambiguous classes stay unchanged unless the operator
authorizes them.

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
| macOS (Apple Silicon) | GUI + CLI | Supported |
| macOS (Intel x86_64) | CLI only | Supported (universal binary) |
| Linux x86_64 | CLI only | Supported |
| Linux arm64 | CLI only | Supported |
| Windows | — | Not supported natively — run the Linux binary under WSL2 |

The GUI (clipboard monitoring) is macOS-only. The CLI runs on macOS and Linux via Homebrew or direct download.

**Windows:** there is no native Windows build. Run the CLI inside [WSL2](https://learn.microsoft.com/windows/wsl/) using the Linux `amd64` binary (see Installation → Linux x86_64). If you need native Windows secret-redaction on the API wire, that is the domain of the gateway layer, not this tool.

**Linux proxy note:** On Linux, the proxy uses `curl` (Process) for upstream HTTP requests instead of Swift's `URLSession`. This works around a known `FoundationNetworking` bug on arm64 where `dataTask` completion handlers silently fail. Requires `curl` on `PATH` (present on all standard Linux distributions).

---

## Documentation

- [docs/agent-integration.md](docs/agent-integration.md) - Consolidated agent reference (enforcement matrix, MCP setup, hooks, config)
- [docs/agent-setup.md](docs/agent-setup.md) - Per-agent MCP setup (Claude Code, Claude Desktop, Cline, Cursor, OpenCode, Codex CLI, Qwen Code)
- [docs/agent-safety.md](docs/agent-safety.md) - Agent safety guide (layered defenses for AI coding agents)
- [docs/examples/](docs/examples/) - Ready-to-use agent configs (Claude Code, Cline, Cursor)
- [docs/hard-constraints.md](docs/hard-constraints.md) - Design philosophy and non-negotiable rules
- [docs/status.md](docs/status.md) - Feature milestones, stability, current scope, and non-goals
- [docs/cli-reference.md](docs/cli-reference.md) - Full CLI command reference (scan, proxy, guard, MCP, and all subcommands)

---

## License

[MIT License](LICENSE).

Use it. Fork it. Modify it.

Do not pretend it guarantees compliance or safety.

---

## Project Status

**Status: Stable, feature-complete** · **v0.35.2** · Accepting compatibility and bug fixes only

Pastewatch is stable and in maintenance mode. See [docs/status.md](docs/status.md) for the full feature-milestone breakdown.
