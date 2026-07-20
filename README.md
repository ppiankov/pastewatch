# Pastewatch
[![Stable](https://img.shields.io/badge/status-stable-brightgreen)](https://github.com/ppiankov/pastewatch/releases)
[![Version](https://img.shields.io/badge/version-0.33.0-blue)](https://github.com/ppiankov/pastewatch/releases/tag/v0.33.0)
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

- **Mutated:** intrinsically identifiable secrets such as provider tokens, complete private keys, validated JWTs and cards; exact values supplied by a trusted local source; and patterns **you** approve with a custom rule.
- **Advisory only:** format-only DSN/JDBC URLs, broad generic API-key prefixes (`sk-`, `pk-`, `api_`), generic credential assignments, XML credential-shaped text, and ambiguous detections such as emails, phone numbers, IPs, hostnames, file paths, and UUIDs. Pastewatch reports these off-band without rewriting them unless exact-value or custom-rule evidence authorizes mutation. Exact sourced-provider grammars, including GitHub classic tokens and Stripe keys, remain intrinsically authorized.
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

### API Proxy — Last Line of Defense

Every tool call an AI agent makes — including internal subprocesses you don't control — ends up as an HTTP request to the API. The proxy scans and redacts secrets from outbound requests before they leave your machine — including from subagents and tools that bypass the hooks.

> **Anthropic-shaped traffic.** The proxy redacts the Anthropic Messages API (`/v1/messages`, what Claude Code sends) and Message Batch create requests (`/v1/messages/batches`). It does **not** parse the OpenAI Chat Completions wire format, so it cannot redact OpenAI/Codex request bodies — rather than forward one unscanned and let you believe it was protected, the proxy **refuses** an unrecognized upstream body shape (HTTP 415). Model names are advisory telemetry only because gateways and Anthropic-compatible providers may rewrite them; path and structural body checks form the admission boundary. Protect Codex and other agents with configured pastewatch hooks and MCP tools where available.

> **Single session.** The proxy handles one agent session at a time. Run a separate `pastewatch-cli proxy` instance (on a different port) for each concurrent session.

![Proxy alert injection — 27 secrets redacted from a tool call](assets/proxy-alert.png)

```
  Your machine
  ┌──────────────────────────────────────┐
  │  Agent (any process, any tool)       │
  │           │                          │
  │           ▼                          │
  │  pastewatch proxy (localhost:8443)   │
  │  scan request body → redact secrets  │
  │           │                          │
  │           ▼                          │
  │  corporate proxy (if present)        │
  │           │                          │
  └───────────┼──────────────────────────┘
              │
              ▼  Cloud API
         api.anthropic.com (authorized matches removed)
```

```bash
# One command — starts proxy, launches agent, cleans up on exit
pastewatch-cli launch claude

# With options
pastewatch-cli launch --audit-log /tmp/pw.log -- claude --model opus
```

Only `claude` is routed through the proxy today (the proxy redacts Anthropic-shaped traffic). Launching another agent through `launch` does **not** start or wire the proxy. `--audit-log` is rejected for non-routed agents because no proxy audit stream exists for those launches. Protect non-routed agents with configured pastewatch hooks and MCP tools where available.

Or start the proxy manually for more control:

```bash
# Start the proxy in one terminal
pastewatch-cli proxy

# Start your agent in another
ANTHROPIC_BASE_URL=http://127.0.0.1:8443 claude
```

**Corporate proxy chaining.** Many organizations require API traffic to go through a corporate proxy. For routed Claude Code traffic, pastewatch chains transparently — it scans and redacts first, then forwards through the corporate proxy:

```bash
# Corporate proxy at proxy.corp:8080
# Pastewatch scans → forwards to corporate proxy → corporate proxy forwards to API
pastewatch-cli launch --forward-proxy http://proxy.corp:8080 -- claude
```

```
  Agent (claude)
    │
    ▼
  pastewatch proxy (localhost:8443)     ← scans + redacts secrets
    │
    ▼
  corporate proxy (proxy.corp:8080)     ← existing network policy
    │
    ▼
  api.anthropic.com                     ← secrets never arrive
```

If the corporate proxy requires a specific port, match it:

```bash
# Corporate proxy expects traffic on :3456
pastewatch-cli launch --port 3456 --forward-proxy http://127.0.0.1:3457 -- claude
```

**Custom gateway / private-CA endpoints.** To front an LLM gateway or corporate API endpoint (any pass-through proxy) instead of `api.anthropic.com`, point `--upstream` at it. The upstream base path is preserved, and any custom auth headers the agent sends are forwarded through:

```bash
# Gateway with a pass-through base path (preserved when forwarding)
pastewatch-cli launch --upstream https://gateway.example.com/v1/passthrough -- claude
```

If the gateway's TLS certificate chains to a private/corporate CA, trust it with `--ca-cert` (added on top of the system trust store):

```bash
pastewatch-cli launch \
  --upstream https://gateway.example.com/v1/passthrough \
  --ca-cert /path/to/corp-ca.pem \
  -- claude
```

As a last-resort escape hatch, `--insecure` skips upstream TLS verification entirely (prints a warning; use only for trusted private gateways):

```bash
pastewatch-cli launch --upstream https://gateway.example.com -- claude --insecure
```

Both flags govern **only** the proxy-to-upstream connection; the agent-to-proxy hop stays plain HTTP on `127.0.0.1`.

**Gateway reachable only through a corporate proxy.** If the upstream gateway is behind a corporate HTTP proxy (common in enterprise networks), route pastewatch's upstream connection through it with the standard `HTTPS_PROXY` / `NO_PROXY` environment variables. Keep `127.0.0.1` and your internal domains in `NO_PROXY` so the local agent-to-proxy hop and internal hosts are not sent through the corporate proxy:

```bash
HTTPS_PROXY=http://corp-proxy.example.com:8080 \
NO_PROXY="127.0.0.1,localhost,example.com,.example.com" \
ANTHROPIC_CUSTOM_HEADERS="x-your-gateway-key: <value>" \
pastewatch-cli launch --upstream https://gateway.example.com/v1/passthrough -- claude
```

Set any gateway auth on the same line via `ANTHROPIC_CUSTOM_HEADERS` — the agent sends it, and the proxy forwards it to the gateway unchanged. The `HTTPS_PROXY` env-var path is the recommended way to chain through a corporate proxy to an `https://` gateway; it uses the system's native HTTP CONNECT tunneling.

**Resume sessions** through the proxy — all flags pass through:

```bash
pastewatch-cli launch -- claude -r
pastewatch-cli launch -- claude --resume <session-id>
```

**Shell alias** for zero-friction protected sessions:

```bash
# .zshrc / .bashrc / config.fish
alias claude='pastewatch-cli launch claude'

# With corporate proxy
alias claude='pastewatch-cli launch --forward-proxy http://proxy.corp:8080 -- claude'
```

**Audit logging.** The proxy logs redactions to stderr and deduplicates repeated history scans. Use `--audit-log` to write to a file for dashboard aggregation. Set `operatorRedactionNotices` to `true` to force a notice for every proxy mutation, including repeated events under `--quiet`; the default is `false`.

```bash
pastewatch-cli launch --audit-log /tmp/pw-audit.log -- claude
```

```
[2026-03-16T11:36:56Z] PROXY REDACTED 3 secret(s) in /v1/messages
```

When an alert is injected, it tells the model that `<TYPE_n>` markers are expected one-way redactions, while malformed markers or mangled surrounding bytes may indicate real corruption. Proxy placeholders are not restored.

**Streaming response mode.** `responseStreamingRedactionMode=buffer` is a compatibility mode for full-response buffering. It does not scan buffered response bodies for secrets; use the default `per_sse_event` mode when response redaction is required. The event-aware relay reassembles Anthropic `input_json_delta.partial_json` and OpenAI-compatible/LiteLLM `tool_calls[].function.arguments` fragments before scanning, then preserves all frame bytes outside authorized replacements. This response support does not change request admission: OpenAI-shaped request bodies are still refused.

Response streaming has no authoritative catalog of exact local secret values. It mutates intrinsically identifiable formats and operator-approved custom rules; adding exact-value response matching requires a separately designed local secret source and lifecycle.

For local protocol diagnosis only, `pastewatch-cli proxy --debug-stream-dump <path>` writes raw input frames, transformed output, and mutation decisions as owner-only JSONL. It requires the default `per_sse_event` mode so each record reflects the actual frame decision; startup fails instead of producing an incomplete dump in `raw_stream` or `buffer` mode. The file contains unredacted secrets by design, is disabled unless the option is supplied, and prints a warning even with `--quiet`. Delete it securely after diagnosis and never attach it to an issue or commit.

### MCP Server - Redacted Read/Write

AI coding agents send file contents to cloud APIs. Pastewatch MCP replaces authorized secret matches with reversible placeholders while keeping the secret map local; advisory-only matches remain unchanged for operator review.

```
  Your machine (local only)
  ┌────────────────────────┐
  │  pastewatch MCP server │
  │                        │   __PW_AWS_KEY_1__
  │  read: scan + redact ──┼──────────────────────► Agent sees placeholders
  │  write: resolve local ◄┼────────────────────── Agent returns placeholders
  │                        │
  │  mapping stays local   │   Authorized matches leave only as placeholders.
  └────────────────────────┘
```

**Setup** (the config shape and file location vary by agent):

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
| `pastewatch_read_file` | Read file with secrets replaced by `__PW_TYPE_N__` placeholders |
| `pastewatch_write_file` | Write file, resolving placeholders back to real values locally |
| `pastewatch_check_output` | Verify text contains no raw secrets before returning |
| `pastewatch_scan` | Scan text for sensitive data |
| `pastewatch_scan_file` | Scan a file for sensitive data |
| `pastewatch_scan_dir` | Scan a directory recursively |

The server holds mappings in memory for the session. Same file re-read returns the same placeholders. Mappings die when the server stops. A redacted read includes a short model-facing note: well-formed `__PW_TYPE_n__` markers, or markers using the configured `placeholderPrefix`, are two-way placeholders restored locally by `pastewatch_write_file`; malformed markers or mangled nearby bytes may indicate real corruption. Set `operatorRedactionNotices` to `true` for a metadata-only notice on every MCP substitution. Notices go to the configured audit log, or to stderr when no audit log is configured.

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

**What this protects:** Intrinsically identifiable secrets, exact known values, and custom-rule matches are rewritten before supported API requests leave. Format-only credentials and DSNs are advisory-only by default and can still reach upstream unless exact-value or custom-rule evidence authorizes mutation. **What this doesn't protect:** prompt content, code structure, and business logic still reach the API; use a local model when those must remain local.

See [docs/agent-setup.md](docs/agent-setup.md) for the verified per-agent config
paths and automatic/manual setup status.

### Agent Auto-Setup

Agent integration configures every supported component that can be updated without
damaging an existing config. Goose and Codex print manual YAML/TOML blocks; Aider
reports MCP unavailable.

```bash
pastewatch-cli setup claude-code              # global config
pastewatch-cli setup claude-code --project    # project-level config
pastewatch-cli setup cline
pastewatch-cli setup cursor
pastewatch-cli setup claude-code --severity medium  # align hook + MCP thresholds
```

Idempotent - safe to re-run. Updates existing config without duplication.

### Agent Compatibility

| Agent | Hook | MCP | Proxy |
|-------|------|-----|-------|
| Claude Code | Yes - PreToolUse | Automatic | Routed by `launch` |
| Cline | Yes - PreToolUse JSON cancel | Automatic | Not routed by `launch` |
| Cursor | Yes - preToolUse | Automatic | Not routed by `launch` |
| Windsurf | Yes - pre_read/write/run | Automatic | Not routed by `launch` |
| Continue | Yes - PreToolUse | Automatic | Not routed by `launch` |
| Amazon Q | Yes - preToolUse | Automatic | Not routed by `launch` |
| Antigravity (agy) | **NO HOOK INTEGRATION** - no structural read blocking; schema/plugin hook probes failed ([discovery](docs/research/agy-hooks-discovery.md), [follow-up](docs/research/agy-hooks-follow-up.md)) | Yes - manual `~/.gemini/config/mcp_config.json` ([discovery](docs/research/agy-hooks-discovery.md)) | Not applicable (`agy` does not expose an API endpoint override) |

Antigravity/agy can use pastewatch only through voluntary MCP tools today; hook probes in [discovery](docs/research/agy-hooks-discovery.md) and [follow-up](docs/research/agy-hooks-follow-up.md) found no working hook registration, so pastewatch does NOT block agy reads structurally.

See the version-bounded [Antigravity hook verification retrospective](docs/research/agy-hallucinated-hooks.md) for the probe methodology and current-docs caveat.

See [gh CLI multi-account on macOS](docs/research/gh-multi-account-macos.md) for the directory-environment/keychain boundary behind startup-sweep guidance.

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

### Watch Mode

Continuous file monitoring — scans changed files in real-time:

```bash
pastewatch-cli watch --dir .                    # watch current directory
pastewatch-cli watch --dir . --severity high    # only report high+ findings
pastewatch-cli watch --dir . --json             # newline-delimited JSON output
```

Polls every 2 seconds, prints warnings to stderr. Respects `.pastewatchignore` and `.gitignore`. Ctrl-C to stop.

### Dashboard

Aggregate view across multiple MCP audit log sessions:

```bash
pastewatch-cli dashboard                            # text summary from /tmp
pastewatch-cli dashboard --dir /tmp --format json   # machine-readable
pastewatch-cli dashboard --since 2026-03-01T00:00:00Z --format markdown
```

Shows total sessions, secrets redacted, top secret types, hot files, and overall verdict.

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
pastewatch-cli init                    # creates .pastewatch.json and .pastewatch-allow
pastewatch-cli init --profile banking  # banking profile: JDBC, medium severity, internal host detection
pastewatch-cli init --force            # overwrite existing files
```

**Banking profile** sets `mcpMinSeverity: medium` (catches IPs and internal hostnames), enables JDBC URL detection, adds example `customRules` for service accounts and internal URIs, and pre-fills `sensitiveIPPrefixes` with all RFC 1918 ranges. Replace `YOURBANK` in `sensitiveHosts` with your domain.

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
    rev: v0.33.0
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
  "mcpMinSeverity": "high",
  "operatorRedactionNotices": false,
  "placeholderPrefix": "REDACTED_PLACEHOLDER_"
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
| `operatorRedactionNotices` | bool | Emit a metadata-only operator notice for every proxy/MCP mutation, including under `--quiet` (default: `false`) |
| `placeholderPrefix` | string? | Custom prefix for MCP placeholders (e.g., `REDACTED_` produces `REDACTED_001`). Default: `null` (uses `__PW_TYPE_N__` format) |

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
| macOS (Apple Silicon) | GUI + CLI | Supported |
| macOS (Intel x86_64) | CLI only | Supported (universal binary) |
| Linux x86_64 | CLI only | Supported |
| Linux arm64 | CLI only | Supported |

The GUI (clipboard monitoring) is macOS-only. CLI works on all platforms via Homebrew or direct download.

**Linux proxy note:** On Linux, the proxy uses `curl` (Process) for upstream HTTP requests instead of Swift's `URLSession`. This works around a known `FoundationNetworking` bug on arm64 where `dataTask` completion handlers silently fail. Requires `curl` on `PATH` (present on all standard Linux distributions).

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

**Status: Stable, feature-complete** · **v0.33.0** · Accepting compatibility and bug fixes only

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
| API proxy (outbound secret redaction) | Complete |
| Proxy alert injection (agent feedback on redaction) | Complete |
| Launch command (one-step proxy + agent) | Complete |
| Multi-platform binaries (macOS universal, Linux amd64/arm64) | Complete |
