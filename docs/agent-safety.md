# Agent Safety Guide

How to use AI coding agents (Claude Code, Cline, Cursor) without leaking secrets to cloud APIs.

---

## The Problem

When an AI agent reads your files, the contents are sent to the provider's API. If those files contain API keys, connection strings, or credentials, the secrets leave your machine.

```
Your machine                          Cloud API
┌──────────────┐     file contents    ┌──────────────┐
│  source code │ ──────────────────►  │  AI provider │
│  with secrets│     (secrets leak)   │              │
└──────────────┘                      └──────────────┘
```

This is not hypothetical. Config files, .env files, and hardcoded credentials are routinely sent to AI APIs during normal agent workflows.

---

## Layer 1: Don't Put Secrets in Code

The most effective defense. If secrets aren't in files, they can't leak.

- Use `.env` files (gitignored) for local development
- Use vault references or config templates with placeholders in committed code
- Use environment variables in CI/CD pipelines

**Verify before starting an agent session:**
```bash
pastewatch-cli scan --dir . --check
```

Fix findings first. Move hardcoded secrets to environment variables or vault references.

---

## Layer 2: Pastewatch MCP Redacted Read/Write

For files that must contain secrets (legacy code, config files being migrated), use pastewatch MCP tools. The MCP server sits between the agent and your files:

```
Your machine (local)
┌─────────────────────────────────────────────┐
│                                             │
│  pastewatch MCP server                      │
│  ┌───────────────────────────────────────┐  │
│  │ read_file:                            │  │
│  │   file (real secrets)                 │  │
│  │     → scan → store mapping in RAM     │  │
│  │     → return content with             │  │
│  │       __PW{EMAIL_1}__ placeholders  ──┼──┼──► AI API (sees only placeholders)
│  │                                       │  │
│  │ write_file:                           │  │
│  │   content with placeholders         ◄─┼──┼─── AI API returns code
│  │     → resolve from RAM mapping        │  │    (contains placeholders)
│  │     → write real values to disk       │  │
│  └───────────────────────────────────────┘  │
│                                             │
│  Secrets never leave this box.              │
└─────────────────────────────────────────────┘
```

### Setup

Install pastewatch:
```bash
brew install ppiankov/tap/pastewatch
```

For per-agent registration instructions (Claude Code, Claude Desktop, Cline, Cursor, OpenCode, Codex CLI, Qwen Code), see [agent-setup.md](agent-setup.md).

### How the agent uses it

Once configured, the agent has access to these MCP tools:

| Tool | Purpose |
|------|---------|
| `pastewatch_read_file` | Read file with secrets replaced by `__PW{EMAIL_1}__` placeholders |
| `pastewatch_write_file` | Write file, resolving placeholders back to real values locally |
| `pastewatch_check_output` | Verify text contains no raw secrets before returning |

**Round-trip workflow:**
1. Agent calls `pastewatch_read_file` for sensitive files
2. Gets back content with `__PW{CREDENTIAL_1}__`, `__PW{AWS_KEY_1}__` etc.
3. API processes code — only sees placeholders, never real secrets
4. Agent calls `pastewatch_write_file` — MCP server resolves placeholders on-device
5. Written file contains real values — code stays functional

**What the agent sees (sent to API):**
```yaml
database:
  host: db.internal.corp
  port: 5432
  password: __PW{CREDENTIAL_1}__
  api_key: __PW{AWS_KEY_1}__
```

**What gets written to disk:**
```yaml
database:
  host: db.internal.corp
  port: 5432
  password: (original secret restored)
  api_key: (original key restored)
```

### Severity threshold (`min_severity`)

`pastewatch_read_file` accepts an optional `min_severity` parameter (default: `high`). Only findings at or above the threshold are redacted — everything below passes through unchanged.

**What gets redacted at each threshold:**

| `min_severity` | Redacted | Passes through |
|---|---|---|
| `critical` | AWS keys, API keys, DB connections, SSH keys, JWTs, cards, webhooks | Credentials, emails, phones, IPs, hostnames, UUIDs |
| `high` (default) | All critical + credentials, emails, phones | IPs, hostnames, file paths, UUIDs |
| `medium` | All high + IPs, hostnames, file paths | UUIDs, high entropy |
| `low` | Everything | Nothing |

**Example: `.env` file read with default `min_severity: "high"`**

Original file contains AWS keys, a database URL, an API token, an IP address, and an internal hostname. After redaction with the default `high` threshold:

```bash
# What the agent sees (sent to API)
AWS_ACCESS_KEY_ID=__PW{AWS_KEY_1}__          # critical — redacted
DATABASE_URL=__PW{DB_CONNECTION_1}__         # critical — redacted
API_TOKEN=__PW{OPENAI_KEY_1}__               # critical — redacted
ANSIBLE_HOST=172.16.161.206                  # medium — passes through
INTERNAL_SERVER=keeper2.ipa.local            # medium — passes through
```

The IP and hostname pass through because they are `medium` severity — below the default `high` threshold. To redact them too, pass `min_severity: "medium"`:

```bash
# With min_severity: "medium" — IPs and hostnames also redacted
AWS_ACCESS_KEY_ID=__PW{AWS_KEY_1}__
DATABASE_URL=__PW{DB_CONNECTION_1}__
API_TOKEN=__PW{OPENAI_KEY_1}__
ANSIBLE_HOST=__PW{IP_1}__                   # medium — now redacted
INTERNAL_SERVER=__PW{HOSTNAME_1}__           # medium — now redacted
```

The default `high` threshold is intentional — it protects credentials (the highest-damage leak vector) while keeping infrastructure identifiers readable so the agent can reason about architecture.

### Per-agent severity

Different agents may need different thresholds. Use `--min-severity` on the MCP server command to set each agent's default independently:

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

**Precedence chain:** per-request `min_severity` parameter > `--min-severity` CLI flag > `mcpMinSeverity` config field > default (`high`).

This means you can run Claude Code at `high` (default) and Cline at `medium` — each agent's MCP registration controls its own threshold, and any agent can still override per-request when needed.

### Audit logging

Enable audit logging to get proof of what the MCP server did during a session:

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

The log records every tool call with timestamps — what files were read, how many secrets were redacted, what types were found, how many placeholders were resolved on write. Secret values are never logged.

```
2026-02-25T00:30:12Z READ  /app/config.yml  redacted=3 [AWS Key, Credential, Email]
2026-02-25T00:30:15Z WRITE /app/config.yml  resolved=3 unresolved=0
2026-02-25T00:30:18Z CHECK (inline)  clean=true
```

### Important notes

- The MCP tools are **opt-in** — the agent must choose to use them
- Built-in Read/Write tools still bypass pastewatch unless hooks enforce it (see Layer 2b)
- Mappings live in server process memory only — die when MCP server stops
- Same file re-read returns the same placeholders (idempotent within session)

---

## Layer 2b: Enforce MCP Usage via Hooks

MCP tools are opt-in — agents can still use native Read/Write and `cat .env` via Bash, bypassing redaction entirely. Hooks make enforcement structural.

### Bash command guard

The `guard` subcommand intercepts shell commands before execution:

```bash
pastewatch-cli guard "cat .env"
# BLOCKED: .env contains 3 secret(s) (2 critical, 1 high)
# Use pastewatch MCP tools for files with secrets.

pastewatch-cli guard "echo hello"
# exit 0 (safe)
```

It parses shell commands (`cat`, `head`, `tail`, `sed`, `awk`, `grep`, `source`), extracts file arguments, and scans those files for secrets. Unknown commands pass through (exit 0).

Integrate with agent Bash hooks to block commands automatically. See [agent-setup.md](agent-setup.md) for hook configuration per agent.

### `PW_GUARD=0` — escape hatch

`PW_GUARD=0` is a native feature of pastewatch-cli. When set, `guard` and `scan --check` exit 0 immediately — every hook that calls pastewatch-cli gets the bypass for free.

```bash
export PW_GUARD=0    # disable for current shell session
unset PW_GUARD       # re-enable
```

This is **agent-proof by design**: the guard runs in the hook's process, not the agent's shell. The agent cannot set `PW_GUARD=0` to bypass it — only the human can, before starting the agent session. The bypass requires human action outside the agent's control.

Use it when editing detection rules, working with test fixtures, or handling files with intentional secret-like patterns.

---

## Layer 3: Restrict Agent File Access

Limit which files the agent can read. Fewer files exposed = fewer secrets at risk.

**Claude Code** — `.claude/settings.json`:
```json
{
  "permissions": {
    "deny": [
      "Read(path:**/.env*)",
      "Read(path:**/credentials*)",
      "Read(path:**/secrets/**)"
    ]
  }
}
```

**General principle:** Keep secrets in dedicated directories or files with predictable names. Restrict agent access to those paths.

---

## Layer 4: Pre-commit Safety Net

Catches secrets before they're committed — including secrets an agent may have written into code.

```bash
# Install pastewatch pre-commit hook
pastewatch-cli hook install

# Or use pre-commit.com framework
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ppiankov/pastewatch
    rev: v0.17.0
    hooks:
      - id: pastewatch
```

This catches cases where:
- An agent writes a new secret into code
- An agent copies a secret from one file to another
- Config changes accidentally expose credentials

---

## Layer 5: Pre-session Scanning

Before starting an agent session on a project:

```bash
# Full scan
pastewatch-cli scan --dir . --check

# Only fail on critical (API keys, credentials, connection strings)
pastewatch-cli scan --dir . --check --fail-on-severity critical

# Detailed report
pastewatch-cli scan --dir . --format markdown --output /tmp/scan-report.md
```

Fix findings before the agent reads them. The cheapest secret to protect is the one that's not in a file.

---

## Layer 6: Baseline for Existing Projects

For projects with known historical secrets that can't be cleaned up immediately:

```bash
# Create baseline of current findings
pastewatch-cli baseline create --dir . --output .pastewatch-baseline.json

# Only flag new secrets (ignore baseline)
pastewatch-cli scan --dir . --baseline .pastewatch-baseline.json --check
```

This lets you adopt agent safety incrementally without blocking work on legacy codebases.

---

## Summary

| Layer | What it does | Effort |
|-------|-------------|--------|
| 1. No secrets in code | Eliminate the source | High (best ROI) |
| 2. MCP redacted read/write | Secrets stay local during agent sessions | Low (configure once) |
| 2b. Enforce via hooks | Block native Read/Write/Bash when secrets present | Low (configure once) |
| 3. Restrict file access | Limit agent's blast radius | Low |
| 4. Pre-commit hook | Catch secrets before commit | Low (one-time setup) |
| 5. Pre-session scan | Find secrets before agent reads them | Per-session |
| 6. Baseline | Gradual cleanup of legacy codebases | Per-project |

Layers are additive. Use as many as your threat model requires. Layer 2 (MCP redacted read/write) is the most impactful for active agent workflows.

---

## What Pastewatch Covers — and What It Doesn't

Pastewatch protects **credentials** — the highest-damage leak vector. If a key leaks, attackers get immediate access to infrastructure. Pastewatch prevents this structurally.

**What pastewatch protects (secrets never leave your machine):**

| Category | Examples |
|----------|----------|
| API keys | AWS, OpenAI, Anthropic, Stripe, GitHub tokens, etc. |
| Database credentials | Connection strings, passwords in config files |
| SSH/TLS keys | Private key headers |
| Identity data | Emails, phone numbers, IPs |
| Session tokens | JWTs, bearer tokens |
| Platform credentials | Slack/Discord webhooks, Azure/GCP keys |

**What pastewatch does NOT protect:**

| Category | Why |
|----------|-----|
| Prompt content | Your questions and instructions still reach the API |
| Code structure | Architecture, patterns, business logic — visible to the provider |
| Conversation context | What you're building, for whom, why |
| Non-secret data | Domain names, file paths, comments, variable names |

Pastewatch protects your **keys**. For protecting your **ideas**, you need a local model (Ollama, llama.cpp). For protecting your **commands**, you need a local proxy (intercepting before they reach the API).

Think of it as: secrets are the highest-consequence leak — a leaked API key has immediate, measurable damage. Pastewatch eliminates that risk. The other risks (prompt content, business logic) are real but require different tools.
