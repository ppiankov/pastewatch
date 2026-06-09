# Project Status

## Current State

**Stable, feature-complete - v0.27.0**

Accepting compatibility, safety, and bug fixes only. No major new features planned.

Core and CLI functionality complete:
- Clipboard monitoring and obfuscation (GUI)
- 30 detection types with severity levels (critical/high/medium/low)
- CLI: file, directory, stdin, git-diff, and git-log scanning
- Linux binary for CI runners
- SARIF 2.1.0 and markdown output with severity-appropriate levels
- Format-aware parsing (.env, JSON, YAML, properties)
- Allowlist, custom detection rules with custom severity, inline allowlist comments
- MCP server for AI agent integration with per-agent severity thresholds
- Bash command guard with pipe chains, subshells, redirects, database CLIs, infra tools
- Read/Write tool guards for Claude Code hooks
- Baseline diff mode for existing projects
- Pre-commit hook installer + pre-commit.com framework integration
- Project-level config init, resolution, and validation
- fix subcommand for secret externalization to env vars
- inventory subcommand for secret posture reports with compare mode
- doctor subcommand for installation health checks
- setup subcommand for one-command agent integration
- report subcommand for MCP audit log session reports
- canary subcommand for leak detection honeypots
- VS Code extension with real-time diagnostics
- Entropy-based detection (opt-in)
- --stdin-filename, --fail-on-severity, --output, --ignore flags
- .pastewatchignore for glob-based path exclusion
- explain and config check subcommands

---

## What Works

| Feature | Status |
|---------|--------|
| Email detection | ✓ Stable |
| Phone detection (intl + US) | ✓ Stable |
| IP address detection | ✓ Stable |
| AWS key detection | ✓ Stable |
| Generic API key detection | ✓ Stable |
| GitHub token detection | ✓ Stable |
| Stripe key detection | ✓ Stable |
| OpenAI key detection | ✓ Stable |
| Anthropic key detection | ✓ Stable |
| Hugging Face token detection | ✓ Stable |
| Groq key detection | ✓ Stable |
| npm token detection | ✓ Stable |
| PyPI token detection | ✓ Stable |
| RubyGems token detection | ✓ Stable |
| GitLab token detection | ✓ Stable |
| Telegram bot token detection | ✓ Stable |
| SendGrid key detection | ✓ Stable |
| Shopify token detection | ✓ Stable |
| DigitalOcean token detection | ✓ Stable |
| UUID detection | ✓ Stable |
| JWT detection | ✓ Stable |
| DB connection string detection | ✓ Stable |
| SSH private key detection | ✓ Stable |
| Credit card detection (Luhn) | ✓ Stable |
| File path detection | ✓ Stable |
| Hostname detection | ✓ Stable |
| Credential detection | ✓ Stable |
| Menubar UI | ✓ Functional |
| System notifications | ✓ Functional |
| Configuration persistence | ✓ Functional |
| CLI scan (file/stdin) | ✓ Stable |
| CLI directory scanning | ✓ Stable |
| SARIF 2.1.0 output | ✓ Stable |
| Format-aware parsing | ✓ Stable |
| Allowlist | ✓ Stable |
| Custom detection rules | ✓ Stable |
| MCP server | ✓ Stable |
| Baseline diff mode | ✓ Stable |
| Pre-commit hook installer | ✓ Stable |
| Config init / resolution | ✓ Stable |
| Linux CLI binary | ✓ Stable |
| Severity levels | ✓ Stable |
| Inline allowlist comments | ✓ Stable |
| Pre-commit framework | ✓ Stable |
| Stdin filename hint | ✓ Stable |
| Slack Webhook detection | ✓ Stable |
| Discord Webhook detection | ✓ Stable |
| Azure Connection String detection | ✓ Stable |
| GCP Service Account detection | ✓ Stable |
| --fail-on-severity threshold | ✓ Stable |
| --output file reporting | ✓ Stable |
| Markdown output format | ✓ Stable |
| Custom rule severity | ✓ Stable |
| .pastewatchignore | ✓ Stable |
| explain subcommand | ✓ Stable |
| config check subcommand | ✓ Stable |
| MCP redacted read/write | ✓ Stable |
| Agent safety guide | ✓ Stable |
| LLM key detection (OpenAI, Anthropic, HF, Groq) | ✓ Stable |
| Registry token detection (npm, PyPI, RubyGems) | ✓ Stable |
| Platform token detection (GitLab, Telegram, SendGrid, Shopify, DO) | ✓ Stable |
| ClickHouse connection string detection | ✓ Stable |
| MCP audit logging (--audit-log) | ✓ Stable |
| MCP per-agent severity (--min-severity) | ✓ Stable |
| Guard: Bash command scanning | ✓ Stable |
| Guard: pipe chains, command chaining | ✓ Stable |
| Guard: scripting interpreters | ✓ Stable |
| Guard: file transfer tools (scp, rsync, ssh) | ✓ Stable |
| Guard: infrastructure tools (terraform, docker, kubectl) | ✓ Stable |
| Guard: database CLIs (psql, mysql, redis-cli) | ✓ Stable |
| Guard: redirect operators, subshell extraction | ✓ Stable |
| Guard: inline value scanning (connection strings, passwords) | ✓ Stable |
| Guard-read / guard-write (Read/Write tool hooks) | ✓ Stable |
| Startup sweep (pre-existing shell-config credential warning) | ✓ Stable |
| Fix subcommand (secret externalization) | ✓ Stable |
| Inventory subcommand (posture reports) | ✓ Stable |
| Doctor subcommand (health check) | ✓ Stable |
| Setup subcommand (agent auto-setup) | ✓ Stable |
| Report subcommand (MCP session report) | ✓ Stable |
| Canary subcommand (leak detection honeypots) | ✓ Stable |
| Git diff scanning (--git-diff) | ✓ Stable |
| Git history scanning (--git-log) | ✓ Stable |
| Entropy-based detection (opt-in) | ✓ Stable |
| VS Code extension | ✓ Stable |
| safeHosts / sensitiveHosts config | ✓ Stable |
| sensitiveIPPrefixes config | ✓ Stable |
| allowedPatterns config | ✓ Stable |
| PW_GUARD=0 bypass | ✓ Stable |
| Homebrew distribution | ✓ Stable |

---

## Known Limitations

| Limitation | Notes |
|------------|-------|
| GUI macOS 14+ only | Uses modern SwiftUI APIs (CLI works on Linux) |
| Polling-based | 500ms interval, not event-driven |
| String content only | Images, files not scanned |
| English-centric patterns | Phone formats may miss some regions |
| No undo | Original content not recoverable |

---

## Future Directions

**Considered for future versions:**

- Additional regional phone formats
- Keyboard shortcut for pause/resume
- Launch at login option

**Will evaluate carefully:**

- Detection statistics (local only)

---

## Non-Goals

**These will never be in scope:**

| Feature | Reason |
|---------|--------|
| Cloud sync | Violates local-only constraint |
| ML detection | Violates deterministic constraint |
| Clipboard history | Violates memory-only constraint |
| Cross-platform GUI | macOS-native by design (CLI is cross-platform) |
| Browser extension | Different tool, different boundary |
| Compliance certification | Not a compliance product |
| Enterprise features | Not an enterprise tool |
| Telemetry | Not negotiable |
| Premium tier | Not a business |

If you need these features, Pastewatch is not the right tool.

---

## Version History

See [CHANGELOG.md](../CHANGELOG.md) for detailed version history.

---

## Contributing

Before proposing changes, read:
- [docs/hard-constraints.md](hard-constraints.md) - Design philosophy and non-negotiable rules
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development workflow
