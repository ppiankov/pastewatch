# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.24.1] - 2026-03-26

### Fixed

- Workledger key regex now matches 32+ base64url chars (was exactly 44, real keys are 43)
- Standalone `wl_sk_` keys without `KEY=` context now detected

## [0.24.0] - 2026-03-26

### Added

- Proxy alert injection: when secrets are redacted, a `[PASTEWATCH]` alert is prepended to the API response so the agent gets immediate feedback
- `--alert` / `--no-alert` flag on `proxy` command (default: on)
- Type names included in alert (deduplicated, sorted)
- Pass-through on non-JSON, error responses, or missing content array

## [0.23.3] - 2026-03-26

### Fixed

- New detection types (Workledger Key, Oracul Key, JDBC URL, etc.) now auto-enable in existing configs
- Previously, configs saved before new types were added silently missed them

## [0.23.2] - 2026-03-25

### Added

- Path-based protection for `~/.openclaw/` directory in guard commands
- Configurable `protectedPaths` in `config.json` (default: `["~/.openclaw"]`)
- Tests for workledger key detection and path protection (8 new tests)

## [0.23.1] - 2026-03-23

### Added

- Detection rules for Workledger API keys (`wl_sk_` prefix)
- Detection rules for Oracul API keys (`vc_<role>_` prefix)

## [0.23.0] - 2026-03-16

### Added

- `proxy` subcommand: API proxy that scans and redacts secrets from all outbound requests (WO-81)
- `--forward-proxy` flag for corporate proxy chaining
- Catches secrets from subagents that bypass hooks and MCP — the last line of defense

## [0.22.0] - 2026-03-16

## [0.21.0] - 2026-03-15

### Fixed

- Credential regex: exclude boolean values (`auth=true`), Go env lookups (`os.Getenv`), and short values (WO-79)
- AWS Secret Key regex: require keyword context, no longer matches standalone 40-char strings (WO-79)

### Added

- `watch` subcommand: continuous file monitoring with real-time secret detection (WO-59)
- `dashboard` subcommand: aggregate view across multiple audit log sessions (WO-65)
- Gitignore-aware scanning: gitignored files shown with `[gitignored]` prefix but excluded from `--check` exit code (WO-80)
- `--include-gitignored` flag to count gitignored findings toward exit code

## [0.20.0] - 2026-03-13

### Added

- `setup claude-code` auto-injects pastewatch snippet into CLAUDE.md (WO-74)
- `setup` runs `doctor` health check and canary smoke test after configuration (WO-75, WO-78)
- Manual install documentation for environments without Homebrew (WO-76)
- Admin-enforced config layer at `/etc/pastewatch/config.json` — highest priority in cascade (WO-77)

## [0.19.8] - 2026-03-13

### Added

- JDBC URL built-in detection type — Oracle, DB2, MySQL, PostgreSQL, SQL Server, AS/400 (WO-71)
- `init --profile banking` for enterprise onboarding — medium severity, JDBC, RFC 1918 IPs, service account rules (WO-72)

## [0.19.7] - 2026-03-13

### Changed

- MCP placeholder format from `__PW{TYPE_N}__` to `__PW_TYPE_N__` for LLM proxy compatibility (WO-70)

## [0.19.6] - 2026-03-11

### Fixed

- `init` generates complete config with all fields including `placeholderPrefix`

## [0.19.5] - 2026-03-11

### Added

- Configurable `placeholderPrefix` for LLM-proxy compatible redaction placeholders

## [0.19.4] - 2026-03-11

### Added

- XML value parser for ClickHouse and other XML config files
- XML credential detection (`<password>`, `<secret_access_key>`, etc.)
- XML username detection (`<user>`, `<quota_key>`)
- XML hostname detection (`<host>`, `<hostname>`, `<interserver_http_host>`)
- Configurable `xmlSensitiveTags` for custom XML tag scanning

## [0.19.3] - 2026-03-09

### Added

- Perplexity AI API key detection (`pplx-` prefix, critical severity)

## [0.19.2] - 2026-03-07

### Added

- `posture --org <user>` scans all repos in a GitHub org/user for secret posture
- `--repos org/repo` flag for scanning specific repositories
- `--compare` compares with previous posture scan JSON for trend tracking
- `--findings-only` hides clean repositories from output
- Output formats: text, json, markdown

## [0.19.1] - 2026-03-05

### Fixed

- `version` subcommand now reads from CommandConfiguration instead of hardcoded string (was stuck at 0.8.1)

## [0.19.0] - 2026-03-05

### Added

- `fix --encrypt` writes secrets to ChaCha20-Poly1305 encrypted vault (`.pastewatch-vault`) instead of plaintext `.env`
- `--init-key` generates a 256-bit encryption key (`.pastewatch-key`, local-only, mode 0600)
- `vault decrypt` exports vault to `.env` for deployment
- `vault export` prints `export VAR=VALUE` for shell eval
- `vault rotate-key` re-encrypts all entries with a new key
- `vault list` shows vault entries without decrypting values
- `canary generate` creates format-valid but non-functional canary tokens for 7 critical secret types (AWS, GitHub, OpenAI, Anthropic, DB, Stripe, API Key)
- `--prefix` flag embeds identifier in canary values for source tracking
- `canary verify` confirms all canaries are detected by DetectionRules
- `canary check --log` searches external log files for leaked canary values
- `report` subcommand generates session report from MCP audit log: `pastewatch-cli report --audit-log /tmp/pw.log`
- Report aggregates files read/written, secrets redacted, placeholders resolved, output checks, scan findings
- Report outputs text, JSON, markdown formats with `--format` and `--output` flags
- `--since` flag filters report to entries after a given ISO timestamp
- Verdict indicates whether secrets leaked (unresolved placeholders or dirty output checks)
- `setup` subcommand for one-command agent integration: `pastewatch-cli setup claude-code`, `setup cline`, `setup cursor`
- Claude Code setup: writes guard hook script, merges MCP + hook config into settings.json, aligns severity
- Cline setup: merges MCP config, writes hook script, prints hook registration instructions
- Cursor setup: merges MCP config, prints advisory instructions
- `--severity` flag aligns hook blocking and MCP redaction thresholds by construction
- `--project` flag for project-level Claude Code config (`.claude/settings.json`)
- Idempotent: safe to re-run — updates existing config without duplication
- `scan --git-log` scans git commit history for secrets, reporting only the first commit that introduced each finding
- `--range`, `--since`, `--branch` flags for scoping history scans (e.g., `--range HEAD~50..HEAD`, `--since 2025-01-01`)
- Deduplication by fingerprint — same secret across multiple commits is reported once at its introduction point
- All output formats supported: text (commit-grouped), json, sarif, markdown
- `guard` now detects database CLIs: `psql`, `mysql`, `mongosh`, `mongo`, `redis-cli`, `sqlite3` — extracts file flags (`-f`, `--defaults-file`) and positional database files
- `guard` now scans inline values in database commands: connection strings (`postgres://`, `mongodb://`, `redis://`), attached passwords (`-psecret`, `--password=secret`), auth tokens (`-a token`)
- `guard` now strips redirect operators (`>`, `>>`, `2>`, `&>`) from commands and scans input redirect (`<`) source files
- `guard` now extracts and scans subshell commands: `$(cat .env)` and backtick expressions

### Fixed

- CI auto-tag now waits for all jobs (build, test, lint) to pass before tagging
- Release workflow now checks out the tag commit, not main HEAD, for workflow_dispatch triggers
- Release notes now extracted from CHANGELOG.md instead of auto-generated

## [0.17.3] - 2026-03-02

### Added

- `guard` now detects scripting interpreters: `python3`, `python`, `ruby`, `node`, `perl`, `php`, `lua` (skips `-c`/`-e` inline code)
- `guard` now detects file transfer tools: `scp`, `rsync`, `ssh`, `ssh-keygen` (skips remote paths with `:`)
- `guard` now parses pipe chains (`|`) and command chaining (`&&`, `||`, `;`) — each segment scanned independently
- Quoted strings are preserved across pipe/chain splitting (e.g., `grep 'foo|bar'` is not split)

## [0.17.2] - 2026-03-02

### Added

- `guard` now detects infrastructure tools: `ansible-playbook`, `ansible`, `ansible-vault`, `terraform`, `docker-compose`, `docker`, `kubectl`, `helm`
- Extracts file paths from tool-specific flags (`-i`, `-f`, `--env-file`, `-var-file`, etc.) and positional arguments

## [0.17.1] - 2026-03-02

### Added

- `doctor` now shows per-process `--min-severity` and `--audit-log` for each running MCP server
- `doctor` now shows `mcpMinSeverity` from resolved config
- Ready-to-use agent integration examples in `docs/examples/` (Claude Code, Cline, Cursor)

## [0.17.0] - 2026-03-02

### Added

- `mcpMinSeverity` config field — set default MCP redaction threshold in `.pastewatch.json`
- `--min-severity` flag on `mcp` subcommand — per-agent severity thresholds (e.g., `pastewatch-cli mcp --min-severity medium`)
- Severity precedence: per-request `min_severity` > `--min-severity` CLI flag > config `mcpMinSeverity` > default (`high`)

## [0.16.0] - 2026-03-01

### Added

- `doctor` subcommand — installation health check showing CLI version, active config, hook status, MCP server processes, and Homebrew formula version
- `--json` flag for `doctor` for programmatic output

### Fixed

- CI auto-tag now triggers release workflow (uses PAT instead of GITHUB_TOKEN for tag push)
- SwiftLint orphaned doc comment violation in DetectionRules.swift

## [0.15.0] - 2026-03-01

### Added

- `sensitiveHosts` now catches 2-segment hostnames (e.g., `.local` matches `nas.local`)
- `sensitiveIPPrefixes` config field — IP prefixes that override the built-in exclude list (e.g., `172.16.`, `10.`)

### Fixed

- MCP server now reads `.pastewatch.json` and `~/.config/pastewatch/config.json` instead of using hardcoded defaults

## [0.14.1] - 2026-03-01

### Fixed

- MCP redaction now produces consistent placeholders across files — same secret value always maps to same placeholder regardless of which file it appears in

## [0.14.0] - 2026-02-27

### Added

- VS Code extension (`vscode-pastewatch/`): real-time secret detection in the editor
  - Inline diagnostics with severity-mapped squiggles (red/yellow/blue)
  - Hover tooltips showing detection type and severity
  - Quick-fix actions: add inline `pastewatch:allow` or append to `.pastewatch-allow`
  - Status bar with finding count, auto-refresh on save (debounced)
  - CI workflow for build, VSIX packaging, and marketplace publishing

## [0.13.0] - 2026-02-27

### Added

- `inventory` subcommand: generates structured secret posture reports for a directory
  - Output formats: text (default), json, markdown, csv
  - Severity breakdown, hot spots (top 10 files), findings by type, per-entry line numbers
  - `--compare` flag loads a previous JSON inventory and shows added/removed findings
  - `--output` writes report to file instead of stdout
  - Supports `--allowlist`, `--rules`, `--ignore` (same as `scan`)

## [0.12.0] - 2026-02-27

### Added

- Entropy-based secret detection: Shannon entropy scoring as opt-in second pass after pattern rules
  - Threshold 4.0 bits/char, minimum 20 characters, requires 2+ character classes
  - Filters git SHAs, pure alphabetic/numeric strings; severity `.low`
  - Enable via `enabledTypes: ["High Entropy", ...]` in `.pastewatch.json`
- `guard-read` subcommand: blocks Claude Code Read tool on files containing secrets (exit 2)
- `guard-write` subcommand: blocks Claude Code Write tool on files containing secrets (exit 2)
  - Both use format-aware scanning (`.env`, `.json`, `.yml`) unlike the shell-based `guard` command
  - Support `--fail-on-severity`, `PW_GUARD=0` bypass, inline `pastewatch:allow` comments

## [0.11.0] - 2026-02-27

### Added

- `--git-diff` flag for `scan`: scans only added lines in git diff with format-aware parsing and accurate line numbers
  - Staged changes by default, `--unstaged` for working tree changes
  - Proper JSON/YAML/env parsing (scans full file, filters to added lines)
  - Works with `--check`, `--bail`, `--format`, `--fail-on-severity`
  - Replaces raw `git diff | scan` piping with correct per-file scanning

## [0.10.0] - 2026-02-27

### Added

- `fix` subcommand: externalize secrets to environment variables with language-aware code patching
  - `--dry-run` to preview fix plan without applying
  - `--min-severity` to filter by severity threshold (default: high)
  - `--env-file` to specify output .env path
  - Language-aware replacements: Python (`os.environ`), JS/TS (`process.env`), Go (`os.Getenv`), Ruby (`ENV`), Swift (`ProcessInfo`), Shell (`${VAR}`)
  - Auto-generates `.env` file with extracted secrets
  - Warns if `.env` not in `.gitignore`

## [0.9.4] - 2026-02-27

### Added

- `--bail` flag for `scan --dir`: stops at first finding for fast pre-dispatch gate checks (optimized for runforge integration)

## [0.9.3] - 2026-02-27

### Added

- Host suffix matching: leading-dot entries in `safeHosts`/`sensitiveHosts` match any subdomain (e.g., `.company.com` matches `db.company.com`)
- `allowedPatterns` config field: regex-based allowlist for suppressing findings by pattern (e.g., `sk_test_.*` suppresses Stripe test keys)

## [0.9.2] - 2026-02-27

### Added

- `safeHosts` config field: user-defined hostnames excluded from detection (extends built-in safe list)
- `sensitiveHosts` config field: hostnames that always trigger detection, overriding built-in and user safe hosts
- Config validation: warns when a host appears in both lists

## [0.9.1] - 2026-02-26

### Added

- `PW_GUARD=0` environment variable: native bypass for `guard` and `scan --check` — every hook gets the escape hatch for free
- Homebrew formula auto-update in release workflow
- Documentation: guard subcommand in README, enforcement hooks in agent-setup, Layer 2b in agent-safety

## [0.9.0] - 2026-02-26

### Added

- `guard` subcommand: scans files referenced in Bash commands for secrets, blocks commands that would leak sensitive data to cloud APIs
- `CommandParser` for extracting file paths from shell commands (cat, head, tail, sed, awk, grep, source)

### Changed

- Extracted per-type validators in `DetectionRules` to fix cyclomatic complexity lint violation

## [0.8.1] - 2026-02-26

### Fixed

- Reduced false positives: exclude well-known DNS IPs, noreply/bot emails, common system paths, nil UUIDs

## [0.8.0] - 2026-02-26

### Added

- `min_severity` parameter for `pastewatch_read_file` MCP tool (default: `high`) — only redacts findings at or above the threshold
- Built-in safe hosts allowlist for badge services, CI/CD platforms, package registries, and CDNs

## [0.7.2] - 2026-02-26

### Fixed

- MCP audit log now flushes after each write (tool calls were lost when server process was killed)

## [0.7.1] - 2026-02-26

### Fixed

- MCP server no longer responds to JSON-RPC notifications (fixes Cline compatibility)

### Added

- Per-agent MCP setup guide (`docs/agent-setup.md`) covering Claude Code, Claude Desktop, Cline, Cursor, OpenCode, Codex CLI, Qwen Code

## [0.7.0] - 2026-02-25

### Added

- 12 new detection types: OpenAI Key, Anthropic Key, Hugging Face Token, Groq Key, npm Token, PyPI Token, RubyGems Token, GitLab Token, Telegram Bot Token, SendGrid Key, Shopify Token, DigitalOcean Token (all critical severity)
- ClickHouse connection string detection (`clickhouse://`)
- MCP redacted read/write tools (`pastewatch_read_file`, `pastewatch_write_file`, `pastewatch_check_output`) for AI agent secret protection
- MCP audit logging via `--audit-log` flag — proof of what was redacted during agent sessions
- Agent safety guide (`docs/agent-safety.md`) with setup for Claude Code, Cline, and Cursor

## [0.6.0] - 2026-02-23

### Added

- `--fail-on-severity` flag: only exit 6 when findings meet or exceed a severity threshold
- `--output` flag: write report to file instead of stdout
- `--format markdown` output for PR comments via `gh pr comment --body-file`
- `--ignore` flag and `.pastewatchignore` file for glob-based path exclusion
- 4 new credential detection types: Slack Webhook, Discord Webhook, Azure Connection String, GCP Service Account (all critical severity)
- Custom severity on custom rules: `{"name": "...", "pattern": "...", "severity": "low"}`
- `explain` subcommand: show detection type details, severity, and examples
- `config check` subcommand: validate config, custom rules, and severity strings

## [0.5.0] - 2026-02-23

### Added

- Linux binary support (`pastewatch-cli-linux-amd64`) for CI runners
  - 10x cheaper GitHub Actions via `ubuntu` runners instead of `macos`
  - `swift-crypto` for cross-platform SHA256 hashing
- Severity levels on all detection types (critical, high, medium, low)
  - SARIF output uses severity-appropriate levels (error, warning, note)
  - JSON output includes `severity` field on each finding
- Pre-commit framework integration (`.pre-commit-hooks.yaml`)
  - `language: system` hook for pre-commit.com users
- `--stdin-filename` flag for format-aware stdin parsing
  - Enables structured parsing (.env, .json, .yml) when piping via stdin
- Inline allowlist comments (`pastewatch:allow` on any line)
  - Works with `#`, `//`, and `/* */` comment styles
- GitHub Action test workflow for `pastewatch-action`

### Fixed

- CI: pin Linux jobs to `ubuntu-22.04` for Swift 5.9 compatibility

## [0.4.0] - 2026-02-23

### Added

- MCP server (`pastewatch-cli mcp`) — JSON-RPC 2.0 over stdio for AI agent integration
  - Three tools: `pastewatch_scan`, `pastewatch_scan_file`, `pastewatch_scan_dir`
  - Compatible with Claude Desktop, Cursor, and other MCP clients
- Baseline diff mode (`--baseline path` and `baseline create` subcommand)
  - SHA256 fingerprints for suppressing known findings
  - Only new findings are reported when a baseline is provided
- Pre-commit hook installer (`hook install` and `hook uninstall`)
  - Marker-based sections (`# BEGIN PASTEWATCH` / `# END PASTEWATCH`)
  - `--append` flag for existing hooks
  - Worktree-safe via `git rev-parse --git-path hooks`
- Config init (`pastewatch-cli init`) generates `.pastewatch.json` and `.pastewatch-allow`
- Project-level config resolution: CWD `.pastewatch.json` → `~/.config/pastewatch/config.json` → defaults

## [0.3.0] - 2026-02-23

### Added

- SARIF 2.1.0 output format (`--format sarif`) for GitHub code scanning integration
- Directory scanning (`--dir path`) with recursive file discovery
  - Extension whitelist for config, source, and key files
  - Skips .git, node_modules, vendor, build directories
  - Binary file detection
- Format-aware scanning for structured files
  - .env: KEY=VALUE with quote stripping
  - .json: recursive string value extraction
  - .yml/.yaml: line-by-line key: value parsing
  - .properties/.cfg/.ini: key=value with comment handling
- Allowlist for false positive suppression (`--allowlist path`)
  - File-based (one value per line, # comments)
  - Config-based (allowedValues array)
  - Merged from all sources into O(1) lookup
- Custom detection rules (`--rules path`)
  - JSON array of {name, pattern} objects
  - Regex validated at load time
  - Runs after built-in rules with same overlap logic
  - SARIF integration: `pastewatch/CUSTOM_<NAME>` rule IDs
- Line number tracking in DetectedMatch for precise location reporting

## [0.2.0] - 2026-02-22

### Added

- CLI scan mode via `pastewatch-cli` binary
  - `scan` subcommand reads from stdin or file
  - `--check` mode for CI (exit code 6 = findings)
  - `--format json` for structured output
  - `version` subcommand
- New detection types ported from chainwatch nullbot:
  - File Path — Linux system paths (/home, /etc, /var, ...)
  - Hostname — internal FQDNs with safe list filtering
  - Credential — key=value credential pairs (password=, secret=, etc.)
- Safe host list for reducing hostname false positives
- SKILL.md for agent integration
- Agent Integration section in README
- CLI Mode section in README
- Project Status section in README

### Changed

- Package.swift restructured: shared logic extracted to PastewatchCore library
- Tests target PastewatchCore directly
- CI lint job now fails on violations (removed `|| true`)
- Release workflow supports manual dispatch and includes CLI binary

## [0.1.0] - 2026-02-05

### Added

- Initial release
- Clipboard monitoring with configurable polling interval
- Detection rules for:
  - Email addresses
  - Phone numbers (international and US formats)
  - IP addresses (excluding localhost)
  - AWS access keys
  - Generic API keys (sk_, pk_, token_, etc.)
  - GitHub tokens
  - Stripe keys
  - UUIDs
  - Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
  - JWT tokens
  - SSH private keys
  - Credit card numbers (with Luhn validation)
- Obfuscation with stable placeholders per paste
- macOS menubar app with status indicator
- System notifications (optional)
- Configuration via `~/.config/pastewatch/config.json`
- GitHub Actions for CI and releases
