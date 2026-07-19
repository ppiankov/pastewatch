# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.33.0] - 2026-07-19

### Added

- The API proxy now redacts secrets inside **streamed tool-call arguments**. A shared
  event-aware relay reassembles Anthropic `input_json_delta.partial_json` and
  OpenAI-compatible/LiteLLM `tool_calls[].function.arguments` fragments across SSE frames
  before scanning, so a secret split across frame boundaries — or carried in a JSON object
  key, or spelled with `\u` escapes — is still caught. Redaction preserves the exact JSON
  bytes outside authorized replacements; a fragment that cannot be redacted while keeping
  valid JSON is blocked fail-closed rather than forwarded.
- `pastewatch-cli proxy --debug-stream-dump <path>` captures raw upstream frames,
  transformed output, and mutation decisions as owner-only (`0600`) JSONL for local
  protocol diagnosis. Opt-in only, requires the default `per_sse_event` mode (startup
  fails otherwise), contains unredacted secrets by design, and prints a warning even under
  `--quiet`. The dump file is opened no-follow to prevent symlink path substitution.

### Fixed

- A `\u`-escaped secret carried in a **truncated or malformed** tool-call JSON payload is
  no longer forwarded unredacted: complete escaped tokens are decoded and scanned even
  when the aggregate JSON never parses, and any escape that cannot be mapped and scanned
  blocks the frame fail-closed.
- `ProxyServer` serializes the shared `ISO8601DateFormatter`'s lazy cache initialization on
  Linux (swift-corelibs-foundation) so concurrent audit-log timestamping is thread-safe.

## [0.32.0] - 2026-07-17

### Added

- Detect workspace-scoped Alibaba Model Studio (DashScope) API keys with the `sk-ws-`
  prefix, including dot-separated payloads, as intrinsic secrets that are safe to
  obfuscate.

### Changed

- The Anthropic request scanner now also covers `document` and `search-result` content
  blocks, so intrinsic secrets in those payloads are redacted while the block structure
  and opaque execution payloads are preserved.

### Fixed

- Streamed-response redaction no longer drops, duplicates, or mis-orders audit entries
  across malformed, oversized, and post-`[DONE]` streams. Terminal-state (`[DONE]`)
  latching, per-frame scan-before-send ordering, and cross-chunk secret assembly now
  hold on both the macOS and Linux relay paths, so a credential split across raw-stream
  chunk boundaries — including after `[DONE]` — is still redacted.
- Encrypted and opaque code-execution result payloads are preserved intact; only the
  documented plaintext fields beside them are scanned, so replay payloads are never
  corrupted.

## [0.31.1] - 2026-07-17

### Fixed

- Proxy audit dedup no longer collapses distinct request targets into one entry. The
  dedup signature keyed on the sanitized display path, so two genuinely different
  requests whose paths reduced to the same safe form were treated as duplicates and one
  audit entry was dropped. Dedup now keys on an ephemeral non-reversible digest of the
  full request target across all four audit chains (refusal, redaction, advisory, model
  identity), while the written audit line still omits query values.

## [0.31.0] - 2026-07-17

### Added

- `setup <agent>` now reports the real MCP integration status per agent — automatic,
  manual (with the exact config block to paste), or unavailable — and states whether
  `launch` routes that agent through the API proxy. Previously the tables claimed a
  blanket "Yes" for MCP on every agent.
- Codex CLI setup prints the required next step: restart Codex, run `/hooks`, and trust
  the generated Pastewatch hook (Codex skips non-managed hooks until trusted).

### Changed

- Unified `.env` filename classification behind a single `DotenvClassifier` shared by
  every scanner, replacing seven independently drifting `.hasSuffix(".env")` checks.
- Agent-safety and setup documentation now reflect verified per-agent config paths and
  automatic/manual status instead of a uniform claim.

### Fixed

- Guard no longer honors an inline `# pastewatch:allow` comment in a file referenced by
  an agent-controlled command. An agent could write the allow comment into a file it
  controls and then `cat` it to slip a secret past the guard; referenced-file content is
  now scanned as agent-controlled. Operator-named files (guard-read/guard-write, watch)
  still honor inline allow.
- Proxy now redacts plaintext in unknown and mixed content blocks while preserving
  protocol discriminators and base64 payload bytes intact.

## [0.30.0] - 2026-07-15

### Added

- Standalone detection for provider tokens that were previously only caught next to a
  keyword: HashiCorp Vault (`hvs.`/`hvb.`/`hvr.` and legacy one-letter tokens), Slack
  (`xoxb-`/`xoxp-`/`xapp-`/…), Google API keys (`AIza…`), Docker access tokens, and the
  current GitHub token formats. A real token now redacts wherever it appears, not only in
  `KEY=value` context.
- Whole-secret containment for structured credentials: SSH private-key PEM blocks and GCP
  service-account JSON are captured as complete payloads instead of a single marker line,
  without overcapturing adjacent content.

### Changed

- **Mutation is now authorized by evidence, not by shape alone.** A value is rewritten only
  when it is an intrinsic (unambiguous-format) secret, an exact known value, or a match for
  an operator custom rule. Format-only ambiguous matches — DSNs, JDBC URLs, and generic
  `credential`/API-key keyword hits — are now **advisory-only**: detected and reported
  off-band but never rewritten, so a DSN-shaped example in a schema, prompt, or tool
  description no longer corrupts a working request. `--severity` and request-field context
  affect advisory volume only, never what gets mutated. Promote a value to mutation with a
  custom rule.
- The Anthropic request scanner now covers tool contracts, `input_schema`, input examples,
  message text, tool inputs/results, and stop sequences under the same evidence policy, and
  fails closed on malformed tool/stop containers, malformed private-key containers, invalid
  routed-proxy custom rules, and request-body serialization failures.
- The proxy is documented as **one-way** (redact outbound). Reversible restoration — the
  agent works with real values while the model sees only placeholders — remains the MCP
  read/write round-trip, not a proxy-response capability.

### Fixed

- The Vault legacy one-letter token grammar (`s.`/`b.`/`r.`) is tightened to exactly 24
  base62 characters, so code-like dotted identifiers (`s.someMethodName`,
  `r.snake_case_ident`) are never mistaken for a token and rewritten.
- Azure Storage connection-string detection no longer consumes bytes following the
  base64 `AccountKey` value.
- The proxy no longer logs a benign client disconnect (Esc/interrupt closing the socket
  mid-response) as an error under `launch`; `EPIPE`/`ECONNRESET` and quiet mode are honored.
- Launch loopback cleanup, termination handling, and refused-request accounting hardened.

## [0.29.0] - 2026-07-12

### Added

- The API proxy now **streams SSE responses incrementally** instead of buffering the whole
  response. Fixes context compaction on Sonnet (and any long streamed generation) hanging at ~95%
  and then looping — the proxy no longer waits for the entire response before relaying a single byte.
- Per-SSE-event redaction: secrets in a streamed response are redacted frame-by-frame as they arrive,
  without ever buffering the whole stream (buffer at most one SSE event).
- `responseStreamingRedactionMode` config key (`per_sse_event` default, `raw_stream`, `buffer`) to
  control response-stream handling.

### Changed

- **Zero false-positive mutation is now a hard invariant.** The proxy obfuscates/restores bytes only
  for deterministic secret classes (API keys, tokens, DSNs, JWTs, SSH keys, Luhn-valid cards) and
  operator-approved custom rules. Ambiguous built-ins (email, phone, IP, hostname, file path, UUID)
  are **advisory-only** and are never mutated, regardless of `--severity`. `--severity` now controls
  advisory reporting volume, not what gets rewritten. Promote an ambiguous pattern to mutation by
  adding a custom rule.
- Streaming, buffered-response, Linux-response, and request-side redaction now share one certainty-based
  mutation rule (no path divergence).

### Fixed

- The 120-second whole-response timeout that caused compaction to return 504 and retry-loop is replaced
  with an **idle timeout** (fails only when no bytes arrive for the idle window), so a long-but-progressing
  stream succeeds. Non-streaming responses use a 600s ceiling.
- macOS `URLSession` request/resource timeouts no longer undercut the proxy's non-streaming ceiling.

## [0.28.0] - 2026-07-02

### Added

- `proxy` and `launch` gain `--ca-cert <path>` to trust a private/corporate CA bundle for the
  upstream TLS handshake (added on top of the system trust store), and `--insecure` to skip upstream
  TLS verification entirely (prints a warning). These make the proxy usable in front of an LLM
  gateway or corporate API endpoint whose certificate chains to a private CA. Both govern only the
  proxy-to-upstream connection; default behavior is unchanged (full system-trust verification).

### Fixed

- The proxy now preserves a non-root upstream base path when forwarding. Pointing `--upstream` at a
  gateway pass-through URL (e.g. `https://host/v1/passthrough`) previously dropped the base path
  because the agent's absolute request target replaced it; the base path and request path are now
  joined correctly.

## [0.27.0] - 2026-06-09

### Added

- `pastewatch-cli launch` runs a startup sweep that warns once per changed shell startup file when
  common shell/config files (`.zshrc`, `.zshenv`, `.bashrc`, fish config, `.envrc`, …) contain
  pre-existing credential candidates; use `--no-startup-sweep` to disable. Findings only warn — they
  never block launch, auto-edit files, or rotate credentials.

### Fixed

- `pastewatch-cli guard` no longer flags quote-wrapped environment-variable references
  (`KEY="$VAR"`, `KEY="${VAR}"`, `KEY="${VAR:-default}"`, single-quoted, and quoted `%VAR%`) as
  inline credentials. Literal secrets — including quoted and backtick-wrapped — still block.
- `pastewatch-cli guard --json` redacts inline credential values in the emitted `command` field
  instead of echoing them, covering every detected inline finding regardless of the
  `--fail-on-severity` block threshold.
- `pastewatch-cli launch --help` (and `-h`, in any flag order) prints help and exits without running
  the startup sweep, starting the proxy, mutating `ANTHROPIC_BASE_URL`, or launching an agent.

## [0.26.7] - 2026-06-07

### Added

- File IO redaction can consume NR-compatible shared secret-pattern artifacts, so generated pattern
  sources cover pastewatch read/write redaction without copying detector lists.
- Shared-pattern manifests record the NR source/provenance fields while pastewatch keeps its
  proxy-compatible `__PW_TYPE_N__` MCP placeholders.
- Shared-pattern coverage extends to single-file CLI scans, `pastewatch_scan_file`, and the plain
  stdin scan path.

### Fixed

- Fail closed when a configured `sharedPatternFiles` artifact is missing, malformed, unsupported, or
  contains an invalid regex — scans return exit 2 instead of a false clean result. Covers directory,
  git diff/history, file watcher, guard read/write, single-file, MCP, and empty-stdin paths.
- The generated pre-commit hook blocks the commit on any non-zero `pastewatch-cli scan --check`
  result, not just exit 6 for findings.
- Shared-pattern matches preserve their manifest type and policy metadata through redaction: policy
  `block`/`redact`/`warn` map to critical/high/medium severity, and typed rules use the matching
  placeholder category instead of collapsing to `__PW_CREDENTIAL_N__`.
- MCP redacted round-trip (`pastewatch_read_file` → `pastewatch_write_file`) no longer corrupts
  content when an emoji or other astral-plane character precedes a redacted value. Placeholder
  resolution converted a UTF-16 range with grapheme-cluster offsets, drifting after surrogate
  pairs; it now uses an exact `Range(_:in:)` conversion so the original bytes restore faithfully.

## [0.26.6] - 2026-05-16

### Added

- Detection for ObstaLabs license keys (`ol_` prefix with Ed25519 signature payload)
- Detection for Resend API keys (`re_` prefix, 24+ alphanumeric chars)
- Detection for Stripe webhook secrets (`whsec_` prefix) — previously only caught in key=value context
- `pastewatch-cli setup codex` — installs PreToolUse guard hook for Codex CLI (`~/.codex/hooks.json`); covers `Read|Write|Edit|apply_patch|Bash`
- `pastewatch-cli setup qwen-code` — installs PreToolUse guard hook + MCP for Qwen Code (`~/.qwen/settings.json`)
- Codex CLI and Qwen Code upgraded from Proxy only to **Structural** protection in the agent safety matrix

### Changed

- Version is now a single constant (`PastewatchCore.AppVersion.current`) consumed by all call sites — eliminates the class of bug where a misplaced tag ships a binary with a stale version literal
- New `scripts/bump-version.sh` and `make bump VERSION=X.Y.Z` atomically update Version.swift, README, docs, and CHANGELOG in one command
- New `validate-tag` CI job fails the release immediately if the source version constant doesn't match the pushed tag

## [0.26.4] - 2026-05-16

### Added

- Detection for ObstaLabs license keys (`ol_` prefix with Ed25519 signature payload)
- Detection for Resend API keys (`re_` prefix, 24+ alphanumeric chars)
- Detection for Stripe webhook secrets (`whsec_` prefix) — previously only caught in key=value context
- `pastewatch-cli setup codex` — installs PreToolUse guard hook for Codex CLI (`~/.codex/hooks.json`); covers `Read|Write|Edit|apply_patch|Bash`
- `pastewatch-cli setup qwen-code` — installs PreToolUse guard hook + MCP for Qwen Code (`~/.qwen/settings.json`)
- Codex CLI and Qwen Code upgraded from Proxy only to **Structural** protection in the agent safety matrix

### Changed

- Version is now a single constant (`PastewatchCore.AppVersion.current`) consumed by all call sites — eliminates the class of bug where a misplaced tag ships a binary with a stale version literal
- New `scripts/bump-version.sh` and `make bump VERSION=X.Y.Z` atomically update Version.swift, README, docs, and CHANGELOG in one command
- New `validate-tag` CI job fails the release immediately if the source version constant doesn't match the pushed tag

## [0.26.3] - 2026-05-14

### Fixed

- Release pipeline shipped 0.26.1 binary under the v0.26.2 Homebrew formula — tag v0.26.2 pointed to a commit before the version-bump, so every Sources/ literal still read 0.26.1. v0.26.3 corrects version literals and is tagged at the correct commit

## [0.26.2] - 2026-04-06

### Fixed

- Proxy 502 Bad Gateway on Linux arm64 — `URLSession.dataTask` completion handlers silently fail on FoundationNetworking/arm64. Proxy now uses `Process` + `curl` on Linux for reliable upstream HTTP
- Proxy handles all requests on Linux (non-streaming and streaming) without hanging

### Changed

- Project marked feature-complete — accepting compatibility and bug fixes only

## [0.26.1] - 2026-04-06

### Fixed

- Proxy silent death on client disconnect — SIGPIPE now ignored instead of killing the process
- Proxy upstream timeout (120s) to prevent hung connections from blocking threads indefinitely

### Known Limitations

- Proxy handles one session at a time — it does not multiplex multiple concurrent agent sessions

## [0.26.0] - 2026-03-29

### Added

- **Agent Safety Matrix** in README — comprehensive table showing protection level for all 15 supported agents
- **Proxy alert screenshot** in README — real-world example of 27 secrets redacted from a tool call
- **8 new agents** in `pastewatch-cli setup`:
  - **Cursor** — structural enforcement via `preToolUse` hooks (exit 2 + JSON deny protocol)
  - **Roo Code** — structural enforcement, reuses Cline hook protocol (JSON cancel)
  - **Windsurf** — structural enforcement via `pre_read_code`/`pre_write_code`/`pre_run_command` hooks
  - **Continue** — structural enforcement via Claude Code-compatible `PreToolUse` hooks
  - **Amazon Q** — structural enforcement via `preToolUse` hooks
  - **GitHub Copilot** — structural enforcement via `preToolUse` hooks (`.github/hooks/` config)
  - **Goose** — MCP setup (advisory, YAML config), upstream hook issue filed ([block/goose#8184](https://github.com/block/goose/issues/8184))
  - **Kilo Code** — MCP setup (advisory), upstream hook issue filed ([Kilo-Org/kilocode#7859](https://github.com/Kilo-Org/kilocode/issues/7859))
  - **Gemini Code Assist** — MCP setup (advisory, `~/.gemini/settings.json`)
  - **Aider** — proxy-only (no MCP support yet, [aider-ai/aider#4506](https://github.com/aider-ai/aider/issues/4506))
- Upstream hook support issue commented on [openai/codex#14754](https://github.com/openai/codex/issues/14754) for Codex CLI

### Changed

- API proxy (`launch`) positioned as default/recommended setup in all docs
- Cursor upgraded from advisory to structural enforcement
- `docs/agent-safety.md` Layer 0 section updated to use `launch` command
- `docs/agent-setup.md` restructured: proxy first, then MCP registration
- `docs/agent-integration.md` restructured with proxy as section 1, all sections renumbered
- `docs/CLAUDE-SNIPPET.md` now includes proxy setup section

## [0.25.8] - 2026-03-28

### Added

- Proxy log shows type breakdown per redaction (`Credential x3, DB Connection x2`)
- Proxy log includes actionable fix suggestion for the human operator
- Proxy log deduplicates repeated lines when conversation history re-scans same secrets

## [0.25.7] - 2026-03-28

### Fixed

- Launch command strips leading `--` from passthrough args (fixes `execvp: No such file or directory`)

## [0.25.6] - 2026-03-28

### Added

- Proxy alert now includes actionable fix suggestion per secret type (use env vars, store in key file, use detectable keywords)

## [0.25.5] - 2026-03-27

### Added

- Credential storage rules in CLAUDE.md snippet — prevents agents from echoing or storing plaintext credentials
- Setup step added to Quick Start — `pastewatch-cli setup claude-code` is now essential, not optional

## [0.25.4] - 2026-03-27

### Fixed

- Credential false positives — documentation text like `password: rotated`, `token: POST` no longer triggers detection
- Proxy stderr log suppressed in launch mode to prevent TUI interference with interactive CLIs
- Added `--quiet` flag to `proxy` command

## [0.25.3] - 2026-03-27

### Fixed

- Launch command uses fork/exec for proper TTY passthrough to interactive agents

## [0.25.2] - 2026-03-27

### Fixed

- Launch command now passes TTY through to agent for interactive CLIs

## [0.25.1] - 2026-03-27

### Added

- Bash command argument scanning — guard now scans full command string for inline secrets (DSNs, API keys, tokens)
- Bash tool handling in shell guard hook — blocks commands containing secrets before execution
- Test credential exclusions — AWS EXAMPLE keys and Stripe `sk_test_` keys bypass guard blocking
- CodeQL code scanning and Dependabot dependency monitoring

### Fixed

- VS Code extension workflow skips publish when version unchanged

## [0.25.0] - 2026-03-26

### Added

- `launch` command: one-step proxy + agent startup (`pastewatch-cli launch claude`)
- Starts proxy in background, waits for TCP readiness, launches agent with `ANTHROPIC_BASE_URL` set
- Cleans up proxy on agent exit, forwards exit codes
- `--quiet` flag to suppress proxy messages
- Universal macOS binary (arm64 + x86_64) in release workflow
- Multi-platform Homebrew formula (macOS, Linux amd64, Linux arm64)

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
