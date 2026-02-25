# Project: pastewatch

## New Agent? Start Here
Run `/load-context` to read project context, work orders, and current status before doing anything.

## Commands
- `make build` — Build debug binary
- `make release` — Build release binary
- `make test` — Run tests
- `make lint` — Run SwiftLint (--strict)
- `make fmt` — Format with SwiftFormat
- `make build-cli` — Build CLI debug binary only
- `make release-cli` — Build CLI release binary only
- `make app` — Build macOS app bundle
- `make dmg` — Build DMG installer
- `make clean` — Clean build artifacts

## Architecture
- **PastewatchCore** (library): detection rules, types, obfuscation, formatters, scanner, MCP protocol
- **PastewatchCLI** (executable): Cobra-style CLI via swift-argument-parser
- **Pastewatch** (executable): SwiftUI menu bar app, macOS 14+ only
- Entry: `Sources/PastewatchCLI/PastewatchCLI.swift` (CLI), `Sources/Pastewatch/PastewatchApp.swift` (GUI)
- Subcommands: scan, init, baseline, hook, mcp, explain, config, version

## What pastewatch Is
Local-only clipboard guardian. Deterministic detection of sensitive data via regex/heuristics. Obfuscates before paste. Offline. Minimal. Silent by default.

## What pastewatch Is NOT
- Not a DLP system or compliance product
- Not ML/AI-powered — deterministic only
- Not a browser extension or LLM proxy
- Not a monitoring/logging tool — no clipboard history
- Not a network tool — no telemetry, no cloud, no sync
- Not a policy engine or SAST replacement

## Conventions
- Swift 5.9, macOS 14+ deployment target
- SwiftLint (strict), SwiftFormat
- PastewatchCore holds all shared logic — CLI and GUI depend on it
- 29 detection types with severity levels (critical/high/medium/low)
- Output formats: text, json, sarif, markdown
- Exit codes: 0 (clean), 1 (error), 2 (invalid args), 6 (findings)
- Config cascade: CWD `.pastewatch.json` > `~/.config/pastewatch/config.json` > defaults

## Anti-Patterns
- NEVER make network calls — no telemetry, analytics, update checks, cloud processing
- NEVER use ML or probabilistic detection — regex and heuristics only
- NEVER store clipboard history or persist sensitive data — memory-only state
- NEVER block paste — obfuscate, never prevent
- NEVER require configuration for secure operation — safe defaults always
- NEVER add engagement features, dashboards, or gamification
- NEVER use NSPredicate for pattern matching — unavailable on Linux, use pure Swift
- NEVER put real secrets in test files or examples — pre-commit hook blocks AKIA patterns, ghp_ tokens, postgres:// URIs, eyJ prefixes
- NEVER exceed SwiftLint cyclomatic complexity of 15 — extract helpers early

## Platform Gotchas
- NSPredicate(format:_:) unavailable in swift-corelibs-foundation on Linux
- Darwin.exit() unavailable on Linux — use `throw ExitCode()`
- swift-crypto required on Linux only (conditional in Package.swift)
- Pre-commit hook scans for secret patterns in staged diffs — sanitize examples

## Verification
- Run `make test` after code changes (211 tests as of v0.7.0)
- Run `make lint` before marking complete
- Test on both macOS and Linux (CI covers both)

## Release Process
- Version strings in: PastewatchCLI.swift, VersionCommand.swift, ScanCommand.swift (SARIF)
- Tag triggers release workflow: builds macOS app + DMG + CLI, Linux CLI binary
- Update homebrew-tap: `Formula/pastewatch.rb` (version + SHA256, must include explicit `version`)
- Update pastewatch-action: `action.yml` default version
- Move v1 tag on pastewatch-action after release
