# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
