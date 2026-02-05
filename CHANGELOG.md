# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
