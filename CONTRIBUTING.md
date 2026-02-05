# Contributing to Pastewatch

Thank you for your interest in contributing.

## Project Philosophy

Before contributing, understand what Pastewatch is and is not:

**Pastewatch is:**
- A local-only utility
- Deterministic and predictable
- Conservative (false negatives > false positives)
- Silent when successful

**Pastewatch is not:**
- A cloud service
- An ML-powered classifier
- A compliance tool
- A logging/monitoring system

If your contribution moves Pastewatch toward the second list, it will be declined.

## Development Rules

1. **Local-only** — No network calls. No telemetry. No exceptions.
2. **Deterministic** — All detection must be regex/rules-based. No ML.
3. **Conservative** — When uncertain, do nothing. False negatives preferred.
4. **Minimal** — If a feature isn't essential, it doesn't exist.
5. **Tested** — All detection rules must have tests.

## Project Structure

```
pastewatch/
├── Sources/Pastewatch/
│   ├── PastewatchApp.swift      # Main app entry
│   ├── Types.swift              # Data models
│   ├── DetectionRules.swift     # Pattern detection
│   ├── Obfuscator.swift         # Value replacement
│   ├── ClipboardMonitor.swift   # Clipboard watching
│   ├── MenuBarView.swift        # UI
│   └── NotificationManager.swift
├── Tests/PastewatchTests/
│   ├── DetectionRulesTests.swift
│   └── ObfuscatorTests.swift
├── Package.swift
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── SECURITY.md
└── LICENSE
```

## Development Workflow

### Prerequisites

- macOS 13.0+
- Xcode 15.0+ or Swift 5.9+

### Building

```bash
# Build
swift build

# Build release
swift build -c release

# Run
swift run

# Test
swift test
```

### Adding Detection Rules

1. Add pattern to `DetectionRules.swift`
2. Add corresponding tests to `DetectionRulesTests.swift`
3. Verify no false positives on common text
4. Document the pattern in README

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run `swift test` — all tests must pass
5. Submit PR with clear description

### Commit Messages

Use clear, descriptive commit messages:

```
Add detection for Slack webhook URLs

- Pattern matches https://hooks.slack.com/...
- Includes tests for valid/invalid formats
- No false positives on regular URLs
```

## What We Accept

- New detection patterns (with tests, conservative)
- Bug fixes (with reproduction case)
- Documentation improvements
- Performance improvements (with benchmarks)

## What We Decline

- ML/AI-based detection
- Cloud features
- Logging/analytics
- Complex configuration
- Features that require network access
- UI complexity beyond current scope

## Questions

Open an issue for discussion before large changes.
