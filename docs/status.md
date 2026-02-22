# Project Status

## Current State

**Stable — v0.3.0**

Core and CLI functionality complete:
- Clipboard monitoring and obfuscation (GUI)
- 13 detection types with deterministic regex matching
- CLI: file, directory, and stdin scanning
- SARIF 2.1.0 output for CI integration
- Format-aware parsing (.env, JSON, YAML, properties)
- Allowlist and custom detection rules

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

---

## Known Limitations

| Limitation | Notes |
|------------|-------|
| macOS 14+ only | Uses modern SwiftUI APIs |
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
- Inline allowlist comments (`# pastewatch:allow`)

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
| Cross-platform | macOS-native by design |
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
- [docs/design-baseline.md](design-baseline.md) — Core philosophy
- [docs/hard-constraints.md](hard-constraints.md) — Non-negotiable rules
- [CONTRIBUTING.md](../CONTRIBUTING.md) — Development workflow
