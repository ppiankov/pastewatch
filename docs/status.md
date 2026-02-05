# Project Status

## Current State

**MVP — Experimental Prototype**

The core functionality works:
- Clipboard monitoring active
- Detection rules implemented
- Obfuscation functional
- macOS menubar app running

Edge cases exist. Feedback welcome.

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
| Menubar UI | ✓ Functional |
| System notifications | ✓ Functional |
| Configuration persistence | ✓ Functional |

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
- Custom pattern definitions
- Keyboard shortcut for pause/resume
- Launch at login option

**Will evaluate carefully:**

- Pattern import/export
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
