# Security Policy

## Design Philosophy

Pastewatch is designed with security as a core constraint, not a feature.

**Pastewatch operates locally.** There is no server. No telemetry. No network calls.

The clipboard content never leaves your machine.

## Threat Model

### What Pastewatch Protects Against

| Threat | Protection |
|--------|------------|
| Accidental paste of secrets into AI chat | Obfuscation before paste |
| Credential leakage to LLM training data | Data never reaches the service |
| API key exposure in prompts | Pattern-based detection and replacement |

### What Pastewatch Does NOT Protect Against

| Threat | Why Not |
|--------|---------|
| Malicious apps reading clipboard | OS-level concern, not in scope |
| Screenshots of sensitive data | Visual, not text-based |
| Intentional bypass by user | User agency is preserved |
| Unknown secret formats | Conservative detection only |
| Clipboard history apps | Third-party tools outside control |

### Limitations

Pastewatch is an **MVP prototype**. Known limitations:

1. **Detection is conservative** — Unknown secret formats will not be detected
2. **No encryption** — Obfuscated content uses plaintext placeholders
3. **No audit log** — Obfuscation events are not logged
4. **Memory only** — Mappings are not persisted (by design)
5. **macOS only** — No Windows/Linux support

## Security Boundaries

### What Pastewatch Can Access

- System clipboard (read and write)
- Configuration file at `~/.config/pastewatch/config.json`
- System notification service

### What Pastewatch Cannot Access

- Network
- Other applications' data
- Keychain
- File system (beyond config)
- Screen content

## Responsible Disclosure

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email the maintainer directly (see GitHub profile)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
4. Allow 90 days for response before public disclosure

## Security Updates

Security fixes will be released as patch versions (e.g., 0.1.1) and documented in CHANGELOG.md.

## Verification

All releases include SHA256 checksums. Verify downloads:

```bash
shasum -a 256 -c Pastewatch-vX.X.X.dmg.sha256
```

## No Warranty

This software is provided as-is. It does not guarantee security or compliance.

See LICENSE for full terms.
