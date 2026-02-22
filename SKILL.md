---
name: pastewatch
description: "Sensitive data scanner — deterministic detection and obfuscation for text content"
user-invocable: false
metadata: {"requires":{"bins":["pastewatch-cli"]}}
---

# pastewatch-cli — Sensitive Data Scanner

You have access to `pastewatch-cli`, a tool that scans text for sensitive data patterns and either reports findings or outputs obfuscated text. All detection is deterministic regex-based pattern matching with no ML or network calls.

## Install

```bash
brew install ppiankov/tap/pastewatch
```

Or download binary:

```bash
curl -LO https://github.com/ppiankov/pastewatch/releases/latest/download/pastewatch-cli_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m).tar.gz
tar -xzf pastewatch-cli_*.tar.gz
sudo mv pastewatch-cli /usr/local/bin/
```

## Commands

| Command | What it does |
|---------|-------------|
| `pastewatch-cli scan` | Scan text for sensitive data (default subcommand) |
| `pastewatch-cli version` | Print version |

## Key Flags

| Flag | Description |
|------|-------------|
| `--file` | File to scan (reads from stdin if omitted) |
| `--format` | Output format: text (default), json |
| `--check` | Check mode: exit code only, no output modification |

## Detection Types

| Type | What it matches |
|------|----------------|
| Email | Email addresses |
| Phone | International and local phone numbers (10+ digits) |
| IP | IPv4 addresses (excludes localhost, broadcast) |
| AWS Key | AKIA/ABIA/ACCA/ASIA key IDs and 40-char secret keys |
| API Key | Generic keys (sk-, pk-, api_, token_), GitHub tokens, Stripe keys |
| UUID | Standard UUID v4 format |
| DB Connection | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| SSH Key | RSA, DSA, EC, OPENSSH private key headers |
| JWT | Three-segment base64url tokens (eyJ...) |
| Card | Visa, Mastercard, Amex, Discover with Luhn validation |
| File Path | Infrastructure paths (/home, /var, /etc, /root, /usr, /tmp, /opt) |
| Hostname | Fully qualified domain names (excludes safe public hosts) |
| Credential | Key-value pairs with password, secret, token, api_key keywords |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no sensitive data found |
| `1` | Internal error |
| `2` | Invalid arguments (e.g. file not found) |
| `6` | Findings detected |

## Agent Usage Patterns

### Pre-commit hook

```bash
git diff --cached --diff-filter=d | pastewatch-cli scan --check
```

### CI pipeline scan

```bash
pastewatch-cli scan --file config.yml --check --format json
```

### Obfuscate before sharing

```bash
cat debug.log | pastewatch-cli scan > sanitized.log
```

### JSON output example

```json
{
  "count": 2,
  "findings": [
    {
      "type": "Email",
      "value": "admin@internal.corp.net"
    },
    {
      "type": "AWS Key",
      "value": "AKIA****************"
    }
  ],
  "obfuscated": "contact ****@**** about key ****"
}
```

In check mode (`--check --format json`), the `obfuscated` field is null and the tool writes to stdout then exits with code 6 if findings exist.

## What pastewatch Does NOT Do

- No ML or probabilistic scoring — deterministic regex matching only
- No network calls — all detection is local, offline
- No clipboard modification in CLI mode — reads input, writes output
- No persistent state — every invocation is stateless
- No blocking or interception — reports findings, does not prevent actions
