---
name: pastewatch
description: "Sensitive data scanner — deterministic detection and obfuscation for text content"
user-invocable: false
metadata: {"requires":{"bins":["pastewatch-cli"]}}
---

# pastewatch-cli

Sensitive data scanner. Deterministic regex-based detection and obfuscation for text content. No ML, no network calls.

## Install

```bash
brew install ppiankov/tap/pastewatch
```

## Commands

### pastewatch-cli scan

Scan text for sensitive data patterns. Reports findings or outputs obfuscated text.

**Flags:**
- `--format json` — output as JSON (default: text). Also supports `sarif` for OASIS SARIF 2.1.0
- `--file path` — file to scan (reads from stdin if omitted)
- `--dir path` — directory to scan recursively (mutually exclusive with --file)
- `--check` — check mode: exit code only, no output modification
- `--allowlist path` — path to allowlist file (one value per line, # comments)
- `--rules path` — path to custom rules JSON file

**JSON output:**
```json
{
  "count": 2,
  "findings": [
    {"type": "Email", "value": "admin@internal.corp.net"},
    {"type": "AWS Key", "value": "AKIA****************"}
  ],
  "obfuscated": "contact ****@**** about key ****"
}
```

In check mode (`--check`), the `obfuscated` field is null.

**Exit codes:**
- 0: clean — no sensitive data found
- 1: internal error
- 2: invalid arguments (file not found, conflicting flags)
- 6: findings detected

### pastewatch-cli version

Print version information.

**Flags:**
No flags.

**Exit codes:**
- 0: success

### pastewatch-cli init

Not implemented. Pastewatch is stateless and requires no config file. Pass all options via flags.

## Detection types

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

## What this does NOT do

- Does not use ML or probabilistic scoring — deterministic regex matching only
- Does not make network calls — all detection is local, offline
- Does not modify the clipboard in CLI mode — reads input, writes output
- Does not maintain persistent state — every invocation is stateless
- Does not block or intercept — reports findings, does not prevent actions
- Does not execute or evaluate scanned content

## Parsing examples

```bash
# Check if text is clean
echo "hello world" | pastewatch-cli scan --check && echo "clean" || echo "found sensitive data"

# Get finding count
pastewatch-cli scan --file config.yml --format json | jq '.count'

# List finding types
pastewatch-cli scan --file .env --format json | jq -r '.findings[].type'

# Get obfuscated output
cat debug.log | pastewatch-cli scan --format json | jq -r '.obfuscated'

# Scan directory, check mode
pastewatch-cli scan --dir . --check --format json | jq '.count'
```
