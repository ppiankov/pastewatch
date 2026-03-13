# Pastewatch — Claude Code Integration Snippet

Copy the block below into your project's `CLAUDE.md` (or `~/.claude/CLAUDE.md` for global).

---

```markdown
## Pastewatch — Secret Redaction

This project uses [pastewatch](https://github.com/ppiankov/pastewatch) to prevent secrets from reaching AI APIs.

### When hooks block you

If a pastewatch hook blocks `Read`, `Write`, or `Edit`:
- Use `pastewatch_read_file` MCP tool to read the file (secrets are replaced with `__PW_TYPE_N__` placeholders)
- Use `pastewatch_write_file` MCP tool to write back (placeholders are resolved to real values locally)
- NEVER use `cat`, `head`, `python3`, or any Bash workaround to read blocked files
- NEVER delete or rename files to bypass the hook

### Round-trip workflow

1. Read: `pastewatch_read_file` → you see `password: __PW_CREDENTIAL_1__`
2. Edit: work with placeholders in your code changes
3. Write: `pastewatch_write_file` → real values restored on disk

### Rules

- Same secret always maps to the same placeholder within a session
- Placeholders are in-memory only — they die when the MCP server stops
- If you see `__PW_` prefixed values, those are redacted secrets — do not treat them as real values
- When writing files that contain `__PW_` placeholders, always use `pastewatch_write_file` — native Write will be blocked
```

---

## Setup

If pastewatch is not yet configured for this project:

```bash
brew install ppiankov/tap/pastewatch
pastewatch-cli setup claude-code          # auto-configures MCP + hooks
pastewatch-cli init                       # creates .pastewatch.json
# or for banking/enterprise:
pastewatch-cli init --profile banking     # JDBC, medium severity, internal host detection
```
