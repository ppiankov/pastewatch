# Startup Sweep

`pastewatch-cli launch` runs a local startup sweep before it starts the proxy and agent. The
sweep looks for credential candidates that already exist in common shell startup files, then
prints one aggregated warning to stderr.

The sweep is detection-only. It does not block launch, edit files, rotate credentials, upload
findings, or call external services.

## Files Scanned

The startup sweep resolves candidates from the current home directory and current working
directory:

- `~/.zshrc`
- `~/.zshenv`
- `~/.zprofile`
- `~/.bashrc`
- `~/.bash_profile`
- `~/.profile`
- `~/.config/fish/config.fish`
- `~/.config/fish/conf.d/*.fish`
- `.envrc` files from the current directory upward through the home directory

Missing files are skipped silently. Files larger than 1 MB are not scanned; the warning may
mention the skipped path and byte count, but never file contents.

## Warning Shape

The warning is a single stderr block. For files with findings, it includes only:

- path
- finding count
- severity histogram
- line numbers

It never prints credential values, source lines, snippets, partial values, reversible
placeholders, or file contents.

## Dedup Rule

Pastewatch stores a local JSON cache at `~/.pastewatch/sweep-cache.json`. Entries are keyed by:

- normalized path
- content hash
- finding count
- severity summary

An unchanged file with the same finding summary warns once, then stays silent. Editing the file
so its content hash changes warns again when findings remain. Changing the finding count or
severity summary also warns again. Clean files may be cached, but a later content change with
findings still produces a warning.

## Disable Flag

Use `--no-startup-sweep` to suppress the sweep entirely:

```bash
pastewatch-cli launch --no-startup-sweep -- claude
```

When disabled, pastewatch does not read startup sweep candidate files and emits no startup sweep
warning.

## Limits

The sweep reuses pastewatch's existing file-IO detection pipeline. It does not add a second
classifier or separate regex list.

This feature is intentionally narrow:

- no auto-rotation
- no auto-editing
- no quarantine or deletion
- no network calls
- no file watching
- no arbitrary project scan
- no `.env` scanning beyond the documented `.envrc` chain

Use `pastewatch-cli scan --file <path>` or `pastewatch-cli scan --dir <path>` for explicit
ad-hoc scans.
