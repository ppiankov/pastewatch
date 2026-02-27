# pastewatch — VS Code Extension

Real-time secret detection in the editor. Catches secrets as you type — before they reach git history or CI.

## Features

- **Inline diagnostics** — red/yellow/blue squiggles on detected secrets
- **Hover tooltips** — detection type and severity on hover
- **Quick-fix actions** — add `// pastewatch:allow` inline or append to `.pastewatch-allow`
- **Status bar** — finding count for the active file
- **Auto-refresh** — re-scans on file save (debounced, configurable)

## Requirements

`pastewatch-cli` must be installed and available in your PATH.

```sh
brew install ppiankov/tap/pastewatch-cli
```

## Installation

### From Marketplace

Search for "pastewatch" in the VS Code Extensions view.

### From VSIX

```sh
cd vscode-pastewatch
npm run package:vsix
code --install-extension pastewatch-*.vsix
```

## Configuration

| Setting | Default | Description |
|---|---|---|
| `pastewatch.autoRefresh` | `true` | Re-run diagnostics on file save |
| `pastewatch.binaryPath` | `pastewatch-cli` | Path to the CLI binary |
| `pastewatch.debounceMs` | `500` | Debounce window for save-triggered refresh |
| `pastewatch.failOnSeverity` | `low` | Minimum severity to show diagnostics |

## How It Works

The extension shells out to `pastewatch-cli scan --format json --file <path>` for each file. No detection logic is bundled — the CLI is the single source of truth.

### Severity Mapping

| CLI Severity | VS Code Diagnostic | Squiggle Color |
|---|---|---|
| critical | Error | Red |
| high | Error | Red |
| medium | Warning | Yellow |
| low | Information | Blue |

## License

MIT
