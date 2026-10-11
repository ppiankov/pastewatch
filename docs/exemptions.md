# Exemptions: every way a finding gets through

Pastewatch blocks by evidence. Sometimes a finding is known to be safe: a test
fixture, a documented example, a binary you have already inspected. This page
lists every path that lets a finding through, who may author it, and how far it
reaches.

One rule sits above the table: **an intrinsic secret is never exempted by a
pattern.** Provider keys, private keys, validated JWTs and cards can only be
exempted as an exact whole value, and only from an operator tier. A tired regex
must not open the door for every key of a kind.

<!-- WO-676@v4: removed markers have no reach, and remedy files cover exact advisory values only. -->
## The paths

| Path | Who authors it | Reaches intrinsic secrets? | Reaches other classes | Scope / lifetime |
|------|----------------|----------------------------|-----------------------|------------------|
| System or user config `allowedValues` | Operator | Yes, exact whole value only | Yes | Every surface, until removed |
| System or user config `allowedPatterns` | Operator | No | Yes | Every surface, until removed |
| Project `.pastewatch.json` `allowedValues` | Operator-owned; tighten-only tier (project `allowedPatterns` are dropped) | No | Advisory classes only, never custom-rule hits | That project, until removed |
| Project `.pastewatch-allow` | Operator-owned; agents cannot create or edit it | No | Advisory classes only, exact values | File targets in that Git toplevel or scan root |
| `scan --allowlist <file>` | Whoever runs the command | No | Exact advisory-class values only; never custom rules or obfuscate opt-ins | That one invocation |
| `safeHosts` (system or user config) | Operator | n/a (host class only) | Hostnames | Every surface; ignored in project config |
| `pastewatch-cli allow-binary <file>` | Operator, in their own terminal | n/a (binary transfer only) | Binary transfer sources | One file's exact bytes, at most 24 hours |
| `.pastewatch-baseline.json` via `scan --baseline` | Whoever runs the command | Reporting only | Reporting only | `scan` output; does not affect guard, MCP or proxy |
| `.pastewatchignore` | Repository | Path exclusion | Path exclusion | Directory scans; does not affect guard, MCP or proxy |
| `PW_GUARD=0` | Whoever sets the environment | **Everything** | **Everything** | The whole session: guard and `scan --check` are off |

Notes:

- **Advisory classes** are the ambiguous ones: email, hostname, IP, path, phone,
  UUID, database connection strings, generic credentials and similar. They are
  advisory-only by default and never rewritten unless you opt in with
  `obfuscate`. See [Configuration](../README.md#configuration).
- When a system config (`/etc`) exists, the user tier becomes tighten-only too,
  with the same advisory-only exemption reach as a project file.
- **Tighten-only** means a project file can add rules and lower thresholds, but
  cannot loosen what the operator configured. Project `enabled`, `safeHosts` and
  similar loosening fields are ignored.
- **`allow-binary`** binds a grant to the file's canonical path, its SHA-256 and
  an expiry (default one hour). Changed bytes or a retargeted symlink still
  block. Details and limits: [Binary Transfer Grants](cli-reference.md#binary-transfer-grants).
- **`PW_GUARD=0`** is a session-wide escape hatch, not an exemption. It turns the
  guard off. Do not leave it set in a shell that starts agents.
- `obfuscate` works in the opposite direction: it adds protection for ambiguous
  values. It never exempts anything.

<!-- WO-676@v4: replacement routes remain operator-authored and do not add an exemption mechanism. -->
## Removed in 0.43.0

The inline `pastewatch:allow` marker and its VS Code quick fix were removed.
Marked lines are scanned normally; CLI findings on them include a migration notice.

For legitimate uses, an operator can place an exact whole value in system config
or user config when no system policy exists. Use `.pastewatch-allow` for exact
advisory values, `.pastewatchignore` for fixture directories in directory scans,
and the canonical [documentation placeholders](../README.md#documenting-credentials)
for examples. `scan --allowlist` covers only exact advisory values, never custom
rules, exact-known secrets, non-ambiguous types, intrinsic secrets or `obfuscate`
opt-ins. Agents must report false positives, not create exceptions.

## Who can write what

<!-- WO-676@v4: inline comments cannot authorize exemptions at all. -->
Pastewatch runs as your user, and so does your agent. Pastewatch can refuse
guarded agent writes to operator-owned files, and it does. It cannot prove who
wrote a file that changed by some other route. That is why the paths that reach
furthest (exact intrinsic values, `allow-binary`) are operator-tier only, and why
agent-writable exemption sources are limited to advisory classes or refuse
intrinsic secrets outright. Inline comments confer no exemption.

The shell guard is a guardrail for cooperative agents, not a sandbox against a
hostile process running as you.

## Design boundary

Pastewatch does not collect, queue or adjudicate approvals. There is no approval
inbox, no batch approval, no delegated "approve anything matching this rule"
authority, and no approval record. Exemptions stay narrow, scoped and
operator-authored. That boundary is deliberate: see
[Where Pastewatch stops](../README.md#where-pastewatch-stops).
