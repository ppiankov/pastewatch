# Troubleshooting

<!-- WO-671@v2: prefer a narrow edit and reconnect a stale server rather than rebuilding an opaque file. -->
## MCP tools are missing after an upgrade

Run `pastewatch-cli doctor`. A running server can outlive an upgrade: warnings
identify processes started before the installed binary was updated, or reporting
a different version. Reconnect MCP or restart the agent session to load the new
server. Initialization exposes `serverInfo.version`; tool results expose
`_meta.server_version`.

For a small change to a protected file, use `pastewatch_edit_file` with
`old_string`/`new_string` copied from the `pastewatch_read_file` placeholder view,
or use [`pastewatch-cli edit`](cli-reference.md#redacted-cli-readedit). If
`pastewatch_edit_file` is missing, reconnect your MCP server. Use
`pastewatch_write_file` only as a last resort for a full-file replacement; do not
retype large data URIs or unrelated content to apply a small edit.

<!-- WO-640: Diagnose inactive rules through the production diagnostic commands. -->
## My rules are not applied

Run these checks from the same working directory as the agent or command that behaved unexpectedly.

<!-- WO-672@v1: merged policy has contributions rather than a shadowed winner. -->
### 1. Inspect the contributing configurations

```bash
pastewatch-cli doctor --explain
pastewatch-cli doctor --explain --json
```

<!-- WO-672@v1: diagnose contributing tiers instead of config replacement. -->
Start at **Resolution (merged; project policy can only tighten)** and **Field contributions**. Administrator and user policy remain active when a project `.pastewatch.json` exists. Project detectors, custom rules, protected paths, shared patterns and obfuscation add protection; existing entries cannot be removed and rule severities cannot decrease.

<!-- WO-672@v1: project policy cannot shadow user rules or opt-in detectors. -->
Read each tier's contribution counts and field attribution. Project suppression patterns are ignored and produce a count-only warning. When system policy exists, user policy is also tighten-only and its suppression patterns are ignored. Lowering `mcpMinSeverity` reports more advisories; subordinate tiers cannot raise it to hide reports. Any present invalid tier fails enforcement closed. The walkthrough never prints rule patterns or allowed values.

The **Config in use** line gives the compiled custom-rule count. If it is smaller than expected, inspect **Custom rules** for compilation failures and duplicate names, **Detectors** for enabled types, and **Shared pattern files** for loading errors. These are separate from matching: a rule that loaded can still fail to match the input.

### 2. Compare severity and surface

The guard's default blocking threshold is `high`; `critical` also blocks. A custom rule with no explicit severity defaults to `high`. A `medium` or `low` rule may be reported without blocking the guard. Read the per-rule guard, scan, MCP, and proxy verdicts rather than treating all four as the same decision.

`mcpMinSeverity` defaults to `high` and controls MCP advisory reporting. Mutation-authorized matches still become placeholders; lowering this threshold does not authorize ambiguous matches for mutation. MCP is two-way: local writes restore the placeholders. The proxy redacts outbound data one-way and does not restore it. File-path documentation policy can also change a guard verdict; see below.

### 3. Verify one value

```bash
printf '%s\n' '<value>' | pastewatch-cli check
pastewatch-cli check --file README.md
printf '%s\n' '<value>' | pastewatch-cli check --json
```

The piped example is a placeholder. For a real secret, use an existing file or run `pastewatch-cli check` at a terminal for no-echo input. Never type a real secret into a shell command or pass it as a positional argument; arguments can appear in history and process listings. Positional values are refused with exit 64.

`--file` preserves the input path for document policy. Stdin is pathless, so these can legitimately yield different guard verdicts. The proxy verdict models user-message text, and the MCP verdict models a trusted file read; neither sends the input to a remote service. Output contains only type/name, severity, line, length, character classes, and decisions, not the input or a value fingerprint. Exit 0 means the diagnosis completed, **not** that every surface allowed it. See the [complete field reference](cli-reference.md#check-json-fields).

### 4. Check suppression

<!-- WO-672@v1: operator exact-value exemptions do not grant authority to project or pattern sources. -->
Review **Allowlists** and possible-suppression warnings in `doctor --explain`, then the finding's suppression reasons in `check --json`. Intrinsic secrets require an exact whole value in administrator `allowedValues`, or user `allowedValues` when system policy is absent; patterns, project entries, inline directives and remedy allowlists cannot exempt them.
<!-- WO-672@v1: subordinate exemptions do not discard independently authorized or non-ambiguous findings. -->
Project and tighten-only user entries exempt advisory classes only, never non-ambiguous types, custom rules or intrinsic/exact-known-secret evidence. Inline and remedy behavior is otherwise unchanged. Verify the actual value with `check` rather than assuming a pattern warning proves suppression.

<!-- WO-670@v1: diagnostic loading evidence reflects target-root discovery across file surfaces. -->
<!-- WO-672@v1: ineffective non-advisory and custom-rule entries contribute to the diagnostic warning. -->
For `.pastewatch-allow`, inspect **Project allow file**: resolved path, loaded status, effective entries and ignored non-advisory/custom-rule entries (`ignoredIntrinsicEntries` in JSON). File targets load one file from their Git toplevel, or the explicit scan/watch root outside Git. A single non-Git file uses its parent directory. This file grants exact advisory-class exemptions only, never non-ambiguous types, custom rules or intrinsic/exact-known-secret evidence. Hooks running outside the repository still use the target's root. Stdin and raw MCP text have no target and do not load a project allow file.

Trusted file reads can honor recognized comment markers such as `# pastewatch:allow` on a line. Agent-controlled text does not gain that trust merely by including the marker. Do not add blanket allow patterns to make a guard pass. For an intentional database example, use the canonical [Documenting credentials](../README.md#documenting-credentials) forms; an exact-value exception must allow the **whole connection string**, not just its password.

### 5. Fix invalid configuration

```bash
pastewatch-cli config check --file .pastewatch.json
```

<!-- WO-672@v1: every participating configuration tier must be valid. -->
Invalid configuration fails closed: a malformed contributing file does not silently fall back to a less restrictive policy or defaults. Invalid rules and unknown `documentationPolicy` values must be corrected. `doctor --explain --json` can still complete with exit 0 while reporting `valid: false`; the diagnostic exit code is not an enforcement result. Config validation and a `check` that cannot run return 2.

<!-- WO-640: Distinguish documentation advisories from secret evidence. -->
## Why was my Markdown not blocked?

The default `documentationPolicy` is `advisory`. Ambiguous findings in `.md`, `.mdx`, `.markdown`, `.rst`, and `.adoc` files are warnings instead of guard blocks. Classification is by the source path's extension, case-insensitively, not by guessing whether the content is prose. No file path means no document exception.

Intrinsic-format secrets, exact-known-secret evidence, and custom rules are not downgraded. A database connection with a non-placeholder password supplies intrinsic evidence even though a connection string as a whole is an ambiguous class. Use [Documenting credentials](../README.md#documenting-credentials) rather than inventing a new example password.

<!-- WO-672@v1: document enforcement is an additional restriction, never a project relaxation. -->
To apply the ordinary guard threshold to ambiguous document findings as well, set `documentationPolicy` to `enforce`. A project cannot relax administrator or user enforcement. An invalid value fails closed. Use `doctor --explain` to verify the effective policy and `check --file README.md` to inspect a file-path-aware verdict. The same policy applies to `scan --check --file`: document advisories are listed but do not fail the scan; use `enforce` if a CI gate must fail on them.

<!-- WO-640: Explain the guarded source and the conservative parser's limits. -->
## Why was my cp/mv blocked?

The command guard scans recognized **source files** of `cp`, `mv`, `install`, `rsync`, and `ditto`. It also scans files fed through `cat` or `<` into `tee`, `>`, or `>>`. Each source uses its own path and policy. Copying a protected non-document file to a Markdown destination does not turn the source into documentation; destination-only operands are not newly treated as read sources.

Inspect the source with `check --file` and use the MCP redacted read/write path when the agent needs to work with a protected file. Do not rename the destination to suppress a source decision.

This is conservative shell parsing, not a shell interpreter or a sandbox. Unparseable/obfuscated commands keep the previous behavior rather than gaining speculative blocks. Renaming through scripts, unsupported options, and recursive directory copies are known limitations; an allowed shell command is not proof that every file it could reach was inspected. Keep native tool hooks and transport protection enabled. See [Agent safety](agent-safety.md) for the layered model.
