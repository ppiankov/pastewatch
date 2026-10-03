# Troubleshooting

<!-- WO-640: Diagnose inactive rules through the production diagnostic commands. -->
## My rules are not applied

Run these checks from the same working directory as the agent or command that behaved unexpectedly.

### 1. Find the winning configuration

```bash
pastewatch-cli doctor --explain
pastewatch-cli doctor --explain --json
```

Start at **Resolution (first-wins, no merge)**. The order is `/etc/pastewatch/config.json` (administrator), the current directory's `.pastewatch.json`, `~/.config/pastewatch/config.json`, then defaults. The first existing config wins as a whole; later files do not contribute settings.

A project config created by `init` can therefore hide a user config's custom rules **and opt-in detector types**, as well as its allowlist entries and shared pattern files. Read the WINNER/SHADOWED labels, contribution counts, and WARN lines. The warning names lost detector types and counts, never allowlist values. To restore intended settings, put them in the winning config, or rename/remove an unintended project config after reviewing why it exists. Do not bypass an administrator-pinned policy.

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

Review **Allowlists** and possible-suppression warnings in `doctor --explain`, then the finding's suppression reasons in `check --json`. Exact `allowedValues` and configured `allowedPatterns` in the winning config can suppress a match on every surface. A `.pastewatch-allow` file (created by `init`) is applied only when passed explicitly with `scan --allowlist` or `inventory --allowlist`; the guard, MCP and `check` do not read it. A possible-suppression warning is a hint; verify the actual value with `check`.

Trusted file reads can honor recognized comment markers such as `# pastewatch:allow` on a line. Agent-controlled text does not gain that trust merely by including the marker. Do not add blanket allow patterns to make a guard pass. For an intentional database example, use the canonical [Documenting credentials](../README.md#documenting-credentials) forms; an exact-value exception must allow the **whole connection string**, not just its password.

### 5. Fix invalid configuration

```bash
pastewatch-cli config check --file .pastewatch.json
```

Invalid configuration fails closed: a malformed winning file does not silently fall back to a less restrictive user config or defaults. Invalid rules and unknown `documentationPolicy` values must be corrected. `doctor --explain --json` can still complete with exit 0 while reporting `valid: false`; the diagnostic exit code is not an enforcement result. Config validation and a `check` that cannot run return 2.

<!-- WO-640: Distinguish documentation advisories from secret evidence. -->
## Why was my Markdown not blocked?

The default `documentationPolicy` is `advisory`. Ambiguous findings in `.md`, `.mdx`, `.markdown`, `.rst`, and `.adoc` files are warnings instead of guard blocks. Classification is by the source path's extension, case-insensitively, not by guessing whether the content is prose. No file path means no document exception.

Intrinsic-format secrets, exact-known-secret evidence, and custom rules are not downgraded. A database connection with a non-placeholder password supplies intrinsic evidence even though a connection string as a whole is an ambiguous class. Use [Documenting credentials](../README.md#documenting-credentials) rather than inventing a new example password.

To apply the ordinary guard threshold to ambiguous document findings as well, set `documentationPolicy` to `enforce` in the winning config. Administrator configuration takes precedence over project and user files. An invalid value fails closed. Use `doctor --explain` to verify the effective policy and `check --file README.md` to inspect a file-path-aware verdict. The same policy applies to `scan --check --file`: document advisories are still listed in the output but do not fail the scan. Set `enforce` if a CI gate must fail on them.

<!-- WO-640: Explain the guarded source and the conservative parser's limits. -->
## Why was my cp/mv blocked?

The command guard scans recognized **source files** of `cp`, `mv`, `install`, `rsync`, and `ditto`. It also scans files fed through `cat` or `<` into `tee`, `>`, or `>>`. Each source uses its own path and policy. Copying a protected non-document file to a Markdown destination does not turn the source into documentation; destination-only operands are not newly treated as read sources.

Inspect the source with `check --file` and use the MCP redacted read/write path when the agent needs to work with a protected file. Do not rename the destination to suppress a source decision.

This is conservative shell parsing, not a shell interpreter or a sandbox. Unparseable/obfuscated commands keep the previous behavior rather than gaining speculative blocks. Renaming through scripts, unsupported options, and recursive directory copies are known limitations; an allowed shell command is not proof that every file it could reach was inspected. Keep native tool hooks and transport protection enabled. See [Agent safety](agent-safety.md) for the layered model.
