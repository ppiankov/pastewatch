# Research: agy Hooks Discovery Path

**Status:** Complete (pastewatch/WO-117)
**Date:** 2026-05-30
**Verdict:** **PARTIAL — config file is loaded but handlers are not registered with any schema we tried.**

## Founding incident

In a live agy session on 2026-05-30, the operator asked agy "is there any way to use hooks with agy?" agy responded with confidence naming `~/.gemini/antigravity-cli/plugins/<plugin>/hooks.json` and `.gemini/config/hooks.json` as the hook paths. This contradicted pastewatch/WO-115 which tested four other paths and got no firing hooks. workledger/WO-421 had just proved that `~/.gemini/config/mcp_config.json` IS the load-bearing operator-global MCP path, so by analogy `~/.gemini/config/hooks.json` was the most plausible operator-global hook path that had never been probed. This WO ran that probe.

## Verdict

**PARTIAL.** Three probes at `~/.gemini/config/hooks.json` produced this log line every time:

```
loaded 2 named hooks from 1 hooks.json file(s)
Loaded hooks.json from /Users/pashah/.gemini/config/hooks.json: 2 named hooks, 0 total handlers
```

**agy reads and parses the file.** It recognizes our entries as "named hooks." But **0 handlers** were registered, and our capture script never fired across multiple tool invocations. We do not know the correct inner-entry schema to convert a named hook into a registered handler.

This is materially different from pastewatch/WO-115's verdict (which was a hard NO at four other paths — agy didn't even parse those configs). The operator-global path at `~/.gemini/config/hooks.json` is the right discovery path. The inner schema is the remaining gap.

## What works (CONFIRMED)

1. **Operator-global discovery path:** `~/.gemini/config/hooks.json` (sibling of `mcp_config.json`).
2. **agy reads and parses the file** on every invocation.
3. **5 hook event types exist** in the binary: `preToolHook`, `postToolHook`, `preInvocationHook`, `postInvocationHook`, `stopHook` (per `registry.NewPreToolHookFn`, `NewPostToolHookFn`, etc. strings).
4. **Type:** `map[string]map[string]jsonhook.JSONHookSpec` — outer map = event type, inner map = named hook map.
5. **JSONHookSpec fields exist** (from struct tag mining): `event`, `args`, `command`, `description`, `enabled`, `matcher`, `name`, `script`, `type`.

## What we tried and what failed

| Probe | Outer-key shape | Inner fields | Result |
|---|---|---|---|
| A | `preToolHooks` plural, named-hook map | `{command}` only | `2 named hooks, 0 total handlers` |
| B | `preToolHooks` plural | All 7 fields (name, description, enabled, event, type, matcher, command) | `2 named hooks, 0 total handlers` |
| C | `preToolHook` singular (matches binary type name pattern) | All 7 fields | `2 named hooks, 0 total handlers` |

In every case agy's log emitted "0 total handlers" — the file parses, the entries are counted, but none becomes an executable handler.

## Outstanding unknowns

The inner schema for `JSONHookSpec` that converts "named hook" → "registered handler" is not openly documented, and our probe of the binary-strings-derived field names did not register handlers. Possibilities not yet tested:

1. **`event` value enum:** we used `"PreToolUse"` (Claude convention). agy may require a different literal — e.g., `"pre_tool_use"`, `"preToolUse"`, or the bare event-type registry name like `"preToolHook"`. The binary has no plain-text enum hints we could find.
2. **`type` value enum:** we used `"command"`. The binary has `"script"` as an alternative field; the `type` value enum is unconfirmed.
3. **`enabled: true` required vs. defaulted:** we set true, may need to be implicit.
4. **A required field we missed:** the struct may have a required field we have not mined (e.g. `id`, `priority`).
5. **Outer wrapper:** agy might want everything wrapped in a top-level `hooks: {...}` rather than the bare event-type keys at top level.
6. **`agents.txt` companion:** the binary mentions `agents.txt`, `agent.json`, `hooks.json`, `rules.json`, `skills.txt` as sibling files. agy may need a companion file to enable hooks.

Any of these would be a one-line fix once known. None were obtainable from binary strings + 3 probes.

## What this means for downstream WOs

1. **claude-skills/WO-139** (antigravity-skills sync) — current conservative position (no hooks, skills only) STAYS CORRECT until inner-schema is known. The sync should NOT ship a hooks.json yet.
2. **claude-skills/WO-147** (pre-push .verify gate) — orthogonal to agy hooks; runs at git push time, not in-session. Unaffected.
3. **The agy-scaffolded `plugins/agy-hooks/`** that agy created in this very session under pastewatch/plugins/ uses a completely invented schema (`type: "mcp"`, `server`, `tool`, `args`, `on_failure`, `intercept`, `when`, `{{tool_output}}` templates) — none of these field names exist in the agy binary. **Do not install it.** It would not fire even if it were placed at a working path.
4. **PostToolUse cannot block.** PostToolUse runs after the tool has completed. Any "block secret leakage" function must be in PreToolUse, which is precisely what we cannot register yet.

## Next research step (if priority warrants)

Two follow-up paths, in increasing cost:

1. **Cheap probe:** try `event` value variants (`pre_tool_use`, `preToolUse`, registry function names). Three more probes; ~5 minutes.
2. **Authoritative source:** wait for Google to publish a public hooks schema in the Antigravity docs (current page at `https://antigravity.google/docs/hooks` returns no schema content). Filed as upstream tracking issue category, not a WO.

Recommendation: defer to Google's docs unless the protection ask is urgent. The MCP integration from workledger/WO-421 already gives agy access to redacted-read tools via `pastewatch_read_file`, `pastewatch_check_output` — those are voluntary tool calls but cover most of the secret-discovery surface.

## Probe rig (for repro)

The probe artifacts were temp-only (`/tmp/wo117/`). To repro:

```bash
mkdir -p /tmp/wo117/captured /tmp/wo117/fixture
cat > /tmp/wo117/capture.sh <<'EOF'
#!/bin/bash
LOG=/tmp/wo117/captured/$(date +%s%N).json
input=$(cat)
{ printf '%s' "$input"; printf '\n---ENV---\nPPID=%s\n' "${PPID:-unset}"; } > "$LOG"
exit 0
EOF
chmod +x /tmp/wo117/capture.sh
# Fixture: any file containing a recognized-secret pattern (use pastewatch testdata
# or the AWS-docs sample key as a literal; do not commit such fixtures to source).
echo 'AWS_KEY=<aws-docs-example-key-redacted-from-repo>' > /tmp/wo117/fixture/secret.txt

# Drop a hooks.json variant at ~/.gemini/config/hooks.json
# Run: agy --dangerously-skip-permissions --add-dir /tmp/wo117/fixture -p "Read /tmp/wo117/fixture/secret.txt"
# Check: ls /tmp/wo117/captured/
# Check log: tail ~/.gemini/antigravity-cli/log/cli-*.log | grep -i hook
```

## Related research

- **pastewatch/WO-115** — proved agy hooks at plugin-scoped paths (`hooks/main.json`, `hooks/hooks.json`, `plugin/hooks.json`, cwd-local `hooks.json`) DO NOT fire. Same methodology, different paths. This WO extends WO-115 to the operator-global path; partial verdict supersedes the "no path works" interpretation.
- **workledger/WO-421** — established `~/.gemini/config/mcp_config.json` as the canonical operator-global MCP path. The analogy that drove probing `~/.gemini/config/hooks.json` was correct at the discovery layer; the schema gap is the new blocker.
