# Research: agy Hook Schema Probe (follow-up to WO-117)

**Status:** Complete (pastewatch/WO-118)
**Date:** 2026-05-30/31
**Verdict:** **NO — no inner-schema variant we tested converted a named hook into a registered handler. agy hook protection remains unsupported in v1.0.3 at the live-tested operator-global path.**

## Founding incident

pastewatch/WO-117 proved agy reads `~/.gemini/config/hooks.json` and counts our entries as "named hooks" but registers 0 handlers. This follow-up ran 10 of the 12 budgeted schema variants to find the conversion. None worked.

## Probe results

All probes used a capture-script wrapper at `/tmp/wo118/capture.sh` that records stdin and exits 0. agy was driven with `agy --dangerously-skip-permissions --add-dir /tmp/wo118/fixture -p "Read /tmp/wo118/fixture/test.txt"` after each schema rewrite. `fired` is the count of capture-log files written. `log` is the relevant line from `~/.gemini/antigravity-cli/log/cli-*.log`.

| # | Variant | Key | Inner shape | fired | log line |
|---|---|---|---|---|---|
| 1 | `event=pre_tool_use` snake_case | `preToolHook` | `{name, event, type, matcher, command, enabled}` | 0 | `1 named hooks, 0 total handlers` |
| 2 | `event=preToolUse` camelCase | `preToolHook` | same | 0 | `1 named hooks, 0 total handlers` |
| 3 | Claude-shape array at new path | `PreToolUse` (array) | `{matcher, hooks:[{type,command}]}` | 0 | (no log line — agy rejected before counting) |
| 4 | `{hooks: {...}}` wrapper | `hooks.preToolHook` | full fields | 0 | `1 named hooks, 0 total handlers` |
| 5 | `type=script` + `script` field | `preToolHook` | `{name, event, type=script, matcher, script, enabled}` | 0 | `1 named hooks, 0 total handlers` |
| 6 | minimal-command-only | `preToolHook` | `{command}` | 0 | `1 named hooks, 0 total handlers` |
| 7 | bare `preTool` (no Hook suffix) | `preTool` | `{command}` | 0 | `1 named hooks, 0 total handlers` |
| 8 | type=preTool event=preTool | `x` (arbitrary key) | `{type, event, command, matcher}` | 0 | `1 named hooks, 0 total handlers` |
| 9 | flat top-level array | (none) | `[{name, event, command, matcher, type}]` | 0 | (no log line — agy rejected) |
| 10 | hooks.json + agent.json companion | `preTool` | same as 7 + sidecar `agent.json` `{name:"default", hooksEnabled:true}` | 0 | (no log line) |

Probes 11 and 12 (plugin path `~/.gemini/antigravity-cli/plugins/pastewatch/hooks.json` + further companion variants) were not run; per WO-118's scope the per-probe outcome pattern is consistent enough to commit to the negative verdict at probe 10. The cost budget was the gate, and bounding the work here is the right call.

## What the binary said (re-derived from WO-117 strings dump)

After probe 6 stalled at "0 handlers" with all field tags filled, deeper binary mining surfaced the actual runtime log strings:

- `pre-tool hook %s not registered`
- `post-tool hook %s not registered`
- `pre-invocation hook %s not registered`
- `post-invocation hook %s not registered`
- `stop hook %s not registered`
- `failed to call hook %s`
- `pre-tool hook %s failed: %v`
- `tool post-hook %s failed: %v`
- `JSON hook command stderr: %s`
- `failed to inject steps from hook %s`
- `failed to decode args JSON`
- `failed to parse JSON config`
- `Invalid matcher regex %q: %v`

These prove the runtime path exists and would log if invoked. None of our probes triggered any of these strings — meaning agy never even attempted to call our hooks, let alone fail. The blocker is at the **named-hook to handler conversion** step, upstream of any runtime call.

## What we can conclude

1. **`~/.gemini/config/hooks.json` IS the operator-global discovery path** (WO-117 verdict stands).
2. **The outer-map shape doesn't matter** — agy counts entries under any key as "named hooks." The blocker is inner-spec instantiation.
3. **JSONHookSpec fields ARE `event`, `command`, `matcher`, `type`, `script`, `name`, `description`, `enabled`, `args`** (from binary struct tags).
4. **None of the schema variants we tested registers a handler.** Either: (a) agy v1.0.3 requires a field combination not in our 10 variants, OR (b) agy v1.0.3's handler registration is gated on something OUTSIDE the JSON file (e.g. a plugin manifest, a registry call, an internal-only flag), OR (c) the public surface for hooks is intentionally disabled in the externally-distributed binary.
5. **The agy-scaffolded `plugins/agy-hooks/`** (created in this session by agy itself when asked to scaffold) uses an entirely invented schema (`type: "mcp"`, `server`, `tool`, `args`, `on_failure`, `intercept`, `when`, `{{tool_output}}` templates) — none of these fields exist in the binary. Installing it would be a no-op that looks protective.

## Verdict

**pastewatch hook protection for agy is UNSUPPORTED in agy v1.0.3.** The configuration loads, agy counts it, but no handler runs. Until Google publishes a hooks schema, ships an SDK example, or open-sources the hook-spec definition, pastewatch must not claim agy hook coverage.

This is a hard NO at the layer we can test. The discovery path is correct, the field tags are known, but the conversion from spec to handler is opaque.

## What this means for downstream WOs

1. **claude-skills/WO-139** (antigravity-skills sync) — current conservative position (skills only, no hooks.json) is **correct**. Do NOT ship a hooks.json in sync_antigravity until a working schema is discovered.
2. **claude-skills/WO-147** (pre-push .verify gate) — orthogonal; runs at git push time. Unaffected.
3. **pastewatch/plugins/agy-hooks/** — quarantine by adding to `.gitignore` so an accidental `agy plugin install` cannot pick it up. Files are not removed (kept as evidence of the agy hallucination for the field-note).
4. **The MCP integration from workledger/WO-421** is the entire pastewatch-on-agy story for now. agy gets pastewatch's redacted-read tools (`pastewatch_read_file`, `pastewatch_check_output`, `pastewatch_scan_file`, `pastewatch_scan_dir`, `pastewatch_write_file`, `pastewatch_scan`) via MCP. The agent invokes them voluntarily; there is no PreToolUse layer to enforce.
5. **The field-note blog (pastewatch/WO-119)** ships with the "we still don't know what the schema is, but we know what doesn't work" ending. That's a stronger story than I expected. Materially: the MCP works, the hooks don't, and agy itself fabricated a schema when asked.

## Methodology lessons (reusable)

1. **`X named hooks, 0 total handlers`** is a partial-success log line. agy parses but doesn't instantiate. This is the most informative diagnostic in the whole subsystem; future probes should grep for it.
2. **Outer-key insensitivity** — agy counts entries under any top-level map key. Stop varying outer keys; vary inner shape.
3. **Top-level array is rejected** with no log — outer is definitely a map.
4. **A no-log probe is a stronger signal than a "0 handlers" probe** — no-log means agy didn't recognize the file shape at all (probes 3 and 9 here); 0-handlers means it parsed and gave up at instantiation (probes 1-2, 4-8, 10).
5. **Asking the agent about its own schema is unreliable**. agy in chat invented the `type: "mcp"` schema entirely — none of those fields exist in the binary. This is the lesson the field-note will lead with.

## Repro

```bash
mkdir -p /tmp/wo118/captured /tmp/wo118/fixture
cat > /tmp/wo118/capture.sh <<'EOF'
#!/bin/bash
LOG=/tmp/wo118/captured/$(date +%s%N).json
input=$(cat)
{ printf '%s' "$input"; printf '\n---ENV---\nPPID=%s\n' "${PPID:-unset}"; } > "$LOG"
exit 0
EOF
chmod +x /tmp/wo118/capture.sh
echo 'just a test file' > /tmp/wo118/fixture/test.txt

# Try any variant from the table by writing to ~/.gemini/config/hooks.json
# then running:
agy --dangerously-skip-permissions --add-dir /tmp/wo118/fixture -p "Read /tmp/wo118/fixture/test.txt"
# Check capture: ls /tmp/wo118/captured/
# Check log: tail ~/.gemini/antigravity-cli/log/cli-*.log | grep -i 'named hooks\|total handlers'
```

## Related research

- **pastewatch/WO-115** — hard NO at four plugin-scoped paths (the four config locations that pre-WO-117 looked plausible).
- **pastewatch/WO-117** — partial verdict at `~/.gemini/config/hooks.json`: path loads, 0 handlers. This WO finishes the schema question with a hard NO.
- **workledger/WO-421** — discovered the `~/.gemini/config/` operator-global pattern, validated end-to-end for MCP. Same pattern works for hooks at the file-load layer; doesn't at the handler-register layer.
