# Research: Antigravity Hook Claims Need Runtime Proof

**Status:** Retrospective note
**Date:** 2026-06-09
**Verdict:** The historical evidence is bounded to the observed Antigravity CLI v1.0.3 probe arc. In that arc, MCP integration worked, the hook configuration file loaded, named hooks were counted, but no tested hook shape registered a handler or proved PreToolUse blocking. Current Antigravity hook support must be verified with fresh runtime capture probes before pastewatch or any integration depends on it.

## Version Boundary

This note summarizes the v1.0.3 research already recorded in:

- [agy Hooks Discovery Path](agy-hooks-discovery.md)
- [agy Hook Schema Probe](agy-hooks-follow-up.md)

It does not claim that current Antigravity hook support works or fails. Antigravity documentation and runtime behavior may have changed after the v1.0.3 probes. Treat this document as a methodology and product-boundary note, not as current-version support evidence.

## Current Documentation Check

Official Antigravity documentation checked on 2026-06-09:

- Hooks: <https://www.antigravity.google/docs/hooks>
- Plugins: <https://www.antigravity.google/docs/plugins>
- MCP integration: <https://www.antigravity.google/docs/mcp>

The current hooks documentation describes a `hooks.json` format, hook events, matchers, handler configuration, and JSON stdin/stdout contracts. The current plugins documentation describes plugins as bundles that can include MCP servers, hooks, skills, and rules. The current MCP documentation describes custom MCP server configuration.

Those pages are useful input for any future implementation. They are not a substitute for runtime proof. The v1.0.3 investigation found that plausible paths, inferred schemas, binary strings, and agent-provided descriptions could all be insufficient unless a capture probe showed that the runtime actually invoked the handler before sensitive file content entered the model context.

## Premise

Hook systems are safety boundaries only when they execute at the right time. For pastewatch, that means a hook must run before a native file read exposes content. A configuration file that parses cleanly is not enough. A hook name that appears in a log is not enough. A post-action observer is not enough.

The v1.0.3 research separated the problem into three layers:

1. MCP tool availability: can Antigravity see voluntary pastewatch tools?
2. Hook configuration parsing: does Antigravity load and parse a hook config file?
3. Hook handler execution and blocking: does a PreToolUse handler actually run before a native read and have a blocking path?

Only the third layer is structural protection.

## What MCP Proved

The existing research records that Antigravity could expose pastewatch MCP tools. That gives the model a voluntary redacted-read path and output-check tools. It does not force the model to use those tools, and it does not prevent native reads through Antigravity's own file tools.

MCP is therefore useful, but it is not the same control as a PreToolUse gate.

## What The Hook Probes Proved

The v1.0.3 hook probes showed a partial but important result:

- The operator-global hook configuration path loaded in the tested runtime.
- Antigravity counted configured entries as named hooks.
- Across the recorded variants, handler count stayed at zero or the file shape was rejected before counting.
- The capture script did not fire.
- No PreToolUse blocking was proven.

The follow-up note contains the detailed probe table. This retrospective intentionally does not duplicate it.

## Agent Self-Description Failure Mode

The research also exposed a common agent-runtime failure mode: an agent can confidently describe a configuration path or schema that is only partly true or not executable in the runtime being used.

In the v1.0.3 arc, the useful part was the clue that an operator-global customization path existed. The unsafe part was treating the agent's schema description as if it were executable product evidence. Runtime capture separated those two claims.

The durable lesson is simple: an agent runtime extension point is not real enough for a safety claim until a probe captures the handler firing at the required phase.

## Methodology

A safe extension-point verification should record:

- Runtime version and date.
- Exact documentation URLs checked that day.
- The configuration path and whether the runtime logs that it loaded it.
- A capture script or fixture that proves handler execution without exposing real credential values.
- Whether the handler fires before or after the sensitive operation.
- Whether the handler can block, ask, or only observe.
- A negative verdict when parsing succeeds but handler execution is not proven.

This is deliberately stricter than reading documentation or asking the agent. Documentation is the starting hypothesis. The capture probe is the product evidence.

## Pastewatch Product Boundary

As of this note, pastewatch's committed Antigravity boundary remains conservative:

- Antigravity can use pastewatch through voluntary MCP tools.
- pastewatch does not claim structural native-read blocking for Antigravity based on the v1.0.3 hook probes.
- The existing README compatibility rows should not be upgraded or downgraded by this retrospective alone.

A separate current-version verification would be warranted before shipping any stronger Antigravity hook claim or generated Antigravity hook integration.

## Disclosure Boundary

This note contains no external publication claim and no private runtime artifacts. It cites the committed research notes for the historical probe details and avoids reproducing private transcripts, credential values, local absolute home paths, or machine-specific configuration contents.
