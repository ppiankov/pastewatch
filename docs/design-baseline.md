# Design Baseline

## Core Principle

**Principiis obsta** — resist the beginnings.

Pastewatch applies this principle to clipboard data transmission. The irreversible boundary is the moment sensitive data leaves the user's control and enters an AI system.

Once pasted:
- Data cannot be reliably recalled
- Data may be logged, stored, or used for training
- The user loses all control over its fate

Pastewatch refuses that transition.

---

## Why Before Paste

Downstream controls fail because they operate too late:

| Approach | Problem |
|----------|---------|
| Browser extension | Only sees web apps, blind to native |
| LLM proxy | Data already transmitted |
| DLP system | Blocks after detection, user already exposed intent |
| Prompt sanitizer | Runs after submission |

The clipboard is the last moment of user control. After ⌘V, the data belongs to someone else.

Pastewatch intervenes at the only point that matters: before the irreversible action.

---

## Design Priorities

### 1. Determinism over Convenience

All detection uses regex and heuristics. No ML. No probabilistic scoring.

Why:
- Users must be able to predict behavior
- No "confidence levels" to second-guess
- No model drift or version differences
- Explainable: "This matched pattern X"

### 2. False Negatives over False Positives

When uncertain, Pastewatch does nothing.

Why:
- Breaking user workflow is worse than missing edge cases
- Users will disable tools that cry wolf
- Conservative tools build trust
- Missing one secret < breaking every paste

### 3. Silence over Notification

Default behavior is invisible. Feedback only when action taken.

Why:
- Attention is expensive
- "Nothing happened" is the success state
- Users should forget the tool exists
- Notification fatigue kills adoption

### 4. Local over Connected

All processing happens on-device. No network calls.

Why:
- Clipboard data is inherently sensitive
- Cloud processing defeats the purpose
- Latency would break UX
- No dependency on external services

---

## Irreversible Boundaries

Pastewatch guards a specific boundary: clipboard → external system.

This boundary is irreversible because:
- AI systems may log all inputs
- Data may enter training pipelines
- No "undo" exists for transmitted data
- Legal/compliance implications are immediate

The tool does not guard:
- Clipboard → local app (user's domain)
- File system operations
- Network traffic generally
- Anything after paste succeeds

Scope is narrow by design. Broader scope = weaker guarantees.

---

## Refusal as Feature

Pastewatch refuses to:
- Detect ambiguous patterns
- Store clipboard history
- Phone home
- Guess user intent
- Block paste entirely

These refusals are features, not limitations.

A tool that does less, reliably, is more valuable than a tool that attempts everything and fails unpredictably.

---

## Related Projects

Pastewatch is part of a family applying **Principiis obsta** at different boundaries:

| Project | Boundary | Intervention Point |
|---------|----------|-------------------|
| **Chainwatch** | AI agent execution | Before tool calls |
| **Pastewatch** | Data transmission | Before paste |
| **VaultSpectre** | Secrets lifecycle | Before exposure |
| **Relay** | Human connection | Before isolation compounds |

Same principle. Different surfaces. Consistent philosophy.

---

## Success Criteria

Pastewatch succeeds when:
- Users forget it exists
- Sensitive data never reaches AI chats
- No false positives disrupt workflow
- The system returns to rest after each paste

Pastewatch fails when:
- Users disable it due to annoyance
- Complex configuration is required
- Detection becomes unpredictable
- The tool demands attention
