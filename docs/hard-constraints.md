# Hard Constraints

These constraints are non-negotiable. They define what Pastewatch is.

Violating any constraint means building a different tool.

---

## 1. Local-Only Operation

**No network calls. No exceptions.**

- No telemetry
- No analytics
- No cloud processing
- No update checks
- No "optional" sync

The clipboard is sensitive by definition. Transmitting it anywhere defeats the purpose.

---

## 2. Deterministic Detection

**All detection must be rules-based. No ML.**

- Regex patterns only
- Heuristic validation (Luhn, length checks)
- No probabilistic scoring
- No "confidence levels"
- No model inference

Users must be able to predict exactly what will be detected. ML introduces unpredictability.

---

## 3. Conservative Matching

**False negatives are preferred over false positives.**

- When uncertain, do nothing
- Never guess intent
- Never match "probably" sensitive data
- Accept that some secrets will pass through

A tool that cries wolf gets disabled. A tool that occasionally misses stays installed.

---

## 4. Memory-Only State

**No persistence of sensitive data.**

- Mappings exist only during paste
- No clipboard history
- No logs of original content
- No recovery mechanism

After paste completes, the system returns to rest. No trace remains.

---

## 5. Minimal UI Surface

**The tool should be invisible when working correctly.**

- No dashboards
- No statistics beyond session count
- No engagement features
- No gamification
- Notifications only when action taken

Attention is expensive. Don't waste it.

---

## 6. Safe Defaults

**No configuration required for secure operation.**

- Works immediately after install
- All detection types enabled by default
- Notifications on by default
- No "setup wizard"

Users who never open settings should be fully protected.

---

## 7. No Blocking

**Never prevent paste entirely.**

- Obfuscate, don't block
- User retains control
- Paste always succeeds (with modifications)
- No modal dialogs interrupting workflow

The user's intent is sacred. Modify the data, not the action.

---

## 8. Scope Limitation

**Only guard clipboard → external system boundary.**

- Not a general DLP tool
- Not a compliance product
- Not a file scanner
- Not a network monitor

Narrow scope = strong guarantees. Broader scope = weaker everything.

---

## Constraint Violations

If a proposed feature violates any constraint, the answer is **no**.

Not "maybe with a flag."
Not "optional for power users."
Not "behind a config."

No.

These constraints exist because removing them creates a different tool — one that erodes trust, demands attention, and eventually gets uninstalled.
