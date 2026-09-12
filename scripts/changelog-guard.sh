#!/usr/bin/env bash
# WO-623@v2: validate and emit the exact release section through one shared publication gate.
set -euo pipefail

# WO-623@v2: use only the resolved release version, never an adjacent changelog section.
VERSION="${1:-}"
# WO-623@v2: accept both workflow tags and the numeric version used by local checks.
VERSION="${VERSION#v}"
# WO-623@v2: allow isolated fixtures to exercise the production parser.
CHANGELOG="${2:-CHANGELOG.md}"
if [[ $# -lt 1 || $# -gt 2 || ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf 'Usage: %s [v]X.Y.Z [CHANGELOG.md]\n' "$0" >&2
    exit 2
fi
if [[ ! -f "$CHANGELOG" || ! -r "$CHANGELOG" ]]; then
    printf '::error file=%s,line=1::CHANGELOG [%s] is missing or unreadable\n' "$CHANGELOG" "$VERSION" >&2
    exit 1
fi

# WO-623@v2: buffer notes until validation finishes so failures never emit publishable output.
awk -v version="$VERSION" '
    # WO-623@v2: diagnostics locate the version and offending source line without rewriting notes.
    function reject(line, reason) {
        printf "::error file=%s,line=%d::CHANGELOG [%s] %s; edit this section before tagging\n", FILENAME, line, version, reason > "/dev/stderr"
        exit 1
    }
    BEGIN { heading = "## [" version "]" }
    {
        sub(/\r$/, "")
        if (/^##[[:space:]]/) {
            active = ($0 == heading || index($0, heading " ") == 1 || index($0, heading "\t") == 1)
            if (active) {
                sections++
                header_line = NR
            }
            next
        }
        if (!active) next
        notes = notes $0 "\n"
        lower = tolower($0)
        if (!placeholder_line && (lower ~ /^[[:space:]]*([-*+][[:space:]]+)?tbd([^[:alnum:]_]|$)/ || lower ~ /fill[[:space:]]+in[[:space:]]+before[[:space:]]+tagging/)) {
            placeholder_line = NR
        }
        if (/[^[:space:]]/ && !/^[[:space:]]*#+([[:space:]]|$)/) content = 1
    }
    END {
        if (!sections) reject(1, "section is missing")
        if (sections > 1) reject(header_line, "section is duplicated")
        if (placeholder_line) reject(placeholder_line, "contains a TBD placeholder; replace it with real release notes")
        if (!content) reject(header_line, "section is empty; add real release notes")
        printf "%s", notes
    }
' "$CHANGELOG"
