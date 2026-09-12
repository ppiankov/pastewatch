#!/usr/bin/env bash
# WO-623@v2: exercise the same section validator used before release builds and publication.
set -euo pipefail

# WO-623@v2: resolve fixtures independently of the invoking working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# WO-623@v2: test the exact helper invoked by the release workflow.
GUARD="$SCRIPT_DIR/changelog-guard.sh"
# WO-623@v2: keep regression fixtures isolated from the repository changelog.
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pastewatch-changelog.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
# WO-623@v2: count only cases that satisfy output and diagnostic assertions.
CASES=0

# WO-623@v2: accepted output must contain exactly the requested notes, not neighboring sections.
accepts() {
    local name="$1" tag="$2" input="$3" expected="$4"
    printf '%s' "$input" > "$FIXTURE_DIR/CHANGELOG.md"
    printf '%s' "$expected" > "$FIXTURE_DIR/expected"
    bash "$GUARD" "$tag" "$FIXTURE_DIR/CHANGELOG.md" > "$FIXTURE_DIR/actual" 2> "$FIXTURE_DIR/error"
    if ! cmp -s "$FIXTURE_DIR/expected" "$FIXTURE_DIR/actual" || [[ -s "$FIXTURE_DIR/error" ]]; then
        printf 'FAIL: %s returned unexpected notes or diagnostics\n' "$name" >&2
        exit 1
    fi
    CASES=$((CASES + 1))
}

# WO-623@v2: refusals must be nonzero, version/line-specific, and leave stdout empty.
rejects() {
    local name="$1" input="$2" line="$3" reason="$4"
    printf '%s' "$input" > "$FIXTURE_DIR/CHANGELOG.md"
    if bash "$GUARD" v1.2.3 "$FIXTURE_DIR/CHANGELOG.md" > "$FIXTURE_DIR/actual" 2> "$FIXTURE_DIR/error"; then
        printf 'FAIL: %s was accepted\n' "$name" >&2
        exit 1
    fi
    if [[ -s "$FIXTURE_DIR/actual" ]] ||
        ! grep -Fq "line=$line::CHANGELOG [1.2.3]" "$FIXTURE_DIR/error" ||
        ! grep -Fq "$reason" "$FIXTURE_DIR/error"; then
        printf 'FAIL: %s did not produce the expected refusal\n' "$name" >&2
        exit 1
    fi
    CASES=$((CASES + 1))
}

NOTES=$'\n### Fixed\n\n- Correct release behavior.\n\n'
accepts real-notes v1.2.3 $'## [1.2.3] - 2026-09-12\n'"$NOTES" "$NOTES"
accepts unprefixed-version 1.2.3 $'## [1.2.3]\n'"$NOTES" "$NOTES"
accepts unrelated-placeholders v1.2.3 \
    $'## [Unreleased]\n\nTBD - fill in before tagging\n\n## [1.2.3]\n'"$NOTES"$'## [1.2.2]\nTBD\n' "$NOTES"
accepts literal-version v1.2.3 \
    $'## [1x2x3]\nTBD\n## [1.2.30]\nTBD\n## [1.2.3]\n'"$NOTES" "$NOTES"
accepts crlf v1.2.3 $'## [1.2.3]\r\n\r\n- Fixed behavior.\r\n' $'\n- Fixed behavior.\n'
accepts final-line-without-newline v1.2.3 $'## [1.2.3]\n- Fixed behavior.' $'- Fixed behavior.\n'
accepts authored-placeholder-mention v1.2.3 \
    $'## [1.2.3]\n- Removed obsolete TBD placeholders.\n' $'- Removed obsolete TBD placeholders.\n'
rejects leftover-stub $'## [1.2.3]\n\n### Fixed\n\n- Actual fix.\n\nTBD - fill in before tagging\n' 7 'TBD placeholder'
rejects mixed-case $'## [1.2.3]\n  tBd: pending\n' 2 'TBD placeholder'
rejects bulleted-placeholder $'## [1.2.3]\n- TBD\n' 2 'TBD placeholder'
rejects placeholder-phrase $'## [1.2.3]\n- Please FILL IN BEFORE TAGGING.\n' 2 'TBD placeholder'
rejects empty $'## [1.2.3]\n' 1 'section is empty'
rejects whitespace $'## [1.2.3]\n \t\n\n## [1.2.2]\n- Other notes.\n' 1 'section is empty'
rejects headings-only $'## [1.2.3]\n\n### Fixed\n\n' 1 'section is empty'
rejects missing $'## [Unreleased]\n- Upcoming.\n## [1.2.30]\n- Other notes.\n' 1 'section is missing'
rejects duplicate $'## [1.2.3]\n- First.\n## [1.2.3]\n- Second.\n' 3 'section is duplicated'

# WO-623@v2: invalid invocation and missing input must fail without producing release notes.
if bash "$GUARD" 1x2x3 "$FIXTURE_DIR/CHANGELOG.md" > "$FIXTURE_DIR/actual" 2> "$FIXTURE_DIR/error"; then
    printf 'FAIL: malformed version was accepted\n' >&2
    exit 1
fi
[[ ! -s "$FIXTURE_DIR/actual" ]]
grep -Fq 'Usage:' "$FIXTURE_DIR/error"
CASES=$((CASES + 1))
if bash "$GUARD" v1.2.3 "$FIXTURE_DIR/missing.md" > "$FIXTURE_DIR/actual" 2> "$FIXTURE_DIR/error"; then
    printf 'FAIL: missing changelog was accepted\n' >&2
    exit 1
fi
[[ ! -s "$FIXTURE_DIR/actual" ]]
grep -Fq 'line=1::CHANGELOG [1.2.3] is missing or unreadable' "$FIXTURE_DIR/error"
CASES=$((CASES + 1))
printf 'Passed %d changelog guard cases\n' "$CASES"
