#!/usr/bin/env bash
# WO-664@v1: previously published changelog sections cannot acquire ordinary PR additions.
set -euo pipefail

# WO-664@v1: callers provide the PR base and actual head, not the synthetic merge commit.
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s BASE_COMMIT HEAD_COMMIT\n' "$0" >&2
    exit 64
fi
# WO-664@v1: resolve the comparison base to an immutable commit before reading published headings.
BASE="$(git rev-parse --verify --end-of-options "${1}^{commit}")"
# WO-664@v1: resolve the actual PR head before reading its subject or changelog additions.
HEAD="$(git rev-parse --verify --end-of-options "${2}^{commit}")"
# WO-664@v1: compare PR-owned additions since its fork, not unrelated edits at the base tip.
BASE="$(git merge-base "$BASE" "$HEAD")"

# WO-664@v1: a release subject exempts only its named version, never older published notes.
SUBJECT="$(git show -s --format=%s "$HEAD")"
# WO-664@v1: ordinary subjects receive no released-section exemption.
RELEASE_VERSION=""
# WO-664@v1: only the two exact release-subject forms authorize a named-version exception.
RELEASE_SUBJECT='^chore: (release v|bump version to )([0-9]+\.[0-9]+\.[0-9]+)$'
if [[ "$SUBJECT" =~ $RELEASE_SUBJECT ]]; then
    RELEASE_VERSION="${BASH_REMATCH[2]}"
fi

# WO-664@v1: inspect committed blobs without modifying either revision or rewriting UTF-8 documentation.
FIXTURE_DIR="$(mktemp -d /tmp/pastewatch-changelog-placement.XXXXXX)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
git show "$BASE:CHANGELOG.md" > "$FIXTURE_DIR/base"
git show "$HEAD:CHANGELOG.md" > "$FIXTURE_DIR/head"
git diff --no-color --no-ext-diff --no-textconv --unified=0 "$BASE" "$HEAD" -- CHANGELOG.md > "$FIXTURE_DIR/diff"

# WO-664@v1: map added hunk lines to head sections, emitting only version and line metadata on refusal.
awk -v release="$RELEASE_VERSION" '
    # WO-664@v1: match literal version headings, not arbitrary brackets or version substrings.
    function version(line, result) {
        sub(/\r$/, "", line)
        if (line !~ /^##[[:space:]]+\[[0-9]+\.[0-9]+\.[0-9]+\]([[:space:]]|$)/) return ""
        result = line
        sub(/^##[[:space:]]+\[/, "", result)
        sub(/\].*$/, "", result)
        return result
    }
    FILENAME == ARGV[1] {
        value = version($0)
        if (value != "") published[value] = 1
        next
    }
    FILENAME == ARGV[2] {
        if ($0 ~ /^##[[:space:]]/) section = version($0)
        sections[FNR] = section
        next
    }
    /^@@ / {
        split($0, fields, " ")
        range = fields[3]
        sub(/^\+/, "", range)
        split(range, offsets, ",")
        line = offsets[1] + 0
        in_hunk = 1
        next
    }
    !in_hunk { next }
    /^\+/ {
        section = sections[line]
        if (section in published && section != release) {
            printf "::error file=CHANGELOG.md,line=%d::Added line is in previously released section [%s]; use [Unreleased].\n", line, section > "/dev/stderr"
            rejected = 1
        }
        line++
        next
    }
    /^ / { line++ }
    END {
        if (rejected) exit 1
        print "Changelog placement check passed"
    }
' "$FIXTURE_DIR/base" "$FIXTURE_DIR/head" "$FIXTURE_DIR/diff"
