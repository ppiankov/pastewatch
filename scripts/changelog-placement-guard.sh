#!/usr/bin/env bash
# WO-664@v1: previously published changelog sections cannot acquire ordinary PR additions.
set -euo pipefail

# WO-664@v1: callers provide the PR base and actual head, not the synthetic merge commit.
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s BASE_COMMIT HEAD_COMMIT\n' "$0" >&2
    exit 64
fi
# WO-675@v2: published headings at the current base tip remain protected after a branch fork.
BASE_TIP="$(git rev-parse --verify --end-of-options "${1}^{commit}")"
# WO-664@v1: resolve the actual PR head before reading its subject or changelog additions.
HEAD="$(git rev-parse --verify --end-of-options "${2}^{commit}")"
# WO-664@v1: compare PR-owned additions since its fork, not unrelated edits at the base tip.
# WO-675@v2: only branch-owned changes since the fork are attributed to the pull request.
BASE="$(git merge-base "$BASE_TIP" "$HEAD")"

# WO-664@v1: a release subject exempts only its named version, never older published notes.
SUBJECT="$(git show -s --format=%s "$HEAD")"
# WO-664@v1: ordinary subjects receive no released-section exemption.
RELEASE_VERSION=""
# WO-664@v1: only the two exact release-subject forms authorize a named-version exception.
RELEASE_SUBJECT='^chore: (release v|bump version to )([0-9]+\.[0-9]+\.[0-9]+)$'
if [[ "$SUBJECT" =~ $RELEASE_SUBJECT ]]; then
    RELEASE_VERSION="${BASH_REMATCH[2]}"
fi
# WO-675@v2: typo corrections require an explicit, exact operator subject rather than a blanket release bypass.
CORRECTION=0
if [[ "$SUBJECT" == 'chore: fix changelog' ]]; then CORRECTION=1; fi

# WO-664@v1: inspect committed blobs without modifying either revision or rewriting UTF-8 documentation.
FIXTURE_DIR="$(mktemp -d /tmp/pastewatch-changelog-placement.XXXXXX)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
git show "$BASE:CHANGELOG.md" > "$FIXTURE_DIR/base"
# WO-675@v2: the fork and base tip jointly identify sections already published.
git show "$BASE_TIP:CHANGELOG.md" > "$FIXTURE_DIR/tip"
git show "$HEAD:CHANGELOG.md" > "$FIXTURE_DIR/head"
git diff --no-color --no-ext-diff --no-textconv --unified=0 "$BASE" "$HEAD" -- CHANGELOG.md > "$FIXTURE_DIR/diff"

# WO-675@v2: inspect additions and deletions so a release cannot rewrite another published version.
awk -v release="$RELEASE_VERSION" -v correction="$CORRECTION" '
    # WO-664@v1: match literal version headings, not arbitrary brackets or version substrings.
    function version(line, result) {
        sub(/\r$/, "", line)
        if (line !~ /^##[[:space:]]+\[[0-9]+\.[0-9]+\.[0-9]+\]([[:space:]]|$)/) return ""
        result = line
        sub(/^##[[:space:]]+\[/, "", result)
        sub(/\].*$/, "", result)
        return result
    }
    # WO-675@v2: removed lines retain their original section, including headings and blank lines.
    FILENAME == ARGV[1] {
        value = version($0)
        if (value != "") published[value] = 1
        if ($0 ~ /^##[[:space:]]/) old_section = value
        old_sections[FNR] = old_section
        next
    }
    # WO-675@v2: protect post-fork releases without attributing their unrelated changes to the branch.
    FILENAME == ARGV[2] {
        value = version($0)
        if (value != "") published[value] = 1
        next
    }
    FILENAME == ARGV[3] {
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
        # WO-675@v2: deletion positions are measured in the fork blob, not the head blob.
        old_range = fields[2]
        sub(/^-/, "", old_range)
        split(old_range, old_offsets, ",")
        old_line = old_offsets[1] + 0
        in_hunk = 1
        next
    }
    !in_hunk { next }
    /^\+/ {
        section = sections[line]
        # WO-675@v2: only the named release or explicit correction can change published notes.
        if (section in published && section != release && !correction) {
            printf "::error file=CHANGELOG.md,line=%d::Added line is in previously released section [%s]; use [Unreleased].\n", line, section > "/dev/stderr"
            rejected = 1
        }
        line++
        next
    }
    # WO-675@v2: removal-only changes to older releases must not escape the placement check.
    /^-/ {
        section = old_sections[old_line]
        if (section in published && section != release && !correction) {
            printf "::error file=CHANGELOG.md,line=%d::Removed line is in previously released section [%s]; use [Unreleased].\n", old_line, section > "/dev/stderr"
            rejected = 1
        }
        old_line++
        next
    }
    /^ / { line++; old_line++ }
    END {
        if (rejected) exit 1
        print "Changelog placement check passed"
    }
' "$FIXTURE_DIR/base" "$FIXTURE_DIR/tip" "$FIXTURE_DIR/head" "$FIXTURE_DIR/diff"
