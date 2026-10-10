#!/usr/bin/env bash
# WO-664@v1: exercise committed-blob comparisons using isolated deterministic Git fixtures.
set -euo pipefail

# WO-664@v1: fixture paths do not depend on the caller CWD or on operator files.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# WO-664@v1: fixtures execute the production entry point, not a copied validator.
GUARD="$SCRIPT_DIR/changelog-placement-guard.sh"
# WO-664@v1: all generated fixture objects stay in an owned temporary directory.
FIXTURE_DIR="$(mktemp -d /tmp/pastewatch-placement-tests.XXXXXX)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
# WO-664@v1: the bare fixture repository cannot modify the product checkout.
REPO="$FIXTURE_DIR/repo.git"
git init --bare --quiet "$REPO"
# WO-664@v1: count cases only after checking both exit status and diagnostic output.
CASES=0

# WO-664@v1: synthesize real commit objects without changing a checkout or requiring external services.
commit_fixture() {
    local content="$1" subject="$2" parent="${3:-}" blob tree
    blob="$(printf '%s' "$content" | git --git-dir="$REPO" hash-object -w --stdin)"
    tree="$(printf '100644 blob %s\tCHANGELOG.md\n' "$blob" | git --git-dir="$REPO" mktree)"
    local args=("$tree")
    if [[ -n "$parent" ]]; then args+=(-p "$parent"); fi
    printf '%s\n' "$subject" | GIT_AUTHOR_NAME=ppiankov GIT_COMMITTER_NAME=ppiankov \
        GIT_AUTHOR_EMAIL=103106369+ppiankov@users.noreply.github.com \
        GIT_COMMITTER_EMAIL=103106369+ppiankov@users.noreply.github.com \
        GIT_AUTHOR_DATE=2026-10-08T00:00:00Z GIT_COMMITTER_DATE=2026-10-08T00:00:00Z \
        git --git-dir="$REPO" commit-tree "${args[@]}"
}

# WO-664@v1: accepted changes must pass the production script without refusal diagnostics.
accepts() {
    local name="$1" content="$2" subject="$3" head
    head="$(commit_fixture "$content" "$subject" "$BASE")"
    if ! GIT_DIR="$REPO" bash "$GUARD" "$BASE" "$head" > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
        printf 'FAIL: %s was refused\n' "$name" >&2
        exit 1
    fi
    [[ ! -s "$FIXTURE_DIR/error" ]]
    grep -Fq 'Changelog placement check passed' "$FIXTURE_DIR/output"
    CASES=$((CASES + 1))
}

# WO-664@v1: failures must locate the released section and added line, never print its content.
rejects() {
    local name="$1" content="$2" subject="$3" line="$4" head
    head="$(commit_fixture "$content" "$subject" "$BASE")"
    if GIT_DIR="$REPO" bash "$GUARD" "$BASE" "$head" > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
        printf 'FAIL: %s was accepted\n' "$name" >&2
        exit 1
    fi
    [[ ! -s "$FIXTURE_DIR/output" ]]
    grep -Fq "file=CHANGELOG.md,line=$line::" "$FIXTURE_DIR/error"
    grep -Fq 'previously released section [1.2.3]' "$FIXTURE_DIR/error"
    if grep -Fq 'misplaced fixture text' "$FIXTURE_DIR/error"; then
        printf 'FAIL: %s printed line contents\n' "$name" >&2
        exit 1
    fi
    CASES=$((CASES + 1))
}

# WO-664@v1: the base pins which release sections were already published.
BASE_TEXT=$'# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- Upcoming change.\n\n## [1.2.3] - 2026-10-01\n\n- Published change.\n'
BASE="$(commit_fixture "$BASE_TEXT" 'chore: fixture base')"
accepts unreleased-addition \
    $'# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- Upcoming change.\n- New change.\n\n## [1.2.3] - 2026-10-01\n\n- Published change.\n' \
    'fix: add new change'
rejects published-addition "$BASE_TEXT"$'- misplaced fixture text\n' 'fix: add new change' 12
accepts release-moves-unreleased \
    $'# Changelog\n\n## [Unreleased]\n\n## [1.2.4] - 2026-10-08\n\n### Fixed\n\n- Upcoming change.\n\n## [1.2.3] - 2026-10-01\n\n- Published change.\n' \
    'chore: release v1.2.4'
accepts bump-moves-unreleased \
    $'# Changelog\n\n## [Unreleased]\n\n## [1.2.4] - 2026-10-08\n\n### Fixed\n\n- Upcoming change.\n\n## [1.2.3] - 2026-10-01\n\n- Published change.\n' \
    'chore: bump version to 1.2.4'
rejects release-cannot-rewrite-older "$BASE_TEXT"$'- misplaced fixture text\n' 'chore: release v1.2.4' 12
accepts release-can-edit-named-section "$BASE_TEXT"$'- Release correction.\n' 'chore: release v1.2.3'
rejects near-miss-release-subject "$BASE_TEXT"$'- misplaced fixture text\n' 'chore: release v1.2.3 later' 12
accepts unchanged "$BASE_TEXT" 'fix: unrelated change'

# WO-675@v2: only an explicit operator correction subject permits edits to published notes.
accepts operator-typo-correction "${BASE_TEXT/Published change./Published correction.}" 'chore: fix changelog'
rejects near-miss-typo-subject "$BASE_TEXT"$'- misplaced fixture text\n' 'chore: fix changelog later' 12

# WO-675@v2: a release must not delete or rewrite any other published section.
rejects release-cannot-delete-older \
    $'# Changelog\n\n## [Unreleased]\n\n## [1.2.4] - 2026-10-08\n\n- Release change.\n\n## [1.2.3] - 2026-10-01\n' \
    'chore: release v1.2.4' 10

# WO-675@v2: protect a version published at the base tip even if the branch fork predates it.
TIP_TEXT=$'# Changelog\n\n## [Unreleased]\n\n## [1.2.4] - 2026-10-08\n\n- Released on main.\n\n## [1.2.3] - 2026-10-01\n\n- Published change.\n'
PUBLISHED_TIP="$(commit_fixture "$TIP_TEXT" 'chore: release v1.2.4' "$BASE")"
FORK_HEAD="$(commit_fixture "${TIP_TEXT/Released on main./Ordinary branch change.}" 'fix: new change' "$BASE")"
if GIT_DIR="$REPO" bash "$GUARD" "$PUBLISHED_TIP" "$FORK_HEAD" > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
    printf 'FAIL: section published after the fork was not protected\n' >&2
    exit 1
fi
grep -Fq 'previously released section [1.2.4]' "$FIXTURE_DIR/error"
CASES=$((CASES + 1))

# WO-664@v1: later base-branch edits are not additions made by a stale pull-request branch.
MAIN_TIP="$(commit_fixture "${BASE_TEXT/Published change./Corrected published change.}" 'docs: fix published notes' "$BASE")"
STALE_HEAD="$(commit_fixture "$BASE_TEXT" 'fix: unrelated stale branch' "$BASE")"
if ! GIT_DIR="$REPO" bash "$GUARD" "$MAIN_TIP" "$STALE_HEAD" > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
    printf 'FAIL: stale branch was blamed for later main changes\n' >&2
    exit 1
fi
[[ ! -s "$FIXTURE_DIR/error" ]]
CASES=$((CASES + 1))

# WO-664@v1: missing commit inputs fail before any apparent successful validation.
if GIT_DIR="$REPO" bash "$GUARD" "$BASE" absent > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
    printf 'FAIL: invalid commit input was accepted\n' >&2
    exit 1
fi
[[ ! -s "$FIXTURE_DIR/output" ]]
CASES=$((CASES + 1))
printf 'Passed %d changelog placement cases\n' "$CASES"
