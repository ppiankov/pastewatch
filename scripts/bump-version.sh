#!/usr/bin/env bash
# Bump the version in every file that embeds the version literal.
# Usage: scripts/bump-version.sh X.Y.Z
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 X.Y.Z" >&2
    exit 1
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: '$VERSION' is not a valid version (expected X.Y.Z)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION_FILE="Sources/PastewatchCore/Version.swift"
CURRENT=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "$VERSION_FILE" | head -1)
if [[ -z "$CURRENT" ]]; then
    echo "ERROR: could not extract current version from $VERSION_FILE" >&2
    exit 1
fi

if [[ "$CURRENT" == "$VERSION" ]]; then
    echo "Already at version $VERSION, nothing to do"
    exit 0
fi

echo "Bumping $CURRENT → $VERSION"
echo ""

CHANGED=()

# Replace $2 with $3 in file $1; exit non-zero if the pattern is not found.
replace_in() {
    local file="$1"
    local pattern="$2"
    local replacement="$3"

    if ! grep -qF "$pattern" "$file"; then
        echo "ERROR: expected pattern not found in $file" >&2
        echo "  Pattern: $pattern" >&2
        exit 1
    fi
    perl -i -pe "s|\Q${pattern}\E|${replacement}|g" "$file"
    CHANGED+=("$file")
}

# Single source of truth — version number only (no surrounding quotes in pattern)
replace_in "$VERSION_FILE" "${CURRENT}" "${VERSION}"

# README.md — shields.io badge URL, tag URL, status line
replace_in "README.md" "version-${CURRENT}-blue"  "version-${VERSION}-blue"
replace_in "README.md" "/tag/v${CURRENT}"          "/tag/v${VERSION}"
replace_in "README.md" "**v${CURRENT}**"           "**v${VERSION}**"

# WO-545@v2: Keep extracted versioned documentation synchronized during releases.
# docs/cli-reference.md — pre-commit rev
replace_in "docs/cli-reference.md" "rev: v${CURRENT}" "rev: v${VERSION}"

# docs/agent-safety.md — pre-commit rev
replace_in "docs/agent-safety.md" "rev: v${CURRENT}" "rev: v${VERSION}"

# docs/status.md — status headline
replace_in "docs/status.md" "v${CURRENT}" "v${VERSION}"

# CHANGELOG.md — prepend new section after [Unreleased] heading
TODAY=$(date +%Y-%m-%d)
python3 - <<PYEOF
import re, sys

with open('CHANGELOG.md', 'r') as f:
    content = f.read()

entry = "## [${VERSION}] - ${TODAY}\n\nTBD - fill in before tagging\n\n"
new = re.sub(r'(## \[Unreleased\]\n\n)', r'\g<1>' + entry, content, count=1)

if new == content:
    print("ERROR: [Unreleased] marker not found in CHANGELOG.md", file=sys.stderr)
    sys.exit(1)

with open('CHANGELOG.md', 'w') as f:
    f.write(new)
PYEOF
CHANGED+=("CHANGELOG.md")

echo "Files changed:"
printf '%s\n' "${CHANGED[@]}" | sort -u | while read -r f; do echo "  $f"; done

echo ""
echo "Next steps:"
echo "  1. Fill in CHANGELOG.md entry for [${VERSION}]"
echo "  2. git add -A && git commit -m 'chore: bump version to ${VERSION}'"
# WO-546: Releases must pass through branch CI before automation tags them.
echo "  3. Push the release branch and open a PR; do not push directly to main"
echo "  4. Merge after CI; release automation will tag and publish v${VERSION}"
