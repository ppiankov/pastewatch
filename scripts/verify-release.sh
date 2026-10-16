#!/usr/bin/env bash
# WO-693@v1: independently verify published release artifacts without changing remote state.
set -euo pipefail

# WO-693@v1: failures identify the check without exposing downloaded content or tool diagnostics.
fail() {
    printf 'FAIL %s\n' "$1" >&2
    exit 1
}

[[ $# -eq 1 && $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'version: expected X.Y.Z without v'
version=$1
tag="v$version"
repository=ppiankov/pastewatch
max_polls=${VERIFY_RELEASE_MAX_POLLS:-60}
poll_interval_seconds=30
[[ $max_polls =~ ^[1-9][0-9]*$ ]] || fail 'poll limit: expected a positive integer'

# WO-693@v1: peel annotated tags so release runs are always matched to the commit, not a tag object.
reference=$(gh api "repos/$repository/git/ref/tags/$tag" \
    --jq '.object | [.type, .sha] | @tsv' 2>/dev/null) || fail 'tag lookup'
max_tag_depth=16
for ((depth = 0; depth < max_tag_depth; depth++)); do
    IFS=$'\t' read -r object_type tag_commit <<< "$reference"
    [[ $tag_commit =~ ^[0-9a-f]{40}$ ]] || fail 'tag commit'
    [[ $object_type != commit ]] || break
    [[ $object_type == tag ]] || fail 'tag object type'
    reference=$(gh api "repos/$repository/git/tags/$tag_commit" \
        --jq '.object | [.type, .sha] | @tsv' 2>/dev/null) || fail 'annotated tag lookup'
done
[[ $object_type == commit ]] || fail 'tag depth limit'
printf 'PASS tag %s %s\n' "$tag" "$tag_commit"

# WO-693@v1: workflow_dispatch releases may run on main; only the tag commit selects release runs.
run_list=$(gh run list --repo "$repository" --workflow release.yml --commit "$tag_commit" --limit 1000 \
    --json databaseId,headSha,event,status,conclusion \
    --jq ".[] | select(.headSha == \"$tag_commit\") | .databaseId" 2>/dev/null) || fail 'release run lookup'
run_ids=()
while IFS= read -r run_id; do
    [[ -n $run_id ]] || continue
    [[ $run_id =~ ^[0-9]+$ ]] || fail 'release run id'
    run_ids+=("$run_id")
done <<< "$run_list"
[[ ${#run_ids[@]} -gt 0 ]] || fail 'no release run for tag commit'
if [[ ${#run_ids[@]} -gt 1 ]]; then
    printf 'WARN DOUBLE-RUN'
    printf ' %s' "${run_ids[@]}"
    printf '\n'
fi

# WO-693@v1: every selected run must finish successfully within the bounded polling interval.
for ((poll = 1; poll <= max_polls; poll++)); do
    pending=0
    for run_id in "${run_ids[@]}"; do
        state=$(gh run view "$run_id" --repo "$repository" --json status,conclusion \
            --jq '[.status, (.conclusion // "")] | @tsv' 2>/dev/null) || fail "release run $run_id status"
        IFS=$'\t' read -r status conclusion <<< "$state"
        [[ -n $status ]] || fail "release run $run_id status"
        if [[ $status == completed ]]; then
            [[ $conclusion == success ]] || fail "release run $run_id conclusion"
        else
            pending=1
        fi
    done
    [[ $pending -ne 0 ]] || break
    [[ $poll -lt $max_polls ]] || fail 'release run polling limit'
    sleep "$poll_interval_seconds"
done
for run_id in "${run_ids[@]}"; do
    printf 'PASS release run %s\n' "$run_id"
done

# WO-693@v1: downloads stay in a private temporary directory and are removed on every exit.
scratch=$(mktemp -d /tmp/pastewatch-verify-release.XXXXXX) || fail 'temporary directory'
trap 'rm -rf "$scratch"' EXIT
download_url="https://github.com/$repository/releases/download/$tag"
assets=(pastewatch-cli pastewatch-cli-linux-amd64 pastewatch-cli-linux-arm64)
digests=()
for asset in "${assets[@]}"; do
    curl -fsSL -o "$scratch/$asset" "$download_url/$asset" 2>/dev/null || fail "download $asset"
    curl -fsSL -o "$scratch/$asset.sha256" "$download_url/$asset.sha256" 2>/dev/null || fail "download $asset.sha256"
    expected=$(awk 'NR == 1 { print tolower($1) }' "$scratch/$asset.sha256") || fail "checksum file $asset"
    actual=$(shasum -a 256 "$scratch/$asset" 2>/dev/null | awk '{ print tolower($1) }') || fail "checksum $asset"
    [[ $expected =~ ^[0-9a-f]{64}$ && $actual =~ ^[0-9a-f]{64}$ && $actual == "$expected" ]] \
        || fail "published checksum $asset"
    digests+=("$actual")
    printf 'PASS checksum %s %s\n' "$asset" "$actual"
done

# WO-693@v1: bind each formula checksum to its exact platform URL, not an unordered set of digests.
gh api 'repos/ppiankov/homebrew-tap/contents/Formula/pastewatch.rb?ref=main' \
    -H 'Accept: application/vnd.github.raw+json' > "$scratch/formula.rb" 2>/dev/null || fail 'formula download'
awk -v expected="$version" '
    $1 == "version" { split($0, fields, "\""); count++; valid = fields[2] == expected }
    END { exit !(count == 1 && valid) }
' "$scratch/formula.rb" || fail 'formula version'
printf 'PASS formula version %s\n' "$version"
for ((index = 0; index < ${#assets[@]}; index++)); do
    asset=${assets[index]}
    awk -v expected_url="$download_url/$asset" -v expected_sha="${digests[index]}" '
        $1 == "url" { split($0, fields, "\""); url = fields[2] }
        $1 == "sha256" && url == expected_url {
            split($0, fields, "\""); count++; valid = tolower(fields[2]) == expected_sha
        }
        END { exit !(count == 1 && valid) }
    ' "$scratch/formula.rb" || fail "formula checksum $asset"
    printf 'PASS formula checksum %s %s\n' "$asset" "${digests[index]}"
done

# WO-693@v1: the downloaded macOS CLI must identify the requested version after its digest is verified.
if [[ $(uname -s) == Darwin ]]; then
    chmod u+x "$scratch/pastewatch-cli" || fail 'macOS binary permissions'
    installed_version=$("$scratch/pastewatch-cli" --version 2>/dev/null) || fail 'macOS binary version'
    [[ $installed_version == "$version" ]] || fail 'macOS binary version'
    printf 'PASS macOS binary version %s\n' "$version"
fi
printf 'VERIFIED %s\n' "$tag"
