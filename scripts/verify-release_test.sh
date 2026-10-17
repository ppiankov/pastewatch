#!/usr/bin/env bash
# WO-693@v1: exercise release verification with isolated command stubs and no network access.
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
scratch=$(mktemp -d /tmp/pastewatch-verify-release-test.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin"
# WO-693@v1: command stubs receive only the isolated fixture directory.
export VERIFY_RELEASE_FIXTURES="$scratch"
export FIXTURE_TAG_SHA
export FIXTURE_MAC_SHA FIXTURE_AMD_SHA FIXTURE_ARM_SHA
# WO-693@v1: the synthetic commit identity is independent of the release branch name.
FIXTURE_TAG_SHA=$(printf '%040d' 1)
# WO-693@v1: platform-specific fixture digests make cross-platform swaps observable.
FIXTURE_MAC_SHA=$(printf '%064d' 1)
# WO-693@v1: the amd64 asset has its own independently checked fixture digest.
FIXTURE_AMD_SHA=$(printf '%064d' 2)
# WO-693@v1: the arm64 asset has its own independently checked fixture digest.
FIXTURE_ARM_SHA=$(printf '%064d' 3)

cat > "$scratch/pastewatch-cli" <<'BINARY'
#!/usr/bin/env bash
[[ ${1-} == --version ]] || exit 1
printf '%s\n' '0.43.0'
BINARY
cp "$scratch/pastewatch-cli" "$scratch/pastewatch-cli-linux-amd64"
cp "$scratch/pastewatch-cli" "$scratch/pastewatch-cli-linux-arm64"

cat > "$scratch/bin/gh" <<'GH'
#!/usr/bin/env bash
# WO-693@v1: model tag resolution and workflow projections without contacting GitHub.
set -euo pipefail
scenario=$VERIFY_RELEASE_SCENARIO
if [[ $1 == api ]]; then
    case $2 in
        repos/ppiankov/pastewatch/git/ref/tags/v0.43.0)
            [[ $scenario != missing-tag ]] || exit 1
            if [[ $scenario == annotated-tag ]]; then
                printf 'tag\t%040d\n' 9
            else
                printf 'commit\t%s\n' "$FIXTURE_TAG_SHA"
            fi
            ;;
        repos/ppiankov/pastewatch/git/tags/*)
            [[ $scenario == annotated-tag ]] || exit 1
            printf 'commit\t%s\n' "$FIXTURE_TAG_SHA"
            ;;
        'repos/ppiankov/homebrew-tap/contents/Formula/pastewatch.rb?ref=main')
            [[ $* == *'Accept: application/vnd.github.raw+json'* ]] || exit 1
            cat "$VERIFY_RELEASE_FIXTURES/formula.rb"
            ;;
        *) exit 1 ;;
    esac
elif [[ $1 == run && $2 == list ]]; then
    [[ $* == *'--workflow release.yml'* && $* == *'--json databaseId,headSha,event,status,conclusion'* ]] || exit 1
    [[ $* != *headBranch* && $* != *--branch* && $* != *--event* ]] || exit 1
    shift 2
    query=
    while [[ $# -gt 0 ]]; do
        if [[ $1 == --jq ]]; then
            query=$2
            shift 2
        else
            shift
        fi
    done
    [[ $query == ".[] | select(.headSha == \"$FIXTURE_TAG_SHA\") | .databaseId" ]] || exit 1
    candidate_sha=$FIXTURE_TAG_SHA
    [[ $scenario != no-run ]] || candidate_sha=$(printf '%040d' 9)
    # WO-693@v1: the selected fixture has headBranch=main and workflow_dispatch, not a tag branch.
    while read -r id sha branch event; do
        [[ $branch == main && $event == workflow_dispatch ]] || exit 1
        [[ $sha != "$FIXTURE_TAG_SHA" ]] || printf '%s\n' "$id"
    done <<< "101 $candidate_sha main workflow_dispatch"
    [[ $scenario != two-runs ]] || printf '%s\n' 102
elif [[ $1 == run && $2 == view ]]; then
    [[ $3 == 101 || $3 == 102 ]] || exit 1
    case $scenario in
        failed-run) printf 'completed\tfailure\n' ;;
        pending-run) printf 'in_progress\t\n' ;;
        *) printf 'completed\tsuccess\n' ;;
    esac
else
    exit 1
fi
GH

cat > "$scratch/bin/curl" <<'CURL'
#!/usr/bin/env bash
# WO-693@v1: downloads require fail-on-HTTP-error and redirects, and never fall through to real curl.
set -euo pipefail
[[ $# -eq 4 && $1 == -fsSL && $2 == -o ]] || exit 1
output=$3
[[ $4 == https://github.com/ppiankov/pastewatch/releases/download/v0.43.0/* ]] || exit 1
asset=${4##*/}
case ${asset%.sha256} in
    pastewatch-cli) digest=$FIXTURE_MAC_SHA ;;
    pastewatch-cli-linux-amd64) digest=$FIXTURE_AMD_SHA ;;
    pastewatch-cli-linux-arm64) digest=$FIXTURE_ARM_SHA ;;
    *) exit 1 ;;
esac
if [[ $asset == *.sha256 ]]; then
    printf '%s  %s\n' "$digest" "${asset%.sha256}" > "$output"
else
    cp "$VERIFY_RELEASE_FIXTURES/$asset" "$output"
fi
CURL

cat > "$scratch/bin/shasum" <<'SHASUM'
#!/usr/bin/env bash
# WO-693@v1: deterministic digest projections let mismatch cases test each independent comparison.
set -euo pipefail
[[ $# -eq 3 && $1 == -a && $2 == 256 && -f $3 ]] || exit 1
case ${3##*/} in
    pastewatch-cli) digest=$FIXTURE_MAC_SHA ;;
    pastewatch-cli-linux-amd64) digest=$FIXTURE_AMD_SHA ;;
    pastewatch-cli-linux-arm64) digest=$FIXTURE_ARM_SHA ;;
    *) exit 1 ;;
esac
[[ $VERIFY_RELEASE_SCENARIO != checksum-mismatch ]] || digest=$(printf '%064d' 4)
printf '%s  %s\n' "$digest" "$3"
SHASUM
chmod +x "$scratch/bin/gh" "$scratch/bin/curl" "$scratch/bin/shasum"

# WO-693@v1: formula fixtures preserve platform URL bindings while varying exactly one check.
write_formula() {
    local scenario=$1 formula_version=0.43.0 amd_sha=$FIXTURE_AMD_SHA arm_sha=$FIXTURE_ARM_SHA
    [[ $scenario != formula-version-mismatch ]] || formula_version=0.42.0
    [[ $scenario != formula-sha-mismatch ]] || amd_sha=$(printf '%064d' 4)
    if [[ $scenario == swapped-formula-shas ]]; then
        amd_sha=$FIXTURE_ARM_SHA
        arm_sha=$FIXTURE_AMD_SHA
    fi
    cat > "$scratch/formula.rb" <<FORMULA
class Pastewatch < Formula
  version "$formula_version"
  on_macos do
    url "https://github.com/ppiankov/pastewatch/releases/download/v0.43.0/pastewatch-cli"
    sha256 "$FIXTURE_MAC_SHA"
  end
  on_linux do
    on_intel do
      url "https://github.com/ppiankov/pastewatch/releases/download/v0.43.0/pastewatch-cli-linux-amd64"
      sha256 "$amd_sha"
    end
    on_arm do
      url "https://github.com/ppiankov/pastewatch/releases/download/v0.43.0/pastewatch-cli-linux-arm64"
      sha256 "$arm_sha"
    end
  end
end
FORMULA
}

# WO-693@v1: assertions report only scenario names, never captured fixture contents.
run_case() {
    local scenario=$1 expected=$2 diagnostic=$3 version=${4:-0.43.0} status=0
    write_formula "$scenario"
    VERIFY_RELEASE_SCENARIO="$scenario" VERIFY_RELEASE_MAX_POLLS=1 PATH="$scratch/bin:$PATH" \
        bash "$repository/scripts/verify-release.sh" "$version" > "$scratch/result.log" 2>&1 || status=$?
    if [[ $status -ne $expected ]] || ! grep -Fq -- "$diagnostic" "$scratch/result.log"; then
        printf 'FAIL fixture %s\n' "$scenario" >&2
        exit 1
    fi
    if [[ $expected -eq 0 ]]; then
        [[ $(grep -c '^PASS checksum ' "$scratch/result.log") -eq 3 ]] || exit 1
        [[ $(grep -c '^PASS formula checksum ' "$scratch/result.log") -eq 3 ]] || exit 1
        grep -Fxq 'VERIFIED v0.43.0' "$scratch/result.log" || exit 1
    fi
    printf 'PASS fixture %s\n' "$scenario"
}

run_case all-green-main 0 'VERIFIED v0.43.0'
run_case missing-tag 1 'FAIL tag lookup'
run_case no-run 1 'FAIL no release run for tag commit'
run_case two-runs 0 'WARN DOUBLE-RUN 101 102'
run_case checksum-mismatch 1 'FAIL published checksum pastewatch-cli'
run_case formula-sha-mismatch 1 'FAIL formula checksum pastewatch-cli-linux-amd64'
run_case formula-version-mismatch 1 'FAIL formula version'
run_case swapped-formula-shas 1 'FAIL formula checksum pastewatch-cli-linux-amd64'
run_case failed-run 1 'FAIL release run 101 conclusion'
run_case pending-run 1 'FAIL release run polling limit'
run_case annotated-tag 0 'VERIFIED v0.43.0'
run_case v-prefixed-version 1 'FAIL version: expected X.Y.Z without v' v0.43.0
printf 'PASS all 12 release verification fixtures\n'
