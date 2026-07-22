# Release Procedure

Pastewatch releases use one trigger per version tag. Never push a tag and manually dispatch the release workflow for the same version while another release attempt is active.

## Automated Version Bump

1. Merge a commit named `chore: bump version to X.Y.Z` to `main`.
2. Let CI create the `vX.Y.Z` tag and dispatch the release workflow.
3. Do not push the tag locally or dispatch the workflow manually.

The auto-tag job pushes with GitHub's built-in token, so the tag push cannot recursively start the release workflow. Its explicit dispatch is the only automated release trigger.

## Manual Fallback

Use exactly one path:

- Push a local `vX.Y.Z` tag and let the tag-push trigger start the release. Do not dispatch the workflow.
- If the tag already exists but no release run started, dispatch `release.yml` with that existing tag. Do not push or recreate the tag.

Release attempts for the same tag are serialized. A run publishes all assets before it computes and writes the Homebrew formula checksums.

## Verify Checksums

After the release and Homebrew update complete, verify all CLI assets against their published checksum files:

```bash
TAG=vX.Y.Z
BASE="https://github.com/ppiankov/pastewatch/releases/download/${TAG}"

for asset in pastewatch-cli pastewatch-cli-linux-amd64 pastewatch-cli-linux-arm64; do
  curl -fsSLO "${BASE}/${asset}"
  curl -fsSLO "${BASE}/${asset}.sha256"
  shasum -a 256 -c "${asset}.sha256"
done
```

Each command must report `OK` before announcing the release.
