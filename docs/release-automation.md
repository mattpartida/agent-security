# Release Automation and Attestations

Phase 19 adds a review-gated tagged-release workflow. Pushing a stable `vX.Y.Z` tag
runs the full quality gate, rebuilds the skill archives deterministically, verifies
the release with a fail-closed gate script, attests build provenance for the
archives, and publishes the GitHub release. The workflow never runs on pull
requests and does not grant pull requests (or any other context) release
permissions.

## What the release workflow does

[`../.github/workflows/release.yml`](../.github/workflows/release.yml) triggers
only on tag pushes matching `v*.*.*`:

1. Checks out the tagged commit with `persist-credentials: false`.
2. Runs the same quality gate as CI: ruff, `compileall`, pytest.
3. Rebuilds the archives with `./package-skills.sh`.
4. Runs `scripts/verify_release_gate.py` (see below). Any failure blocks the release.
5. Attests build provenance for `dist/agent-security.skill` and
   `dist/healthcheck.skill` with `actions/attest-build-provenance@v4`, which
   requires and receives only `attestations: write` and `id-token: write` for this job.
6. Publishes the GitHub release with `gh release create --verify-tag` and uploads
   `dist/agent-security.skill`, `dist/healthcheck.skill`, and `dist/MANIFEST.json`.

The job-level permissions are exactly `contents: write` (to create the release),
`attestations: write`, and `id-token: write`. The workflow-level default is
`permissions: {}`, so every permission is explicit and job-scoped. Pull requests
never receive release permissions from this workflow.

## The release gate

`scripts/verify_release_gate.py <tag> [--dist-dir dist] [--commit <sha>]` fails
closed on all of the following:

- **Tag shape:** the tag must be a stable `vMAJOR.MINOR.PATCH` tag. Pre-release
  suffixes are rejected for now.
- **Tag/commit binding:** the tag must resolve to the exact commit the workflow is
  building. Both sides are peeled to commit SHAs, so an annotated tag object SHA
  binds correctly to its commit. This prevents publishing a release built from a
  different commit than the one tagged.
- **Changelog coverage:** `CHANGELOG.md` must contain a `## X.Y.Z` section for the
  tag, with released sections ordered above older releases. This stops tagging a
  release whose notes still live under `Unreleased`.
- **Artifact inventory:** `dist/` must contain exactly `agent-security.skill`,
  `healthcheck.skill`, and `MANIFEST.json` — nothing missing, nothing extra.
- **Manifest validity:** `MANIFEST.json` must parse, carry a schema version, and
  list exactly the two published skills.
- **Digest verification:** every archive's recomputed SHA-256 must match the
  manifest, so tampered or stale archives fail before publication.
- **Secret scan:** archive bytes are scanned for secret-shaped content (GitHub
  tokens, AWS access key IDs, Slack tokens, private key blocks, Google API keys).
  Matches are reported by label only and never echoed.
- **Deterministic rebuild:** the Phase 18 packager `--check` gate must confirm the
  built artifacts byte-match a clean rebuild of the tagged sources.

Exit codes: `0` when every gate passes, `1` when any gate fails, `2` on usage
errors. The gate never modifies the repository, the dist tree, or remote state.

Run it locally before tagging:

```bash
./package-skills.sh
python3 scripts/verify_release_gate.py v0.2.0
```

## Release flow for maintainers

1. Move the intended `Unreleased` changelog entries into a new `## X.Y.Z` section
   (see [versioning guidance](installation-and-release.md#versioning-guidance)).
2. Commit the changelog update and wait for CI to pass on that commit.
3. Tag the commit — annotated tags are recommended:

   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. The Release workflow runs the gate, attests the archives, and publishes the
   GitHub release with the three dist artifacts attached.
5. Verify the release page shows the expected artifacts, and check the attestation
   via the release workflow's summary or `gh attestation verify` with the
   artifact digest from `dist/MANIFEST.json`.

If any gate step fails, no release is created. Fix the underlying issue, delete the
local tag, re-tag, and push again. Deleting and re-pushing a tag is the documented
retry path; the workflow itself never force-pushes or rewrites history.

## Relationship to the release checklist

The workflow automates the mechanical steps of the
[release checklist](installation-and-release.md#release-checklist) (clean rebuild,
quality gate, archive inspection, secret scan, manifest digest verification). The
human review steps — rule doc review, fixture review, and changelog wording —
still happen before tagging.
