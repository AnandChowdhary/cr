# Releasing cr

Every push to `main` that changes `src/`, `Cargo.toml`, or `Cargo.lock` is
released by [`.github/workflows/release.yml`](../.github/workflows/release.yml).
Documentation and CI changes are not. A release builds every target in the
[install table](../README.md#quick-start) and attaches
`cr-<tag>-<target>.tar.gz` archives, `SHA256SUMS`, and one build-provenance
attestation covering every archive. Its notes are generated from the pull
requests merged since the previous release.

## Choosing the version

The workflow releases the tip of `main`:

- If `package.version` in `Cargo.toml` has no tag yet, it is released as it
  is. To ask for a minor or major release, set the new version in the pull
  request: `0.3.0` merged to `main` becomes `v0.3.0`.
- Otherwise the patch number goes up. `github-actions[bot]` commits
  `chore(release): vX.Y.Z` to `main`, updating `Cargo.toml` and `Cargo.lock` so
  they, `cr --version`, and the tag all agree, then tags that commit. The
  commit and tag are pushed together, so neither can land without the other.
  If `main` moved in the meantime, the cut is redone on top of it.

So `main` gains a release commit after most merges. Pull before branching.

Only a plain `X.Y.Z` version is released automatically. A prerelease version
on `main`, such as `0.4.0-rc.1`, stops the workflow with an error; release one
by pushing its tag by hand instead.

## What stops a release

The workflow fails before publishing if:

- a binary reports a version other than the tag's;
- a glibc build requires glibc newer than 2.35;
- the musl build is not static;
- any target fails to build.

A tag whose build failed stays on `main` without a release. The next change
takes the next patch number. To publish the failed version anyway, rerun it
by hand as below.

A pull request that changes the workflow, `Cargo.toml`, or `Cargo.lock` runs
the same builds and checks as a dry run, without publishing anything.

## Editing notes

The generated notes are a starting point. Replace them at any time:

```sh
gh release edit v0.3.0 --notes-file notes.md
```

## Attaching binaries to an existing tag

Run the workflow by hand with the tag:

```sh
gh workflow run release.yml -f tag=v0.2.0
```

This builds the tagged source with the workflow on `main`. The attestation
therefore names `main` as the workflow's ref, not the tag. A tag pushed by hand
is built and released the same way as one the workflow cuts.

Uploads never replace an asset that is already attached, because a published
checksum has to stay true. To rebuild an archive, delete it from the release
first.
