# Releasing cr

A release is a `v*` tag on `main`. Pushing the tag starts
[`.github/workflows/release.yml`](../.github/workflows/release.yml). It builds
every target in the [install table](../README.md#quick-start) and attaches
`cr-<tag>-<target>.tar.gz` archives, `SHA256SUMS`, and one build-provenance
attestation covering every archive.

1. Bump `version` in `Cargo.toml`, run `cargo build` so `Cargo.lock` follows,
   update the `--tag` in the README's `cargo install` line, and merge that to
   `main`.
2. Tag the merged commit and push the tag:

   ```sh
   git tag -a v0.3.0 -m "cr v0.3.0" <commit>
   git push origin v0.3.0
   ```

3. Write the notes while the builds run, which takes a few minutes:

   ```sh
   gh release create v0.3.0 --verify-tag --title "cr v0.3.0" --notes-file notes.md
   ```

   If the release does not exist by the time the builds finish, the workflow
   creates it with generated notes. Replace them with
   `gh release edit v0.3.0 --notes-file notes.md`.

The workflow refuses a tag that does not match `package.version`. It also
fails if a binary reports a different version, if a glibc build requires a
glibc newer than 2.35, or if the musl build is not static. Nothing is
published unless every target builds. A pull request that changes the workflow,
`Cargo.toml`, or `Cargo.lock` runs the same builds and checks as a dry run,
without publishing anything.

## Attaching binaries to an existing tag

Run the workflow by hand with the tag:

```sh
gh workflow run release.yml -f tag=v0.2.0
```

This builds the tagged source with the workflow on `main`. The attestation
therefore names `main` as the workflow's ref, not the tag.

Uploads never replace an asset that is already attached, because a published
checksum has to stay true. To rebuild an archive, delete it from the release
first.
