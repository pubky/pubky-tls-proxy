# Releasing

Releases are built and published by GitHub Actions
([`.github/workflows/release.yml`](.github/workflows/release.yml)). Pushing a signed
`v*` tag on `main` builds the binaries for 7 platforms and creates a GitHub release with
the matching [CHANGELOG.md](CHANGELOG.md) section as release notes.

## Versioning

- Versions follow [Semantic Versioning](https://semver.org/). Before 1.0, a breaking
  change bumps the minor version (`0.2.0` → `0.3.0`), anything else the patch version.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/),
  e.g. `feat: …`, `fix: …`, `docs: …`, `chore: …`.
- Every PR with a user-facing change adds a line under `## [Unreleased]` in
  `CHANGELOG.md`. Mark breaking changes with `**Breaking:**`.

## Steps

In the commands, replace `0.5.0` with the version you're releasing.

1. **Prepare the release in a PR.** On a branch `release/0.5.0`:
   - Set `version = "0.5.0"` in `Cargo.toml` and run `cargo check` to update `Cargo.lock`.
   - In `CHANGELOG.md`, move the entries under `## [Unreleased]` to a new
     `## [0.5.0] - YYYY-MM-DD` section, dated with the release day, and update the
     compare links at the bottom.
   - Update the versions used in `docs/guides/`.
   - Commit as `chore(release): 0.5.0`, open a PR and merge it.

2. **Tag the merge commit** on `main` with a signed tag and push it:
   ```bash
   git checkout main && git pull
    git tag -s v0.5.0 -m v0.5.0
    git push origin v0.5.0
   ```

3. **Wait for the workflow** and check the release:
   ```bash
   gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
    gh release view v0.5.0
   ```
   The workflow:
   - checks that the tag is on `main` and matches the version in `Cargo.toml`,
    - takes the release notes from the `## [0.5.0]` section of `CHANGELOG.md` on `main`,
    - builds `pubky-tls-proxy-<platform>-v0.5.0.tar.gz` for `linux-amd64`, `linux-arm64`,
     `linux-armv7hf`, `linux-armhf`, `windows-amd64`, `osx-amd64` and `osx-arm64`,
   - publishes the release with all archives and a `SHA256SUMS` file. Tags with a `-`,
      such as `v0.5.0-rc.0`, become pre-releases.

## When something fails

- The release is only published if **every** platform builds. If a build fails, fix it
  in a PR, then run the workflow again for the same tag. Only move the tag if the tag
  itself is wrong.
  ```bash
   gh workflow run release.yml -f tag=v0.5.0
  ```
- The same manual run releases tags that were pushed before the workflow existed.

## Building a binary locally

For a one-off binary, e.g. to deploy a test build, use
[`cross`](https://github.com/cross-rs/cross) with Docker:

```bash
cross build --release --target x86_64-unknown-linux-musl
```
