# Releasing

Releases are made by hand: there is no CI. A release is a signed git tag plus a GitHub
release with prebuilt binaries for 7 platforms.

## Versioning

- Versions follow [Semantic Versioning](https://semver.org/). Before 1.0, a breaking
  change bumps the minor version (`0.2.0` → `0.3.0`), anything else the patch version.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/),
  e.g. `feat: …`, `fix: …`, `docs: …`, `chore: …`.
- Every PR with a user-facing change adds a line under `## [Unreleased]` in
  [CHANGELOG.md](CHANGELOG.md). Mark breaking changes with `**Breaking:**`.

## Prerequisites

- [`gh`](https://cli.github.com/), logged in with push access to `pubky/pubky-tls-proxy`.
- [`cross`](https://github.com/cross-rs/cross) and a running Docker daemon.
- `tree`, used by `build.sh` to list the built archives.
- A GPG key configured for git, to sign the tag.

## Steps

In the commands, replace `0.3.0` with the version you're releasing.

1. **Prepare the release in a PR.** On a branch `release/0.3.0`:
   - Set `version = "0.3.0"` in `Cargo.toml` and run `cargo check` to update `Cargo.lock`.
   - In `CHANGELOG.md`, move the entries under `## [Unreleased]` to a new
     `## [0.3.0] - YYYY-MM-DD` section, dated with the release day, and update the
     compare links at the bottom.
   - Commit as `chore(release): 0.3.0`, open a PR and merge it.

2. **Tag the merge commit** on `main` with a signed tag and push it:
   ```bash
   git checkout main && git pull
   git tag -s v0.3.0 -m v0.3.0
   git push origin v0.3.0
   ```

3. **Build the binaries:**
   ```bash
   ./build.sh
   ```
   `build.sh` reads the version from `Cargo.toml`, cross-compiles every target, and writes
   `target/github-release/pubky-tls-proxy-<platform>-v0.3.0.tar.gz` for `linux-amd64`,
   `linux-arm64`, `linux-armv7hf`, `linux-armhf`, `osx-amd64`, `osx-arm64` and
   `windows-amd64`.

4. **Create the GitHub release** with the changelog section as release notes:
   ```bash
   awk -v version=0.3.0 '/^\[.+\]: / { exit } /^## \[/ { in_section = ($0 ~ "^## \\[" version "\\]"); next } in_section' \
     CHANGELOG.md > target/release-notes.md
   gh release create v0.3.0 target/github-release/*.tar.gz \
     --verify-tag --title v0.3.0 --notes-file target/release-notes.md
   ```
   Add `--prerelease` for release candidates such as `0.4.0-rc.0`.

5. **Check the release.** Open the release page, then download an archive and check that
   `pubky-tls-proxy --version` prints the new version.
