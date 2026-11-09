#!/usr/bin/env bash
# Usage: scripts/prepare-release.sh [X.Y.Z]
#
# Bumps the crate and example lockfiles, and inserts the git-cliff changelog section.
# Without a version argument, git-cliff derives it from conventional commits since the last tag.
#
# Exits 0 without writing anything when:
#   - the current Cargo.toml version is already tagged (release already done)
#   - git-cliff finds no releasable commits since the last tag
#
# In CI, sets GITHUB_OUTPUT version=X.Y.Z only when it wrote changes.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The previous released version is the highest semver tag reachable from HEAD.
previous=$(git tag --merged HEAD --sort=-v:refname | grep -E -m 1 '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)

# Current version in Cargo.toml.
current_version=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')

# Derive or validate the target version.
version=${1:-$(git cliff --config cliff.toml --bumped-version)}
version=${version#v}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::version is not X.Y.Z: $version" >&2; exit 1; }

# When auto-deriving without an explicit version, if git-cliff found no reason to bump beyond current, exit 0.
if [[ -z "${1:-}" && "$version" == "$current_version" ]]; then
  echo "version $version matches Cargo.toml and no bump is needed; nothing to prepare"
  exit 0
fi

# Don't overwrite an already-released version.
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  echo "v$version is already released; nothing to prepare"
  exit 0
fi

# Generate the changelog section. Exit cleanly if there is nothing to release.
section=$(git cliff --config cliff.toml --unreleased --tag "v$version" --strip all)
if [[ -z $section ]]; then
  echo "no releasable commits since ${previous:-the beginning}"
  exit 0
fi

# Bump Cargo.toml (only the first occurrence of version = "...").
V=$version perl -pi -e \
  'if (!$done && s/^(version\s*=\s*)"[^"]*"/$1"$ENV{V}"/) { $done = 1 }' \
  Cargo.toml

# Update lockfiles.
cargo update --workspace -p leptos-nostr-auth
for lock in examples/*/Cargo.lock; do
  cargo update --manifest-path "$(dirname "$lock")/Cargo.toml" -p leptos-nostr-auth
done

# Insert the new section under ## [Unreleased] and update the compare links.
repo="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-Sturnine/leptos-nostr-auth}"
SECTION=$section V=$version P=${previous:-v$current_version} R=$repo perl -0pi -e '
  s/^## \[Unreleased\]\n/## [Unreleased]\n\n$ENV{SECTION}\n/m
    or die "CHANGELOG.md is missing the ## [Unreleased] heading\n";
  s{^\[Unreleased\]: \S+$}
   {[Unreleased]: $ENV{R}/compare/v$ENV{V}...HEAD\n[$ENV{V}]: $ENV{R}/compare/$ENV{P}...v$ENV{V}}m
    or die "CHANGELOG.md is missing the [Unreleased] compare link\n";
' CHANGELOG.md

echo "prepared v$version"
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  echo "version=$version" >> "$GITHUB_OUTPUT"
fi
