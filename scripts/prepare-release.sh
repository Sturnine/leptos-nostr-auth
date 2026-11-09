#!/usr/bin/env bash
# Usage: scripts/prepare-release.sh [X.Y.Z]
# Bumps the crate and example lockfiles, and inserts the git-cliff section for the release.
# Without a version, git-cliff derives it from the commits since the last tag. Exits 0 without
# changes when there is nothing to release; in CI, `version` is set only when it made changes.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
current=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
if ! git rev-parse -q --verify "refs/tags/v$current" >/dev/null; then
  echo "v$current is not tagged yet, so its release is still running"
  exit 0
fi
previous=$(git tag --merged HEAD --sort=-v:refname | grep -E -m 1 '^v[0-9]+\.[0-9]+\.[0-9]+$')

version=${1:-$(git cliff --config cliff.toml --bumped-version)}
version=${version#v}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not X.Y.Z: $version" >&2; exit 1; }
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  echo "v$version is already released"
  exit 0
fi

section=$(git cliff --config cliff.toml --unreleased --tag "v$version" --strip all)
if [[ -z $section ]]; then
  echo "no changelog entries since $previous"
  exit 0
fi

V=$version perl -pi -e 'if (!$done && s/^(version\s*=\s*)"[^"]*"/$1"$ENV{V}"/) { $done = 1 }' Cargo.toml
cargo update --workspace
for lock in examples/*/Cargo.lock; do
  cargo update --manifest-path "$(dirname "$lock")/Cargo.toml" -p leptos-nostr-auth
done

repo=https://github.com/Sturnine/leptos-nostr-auth
SECTION=$section V=$version P=$previous R=$repo perl -0pi -e '
  s/^## \[Unreleased\]\n/## [Unreleased]\n\n$ENV{SECTION}\n/m or die "no Unreleased heading\n";
  s{^\[Unreleased\]: \S+$}{[Unreleased]: $ENV{R}/compare/v$ENV{V}...HEAD\n[$ENV{V}]: $ENV{R}/compare/$ENV{P}...v$ENV{V}}m
    or die "no Unreleased link\n";
' CHANGELOG.md

if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  echo "version=$version" >>"$GITHUB_OUTPUT"
fi
