#!/usr/bin/env bash
# Usage: scripts/prepare-release.sh [X.Y.Z]
# Bumps the crate and example lockfiles, and inserts the git-cliff section for the release.
# Without a version, git-cliff derives it from the commits since the last tag.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
version=${1:-$(git cliff --config cliff.toml --bumped-version)}
version=${version#v}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not X.Y.Z: $version" >&2; exit 1; }

previous=$(git describe --tags --abbrev=0 --match 'v[0-9]*')
current=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
[[ $previous == "v$current" ]] || { echo "Cargo.toml is $current but the last tag is $previous" >&2; exit 1; }
git rev-parse -q --verify "refs/tags/v$version" >/dev/null && { echo "v$version already exists" >&2; exit 1; }

V=$version perl -pi -e 'if (!$done && s/^(version\s*=\s*)"[^"]*"/$1"$ENV{V}"/) { $done = 1 }' Cargo.toml
cargo update --workspace
for lock in examples/*/Cargo.lock; do
  cargo update --manifest-path "$(dirname "$lock")/Cargo.toml" -p leptos-nostr-auth
done

section=$(git cliff --config cliff.toml --unreleased --tag "v$version" --strip all)
[[ -n $section ]] || { echo "git-cliff found no changelog entries since $previous" >&2; exit 1; }

repo=https://github.com/Sturnine/leptos-nostr-auth
SECTION=$section V=$version P=$previous R=$repo perl -0pi -e '
  s/^## \[Unreleased\]\n/## [Unreleased]\n\n$ENV{SECTION}\n/m or die "no Unreleased heading\n";
  s{^\[Unreleased\]: \S+$}{[Unreleased]: $ENV{R}/compare/v$ENV{V}...HEAD\n[$ENV{V}]: $ENV{R}/compare/$ENV{P}...v$ENV{V}}m
    or die "no Unreleased link\n";
' CHANGELOG.md

if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  echo "version=$version" >>"$GITHUB_OUTPUT"
fi
