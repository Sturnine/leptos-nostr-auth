#!/usr/bin/env bash
# Usage: scripts/prepare-release.sh [X.Y.Z]
#
# Without a version, exits 0 without writing anything when nothing releasable landed since the last
# tag, or when the Cargo.toml version is not tagged yet (its release is running or failed). A
# version given fails when nothing releasable landed. Given while the Cargo.toml version is
# untagged, it supersedes that version and takes over its changelog entries, and restores from its
# tag a released section a supersede deleted. In CI, sets the `version` output only when it wrote
# changes.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

repo=https://github.com/Sturnine/leptos-nostr-auth
current=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
context=$(git cliff --config cliff.toml --unreleased --bump --context)
# git-cliff's own previous version may be a tag that HEAD does not contain.
previous=$(git tag --merged HEAD --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed -n 1p)
previous=${previous#v}

restored='' link=''
if [[ $previous != "$current" ]]; then
  if [[ -z ${1:-} ]]; then
    echo "v$current is not tagged yet; its release is running or failed; nothing to prepare"
    exit 0
  fi
  above=$(curl -sSf --retry 3 --retry-all-errors -A "leptos-nostr-auth release workflow ($repo)" \
    https://crates.io/api/v1/crates/leptos-nostr-auth/versions \
    | jq -r --arg p "$previous" 'if .meta.next_page then error("paginated") else . end | [.versions[].num | select((split(".") | map(tonumber)) > ($p | split(".") | map(tonumber)))] | join(", ")')
  [[ -z $above ]] || { echo "::error::crates.io has $above, released after v$previous; re-run its release so it is tagged" >&2; exit 1; }
  # A supersede merged after the superseded version shipped deleted that version's section.
  if ! grep -qF "## [$previous] - " CHANGELOG.md; then
    restored=$(git show "v$previous:CHANGELOG.md" \
      | awk -v h="## [$previous] - " 'index($0, h) == 1 { f = 1; print; next } /^## \[/ { f = 0 } f')
    link=$(git show "v$previous:CHANGELOG.md" | awk -v l="[$previous]: " 'index($0, l) == 1 && !n++')
    [[ -n $restored && -n $link ]] || { echo "::error::v$previous has no changelog section to restore" >&2; exit 1; }
  fi
fi

if [[ $(jq '.[0].commits | length' <<<"$context") == 0 ]]; then
  [[ -z ${1:-} ]] || { echo "::error::no releasable commits since v$previous" >&2; exit 1; }
  echo "no releasable commits since v$previous"
  exit 0
fi

bumped=$(jq -r '.[0].version | ltrimstr("v")' <<<"$context")
version=${1:-$bumped}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::version is not X.Y.Z: $version" >&2; exit 1; }
if ! printf '%s\n' "$current" "$version" | sort -uVC || ! printf '%s\n' "$bumped" "$version" | sort -VC; then
  echo "::error::version $version must be above $current and at least the derived $bumped" >&2
  exit 1
fi

section=$(git cliff --config cliff.toml --unreleased --tag "v$version" --strip all)

V=$version perl -pi -e \
  'if (!$done && s/^(version\s*=\s*)"[^"]*"/$1"$ENV{V}"/) { $done = 1 }' \
  Cargo.toml

for manifest in Cargo.toml examples/*/Cargo.toml; do
  cargo update --manifest-path "$manifest" -p leptos-nostr-auth
done

SECTION=$section RESTORED=$restored LINK=$link V=$version C=$current P=$previous R=$repo perl -0pi -e '
  if ($ENV{C} ne $ENV{P}) {
    s/^## \[\Q$ENV{C}\E\] .*?(?=^## \[)//ms;
    s/^\[\Q$ENV{C}\E\]: \S+\n//m;
  }
  my $r = length $ENV{RESTORED} ? "\n$ENV{RESTORED}\n" : "";
  s/^## \[Unreleased\]\n/## [Unreleased]\n\n$ENV{SECTION}\n$r/m
    or die "CHANGELOG.md is missing the ## [Unreleased] heading\n";
  s{^\[Unreleased\]: \S+$}
   {[Unreleased]: $ENV{R}/compare/v$ENV{V}...HEAD\n[$ENV{V}]: $ENV{R}/compare/v$ENV{P}...v$ENV{V}@{[length $ENV{LINK} ? "\n$ENV{LINK}" : ""]}}m
    or die "CHANGELOG.md is missing the [Unreleased] compare link\n";
' CHANGELOG.md

echo "prepared v$version"
echo "version=$version" >> "${GITHUB_OUTPUT:-/dev/null}"
