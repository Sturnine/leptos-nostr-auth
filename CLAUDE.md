# leptos-nostr-auth

## Project management

CCPM PRDs, epics and tasks in `.claude/` stay local. Never sync them to GitHub: no epic sync, no
`gh issue` create, comment or close for ccpm work, and `github:` frontmatter stays empty. Rollouts
close tasks by updating the local files. The repo is public and these files describe unfixed bugs.

## Releases

`main` is the only long-lived branch. Changes land through PRs into `main`, which the ruleset gates on the CI checks and merge commits only.

The ruleset requires a PR branch to be up to date with `main`. Actions run only if pinned to a full commit SHA and listed in the repo's allowed actions (Settings, Actions), which must include every action a new action calls. Release tags `v*` cannot be moved or deleted.

Every push to `main` runs the `Release PR` workflow (it can also be run by hand with a version). It runs `scripts/prepare-release.sh`: when there are changelog-worthy commits since the last tag, git-cliff (`cliff.toml`) derives the version from Conventional Commits, the script bumps `Cargo.toml` and every lockfile and inserts the changelog section, cargo-semver-checks checks the bump against crates.io, and the `release-pr` branch and its PR are force-updated. Never push to that branch; it is regenerated on every push to `main`.

The `Release` workflow also runs on every push to `main`, and releases when that push changes the `Cargo.toml` version to one with no `v` tag, which in practice is merging the release PR. It publishes the pushed commit through trusted publishing in the `release` environment, and creates the `vX.Y.Z` tag and GitHub release on that commit with the merged changelog section as notes. A failed or cancelled release is retried by re-running that run, never by a later push.

Agents never run the release workflows by hand, merge the release PR, push a `v*` tag, push to `main`, publish, or edit `CHANGELOG.md` entries for released versions. Commit subjects become changelog lines: write them for readers of the release notes. `chore`, `ci`, `test`, `style` and `build` subjects are left out.
