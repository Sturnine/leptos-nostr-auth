# leptos-nostr-auth

## Project management

CCPM PRDs, epics and tasks in `.claude/` stay local. Never sync them to GitHub: no epic sync, no
`gh issue` create, comment or close for ccpm work, and `github:` frontmatter stays empty. Rollouts
close tasks by updating the local files. The repo is public and these files describe unfixed bugs.

## Releases

`main` is the only long-lived branch. Changes land through PRs into `main`, which the ruleset gates on the CI checks and merge commits only.

A release starts when the maintainer runs the `Release-plz` workflow on `main` (Actions, Release-plz, Run workflow). It opens a `release-plz-*` PR with the version bump and changelog, generated from Conventional Commits. Merging that PR publishes to crates.io through trusted publishing in the `release` environment. The 0.2.0 entry was hand-written and is edited by hand until it is released.

Agents never run that workflow, merge a `release-plz-*` PR, push to `main`, publish, or edit `CHANGELOG.md` entries for released versions. Commit subjects become changelog lines: write them for readers of the release notes. `chore`, `ci`, `test`, `style` and `build` subjects are left out.
