# LoonInspect

Notes for agent sessions. The rules are [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/BRANCHING.md](docs/BRANCHING.md); this file holds only what a session gets wrong
without being told.

**Pull request bodies follow
[.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md).** GitHub fills the
template into the web form only; `gh pr create --body` bypasses it. Copy the file, fill
every section, and pass it with `--body-file`. The `PR body` check fails a body without a
filled-in `## Validation` section or without the `posture_snapshot: <keys | none>` line,
and it re-runs when the body is edited. Answer the checklist's last line with
`AI-assisted: yes` and leave its box unticked; the human who reads the diff ticks it.
