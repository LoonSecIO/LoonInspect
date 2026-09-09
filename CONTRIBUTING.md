# Contributing

LoonInspect is young and moving fast toward a stable v1. Contributions are welcome,
with two things worth knowing up front.

## Open an issue first

Scope is deliberately narrow (Jamf-only at launch; the README's *What it does not do*
section is a list of decisions, not gaps). An issue conversation before a pull request saves everyone from building
something the project has already ruled out — or already designed differently. Small
fixes (typos, broken links, obvious bugs) can go straight to a PR.

Security findings go through [SECURITY.md](SECURITY.md), never a public issue.

`INSPECT-NNNN` in code comments, commit subjects and issue titles is issue #NNNN in
this tracker; the convention is in [docs/BRANCHING.md](docs/BRANCHING.md) §2.

## What CI expects

Every PR must pass the same gates `main` enforces:

- **Backend** — `uv run ruff check .`, `uv run ruff format --check .` and `uv run pytest`
  (Python 3.12, `uv sync --frozen`). Database-backed tests need a real Postgres and opt in via
  `RUN_DB_TESTS=1`; the three-step local recipe (a throwaway Postgres, CI's role, the
  environment variables) is in the docstring of `backend/tests/conftest.py`, and
  `.github/workflows/ci.yml` is what it mirrors — the app must not connect as a
  superuser or the row-level-security tests prove nothing.
- **Frontend** — `npx tsc -b --noEmit`, `npx eslint .`, `npm test` (vitest, node
  environment, over the pure modules), `npm run build` (Node 22, `npm ci`).
- **Image** — the multi-stage Docker build must complete.

Lockfiles are part of the contract: `uv.lock` and `package-lock.json` must match
their manifests (`--frozen` / `npm ci` enforce this).

## Measurement

History not recorded can never be backfilled. Every feature issue that creates or
reshapes a data area, and every pull request, answers one line:

```
posture_snapshot: <keys | none>
```

— naming the nightly posture keys ([docs/posture-snapshot.md](docs/posture-snapshot.md))
the change adds, activates, or retires. `none` is a first-class answer: it means the
question was asked and the change moves no fleet-level number worth a nightly row. A
missing line means the question was never asked.

## Pull requests

A pull request body follows
[.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md): Description, Scope,
Validation, Risk, Measurement, Checklist. GitHub fills the template into the web form
only — `gh pr create --body` bypasses it, so start from the file and pass it with
`--body-file`. Two sections are required, not optional, and the `PR body` check
([.github/workflows/pr-body.yml](.github/workflows/pr-body.yml)) fails a pull request
without them: **Validation**, with the commands actually run, where, and what was *not*
run; and **Measurement**, the line above. The checklist holds only what CI cannot see.
Three of its lines are rules of this project rather than of the template:

- A change to a measured limit updates [KNOWN_ISSUES.md](KNOWN_ISSUES.md). Every number
  there was measured, and a stale one is worse than none.
- A change to any event shape updates
  [docs/splunk-wire-vocabulary.md](docs/splunk-wire-vocabulary.md), additively only —
  §5 of that document is the clause.
- The body says whether the change was AI-assisted, and its last box is ticked by the
  human who has read the full diff — before merge, not necessarily before opening, since
  most pull requests here are opened by an agent session. That is nothing to hide; an
  unread diff is.

## License

Apache-2.0. By contributing you agree your contributions are licensed under the same
terms.
