# Contributing

LoonInspect is young and moving fast toward a stable v1. Contributions are welcome,
with two things worth knowing up front.

## Open an issue first

Scope is deliberately narrow (Jamf-only at launch; see the README's roadmap for what
that means). An issue conversation before a pull request saves everyone from building
something the project has already ruled out — or already designed differently. Small
fixes (typos, broken links, obvious bugs) can go straight to a PR.

Security findings go through [SECURITY.md](SECURITY.md), never a public issue.

## What CI expects

Every PR must pass the same gates `main` enforces:

- **Backend** — `uv run ruff check .` and `uv run pytest` (Python 3.12, `uv sync
  --frozen`). Database-backed tests need a real Postgres and opt in via
  `RUN_DB_TESTS=1`; see `.github/workflows/ci.yml` for the exact role setup — the
  app must not connect as a superuser or the row-level-security tests prove nothing.
- **Frontend** — `npx tsc -b --noEmit`, `npx eslint .`, `npm run build` (Node 22,
  `npm ci`).
- **Image** — the multi-stage Docker build must complete.

Lockfiles are part of the contract: `uv.lock` and `package-lock.json` must match
their manifests (`--frozen` / `npm ci` enforce this).

## Measurement

History not recorded can never be backfilled. Every feature issue or PR that creates
or reshapes a data area answers one line:

```
posture_snapshot: <keys | none>
```

— naming the nightly posture keys ([docs/posture-snapshot.md](docs/posture-snapshot.md))
the change adds, activates, or retires. `none` is a first-class answer: it means the
question was asked and the change moves no fleet-level number worth a nightly row. A
missing line means the question was never asked.

## License

Apache-2.0. By contributing you agree your contributions are licensed under the same
terms.
