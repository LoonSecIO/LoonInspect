# Security policy

LoonInspect handles MDM credentials, fleet inventory, and SIEM delivery. If you find a
way to make it betray any of those, we want to know before anyone else does.

## Reporting a vulnerability

**Please do not open a public issue for a security finding.**

Report privately via GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on this repository. That channel reaches the maintainer directly and
keeps the report out of public view while a fix is prepared.

If that form is unavailable to you, email **security@loonsec.io** instead — it reaches
the same maintainer and stays out of public view.

You can expect an acknowledgement within a few days. LoonInspect is a small project —
there is no bounty program — but reports are taken seriously, fixes are prioritized
over feature work, and reporters are credited in the fix's release notes unless they
ask not to be.

## Scope

- This repository: the application image (FastAPI backend, React frontend), the
  bundled Postgres configuration, and the deployment templates under `ops/`.
- The hosted LoonSec services (`api.loonsec.io`, `*.pods.loonsec.io`): report through
  the same channel; it is the same maintainer.

Out of scope: vulnerabilities in Jamf Pro, Splunk, or other third-party systems
LoonInspect connects to — report those to their vendors.

## Hiding something is not a control

LoonInspect withholds some facts from unauthenticated callers — the running build is
the worked example (issue #130): the sign-in page used to state it, and no longer does,
because after this repo went public a commit sha resolves to a diff and that diff is a
list of the fixes an instance has not taken.

That decision removes a convenience for an attacker. **It is not a security boundary,
and nothing in this codebase may be built as though it were.** Three rules follow, and
they are the ones that matter:

1. **Obscurity never substitutes for a control.** "It isn't displayed anywhere" is not
   a reason to skip an authorization check, a scope narrowing, or a rate limit. Every
   endpoint is default-deny (`backend/app/core/auth.py`) regardless of how discoverable
   it is, and hiding a thing must never be the argument for why guarding it is optional.
2. **Assume the adversary has the source and can fingerprint the build.** This repository
   is public. Anyone can read the code, diff two commits, and match a deployment against
   them. Where hiding is genuinely defeatable we say so rather than implying otherwise —
   the README's "Which build am I running?" section admits that static-asset
   `Last-Modified` headers still disclose the build date and that the shipped SPA bundle
   is its own fingerprint.
3. **We would rather write down an accepted exposure than quietly rely on it.** #130
   exists because a deliberate acceptance recorded in one place (issue #41) was
   contradicted by two code comments claiming the opposite. If a fact is exposed on
   purpose, the acceptance belongs next to the code that exposes it, dated and
   attributed — not in a commit message nobody will find.

For reporters, that means a finding of the form "your instance reveals its version" is
already known and documented, and is not on its own a vulnerability we will act on. A
finding of the form "knowing X, I can reach Y I should not reach" is exactly what we
want, and X being easy to discover does not weaken it.

## Supported versions

Pre-1.0, the supported version is the tip of `main` — there is no public image registry
yet, so the image you run is the one you built from it.
Fixes are not backported.

## Deployment notes worth reading first

Some findings are configuration, not vulnerability. Before reporting, see the README's
sections on TLS modes (`TLS_MODE` defaults to `off` for reverse-proxy deployments —
terminate TLS in front of it or turn it on), secure cookies, and the non-superuser
database role that row-level security depends on.
