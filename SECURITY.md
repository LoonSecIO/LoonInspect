# Security policy

LoonInspect handles MDM credentials, fleet inventory, and SIEM delivery. If you find a
way to make it betray any of those, we want to know before anyone else does.

## Reporting a vulnerability

**Please do not open a public issue for a security finding.**

Report privately via GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on this repository. That channel reaches the maintainer directly and
keeps the report out of public view while a fix is prepared.

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

## Supported versions

Pre-1.0, the supported version is the latest published image and the tip of `main`.
Fixes are not backported.

## Deployment notes worth reading first

Some findings are configuration, not vulnerability. Before reporting, see the README's
sections on TLS modes (`TLS_MODE` defaults to `off` for reverse-proxy deployments —
terminate TLS in front of it or turn it on), secure cookies, and the non-superuser
database role that row-level security depends on.
