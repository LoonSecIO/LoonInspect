# Feature flags: the register

Status: **first entry, verdicts unruled** (2026-09-26, #652). Every release runs a flag
gate: each switch below gets one of three verdicts, **promote** (the default flips on and
the flag is scheduled for removal), **keep** (with the reason and the release it is expected
to die in), or **delete** (the code path behind it goes with it), recorded here and in the
release notes ([BRANCHING §1.1](BRANCHING.md#11-release-planning-milestones-labels-and-tags),
ruled 2026-09-25). Flags exist to land unfinished work safely, not to ship two products, so
their number is meant to fall across releases. Hazard knobs and deployment switches are
listed so the inventory is complete; their verdict is always keep.

A flag is an environment setting with a boolean default in `backend/app/core/config.py`,
or a registry key under Settings › Feature Flags (`backend/app/core/feature_flags.py`).
Modes with more than two values (`TLS_MODE`, `LOG_FORMAT`) and per-tenant settings stored
in the database (the sharing tier, patching policies, a destination's transport) are
customer controls, not flags.

## The v2.0.0 gate (#652)

The inventory at `f06c4ea`. The verdict column holds the recommendation until Kyle rules on
#652; a ruled verdict replaces "unruled".

| Switch | Kind | Born in | Default | Read in | Verdict for v2.0.0 | Kill release |
| --- | --- | --- | --- | --- | --- | --- |
| `INTELLIGENCE_ACCESS` | v2 preview | #622 | off | `core/intelligence.py` | unruled (recommended: promote once #624's deployed checks are recorded; Settings › Intelligence Access is the customer control) | v2.1 |
| `CONTRIBUTION_RECEIPTS` | v2 preview | #622 | off | `core/participation.py` | unruled (recommended: promote; a receipt is asked for only by a consenting exchange) | v2.1 |
| `VULN_TENANT_SELECTION` | v2 preview, serving path | #621 | off | 21 reads in 12 modules | unruled (recommended: promote at the tag, then delete the legacy singleton-epoch path after one release of soak) | v2.1 |
| `VULN_RELEASE_RETENTION` | v2 preview, storage | #621 | off | `core/intelligence.py`, `core/participation.py`, `core/vuln_library.py` | unruled (recommended: promote with selection, then fold the two into one) | v2.1 |
| `COMMUNITY_SHARING` | kill switch | data-sharing.md | on | `core/sharing.py`, `core/participation.py`, `api/system.py` | keep, permanent: the air-gapped operator's hard stop | never |
| `UPDATE_CHECK` | operator switch | #43 | on | `core/update_check.py` | keep, permanent: the one outbound call an air-gapped instance can refuse | never |
| `SCHEDULER_ENABLED` | topology switch | operations.md §7 | on | `main.py` | keep, permanent: how a second container is made web-only | never |
| `DEBUG` | developer | baseline | off | `main.py`, `core/database.py` | keep, permanent | never |
| `SECURE_COOKIES` | hazard knob | README | on | `serve.py`, `core/auth.py` | keep, permanent | never |
| `SECURITY_HEADERS` | hazard knob | #186 | on | `core/middleware.py` | keep, permanent | never |
| `ALLOW_INSECURE_MDM_BASE_URL` | hazard knob | #131 | off | `core/egress.py` | keep, permanent | never |
| `ALLOW_INSECURE_DESTINATION_URL` | hazard knob | #603 | off | `core/egress.py` | unruled (recommended: keep for v2.0.0; a delete candidate once every saved destination carries its own choice) | v2.1, to rule |
| `DATABASE_MODE` | stub | #29 | `bundled`, `external` refused | `config.py` | decided by #654: it stops being a stub or it goes | with #654 |
| `jamf_patch` (Settings › Feature Flags) | area override | catalog | off | the registry | unruled (recommended: review; delete if demo instances are its only user) | to rule |
| `vulnerabilities` (Settings › Feature Flags) | area override | #529 | off | the registry | unruled (recommended: keep for a lab ahead of its first corpus, with that reason written down, or delete) | to rule |
| `ai_features` (Settings › Feature Flags) | master switch | #402 | off | the registry, `core/ai.py` | keep, permanent: the whole AI area is one switch by doctrine | never |

## How a gate runs

1. Before the release is tagged, list every switch (`grep -n ': bool = ' backend/app/core/config.py`
   and the registry), diff the list against this file, and add a row for each new switch
   with the issue that bore it.
2. Rule each row: promote, keep with a reason and a kill release, or delete.
3. Land the promote and delete verdicts as pull requests before the tag; each flips a default
   or removes a path and the tests that exercised the off state.
4. Copy the verdicts into the release notes, and the date into this file's status line.

## Change log

| Date | Change |
| --- | --- |
| 2026-09-26 | First entry: the sixteen switches at `f06c4ea` with recommended verdicts (#652, #658). |
