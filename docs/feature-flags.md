# Feature flags: the register

Status: **verdicts ruled 2026-09-26 (#652) and 2026-09-27 (#692), with the #692 row's kill
condition per Kyle's instruction of 2026-09-27; the v1.1.0 gate ruled 2026-11-15 (#797); the
v1.2.0 gate ruled 2026-11-19 (#813)**.
Every release runs a flag
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

The inventory at `f06c4ea`, except the `DATABASE_MODE` row, which reads as #662 left it, and
the `INTELLIGENCE_SUBMISSIONS` row, which #692 added. Kyle ruled every other row on #652 on
2026-09-26 ("accept all"), so each of those verdicts is the one the issue recommended; he
ruled the #692 row on 2026-09-27. A promote verdict has not flipped a default yet: the four
promote pull requests wait for #624's deployed checks, and each switch stays off until its
pull request lands.

| Switch | Kind | Born in | Default | Read in | Verdict for v2.0.0 | Kill release |
| --- | --- | --- | --- | --- | --- | --- |
| `INTELLIGENCE_ACCESS` | v2 preview | #622 | off | `core/intelligence.py`, `core/submissions.py` (previewing and sending only) | **promote** at the tag, once #624's deployed checks are recorded | v2.1 |
| `CONTRIBUTION_RECEIPTS` | v2 preview | #622 | off | `core/participation.py` | **promote** at the tag | v2.1 |
| `INTELLIGENCE_SUBMISSIONS` | opt-in switch | #692 | off | `core/submissions.py` (previewing and sending only), `core/intelligence.py` (reported beside `enabled`, never folded into it) | **keep off** at the tag (Kyle, 2026-09-27): an instance with paid access on sends no coverage request or correction until this is set. Then, per Kyle's instruction of 2026-09-27, **promote** once prod Support has `SubmissionsEnabled` and #624's walk of a submission through to publication has passed, both after v2.0.0 | one release after that promote |
| `VULN_TENANT_SELECTION` | v2 preview, serving path | #621 | off | 21 reads in 12 modules | **promote** at the tag; **delete** the legacy singleton-epoch path in v2.1 | v2.1 |
| `VULN_RELEASE_RETENTION` | v2 preview, storage | #621 | off | `core/intelligence.py`, `core/participation.py`, `core/vuln_library.py` | **promote** with the one above; fold the two into one in v2.1 | v2.1 |
| `COMMUNITY_SHARING` | kill switch | data-sharing.md | on | `core/sharing.py`, `core/participation.py`, `api/system.py` | keep, permanent: the air-gapped operator's hard stop | never |
| `UPDATE_CHECK` | operator switch | #43 | on | `core/update_check.py` | keep, permanent: the one outbound call an air-gapped instance can refuse | never |
| `SCHEDULER_ENABLED` | topology switch | operations.md §7 | on | `main.py` | keep, permanent: how a second container is made web-only | never |
| `DEBUG` | developer | baseline | off | `main.py`, `core/database.py` | keep, permanent | never |
| `SECURE_COOKIES` | hazard knob | README | on | `serve.py`, `core/auth.py` | keep, permanent | never |
| `SECURITY_HEADERS` | hazard knob | #186 | on | `core/middleware.py` | keep, permanent | never |
| `ALLOW_INSECURE_MDM_BASE_URL` | hazard knob | #131 | off | `core/egress.py` | keep, permanent | never |
| `ALLOW_INSECURE_DESTINATION_URL` | hazard knob | #603 | off | `core/egress.py` | keep for v2.0.0; a **delete** candidate for v2.1 once every saved destination carries its own choice (#603) | v2.1 candidate |
| `DATABASE_MODE` | mode | #29 | `bundled` | `core/config.py`, `core/database.py` | keep, permanent: `external` is a real mode since #654 (#662, on main as b54b317) | never |
| `jamf_patch` (Settings › Feature Flags) | area override | catalog | off | the registry | keep, with the reason written here: a demo or lab without a Jamf Pro connection can still show the Jamf Patch tab; a v2.1 delete question | v2.1 question |
| `vulnerabilities` (Settings › Feature Flags) | area override | #529 | off | the registry | keep, with the reason written here: a lab ahead of its first corpus can still list Posture › Vulnerabilities; a v2.1 delete question | v2.1 question |
| `ai_features` (Settings › Feature Flags) | master switch | #402 | off | the registry, `core/ai.py` | keep, permanent: the whole AI area is one switch by doctrine | never |
| `patch_policy` (Settings › Feature Flags) | area listing | #614 | off | the registry | not ruled at this gate: added 2026-10-02, after it, with the first slice of #614. It lists Posture › Patch policy, a reference replay that is not the organization's exposure; the address opens either way. Ruled **keep** at the v1.1.0 gate, below | as the v1.1.0 gate says |
| `app_promotion` (Settings › Feature Flags) | area switch | #793 | off | the registry, `core/sharing.py` (the exchange builder), `core/promotions.py` | not ruled at this gate: added 2026-11-15, after it. On, an administrator can promote installed applications under Settings › Data Sharing, and each exchange then carries those titles' names in plain text. Off, nothing can be promoted, nothing promoted leaves, and the exchange body is unchanged. Ruled **keep off** at the v1.1.0 gate, below | as the v1.1.0 gate says |
| `fleet_maintained_apps` (Settings › Feature Flags) | area switch that also decides an outbound call | #794 | off | the registry, `core/fleet_catalog.py` (the daily check asks GitHub only while some organization has it on), `api/fleet_catalog.py` (off answers no titles) | not ruled at this gate: added 2026-11-15, after it. Lists Devices › Applications › Fleet catalog and has the instance read Fleet's maintained-apps catalog from GitHub once a day. It ships off because the catalog's files are under Fleet's `ee/` licence, which says production use needs a Fleet subscription ([fleet-catalog.md](fleet-catalog.md)). Ruled **keep off** at the v1.1.0 gate, below | as the v1.1.0 gate says |

## The v1.1.0 gate

Status: **ruled** (2026-11-15). v1.1.0 is cut from `main` ahead of v2.0.0, so this is the
first gate run at a tag. The seventeen switches the v2.0.0 gate ruled keep their rulings:
nothing here re-rules them, and the four *promote at the v2.0.0 tag* verdicts stay what they
say, so those switches ship off in v1.1.0. The three registry keys added since were this
gate's to rule. Kyle ruled every row on 2026-11-15 ("accept all"), before the release pull
request (#797) merged, so each verdict is the one that pull request recommended.

| Switch | Born in | Default at v1.1.0 | Verdict for v1.1.0 | Kill release |
| --- | --- | --- | --- | --- |
| `INTELLIGENCE_ACCESS`, `CONTRIBUTION_RECEIPTS`, `VULN_TENANT_SELECTION`, `VULN_RELEASE_RETENTION` | #622, #621 | off | **keep off**: ruled *promote at the v2.0.0 tag* (#652), and v1.1.0 is not that tag | as ruled |
| `INTELLIGENCE_SUBMISSIONS` | #692 | off | **keep off**, as ruled | as ruled |
| The nine permanent switches and `ALLOW_INSECURE_DESTINATION_URL`, `jamf_patch`, `vulnerabilities` | above | as above | **keep**, as ruled | as ruled |
| `patch_policy` (Settings › Feature Flags) | #614 | off | **keep**: it lists a reference page that reads no inventory, and the Patch Policy Lab behind it is unfinished | ruled again when the lab reads real history |
| `app_promotion` (Settings › Feature Flags) | #793 | off | **keep off**: new in this release, and the service's pick-up of a promoted definition is not live | promote or delete once a promoted title has been walked to coverage |
| `fleet_maintained_apps` (Settings › Feature Flags) | #794 | off | **keep off**: new in this release, and the source's licence is the operator's to read before turning it on | ruled at the next gate |

No row was ruled promote or delete, so no default flips and no path is removed before the
tag. The release notes carry the same table
([`releases/v1.1.0.md`](releases/v1.1.0.md)).

## The v1.2.0 gate

Status: **ruled** (2026-11-19, #813). v1.2.0 is cut from `main` ahead of
v2.0.0, three days after v1.1.0. The inventory is the one the v1.1.0 gate listed: fourteen
settings in `backend/app/core/config.py` and six registry keys, with no switch added since.
Kyle ruled every row on 2026-11-19 ("accept all"), before the release pull request (#818)
merged, so each verdict is the one #813 recommended on 2026-11-18.

| Switch | Default at v1.2.0 | Verdict for v1.2.0 | Kill release |
| --- | --- | --- | --- |
| `INTELLIGENCE_ACCESS`, `CONTRIBUTION_RECEIPTS`, `VULN_TENANT_SELECTION`, `VULN_RELEASE_RETENTION` | off | **keep off**: ruled *promote at the v2.0.0 tag* (#652), and v1.2.0 is not that tag | as ruled |
| `INTELLIGENCE_SUBMISSIONS` | off | **keep off**, as ruled | as ruled |
| The nine permanent switches, `jamf_patch` and `vulnerabilities` | as above | **keep**, as ruled | as ruled |
| `ALLOW_INSECURE_DESTINATION_URL` | off | **keep**: ruled a delete candidate for v2.1 once every saved destination carries its own choice. A destination saved since #603 does (*Allow HTTP* in its editor), and one saved before it with no choice recorded still inherits this setting at delivery (`core/egress.py`), so deleting it means giving those rows a choice first. Not this release | v2.1 candidate, as ruled |
| `patch_policy` (Settings › Feature Flags) | off | **keep**: its condition has not been met. The page it lists is still a reference replay that reads no inventory, and the Patch Policy Lab (#614) is unscheduled | ruled again when the lab reads real history |
| `app_promotion` (Settings › Feature Flags) | off | **keep off**: its condition has not been met. Checked on 2026-11-18 with the published v1.1.0 image against LoonSec's development collector: a promoted title's definition is sent and is stored with that exchange's snapshot, and nothing in the service reads it from there, so no promoted title has been walked to coverage | promote or delete once a promoted title has been walked to coverage |
| `fleet_maintained_apps` (Settings › Feature Flags) | off | **keep off**: this is the gate the v1.1.0 ruling deferred it to, and what it waits on has not moved. The catalogue's files are still under Fleet's `ee/` licence, which is the operator's to read, and the area has not changed since v1.1.0 shipped it | a verdict at the v2.0.0 gate: promote, or delete |

No row was ruled promote or delete, so no default flips and no path is removed before the
tag. **The count does not fall at this release**: twenty switches at v1.1.0, twenty at v1.2.0.
The register says the number is meant to fall, and the first removals already ruled are the
v2.1 ones in the v2.0.0 gate above.

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
| 2026-09-26 | The v2.0.0 verdicts as ruled on #652 ("accept all"): every recommendation became its row's verdict, `DATABASE_MODE` became a mode kept for good now that #662 made `external` real, and the two area overrides carry their reasons as v2.1 delete questions. No default flipped: the four promote pull requests wait for #624's deployed checks. |
| 2026-09-27 | `INTELLIGENCE_SUBMISSIONS` added (#692): Request coverage and Report an incorrect match get their own switch, off by default and kept off at the tag, as Kyle ruled ("I would prefer for the primary pod to not have it enabled out of the gate"). |
| 2026-09-27 | `INTELLIGENCE_SUBMISSIONS`'s kill condition, per Kyle's instruction of 2026-09-27: its default flips on once prod Support has `SubmissionsEnabled` and #624's walk of a submission through to publication has passed, and the switch goes one release later. v2.0.0 still ships it off; that walk and LoonVD-Internal #36 come after the tag. |
| 2026-10-02 | `patch_policy` added (#614, first slice): lists the patch-policy reference page under Posture, off by default. Added after the v2.0.0 gate and not ruled; the next gate rules it. |
| 2026-11-15 | `app_promotion` added (#793): the switch for promoted applications, off by default. Added after the v2.0.0 gate and not ruled; the v1.1.0 gate rules it. |
| 2026-11-15 | `fleet_maintained_apps` added (#794): lists Devices › Applications › Fleet catalog and, unlike the other registry keys, decides an outbound call: the daily read of Fleet's maintained-apps catalog from GitHub runs only while some organization has it on. Off by default and not ruled; the v1.1.0 gate rules it. |
| 2026-11-15 | The v1.1.0 gate, as recommendations: v1.1.0 is cut ahead of v2.0.0, the seventeen ruled switches keep their rulings (the four promotes stay for the v2.0.0 tag), and `patch_policy`, `app_promotion` and `fleet_maintained_apps` are recommended keep. Not ruled until the maintainer rules it. |
| 2026-11-15 | The v1.1.0 verdicts as ruled ("accept all", #797): every recommendation became its row's verdict. `patch_policy` is kept, `app_promotion` and `fleet_maintained_apps` are kept off, and the seventeen earlier rulings stand. No default flipped. |
| 2026-11-18 | The v1.2.0 gate, as recommendations (#813): the inventory is unchanged since v1.1.0, every switch is recommended keep or keep off, and `fleet_maintained_apps`, which the v1.1.0 gate deferred to this one, is recommended keep off with a verdict due at the v2.0.0 gate. Not ruled until the maintainer rules it. |
| 2026-11-19 | The v1.2.0 verdicts as ruled ("accept all", #813): every recommendation became its row's verdict. All twenty switches are kept as they are, `fleet_maintained_apps` is kept off with a verdict due at the v2.0.0 gate, and the earlier rulings stand. No default flipped. |
