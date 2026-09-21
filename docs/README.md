# The documents

Every file in `docs/`, in four classes. **Reference** is a contract, schema or vocabulary
something else is built against; a **design record** is how a decision was reached and
what it ruled; a **runbook** is for whoever is operating or connecting the thing; a
**plan** is what is not built yet, or never will be. The status column is each document's
own, quoted from its top — when it disagrees with the code, the code is right and the
document is a defect.

New here? Start with [`ARCHITECTURE.md`](ARCHITECTURE.md), which draws the whole path and
ends with a reading order through the rest.

## Reference

| Document | Status | What it holds |
| --- | --- | --- |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | map, 2026-09-18 (#562) | The whole data path in two figures, the scheduler, what a pull costs Jamf, the provider seam, the glossary. |
| [`BRANCHING.md`](BRANCHING.md) | v1, enforcement partial | How work enters `main`: release milestones and labels (§1.1), branch names, commit subjects, and the control register CI enforces. |
| [`alerts.md`](alerts.md) | v0, 2026-09-04 (#101) | Latches the product holds open while something is true, and what closes them. |
| [`app-catalog.md`](app-catalog.md) | v0, 2026-08-22 (#67) | The tenant's distinct apps, first and last seen, and what Jamf says about each. |
| [`baseline-rules.yml`](baseline-rules.yml) | catalogue v1, 2026-09-16 (#463) | The macOS baseline rule vocabulary the evidence report is printed from. Code reads this file. |
| [`change-log.md`](change-log.md) | v0, 2026-08-22 (#61) | Which differences between two observations become change rows and events, at what level. |
| [`compliance-evidence.md`](compliance-evidence.md) | built, ruled 2026-09-16 (#219 R5) | The evidence artefact an auditor is handed, and what it may claim. |
| [`controls.yml`](controls.yml) | version 1 | `BRANCHING.md` §6 made machine-readable; the policy workflow runs from it. |
| [`data-sharing.md`](data-sharing.md) | settled | The community exchange: key scheme, consent model, wire contract, share log. |
| [`diagnosability.md`](diagnosability.md) | ruled, 2026-09-10 (#291) | The design language every new failure path is written in. Read before adding one. |
| [`ingest-scheduling.md`](ingest-scheduling.md) | implemented, 2026-08-22 (#27) | Collections, the minute tick, the claim, the rate floor — what is read and when. |
| [`jamf-observations.md`](jamf-observations.md) | settled at v0 | What an observation is, how it is identified and hashed, how the ledger stores it. |
| [`jamf-patch-matching.md`](jamf-patch-matching.md) | v0, 2026-08-22 (#65); on the wire since 2026-09-04 (#311) | Which Jamf Patch title an app is, whether it is the latest, and what Jamf has seen. |
| [`posture-snapshot.md`](posture-snapshot.md) | implemented, 2026-08-29 (#102) | The nightly tape of fleet posture: 34 keys, their definitions, and the freeze on them. |
| [`runs.md`](runs.md) | implemented, 2026-08-23 (#31) | The run object: mutex, `jobID`, time window, heartbeat, reclaim, log. |
| [`splunk-event-shaping.md`](splunk-event-shaping.md) | built, since 2026-09-03 (#241) | The per-device snapshot and how Splunk expands it into per-section events. |
| [`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) | frozen, 2026-09-01 (#188) | Every key that may appear on the wire, and the additive-only rule over them. |
| [`vulnerabilities.md`](vulnerabilities.md) | ruled; wire block built | The vulnerability contract: `assessment`, the corpus cut, the epoch, what is never computed here. |

## Design record

| Document | Status | What it records |
| --- | --- | --- |
| [`device-history.md`](device-history.md) | built, 2026-09-20 (#605) | Device timeline, six personal tenant-scoped values, retained assessments and AI summaries. |
| [`inventory-summaries.md`](inventory-summaries.md) | built (#594) | Opt-in compact inventory briefings, evidence, metering and SIEM delivery. |
| [`ai-layer.md`](ai-layer.md) | built 2026-09-05 (#319), plan beyond it | The AI test box as shipped, and the road it sits on. |
| [`ai-threat-model.md`](ai-threat-model.md) | review of 2026-09-05, findings closed in #323 | The fleet as untrusted input: the attack surface, the principles, the tests that hold them. |
| [`auth-design.md`](auth-design.md) | implemented through Phase 6, re-checked 2026-09-16 | Accounts, sessions, audit log, and the seam OIDC drops into. |
| [`data-access-grain.md`](data-access-grain.md) | ruled, 2026-08-30 (#111) | Why row-level scoping is v-never and tenancy is the answer. Prose only. |

## Runbook

| Document | Status | What it is for |
| --- | --- | --- |
| [`jamf-webhooks.md`](jamf-webhooks.md) | built, 2026-09-12 (#406) | Pointing Jamf Pro's webhooks at this instance, and what each event costs. |
| [`operations.md`](operations.md) | runbook, revised 2026-09-16 | Backup, restore, upgrade, rollback — every command run before it was written down. |
| [`splunk-setup.md`](splunk-setup.md) | runbook, revised 2026-09-16 | Sending events to Splunk: HEC, tokens, sourcetypes, what a dead letter means. |
| [`troubleshooting.md`](troubleshooting.md) | ruled, 2026-09-10 (#290) | The step-throughs, written with only what a fresh operator has. |

## Plan

| Document | Status | What it says |
| --- | --- | --- |
| [`vulnerability-service-v2.md`](vulnerability-service-v2.md) | default-off preview; 30-day rollback retention (#621) | Contribute-or-pay access, retained tenant corpora, explicit submissions, ownership and release gates. |
| [`mobile-devices.md`](mobile-devices.md) | scope ruled, 2026-09-01 | v0 is computers only; what mobile would add, and where the boundary is drawn. |
| [`v-never.md`](v-never.md) | standing | Capabilities this product will not grow, with the reason attached. |

`README.md` — this index — is the only file in `docs/` not listed above.
`backend/tests/test_docs_index.py` fails if a document is added without a line here, or if
a line here points at a file that does not exist.
