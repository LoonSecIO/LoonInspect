# Alerts: latches the product holds open while something is true

**Status: v0 (2026-09-04, #101).** Code: `backend/app/alerts/service.py` (the vocabulary,
the pure delta, the two database halves), `backend/app/models/schema.py` (`Alert`),
migration `a1c8f4b62d70`, API under `/api/alerts`, surfaced as Needs Attention rows on
`/` (`frontend/src/features/overview/needsAttention.ts`, #106). Founder ruling
2026-08-29 put alerts in v0 rather than post-launch; the shape below was ruled
2026-09-04.

---

## 1. Derived, not owned

**An alert is not a task. It is a fact about the fleet that is currently true.**

A row is opened by the sync path when its condition becomes true and closed by the same
code path when the condition stops being true. There is no dismiss button, no
`acknowledged_at`, no `acknowledged_by`, no audit action, and no human state anywhere in
the table.

The decisive reason is structural rather than philosophical: #101 rules out a dedicated
alerts page in v0, so a manual acknowledge would have **nowhere to be clicked**. An
alert nobody can close accumulates forever, and a count of latches nobody could ever
clear is not a measurement of anything. So the latch closes itself, and the consequence
is the property everything else in this document depends on:

> `alerts.open` means *true of the fleet right now*.

That is what makes the count safe to put on a nightly tape, safe to put in a sidebar
badge, and safe to compare against a peer aggregate. A "not yet dealt with" count could
mean none of those things.

What this deliberately gives up: there is no way for an operator to say "I know, that
one is fine". The seam is left rather than built (2026-08-29). If a dismissal is ever
added it is a *second* concept beside the latch — a suppression the latch is evaluated
against — never a mutable column on this row, because the day `closed_at` can be set by
a human is the day `alerts.open` stops meaning what its own history means.

## 2. The kind vocabulary is closed

One name today. Later kinds are an entry in `KINDS`, an entry in `KIND_LEVELS`, and a
row in the table below — never a reshape of the table or the module.
`backend/tests/test_alerts.py` holds this document and the tuple to each other in both
directions, so a kind added to one without the other fails the suite.

| Kind | Level | Carrier | Opens when | Closes when |
| --- | --- | --- | --- | --- |
| `new_app` | `high` | app | The app is present on the device and absent from that device's previous inventory. | The app is gone from the device. |

`level` is `app.changes.policy.LEVELS` — `high | normal | low` — reused, never a minted
`severity` (#229, and the correction in
[splunk-wire-vocabulary.md](splunk-wire-vocabulary.md) §3). The product already has one
word for how much a thing matters; a second would have to be mapped onto the first
forever.

## 3. The NEW-app latch

Ruled 2026-08-29: previous-inventory semantics, baseline primes silently, keyed on the
app field, silent new version, level high. The Cyber Essentials framing is the reason it
is `high` — unrecognised software appearing on a managed Mac is the question this
control asks, and it is a question about the fleet rather than about the pipeline.

**Identity is `app_hash` (md5(name:bundle_id)), never `version_hash`.** A version bump
is not a new app. `process_sync` already keeps a map keyed on the version hash for the
inventory delta; the latch keeps a second set keyed on the app hash, because reusing the
first would open a NEW-app alert on every update the fleet takes.

**Two ways a pass is a priming pass, and both open nothing:**

1. The `Device` row did not exist before this pass. Captured *before* the row is created
   — afterwards there is no way to ask the question.
2. The device row existed but has no application rows at all. This is not a theoretical
   case: a device first seen through a collection whose aperture excludes `applications`
   (or through a narrowly-scoped webhook) has a row and no app rows, and without this
   half its first full sweep would open one latch per installed app.

That pair is what makes *baseline primes silently* fall out of the arithmetic rather
than out of a gate somebody has to remember. The rejected alternative is worth naming:
`Run.comparison` looks like the right flag and is not — runs are purged at 30 days and
`comparison` partitions by lock class, so a webhook run's first pass on a connection
that has been sweeping for a year still reports `full`.

The cost of reading (2) conservatively is a single missed alert on a Mac that genuinely
reported zero applications and then installed one. A silence, never a flood.

**A read outside the applications aperture opens and closes nothing.** `device.apps is
None` means the section was not read, so it observed neither presence nor absence — the
same guard `record_device_apps` sits behind (Kyle, 2026-08-29).

**A re-install after a close opens a new row.** There is no cooldown and no memory of
the previous latch; the unique index is partial on `closed_at IS NULL` precisely so this
is legal. An app toggled weekly therefore mints a row a week and appears repeatedly in
`alerts.opened_24h`. That is correct — it *is* being installed again — and it will look
like noise before it looks like a signal. Recorded rather than papered over.

**A fleet-wide deployment fans out.** The latch is per (device, app), so pushing one new
tool to two thousand Macs opens two thousand rows. Needs Attention shows five and counts
the rest rather than swallowing them (`dropped`), which is honest but not yet *useful*;
grouping by app on the read side is the obvious follow-on and is deliberately not in
#101.

**`new_app` ranks last within `high` (Kyle, 2026-09-04).** The level ruling above stands
— the signal *is* `high`. What is ruled here is the tie-break, and it exists because the
level alone starves the panel. Needs Attention orders oldest-first inside a level and
shows five rows. An open latch only closes when the app is uninstalled, which for a
Jamf-deployed app never happens, so latches accumulate and age monotonically; a
destination carries a `lastFailureAt` refreshed on every retry, so a *currently dead*
Splunk pipe is always the newest thing in the band. Five latches older than the last
delivery attempt therefore push "Deliveries are failing" off the list permanently — on
the one surface where a dead pipe reliably shows up.

So within `high`, `new_app` sorts after every other kind, no matter how old the latches
are. One comparator, no schema change, no level change, nothing else's behaviour changed
(`RANK_WITHIN_LEVEL` in `frontend/src/features/overview/needsAttention.ts`). Demoting the
level was rejected: it would have made a genuinely high-severity signal quiet everywhere
rather than only inside a five-row budget.

Two things this does **not** fix, stated so nobody reads more into it. The unbounded
count is untouched — one rollout still opens hundreds of latches, and grouping them into
a single row is the named follow-on for whichever session next touches this panel. And
the tie-break is *within* a level, so a `normal` row (`run_failed`, `collection_overdue`)
still sorts below a `high` `new_app` row: level ordering is prior to rank, which is what
keeps the panel's coloured stripes in blocks. Beating a `normal` row would require the
level to move, which is exactly what the ruling declined to do.

## 4. Cost

The latch runs once per device per pull, on the path written to move 40k devices in ten
minutes. Two rules keep it free:

* **Nothing is written when no app arrived.** The open is one multi-row `INSERT … ON
  CONFLICT DO NOTHING`, issued only when the delta is non-empty.
* **Nothing is queried when no app left.** The close is one `UPDATE` against the open
  index, issued only when something departed.

So a quiet pull — the overwhelmingly common case — adds **zero** round-trips per device.
This is the same discipline `record_device_apps` was designed around: cache, don't
calculate.

## 5. Concurrency

Webhook runs deliberately never take the sweep lock ([runs.md](runs.md)), so two ingests
of one device can be in flight at once. The partial unique index
`uq_alerts_open (tenant_id, kind, device_id, app_hash) WHERE closed_at IS NULL` is the
only thing preventing two identical open latches, and the writer goes through
`ON CONFLICT DO NOTHING` rather than `db.add()` — an ORM add would bypass the inference
and raise on flush instead of losing the race quietly.

## 6. Retention

Closed rows are **not** deleted at close. `alerts.opened_24h` is frozen as "alerts
opened in the trailing 24h"; deleting on close would silently turn it into "…that are
still open", which is a different number wearing the same name. They age out on
`run_retention_days` (30) via `purge_closed_alerts`, called from the existing
`run_cleanup` loop — no new setting, because a closed alert is run history in the same
sense a finished run is.

## 7. The posture keys

Activated in the same commit as the table, per the ruling — no key records before its
feature's table exists, and none records after it either.

| Key | Definition |
| --- | --- |
| `alerts.open` | Alert rows with `closed_at` null at capture, on devices whose connection is active. |
| `alerts.opened_24h` | Alert rows whose `opened_at` falls in the trailing 24h, on devices whose connection is active — **including rows that have since closed**. |

Both count over the active-connection population every `devices.*` key counts over, and
`GET /api/alerts` draws the same cut, so the tape and the surface can never disagree
about how many things need attention. Definitions are frozen per key:
[posture-snapshot.md](posture-snapshot.md).

## 8. The wire: named, not shipped

**Nothing from #101 reaches the wire.** `ENRICHMENTS` in
`backend/app/core/wire_vocabulary.py` has declared the `alert` slot on the app
sub-event since #229 and still has no writer.

What this section does is name the shape so that the session which eventually emits it
has one to *freeze* rather than one to invent — the wire vocabulary's clause 2 freezes a
key's type the day it first ships, and a shape invented under deadline is a shape
customers' SPL is stuck with.

Ruled 2026-09-04: **the block is always present, with a discriminator.** An app with no
open latch still carries it:

```json
{ "alert": { "open": false } }
```

and an app with one carries the kinds:

```json
{ "alert": { "open": true, "kinds": ["new_app"] } }
```

Always-present matches `patch.supported` and `vuln.assessment`, which is what makes
`alert.open=false` searchable in SPL — an absent block would make "apps with no alert"
un-expressible, and `NOT alert.open=true` would silently also match apps from before the
block existed. `kinds` is a list because the vocabulary is open to growth and one app
can hold two latches; it is absent when `open` is false rather than an empty list, for
the same reason the product never writes a zero that means "did not apply".

## 9. Candidate follow-on kinds

Founder's framing (2026-08-29): "a few cheap watchers of common changes". Named here so
the next session has a list rather than a blank page; **none of these is built, and
naming one is not ruling it in.** Each would be an entry in `KINDS`, a level, and a row
in §2.

| Candidate | Carrier | The watch | Why it is cheap |
| --- | --- | --- | --- |
| `patch_laggard` | app | An install has been behind a Jamf Patch title's listed release for more than 14 days. | `installed_apps.patch_available_since` is already stamped at judge time (#68); the latch is a date comparison, not a query. |
| `unlisted_build` | app | The installed build is one Jamf has never listed for a title it matches. | `patch_state = unknown` is already on the row. |
| `admin_added` | device | A new local account with `admin: true`. | The change log already grades this `high`; the latch is a subscription to a row it writes. |
| `security_off` | device | FileVault, the firewall, or SIP moved to off and stayed off. | Same: `high` change-log fields, latched instead of streamed. |
| `unmanaged` | device | The Mac is enrolled but `managed = false`. | A column already on `devices`. |

Two shape questions the first device-carried kind has to answer, flagged now: the table
keys latches on `(kind, device_id, app_hash)`, so a device-scoped kind needs a nullable
`app_hash` and a second partial unique index — additive, but not free — and the wire
carrier moves off `app`, which is a carrier decision on the structure #243 rules for
`change`, not a naming one.
