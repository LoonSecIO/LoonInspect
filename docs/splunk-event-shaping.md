# Splunk event shaping for Jamf data

Status: **partly built.** The per-device snapshot the expansion reads — one
`device.inventory` per device per pass, fattened at enqueue under the frozen vocabulary —
ships since [#241](https://github.com/LoonSecIO/LoonInspect/issues/241) (2026-09-03; shape
in [`runs.md`](runs.md) §4). The Splunk-side expansion of it into per-section sub-events
is [#242](https://github.com/LoonSecIO/LoonInspect/issues/242) and is not built.
Continuation of the destinations/outbox work (Phase complete, see below) — this document
was the handoff for the next conversation to pick up from, written because the prior
session hit a context limit mid-design.

## Goal

LoonInspect streams inventory events to configurable `Destination`s (SIEM, warehouse,
generic webhook) via an outbox/delivery-worker system that's already built and verified
(§ "What's already built," below). This document is about one specific destination
type — Splunk HEC — and how Jamf-sourced data should be *shaped* for it specifically,
so that a customer migrating off an old Jamf→Splunk integration gets equivalent (or
better) search ergonomics, not just equivalent data.

The reference point is the author's own prior product: a Splunk Add-on for Jamf Pro
with ~10k downloads, active 2+ years, since abandoned by Jamf. Its source is public:
**https://github.com/jamf/SplunkBase** (confirmed via GitHub API: not archived, but
last pushed 2022-06-14 — matches the "abandoned" framing). This doc assumes the reader
has NOT read that repo — key facts are extracted below with file references so they
don't need to be re-derived.

## What that old add-on actually did (verified against the real code, not memory)

**It is not a webhook receiver.** It's a Splunk-side *modular input* — Python running
inside Splunk, polling Jamf Pro's modern API (`computers-inventory` with `sections=`,
Basic Auth) on an interval. This is the *opposite* direction from LoonInspect's outbox,
which pushes to Splunk HEC. There is no clean "point the old integration at LoonInspect
instead" swap — a migrating customer disables the old modular input and points Splunk's
HEC token at a LoonInspect `Destination`. Matching format is what keeps their existing
SPL and dashboards alive across that swap, not what makes the swap itself automatic.

**One computer record becomes many Splunk events, not one JSON blob.**
`bin/uapiModels/devices.py`, `JamfComputer.splunk_hec_events()`: splits a single
computer into a separate event per installed app, per extension attribute, per config
profile, per local account, per group membership, per certificate, per disk partition,
per printer, per licensed software title — plus one each for general/hardware/OS/
security/purchasing/user-and-location.

**Sourcetype convention:** `jssUapiComputer:<subtype>` — e.g. `jssUapiComputer:app`,
`jssUapiComputer:computerGeneral`, `jssUapiComputer:extensionAttribute`. This is the
literal string a customer's existing saved searches/dashboards are very likely scoped
by (Splunk panels are commonly `sourcetype=X | ...`).

**Every sub-event carries a `computer_meta` correlation block** — see "The meta block"
below.

**Default Jamf sections requested** (`bin/JAMF_Pro_addon_for_splunk_rh_jamfcomputers.py`,
literal default string):

```
PURCHASING ~ APPLICATIONS ~ HARDWARE ~ OPERATING_SYSTEM ~ EXTENSION_ATTRIBUTES ~ GROUP_MEMBERSHIPS ~ SECURITY
```

Plus three sections force-added regardless of configuration
(`bin/input_module_jamfcomputers.py`, `requiredSections`):
`GENERAL`, `USER_AND_LOCATION`, `HARDWARE`.

**Why sections were force-added, per the author (this session, not in the code):** not
because those sections are intrinsically mandatory, but because the `device_meta` block
needs specific fields *sourced from* them. The floor is "whatever raw data the
correlation block depends on," not the sections themselves — a useful reframing for
LoonInspect's own version.

**Per-app fields already match LoonInspect's, for free.** The app event is Jamf's own
API object (`name`, `bundleId`, `version`) with only `sizeMegabytes`/`externalVersionId`/
`updateAvailable` deleted. Both this add-on and LoonInspect's `JamfClient` independently
read the same Jamf endpoint, so there's nothing to reconcile on field names for apps
specifically.

## The core design principle (why one-event-per-record exists — a correctness fix, not style)

If a device's full app list is emitted as one event with `applications` as a nested
array, Splunk's automatic field extraction turns `name` and `version` into independent
multivalue fields with **no enforced pairing between them**. A search like
`name=Chrome version=4.0.1` does not ask "is there an app that's Chrome *and* is
4.0.1" — it asks two independent questions ("does this event's name-values contain
Chrome" / "does this event's version-values contain 4.0.1") and both can be true even
if Chrome is actually version 127 and some *other* app happens to be 4.0.1. That's a
false positive — for a security tool, "yes this device has the vulnerable version"
being wrong is a real defect.

One event per app makes `name`/`version` genuinely scalar per event, so the plain
search is simply correct. No `mvexpand`, no `spath` gymnastics. The author's own framing:
**"no step 3, make SPL easy."** This is the actual reason the old add-on was popular,
per the author, not a stylistic preference — worth treating as a hard design constraint
for whatever ships here, not a nice-to-have.

The same "precompute what's annoying to derive inline" principle extends to *time*
handling — see `short_date` / `days_since` below, which exist to avoid making a Splunk
analyst write `strftime`/staleness math inline in every search.

## Architecture conclusion already reached (the expansion half not yet implemented)

> **Superseded in part, 2026-09-03 (#241).** The canonical payload is no longer only a
> delta. `process_sync` now enqueues one `device.inventory` **snapshot** per device per
> pass — every section inside the read's aperture under its frozen wrapper key, Jamf's
> object under Jamf's v4 names, `patch{}` and `vuln{}` on each `app` item, `deviceMeta`
> once at the top — fattened at enqueue because `_build_body` can reach neither a run nor
> a device (the same constraint that put the envelope on the payload). The delta keeps
> shipping beside it. What remains for #242 is exactly the paragraph below: the Splunk-side
> expansion of that one snapshot into N HEC sub-events, and the sourcetype stamp.

This is a **Splunk-HEC-specific delivery-time transformation**, not a change to the
canonical event LoonInspect produces internally. The canonical `EventOutbox.payload`
was a delta (`addedApps`/`removedApps`) when this was written and is now the snapshot
beside it — both correct and sufficient for generic-webhook and future warehouse
destinations, which don't have Splunk's multivalue-matching problem. What changes is the
Splunk HEC destination *expanding* that one canonical snapshot into N HEC-shaped
sub-events at send time.

This hooks into `backend/app/core/outbox.py::_build_body()` — already the one place
that's destination-type-aware (it currently only wraps the payload in `{"event": ...}`
for `splunk_hec`). The expansion logic belongs there or adjacent to it, still gated on
`destination.type == "splunk_hec"`.

Because every ingest path (manual sync, nightly sweep, and eventually an inbound
webhook) already funnels through `process_sync` → `enqueue_event()` — the one place
`EventOutbox` rows get created — the "must be true for webhooks or the sync pattern"
requirement the author stated is satisfied structurally: the Splunk-shaping logic lives
downstream of that single choke point, so there's nowhere for a second, drifted copy to
get written. This was confirmed as sound and doesn't need re-litigating.

**HEC batching:** a single HEC POST can contain multiple concatenated JSON event
objects, which Splunk splits into multiple indexed events. For a device with, say, 80
apps, this should almost certainly be one batched POST rather than 80 separate HTTP
requests — proposed default, not yet confirmed with the author. If done this way, the
existing per-`OutboxDelivery`-row retry/backoff/dead-letter machinery (already built,
already verified) doesn't need to change — the expansion happens inside body
construction for one delivery attempt, not as N separate delivery rows.

## The meta block (`device_meta` equivalent) — confirmed requirements

> **Superseded 2026-08-31 by INSPECT-0189.** The block is ruled, named `deviceMeta`, and
> capped at thirteen keys; the shipped shape and its rules live in `docs/runs.md`. What
> follows is the original requirements-gathering, kept because it records *why* each
> field was wanted. Two claims below are now known false: `short_date` is derived at
> **enqueue**, not at delivery (the delivery seam can reach neither the run nor the
> device), and `days_since` was ruled out entirely — a now-relative value frozen into an
> immutable index decays into a lie, and it is not implementable at delivery anyway.

A small object attached to every emitted Splunk sub-event, carrying device-identity/
correlation fields so split-apart events can still be searched and correlated together.

**Confirmed fields and status, from the author's explanation (this session):**

| Field | Purpose | Status |
| --- | --- | --- |
| Serial number | Device identity/correlation key | Free — `Device.serial_number` already exists |
| `shortDate` | Cheap daily-grain dedup (`\| dedup serialNumber shortDate`) without inline `strftime` | Shipped — derived at **enqueue** from the run's window, not at delivery |
| Inventory/sync UUID | Ties together every sub-event that came from one device's one sync pass, so you can "rebuild" (reconstruct) or cross-search everything from that pull | **New work.** Nothing today ties sub-events to one device-sync-pass. `EventOutbox.request_id` is scoped to the triggering job (a whole sweep/manual trigger can cover many devices) — wrong granularity. Needs a fresh id minted per device-sync, stamped on all N resulting Splunk sub-events. |
| `days_since` (with DTG-style timestamps) | Precomputed staleness/gap field so searches don't need inline time math | **Ambiguous — never resolved.** Could be purely device-check-in staleness (`Device.last_check_in`/`last_inventory_at` already support this, cheap) or a generalized "days since any timestamp this event carries" pattern that would also apply to app-lifecycle and group-join timestamps (see "Adjacent unbuilt features" below). Question was asked and the conversation hit the context limit before it was answered. |

**Final requirement from the author, stated last, not yet designed against:**

> The meta block needs to be **configurable** — customers have asked for specific group
> values or EA values to be included, not just the current fixed 8-10 fields. But it
> can't be allowed to grow large, because it gets **duplicated onto every one of the
> (potentially 200+) split sub-events per device** — an unbounded/oversized meta config
> multiplies badly across that volume.

This is the most recent unresolved design point. Whatever config surface gets built for
"which fields go in the meta block" needs a hard size constraint baked in (a field-count
cap, a byte-size cap, or both), not just a free-form list — this wasn't discussed
further before the context limit hit.

## Open questions — explicit status, nothing here should be assumed resolved

1. **Full record scope.** Not "capture everything" and not "just apps" — the author's
   own product let *the end customer* choose which Jamf sections/fields to capture,
   with the author advising against high-bloat ones. Confirmed: `Fonts` is a real Jamf
   `computers-inventory` section worth excluding by default. **Unconfirmed:** "Running
   Processes" was mentioned as another thing to avoid, but is not a standard Jamf Pro
   `computers-inventory` section as far as this session could verify — never resolved
   whether it came from a different Jamf product/API or a custom EA. Don't build a
   section-picker slot for it without checking this first.

2. **Default section set discrepancy.** The author recalled the UI defaults as "EA's,
   general, Security, Groups, Apps, and Disk volumes." The actual shipped default
   (quoted above) matches EA's/General/Security/Groups/Apps exactly, but has
   `PURCHASING` where the author remembered "Disk volumes" (`STORAGE` section) — and
   `STORAGE` is not in the shipped default at all. Possible explanations raised but not
   confirmed: memory of an earlier iteration, or "disk volumes" referring to capacity
   fields inside `HARDWARE` (which *is* default-on) rather than the dedicated `STORAGE`
   section (which the old add-on split into separate `diskPart` events). **Never
   resolved which one LoonInspect's own default should be**, or whether `PURCHASING`
   should be captured at all given it's warranty/purchase metadata rather than
   security-relevant data.

3. **Snapshot vs. retained history for the raw Jamf record.** Does storing "the full
   record" mean one current-state blob per device (overwritten each sync, bounded
   storage) or a row retained per sync (true historical replay, unbounded storage
   without its own retention policy)? Asked via a structured question; **the user
   dismissed the question without answering** — still fully open.

4. **Embed vs. namespace LoonInspect's own augmentations** (CVE/EPSS data, group-join
   timestamps) in Splunk output. **RESOLVED 2026-09-01 (#188): namespaced.** LoonInspect's
   own answers about a Jamf object ride that object's sub-event under their own wrapper
   key — `patch` and `vuln` — and its own assertions about a run carry no vendor segment
   at all (`loon:run`). The registry is
   [docs/splunk-wire-vocabulary.md](splunk-wire-vocabulary.md); this entry is kept rather
   than deleted because the question was open long enough to be answered twice.

5. **`days_since` semantics** — see the meta-block table above. Asked directly as the
   last message before the context limit; no answer received yet.

6. **Configurable-but-bounded meta block** — see "Final requirement" above. Not
   designed at all yet; this is probably the right starting point for the next session,
   since it was the most recent and most concrete open item.

## What's already built and verified (this session, Docker Compose end-to-end)

The outbox/destinations system this work sits on top of is complete and tested — do not
re-derive or rebuild this, extend it:

- **Models** (`backend/app/models/schema.py`): `Destination`, `EventOutbox`,
  `OutboxDelivery`. The tables now ship in the Postgres baseline migration,
  `7fb9f43202ba_postgres_baseline_with_tenancy.py` (the SQLite-era migration this
  originally named was collapsed into it).
- **Delivery engine** (`backend/app/core/outbox.py`): `enqueue_event()` (called once,
  inside `process_sync`, the single choke point), `fan_out_pending()`,
  `deliver_pending()` (exponential backoff, 30s base / 3600s cap / 10 max attempts
  before dead-letter), `purge_delivered_events()` (retention cleanup).
- **Splunk-specific handling that already exists:** `_build_headers()` sets
  `Authorization: Splunk <token>` for `auth_type == "splunk_hec"`; `_build_body()`
  wraps the payload as `{"event": ...}` for `type == "splunk_hec"`. This is the seam
  the per-app expansion work extends.
- **API** (`backend/app/api/destinations.py`), **UI**
  (`frontend/src/features/destinations/DestinationsPage.tsx`), permissions
  (`DESTINATION_READ`/`DESTINATION_WRITE`), audit actions, all wired and verified
  against a real local HTTP receiver: bearer auth, Splunk HEC envelope, retry backoff
  (confirmed exact: 60s after attempt 1), dead-letter at exactly attempt 10, secret
  redaction (grepped the audit log for leakage — zero hits), legacy
  `SIEM_WEBHOOK_URL` → auto-created `Destination` migration on first boot.
- Scheduler: `outbox_worker_tick` every 30s (fan-out + delivery), `outbox_cleanup`
  daily.

## RESOLVED: Splunk `_time` is occurrence time

**Superseded 2026-08-31.** This section previously recorded, as an accepted v0
constraint, that `_build_body()` sent no HEC `time` field and every event was therefore
stamped at HEC *arrival*. That is no longer true, and the SPL workaround it taught is
no longer needed.

`_build_body()` now sets `time` from the event's own `occurredAt`, computed at enqueue
(`backend/app/core/wire.py`). Occurrence semantics are unchanged and still authoritative:
sweep events back-date to the run's window, webhook events carry Jamf's `reportDate`
(`backend/app/core/runs.py::event_time`). So `_time` now means *when the device changed*,
which is what dashboards already assumed.

What this fixes concretely is the onboarding path, not an edge case. Since #157 events
produced before any destination exists are *held* rather than burned, so an operator who
runs the baseline sweep on Monday and adds Splunk on Friday used to get four days of
events all stamped Friday, arriving as one spike — for exactly the pull most worth
searching, the first full inventory of the fleet. Those events now land on their own days.

**Do not** write `| eval _time=strptime(occurred_at, ...)` any more. Two reasons: `_time`
is already correct, and the key was renamed to `occurredAt` by the #188 casing ruling, so
the old expression silently evaluates to null rather than erroring.

**Amended 2026-08-31 (second pass).** As first written this section overstated its own
scope, and the overstatement was live in main. `envelope()` was called from exactly one
producer — `process_sync`, i.e. `device.inventory.changed` — while four sites enqueued.
`device.change`, `run.completed` and `run.failed` shipped with no envelope at all, so
Splunk stamped them at *receive* time (measured skew on real indexed data: 26–250
seconds) and gave them the HEC endpoint's default `host`. All four families now build an
envelope at enqueue. Nothing above changes for the inventory family; the other three now
mean what this section always claimed they did.

Two related things ship in the same envelope, both indexed metadata and therefore free of
licence volume:

- **`host`** — the device hostname. Also carried in the body as `deviceMeta.hostName`, a
  deliberate duplicate: a Splunk admin can override `host` at the HEC input, and envelope
  fields need not survive a summary index or an export into a case file.
- **`source`** — the Jamf instance, scheme dropped and non-default port kept:
  `acme.jamfcloud.com`, `jamf.corp.local:8443`. This is why the instance URL is *not* a
  `deviceMeta` key. Every family sets it, including the run events: a run belongs to
  exactly one Jamf Pro, and `source` is what collects a single instance's whole feed.

**`host` is absent on `run.completed` and `run.failed`, by ruling.** A run is about a
connection, not a Mac. The candidates for filling the slot were the Jamf server — which
is already `source`, and which counting as a device would break every `dc(host)` — and
the container the worker runs in, which a customer's SPL cannot join to anything. `host`
means one thing on this wire, and where there is no device it is left genuinely absent so
HEC applies the input's own visible, overridable default. `device.change` follows the
same rule one level down: a computer subject carries its hostname, a `computer_group`
subject carries none, because a smart group is not a Mac either. Since #223 the same rule
governs that event's body block — a group's `deviceMeta` carries the run's half and
`jamfProID`, with no `hostName`, no `serialNumber` and no `eventID`
([`runs.md`](runs.md) §4).

Per-family `_time`, all five now set:

| event | `_time` from | `host` |
| --- | --- | --- |
| `device.inventory` | `event_time()` — run window, or the device's `reportDate`; the same instant as the delta from the same pull (#241) | hostname |
| `device.inventory.changed` | `event_time()` — run window, or the device's `reportDate` | hostname |
| `device.change` | `event_time()` — same rule, so a change and its own inventory event share one `_time` | hostname; absent for a group subject |
| `run.completed` | the instant the run closed (its `occurred_at` / row `window_end`) | absent |
| `run.failed` | the instant the run reached `failed` (its `window_end`) | absent |

The run events are deliberately **not** back-dated by `event_time()`: a sweep's closing
event stamped at the window start would sort before every event it closes over.

**Amended 2026-09-03: `sourcetype` is now set on one family.** This section said it was
not set at all, which stopped being true when
[#223](https://github.com/LoonSecIO/LoonInspect/issues/223) stamped the `:change` family
ruled in [#243](https://github.com/LoonSecIO/LoonInspect/issues/243). Every
`device.change` is delivered under its entity's string —
`loon:jamf:mac:<wrapper>:change`, fifteen of them, one per collected section plus
`computerGroup` — decided in `app/core/wire_vocabulary.py` and stamped in `_build_body`
for the `splunk_hec` destination type only. It is the first sourcetype the product ever
sent, and it changes what `_time`'s neighbours look like on a customer's search head: a
change event no longer arrives under the sourcetype set on the HEC input, so a saved
search keyed on that input name must add the `:change` strings
([`splunk-setup.md`](splunk-setup.md) §6).

**The other four families are still unstamped**, deliberately, and for the reason this
section always gave: the ruled tree (`loon:jamf:mac:app`) names the fan-out sub-events,
the fan-out below is not built, and a sourcetype is a permanent hand-written `props.conf`
stanza, so minting one for a shape that is about to change would be the expensive kind of
mistake. That includes the per-device snapshot `device.inventory` (#241), which is the
very event those strings will be minted for once #242 splits it: until then it arrives
whole, under the HEC input's own sourcetype, as one nested event per device.
`device.change` was never in that position — it is already one event per changed thing —
which is exactly why #243 let it go first.

**Still open:** `deliver_pending` has no `ORDER BY`, so a drained backlog is delivered in
arbitrary order. With `time` now set this no longer affects where events land on the time
axis, but it does affect the order in which they arrive.

## Adjacent unbuilt features referenced by this design (context, not yet built)

These came up earlier in the same conversation as things `days_since` or the meta block
might eventually need to reference. Designed, **not implemented**:

- **App lifecycle timestamps** — `first_seen_at`/`version_updated_at` on `InstalledApp`,
  requiring `process_sync`'s diff to re-key on `app_hash` for row continuity (currently
  keys on `version_hash`, which treats a version bump as delete+insert with no history).
- **Group membership sync** — per-connection *configurable schedule* (not a global cron),
  soft-deleted membership rows (`first_seen_at`/`left_at`) so both current membership and
  point-in-time/"NOT in group" queries work without Jamf's inverted-smart-group trick.
  New `device.group.joined`/`device.group.left` event types would ride the same outbox.
  Not started.
- **LoonVD / CVE enrichment** — **contract ruled 2026-09-02 (#113), still unbuilt.**
  The keys, the id namespaces, the supersede lifecycle and the tiers are
  [`docs/vulnerabilities.md`](vulnerabilities.md); the wrapper key and sourcetype are
  frozen in [`docs/splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md). The "blocked
  on the real API contract from the author" framing this entry carried is superseded:
  v0 is a **local hash-join against a static corpus**, so there is no endpoint, no auth
  and no response shape to wait for. The stub is still gone — `LoonSecIoClient` was
  excised with the rest of the provider stubs in #79 (Jamf-only at launch;
  `schemas/connections.py` refuses the `loonsecio` provider on set) — and nothing in the
  ruled v0 brings it back.

## Suggested entry point for the next conversation

Start with the most recently raised, most concrete open item: **the configurable-but-
size-bounded meta block**. That was the last thing discussed before the context limit,
it's the most actionable, and answering it (what fields, what cap, per-connection or
global config) will likely clarify `days_since` semantics and the embed-vs-namespace
question along the way, since all three touch the same output object.
