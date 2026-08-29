# Splunk event shaping for Jamf data

Status: **design in progress, nothing built yet**. Continuation of the destinations/outbox
work (Phase complete, see below) — this document is the handoff for the next
conversation to pick up from, written because the prior session hit a context limit
mid-design.

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

## Architecture conclusion already reached (not yet implemented)

This is a **Splunk-HEC-specific delivery-time transformation**, not a change to the
canonical event LoonInspect produces internally. The canonical `EventOutbox.payload`
stays a delta (`added_apps`/`removed_apps`) — correct and sufficient for generic-webhook
and future warehouse destinations, which don't have Splunk's multivalue-matching
problem. What changes is the Splunk HEC destination *expanding* that one canonical
event into N HEC-shaped sub-events at send time.

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

A small object attached to every emitted Splunk sub-event, carrying device-identity/
correlation fields so split-apart events can still be searched and correlated together.

**Confirmed fields and status, from the author's explanation (this session):**

| Field | Purpose | Status |
| --- | --- | --- |
| Serial number | Device identity/correlation key | Free — `Device.serial_number` already exists |
| `short_date` | Cheap daily-grain dedup (`\| dedup serial short_date`) without inline `strftime` | Free — pure derived field at delivery time from `occurred_at`, no schema change |
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
   timestamps) in Splunk output — flattened alongside Jamf's native fields (consistent
   with the "no step 3" principle) or nested under a distinct namespace (clearer
   provenance, more SPL friction)? Same structured question, **also dismissed without
   an answer** — still fully open.

5. **`days_since` semantics** — see the meta-block table above. Asked directly as the
   last message before the context limit; no answer received yet.

6. **Configurable-but-bounded meta block** — see "Final requirement" above. Not
   designed at all yet; this is probably the right starting point for the next session,
   since it was the most recent and most concrete open item.

## What's already built and verified (this session, Docker Compose end-to-end)

The outbox/destinations system this work sits on top of is complete and tested — do not
re-derive or rebuild this, extend it:

- **Models** (`backend/app/models/schema.py`): `Destination`, `EventOutbox`,
  `OutboxDelivery`. Migration `d4e7f2a68b91_destinations_and_event_outbox.py`.
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

## Known constraint (v0): Splunk `_time` is ingest time, not occurrence time

`_build_body()` sends no HEC `time` field, so Splunk stamps every event at HEC
*arrival* — which trails the occurrence by the outbox cadence (30s tick) and, after a
destination hiccup, by up to the full retry envelope. Delivery order is not guaranteed
either (`deliver_pending` has no ORDER BY), so a drained backlog can land shuffled.

Ruled a **known, accepted v0 constraint** (2026-08-29), not a bug to fix in freeze
week. The authoritative occurrence timestamp is **`occurred_at` in the payload**, whose
semantics are deliberate and trustworthy: sweep events back-date to the run's `_time`
window, webhook events carry Jamf's `reportDate` (`backend/app/core/runs.py`). Searches
and dashboards that care about *when the device changed* must key on `occurred_at`
(e.g. `| eval _time=strptime(occurred_at, "%Y-%m-%dT%H:%M:%S.%6Q%z")`), not on the
time picker. Any future change that starts setting HEC `time` from `occurred_at` is
additive and safe for existing consumers — it makes `_time` mean what dashboards
already assume — but it belongs to the per-app expansion work, not v0.

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
- **LoonVD / CVE enrichment** — `LoonSecIoClient.check_apps()` is still
  `raise NotImplementedError`. Blocked on the real API contract (endpoint, auth,
  response shape, error semantics) from the author, not a technical blocker.

## Suggested entry point for the next conversation

Start with the most recently raised, most concrete open item: **the configurable-but-
size-bounded meta block**. That was the last thing discussed before the context limit,
it's the most actionable, and answering it (what fields, what cap, per-connection or
global config) will likely clarify `days_since` semantics and the embed-vs-namespace
question along the way, since all three touch the same output object.
