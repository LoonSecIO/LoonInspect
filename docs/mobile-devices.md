# Mobile devices, and the computers-only boundary

Status: **scope ruled (Kyle, 2026-09-01)** · v0 target: **computers only** · Mobile target: **v1 / v5**

A Jamf Pro tenant manages computers *and* mobile devices. v0 reads computers only, and this
document is the boundary written down: what v0 collects, what it does not, and — the reason
the file exists — every place in the codebase that assumes the boundary, so adding mobile
later is an additive change rather than a breaking one.

The scope itself is deliberate and defensible. What was not deliberate was that nothing said
so: before this file, the assumption lived only in endpoint names, and no document, no run
log line and no screen recorded it. A tenant with 3,000 Macs and 5,000 iPads connected Jamf
Pro, saw 3,000 devices and a green run, and had no way to learn that 5,000 were never asked
for. That is the failure this file closes.

## 1. What v0 reads

Five of the nine Jamf endpoints this client calls are computer-scoped
(`app.mdm.jamf.privileges` holds the list, and the privileges each needs):

| Endpoint | Object |
| --- | --- |
| `/api/v4/computers-inventory` | computers |
| `/api/v4/computers-inventory-detail/{id}` | one computer |
| `/api/v3/computer-groups/smart-groups` | smart **computer** groups |
| `/api/v2/computer-inventory-collection-settings` | the computer aperture |
| `/api/v1/departments`, `/api/v1/buildings` | shared org units |

The webhook allowlist is `ComputerAdded` and `ComputerInventoryCompleted`
(`client.REACTIVE_WEBHOOK_EVENTS`). A mobile-device webhook parses cleanly, falls out of the
allowlist and is logged as dropped — the correct behaviour today, and the log line is what
makes it visible rather than silent.

The fourteen contract sections (`app.mdm.jamf.contract.SECTIONS`) are the
`computers-inventory` section vocabulary verbatim. **Seven have no mobile counterpart**
(`disk_encryption`, `local_user_accounts`, `software_updates`, `group_memberships` among
them), and Jamf's mobile detail carries sections this contract does not model. A mobile
aperture is therefore a **second section registry**, not a subset of this one — the single
most important sizing fact for the eventual work.

## 2. The platform vocabulary (Kyle, 2026-09-01)

Mobile is not one platform. Jamf Pro's mobile device object spans iOS, iPadOS, tvOS and
visionOS, and they can be filtered apart with RSQL in the collection's selector. So the wire's
platform segment — already ruled into the sourcetype tree by #188 and today defaulting to
`mac` — takes **one value per Apple OS**, not a single `mobile`:

```
loon:jamf:mac:$section        loon:jamf:ipados:$section
loon:jamf:ios:$section        loon:jamf:tvos:$section
                              loon:jamf:visionos:$section
```

Lowercase short names, matching the already-minted `mac`. A sourcetype string is permanent
once minted (`wire_vocabulary.ADDITIVE_ONLY_CLAUSES`), so these are the shapes, and #222 is
free to stamp `mac` today without foreclosing any of them.

**Two axes, not one — the consequence that decides the implementation.** The *read* branches
by Jamf **object**: computers-inventory and mobile-devices are two endpoints, two section
registries, two apertures. The *wire* branches by **OS**: one mobile read produces events
under four different sourcetypes. So the platform segment is derived from the device's own OS
field at enqueue time; it is **not** a property of which endpoint the record came from.
Anything that treats "platform" as "which client fetched this" will be wrong for four values
out of five.

The vendor segment is **`jamf`, not `jamfpro`** — #188 dropped `pro` deliberately, and
`wire_vocabulary.py:27` reserves `loon:jamfschool:*` for Jamf School.

**watchOS is not a platform value** (Kyle, 2026-09-01). An Apple Watch cannot be enrolled;
it is queried through the iPhone it is paired to. So paired-watch data is a **field on the
parent iPhone's record**, exactly as `collectSyncedMobileDeviceInfo` puts synced-device data
on a Mac's record — not a subject, not a device row, and not a sourcetype. Anything that
models a Watch as its own device is modelling something Jamf does not have.

## 3. The register — what must land before the first mobile sweep

Two of these are **v0 blockers**: they record history at launch that cannot be backfilled, so
shipping without them destroys data rather than deferring work. The rest are **v1
prerequisites** — correct as they stand for a computers-only fleet, and cheap now or later,
but each one silently wrong the first time a mobile record reaches it.

| | What assumes computers | Where | When it must land |
| --- | --- | --- | --- |
| **P‑1** | ~~`posture_snapshot` has no population column; 11 of the 25 keys change meaning~~ | `schema.py:1293` | **LANDED 2026-09-02** — [#230](https://github.com/LoonSecIO/LoonInspect/issues/230) |
| **P‑2** | ~~The data-sharing submission carries no platform; `snapshot.apps` rows are `{title, full, count}`~~ | `sharing.py:98–116` | **LANDED 2026-09-03** — [#231](https://github.com/LoonSecIO/LoonInspect/issues/231) |
| **P‑3** | `devices` is unique on `(mdm_connection_id, external_id)` — one Jamf ID space | `schema.py:130` | 1st mobile sweep — [#233](https://github.com/LoonSecIO/LoonInspect/issues/233) |
| **P‑4** | `deviceMeta.eventID` is `uuid5(run.id, external_id)` — no platform in the name | `service.py:848` | 1st mobile sweep — [#234](https://github.com/LoonSecIO/LoonInspect/issues/234) |
| **P‑5** | `registry_rows()` iterates the computer section table whatever platform it is passed | `wire_vocabulary.py:92` | with the registry — [#235](https://github.com/LoonSecIO/LoonInspect/issues/235) |
| **P‑6** | `Facts.platform` defaults to the string `"Mac"`, so every catalog row is judged as a Mac | `requirements.py:79` | with catalog rows — [#236](https://github.com/LoonSecIO/LoonInspect/issues/236) |
| **P‑7** | The `application` entry hashes `path` and `macAppStore`; entries de-duplicate tenant-wide | `contract.py:322` | with the registry — [#237](https://github.com/LoonSecIO/LoonInspect/issues/237) |

### P‑1 and P‑2 are the v0 half

`posture_snapshot` captures as the last act of every closed full sweep, starting at launch,
and `docs/posture-snapshot.md` already names why that is the one decision that destroys data
if taken late: no-zero-priming means a key minted later has no history behind it, ever. #230
held the migration and **landed 2026-09-02**: every captured row now carries `platform`,
stamped `macos`, and `uq_posture_snapshot_capture` makes `(tenant, key, platform, capture)`
unique before a roll-up row can silently double a reader. The rules that value carries
— the per-Apple-OS vocabulary, the reserved `all`, and read-filters-on-platform — are
[`docs/posture-snapshot.md` § Population](posture-snapshot.md#population).

One spelling note this document must carry, because it looks like drift and is not: the tape
says **`macos`** where the sourcetype says **`mac`** (Kyle, 2026-09-02). They are different
namespaces with different already-minted vocabularies — `mac` is §2's sourcetype segment,
`macos` is the content-key OS domain (`os_key("macos", …)`, hashed into shared-corpus rows
and unchangeable there) — and neither was renamed to match the other. So the tape's
siblings are `ios`, `ipados`, `tvos`, `visionos`, which agree with §2 on every value
except Mac.

`sharing.py` was the same argument at a different table. Its rows were *correct* for v0 —
every device is a Mac, so `os_key("macos", …)` is a fact, not a guess. The gap was that the
submission never **said** so: app rows carried no platform and neither did the envelope. The
cloud-side corpus is partitioned by platform (Kyle, R4), so a v0 corpus of platform-less rows
would have had to be retroactively assumed Mac at exactly the moment mixed submissions start
arriving. #231 **landed 2026-09-03**, before the first exchange, which is the only time it was
cheap: every `apps` and `os` row now carries `platform`, from the single constant
`sharing.SNAPSHOT_PLATFORM` that also feeds `os_key` — the literal is gone, so a submission
cannot state two platforms. The decision it records is that the platform rides **per row**
and not on the envelope, because one container reads both axes from one connection (§2) and a
v1 envelope field could then only be deprecated, never extended. When `devices.platform`
exists (P‑3) the rows read the column and the constant is deleted. No hash moved:
`app_title_key` / `app_full_key` still hash no platform, by the same R4 reasoning.

### P‑4 is not solved by the sourcetype

The platform rides the sourcetype rather than a fourteenth `deviceMeta` key (Kyle, R3), which
is right: the block is over half the raw feed and the segment already exists. But the
sourcetype disambiguates *between* sourcetypes, and `eventID` is the fan-out selector
`app.core.runs.run_meta` teaches analysts to use — `stats … by deviceMeta.eventID` across
`loon:jamf:*:app` is the documented idiom, and a Mac and an iPad sharing a Jamf id would
derive the same UUID and merge. The fix is internal and needs no new key: fold the platform
into the UUID5 name at the same commit that adds the second ID space.

## 4. Supervision — the open revisit (Kyle, R3)

On macOS, supervision is nearly inert; an agent overrides what it would have governed. On the
mobile OSes it is load-bearing: **supervision decides which inventory data exists at all**,
and whether the organization owns the device outright. Two devices reporting different
amounts because one is supervised is not a collection failure, and nothing on the wire can
currently tell those apart.

`supervised` is already collected (`client.py:710`), stored (`schema.py:144`), hashed into the
`general` section, rated HIGH in the change policy — "supervision governs which MDM commands
are possible" — and filterable on the devices API. It is absent from exactly one place: the
`deviceMeta` block. Adding a key there is permitted by the additive-only policy and does not
need to happen before v0, but it is the likeliest fourteenth key and should be ruled with the
mobile work rather than discovered during it.

## 5. What the product says

The scope is stated in three places ([#232](https://github.com/LoonSecIO/LoonInspect/issues/232), Kyle's R5) so it is impossible to
mistake a short count for a bug: the **run summary** names what the sweep read, the **connection** carries the scope
note, and the **devices page** says what population it is counting. The README's "every Mac"
was already accurate; these make the product agree with it.

## 6. Not yet verified against a tenant

Everything in §1 is read from this codebase. The mobile-device API shapes in §2 — the section
vocabulary, and the RSQL field that separates the OSes —
are from the published Jamf reference and have **not** been read against
`loonsecio.jamfcloud.com`. The demo unit has no mobile device enrolled, so there is nothing
to read yet; enrolling one and capturing the record is [#238](https://github.com/LoonSecIO/LoonInspect/issues/238). Until that fixture
exists, every mobile shape in this file is an assumption — which is not the standard the
computer contract was built to
(`tests/fixtures/jamf/computer_inventory_detail_real.json`), and the section registry should
not be estimated against it.
