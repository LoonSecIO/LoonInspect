# The run

Status: **implemented (#31, 2026-08-23)** · Target: V0

Every pull LoonInspect performs happens inside a *run*. Before this there was no such
object: a run was a function call with a status string beside it on `mdm_sync_state`, and
four separate contract clauses each needed something that string could not carry.

| Contract clause | What it needs from the run | Where it is now |
| --- | --- | --- |
| "Postgres-backed mutex — the run row **is** the lock" | The row, and a partial unique index | `uq_run_active_lock` |
| "`device_meta` carries jobID, tenant, runtype, run_type, shortdate" | Identity and classification | `app.core.runs.run_meta` |
| "scheduled runs back-date all events to the run window" | The window | `app.core.runs.event_time` |
| "Run log queryable in Postgres, scoped by tenant and jobID" | A foreign key | `run_log` |

They are one piece of work wearing four hats, which is why they landed together.

---

## 1. The mutex

```
partial unique index on (tenant_id, mdm_connection_id, lock_class)
  where status = 'running' and lock_class <> 'webhook'
```

**Acquisition is the INSERT.** Two callers racing for the same connection both insert;
one commits, the other takes an integrity error and is handed the winner's run. This
replaces a check-then-set race: `connections.py` read `mdm_sync_state.status`, and if it
was not `syncing`, wrote `syncing` — two statements across an `await`, so two run-now
requests arriving together both read `idle`, both passed, and both started a full pull
against the same Jamf server.

**The key is the connection, not the tenant.** #31 originally sketched the index on
`(tenant_id)` alone. That is wrong in one direction: it permits one run per *tenant*, so
a customer holding two Jamf Pro instances could sweep only one at a time, for no reason —
they are separate hosts with separate capacity.

**`lock_class` separates the expensive from the cheap.** A fifteen-minute catalog refresh
has no reason to queue behind a forty-minute device sweep of the same connection, and
making it wait starves the catalog exactly when the sweep is generating references into
it (`ingest-scheduling.md` §6.2).

**Webhooks are exempt, in the predicate rather than in code.** They must ACK fast, a busy
tenant fires many, and serializing them behind a sweep makes the real-time path useless.
A webhook still gets a run — it needs the jobID and the log — but never the lock. Their
ordering against a sweep is handled by the ledger's monotonic guard instead, which is
independently correct: an observation older than what the ledger already holds is
refused, so sweep/webhook interleaving is irrelevant rather than coordinated.

## 2. The heartbeat, which is not optional

A mutex without a heartbeat is a deadlock. A process that dies holding a run leaves the
row `running` forever and **nothing on that connection can sync again** — worse than the
race it replaces, because duplicate load is noisy and self-limiting while permanent
silence pages nobody.

`heartbeat_at` is written every 15 seconds from the device loop (throttled, so it is one
small `UPDATE` per interval and not one per device). A run whose heartbeat is older than
`RUN_STALE_AFTER_SECONDS` (default 300 — twenty missed beats, not a slow one) is failed
by the next acquirer.

Reclaim happens **on acquisition, not at startup**. Startup was the wrong moment twice
over: it never fires in a process that stays up for a month, and the blanket sweep it
replaces (`main.py`, now deleted) failed runs that a *different, healthy* instance was
still performing during a rolling restart — while that instance carried on writing under
a status saying it had died.

## 3. The window, and the `_time` rule

`occurred_at` used to be `datetime.now()` at emit time on all three paths, so a scheduled
event and a webhook event were stamped identically — by when the container processed
them, not by when anything happened.

| Trigger | `_time` | Why |
| --- | --- | --- |
| `sweep` | `window_start` | Every event of one nightly sweep shares one timestamp. A forty-minute pull must not smear across forty minutes of the index, and a sweep the tick reached late must still report the configured hour. |
| `webhook` | device time (Jamf's `reportDate`) | It is a real-time signal about a device; the device's clock is the truth. |
| `manual` | now | Someone is watching it happen. There is no window to belong to, and back-dating an interactive action is a lie about when it occurred. |

`window_start` for a scheduled run is the occurrence being served — the `next_due_at`
value the tick claimed, captured *before* the claim advances it, not the moment the tick
got around to it.

This is what makes the contract's *"verify webhooks always land after the run stamp"* a
checkable statement rather than a hope: the sweep's events sit at the window, the
webhook's sit later at device time, and the ordering falls out. `test_runs.py` asserts it.

## 4. `runtype` and `run_type` became `trigger` and `comparison`

The contract specified two `device_meta` fields differing by one underscore and meaning
entirely unrelated things: `runtype` (what triggered this) and `run_type` (what kind of
comparison this is). That sits badly against the contract's own rule two lines below —
*"Field names readable English, no abbreviations"* — because an analyst reading
`runtype=manual run_type=delta` has no way to tell which is which, and will eventually
type the wrong one and get zero results with no error.

Emitted as **`trigger`** (`sweep` | `manual` | `webhook`) and **`comparison`**
(`baseline` | `delta`). Renamed while renaming was still free; customer SPL written
against these names makes them permanent.

`trigger` reuses the vocabulary the observation ledger already stamps on every span as
`last_trigger`, rather than the contract's `scheduled`: one word per concept across the
ledger, the run, and the wire. `comparison` is `baseline` until a connection and lock
class have completed one successful run, and `delta` after — and it rides `run.completed`
(§7), **not** `deviceMeta`, for the reason below.

The `deviceMeta` block on `device.inventory` and `device.inventory.changed`, ruled in #189:

```json
{"jobID": "…", "trigger": "sweep", "connectionID": 1,
 "shortDate": "2026-08-31", "eventID": "…", "serialNumber": "C02…",
 "jamfProID": "1743", "hostName": "kyle-mbp",
 "lastReportDate": "2026-08-31T21:44:03+00:00",
 "managed": true, "schemaVersion": "v0"}
```

Eleven keys, capped at **thirteen**, because a Splunk destination expands one device's
event into one sub-event per app, per extension attribute, per certificate and per profile,
and every field here is written onto all of them — measured against a real tenant record
the block is over half the raw feed. The ruling spent twelve of the thirteen slots and
held the thirteenth open deliberately; the twelfth, **`custom`**, reserves a name and
ships zero bytes in v0, with the shape frozen (`deviceMeta.custom.groups` as a filtered
array, `deviceMeta.custom.ea` as a name→value map) so that a customer who writes
`| fields deviceMeta.*` today has not written something whose expansion changes the day
an object appears among these scalars. Keys can be added later and never taken away, so
anything proposed for it goes through #189 first.

**Two keys the ruling cut, and where they went instead.** Both shipped in this block
before the ruling and were removed after it — `comparison` because it describes run
*history* rather than the row (it is `delta` on every device of every run after the first,
so it partitions nothing), and `collectionID` because it is null on the entire webhook
path, where a `BY` clause over it produces a null bucket that silently means "intraday".
`comparison` rides `run.completed` (§7); the collection belongs to the run's own event
when something emits it, joined by `jobID`, and is a run-family key when it does. The
refusal is pinned in `backend/tests/test_device_meta.py`, which holds the emitted set to
exactly the names above.

Two rules a consumer can rely on:

- **Null values are dropped, not sent.** `lastReportDate` is absent on a device Jamf has
  never completed inventory on, rather than present and null.
  `NOT deviceMeta.lastReportDate=*` finds those events.
- **`eventID` is one id per device per pull** — `uuid5(jobID, jamfProID)`, so a retry
  recomputes the same value. It is the only key that selects a single device's complete
  inventory pass: two sweeps in a day share a `shortDate`, and one sweep's `jobID` is
  shared by every device in the fleet.

**`device.change` carries the same block**, since
[#223](https://github.com/LoonSecIO/LoonInspect/issues/223) (2026-09-03) on the fold ruled
in [#243](https://github.com/LoonSecIO/LoonInspect/issues/243) — the same names, the same
values, and the same `eventID` derived from the same formula, so a change joins to the
inventory pass that produced it on `deviceMeta.eventID` alone rather than on
`jobID` + `jamfProID`, the two-term join #189 rejected because it can be half-used and
return a plausible superset with no error.

It is built from the **observation and the run**, not from the device row
(`app/changes/derive.py`): the derivation runs before `process_sync` writes that row, so
reading it would put the *previous* pull's hostname, report date and managed flag beside
this pull's change, and the two families would disagree about the device on the one pull
the block exists to correlate. Two consequences a consumer sees:

- A section outside the aperture drops its keys under the null rule above rather than
  carrying the last read's answer — `managed` and `hostName` come from GENERAL,
  `serialNumber` from HARDWARE.
- A `computer_group` subject — a smart group's definition, which is a subject and not a
  Mac — carries the run's half and `jamfProID` and nothing else. No `hostName` or
  `serialNumber`, for the same reason the envelope gives it no `host`; and **no
  `eventID`**, because that id is `uuid5(jobID, jamfProID)` over an id from a different id
  space, and deriving one would mint a correlation key that collides with a computer's by
  construction.

Casing is camelCase throughout with the token `ID` uppercased on LoonInspect's own keys
(#188). A vendor's native key keeps the vendor's spelling — Jamf writes `bundleId`, so
the wire does too.

The law covers **all five families** — `device.inventory`, `device.inventory.changed`,
`device.change`, `run.completed`, `run.failed` — and for a year it was applied to one. The consequence,
seen on real indexed data, was one index, one sourcetype, and one run UUID arriving under
three names (`deviceMeta.jobID`, `job_id`, `run_id`) with no single predicate able to
select LoonInspect events by type. Three decisions closed that:

- **The discriminator is `event`, on every family.** The run families said `event_type`;
  they now say `event` too, so `event=device.*` and `event=run.*` are one search. This is
  the change most visible to a customer: a saved search or alert written against
  `event_type=run.failed` returns zero rows — silently, because SPL has no such thing as
  an unknown-field error. `event` won over `eventType` because it was already the
  spelling on the two device families, which carry essentially all of the volume, and
  renaming those to chase the smaller pair would have been the expensive direction.
- **The run UUID is `jobID` everywhere.** `deviceMeta` said `jobID`, `device.change` said
  `job_id`, and the run events said `run_id`; all three are now `jobID`, carrying the
  same value. `runID` was rejected for the same reason: one value, one name.
- **`jamfProID` is the object's id in Jamf Pro on both device families**, computer or
  group — `subjectKind` says which kind of object it belongs to, and since #223 the
  sourcetype does too: a group's change arrives as `loon:jamf:mac:computerGroup:change`,
  so the two id spaces are separated by the field Splunk routes on. Joining across
  sourcetypes on the id alone still mixes them, and this sentence is the warning.

`jobID` is **top-level on all five families**, and on the three device families —
`device.inventory`, `device.inventory.changed`, `device.change` — it is carried a second
time inside `deviceMeta`, where Splunk's JSON extraction names it `deviceMeta.jobID`. The
cross-family join is therefore a bare `jobID=$id$` — not
`jobID=$id$ OR deviceMeta.jobID=$id$`, and not a `coalesce` — which is what lets the
payload tables below call the run id joinable with no qualification attached.

The duplicate is deliberate, ruled on
[#220](https://github.com/LoonSecIO/LoonInspect/issues/220), 2026-09-02, against three
alternatives. The root copy is what lets one predicate select every family. The nested
copy stays because a customer's SPL may already name it and an unknown field returns zero
rows with no error, and because `deviceMeta` is meant to be the self-contained identity of
the pull — a sub-event read alone should still know which run produced it. It costs ~47
bytes on the event whose cost multiplies by every app, EA, certificate and profile once
the fan-out lands, which is what made this a #189 decision rather than a casing one; a
join every consumer writes twice, or writes once and silently under-reports on the
highest-volume family, was ruled the more expensive of the two. `host` already rides in
both the envelope and the body on the same reasoning.

Two spellings were genuinely ambiguous and are ruled here so nobody has to guess twice:

- **`jamfUrl`, not `jamfURL`.** The law uppercases exactly one token, `ID`. Extending it
  to `URL` in passing would be a second ruling; Jamf's own API spells url keys `...Url`.
- **`udid` stays `udid`.** It is one acronym rather than a name ending in an `Id` token,
  camelCase puts the leading word in lower case, and Jamf spells it `udid` as well.

Alongside the body, a Splunk HEC delivery sets three envelope fields: `time` from the
event's own `occurredAt`, `host` from the hostname, and `source` from the Jamf instance
(scheme dropped, non-default port kept — `jamf.corp.local:8443`). They are indexed
metadata, so they cost no licence volume.

**`sourcetype` is set on three families, on Splunk HEC deliveries only**, decided by
`app/core/wire_vocabulary.py` and stamped in `app/core/outbox.py`; every other destination
type gets the canonical event with no sourcetype at all. The strings are ruled in
[`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) §2 and the stanzas they imply are
in [`splunk-setup.md`](splunk-setup.md) §6.

- `device.change` — its entity's string, `loon:jamf:mac:<wrapper>:change`, fifteen in all
  ([#243](https://github.com/LoonSecIO/LoonInspect/issues/243), stamped by
  [#223](https://github.com/LoonSecIO/LoonInspect/issues/223)). It went first because it was
  already at sub-event grain, one event per kept change row.
- `device.inventory` — not one string but a fan-out: on Splunk the snapshot is expanded at
  delivery into one HEC event per section item, each under the registry's string for its
  wrapper, `loon:jamf:mac:app` and its thirteen siblings
  ([#242](https://github.com/LoonSecIO/LoonInspect/issues/242), 2026-09-03, absorbing
  [#222](https://github.com/LoonSecIO/LoonInspect/issues/222)). The shape is below.
- `run.completed` and `run.failed` — `loon:run`, LoonInspect's own assertion about a run,
  no vendor segment (#242 item 6, in the same change as the section tree).

Still under the HEC input's own sourcetype, deliberately: `device.inventory.changed` — the
delta family has no ruled string; [#277](https://github.com/LoonSecIO/LoonInspect/issues/277) puts the ruling to Kyle before the flip — and
the test event, which is meant to be identifiable rather than routed.

### The snapshot family: `device.inventory` (#241)

One `device.inventory` per device per pass that clears the ledger's monotonic guard —
sweep and webhook alike, whether or not anything changed — enqueued by `process_sync` in
the same transaction as the ledger write and the row updates, and **fattened at enqueue**
(Kyle, 2026-09-02: "flatten at enqueue", read as *fatten*, the option he confirmed on
2026-09-01). It never fires on the stale path and never for a device whose ingest was
rolled back. It is the state; `device.inventory.changed` is what happened to the app list
and keeps shipping unchanged beside it — #81 ruling 6's IS/HAPPENED test applied to the
discriminator — so `event=device.inventory*` collects both and a delta-only subscription
still means what it did. It is the event the fan-out (#242) expands, and it carries the
three keys every sub-event must survive with ([`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md)
§6) at its root.

```json
{"event": "device.inventory", "jobID": "0199a5c4-…", "occurredAt": "2026-09-02T02:00:00Z",
 "deviceMeta": {"jobID": "0199a5c4-…", "trigger": "sweep", "eventID": "…", "…": "the ruled block, once"},
 "general": {"name": "Loon’s Mac mini", "remoteManagement": {"managed": true}, "…": "…"},
 "hardware": {"serialNumber": "LOONMINI0M4", "model": "Mac mini", "…": "…"},
 "operatingSystem": {"…": "…"}, "userAndLocation": {}, "purchasing": {"…": "…"},
 "security": {"…": "…"}, "diskEncryption": {"…": "…"},
 "app": [
   {"app": {"name": "Maps.app", "path": "/System/Applications/Maps.app", "version": "3.0",
            "cfBundleShortVersionString": "3.0", "cfBundleVersion": "2972.20.6.12.13",
            "bundleId": "com.apple.Maps", "macAppStore": false},
    "patch": {"supported": false},
    "vuln": {"assessment": "off"}}
 ],
 "ea": [{"ea": {"definitionId": "3", "name": "…", "values": [], "enabled": true, "…": "…", "source": "extensionAttributes"}}],
 "group": [{"group": {"groupId": "1", "smartGroup": true, "groupName": "All Managed Clients"}}],
 "profile": [{"profile": {"…": "…"}}], "localUserAccount": [{"localUserAccount": {"…": "…"}}],
 "cert": [{"cert": {"…": "…"}}], "update": [{"update": {"…": "…"}}]}
```

Four properties, each traceable to a ruling:

- **The section keys are the registry's and nothing else.** Fourteen at most, exactly
  `SECTION_WRAPPERS.values()` ([`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md)
  §2): the seven one-per-device sections are Jamf's object, the seven list sections are
  lists — `localUserAccount` included, whatever the naming comment says, because the
  contract's `entry_kind` makes it a list. Under the frozen registry the "device anchor"
  #81 spoke of is one sub-event per scalar section, which is why all seven ride.
- **A list item is the sub-event body minus the three sub-event keys.** `{"cert": {…}}`,
  and for an app `{"app": {…}, "patch": {…}, "vuln": {…}}` — byte for byte what the
  fan-out emits under the section's sourcetype once it adds `event`, `jobID` and
  `deviceMeta` and the envelope. So the fan-out is iteration, not reshaping, and every
  shape decision lives on this side of the outbox, where the data is. It also keeps
  LoonInspect's enrichment keys *beside* Jamf's object rather than inside it — namespaced,
  not flattened — so Jamf can never add a field that collides with `patch`. The price is
  `app[].app.bundleId` on a generic-webhook or Elastic document.
- **Jamf's v4 names, verbatim; the ledger's allowlist for the field set.** Kyle,
  2026-09-02: "Use Jamf's v4 Names Verbatim in the sections I am copying them." Every
  section object is Jamf's `computers-inventory` object under Jamf's keys, restricted to
  the contract's allowlist for that section (`app/mdm/jamf/contract.py`), with values in
  the ledger's canonical form — the snapshot agrees with the ledger byte for byte, which
  is what makes a `device.inventory` sub-event and a `device.change` from the same span
  join on equal strings. The field set is the labelled assumption on #81's 2026-09-02
  ruling comment, applied to every section: the telemetry the allowlist excludes
  (`lastContactTime`, `lastIpAddress`, `reportDate`, battery) is off the wire in v0 and
  additive later under clause 1; `lastReportDate` already rides `deviceMeta`. The four
  minted identity fields — `appHash`, `versionHash`, `keyTitle`, `keyFull` — ride no app
  object here (Kyle, 2026-09-02: "leave them out for now we can add them in the future.
  We can add keys later but we can't take them away"); they keep riding the delta's
  `addedApps[]` / `removedApps[]`, which is not the fan-out.
- **Labelled entries carry their label under Jamf's key**, and the extension-attribute
  item is #197's ruled wire object. The contract keeps names out of the hash and carries
  them as the entry's label; the wire wants `group.groupName` and `profile.displayName`,
  because that is what an analyst types. The `ea` item is Jamf's object verbatim plus
  `source` — the one key LoonInspect mints inside a Jamf object anywhere on the wire
  ([`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) §4).

`patch` and `vuln` ride every app item because fatten-at-enqueue leaves the fan-out
nothing to join against: `patch.supported` is a bool, always present, `true` iff the
installed-app row's Jamf Patch answer names a title (Kyle, 2026-09-01: "we need a default
for the patching... a boolean ... set that equal to false. That way you can always search
for it or not it easy"), read off the row already in the transaction — cache, don't
calculate; `vuln` is `{"assessment": "off"}` until the corpus lands
([`vulnerabilities.md`](vulnerabilities.md) §4a). `alert` is name-only in v0 (#229) and
rides nothing.

**`supported: false` has two causes and, in v0, no discriminator.** It means either that
no Jamf Patch title matches the app, or that the Jamf Patch catalog has not been synced
yet: the catalog refreshes on the hour (`hourly_jamf_patch_sync`, `CronTrigger(minute=0)`
in `app/main.py`) with no run at startup, so a first sweep that beats the hour ships
`supported: false` for every app in the fleet — Wireshark included — and the next sweep
flips the matched ones. The key's meaning is the ruled one and does not change; a
discriminator that says *not yet judged* is additive under clause 1 and is left to
[#249](https://github.com/LoonSecIO/LoonInspect/issues/249).

**Three meanings of absence**, and a consumer can rely on all three:

- **A section wrapper absent** — the section was outside this read's aperture. The
  2026-08-29 ruling applied per section: a webhook collection scoped to
  `["general", "hardware", "operating_system"]` produces three wrappers and no `app` key;
  the snapshot never asserts an absence the read did not observe. This is a per-event
  exception to additive-only clause 4 ("absence means the event predates the key"),
  recorded beside the clause rather than amended into it: the wrapper rule is the
  aperture's, not the vocabulary's, and a section-less snapshot cannot exist because the
  webhook path falls back to the whole contract.
- **`{}` or `[]`** — read, and genuinely empty. The real fixture's `userAndLocation` is
  `{}`; a full read of a device with no apps is `"app": []`.
- **A key absent inside a Jamf object** — Jamf sent no value: an older server that does
  not report the field, or a null the canonicalizer dropped. The additive-only clauses
  govern LoonInspect's own keys; they never describe Jamf's object.

**The v4 pin.** Every section object is pinned to the v4 `computers-inventory` shape. A
field Jamf adds reaches the wire when the allowlist admits it — additive under clause 1,
never automatic; a rename or removal forced by adopting a later major endpoint version is
a breaking wire change and ships as a `schemaVersion` bump in `deviceMeta` (clause 6),
never a silent reshape.

**Size and the subscription default.** Measured against the captured Jamf Pro 11.31
record (`backend/tests/fixtures/jamf/computer_inventory_detail_real.json`, 83 apps) as
compact JSON: **28,783 bytes** for one device — ~22.3 KB of it the `app` list at ~268
bytes an item — every pass, not once. On a Splunk destination the same device is
**84,135 bytes** as 107 sub-events (2.92×; see the fan-out below). `device.inventory`
joined `KNOWN_EVENT_TYPES` under the default the type was born with: null or empty
`subscribed_events` keeps meaning every event, so a destination on the default receives
one snapshot per device per pass from the day it ships, and explicit lists were **not**
appended to (unlike `run.failed`, migration `a9d4c7e1f3b8`): a destination that curated its
list never asked for a state stream. Opting out, or in, is `subscribed_events` on the API
— what each destination type receives is in [`splunk-setup.md`](splunk-setup.md) §7. The
snapshot's shape is pinned against the fixture in
`backend/tests/test_inventory_snapshot.py`, size ceiling included.

#### The fan-out: what a Splunk destination receives (#242)

On a `splunk_hec` destination — and only there — the snapshot is expanded **at delivery**
into one HEC event per section item, under the registry's string for its wrapper
(`app/core/hec_fanout.py`, called from `app/core/outbox.py`). It is #81's HEC expansion:
*"snapshot event → N per-app events + device anchor … Splunk-destination-scoped; other
destination types keep the canonical event."* The outbox still stores one row per device
per pass, never N; the split happens in the one place a HEC body is assembled, so an event
enqueued before the fan-out existed arrives split rather than whole.

- **The seven one-per-device sections are one sub-event each** — `general`, `hardware`,
  `operatingSystem`, `userAndLocation`, `purchasing`, `security`, `diskEncryption` — the
  *device anchor*. **The seven list sections fan one sub-event per item**, in the
  payload's order. Cardinality is the contract's `SectionSpec.is_list`, so
  `localUserAccount` fans per item whatever the registry's naming comment says.
- **The sub-event body is the item plus the three sub-event keys** of
  [`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) §6 — `event` (the snapshot's
  own type, `device.inventory`, verbatim: D1, ruled on #220), `jobID` at the root, and
  `deviceMeta` copied whole — laid out as the snapshot is, head first, block last. Nothing
  is minted, renamed or dropped; the wrapper object is Jamf's, byte for byte. `occurredAt`
  does not ride: the three are the complete list, and the same instant is the envelope's
  `time` on every sub-event. `patch{}` and `vuln{}` ride the app sub-event inline and
  nowhere else, and the three enrichment strings stay unstamped (#242 item 6).
- **The envelope rides every sub-event** — the snapshot's `time`, `host` and `source`,
  the same values on all of them.

One app sub-event of the real fixture as the fan-out posts it, the two UUIDs elided:

```json
{"event": {"event": "device.inventory", "jobID": "0199a5c4-…",
           "app": {"bundleId": "com.apple.Maps", "cfBundleShortVersionString": "3.0",
                   "cfBundleVersion": "2972.20.6.12.13", "macAppStore": false, "name": "Maps.app",
                   "path": "/System/Applications/Maps.app", "version": "3.0"},
           "patch": {"supported": false}, "vuln": {"assessment": "off"},
           "deviceMeta": {"jobID": "0199a5c4-…", "trigger": "sweep", "connectionID": 1,
                          "shortDate": "2026-09-02", "eventID": "a0022c4f-…", "serialNumber": "LOONMINI0M4",
                          "jamfProID": "3", "hostName": "Loon’s Mac mini",
                          "lastReportDate": "2026-08-22T01:44:27+00:00", "managed": true, "schemaVersion": "v0"}},
 "sourcetype": "loon:jamf:mac:app", "time": 1788314400.0, "host": "Loon’s Mac mini", "source": "e2e.jamfcloud.com"}
```

and the `general` anchor is `{"event": "device.inventory", "jobID": "…", "general": {…Jamf's
object…}, "deviceMeta": {…}}` under `loon:jamf:mac:general`.

**One delivery, one request, N events.** All of a device's sub-events go in one POST as
newline-concatenated JSON objects, which `/services/collector/event` indexes one by one —
per-event expansion, not cross-event batching: two devices' snapshots are two requests.
The `OutboxDelivery` row, its backoff and its dead-letter are unchanged. Measured on the
real fixture: **107 sub-events, 84,135 bytes** — `deviceMeta` is 314 bytes × 107 = 33.6 KB of
it, the envelope and sourcetype ~109 bytes per sub-event, `event` + `jobID` 73 — verified
against a local Splunk 10.4 (the #242 PR). A device whose expansion exceeds
`SPLUNK_HEC_MAX_REQUEST_BYTES` (default **900,000**: 10% under the 1 MB `max_content_length`
Splunk Cloud Platform documents for HEC) is sent as consecutive requests of at most that
size, whole events only, in order. Order is fixed — registry order, anchors first, items in
payload order — so a retry re-expands the same row to the same bytes.

**Failure is per request, retry is per delivery.** Any non-2xx or transport error fails
the delivery, which stays pending, backs off and retries the whole delivery — every
request, rebuilt from the same row — until it lands or dead-letters after ten attempts.
HEC parses a request in order and, on a malformed event, indexes the events before it and
reports the position (`invalid-event-number`, HTTP 400); nothing built here can produce a
malformed event, so that 400 is a producer bug on the ordinary path. A retry therefore
re-sends sub-events Splunk may already hold — the at-least-once story the outbox always
had, one level down. The dedup key on a fan-out sourcetype is the pull plus the item:
`dedup keepempty=true deviceMeta.eventID app.path app.version` on `loon:jamf:mac:app`,
each sibling section's own identity on its sourcetype — never `deviceMeta.eventID` alone,
which collapses a device's pass to one arbitrary row. Keyed on `path`, not `bundleId`,
and with `keepempty=true`: the canonicalizer omits an empty `bundleId`, and Splunk's
`dedup` drops every event missing one of its fields unless told to keep them, so a key
on `bundleId` would silently lose every app Jamf reports without one.

**What the wire cannot say.** A section outside the read's aperture is absent from the
snapshot and fans out nothing. A *list* section read and genuinely empty fans out nothing
too, so on the wire the two look the same: `loon:jamf:mac:general` with no
`loon:jamf:mac:cert` for the same `deviceMeta.eventID` means *either* zero certificates
*or* certificates not read. The payload keeps the distinction (absent versus `[]`); the
fan-out loses it, and a key saying "unread" on the most-multiplied event is #189's
decision, not taken. Under a full-contract sweep "zero" is the right reading; under a
scoped webhook collection it is not ([`splunk-setup.md`](splunk-setup.md) §7). A *scalar*
section read and genuinely empty is different: it still emits its anchor, as `{}` — the
real record's `userAndLocation` is one sub-event, `{"userAndLocation": {}}`, under
`loon:jamf:mac:userAndLocation` — so for the seven anchors absent means unread and `{}`
means read-and-empty, and a full read always produces all seven. (Ruled by default —
built, tested and posted this way in #242; Kyle confirms or overrules.)

**A section the registry does not name** — a shape from a newer producer replayed on an
older worker — is delivered unstamped rather than dropped or raised, the same degrade the
change family uses: `InventorySnapshotEvent` refuses unknown wrappers at enqueue, so this
is version skew, never a producer bug.

**The run id is UUIDv7, not `uuid4`, since
[#225](https://github.com/LoonSecIO/LoonInspect/issues/225).** `jobID` being a
correlation key (the ruling above) means `eventstats max(jobID) by serialNumber` — the
natural latest-state idiom on a fan-out sourcetype — is a search an analyst will reach
for. Over `uuid4`'s random hex that search was not wrong, exactly; it was meaningless,
silently, which is the failure mode this whole document exists to close off elsewhere.
UUIDv7 keeps the exact 36-character shape `uuid4()` already had — nothing downstream
that stores or displays a run id changes format — and sorts by creation time instead of
by nothing. Minted locally (`app/core/uuid7.py`) rather than the standard library's own
`uuid.uuid7()`, which is Python 3.14; this repo runs 3.12. ULID was considered and
rejected on the same #188 ruling that named UUIDv7: a second, differently-shaped id
format on the wire beside `eventID` for no gain UUIDv7 doesn't already give. Free before
the flip and a breaking change after it: `eventID` is `uuid5(jobID, jamfProID)`, so
changing `jobID`'s generator changes every derived event id too.

## 5. The log, and run-now

`run_log` is one row per engine line, scoped by tenant and run. Deliberately **not** per
device — a 40,000-device sweep writes milestones plus a progress line every 500 devices,
about 80 rows. The ledger is already the per-device record.

- `GET /api/runs?connectionId=&status=&limit=` — recent runs
- `GET /api/runs/{jobId}` — one run
- `GET /api/runs/{jobId}/log?after=<id>` — lines after a cursor, plus the run and a
  `complete` flag

`POST /api/mdm/connections/{id}/sync` now **always returns 202 with a jobID**, plus
`started` saying whether it began a run or joined one. Contention is not a 409: someone
clicking "Run now" during a cron sweep is asking "is my fleet syncing?", and showing them
the running sweep's log answers that better than an error does
(`ingest-scheduling.md` §4.2).

The UI (`RunLogPanel.tsx`) polls every two seconds and stops on two conditions, both
required: the run reaching a terminal status (**not** an empty page — a sweep mid-fleet
can be quiet for a minute and still be alive), and the tab becoming hidden
(`visibilitychange`, resumed on return; the cursor means resuming costs one request for
everything missed).

## 6. Retention

`RUN_RETENTION_DAYS`, default **30**, purged daily at 02:50 alongside the other cleanups.

Two existing precedents disagreed: `event_outbox_retention_days = 7` and
`audit_retention_days = 30`. The run log follows audit. It is what someone opens to
answer "did this run last month", so a week cannot serve its own purpose, and it is far
smaller than the outbox, which carries a row per event per destination. Log lines are
removed by cascade from the run rather than by a second delete that could drift.

## 7. Failure accounting (#92)

One device must not kill the sweep. Before this, the device loop had no per-device
isolation: any single failure — a corrupt record, or the race a webhook's mutex
exemption makes possible when both paths insert the same device's span within
milliseconds — failed the entire run, and because the tick claims an occurrence before
running it, that occurrence was already spent. On a 40,000-device fleet the odds of one
bad device are roughly certainty, so the failure mode lived exactly where a first
impression is made.

**Isolation.** A device that raises mid-sweep is rolled back (its partial writes must
not poison the session for the next device — per-device commits are the checkpoints
that make this cheap), recorded in the run log with its identity and error
(`device failed; sweep continues`, with `jamfId`, `serialNumber`, and the error class),
and the sweep continues. Two exceptions deliberately pass through: `RunReclaimed`
(the #94 fence — a reclaimed run must unwind, not absorb the signal into a failure
count) and cancellation.

**The threshold.** The run fails only when failures exceed
`max(SWEEP_FAILURE_MAX_ABSOLUTE, SWEEP_FAILURE_MAX_PERCENT% of devices attempted so
far)` — defaults **25** and **1.0**. Both are settings rather than constants on
least-regret grounds: a wrong default is corrected by an operator with one env var, not
by waiting for a release. The absolute floor keeps a small fleet from failing over a
handful of bad devices (1% of 200 is 2); the percentage keeps 25 from reading as an
outage on 40,000. Evaluated against devices *attempted so far* because that is the only
denominator that exists mid-stream — Jamf's totalCount is a floor, not gospel. The
consequence is deliberate: scattered failures across a big fleet stay inside a growing
allowance, while a run where everything fails from the first device is stopped just
past the floor rather than grinding through the whole fleet. At or under the threshold
the run finishes `succeeded` with its failures recorded; over it, the run is `failed`
with the count in its error and processing stops where the threshold was crossed.

**On the row.** `devices_processed` and `devices_failed`, with
`processed + failed = device_count` (attempted). A run can be `succeeded` with
`devices_failed > 0` — that is the point: "39,998 processed, 2 failed" is a healthy
night on a big fleet, and hiding the 2 inside a bare `succeeded` is how evidence rots.
The API returns both; the run panel shows a failed count only when it is non-zero.

**On the wire.** Every device-sweep or webhook run that closes — `succeeded` or
`failed` — emits `run.completed` through the outbox, in the same transaction as the
status flip, so the row and the wire cannot drift apart. Widened to webhook runs by
[#224](https://github.com/LoonSecIO/LoonInspect/issues/224): every inventory event
carries a `jobID`, sweep or webhook alike, and a webhook's `jobID` pointing at a
`run.completed` that could never arrive broke the one join a SIEM most wants to make —
"show me everything this run produced" — and voided the #188 ruling that the
`shortDate` basis and the aperture digest ride `run.completed`, joined by `jobID`, for
every run those events named. Catalog refreshes are the one lock class still excluded:
an hourly catalog `run.completed` would satisfy the absence search the nightly sweep
was supposed to answer, and a catalog pull has no device count worth reporting. A
*reclaimed* run emits no `run.completed` either — the reclaim is not a finish, and the
absence downstream is the signal that the run died (it does emit `run.failed`; see
below).

Always-emitting for a sweep or a webhook is the least-regret choice: it puts partial
failure in the evidence trail, where the silent gap — this product's worst class of bug
— cannot hide. It also moves a cost onto the one search this event exists to serve:
**"is the fleet fully inventoried" is `trigger=sweep OR trigger=manual` now, not a bare
`event=run.completed`.** A busy tenant's webhooks emit this event too, several times an
hour, and would silence a naive absence search on a night the actual nightly sweep never
closed. Payload, camelCase under the casing law above — every key on every family, not
just the inventory one:

| Field | Meaning |
| --- | --- |
| `event` | `run.completed` |
| `jobID` | The run — the same name and value `deviceMeta.jobID` carries |
| `connectionID` | Which connection swept |
| `trigger` | `sweep` \| `manual` \| `webhook` |
| `comparison` | `baseline` \| `delta` |
| `occurredAt` | The run's window end — the instant the row's `window_end` was stamped |
| `devicesTotal` | Devices attempted (`processed + failed`) — `1` for a webhook run |
| `devicesProcessed` | Devices ingested |
| `devicesFailed` | Devices that raised and were isolated |
| `status` | `succeeded` \| `failed` |

**The alarm beside the heartbeat (#103).** The moment any run reaches `failed` — by
finish or by the reclaim — it also emits `run.failed`, in the same transaction as the
status flip. Where `run.completed` is scoped to device sweeps so its *absence* stays
meaningful, `run.failed` fires for every trigger and every lock class: a failed
webhook or catalog run is exactly as silent as a failed sweep, and a failed device
sweep emits both — one answers "did the sweep close", the other pages on why. A
reclaimed run's `run.failed` comes from the reclaim itself; the zombie's late,
refused finish adds nothing, so each failure is one event. Delivery is default-on for
every destination: null/empty subscriptions already mean "all", and the
`a9d4c7e1f3b8` migration appended the type to every pre-existing explicit list — a
destination unsubscribes through its `subscribed_events` the ordinary way. Payload,
camelCase like `run.completed`'s — exactly the ruled fields, no credentials, no log
lines (the run id is the pointer to the full story):

| Field | Meaning |
| --- | --- |
| `event` | `run.failed` |
| `jobID` | The run — joinable against the run log and everything the run produced |
| `connectionID` | Which connection failed |
| `connectionName` | The same connection, readable in an alert without a join |
| `trigger` | `sweep` \| `manual` \| `webhook` |
| `windowStart` | The occurrence the run was serving |
| `windowEnd` | When it died — the instant the row's `window_end` was stamped |
| `error` | The stored run error, truncated to 500 characters |

## 8. What this does not do

- **The concurrency cap** (`ingest-scheduling.md` §4.3) — thirty connections due at 02:00
  are still admitted one at a time only because the tick runs sequentially, not because
  anything bounds it. Belongs to #27's queue.
- **`MdmSyncState` is now a projection**, not a lock. The Connections list still reads its
  `status`, and the sweep still writes it; nothing decides anything from it any more. The
  tick's busy check reads the run table instead. Collapsing it into `runs` is a follow-up.
- **The generic (non-Jamf) provider path** does not open a run. It has no collections and
  no ledger; when a second provider gets either, it gets a run with them.
