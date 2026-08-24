# Ingest scheduling for Jamf Pro pulls

Status: **implemented — the what and the when (#27, 2026-08-22) as *collections*; the run
object, mutex, heartbeat and `_time` window (#31, 2026-08-23, see [runs.md](runs.md))** ·
Target: V0

> **What landed, and where it deviates.** The ingest profile of §3/§10 shipped under the
> user-facing name **collection** (`collections` table, `app/mdm/collections.py`,
> `app/api/collections.py`, Settings → Connections → Collections). Three kinds:
> `device_sweep` (sections + RSQL selector pushed into Jamf's query; always ends with a
> catalog refresh, §6.2), `catalog` (smart-group definitions with criteria on their own
> cadence), `webhook` (event-driven; scopes the fetch-by-jssID). Connection setup creates
> the three defaults as real rows (§3.2); the old `SYNC_HOUR` / `SYNC_MINUTE` /
> `SYNC_TIMEZONE` became the default sweep's schedule rather than a global cron. A minute
> tick (`collections_tick`) claims due rows with one conditional `UPDATE … WHERE
> next_due_at <= now RETURNING` (§5 — correct across processes without the run row), runs
> them sequentially, and advances `next_due_at` in the row's own zone. Rate floors (§4.2)
> are enforced on save and at claim time; a manual run resets the scheduled one. A device
> sweep whose connection is mid-sync is left unclaimed and retried next minute.
>
> **Then #31 (2026-08-23), which took every correction §4 and §11 propose.** The mutex is
> a `runs` row with the partial unique index on `(tenant_id, mdm_connection_id,
> lock_class)` of §4.1; webhooks are lock-exempt in the index predicate (§4.4); the
> heartbeat shipped with it and replaced the startup blanket reset (§4.5); run-now returns
> 202 with a jobID on contention rather than a 409 (§4.2); the tick's busy check now reads
> the run table rather than `mdm_sync_state.status`; and `claim_due` hands back the
> occurrence it claimed, so a run's window is the time it was *due*. Full design in
> [runs.md](runs.md). Still open and owned by #27: the concurrency cap of §4.3 — a tick
> runs one collection at a time because it is sequential, not because anything bounds it.

This document settles how a customer chooses when LoonInspect pulls from Jamf Pro, and
what stops those pulls from harming the Jamf tenant they point at. It is a design
handoff, not a specification of code — the implementation belongs to #27, and several
of its guarantees depend on run-object work that belongs to #31.

The reference point throughout is the Splunk Add-on for Jamf Pro that this product
replaces (`https://github.com/jamf/SplunkBase`, abandoned 2022), for the same reason
`splunk-event-shaping.md` uses it: a migrating customer should find the scheduling model
familiar, and where we deviate we should have decided to.

---

## 1. Problem

Scheduling today is one global cron with no per-customer surface at all.

`main.py:268` registers a single `nightly_sync_sweep` on
`CronTrigger(hour=settings.sync_hour, minute=settings.sync_minute)`. The defaults are
`sync_hour=1`, `sync_minute=0`, `sync_timezone="America/Chicago"` (`config.py:49-52`),
settable only as environment variables (`.env.example:47-50`). The job then loops every
active connection with no selector and no per-connection policy.

So: one time, one timezone, every tenant, every connection, changeable only by an
operator with shell access to the container. Nothing in the API, nothing in the
frontend.

Three things need to be true when this is done:

1. A customer can choose when their fleet is pulled, per ingest path, without an
   operator editing `.env`.
2. No configuration a customer can express — and no combination of scheduled, manual,
   and webhook triggers — can pull one Jamf Pro tenant more often than policy allows.
3. The shape supports an MSP with many Jamf Pro instances **without being repainted**,
   even though the MSP-facing surface itself is not V0.

---

## 2. Non-negotiable design constraints

| Constraint | Consequence |
| --- | --- |
| Customers migrate from a Splunk modular input | Scheduling attaches to an *input*, not to an account (§3) |
| The product exists to avoid grinding the MDM API | A rate floor enforced at claim time, not only at config time (§4.2) |
| Webhooks must ACK fast (#14) | Webhooks are exempt from the sweep lock; ordering is solved on the write (§4.4) |
| One process today, more later | No scheduling state in process memory (§5) |
| An MSP may hold 30+ Jamf connections | Total concurrency is bounded globally, not per connection (§4.3) |
| Customers span timezones | Timezone is a property of the schedule row, not a global setting (§3.3) |
| A stalled run must not wedge a tenant forever | The mutex ships with a heartbeat or not at all (§4.1) |

---

## 3. The model: inputs, not connections

### 3.1 Setup enables a schedule; it does not imply one

**Decision: a Jamf Pro connection carries credentials and nothing else. Schedules live
on ingest profiles that reference it.**

This is the Splunk add-on's own shape. The add-on is a *modular input* — Python running
inside Splunk, polling `computers-inventory` on an interval
(`splunk-event-shaping.md` §"What that old add-on actually did"). Its per-input module
is `bin/input_module_jamfcomputers.py`, the Splunk Add-on Builder naming convention for
an input whose account configuration is a separate object.

One account, N inputs, each with its own interval, scope, and enabled flag.

That separation is not fidelity for its own sake — it is the only model in which §6's
two polling classes can be expressed at all. "Device sweep daily, service catalog
hourly" is two inputs against one account. A schedule attached to the connection cannot
say it.

`ingest_profiles` in #27 **is** this object. That issue arrived at it from the other
direction — arguing about fetch *scope* rather than cadence — and the two are the same
table. #27 should absorb scheduling rather than being collided with.

> **Deviation from the reference, deliberate.** Splunk inputs carry their own interval
> with no inheritance, which is exactly why managing thirty of them is miserable. See
> §8.2 — we should not copy that part.

### 3.2 One default input at setup

A user who connects Jamf Pro and observes nothing happen concludes the product is
broken. Connection setup therefore creates **one** ingest profile — full device sweep,
daily, off-peak — as a real row that is visible, editable, and deletable.

Defaults are a first-run courtesy. Implicit behaviour with no row behind it is a support
ticket.

### 3.3 What a customer may express

Not a cron expression. Three reasons: it invites `* * * * *` pointed at a production
Jamf tenant, it is a support burden, and it has no way to say "event-driven, no
cadence," which §6 needs.

The surface is **time-of-day + timezone + a coarse frequency** (daily / every N days /
weekly). That covers the real request — "sweep my fleet at 2am my time, unmanaged
devices on Sundays" — and is a closed set that can be validated and rendered.

Timezone belongs on the profile row. `sync_timezone` is currently a single global
setting, and the scheduler object itself is constructed with it (`main.py:54`), so an
MSP with customers in New York and Los Angeles cannot express two 2ams three hours
apart. §5's due-check design removes that limitation for free, because "is this due?"
is evaluated per row in that row's zone.

---

## 4. The three guards

These are three different mechanisms preventing three different failures. They are
frequently conflated; a design that ships only the first is not safe.

| Guard | Prevents | Grain | Owner |
| --- | --- | --- | --- |
| Mutex | Two sweeps of the **same** Jamf at once | Per connection, per lock class | #31 |
| Rate floor | Sixty sweeps of **one** Jamf in an hour | Per connection | #27 |
| Concurrency cap | Thirty sweeps of **thirty** Jamfs at once | Global, per process | #27 |

### 4.1 Mutex — and the grain #31 currently gets wrong

The present check-then-set is a race. `connections.py:409` does `db.get` → inspect
`status` → `set_sync_status` as separate statements across an await. The comment on
line 416 claims a second racing request "sees 'syncing' and is rejected," but both
requests read `idle` before either commits. The comment describes intent, not a
guarantee. #31 already identifies this.

#31's fix is a run row with a partial unique index, sketched as:

```
partial unique index on (tenant_id) where status = 'running'
```

**That key is wrong in one direction.** It permits only one run per *tenant*, so a
tenant holding two Jamf Pro instances can sweep only one at a time, for no reason —
they are separate hosts with separate capacity. And once §6's classes exist, a
fifteen-minute catalog refresh could never run during a forty-minute device sweep,
starving the catalog exactly when the sweep is generating references into it (§6.2).

The resource being protected is the Jamf server, which is the connection. The key is:

```
partial unique index on (tenant_id, connection_id, lock_class) where status = 'running'
```

`tenant_id` is present for RLS and scoping; `connection_id` does the mutual exclusion;
`lock_class` separates expensive device sweeps from cheap catalog reads.

Acquisition is the insert. The loser gets an integrity error rather than a second run —
atomic, unlike SELECT-then-INSERT.

### 4.2 Rate floor — enforced at claim time

"No full pull more than once an hour" cannot be enforced only by validating the
schedule, because manual runs and webhooks never pass through schedule validation. A
floor enforced at config time is a floor with a bypass button next to it.

Enforce in both places:

1. **On save** — reject a cadence below the floor for that profile kind.
2. **At claim time** — check elapsed time against `MdmSyncState.last_sync_at`
   (`schema.py:189`, already present) before starting, regardless of trigger.

Floors are per profile kind, not global:

| Kind | Floor | Why |
| --- | --- | --- |
| Full device sweep | 1 hour | Thousands of devices, the expensive path |
| Catalog / definitions | 15 minutes | Hundreds of rows, seconds of work |
| Webhook | none | One device that already changed — see §6.3 |

Two consequences worth stating, because both are counterintuitive:

- **A manual run resets the cooldown for the scheduled one.** Run manually at 01:55 and
  the 02:00 sweep skips, logging why. Otherwise the floor is not a floor.
- **A blocked manual run returns the in-flight run's jobID, not a 409.** Someone
  clicking "Run now" during a cron sweep wants to know the fleet is syncing; showing
  them the running sweep's log answers that better than an error does. #31 already wants
  run-now to gray to "processing" with a jobID-filtered log view, so this points the
  same component at a run it did not start. The contract becomes: `POST
  /connections/{id}/sync` always returns 202 with a jobID plus a flag for whether it
  started a new run or joined one.

### 4.3 Concurrency cap — the guard the MSP case exposes

With the mutex keyed per connection, thirty connections due at 02:00 are all free to
start: **thirty concurrent full pulls in one process**, each paginating thousands of
devices and writing device and app rows.

Jamf-side that is fine — thirty different servers, one sweep each. The bottleneck is
ours: connection pool, memory, and the event loop.

So **02:00 is a queue admission time, not a start time.** All thirty become due, N
start, the rest drain in turn. This matches the reference product's behaviour, where
modular inputs are scheduled independently but the forwarder bounds what actually runs.

> **This supersedes #31's random-minute jitter for the intra-install case.** Jitter is a
> poor man's concurrency cap — it spreads load statistically and hopes. A queue bounds
> it exactly, exposes the backlog, and degrades predictably at 300 connections instead
> of 30. #31's jitter retains a purpose across *separate installs* hitting Jamf Cloud;
> it should not be the mechanism protecting a single install from itself.

### 4.4 Webhooks are lock-exempt, and that is a separate problem

Webhooks cannot take the sweep lock. They must ACK fast (#14), a busy tenant fires many,
and serializing them behind a forty-minute sweep makes the real-time path useless. #31's
"a webhook is a run with one device in it" is right about the *machinery* and must not
extend to the *lock*.

That leaves a real collision: a sweep reads device X at 01:10, a webhook reads the same
device at 01:30 and writes, the sweep writes its stale copy at 01:40. Last-writer-wins
loses the newer data.

The fix is not a lock but a **monotonic guard on the write** — compare Jamf's own
`reportDate` (already normalised as `last_inventory_at`, `client.py:144`) and refuse to
let an older observation overwrite a newer one. That makes sweep/webhook ordering
irrelevant rather than coordinated, and is independently correct.

### 4.5 The trap: a mutex without a heartbeat is a deadlock

If a run holds the lock and the process dies, the row stays `running` forever and
**nothing in that tenant can sync again** — cron, manual, or otherwise.

That is strictly worse than the race it replaces. The race causes duplicate load, which
is noisy and self-limiting; this causes permanent silence, and silence pages nobody.

#31 has `heartbeat_at` with stale reclaim for exactly this, and it is what lets it
delete the startup blanket reset at `main.py:255` that is already wrong under multiple
processes. **The heartbeat is inseparable from the mutex — they ship together or the
mutex does not ship.**

---

## 5. Execution: a due-check tick, not registered jobs

The obvious implementation registers one APScheduler job per profile. It would work
today, because `serve.py:71` runs a single uvicorn process with no `workers`. It should
still be rejected.

Two things break at the second process, which is the direction #31 already describes as
"actively wrong with more than one worker or during a rolling restart":

- The scheduler is a module-level in-memory `AsyncIOScheduler` (`main.py:54`). N
  processes means N copies of every job, so every profile runs N times.
- A `PATCH` changing a schedule can only mutate the scheduler object *in the process
  that served the request*. Other processes keep the old schedule until restart — a
  silent divergence with nothing in the logs.

**Instead: one frequent global tick asks the database which profiles are due, claims
each, and runs it.** Schedule changes become an ordinary row write. No live scheduler
mutation, no cross-process coordination, identical behaviour on one process or six.

The reason this fits *here* specifically is that it composes with #31 rather than
duplicating it: the partial unique index of §4.1 **is** the claim. Two processes racing
for the same due profile both insert; one wins, the other takes the integrity error and
moves on. Correct distributed scheduling falls out of work that is already a V0 blocker.

The cost is granularity bounded by the tick interval. For a nightly fleet sweep, nobody
cares.

---

## 6. Two polling classes

### 6.1 What actually exists today

The Jamf client has exactly one fetch method: `fetch_devices()` (`client.py:77`) against
`/api/v4/computers-inventory`. There is no group, profile, or extension-attribute
definition fetching anywhere. EA *values* ride inside each computer record, which is why
`EXTENSION_ATTRIBUTES` sits in `INVENTORY_SECTIONS`.

**The service/catalog class is new surface, not a rescheduling of existing code.** That
matters for V0 sizing.

### 6.2 Definitions and assignments are different objects

For groups, profiles, and extension attributes there are two things, and only one of
them is what "service polling" means:

| | Definitions | Assignments |
| --- | --- | --- |
| What | The smart group, the profile, the EA and its type | Which devices are in it / have it |
| Size | Tens to hundreds per tenant | Rows × devices |
| Changes | When an admin edits something | Constantly |
| Source | Its own endpoint (**unbuilt**) | Inside device inventory |

Definitions are small and slow-changing, so they can poll far more often than devices —
and they **must**, for a correctness reason rather than a cost preference:

> **The catalog must be at least as fresh as the device data referencing it.** If a
> sweep emits "device joined group 47" and the catalog has never heard of group 47, we
> have shipped a dangling reference into the customer's SIEM. Splunk-side lookups have
> exactly this failure mode.

So a device sweep that encounters an unknown reference should trigger a catalog refresh
rather than emitting the bare ID.

### 6.3 The fetch-direction fork stays with #27

Assignments can be fetched device-first (add `GROUP_MEMBERSHIPS` to `INVENTORY_SECTIONS`
and pay per device on every sweep) or group-first (enumerate each group's members and
pay per group). #27 already noticed the first half — memberships are not fetched at all
today.

Given #27's own argument about not paying per-device for data nobody reads, group-first
likely wins for bulk and device-first for webhooks — the same inversion #27 states. That
decision belongs in #27 against a real tenant, not here.

---

## 7. More than one Jamf Pro in one tenant

**The schema is already correct.** `schema.py:113`:

```python
UniqueConstraint("mdm_connection_id", "external_id", name="uq_device_connection_external_id")
```

Devices are keyed per connection, not per serial, so two Jamf Pro instances produce two
device rows for the same physical Mac and never contend.

This avoids a genuinely bad failure that a `(tenant_id, serial_number)` key would have
caused: connection A reporting `managed=true` and connection B reporting `managed=false`
would flap the same row on every sweep and emit a change event to the SIEM each time.
Unbounded event churn. Not a risk as built.

The cost is no cross-Jamf correlation — `serial_number` carries no index or constraint.
For an MSP that is correct behaviour (customer A's device must never merge with customer
B's). For a Jamf-to-Jamf **migration**, "show me this serial in both" is a sequential
scan; an index on `(tenant_id, serial_number)` is cheap and worth taking whenever
migration becomes a supported use case. Not V0.

---

## 8. The MSP case

### 8.1 An MSP's customers are tenants, not connections

Given RLS, thirty customers must be thirty tenants — customer A's devices must not be
visible to a query scoped to customer B, which is the boundary `tenant_id` exists to
enforce. #35 and #36 exist for this shape.

Which means **"all my Jamf Pros at 02:00" is a cross-tenant operation.** It cannot live
on the connection, and it cannot live on the tenant either. It needs a scope *above*
tenant, and writing a schedule spanning thirty tenants is precisely the RLS bypass #35
is about.

The scheduler already has this shape internally: `_tenants_with_work()` (`main.py:58`)
iterates tenants specifically because background jobs have no tenant to inherit.

### 8.2 Decision: V0 ships the per-profile layer; inheritance waits for #35

**This is the judgement call in this document, and the one most worth overturning if the
author disagrees.**

V0 ships schedules on ingest profiles, per connection, with their own timezone. The
"set it once for all thirty" inheritance layer is **deferred behind #35**, because
whether it hangs off an organisation row or a tenant-group row depends on what exists
above tenant — and that is not decided.

Reasoning: feature freeze is ~2026-09-07, #35 is labelled post-V0, and inheritance
genuinely cannot be designed before the tenancy question is answered. Meanwhile
everything expensive to reverse is settled here and lands MSP-safe: where the schedule
lives, the lock key grain, timezone on the row, and queue-over-jitter.

What this costs an MSP at V0: editing thirty profiles instead of one. Real, and
survivable for a release whose first customers are unlikely to be MSPs.

What it would cost to get wrong instead: a schedule column on the wrong table, migrated
later under customer data.

---

## 9. Outbound events: unchanged, and why

**Decision: not its own cron, not event-triggered, not user-configured. No change.**

This is already built and the pattern is right. `enqueue_event()` writes the event in the
same transaction as the state change (`outbox.py:28`) and `deliver_pending()` ships it on
an independent 30-second tick (`outbox.py:121`). The code comments are emphatic about
why: a slow or down destination must never block a sync or delay a webhook ACK.

Making delivery a user-facing schedule would reintroduce exactly the coupling the outbox
exists to remove.

There are three questions hiding inside "how does scheduling connect to outbound," and
only one is open:

| Question | Status |
| --- | --- |
| When is the event written? | During the run, transactionally. Settled, correct. |
| When is it delivered? | 30s tick. Settled — a latency knob, not a schedule. |
| What `_time` does it carry? | **Open, and owned by #31.** |

The third is the one that matters. To a Splunk analyst, delivery timing is invisible and
`_time` is the entire experience. #31's rule — scheduled runs back-date events to the run
window, webhooks carry device time — is the answer, and `occurred_at` is currently
`datetime.now(timezone.utc)` at emit time for all three paths (`service.py:289`). If
outbound feels unsettled, this is why, and it is already assigned.

The only genuinely open outbound configuration is **per-destination batching** (max
events per HEC request), which is a destination property rather than a schedule. Out of
V0 unless the reference add-on exposes it.

---

## 10. Data model sketch

Extends #27's `ingest_profiles` rather than replacing it.

```
ingest_profiles
  id, tenant_id, connection_id, name, enabled
  kind              -- device_sweep | catalog | (webhook profiles carry no schedule)
  selector          -- management status, last-check-in age        (#27)
  sections          -- which Jamf sections to fetch                (#27)

  -- scheduling (this document)
  frequency         -- daily | every_n_days | weekly | null (event-driven)
  interval_n        -- for every_n_days
  at_hour, at_minute
  timezone          -- IANA zone, per profile; not the global setting
  next_due_at       -- computed on write and after each run; the tick's index
  last_claimed_at

  lock_class        -- derived from kind; the mutex dimension (§4.1)

runs                                                              (#31)
  ... plus:
  partial unique index on (tenant_id, connection_id, lock_class) where status = 'running'
```

`next_due_at` is materialised rather than computed per tick so the due query is an index
scan over one column instead of timezone arithmetic across every profile row.

---

## 11. Corrections to make to existing issues

Neither issue is edited by this document. These are the changes it proposes.

**#27 — becomes the V0 implementation issue**

- Relabel `post-v0` → `v0`. It is the substrate for scheduling, not an optimisation.
- Absorbs schedule, timezone, and rate floor; drops the bare `schedule` line from its
  sketch in favour of §10.
- State that `ingest_profiles` is the Splunk *input* object (§3.1).
- Keep the fetch-direction fork for assignments (§6.3).

**#31 — four corrections**

1. Index key becomes `(tenant_id, connection_id, lock_class)`, not `(tenant_id)` (§4.1).
2. Webhooks are lock-exempt; ordering is solved by a monotonic write guard (§4.4).
3. Run-now returns a jobID on contention rather than a 409 (§4.2).
4. Random-minute jitter is superseded by the concurrency queue for the intra-install
   case; retain it only for cross-install spread (§4.3).

Plus one emphasis, not a correction: the heartbeat is not follow-on polish (§4.5).

---

## 12. Open questions

Nothing here should be assumed resolved.

1. **Is the MSP surface V0?** Answered "no" in §8.2 as a judgement call in the author's
   absence. The most consequential single decision in this document.
2. **Splunk account/input separation** — §3.1 is grounded in the modular-input facts
   already verified in `splunk-event-shaping.md` and in Add-on Builder naming
   convention. The specific claim that account and input configuration are separate
   objects with per-input intervals is **not yet verified against
   `https://github.com/jamf/SplunkBase` directly.** It should be, before #27 is written
   — it is load-bearing for §3.
3. **Tick interval for the due check.** Bounds schedule granularity. 1 minute is
   defensible; 5 is cheaper. No strong opinion.
4. **Concurrency cap default** — needs measuring against a real tenant with a real
   device count, not choosing by intuition.
5. **Does the catalog class ship in V0 at all?** §6.1 establishes it is entirely new
   surface. Scheduling could ship with device sweeps only, and catalog profiles land
   after. Probably the right cut, but it is the author's call.
6. **`hourly_jamf_patch_sync` is deliberately out of scope.** It fetches the public
   catalog and is intentionally global and tenant-free (`schema.py:194`). It stays a
   fixed cron. Recorded here so the omission is explicit rather than accidental.

---

## 13. Suggested implementation order

1. **#31** — run row, mutex with the corrected key, heartbeat, `_time` back-dating.
   Everything below depends on it; nothing below is safe without it.
2. **#27** — `ingest_profiles` with scope and schedule, the due-check tick, rate floors,
   concurrency cap, and the default profile at connection setup.
3. **Catalog profiles** — new client methods for definitions, plus the freshness
   ordering in §6.2. Separate issue; possibly post-V0 per open question 5.
4. **MSP inheritance** — after #35, per §8.2.
