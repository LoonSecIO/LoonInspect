# The v0 Splunk wire vocabulary

Status: **frozen** · Ruled in [#188](https://github.com/LoonSecIO/LoonInspect/issues/188),
2026-08-31 and 2026-09-01 · Amended, additively, in
[#229](https://github.com/LoonSecIO/LoonInspect/issues/229),
[#220](https://github.com/LoonSecIO/LoonInspect/issues/220) and
[#113](https://github.com/LoonSecIO/LoonInspect/issues/113), 2026-09-02 and
[#243](https://github.com/LoonSecIO/LoonInspect/issues/243), 2026-09-03 · Stamped on the
wire by [#223](https://github.com/LoonSecIO/LoonInspect/issues/223) (the `:change`
family), [#242](https://github.com/LoonSecIO/LoonInspect/issues/242) (the section tree
and `loon:run`) and [#277](https://github.com/LoonSecIO/LoonInspect/issues/277) (the
delta family), 2026-09-03 · Registry generated from
[`app/core/wire_vocabulary.py`](../backend/app/core/wire_vocabulary.py)

The vocabulary had been ruled three times, differently — the draft, #81 on 2026-08-24,
and the schema review on 2026-08-31 — with no single artifact holding the answer.
Whoever implemented next picked at random. This document is the answer.

It matters more than its size suggests. A `props.conf [<sourcetype>]` stanza accepts no
wildcards, so every string minted here is a hand-written stanza in a customer's Splunk
forever. SPL field names are case-sensitive, and a wrong one returns **zero rows with no
error** — the same argument `core/runs.py` already makes in writing for the
`runtype` / `run_type` rename.

**This document changes no code by itself.** The registry table below is generated from
`SECTIONS` in `app/mdm/jamf/contract.py` — the read aperture — so a section cannot be
collected without a name to travel under, and a name cannot outlive its section.
`tests/test_wire_vocabulary.py` fails on drift in either direction.

Companion documents: the casing law and the `deviceMeta` block are in
[`docs/runs.md`](runs.md) (#189); the envelope — `time` / `host` / `source` — is
[`app/core/wire.py`](../backend/app/core/wire.py); the `vuln` enrichment's own keys and
their lifecycle are [`docs/vulnerabilities.md`](vulnerabilities.md) (#113); what an
operator does with all of it is [`docs/splunk-setup.md`](splunk-setup.md).

---

## 1. The sourcetype tree

```
loon:<vendor>:<platform>:<entity>[:<enrichment>]
```

**The producer token leads.** A sourcetype describes *format*, not provenance, and this
is LoonInspect's shape — fan-out grain, meta block, enrichment slots, envelope — not
Jamf's. Leading with `loon` makes `loon:*` the one token that finds everything this
product wrote in an index it shares with EDR, DHCP and identity logs.

**The vendor segment is insurance.** Addigy, Fleet and SimpleMDM produce records that
genuinely differ in shape; `loon:*:mac:app` covers them all in one dashboard on the day
they exist. `pro` is dropped — Jamf School, if it ever happens, is `loon:jamfschool:*`.

**No vendor segment means LoonInspect's own assertions.** `loon:run` carries
`run.completed` and `run.failed`: statements about a run, not about a fleet. This is also
the standing answer to open question 4 of [`splunk-event-shaping.md`](splunk-event-shaping.md)
— LoonInspect's augmentations are **namespaced, not flattened** into Jamf's native fields.

**The leaf equals the body's wrapper key**, so `sourcetype=loon:jamf:mac:app` implies
`app.*` and there is one vocabulary rather than two.

**The trailing compound survives.** `loon:jamf:mac:app:vuln` keeps `*:vuln` working as a
search across every subject and every vendor.

## 2. The registry

Generated from `SECTIONS`. One row per collected section, in the order the contract
declares them.

| Contract section | Jamf response key | Wrapper key | Sourcetype |
| --- | --- | --- | --- |
| `general` | `general` | `general` | `loon:jamf:mac:general` |
| `hardware` | `hardware` | `hardware` | `loon:jamf:mac:hardware` |
| `operating_system` | `operatingSystem` | `operatingSystem` | `loon:jamf:mac:operatingSystem` |
| `user_and_location` | `userAndLocation` | `userAndLocation` | `loon:jamf:mac:userAndLocation` |
| `purchasing` | `purchasing` | `purchasing` | `loon:jamf:mac:purchasing` |
| `security` | `security` | `security` | `loon:jamf:mac:security` |
| `disk_encryption` | `diskEncryption` | `diskEncryption` | `loon:jamf:mac:diskEncryption` |
| `applications` | `applications` | `app` | `loon:jamf:mac:app` |
| `extension_attributes` | `extensionAttributes` | `ea` | `loon:jamf:mac:ea` |
| `group_memberships` | `groupMemberships` | `group` | `loon:jamf:mac:group` |
| `configuration_profiles` | `configurationProfiles` | `profile` | `loon:jamf:mac:profile` |
| `local_user_accounts` | `localUserAccounts` | `localUserAccount` | `loon:jamf:mac:localUserAccount` |
| `certificates` | `certificates` | `cert` | `loon:jamf:mac:cert` |
| `software_updates` | `softwareUpdates` | `update` | `loon:jamf:mac:update` |

**Stamped since [#242](https://github.com/LoonSecIO/LoonInspect/issues/242), 2026-09-03.**
Each string above is the `sourcetype` of the sub-events the fan-out expands one
`device.inventory` snapshot into — one HEC event per section item, `app/core/hec_fanout.py`,
read off `registry_rows()` and spelled nowhere else — on Splunk HEC deliveries only. A
scalar section is one sub-event; a list section is one per item; the sub-event body is the
item plus the three keys of §6. What one looks like, and what a delivery carries, is
[`runs.md`](runs.md) §4; the operator's stanzas are [`splunk-setup.md`](splunk-setup.md) §6.

Enrichments — LoonInspect's own answers about a Jamf object, carried on that object's
sub-event rather than as sub-events of their own:

| Carrier | Enrichment | Sourcetype |
| --- | --- | --- |
| `app` | `patch` | `loon:jamf:mac:app:patch` |
| `app` | `vuln` | `loon:jamf:mac:app:vuln` |
| `app` | `alert` | `loon:jamf:mac:app:alert` |

On the wire, `alert` is LoonInspect's own latch on an object — a fact it asserts about an
app, the NEW-app latch first ([#101](https://github.com/LoonSecIO/LoonInspect/issues/101))
— never the customer's Splunk saved-search alert. A LoonInspect `alert` is what a saved
search fires *on*; everywhere else this product's documentation says *alert*, it means the
customer's. Nothing writes the block in v0 (§6).

Changes are their own sourcetypes, not inline keys (#81 ruling 6): an inline key describes
what IS, a sourcetype describes what HAPPENED. One string per entity a `device.change` can
name, generated the same way — fourteen sections plus the one subject that is not a
section:

| Subject | Wrapper key | Sourcetype |
| --- | --- | --- |
| `general` | `general` | `loon:jamf:mac:general:change` |
| `hardware` | `hardware` | `loon:jamf:mac:hardware:change` |
| `operating_system` | `operatingSystem` | `loon:jamf:mac:operatingSystem:change` |
| `user_and_location` | `userAndLocation` | `loon:jamf:mac:userAndLocation:change` |
| `purchasing` | `purchasing` | `loon:jamf:mac:purchasing:change` |
| `security` | `security` | `loon:jamf:mac:security:change` |
| `disk_encryption` | `diskEncryption` | `loon:jamf:mac:diskEncryption:change` |
| `applications` | `app` | `loon:jamf:mac:app:change` |
| `extension_attributes` | `ea` | `loon:jamf:mac:ea:change` |
| `group_memberships` | `group` | `loon:jamf:mac:group:change` |
| `configuration_profiles` | `profile` | `loon:jamf:mac:profile:change` |
| `local_user_accounts` | `localUserAccount` | `loon:jamf:mac:localUserAccount:change` |
| `certificates` | `cert` | `loon:jamf:mac:cert:change` |
| `software_updates` | `update` | `loon:jamf:mac:update:change` |
| `computer_group` | `computerGroup` | `loon:jamf:mac:computerGroup:change` |

**`:change` is a family marker, not a wrapper-key promise.** The leaf rule in §1 is scoped
to section and enrichment leaves. `device.change` already ships `change` as a scalar verb
— `changed` / `added` / `removed` / `updated` — and that is the key an analyst's
`change=removed` search wants; giving the family a `change{}` wrapper would have meant
renaming a shipped key, which clause 2 forbids. What the leaf carries instead is the
trailing-compound property: `*:change` pulls every change across every subject and every
vendor, exactly as `*:vuln` does.

**`computerGroup` names a subject, not a section.** A smart group's definition is its own
ledger subject with no entry in `SECTIONS`, so its segment is the camelCase of that subject
kind. `group` is already the device's `group_memberships` section, and a group has to stay
distinguishable from the definition of a group (§3). The bare `loon:jamf:mac:computerGroup`
is implied by the tree and deliberately not minted — nothing writes it.

Ruled 2026-09-03 on [#243](https://github.com/LoonSecIO/LoonInspect/issues/243) and
stamped the same day by [#223](https://github.com/LoonSecIO/LoonInspect/issues/223) — the
first sourcetypes the product ever sent, because a change is already one event per
changed thing. `wire_vocabulary.change_sourcetype()` decides the string and
`app/core/outbox.py` sends it, on Splunk HEC deliveries only; a subject with no wrapper is
delivered unstamped rather than failing, and every other destination type gets the
canonical event. The operator's side of it — which stanzas this implies — is
[`splunk-setup.md`](splunk-setup.md) §6.

And LoonInspect's own assertions: `loon:run`, carrying `run.completed` and `run.failed`
since [#242](https://github.com/LoonSecIO/LoonInspect/issues/242) — the same change as the
section tree, because the "shape about to change" reason that held the tree back never
applied to a run event. `ASSERTION_EVENT_TYPES` names the two, and `app/core/runs.py`
reads its event-type constants from there so the string and the producer cannot drift.

**Thirty-one strings are stamped, and every one comes from this module** (#222's
acceptance, closed by #242): the fourteen section strings on the fan-out, `loon:run` on
the run family, the fifteen `:change` strings on the change family, and
`loon:inventory:changed` on the delta family
([#277](https://github.com/LoonSecIO/LoonInspect/issues/277), 2026-09-03, stamped the day
before the flip). Still under the HEC input's own default: only the test event, which is
meant to be identifiable rather than routed. The three enrichment strings are minted with
no writer (§7).

## 3. Why some wrapper keys are short and some are not

**Short where the fan-out is high; long where the section is one-per-device.** The block
is written onto every sub-event a device produces, so a section that expands into a
hundred rows pays for its name a hundred times, and one that appears once does not.

**Ambiguity overrides brevity.** `user` / `account` was rejected because
`userAndLocation` and `localUserAccounts` become indistinguishable — the same failure the
contract's *"field names readable English, no abbreviations"* rule exists to prevent.
This is the reason the table is published rather than left derivable: nothing tells a
reader, or an agent writing SPL, that `applications` shortens to `app` while
`operatingSystem` does not.

`patch`, `vuln` and `alert` are short by the same rule. They ride the highest fan-out
object the product emits — one per app, per device — and none collides with anything.

> **Correction, 2026-09-01.** #81 ruling 5, the vulnerability-summary wire design, and
> the #113 CVE scope all carried `vulnerabilities{}`, and by extension `patching{}`.
> Those records are superseded by this table. The brevity rule applies cleanly where
> nothing is ambiguous, and the competing spellings were precedent rather than argument.

> **Correction, 2026-09-02.** #81 ruling 5 parked `alerts{}`, and #101, #106 and the
> posture tape's `alerts.open` / `alerts.opened_24h` carry the plural. On the wire the key
> is `alert` — singular, like every other wrapper, ruled in
> [#229](https://github.com/LoonSecIO/LoonInspect/issues/229). The posture keys are a
> different vocabulary and keep their spelling: this document governs the wire only (§4),
> as `macos` in the data-sharing payload already sits beside `mac` in the sourcetype. The
> field that grades an alert is `level`, reusing the change log's closed
> `high | normal | low`, never `severity`.

## 4. Casing

> Wire keys are camelCase. The token `ID` is uppercase wherever it appears; every other
> initialism follows camelCase.

Narrow deliberately, ruled 2026-09-01. A general "all initialisms are uppercase" rule
contradicts the wrapper keys `ea` and `cert` above, and would mint `CVEID`, `OSVersion`
and `MDMProvider`. Under the narrow clause the vocabulary gets `cveID`, `kevListed`,
`epssScore`, `osVersion`.

A vendor's native key keeps the vendor's spelling — Jamf writes `bundleId`, so the wire
does too. The rule governs LoonInspect-minted keys.

**Scope: the wire only.** `connectionId` in the REST API and `last_run_summary` in the
database are unaffected. The case-sensitivity argument applies to what a customer types
into a search bar, not to this product's own HTTP contract, and renaming the query
parameter would churn the frontend and break bookmarked URLs for no consumer's benefit.

The id vocabulary, ruled in #189 and applied: `eventID`, `jobID`, `connectionID`,
`jamfProID`. `collectionID` was in this list because the block shipped it, not because
#189 ruled it in — the ruling refused it, and it was removed from `deviceMeta` along with
`comparison`. Its casing stands if a run-family key ever carries the collection; nothing
emits one today. See [`runs.md`](runs.md) §4.

**One minted key on a vendor object.** The extension-attribute item is Jamf's object
verbatim — `definitionId`, `name`, `values`, `dataType`, `inputType`, `multiValue`,
`options`, `description`, `enabled`, each under Jamf's spelling — plus `source`, the one
key LoonInspect mints inside a Jamf object anywhere on the wire: the response key the
array was found under (`extensionAttributes`, or the display section `general`,
`hardware`, `operatingSystem`, `userAndLocation`, `purchasing`). Ruled on
[#197](https://github.com/LoonSecIO/LoonInspect/issues/197); the contract discards it and
the wire keeps it, on purpose — [`jamf-observations.md`](jamf-observations.md) §7. It is
unrelated to the envelope's `source` (the Jamf instance): the item's key lands as
`ea.source` under Splunk's JSON extraction, and the envelope field is never in the body.

## 5. Additive-only

Without this in writing there is no licence to add `patch{}` or `vuln{}` later at all —
a key added to a shipped contract is a breaking change by default. These clauses are the
licence. Clause one is verbatim from #188's acceptance list; the set is asserted against
`ADDITIVE_ONLY_CLAUSES` in `app/core/wire_vocabulary.py`.

1. **New keys may appear; consumers must ignore unknown keys.**
2. A key's name, type and meaning never change once shipped. A different meaning is a
   different key.
3. A key that ships is never removed. A key that stops being computed ships its
   null-equivalent, or is absent under the null-dropping rule that already governs
   `deviceMeta`.
4. Absence of a key means the event predates it, never that its value is "none". A
   vocabulary needing to say *never* says so with a sentinel — which is why
   `daysOldestPublished` uses `-1`.
5. A sourcetype string, once minted, is permanent. New shapes get new sourcetypes;
   existing ones are not repurposed.
6. `schemaVersion` rides the `deviceMeta` block and **never** the sourcetype. A version
   in the sourcetype breaks every dashboard on every bump, so it never gets bumped, so it
   is a lie.

> **Correction, 2026-09-02.** Clause 4 cited its sentinel example as `days_oldest`, a
> snake_case name minted before this document froze camelCase and before
> [#113](https://github.com/LoonSecIO/LoonInspect/issues/113) named the clock in the key.
> The clause is unchanged in substance; the key it cites is `daysOldestPublished`, and
> the vulnerability contract it belongs to is [`docs/vulnerabilities.md`](vulnerabilities.md).

`schemaVersion` is deliberately distinct from `CONTRACT_VERSION`
(`app/mdm/jamf/contract.py`), which governs observation digests and never appears on a
delivered event. It ships today as `WIRE_SCHEMA_VERSION` in `app/schemas/payload.py`.

## 6. The keys every sub-event carries

Three, whatever sourcetype the sub-event lands under. Ruled on
[#220](https://github.com/LoonSecIO/LoonInspect/issues/220), 2026-09-02, and named here
rather than in the builder because the fan-out ([#242](https://github.com/LoonSecIO/LoonInspect/issues/242))
was not written yet and the first sub-event ever emitted had to be right. The fan-out is
built (2026-09-03, `app/core/hec_fanout.py`) and reads this tuple; it spells none of the
three by hand.

| Key | What it carries | Ruled |
| --- | --- | --- |
| `event` | The snapshot's own type, verbatim | #220 |
| `jobID` | The run, at the sub-event root | #220 |
| `deviceMeta` | The identity of the pull, whole | #189 |

**`event` is the snapshot's type, not the sub-event's.** Nothing mints
`device.inventory.app`. `sourcetype` is what says an event is an app rather than a
certificate — §1's leaf rule already guarantees that — and `event` is what keeps
`event=device.*` selecting the whole fan-out from one predicate, the same
single-discriminator argument that moved the run families off `event_type`
([`runs.md`](runs.md) §4). It also leaves a sub-event legible on a destination that carries
no sourcetype at all.

**`jobID` sits at the sub-event root and inside `deviceMeta`.** The duplicate is the
ruling: the root copy makes the bare `jobID=$id$` join work across every family and every
sub-event, and the nested copy stays because a customer's SPL may already name it and an
unknown field returns zero rows with no error. [`runs.md`](runs.md) §4 carries the full
argument.

**`deviceMeta` is why the cap is thirteen.** Every key in it is written once per app, per
extension attribute, per certificate and per profile. A fourth key proposed for this list
is a #189 decision about a cost measured in fields × events × devices × syncs, not a
naming one.

The event the fan-out expands is the per-device snapshot, `device.inventory`
([#241](https://github.com/LoonSecIO/LoonInspect/issues/241)): it carries all three at its
root, once, and each of its list items is already the sub-event body minus these three —
`{"app": {…}, "patch": {…}, "vuln": {…}}` — so the split is iteration, not reshaping
([`runs.md`](runs.md) §4). That is what `app/core/hec_fanout.py` does: the sub-event body
is `{event, jobID, …the item…, deviceMeta}` — the snapshot's own layout, head first, block
last — under `sourcetype(wrapper)`, with the envelope hints beside it. The snapshot's fourth
head key, `occurredAt`, does **not** ride the sub-event: these three are the complete list,
and the same instant travels beside every sub-event as the envelope's `time`. Under
additive-only clause 3 omitting it is the reversible direction.

## 7. What is ruled here but not yet built

The vocabulary is frozen; what follows from it and is not yet implemented has its own
issue rather than living on as a footnote.

| Consequence | Issue |
| --- | --- |
| The three enrichment strings — `loon:jamf:mac:app:patch`, `:vuln`, `:alert` — are minted with no writer, because an enrichment rides inline on the app sub-event under its own key (§2). `:vuln` is reserved for the lifecycle records of [`vulnerabilities.md`](vulnerabilities.md) §6; `:patch` and `:alert` name shapes nothing produces. `patch{}` and `vuln{}` themselves ship on every app sub-event since #241/#242, and [#249](https://github.com/LoonSecIO/LoonInspect/issues/249) populated `vuln{}` (2026-09-03) **without stamping anything**: the summary is an inline enrichment on `loon:jamf:mac:app`, because taking the compound for it would force `loon:jamf:mac:app:patch:vuln` on an app carrying both blocks, and a `props.conf` stanza takes no wildcards. Thirty-one strings are still stamped; the registry did not move | post-v0 (`vulnerabilities.md` §10) |
| `alert` is minted with no writer — #101 ships the alerts table and the Needs Attention rows with nothing on the wire; the block's shape (a keyed list on the app, per the 2026-08-29 ruling) and its kind vocabulary are named when it is built, additive under clause 1 | [#101](https://github.com/LoonSecIO/LoonInspect/issues/101) |
