# The v0 Splunk wire vocabulary

Status: **frozen** · Ruled in [#188](https://github.com/LoonSecIO/LoonInspect/issues/188),
2026-08-31 and 2026-09-01 · Amended, additively, in
[#229](https://github.com/LoonSecIO/LoonInspect/issues/229),
[#220](https://github.com/LoonSecIO/LoonInspect/issues/220) and
[#113](https://github.com/LoonSecIO/LoonInspect/issues/113), 2026-09-02 and
[#243](https://github.com/LoonSecIO/LoonInspect/issues/243), 2026-09-03 · Registry
generated from [`app/core/wire_vocabulary.py`](../backend/app/core/wire_vocabulary.py)

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

Ruled 2026-09-03 on [#243](https://github.com/LoonSecIO/LoonInspect/issues/243). Nothing stamps these yet: [#223](https://github.com/LoonSecIO/LoonInspect/issues/223) owns the
stamp, and this family is the stated exception to "the first sourcetype arrives with the
fan-out" (§7).

And LoonInspect's own assertions: `loon:run`.

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
is not written yet and the first sub-event ever emitted has to be right.

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
([`runs.md`](runs.md) §4). It also leaves a sub-event legible with no sourcetype set,
which is the state the wire is in today (#222).

**`jobID` sits at the sub-event root and inside `deviceMeta`.** The duplicate is the
ruling: the root copy makes the bare `jobID=$id$` join work across every family and every
sub-event, and the nested copy stays because a customer's SPL may already name it and an
unknown field returns zero rows with no error. [`runs.md`](runs.md) §4 carries the full
argument.

**`deviceMeta` is why the cap is thirteen.** Every key in it is written once per app, per
extension attribute, per certificate and per profile. A fourth key proposed for this list
is a #189 decision about a cost measured in fields × events × devices × syncs, not a
naming one.

## 7. What is ruled here but not yet built

The vocabulary is frozen; what follows from it and is not yet implemented has its own
issue rather than living on as a footnote.

| Consequence | Issue |
| --- | --- |
| `sourcetype` is not stamped on delivered events — the tree names fan-out sub-events that are not built, so `app/core/outbox.py` deliberately sends none and the operator sets it on the HEC input | [#222](https://github.com/LoonSecIO/LoonInspect/issues/222) |
| The `:change` family is ruled (§2) and nothing stamps it — `changes/derive.py` emits `device.change` with no sourcetype, no `eventID` and no `deviceMeta`, and group ids share the computer id space. #243 ruled this family may be stamped first rather than waiting for the fan-out | [#223](https://github.com/LoonSecIO/LoonInspect/issues/223) |
| `run.completed` fires only for the full sweep, so every intraday `jobID` from a webhook run is a dangling pointer | [#224](https://github.com/LoonSecIO/LoonInspect/issues/224) |
| `JamfClient.host` drops the port that `source` retains, so the aperture merges two instances Splunk separates | [#226](https://github.com/LoonSecIO/LoonInspect/issues/226) |
| `alert` is minted with no writer — #101 ships the alerts table and the Needs Attention rows with nothing on the wire; the block's shape (a keyed list on the app, per the 2026-08-29 ruling) and its kind vocabulary are named when it is built, additive under clause 1 | [#101](https://github.com/LoonSecIO/LoonInspect/issues/101) |
