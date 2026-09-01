# The v0 Splunk wire vocabulary

Status: **frozen** · Ruled in [#188](https://github.com/LoonSecIO/LoonInspect/issues/188),
2026-08-31 and 2026-09-01 · Registry generated from
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
[`app/core/wire.py`](../backend/app/core/wire.py); what an operator does with all of it
is [`docs/splunk-setup.md`](splunk-setup.md).

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

`patch` and `vuln` are short by the same rule. They ride the highest fan-out object the
product emits — one per app, per device — and neither collides with anything.

> **Correction, 2026-09-01.** #81 ruling 5, the vulnerability-summary wire design, and
> the #113 CVE scope all carried `vulnerabilities{}`, and by extension `patching{}`.
> Those records are superseded by this table. The brevity rule applies cleanly where
> nothing is ambiguous, and the competing spellings were precedent rather than argument.

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
`collectionID`, `jamfProID`.

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
   vocabulary needing to say *never* says so with a sentinel — which is why `days_oldest`
   uses `-1`.
5. A sourcetype string, once minted, is permanent. New shapes get new sourcetypes;
   existing ones are not repurposed.
6. `schemaVersion` rides the `deviceMeta` block and **never** the sourcetype. A version
   in the sourcetype breaks every dashboard on every bump, so it never gets bumped, so it
   is a lie.

`schemaVersion` is deliberately distinct from `CONTRACT_VERSION`
(`app/mdm/jamf/contract.py`), which governs observation digests and never appears on a
delivered event. It ships today as `WIRE_SCHEMA_VERSION` in `app/schemas/payload.py`.

## 6. What is ruled here but not yet built

The vocabulary is frozen; three consequences of it are not implemented, and each has its
own issue rather than living on as a footnote.

| Consequence | Issue |
| --- | --- |
| `sourcetype` is not stamped on delivered events — the tree names fan-out sub-events that are not built, so `app/core/outbox.py` deliberately sends none and the operator sets it on the HEC input | [#222](https://github.com/LoonSecIO/LoonInspect/issues/222) |
| `changes/derive.py` emits `device.change` outside this vocabulary — no `eventID`, no `deviceMeta`, and group ids sharing the computer id space | [#223](https://github.com/LoonSecIO/LoonInspect/issues/223) |
| `run.completed` fires only for the full sweep, so every intraday `jobID` from a webhook run is a dangling pointer | [#224](https://github.com/LoonSecIO/LoonInspect/issues/224) |
| The run id is `uuid4`, so `max(jobID)` — the latest-state idiom on a fan-out sourcetype — is meaningless. UUIDv7 is free until the flip | [#225](https://github.com/LoonSecIO/LoonInspect/issues/225) |
| `JamfClient.host` drops the port that `source` retains, so the aperture merges two instances Splunk separates | [#226](https://github.com/LoonSecIO/LoonInspect/issues/226) |
