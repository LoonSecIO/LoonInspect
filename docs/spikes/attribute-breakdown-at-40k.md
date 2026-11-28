---
question: Can the ledger answer scoped attribute and group counts within one second at 40,000 Macs?
owner: codex
opened: 2026-11-28
review-date: 2026-11-30
---

# Attribute breakdown and group counts at 40,000 Macs

Measured on 2026-11-28 for [#966](https://github.com/LoonSecIO/LoonInspect/issues/966). The decision bar is 1,000 ms warm on 40,000 devices with a device filter applied.

**Yes for values. No for group membership, once the ledger has history.**

- **#968** reads built-in values from current ledger sections and extension attribute values from the existing projection. With a simulated year of history and no group rule in the filter, both stay under 150 ms.
- **#979** builds a membership projection, and the `group` branch of `rule_predicate` (`backend/app/core/device_scope.py`) reads it. A filter with a `group is not` rule takes 1.0 to 1.5 seconds after a simulated year and took 11 seconds at day 180. A `group is` rule passes two seconds once short-lived groups churn. The counts #979 asks for are inside the bar on their own after a plain year (409 ms for every group, unfiltered) and at it on the heaviest ledger here (1,019 ms). The group rule is what is outside it, and the Groups pages are made of group rules.
- **Found in shipped code, not part of #966.** `device_scope.py:30` tests the current span as `is_current IS true`, which PostgreSQL 17 does not match to the partial index `uq_observation_spans_current_subject` (`WHERE is_current`), so a group rule scans every span a tenant has ever written. Written plain, the `group is` case on the heaviest ledger below falls from about 1.5 seconds to about 0.6, and `group is not` stays over a second. It affects every existing group filter and wants its own pull request.

## Two measurements, and why the second decides

The spike measured a ledger with one current span per Mac and nothing else: no closed spans, and five of the fourteen section kinds. Its filter was three rules on `devices` columns. On that ledger PostgreSQL scanned both ledger tables whole and was still fast, because there was nothing in them but the answer.

The review of this finding reran the spike's fixture unchanged, then gave it what a running instance has: all fourteen sections on every span, and a year of daily sweeps in which 5% of Macs change, the planning rate in `KNOWN_ISSUES.md` §2. Each change closes a span, opens one and replaces one section (65% applications, 15% extension attributes, 10% security, 5% certificates, 5% a one-day group membership change). It also added filters that carry a `group` or an `ea` rule, which the spike's did not.

## Without history

Each cell gives cold / warm execution time in milliseconds. Cold is the first execution after restarting PostgreSQL for that query and scope, which clears shared buffers and preserves the Docker VM's filesystem cache. Warm is the median of the next three executions. Times come from PostgreSQL's instrumented execution and exclude planning and client transport.

| Query | 5,000, whole fleet | 5,000, scoped | 40,000, whole fleet | 40,000, scoped |
| --- | ---: | ---: | ---: | ---: |
| Hardware model identifier | 13.2 / 10.5 | 11.6 / 8.6 | 60.5 / 54.2 | 48.2 / 44.7 |
| Extension attribute 13 | 25.0 / 10.8 | 22.2 / 8.4 | 182.3 / 179.6 | 161.2 / 158.8 |
| Counts for all 300 groups | 66.6 / 60.2 | 37.7 / 32.7 | 207.1 / 200.3 | 123.2 / 111.8 |
| In, out and unknown for group 7 | 32.8 / 27.8 | 26.9 / 18.2 | 233.6 / 216.8 | 148.1 / 132.8 |

The review's rerun of this fixture gave 41, 153, 107 and 120 ms for the scoped 40,000-device column.

## With history

Warm milliseconds at 40,000 devices. "Day 365" is 764,434 closed computer spans (19.1 per Mac) and 975,998 section rows; the spans heap is 1,651 MB.

| Filter | Ledger | Built-in value | Extension attribute | All groups | One group |
| --- | --- | ---: | ---: | ---: | ---: |
| Three column rules (the spike's) | no history | 41 | 153 | 107 | 120 |
| Three column rules | day 90 | 61 | 58 | 294 | 148 |
| Three column rules | day 180 | 67 | 57 | 292 | 159 |
| Three column rules | day 365 | 83 | 64 | 326 | 200 |
| None, whole fleet | day 365 | 142 | 116 | 409 | 273 |
| `group is`, managed, site | day 365 | 388 | 331 | 456 | 403 |
| `group is`, `ea is not`, site | day 365 | 633 | 601 | 817 | 687 |
| `group is not`, managed, site | day 90 | 431 | 421 | 643 | 485 |
| `group is not`, managed, site | day 180 | 11,478 | 11,156 | 11,571 | 11,238 |
| `group is not`, managed, site | day 365 | 1,150 | 978 | 1,473 | 1,281 |
| `group is`, managed, site | day 365 with rollouts | 2,374 | 2,542 | 2,771 | 2,683 |
| `group is not`, managed, site | day 365 with rollouts | 3,277 | 3,887 | 3,888 | 4,027 |
| None, whole fleet | day 365 with rollouts and superseded rows | 227 | 133 | 1,019 | 1,072 |
| `group is`, managed, site | day 365 with rollouts and superseded rows | 1,479 | 1,445 | 1,915 | 1,821 |

Every result set was checked against counts computed from the fixture.

The day 180 row is one plan, not noise: a nested-loop anti join chosen on an estimate of 35 rows against 10,553. Day 365 chose differently and was ten times faster, which is the other half of the finding. A read whose time depends on which side of an estimate the planner lands is not one to put under a page.

"With rollouts" adds twenty short-lived groups, each taking half the fleet for a day, which stand for the phased rollouts large organizations run. They add ten membership lists per Mac to the ledger's history and nothing to its current state. "Superseded rows" adds 1.94 million section rows no current span points at: twelve Jamf upgrades each rewriting `general`, and extension attribute answers moving on 10% of Macs. Those two ledgers are 6.7 and 7.6 GiB on a VM with 7.75 GiB of memory, so their times may include reads from disk; the ledgers up to day 365 are under 4 GiB and do not.

## Fixture and scope

Each fleet has one synthetic Jamf connection. The production Jamf contract creates the sections. The spike's runs contain 14,594 and 116,326 distinct section rows; the hardware bodies carry 24 model identifiers. The EA projection holds 150 rows per Mac, inserted in device order, for 750,000 and 6,000,000 rows. An empty answer on 2% of devices is counted as unknown.

Observed Macs have 5 to 40 distinct memberships sampled from 300 groups. Common groups occur across the fleet and smaller groups share the tail. At 40,000 devices a group has between 2,239 and 38,400 observed members, so no group here is small. Four percent of devices have an aperture that omits memberships and contribute to unknown for the single-group query.

Every filter uses the existing `scoped_devices` predicate. The spike's requires managed, supervised and site North, joined with AND, leaving 2,286 and 18,285 Macs. Group 7 split that scoped 40,000-device fleet into 2,870 members, 14,500 known non-members and 915 unknown.

## Plans

Without history the hardware query hash-joined current spans, hardware sections and scoped devices, scanning `observation_spans` and `observation_sections` whole. With history, spans are reached through `uq_observation_spans_current_subject`, and `observation_sections` is still scanned whole, so that scan grows with every section an instance has ever stored. The EA query reads the projection through its definition index and does not touch the ledger, which is why history leaves it where it was.

A filter with a group rule runs the group branch of `rule_predicate` for each device. That branch scans spans in full for the reason given at the top, and reads each device's membership list from the ledger.

## Reproduction

The spike's generator and its 64 recorded plans are at `0075e39ba67eff23d616a0bb069f87705e6a5d8e`, and the history harness with its measurement logs is at `fc31a1a6628307ed052cd3363f8387a6741dd211`, both on the branch `spike/attribute-breakdown-at-40k`. [Generator and fixture](https://github.com/LoonSecIO/LoonInspect/tree/0075e39ba67eff23d616a0bb069f87705e6a5d8e/docs/spikes/attribute-breakdown-at-40k) · [history harness](https://github.com/LoonSecIO/LoonInspect/tree/fc31a1a6628307ed052cd3363f8387a6741dd211/docs/spikes/attribute-breakdown-at-40k/history)

`docs/BRANCHING.md` §3.1 has a spike's branch deleted once its finding merges. These commits are reachable from that branch alone, so the links above last only as long as it does. Everything this document concludes is in the tables above.

```sh
uv sync --project backend --frozen
backend/.venv/bin/python docs/spikes/attribute-breakdown-at-40k/bench.py 40000 5000
```

The runner starts a separate PostgreSQL 17.12 container for each size, applies the migrations in main commit `8c42d569` through Alembic head `c614b3d2e8f4`, and runs `VACUUM (ANALYZE)` before timing. A tenant-bound application role has `NOSUPERUSER NOBYPASSRLS`. Docker Desktop reported 16 arm64 vCPUs and 7.75 GiB of VM memory. PostgreSQL used 128MB shared buffers and 4MB work memory.

## What was not measured

A single reader on one connection, with nothing ingesting. More than one tenant or connection. A truly cold cache. The change rate of a real instance: the 5% is the planning figure, not an observation, and the mix of what changes is the review's assumption. The Docker Desktop VM shared CPU and disk with other local work.
