---
question: Can the ledger answer scoped attribute and group counts within one second at 40,000 Macs?
owner: codex
opened: 2026-11-28
review-date: 2026-11-30
---

# Attribute breakdown and group counts at 40,000 Macs

Measured on 2026-11-28 for [#966](https://github.com/LoonSecIO/LoonInspect/issues/966). The decision bar is 1,000 ms warm with a three-rule scope on 40,000 devices.

- **#968** should read built-in values from current ledger sections and EA values from the existing projection (scoped medians of 44.7 and 158.8 ms).
- **#979** should read memberships from current ledger sections (all-group counts took 111.8 ms and the three counts for one group took 132.8 ms).

## Timings

Each cell gives cold / warm execution time in milliseconds. Cold is the first execution after restarting PostgreSQL for that query and scope. This clears shared buffers and preserves the Docker VM’s filesystem cache. Warm is the median of the next three executions. Times come from PostgreSQL’s instrumented execution and exclude planning and client transport.

| Query | 5,000, whole fleet | 5,000, scoped | 40,000, whole fleet | 40,000, scoped |
| --- | ---: | ---: | ---: | ---: |
| Hardware model identifier | 13.2 / 10.5 | 11.6 / 8.6 | 60.5 / 54.2 | 48.2 / 44.7 |
| Extension attribute 13 | 25.0 / 10.8 | 22.2 / 8.4 | 182.3 / 179.6 | 161.2 / 158.8 |
| Counts for all 300 groups | 66.6 / 60.2 | 37.7 / 32.7 | 207.1 / 200.3 | 123.2 / 111.8 |
| In, out and unknown for group 7 | 32.8 / 27.8 | 26.9 / 18.2 | 233.6 / 216.8 | 148.1 / 132.8 |

## Fixture and scope

Each fleet has one synthetic Jamf connection and one current span per Mac. The production Jamf contract creates the general, hardware, operating system, extension attribute and observed group membership sections. The runs contain 14,594 and 116,326 distinct section rows. The hardware bodies carry 24 model identifiers. The EA projection holds 150 rows per Mac, inserted in device order, for 750,000 and 6,000,000 rows. An empty answer on 2% of devices is counted as unknown.

Observed Macs have 5 to 40 distinct memberships sampled from 300 groups. Common groups occur across the fleet and smaller groups share the tail. At 40,000 devices a group has between 2,239 and 38,400 observed members. Four percent of devices have an aperture that omits memberships and therefore contribute to unknown for the single-group query.

Both scopes use the existing `scoped_devices` predicate. The narrower scope requires managed, supervised and site North, joined with AND, leaving 2,286 and 18,285 Macs. Group 7 split the scoped 40,000-device fleet into 2,870 members, 14,500 known nonmembers and 915 unknown. Each of the 16 result sets was checked against counts computed from the fixture.

## Plans

Root-node buffers below are for the median warm execution on the scoped 40,000-device fleet. Shared pages are 8 KiB. Temp counts include work files from joins and aggregates.

| Query | Shared hits | Shared reads | Temp reads | Temp writes |
| --- | ---: | ---: | ---: | ---: |
| Hardware model identifier | 5,471 | 6,596 | 0 | 0 |
| Extension attribute 13 | 0 | 40,606 | 0 | 0 |
| Counts for all 300 groups | 27,929 | 6,500 | 3,722 | 3,760 |
| In, out and unknown for group 7 | 48,768 | 6,596 | 5,060 | 5,092 |

The hardware query hash-joined current spans, hardware sections and scoped devices. The EA query found 40,000 projection rows through the definition-ID bitmap index, then joined the scoped devices. It read 40,606 shared blocks on the median warm run. The all-group query expanded membership arrays and aggregated by group, while the single-group query tested the target digest against each observed list. Both group queries wrote temporary blocks.

The archive contains all 64 JSON plans from `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`, the exact SQL, the returned counts and the database settings. Each case stores the cold plan first and then the three warm plans in execution order. [5,000-device plans](https://github.com/LoonSecIO/LoonInspect/blob/0075e39ba67eff23d616a0bb069f87705e6a5d8e/docs/spikes/attribute-breakdown-at-40k/results-5000.json) · [40,000-device plans](https://github.com/LoonSecIO/LoonInspect/blob/0075e39ba67eff23d616a0bb069f87705e6a5d8e/docs/spikes/attribute-breakdown-at-40k/results-40000.json)

## Reproduction

The spike retains the generator at the measured commit. Check out `0075e39ba67eff23d616a0bb069f87705e6a5d8e` and run the commands below from the repository root with Docker available. [Generator and fixture](https://github.com/LoonSecIO/LoonInspect/tree/0075e39ba67eff23d616a0bb069f87705e6a5d8e/docs/spikes/attribute-breakdown-at-40k)

```sh
uv sync --project backend --frozen
backend/.venv/bin/python docs/spikes/attribute-breakdown-at-40k/bench.py 40000 5000
```

The runner starts a separate PostgreSQL 17.12 container for each size, applies the migrations in main commit `8c42d569` through Alembic head `c614b3d2e8f4`, and runs `VACUUM (ANALYZE)` before timing. A tenant-bound application role has `NOSUPERUSER NOBYPASSRLS`. Docker Desktop reported 16 arm64 vCPUs and 7.75 GiB of VM memory. PostgreSQL used 128MB shared buffers and 4MB work memory.

The Docker Desktop VM shared CPU and disk resources with other local work. Contention and the retained filesystem cache can affect these times. This measures a single reader, one connection, current spans and the specified scope. Fleet history, additional tenants, simultaneous ingest and more selective or expensive device rules can change the plan and its timing.
