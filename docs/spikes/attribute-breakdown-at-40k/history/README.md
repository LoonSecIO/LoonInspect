# Ledger history harness for the 40,000-Mac breakdown spike

The spike timed four reads on a ledger with one current span per Mac, under a filter of three `devices` columns. This harness runs the same four statements, unchanged, after giving that fixture the shape of a ledger that has been running for a year, and under filters that contain a `group` rule.

Measured 2026-11-28 on Docker Desktop (16 arm64 vCPUs, 7.75 GiB VM, other containers running), PostgreSQL 17.12 with its defaults (128MB shared buffers, 4MB work memory, 2 workers per gather), Alembic head `c614b3d2e8f4`. The protocol is the spike's: restart PostgreSQL before each case, one cold run, the median of the next three as warm.

## Stages

Each stage is the one before it plus what its row adds. All hold 40,000 Macs. `C090` is day 90, `-p05` is 5% of Macs changing per day, `-lists10` is ten more membership lists per Mac.

| Label | Adds | Closed spans | Section rows | Membership lists | Database, GiB |
| --- | --- | ---: | ---: | ---: | ---: |
| `A-control` | the spike's `seed.sql` and `ledger.py`, unmodified | 0 | 116,326 | 36,272 | 1.2 |
| `B-current14` | `stage_b.sql`: all fourteen sections and the other entry kinds, no history | 0 | 318,950 | 36,272 | 1.7 |
| `C090-p05` | days 1 to 90 of daily sweeps (`sim.sql`) | 188,514 | 480,983 | 44,842 | 2.3 |
| `C180-p05` | days 91 to 180 | 377,074 | 643,245 | 53,363 | 2.8 |
| `C365-p05` | days 181 to 365 | 764,434 | 975,998 | 71,080 | 3.9 |
| `D365-lists10` | 20 short-lived groups, days 366 to 405 (`sim_rollout.sql`) | 1,553,640 | 1,378,605 | 455,640 | 6.7 |
| `E365-lists10-filler` | superseded content rows (`filler.sql`) | 1,553,640 | 3,318,605 | 455,640 | 7.6 |

- **`stage_b.sql`.** Every computer span gains nine section digests, fourteen in all, and its identity columns. 202,624 section rows: 40,000 each of applications, certificates, local user accounts, user and location, and disk encryption; 2,000 purchasing; 300 configuration profiles; 12 security; 10 software updates; 302 definitions. 380,091 entries: 160,000 certificates, 80,000 accounts, 80,000 per-Mac EA answers, 60,000 applications, 91 profiles and updates. 302 current spans for smart groups and EA definitions. 2,460 departure rows that exclude no Mac. A helper table `verify_orig` (each Mac's original membership list) and a function `vdg` (synthetic digests). Then `VACUUM FULL observation_spans`.
- **A daily sweep (`sim_day`).** The Macs whose hash of (id, day) falls under 5% each change one section: applications 65%, extension attributes 15%, security 10%, certificates 5%, a membership excursion 5% (a new list that day, the original list back the next). A changed Mac gets a content row where the content is new, its span closed and a new span with `previous_id`, as `record_observation` writes them. Unchanged Macs get the counter and timestamp update on their current span, and `devices.last_*` is stamped: daily to day 166, then every fifth day (every fifth pair of days in stage D), with a `VACUUM` each time.
- **A short-lived group (`sim_rollout_day`).** Half the observed Macs get a new membership list for one day (the original minus its first entry, under a new digest); the next day is an ordinary 5% day that returns them. Twenty such pairs of days.
- **`filler.sql`.** 480,000 `general` rows, twelve per Mac, and 1,460,000 `extension_attributes` rows. Content rows only, no spans.

Hardware sections never change and every membership list ends where it began, so `check.py` holds each result set to the counts the fixture's own rules predict. The application lists, and the EA lists the sweeps and the filler write, are empty arrays. A real ledger keeps those lists in TOAST, which the four reads never open, so only the heap row matters to them: 144 bytes here by `pg_column_size`, against the 6.7 MB of heap `KNOWN_ISSUES.md` §2 measures for 40,000 real application lists, 167 bytes each.

## Scopes

| Name | Rules, joined with AND |
| --- | --- |
| `whole-fleet` | none |
| `three-column` | managed is true, supervised is true, site is North (the spike's) |
| `grp_managed_site` | group is 5, managed is true, site is North |
| `grp_ea_site` | group is 5, extension attribute 13 is_not `value-3`, site is North |
| `notgrp_managed_site` | group is_not 7, managed is true, site is North |

Group rules name connection 1. Every scope is compiled by `scoped_devices` at the spike's fixed clock. `queries.json` holds the SQL: `spike` is the spike's eight statements byte for byte, `alt` the three group scopes. A label ending `+plain-is_current` is `altfix`: the same statement with `observation_spans.is_current IS true` replaced by `observation_spans.is_current`. `gen_sql.py` rebuilds every block except `altfix`, so rerun it only if you redo that replacement.

## Rerun

Work in a copy of this directory outside any checkout. `REPO` is a clone that holds the spike commit; the generator at `cc88b9d7` is identical to the one at `0075e39b`. The scripts expect the container name `verify1002-pg`, and `measure.py` restarts it before every case. `T` is `OPERATIONAL_TENANT_ID`, which `simulate.sh`, `rollouts.sh` and `queries.json` also carry. The host needs `docker`, `git`, `openssl` and a `python3` with only its standard library.

```sh
git -C "$REPO" archive cc88b9d7ba94ae95c48cfd5a78f3f5a2224134da backend docs/spikes | tar -x -C work
PGPW=$(openssl rand -hex 20); APPPW=$(openssl rand -hex 20); ENCKEY=$(openssl rand -base64 32 | tr '+/' '-_')
docker network create verify1002-net; docker volume create verify1002-pgdata
docker run -d --name verify1002-pg --network verify1002-net --shm-size 256m -e POSTGRES_PASSWORD="$PGPW" -v verify1002-pgdata:/var/lib/postgresql/data postgres:17-alpine
docker run -d --name verify1002-runner --network verify1002-net -e UV_PROJECT_ENVIRONMENT=/opt/venv -e UV_LINK_MODE=copy -v "$PWD/work":/work -w /work/backend ghcr.io/astral-sh/uv:python3.12-alpine sleep infinity
docker exec verify1002-runner uv sync --frozen; until docker exec verify1002-pg pg_isready -h 127.0.0.1 -U postgres; do sleep 1; done
docker exec verify1002-pg psql -XqAt -U postgres -c "CREATE ROLE bench_app LOGIN PASSWORD '$APPPW' NOSUPERUSER NOBYPASSRLS" -c "CREATE DATABASE bench OWNER bench_app"
docker exec -e DATABASE_URL="postgresql+asyncpg://bench_app:$APPPW@verify1002-pg:5432/bench" -e PYTHONPATH=/work/backend -e UPDATE_CHECK=false -e ENCRYPTION_KEY="$ENCKEY" verify1002-runner /opt/venv/bin/python -m alembic upgrade head

T=00000000-0000-0000-0000-000000000002
sql() { docker exec -i verify1002-pg psql -XqAt -U bench_app -d bench -v ON_ERROR_STOP=1 "$@"; }
py() { docker exec -w /work -e PYTHONPATH=/work/backend:/work/docs/spikes/attribute-breakdown-at-40k verify1002-runner /opt/venv/bin/python "$@"; }
measure() { python3 out/measure.py "$@" && cp "out/results-$1.json" work/harness/ && py harness/check.py "harness/results-$1.json"; }
ALL=spike,alt:grp_managed_site,alt:grp_ea_site,alt:notgrp_managed_site

sql -v n=40000 -v tenant=$T < work/docs/spikes/attribute-breakdown-at-40k/seed.sql
py -c "import asyncio,uuid;from ledger import seed_ledger;asyncio.run(seed_ledger(40000,uuid.UUID('$T'),'postgresql://bench_app:$APPPW@verify1002-pg:5432/bench'))"
sql -c "VACUUM (ANALYZE)"; measure A-control $ALL
sql -v n=40000 -v tenant=$T < work/harness/stage_b.sql; sql < work/harness/sim.sql; sql < work/harness/sim_rollout.sql
sql -c "VACUUM FULL observation_spans" -c "VACUUM (ANALYZE)"; measure B-current14 $ALL
sql < out/sim-1-90.psql; measure C090-p05 $ALL
sed '/^CALL sim_day(167,/,$d' out/sim-91-180.psql | sql; sh out/simulate.sh 167 180 0.05; measure C180-p05 $ALL
sh out/simulate.sh 181 365 0.05; measure C365-p05 $ALL
sh out/rollouts.sh 366 20 0.5 0.05; measure D365-lists10 spike,alt:grp_managed_site,alt:notgrp_managed_site
sql -v tenant=$T < work/harness/filler.sql; measure E365-lists10-filler spike,alt:grp_managed_site
measure E365-lists10-filler spike-scoped --guc "SET max_parallel_workers_per_gather=0;"
python3 out/measure.py E365-lists10-filler altfix:grp_managed_site,altfix:notgrp_managed_site; python3 out/summ.py
docker rm -f verify1002-pg verify1002-runner; docker network rm verify1002-net; docker volume rm verify1002-pgdata
```

Days 1 to 166 are replayed from the two recorded statement lists, because `simulate.sh` now writes the every-fifth-day cadence and would overwrite them; the `sed` stops the second list where the run was stopped. The replay is not identical to the run for days 1 to 90, whose update of unchanged Macs skipped spans never changed since seeding (about 1% of Macs by day 90): see the header of `sim.sql`. `check.py` has no entry for the `+plain-is_current` labels and stops on them; those eight result sets were compared with the same scope's rows under the shipped predicate, and `summ.py` does not print them, so keep `measure.py`'s output. This block was dry-run end to end on a 400-Mac fleet (with 400 in `check.py`) from a directory holding only the files listed as needed below, and every checked result set was correct; it was not rerun at 40,000.

## What is assumed

- **5% of Macs changing per day** is the capacity-planning rate in `KNOWN_ISSUES.md` §2, written there for application sets. Using it as the rate at which a Mac's head digest moves, in any section, is this harness's choice. §1 of the same file plans the change log at two changes per Mac per day, which would imply far more spans.
- **The mix of changed sections**, the twenty short-lived groups and their half-fleet size, and the filler (twelve Jamf upgrades each rewriting `general`, where `jamfBinaryVersion` is hashed, and an EA answer moving on 10% of Macs per day) are guesses. Nothing here was calibrated against a live instance.
- **Plans move with the ANALYZE sample and with autovacuum timing.** The 11-second plan for `notgrp_managed_site` at day 180 is one plan choice seen at one checkpoint. At day 365 three fresh ANALYZE runs all gave 1.1 s for the built-in read under that scope.
- **The last two stages are as large as the VM.** D is 6.7 GiB and E is 7.6 GiB against 7.75 GiB of memory shared with ten other containers, so the page cache may not hold them whole and their times may include reads from disk. Stages A to C365, 3.9 GiB at most, fit.

## Files

- **Needed.** In `out/`: `measure.py`, `simulate.sh`, `rollouts.sh`, `sim-1-90.psql`, `sim-91-180.psql`, and `summ.py` to print the tables. In `work/harness/`: `stage_b.sql`, `sim.sql`, `sim_rollout.sql`, `filler.sql`, `gen_sql.py`, `queries.json`, `check.py`. `measure.py` writes `out/results-<stage>.json`, which `summ.py` and `check.py` read; `check.py` has 40,000 written into it.
- **Logs only.** The seven `out/measure-*.log` files are the record of the numbers: per case the cold time, the warm median and its three runs, planning time, root buffers, and how each table was reached. Everything else in `out/` is a log, a helper (`show_plan.py` and `show_my.py` print plans, `check_doc.py` recomputes the finding's tables from the spike's archive), a copy of the finding, or a statement list the scripts regenerate.
