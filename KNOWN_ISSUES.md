# Known issues

Limits this project knows about and has not fixed. Every number here was measured on
2026-09-01 against a throwaway `docker compose` stack built from `main` at `8af4375`
(schema revision `d5b1e7c4a930`) on Postgres 17.11 — not estimated, and not carried over
from an earlier version of this file. Where a figure is arithmetic on a measured
constant rather than a direct observation, it says so.

Operating procedures — backup, restore, upgrade, rollback — are in
[docs/operations.md](docs/operations.md). Security reports go through
[SECURITY.md](SECURITY.md), never a public issue.

---

## 1. `device_changes` grows for ever

**The limit.** Three things are bounded: outbox events after 7 days
(`event_outbox_retention_days`), runs and their log lines after 30
(`run_retention_days`), and the audit log by daily file rotation keeping
`audit_retention_days` files. The change log is not one of them. Nothing deletes a
`device_changes` row, ever, and there is no setting that would.

**Measured.** 514 bytes per row, all in — 390 bytes of heap and 124 of index across the
seven indexes on the table — over 200,000 synthetic rows of the commonest shape (an
application whose version moved). A second run of 50,000 rows in a different shape came
out at 480. Call it **500 bytes a row**.

**Where it bites.** Multiply by your own change rate; the row size is the measurement,
the rate is your fleet's. At two logged changes per device per day:

| Fleet | Rows / year | `device_changes` / year |
| --- | --- | --- |
| 1,000 | 730,000 | 0.37 GB |
| 10,000 | 7.3M | 3.7 GB |
| 40,000 | 29.2M | **15 GB** |

(GB = 10⁹ bytes. The rate is the assumption in that table — a fleet on a monthly patch
cadence sits well under it and a fleet mid-migration sits well over it. The change *log*
counts every change your policy keeps, which is a larger number than the wire figure in
the README, since that one counts only what a destination is subscribed to.)

**Workaround.** Delete old rows. This is safe by design and not a hack:
`device_changes` is *derived* from the observation ledger, and the model says so in as
many words — "deletable without loss — the spans hold the truth and a re-derivation
under a different policy is always possible". What you lose is the Changes view's
history for that window; the ledger, the devices and the app catalog are untouched.

```bash
docker compose exec -T db psql -U looninspect -d looninspect \
  -c "DELETE FROM device_changes WHERE observed_at < now() - interval '90 days';" \
  -c "VACUUM (ANALYZE) device_changes;"
```

Run it as `looninspect`, the bootstrap superuser, exactly as written: `looninspect_app`
is `NOBYPASSRLS`, so the same statement as the app role deletes one tenant's rows and
silently leaves the rest.

Measured, on 50,000 rows half of which were older than 90 days:

```
 rows  | on_disk
-------+---------
 50000 | 24 MB

DELETE 24981
VACUUM
 rows_left | on_disk
-----------+---------
     25019 | 24 MB
```

**Note the second `on_disk`.** Plain `VACUUM` marks the pages reusable, it does not
give them back to the filesystem, so a purge run to free disk frees none. `VACUUM FULL
device_changes` does, and takes an `ACCESS EXCLUSIVE` lock on the table for the
duration — every read and write blocks. Schedule it, or size the volume so you never
need it.

## 2. The observation ledger grows for ever, and cannot be safely pruned

**The limit.** Same absence of a retention setting, different consequence:
`observation_spans`, `observation_sections` and `observation_entries` are the evidence
every change is derived from, and an old section row stays after nothing points at it.

**Measured**, on `observation_sections` with 40,000 distinct application sets of 100
apps each, drawn from a 5,000-app tenant catalog so the shared digests behave the way a
real fleet's do: **90.6 bytes per app entry**, all in — 6.7 MB of heap, 331 MB of TOAST
and 24 MB of index for 4,000,000 entries. With every digest distinct instead (no app
shared between any two devices — a shape no real fleet has, but the ceiling) the GIN
index on `entry_digests` stops sharing posting lists and the same 4M entries cost
**224 bytes each**, 897 MB.

**Where it bites.** A 40,000-device baseline sweep at ~100 apps a device writes about
**360 MB** of ledger, once. After that a section row is written only when a device's app
*set* changes, and it carries that device's whole list — so one new application on one
Mac costs ~9 KB, not ~90 bytes. At 40,000 devices with 5% of the fleet changing on a
given day that is roughly 18 MB a day, **6.6 GB a year** — arithmetic on the measured
constant, not an observation.

**Workaround.** Capacity planning, and only that. There is deliberately no purge
command here: unlike the change log, the ledger is the truth the change log is derived
from, and a hand-written `DELETE` that orphans a span's section digests leaves the
diffing engine comparing against evidence that is no longer there. Size the volume,
watch it (§3), and if you need bounded ledger retention, open an issue — the shape of a
safe pruner is a design question, not a `DELETE`.

## 3. A full database volume takes the instance down, and says so only in the database's log

**The limit.** Nothing in the product watches free space on the database volume.

**Measured.** Filling the volume under a running Postgres 17.11:

```
PANIC:  could not write to file "pg_wal/xlogtemp.89": No space left on device
server closed the connection unexpectedly
```

The server restarts, recovers, and then refuses every connection — while the container
still reports `Up`:

```
$ df -h /var/lib/postgresql/data
tmpfs   96.0M   95.9M   52.0K  100%

$ psql -U looninspect -d looninspect
psql: error: … FATAL:  could not write init file: No space left on device
```

The application does the right thing in front of that — `/api/health` returns 503 and
the container goes `unhealthy` (§4) — but nothing anywhere names *disk* as the cause.
That sentence exists only in `docker compose logs db`.

**Where it bites.** Whenever §1 + §2 + WAL exceed the volume. At the rates above a
40,000-device instance adds about 22 GB a year, so a 100 GB volume lasts under five —
and far less than that if it was sized against the 360 MB baseline sweep.

**Workaround.** Monitor free space on `<project>_looninspect-db` as a first-class alert,
at 80%, from outside the product. Keep a ballast file in the data directory so there is
something to delete when you are already wedged — verified to work:

```
$ rm /var/lib/postgresql/data/BALLAST
tmpfs   96.0M   72.0M   24.0M  75%
$ psql … -tAc "SELECT 'connections work again'"
connections work again
```

**Footprint to size against.** A fresh install after migrations is **48.6 MB** of data
directory (17 MB of it pre-allocated WAL); `pg_database_size('looninspect')` is 10.6 MB
of that. Initdb plus every migration then on `main` completed on a 64 MB filesystem with 13.7 MB to
spare — so 64 MB installs and nothing more.

## 4. Docker never restarts the container for failing its healthcheck

**The limit.** `/api/health` genuinely depends on the database (it opens a pooled
connection and runs `SELECT 1`), the `HEALTHCHECK` calls it every 30s, and three
failures flip the container to `unhealthy`. Nothing acts on that. `restart:
unless-stopped` reacts to the *process* exiting, and a process serving 503s has not
exited.

**Measured**, with the database container stopped:

```
{"status":"unavailable","reason":"database"}   HTTP 503

2026-09-01 10:42:49 exit=0
2026-09-01 10:43:19 exit=1
2026-09-01 10:43:49 exit=1
2026-09-01 10:44:20 exit=1

loonrb-app-1 :: Up 5 minutes (unhealthy)
```

**Where it bites.** Any single-host compose deployment — which is every deployment this
repository ships for. Under ECS or Kubernetes the orchestrator replaces the task and
this does not apply.

**Workaround.** Alert on `GET /api/health` returning 503 from your own monitoring, not
on container status. It needs no credentials and leaks nothing: the body names the
failure class and nothing else, deliberately.

## 5. A wrong `ENCRYPTION_KEY` is not detected until something reads a credential

**The limit.** Startup validates that `ENCRYPTION_KEY` is a well-formed Fernet key. It
does not — and cannot cheaply — check that it is *this database's* key.

**Measured**, restoring a database beside a valid but different key:

```
loonrb2-app-1 :: Up 6 seconds (healthy)
{"status":"ok"}  <- HTTP 200
login HTTP 200
GET /api/mdm/connections -> Internal Server Error   HTTP 500
log: Failed to decrypt stored value — ENCRYPTION_KEY may have changed
```

Healthy, signed in, and every MDM connection and destination permanently unreadable —
because account passwords are Argon2id hashes, which survive a lost key, while
credentials are Fernet ciphertext, which does not.

**Where it bites.** Every restore, at every fleet size. It is the single most likely way
to lose a LoonInspect instance: back up the database, not the key.

**Workaround.** Back up `.env` with the dump, in your secret store rather than beside
it, and verify the pair with the one-liner in
[docs/operations.md §1](docs/operations.md). There is no key rotation yet, so the key
generated at install is the key that database needs for its whole life.

## 6. The downgrade path is manual, order-dependent, and undocumented in the product

**The limit.** Every migration carries a real `downgrade()`, and nothing ever calls one:
`init_db()` only runs `upgrade head`. A rollback therefore has to be issued by hand
**while the newer image is still running**, because the older image does not contain the
scripts that undo the newer revisions. Swap the image back first — the obvious order —
and it crash-loops: Alembic finds a `version_num` no script in the image knows and
refuses to plan.

**Measured:**

```
loonrb2-app-1 :: Restarting (3) 4 seconds ago
Can't locate revision identified by 'aaaa0000ffff'
```

That phrase is 11,431 characters into a single-line JSON log entry, which is the actual
difficulty — the failure is loud and completely undiagnosable at a glance.

**Where it bites.** Any rollback attempted by reverting the checkout without first
reverting the data.

**Workaround.** Take the dump *before* the upgrade; roll back by running
`alembic downgrade` from the newer image and *then* swapping it, or by restoring the
dump. Full procedure — including the grep that finds the phrase in that log line, and
why `UPDATE alembic_version` is the wrong answer — in
[docs/operations.md §5](docs/operations.md).

*An interrupted upgrade is **not** in this list, and was tested rather than assumed:
Alembic runs the whole upgrade in one transaction and Postgres has transactional DDL, so
killing a migration mid-flight leaves zero tables and no `alembic_version`, and the
container's own restart completes it. Transcript in docs/operations.md §4.*

---

## Checked, and not an issue

Recorded because "we looked" is worth more on an inspection day than silence, and
because each of these was believed to be a defect at some point in this repository's
history.

- **The application does not report healthy while its database is unreachable.** It did
  once; `/api/health` now opens a real pooled connection with a 3-second bound and
  returns 503 with `{"status":"unavailable","reason":"database"}`. Verified by stopping
  the database container. What is still true is §4 — nothing restarts it.
- **Ownership and row-level security survive a `pg_dump`/`psql` round trip.** After a
  restore into a fresh volume, all 34 tables are owned by `looninspect_app`, 30 carry
  RLS both enabled and `FORCE`d, and 30 policies are present — the same counts as
  before the dump.
- **`pg_dump` does not leak credentials.** MDM credentials, webhook secrets, license
  keys and destination auth secrets appear in a dump as Fernet tokens. Verified by
  planting known strings through the API and grepping the dump for them: zero matches,
  and pinned against future columns by `backend/tests/test_backup_secrecy_db.py`.
- **`POSTGRES_APP_PASSWORD` is not part of a `pg_dump` restore.** A dump carries no role
  passwords and a fresh volume re-runs `initdb` from the current `.env`, so a restore
  into a stack with a *different* app password works. Verified. `ENCRYPTION_KEY` is the
  one whose loss is unrecoverable (§5).
