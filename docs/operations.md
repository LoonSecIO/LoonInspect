# Operating a LoonInspect instance

Backup, restore, upgrade, rollback. Every command here was run against a throwaway
compose stack before it was written down, and the outputs quoted are that run's, not a
reconstruction. Where something was reasoned about rather than executed, it says so.

Two cosmetic differences between the commands and the transcripts, so nothing here reads
as more literal than it is: those stacks were `docker compose -p loonrb` / `-p loonrb2`,
so container names in the output say `loonrb-app-1` where yours will say
`looninspect-app-1`; and they published 8055 and 8056 rather than 8001, because a stack
was already on 8001. Nothing else was changed.

Known limits — the sizes, the growth rates and the failure modes — are in
[KNOWN_ISSUES.md](../KNOWN_ISSUES.md).

**Names.** Compose derives the project name from the checkout directory, so a clone into
`LoonInspect/` gives containers `looninspect-app-1` and `looninspect-db-1` and volumes
`looninspect_looninspect-db` and `looninspect_looninspect-data`. `docker compose ps` and
`docker volume ls` show yours. Every command below is written as `docker compose …` run
from the checkout, which needs no name at all; the `docker` forms are for when there is
no checkout to stand in.

---

## 1. What has to be backed up

Two things, and one of them is not the database.

| | Where it lives | Lose it and… |
| --- | --- | --- |
| The database | volume `<project>_looninspect-db` | everything: devices, the observation ledger, the change log, accounts, connections |
| `ENCRYPTION_KEY` | `.env` on the host | the database restores, the app starts, sign-in works, and every MDM connection and destination in it is permanently unreadable |

**`POSTGRES_PASSWORD` and `POSTGRES_APP_PASSWORD` are *not* on that list**, and it is
worth saying so because the intuition is that they are. A `pg_dump` carries no role
passwords, and a restore into a fresh volume re-runs `initdb`, which creates
`looninspect_app` from whatever `.env` says *now* — the same `.env` the app builds its
`DATABASE_URL` from. Verified by restoring the same dump into a stack whose
`POSTGRES_APP_PASSWORD` had been changed to something the original database never saw:

```
restore exit: 0
loonrb3-app-1 :: Up 6 seconds (healthy)
{"status":"ok"}  <- HTTP 200
login HTTP 200
```

They *do* matter for the volume-level copy in §2, where the role and its password live
inside the copied data directory. Keep them anyway; the point is only that
`ENCRYPTION_KEY` is the one whose loss is unrecoverable.

The data volume `<project>_looninspect-data` holds the audit log and, under
`TLS_MODE=self-signed`, a generated certificate. Both are reconstructible — the
certificate regenerates on first boot, the audit log does not, so back it up if your
retention policy is what makes the audit log worth having.

### ENCRYPTION_KEY is not optional, and a dump without it is not a backup

`credentials_encrypted`, `webhook_secret_encrypted`,
`loonsecio_license_key_encrypted` and `destinations.auth_secret_encrypted` are Fernet
tokens (`app/core/crypto.py`). `pg_dump` copies the token, not the secret:

```
### the plaintext client secret is NOT in the dump
not found (0 matches for OPSRB-PLAINTEXT-CANARY-9f3a)
not found (0 matches for OPSRB-WEBHOOK-CANARY-51cc)

### what IS in the dump, in the credentials column
COPY public.mdm_connections (id, tenant_id, name, provider, base_url, is_active, credentials_encrypted, …
1  00000000-…-0002  Runbook Test Jamf  jamf  https://jamf.example.com  t  gAAAAABqlqzItdjckcvfmutOBiaE5kBD…
```

That property is pinned by a test rather than by this paragraph:
`backend/tests/test_backup_secrecy_db.py` reads the row back through raw SQL — the path
the ORM's type decorator never touches, and the same bytes `pg_dump` serialises — and
fails if any secret appears in the clear in any column. A future credential column
declared `String` instead of `EncryptedString` fails it on the day it is added.

That is the property you want at rest and the trap you want to know about before a
restore. Account passwords are Argon2id **hashes**, not ciphertext, so sign-in survives
a lost key while every credential does not — which is why a wrong key produces an
instance that looks healthy and is not. Restored beside a valid-but-different key:

```
### it starts, and reports healthy
loonrb2-app-1 :: Up 6 seconds (healthy)
{"status":"ok"}  <- HTTP 200

### and sign-in still works — passwords are hashed, not encrypted
login HTTP 200

### but every connection is unreadable
Internal Server Error  <- HTTP 500

### what the log says
Failed to decrypt stored value — ENCRYPTION_KEY may have changed
```

**Check that the key in `.env` opens this database before you need it**, not after — a
dump is a serialisation of exactly these bytes, so a key that reads the live column
reads the dump. This answers the question without *printing* the secret, deliberately: a
Jamf client secret in shell history is a worse outcome than the uncertainty it resolves.

```bash
docker compose exec -T db psql -U looninspect -d looninspect -tAc \
  "SELECT credentials_encrypted FROM mdm_connections ORDER BY id LIMIT 1" \
| docker compose exec -T app uv run --frozen --no-sync --no-dev python -c 'import os,sys
from cryptography.fernet import Fernet, InvalidToken
t = sys.stdin.read().strip()
try:
    Fernet(os.environ["ENCRYPTION_KEY"].encode()).decrypt(t.encode())
except (InvalidToken, ValueError):
    sys.exit("ENCRYPTION_KEY does NOT match this database")
print("ENCRYPTION_KEY matches this database")'
```

```
### the documented one-liner, verbatim
ENCRYPTION_KEY matches this database

### and with a key that is valid Fernet but not this database's
ENCRYPTION_KEY does NOT match this database
(exit status 1)
```

**Rejected:** the same script fed in as a `python - <<'PY'` heredoc, which reads much
better and does not work — the heredoc *is* stdin, so `sys.stdin.read()` returns the
empty string and the check reports "nothing to check" whatever the key is. It was
written that way first and caught by running it. `python -c` keeps stdin for the token.

Store the key where you store other break-glass secrets. **Not in git** — `.gitignore`
excludes `.env` for this reason, and a key committed once is a key in every clone's
history for ever. There is no key rotation yet (`app/core/crypto.py` says so in as many
words), so the key you generate at install is the key that database needs for its whole
life.

---

## 2. Backup

```bash
umask 077
docker compose exec -T db pg_dump -U looninspect -d looninspect \
  | gzip > "looninspect-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
```

Real output, against a stack with one connection and one admin:

```
### $ docker compose ps
NAME           SERVICE   STATUS
loonrb-app-1   app       Up 6 minutes (healthy)
loonrb-db-1    db        Up About a minute (healthy)

### $ umask 077; docker compose exec -T db pg_dump ... | gzip > backup.sql.gz
-rw-------@ 1 kylepazandak  wheel  12081 Sep  1 05:46 opsrb-backup.sql.gz

### file mode of the dump (umask 077 -> owner-only)
-rw------- opsrb-backup.sql.gz

### $ gunzip -c backup.sql.gz | grep -c ""   (lines)
    3891
```

And because a backup that failed is worse than no backup, put the pipeline's exit status
where it will be noticed — `gzip` exits 0 on a truncated input, so `$?` alone reports
success:

```bash
set -o pipefail   # bash/zsh; without it, only gzip's status reaches $?
```

```
with pipefail, a failed pg_dump gives exit=1
without it, exit=0
```

Four things about that command line, three of them load-bearing:

- **`umask 077` first.** The dump contains every device record, every account row and
  every audit trail in the instance. A default umask writes it world-readable; on a
  shared host that is the whole database handed to any local account. This is the one
  place in this document where a step exists purely to avoid making the operator's
  posture worse.
- **`-T`.** Without it compose allocates a TTY and mangles the dump. The failure is not
  loud — you get a file, and it is subtly wrong.
- **As `looninspect`, the bootstrap superuser, not `looninspect_app`.** The app role is
  deliberately `NOBYPASSRLS` and owns tables that are `FORCE ROW LEVEL SECURITY` (see
  `ops/postgres/initdb/10-app-role.sh`), so it cannot read a whole table without a
  tenant bound. This was written expecting a *silent* partial dump and the run said
  otherwise, which is the better answer: it fails, loudly, at the first RLS table, and
  `--enable-row-security` does not rescue it either.

  ```
  $ pg_dump -U looninspect_app -d looninspect > dump.sql
  exit=1
  pg_dump: error: query failed: ERROR:  query would be affected by row-level
    security policy for table "account_roles"

  $ pg_dump --enable-row-security -U looninspect_app -d looninspect > dump.sql
  exit=1
  pg_dump: error: query failed: ERROR:  unrecognized configuration parameter
    "looninspect.tenant_id"
  ```

  Check the exit status anyway. The truncated file is still 1,437 lines of schema with
  no data in it, and it is only the exit code and stderr that say so.
- **No `--no-owner`.** The schema is owned by `looninspect_app`, and that ownership is
  what the RLS story rests on: `10-app-role.sh` gives it `public`, so Alembic's tables
  are its tables, which is why every policy in the baseline migration is paired with
  `FORCE ROW LEVEL SECURITY`. Restore a `--no-owner` dump as the superuser and the
  tables end up owned by a superuser with the app role holding no grants at all.
  **Rejected** for that reason; §3 verifies the ownership actually survives.

Verify the dump is readable rather than assuming it:

```bash
gunzip -t looninspect-*.sql.gz && echo "gzip stream intact"
```

That checks the compression, not the SQL. The only test of a backup is a restore, which
is §3 — run it once against a throwaway project (`docker compose -p looninspect-drill …`)
and you will know, before you need to know.

### Backing up the volume instead

Copying `<project>_looninspect-db` while Postgres is running produces a torn copy that
may or may not replay. If you want a file-level backup, stop the stack first:

```bash
docker compose stop
docker run --rm -v looninspect_looninspect-db:/data:ro -v "$PWD:/out" alpine \
  tar czf /out/looninspect-db-volume.tgz -C /data .
docker compose start
```

```
### the volume-level backup, verbatim (stack stopped first)
-rw-r--r--  1 kylepazandak  wheel  7241596 Sep  1 05:56 opsrb-db-volume.tgz
loonrb2-app-1 :: Up 6 seconds (healthy)
```

Substitute your own volume name. `pg_dump` on a running stack is the better answer
almost always: it needs no downtime, it is portable across Postgres versions, and — the
reason it is what §3 restores — a physical copy is only replayable by the *same* major
Postgres version, so a tarball is worth nothing the day the base image moves from 17 to
18. **Not tested here:** untarring one back over a volume. Treat it as the fallback it
is, and note that the archive is written with the default umask; `chmod 600` it, or
prefer §2.

---

## 3. Restore

Into a **fresh** database volume, so `initdb` runs and recreates `looninspect_app` from
`POSTGRES_APP_PASSWORD` before anything is loaded. The `.env` must carry the same
`ENCRYPTION_KEY` (§1); the two database passwords may be whatever that `.env` says,
since both the role and the app's `DATABASE_URL` come from it.

```bash
docker compose down                                    # not -v yet
docker volume rm looninspect_looninspect-db            # the point of no return
docker compose up -d db
gunzip -c looninspect-20260901T104600Z.sql.gz \
  | docker compose exec -T db psql -U looninspect -d looninspect -v ON_ERROR_STOP=1
docker compose up -d app
```

`-v ON_ERROR_STOP=1` because psql's default is to print an error, carry on, and exit 0 —
a restore that skipped half the schema and reported success:

```
without ON_ERROR_STOP exit=0
with ON_ERROR_STOP exit=3
```

Real output:

```
### $ docker compose up -d db     (fresh volume: initdb creates looninspect_app)
### $ docker compose logs db | grep "created application role"
db-1  | created application role looninspect_app (nosuperuser, owns schema public)

### $ gunzip -c backup.sql.gz | docker compose exec -T db psql -v ON_ERROR_STOP=1 ...
psql exit status: 0

### ownership and RLS survived the round trip
     tablename     |   tableowner    | rowsecurity
-------------------+-----------------+-------------
 accounts          | looninspect_app | t
 devices           | looninspect_app | t
 mdm_connections   | looninspect_app | t
 observation_spans | looninspect_app | t

 rls_on | rls_forced | tables
--------+------------+--------
     30 |         30 |     34

 policies
----------
       30

 version_num
--------------
 d5b1e7c4a930

### $ docker compose up -d app   (same .env, same ENCRYPTION_KEY)
loonrb2-app-1 :: Up 6 seconds (healthy)

### the restored instance answers, and the restored admin can sign in
{"status":"ok"}  <- HTTP 200
login HTTP 200
```

Check those numbers after every restore. Thirty tables with RLS **on and forced**,
thirty policies, and all 34 tables owned by `looninspect_app`: tenant isolation is a
property of the restored database, not of the application, so a restore that lost it is
a restore that lost tenant isolation while looking completely normal.

```bash
docker compose exec -T db psql -U looninspect -d looninspect -c \
  "SELECT count(*) FILTER (WHERE relrowsecurity) AS rls_on,
          count(*) FILTER (WHERE relforcerowsecurity) AS rls_forced,
          count(*) AS tables
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r';"

docker compose exec -T db psql -U looninspect -d looninspect -c \
  "SELECT tableowner, count(*) FROM pg_tables WHERE schemaname='public' GROUP BY 1;"
```

```
   tableowner    | count
-----------------+-------
 looninspect_app |    34
```

More than one row there — anything owned by `looninspect` — is a restore to redo rather
than one to patch. `looninspect_app` would hold no privileges on those tables at all,
and re-granting by hand is how a schema ends up with a permission set nobody can
reproduce.

### What the restore does to work that was in flight

**The outbox.** `outbox_deliveries` rows restore with the status the dump captured.
Anything `pending` is retried on the next 30-second tick and delivered again; anything
already `delivered` is not. So a dump taken before a delivery landed **re-sends that
event** — deliberately, because the alternative is losing it. Events LoonInspect produced
*after* the dump was taken are gone from the outbox entirely; they are not lost from the
product, because `device_changes` is derived from the observation ledger and the ledger
is rewound too, so the next sweep diffs live Jamf state against the restored spans and
re-derives the gap as changes at their new observation time. Plan for duplicates in the
SIEM around the restore point and dedup on the correlation key the events already carry
(serial + Jamf URL + Jamf id). *Reasoned from `app/core/outbox.py` and the `DeviceChange`
docstring; not exercised against a live Jamf here.*

**The run mutex.** The `runs` row *is* the lock (`docs/runs.md` §1), so a dump taken
mid-sweep restores a row with `status = 'running'` that no process is performing, and
the partial unique index `uq_run_active_lock` blocks that connection's next sweep. It
clears itself: `_reclaim_stale` runs on every acquisition and fails any running row whose
heartbeat is older than `run_stale_after_seconds` (300s), which a restored row always is.
The reclaim writes a final run-log line and a `run.failed` event, so you will see one
failed run per interrupted connection after a restore. That is correct, not a fault.
**Do not** `DELETE FROM runs` to clear it — the row is the history of that sweep, and the
reclaim is what tells your SIEM the sweep never finished.

---

## 4. Upgrade

Migrations run unattended, in-process, at startup: `init_db()` waits for the database
and then runs `alembic upgrade head` (`app/core/database.py`). There is no separate
migration step to run and no flag to skip it — starting a newer image against an older
database *is* the migration.

```bash
docker compose exec -T db pg_dump -U looninspect -d looninspect \
  | gzip > "looninspect-preupgrade-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"   # §2
git pull
GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build
docker compose logs -f app
```

The backup is the first line because the downgrade path is manual and has to be walked
*before* the old image goes back, not after — §5.

Before and after, the two revisions worth knowing:

```bash
# what the database is at
docker compose exec -T db psql -U looninspect -d looninspect -tAc \
  "SELECT version_num FROM alembic_version"
# what the image expects
docker compose exec -T app uv run --frozen --no-sync --no-dev alembic heads
```

```
d5b1e7c4a930
d5b1e7c4a930 (head)
```

Equal means there is nothing to migrate. Database behind image means the next start
migrates. Database *ahead* of image is §5.

### An interrupted migration is safe

This was worth testing rather than trusting. Alembic wraps the whole `upgrade head` in
one transaction (`migrations/env.py` → `context.begin_transaction()`), Postgres has
transactional DDL, and the two together mean a migration that is killed part-way leaves
nothing behind. Killing the migration's own backend mid-flight on an empty database:

```
### $ alembic upgrade head, with its backend terminated as soon as it connects
sqlalchemy.exc.DBAPIError: … connection was closed in the middle of operation

### state of the database after the interruption
 tables_in_public
------------------
                0
 alembic_version_table
-----------------------
        (null)

### $ alembic upgrade head   (what the container retries on restart)
INFO  [alembic.runtime.migration] Running upgrade c1a6f83b7e42 -> e7c2a9b4f1d6, …
INFO  [alembic.runtime.migration] Running upgrade b4d17e9c3a25 -> d5b1e7c4a930, …

### and the schema is complete
 tables_in_public |  version_num
------------------+--------------
               34 | d5b1e7c4a930
```

Zero tables, no `alembic_version`, and the container's own restart finishes the job.
`restart: unless-stopped` therefore recovers an upgrade interrupted by a power cut, an
OOM kill, or `docker kill` without an operator touching anything. **Do not** reach for
`alembic stamp` after an interrupted upgrade: the database is either fully migrated or
fully not, and stamping tells it a lie about which.

The one caveat this does not cover is a migration that is itself non-transactional —
`CREATE INDEX CONCURRENTLY`, or anything that commits mid-`upgrade()`. None of the
migrations in `backend/migrations/versions/` does that today. A future one that does
is a migration that has to say so in its own docstring.

---

## 5. Rollback

### Do it before you swap the image back

Every migration has a real `downgrade()` — this project takes them
seriously enough to argue with itself in their comments about what a downgrade can
honestly restore. What does not exist is anything that *calls* them: `init_db()` only
ever runs `upgrade head`. So a downgrade is a manual step, and the order matters
absolutely, because **only the newer image contains the scripts that know how to undo
the newer revisions.**

With the newer image still in place:

```bash
# what the database is at, and what it would land on
docker compose exec -T db psql -U looninspect -d looninspect -tAc \
  "SELECT version_num FROM alembic_version"
docker compose run --rm --no-deps app \
  uv run --frozen --no-sync --no-dev alembic downgrade -1
```

```
INFO  [alembic.runtime.migration] Running downgrade d5b1e7c4a930 -> b4d17e9c3a25, community data sharing defaults to off: …
b4d17e9c3a25
```

Then, and only then, put the older checkout back and `docker compose up -d --build`.
Going the other way is fine and is the same command:

```
INFO  [alembic.runtime.migration] Running upgrade b4d17e9c3a25 -> d5b1e7c4a930, …
d5b1e7c4a930
```

`--no-deps` because the app service is the one being replaced and its `depends_on` would
otherwise restart the running one; `run --rm` because this is a one-off container that
should not survive the command. Read the `downgrade()` you are about to run first — a
downgrade restores the *schema*, not the data the upgrade transformed, and several here
say so explicitly.

### If you swap the image back first, it crash-loops

This is the failure that costs an evening: an image *older*
than the database it boots against — `docker compose up -d` after a `git checkout` of
the previous tag, with the volume untouched. Alembic finds a `version_num` no script in
the image knows about, refuses to plan, and startup fails; `restart: unless-stopped`
then does it again, for ever:

```
### $ docker compose ps
loonrb2-app-1 :: Restarting (3) 4 seconds ago
```

The diagnosis is one phrase inside an **11,431-character** single-line JSON log entry —
by a wide margin the longest line in that container's log, and unreadable as it scrolls
past — which is why it is worth grepping for rather than reading:

```bash
docker compose logs app | grep -o "Can't locate revision identified by '[a-f0-9]*'" | tail -1
```

```
Can't locate revision identified by 'aaaa0000ffff'
```

**Recovery, in preference order:**

1. **Go forward.** Put the newer image back (`git checkout` the newer ref,
   `docker compose up -d --build`). The revision it is missing is the revision it has.
   The container recovers on its own next restart attempt — nothing else to do:

   ```
   loonrb2-app-1 :: Up 8 seconds (healthy)
   {"status":"ok"}  <- HTTP 200
   ```

2. **Go forward, downgrade properly, then go back** — the top of this section. The
   older image cannot undo revisions it does not carry, so the newer one has to be
   running when the `downgrade` is issued.

3. **Restore the pre-upgrade dump** (§3) beside the older image. This is why §4 takes a
   backup first. You lose everything written since the dump; the ledger re-derives the
   gap on the next sweep, so what you actually lose is the change log for that window.

4. There is no fourth option. **Rejected:** `UPDATE alembic_version SET version_num =`
   the older revision. It makes the crash loop stop, which is the entire problem — the
   columns and tables the newer migrations added are still there, the older code does
   not know about them, and the next upgrade replays migrations against a schema that
   already has their objects. It converts a loud, fully recoverable failure into a
   quiet, permanently wrong database. (It is used in this document's own test only to
   *cause* the fault, on a throwaway stack, and to hand it back afterwards.)

### The one-time volume-ownership fix

Upgrading from a version before the container ran as uid 10001 needs a `chown` on the
data volume; that note is in the README's "Upgrading an existing install" and still
applies once, to volumes created by those versions.

---

## 6. Health, and what the container does about it

`/api/health` opens a real connection through the application's own pool and runs
`SELECT 1`, bounded at 3 seconds (`app/api/routes.py`). It is unauthenticated, and it
answers with the failure *class* only — no DSN, no host, no driver text.

```
$ curl -s -i http://localhost:8001/api/health          # database up
HTTP/1.1 200 OK
{"status":"ok"}

$ curl -s -o - -w 'HTTP %{http_code}\n' …/api/health   # database stopped
{"status":"unavailable","reason":"database"}
HTTP 503
```

The container `HEALTHCHECK` calls the same endpoint every 30s and flips after three
failures. The probe history is the fastest way to see when it started:

```bash
docker inspect --format '{{range .State.Health.Log}}{{.End}} exit={{.ExitCode}}
{{end}}' looninspect-app-1 | tail -6
```

```
2026-09-01 10:42:49 exit=0
2026-09-01 10:43:19 exit=1
2026-09-01 10:43:49 exit=1
2026-09-01 10:44:20 exit=1

loonrb-app-1 :: Up 5 minutes (unhealthy)
```

Note the "Up". **Docker never restarts a container for failing its healthcheck** —
`restart:` reacts to the process exiting, and this process does not exit. Point your
monitoring at `/api/health` and alert on the 503; the container status alone will sit
there unhealthy and running indefinitely. See
[KNOWN_ISSUES.md §4](../KNOWN_ISSUES.md).
