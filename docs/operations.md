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

Since #480 the stored value begins with a key id — `k1:` and then the token, where the
capture above predates the prefix — so a later rekey can tell which key wrote a row by
reading the row, not a side table. What you back up does not change: the dump still
carries ciphertext and not the secret, and losing `ENCRYPTION_KEY` still costs you every
credential in it. `k1` is the only key id this build knows; values written before the
prefix existed are read as `k1`, with no migration and no backfill.

Two things it does change, and both matter to a runbook. The break-glass check below
takes the token out of the envelope before it tries the key — a `k1:…` value handed to
Fernet whole is refused, and the check would report a wrong key for the right one. And
**an image older than #480 cannot read a row this build wrote**: it hands the whole
string to Fernet, gets the same refusal, and answers with the wrong-key sentence on an
instance whose key is fine. That is a rollback hazard, and it is spelled out in §5.

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
HTTP 503  {"detail": "Stored credentials cannot be read: the ENCRYPTION_KEY in the
environment is not the one this database was written under. Restore the original key
(docs/operations.md §1), or re-enter each connection's and destination's secret
(KNOWN_ISSUES.md §5)."}

### what the log says (once, with no traceback — #374)
Stored credentials cannot be read: the ENCRYPTION_KEY in the environment is not the one
this database was written under. …
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
# The column is a key id and then the token since #480, and the token alone before it. A
# Fernet token is urlsafe base64 and carries no colon, so the tail is the token either way.
key_id, _, t = sys.stdin.read().strip().rpartition(":")
if key_id not in ("", "k1"):
    sys.exit("this row was written under key id " + key_id[:16] + ", which this build does not know: the image is older than the database (docs/troubleshooting.md section 4)")
try:
    Fernet(os.environ["ENCRYPTION_KEY"].encode()).decrypt(t.encode())
except (InvalidToken, ValueError):
    sys.exit("ENCRYPTION_KEY does NOT match this database")
print("ENCRYPTION_KEY matches this database")'
```

The check reads one row (`ORDER BY id LIMIT 1`), which is the whole database's answer
while there is one key: every row is under `k1`, prefixed or not. The key-id branch is
what keeps that true if it ever stops being — a row from a newer build is reported as
what it is, rather than as a key that does not match.

```
### the documented one-liner, verbatim, against a row this build wrote (k1:gAAAAAB…)
ENCRYPTION_KEY matches this database

### the same, against a row written before the prefix existed (gAAAAAB…)
ENCRYPTION_KEY matches this database

### and with a key that is valid Fernet but not this database's
ENCRYPTION_KEY does NOT match this database
(exit status 1)

### a row carrying a key id this build does not know
this row was written under key id k2, which this build does not know: the image is older than the database (docs/troubleshooting.md section 4)
(exit status 1)
```

**Rejected:** the same script fed in as a `python - <<'PY'` heredoc, which reads much
better and does not work — the heredoc *is* stdin, so `sys.stdin.read()` returns the
empty string and the check reports "nothing to check" whatever the key is. It was
written that way first and caught by running it. `python -c` keeps stdin for the token.

**Also caught by running it:** the version of this check written before #480 read the
whole column as the token, so against a `k1:` row it printed *ENCRYPTION_KEY does NOT
match this database* for the key that was right — a break-glass check answering the exact
opposite of the truth. `backend/tests/test_crypto.py` now pulls this snippet out of this
document and runs it, against a value the type decorator wrote and against an unprefixed
one, so the two cannot drift apart again.

Store the key where you store other break-glass secrets. **Not in git** — `.gitignore`
excludes `.env` for this reason, and a key committed once is a key in every clone's
history for ever. There is no key rotation yet — the envelope names the key that wrote a
row, which is what makes a rekey possible later, but this build has one key and no way to
change it (`app/core/crypto.py` says both in as many words) — so the key you generate at
install is the key that database needs for its whole life.

---

## 2. Backup

```bash
(umask 077 && docker compose exec -T db pg_dump -U looninspect -d looninspect \
  | gzip > "looninspect-$(date -u +%Y%m%dT%H%M%SZ).sql.gz")
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

- **`umask 077` first, inside the parentheses.** The dump contains every device record,
  every account row and every audit trail in the instance. A default umask writes it
  world-readable; on a shared host that is the whole database handed to any local account.
  This is the one place in this document where a step exists purely to avoid making the
  operator's posture worse. The parentheses end the umask with the dump: left in force in
  the shell, it makes every file a later `git pull` or `git checkout` writes owner-only,
  and the image build copies those modes in as root's, where the app — uid 10001 — gets
  `Permission denied` reading them (checked 2026-09-13 against the shipped image).
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
(umask 077 && docker compose exec -T db pg_dump -U looninspect -d looninspect \
  | gzip > "looninspect-preupgrade-$(date -u +%Y%m%dT%H%M%SZ).sql.gz")   # §2
git pull
GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build
docker compose logs -f app
```

The backup is the first line because the downgrade path is manual and has to be walked
*before* the old image goes back, not after — §5.

`git pull` upgrades to `main`, which is staging. To install a release instead, put
`git fetch --tags && git checkout <tag>` in its place: that is the line Settings › Support ›
**Updates** prints, with the latest release's tag filled in, since #407 made the update
notice about releases rather than about `main`.

**Read the release's upgrade notes before you take it.** Publishing a release appends them to
its page (the tag under Settings › Support › **Updates** › *Latest release* links there): the
migrations the update runs at first start and, under *Before you update*, each one that
needs a maintenance window or free disk. From `v1.0.0` that includes `e621c4a8b903`, which
rebuilds the installed-apps index while the instance answers nothing
([`troubleshooting.md`](troubleshooting.md) §4 step 2 says what to expect).

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

From `v2.0.0` on, a release's migrations leave the schema readable by the release before it
([`BRANCHING.md`](BRANCHING.md#11-release-planning-milestones-labels-and-tags) §1.1), but an
older image still crash-loops against a newer database (below): this section is the way back.

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

### A downgrade does not un-write what the newer image wrote

The schema is not the only thing a newer build leaves behind, and one case has a sentence
that will send you the wrong way. Since #480 every credential this build writes carries a
key id — `k1:` and then the Fernet token (§1). An image older than that change hands the
whole string to Fernet, which refuses it. So after a rollback past it, a credential
written while the newer image ran answers **503** with *Stored credentials cannot be
read: the `ENCRYPTION_KEY` in the environment is not the one this database was written
under…* — on an instance whose key is fine. `alembic downgrade` does not touch those
rows. Nothing does: a row is restamped only when something writes it, so rows written
before the upgrade are unaffected.

**Measured**, running the image from before that change against a database whose one
connection this build wrote, with the right `ENCRYPTION_KEY` in the environment. The
request below is `GET /api/mdm/connections`; destinations, the AI key and the licence key
are the same column type through the same seam, so they answer the same way — that part
is reasoned, not run:

```
### the older image (pre-#480), same volume, same key
loon480old :: Up 7 seconds (healthy)
{"status":"ok"}  <- HTTP 200
login HTTP 200

### and the connection it cannot read
HTTP 503  {"detail": "Stored credentials cannot be read: the ENCRYPTION_KEY in the
environment is not the one this database was written under. …"}

### the same row, same key, read by the image that wrote it
read back: Runbook Test Jamf | {"clientId": "rb-client", "clientSecret" …
```

**The key is not the problem, so do not re-enter any secret.** That sentence's own
step-through ends in deleting each connection and destination and creating it again
([`troubleshooting.md`](troubleshooting.md) §4 step 3), which here is the wrong move — it
discards credentials that are perfectly readable, under a key that was never wrong. **Go
forward** (recovery 1 below) and they read again; or restore the pre-upgrade dump beside
the older image (recovery 3), which has no `k1:` rows in it. The newer build reads both
spellings, which is why this hazard runs one way only.

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

---

## 7. More than one app process

Reasoned about and tested, not transcribed: the shipped stack is one app container, and
what follows was exercised as two ticks against one database
(`backend/tests/test_outbox_tick_lock_db.py`), never as two containers.

`app/serve.py` runs one uvicorn process and passes no `--workers`, so a second process
means a second container against the same database. **`SCHEDULER_ENABLED`** (default
`true`) is the decision to make before you start one, and each container says which way
it was answered on its `starting` line — `docker compose logs app | grep scheduler_enabled`.

`SCHEDULER_ENABLED=false` makes a process **web-only**. It still serves the UI and the
API, and the work a person starts still runs in the process that served the request:
Sync now, Run now, Re-emit inventory, a destination's **Test** button, **Redrive**, and
**Send now** on Settings › Data sharing. What it stops is everything on a clock — the
eight jobs in `app/main.py`: collections coming due, the outbox's fan-out and delivery,
the purges (sessions hourly, the outbox and the run log nightly), the hourly Jamf Patch
catalog sync, the sign-in cache renewals, the daily data-sharing exchange. So what a
web-only process *queues* — a re-emit's events, a redriven dead letter — is delivered by
the process that still has the scheduler, not by it; with no such process running, the
queue simply grows.

**Leaving it `true` everywhere is safe for the outbox, and only for the outbox.** Each
tenant's outbox tick takes a per-tenant advisory lock for the length of the tick, and a
process that cannot take it delivers nothing and says so, every tick:

```
outbox tick skipped: another process holds this tenant's outbox lock; that process is
fanning out and delivering this tenant's events, this tick did nothing, …
```

That line is the design and not a fault: one process delivers an organization's events at
a time, and the others name which of your containers is doing it. The lock lives on that
process's own database connection, so Postgres drops it when the process does — a worker
killed mid-tick leaves nothing to clean up and the next tick takes it. Delivery stays
at-least-once, as it is with one process.

The other timed loops are outside that promise. Collections claim their work with a run
row and are safe by the same argument
([`ingest-scheduling.md`](ingest-scheduling.md) §5); the rest have not been audited for a
second process. One process with the scheduler on is still the supported shape.

---

## 8. A PostgreSQL you run (`DATABASE_MODE=external`)

Everything above assumes the bundled `db` service. This is what changes when the database
is yours (#654), and what does not: `ENCRYPTION_KEY` is still half of every backup (§1),
migrations still run at startup (§4), and a downgrade still runs from the newer image
before the swap (§5).

**The role.** The app never connects as your master user. Prepare `looninspect_app` with
the program the hosted pods run, as the master, once; it is idempotent, and running it
again after you rotate the role's password teaches the database the new one:

```bash
docker compose -f docker-compose.yml -f docker-compose.external.yml run --rm --no-deps \
  -e PGHOST=db.example.internal -e PGDATABASE=looninspect -e PGUSER=master -e PGPASSWORD='…' \
  -e APP_USER=looninspect_app -e APP_PASSWORD='…' db looninspect-db-init
```

```
application role looninspect_app ready (owns schema public)
```

**Starting.** `DATABASE_MODE=external` and a `DATABASE_URL` that asks for TLS
(`?ssl=require`; `verify-ca` and `verify-full` need a root certificate the container can
read). Before the first migration the app asks the database three things about the role
it connected as — superuser, `BYPASSRLS`, `CREATE` on schema `public` — and refuses with one
sentence when any is wrong; [troubleshooting §4](troubleshooting.md#4-it-will-not-start-or-it-starts-and-every-connection-is-unreadable)
quotes each. `docker-compose.yml` still wants `POSTGRES_PASSWORD` in `.env`; it is unused
here and may be anything.

**Backup.** `pg_dump` from any host that reaches the server. libpq spells the TLS
parameter `sslmode`; the app's URL spells it `ssl`:

```bash
(umask 077 && pg_dump "postgresql://looninspect_app:…@db.example.internal:5432/looninspect?sslmode=require" \
  | gzip > "looninspect-$(date -u +%Y%m%dT%H%M%SZ).sql.gz")
```

Verify it as §2 does, and keep the key with it (§1). **Restore** into an empty database the
role owns, `gunzip -c backup.sql.gz | psql "postgresql://looninspect_app:…?sslmode=require" -v ON_ERROR_STOP=1`;
the role `looninspect-db-init` prepared owns `public`, so the restored objects are its.

**Upgrade and rollback.** §4 and §5 word for word, with
`docker compose -f docker-compose.yml -f docker-compose.external.yml` in place of
`docker compose`, and the two revision commands run against your server:
`psql "…" -tAc "SELECT version_num FROM alembic_version"` for the database's side.

**Two app containers.** Whichever starts first migrates; the other waits on the migration
lock and logs `another process is migrating this database; waiting for it to finish before
starting`, then finds nothing to do. §7 still governs the scheduler.

**What was run.** 2026-09-26, against PostgreSQL 17.11 in a container with TLS on and a
superuser master, from the image this section shipped in: the role prepared by
`looninspect-db-init` (the ready line above); the app started `healthy` in external mode
with `pg_stat_ssl` showing its connection on `TLSv1.3`, logging *external database: the
application role passed its checks* and then *database ready, migrations applied*; the
master's URL refused with the superuser sentence before any migration (exit 3); a URL
without `ssl=` refused at startup as a `Settings` validation error naming `append
?ssl=require` (exit 1); and two containers started together against an empty database,
the second logging *another process is migrating this database; waiting for it to finish
before starting*, both `healthy`, `alembic_version` at head once.
