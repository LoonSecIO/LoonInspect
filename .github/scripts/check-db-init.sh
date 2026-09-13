#!/bin/sh
# Runs looninspect-db-init (#396) the way a pod's task will: from the built db image,
# against a Postgres it does not run, as a master that is not a superuser but can create
# roles and databases and owns its database, which is what RDS gives. Asserts what the
# app relies on, that a second run changes no catalog row, and that a wrong master
# password and a role that could bypass row-level security each end in the script's
# sentence rather than its ready line.
#
#   usage: check-db-init.sh <db-image> <server-container> <network> <superuser> [key]
#
# CI runs it in the Docker image job against smoke-db; locally it runs against any
# Postgres container you can `docker exec` into as a superuser (the shared loon-test-db,
# say). What it creates is named for <key> and dropped before each run, so it is safe
# on a shared server, and after a failure the leftovers are still there to read.
set -eu

IMAGE=$1 SERVER=$2 NETWORK=$3 SUPERUSER=$4 KEY=${5:-ci}
DB=dbinit_$KEY MASTER=dbinit_master_$KEY APP=dbinit_app_$KEY
MASTER_PW=$(openssl rand -hex 16) APP_PW=$(openssl rand -hex 16)
if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$MASTER_PW" && echo "::add-mask::$APP_PW"; fi

fail() { echo "::error::$*" && exit 1; }
as_superuser() { docker exec -e PGOPTIONS=--client-min-messages=warning "$SERVER" psql -X -q -tA -v ON_ERROR_STOP=1 -U "$SUPERUSER" "$@"; }
db_init() { # $1: the master password to present
  docker run --rm --user postgres --network "$NETWORK" \
    -e PGHOST="$SERVER" -e PGDATABASE="$DB" -e PGUSER="$MASTER" -e PGPASSWORD="$1" \
    -e PGSSLMODE=disable -e APP_USER="$APP" -e APP_PASSWORD="$APP_PW" \
    "$IMAGE" /usr/local/bin/looninspect-db-init 2>&1
}
# Every catalog row the script can touch, as the public views show them. The stored
# password hash is not among them: it is re-salted on every run, by design, because the
# password is set on every start.
catalog() {
  as_superuser -d "$DB" \
    -c "SELECT oid, rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication,
               rolbypassrls, rolconnlimit, rolvaliduntil FROM pg_roles WHERE rolname = '$APP'" \
    -c "SELECT nspowner::regrole, nspacl FROM pg_namespace WHERE nspname = 'public'" \
    -c "SELECT roleid::regrole, member::regrole, grantor::regrole, admin_option, inherit_option, set_option
          FROM pg_auth_members WHERE '$APP' IN (roleid::regrole::text, member::regrole::text) ORDER BY 1, 2, 3"
}
cleanup() { as_superuser -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)" -c "DROP ROLE IF EXISTS $APP" -c "DROP ROLE IF EXISTS $MASTER"; }

cleanup
as_superuser -c "CREATE ROLE $MASTER LOGIN PASSWORD '$MASTER_PW' NOSUPERUSER CREATEROLE CREATEDB" -c "CREATE DATABASE $DB OWNER $MASTER"

echo "--- first run, as $MASTER: not a superuser, can create roles and databases, owns $DB"
out=$(db_init "$MASTER_PW") || { echo "$out" && fail "the first run exited non-zero"; }
echo "$out"
[ "$(printf '%s\n' "$out" | tail -n 1)" = "application role $APP ready (owns schema public)" ] || fail "the first run did not end with its ready line"
attributes=$(as_superuser -c "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles WHERE rolname = '$APP'")
[ "$attributes" = "f|f|f|f|t" ] || fail "$APP has rolsuper|rolbypassrls|rolcreaterole|rolcreatedb|rolcanlogin '$attributes', not f|f|f|f|t"
owner=$(as_superuser -d "$DB" -c "SELECT nspowner::regrole FROM pg_namespace WHERE nspname = 'public'")
[ "$owner" = "$APP" ] || fail "schema public in $DB is owned by '$owner', not $APP"
# What the app does next: sign in with APP_PASSWORD and create its tables in public.
docker run --rm --user postgres --network "$NETWORK" -e PGPASSWORD="$APP_PW" "$IMAGE" \
  psql -X -q -v ON_ERROR_STOP=1 -h "$SERVER" -U "$APP" -d "$DB" -c 'CREATE TABLE dbinit_probe (); DROP TABLE dbinit_probe' ||
  fail "$APP cannot sign in with APP_PASSWORD and create a table in schema public"

before=$(catalog)
echo "--- second run"
out=$(db_init "$MASTER_PW") || { echo "$out" && fail "the second run exited non-zero"; }
echo "$out"
after=$(catalog)
[ "$after" = "$before" ] || fail "the second run changed the catalog: before [$before] after [$after]"

echo "--- a wrong master password"
if out=$(db_init not-the-password); then echo "$out" && fail "a wrong master password exited 0"; fi
echo "$out"
case $out in *"could not sign in to $DB"*) ;; *) fail "a wrong master password did not end in the sign-in sentence" ;; esac

echo "--- an application role that could bypass row-level security"
as_superuser -c "ALTER ROLE $APP BYPASSRLS"
if out=$(db_init "$MASTER_PW"); then echo "$out" && fail "a role with BYPASSRLS was reported ready"; fi
echo "$out"
case $out in *"row-level security would not apply to it"*) ;; *) fail "a role with BYPASSRLS did not end in the refusal" ;; esac

cleanup
echo "looninspect-db-init: prepared $DB, changed nothing the second time, refused a wrong password and a bypassing role"
