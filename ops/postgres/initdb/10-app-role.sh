#!/bin/sh
# Creates the role the application actually connects as.
#
# This exists for one reason: a Postgres superuser bypasses row-level security
# entirely, and silently. POSTGRES_USER is created by initdb as a superuser, so
# connecting the app as it would leave every policy in the schema attached, visible
# in \d, and enforcing nothing — the worst possible failure, because it looks
# correct. The role below is deliberately not one.
#
# It owns `public` so Alembic can create tables as it, which makes it their owner too.
# An owner is exempt from RLS by default, which is why every policy in the baseline
# migration is paired with ALTER TABLE ... FORCE ROW LEVEL SECURITY.
#
# Runs once, against an empty data directory, before Postgres accepts connections
# from anywhere else.
set -eu

: "${POSTGRES_APP_USER:?POSTGRES_APP_USER must be set}"
: "${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD must be set}"

# Passed as psql variables rather than interpolated by the shell: :"name" quotes an
# identifier and :'name' quotes a literal, so a password containing a quote is a
# password rather than a syntax error or an injection.
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_user="$POSTGRES_APP_USER" -v app_password="$POSTGRES_APP_PASSWORD" <<'SQL'
CREATE ROLE :"app_user" LOGIN PASSWORD :'app_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

ALTER SCHEMA public OWNER TO :"app_user";
SQL

echo "created application role ${POSTGRES_APP_USER} (nosuperuser, owns schema public)"
