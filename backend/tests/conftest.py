"""Shared fixtures — the pure lane's, and the database lane's.

## Two lanes, one file

The pure-logic lane needs no session and runs anywhere `uv sync` does. The database
lane is every file gated on `RUN_DB_TESTS` (a `pytestmark` at the top of each), and
it needs a real Postgres: row-level security, `JSONB`, the `@>` containment filters
and the migrations under test have no SQLite stand-in — `Settings._require_asyncpg`
refuses any other URL outright (#29). Its three fixtures live here rather than in a
copy per file (#140: sixteen near-verbatim copies, and a docstring recipe that could
not be run from a host shell). Nothing here touches the database at import: every
fixture below imports the app lazily and connects only when a test asks for it, so
collecting this file with no Postgres present still leaves the pure lane runnable —
`create_async_engine` is lazy, and CI's first pytest step proves the point by running
the whole tree with no `DATABASE_URL` at all.

## Running the database lane locally

The same three steps CI takes (`.github/workflows/ci.yml`, the backend job). The
application role is a **non-superuser without BYPASSRLS** on purpose: a superuser
passes every tenancy test by bypassing the policies they exist to prove.

    # 1. A throwaway Postgres. Nothing else on the machine is touched, and the compose
    #    stack's own database publishes no host port by design, so do not reuse it.
    docker run -d --name loon-test-db -p 5432:5432 \
      -e POSTGRES_USER=looninspect -e POSTGRES_PASSWORD=looninspect -e POSTGRES_DB=looninspect \
      postgres:17-alpine

    # 2. The role CI creates, and a database it owns.
    docker exec loon-test-db psql -U looninspect -d looninspect \
      -c "CREATE ROLE looninspect_app LOGIN PASSWORD 'looninspect_app' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS" \
      -c "CREATE DATABASE looninspect_test OWNER looninspect_app"

    # 3. The lane, from backend/. The suite migrates the empty database itself.
    RUN_DB_TESTS=1 \
    DATABASE_URL=postgresql+asyncpg://looninspect_app:looninspect_app@localhost:5432/looninspect_test \
    ENCRYPTION_KEY="$(openssl rand -base64 32 | tr '+/' '-_')" \
    uv run --frozen pytest -q

Two things that read like regressions and are not:

- **Keep `ENCRYPTION_KEY` stable for the life of the database.** Connections and
  destinations written under one key fail to decrypt under another ("Failed to decrypt
  stored value") in files far from the one you changed. Put the key in your shell
  once, or drop and recreate `looninspect_test` when you rotate it.
- **A subset can poison the next full run.** The fixtures are get-or-create so a
  re-run never trips a unique constraint, which also means rows outlive the run. When
  a full run fails in a file you did not touch, `DROP DATABASE looninspect_test` and
  `CREATE DATABASE looninspect_test OWNER looninspect_app` as `looninspect` first, then
  look again.

Without `uv` on the host, the application image carries it: put the database on a
docker network instead of a host port, build the image (`docker build -t looninspect-app .`
at the repo root), and run step 3 inside it with the repo mounted at `/repo`, the working
directory `/repo/backend`, a named volume for the environment (`-v loon-test-venv:/venv
-e UV_PROJECT_ENVIRONMENT=/venv/env -e UV_CACHE_DIR=/venv/cache -e UV_LINK_MODE=copy`,
`--user root`) and the database host set to the container's name. Mount the repo root,
not `backend/`: the registry tests read `../docs` and `../README.md`.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet

from app.core.config import settings

if TYPE_CHECKING:
    from tests.jamf_fake import FakeJamf


# --- the pure lane --------------------------------------------------------------------


@pytest.fixture
def encryption_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """A valid Fernet key installed on the live settings object.

    `get_encryption_key()` reads `settings.encryption_key` on every call rather than
    caching it at import, so patching the attribute is sufficient and needs no reload.
    """
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "encryption_key", key)
    return key


@pytest.fixture
def no_encryption_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicitly unset the key.

    Not a no-op: `Settings` reads `backend/.env` if one exists, so a developer with
    `ENCRYPTION_KEY` set locally would otherwise see the missing-key tests fail while
    CI passed. Asserting the absence rather than assuming it keeps the two identical.
    """
    monkeypatch.setattr(settings, "encryption_key", None)


# --- the database lane ----------------------------------------------------------------
#
# Session-scoped where the work is done once (the migrated schema, the bootstrapped
# tenants) and function-scoped where a test needs its own session. All on the session
# event loop: `app.core.database`'s engine is created once and its pooled connections
# belong to whichever loop first used them, so a per-function loop would hand the second
# test a connection from a closed loop — which surfaces as "attached to a different
# loop" rather than anything about the code under test. Every gated file therefore
# carries `pytest.mark.asyncio(loop_scope="session")` in its `pytestmark`.
#
# A file whose tests need more than these — a second tenant, accounts of its own, a
# per-test clean slate — defines that as its own fixture in the file, named for what it
# adds (`accounts`, `seeded`, `clean`), rather than redefining these under the same name.


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    """The migrated schema and the bootstrapped tenants — the floor every DB test stands
    on. Idempotent, so a persistent local database is migrated once and left alone."""
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready):
    """A session bound to the operational tenant — what the application's own request
    path hands a route, RLS included."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


@pytest.fixture
def jamf(monkeypatch: pytest.MonkeyPatch) -> FakeJamf:
    """A Jamf Pro tenant answered by `tests.jamf_fake.FakeJamf` over an httpx mock
    transport, patched in at `JamfClient.http` so every ingest path — sweep, run-now,
    webhook, catalog — talks to it without knowing. Returned so a test can seed the
    fleet, edit a record between sweeps, or read back what was requested."""
    from app.mdm.jamf.client import JamfClient
    from tests.jamf_fake import FakeJamf

    fake = FakeJamf()

    @asynccontextmanager
    async def _mock_http(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as client:
            yield client

    monkeypatch.setattr(JamfClient, "http", _mock_http)
    return fake
