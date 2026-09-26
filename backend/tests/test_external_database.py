"""External PostgreSQL (#654): the mode is accepted, the URL must ask for TLS, the role is
checked before a migration runs, and two processes starting together serialize on one
lock. The startup words are the ones docs/troubleshooting.md section 4 quotes."""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from pydantic import ValidationError

from app.core import database
from app.core.config import Settings
from app.core.database import role_refusal

# The database-lane tests carry the session loop mark themselves: a module-wide one would
# also decorate the synchronous settings tests, which pytest-asyncio warns about.
needs_db = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

URL = "postgresql+asyncpg://looninspect_app:secret@db.example:5432/looninspect"


def make(**overrides) -> Settings:
    # No .env and no ambient DATABASE_URL: the URL under test is the one given here.
    return Settings(_env_file=None, **overrides)


@pytest.mark.parametrize("query", ["?ssl=require", "?ssl=verify-ca", "?ssl=verify-full"])
def test_external_mode_accepts_a_url_that_asks_for_tls(query):
    assert make(database_mode="external", database_url=URL + query).database_mode == "external"


@pytest.mark.parametrize("query", ["", "?ssl=disable", "?ssl=prefer", "?ssl=allow", "?application_name=x"])
def test_external_mode_refuses_a_url_that_could_fall_back_to_plain_text(query):
    with pytest.raises(ValidationError) as refused:
        make(database_mode="external", database_url=URL + query)
    assert "append ?ssl=require" in str(refused.value)


def test_the_libpq_spelling_is_named_rather_than_silently_ignored():
    # asyncpg's connect() has no `sslmode`; SQLAlchemy would raise a TypeError at the first
    # connection, long after the operator stopped reading the log.
    with pytest.raises(ValidationError) as refused:
        make(database_mode="external", database_url=URL + "?sslmode=require")
    assert "spells the TLS parameter `ssl`, not `sslmode`" in str(refused.value)


def test_bundled_mode_asks_nothing_of_the_url():
    assert make(database_mode="bundled", database_url=URL).database_mode == "bundled"
    assert make(database_url=URL).database_mode == "bundled"


@pytest.mark.parametrize(
    "facts,names",
    [
        ((False, False, True), None),
        ((True, False, True), "is a superuser"),
        ((False, True, True), "is a role with BYPASSRLS"),
        ((True, True, True), "is a superuser"),
        ((False, False, False), "cannot create tables in schema public"),
    ],
)
def test_the_role_refusal_names_the_cause_and_the_fix(facts, names):
    refusal = role_refusal(*facts)
    if names is None:
        assert refusal is None
    else:
        assert names in refusal and "looninspect-db-init" in refusal and "docs/operations.md section 8" in refusal


@needs_db[0]
@needs_db[1]
async def test_the_application_role_passes_the_external_check(db, monkeypatch):
    """What the test database's role is — NOSUPERUSER, NOBYPASSRLS, owner of public — is what
    ops/postgres/looninspect-db-init leaves, so external mode accepts it."""
    monkeypatch.setattr(database.settings, "database_mode", "external")
    await database._check_external_role()


@needs_db[0]
@needs_db[1]
async def test_two_startups_serialize_on_the_migration_lock_and_release_it(db, monkeypatch):
    """Two processes starting against one database run one migration after the other, never
    together; a third start afterwards neither waits for ever nor fails."""
    windows: list[tuple[float, float]] = []

    def one_migration() -> None:
        started = time.monotonic()
        time.sleep(0.3)
        windows.append((started, time.monotonic()))

    monkeypatch.setattr(database, "_run_migrations", one_migration)
    await asyncio.gather(database.init_db(), database.init_db())
    assert len(windows) == 2
    (_first_start, first_end), (second_start, _second_end) = sorted(windows)
    assert first_end <= second_start, "the two migrations overlapped"
    await database.init_db()
    assert len(windows) == 3
