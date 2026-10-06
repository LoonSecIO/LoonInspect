"""The migration round trip: every downgrade undoes its upgrade, on an empty database and under a fleet's rows.

Each walk runs in a database of its own, created and dropped as `ADMIN_DATABASE_URL` (a role that may create
databases: CI's superuser, or the one in tests/conftest.py's recipe) and migrated as the application role in
`DATABASE_URL`, through migrations/env.py as `alembic upgrade` runs. Not a scratch schema in one rolled-back
transaction, the way test_v2_release_gate_db.py walks upgrades: nothing would commit as a real upgrade does, and an
empty stairway alone holds some 2,800 locks to its end. A last database at head holds the models to the migrations.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest
import pytest_asyncio
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import insert, make_url, select, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core import database
from app.core.config import settings
from app.core.tenancy import TENANT_GUC
from app.models import schema  # noqa: F401 — registers every model on Base.metadata, as migrations/env.py does

ADMIN_URL = os.environ.get("ADMIN_DATABASE_URL", "")
pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.skipif(not ADMIN_URL, reason="set ADMIN_DATABASE_URL to a role that may create databases"),
    pytest.mark.asyncio(loop_scope="session"),
]
SCRIPTS = list(ScriptDirectory.from_config(database._alembic_config()).walk_revisions())[::-1]  # base first

# What a downgrade has to put back: each column, index, constraint, policy, relation with its row-level security
# switches, trigger, function and enum or domain in schema public. alembic_version is Alembic's, and filtered out.
SCHEMA = text("""
    SELECT 'column', table_name || '.' || column_name, concat_ws(' ', data_type, character_maximum_length,
           numeric_precision, numeric_scale, is_nullable, column_default, is_identity)
      FROM information_schema.columns WHERE table_schema = 'public'
    UNION ALL SELECT 'index', indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'
    UNION ALL SELECT 'constraint', conrelid::regclass || '.' || conname, pg_get_constraintdef(oid)
      FROM pg_constraint WHERE connamespace = 'public'::regnamespace
    UNION ALL SELECT 'policy', tablename || '.' || policyname, concat_ws(' ', permissive, roles, cmd, qual, with_check)
      FROM pg_policies WHERE schemaname = 'public'
    UNION ALL SELECT 'relation', relname, concat_ws(' ', relkind, relrowsecurity, relforcerowsecurity)
      FROM pg_class WHERE relnamespace = 'public'::regnamespace
    UNION ALL SELECT 'trigger', tgrelid::regclass || '.' || tgname, pg_get_triggerdef(oid) FROM pg_trigger WHERE NOT tgisinternal
    UNION ALL SELECT 'function', oid::regprocedure::text, prosrc FROM pg_proc WHERE pronamespace = 'public'::regnamespace
    UNION ALL SELECT 'type', typname, concat_ws(' ', typtype,
           (SELECT string_agg(enumlabel, ',' ORDER BY enumsortorder) FROM pg_enum WHERE enumtypid = pg_type.oid))
      FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typtype IN ('e', 'd')
""")

NOW = datetime.now(UTC)
SAMPLE = {bool: True, int: 1, float: 1.0, Decimal: Decimal(1), str: "x", bytes: b"x", dict: {}, datetime: NOW, date: NOW.date()}
CHOSEN = {"vuln_corpus_acquisitions.basis": "delivery", "submission_cases.kind": "coverage"}  # what their CHECKs allow
# Rows a fleet holds that three downgrades cannot step back over: (table, the row seeded beside its first, what the
# walk deletes to step past, why). A refused downgrade rolls back, so nothing is lost by trying.
IPAD = ({"platform": "ipados"}, "platform <> 'macos'")
ASSESSMENT = ({"source_id": None}, "source_id IS NULL")  # a point that assessed held inventory (#621)
STEP_PAST = {
    "c621f4a8e902": ("device_history_points", *ASSESSMENT, "refuses, by design, to drop assessment history"),
    "c7d2f9a4b6e1": ("app_catalog", *IPAD, "restores a key without platform; a universal app's Mac and iPad rows share it"),
    "b3c9e7d1a5f2": ("devices", *IPAD, "restores a key without platform; a Mac and an iPad with one Jamf id share it"),
}
# Where the models and the migrations disagree, as autogenerate words it. None is marked deliberate, so each is a strict
# xfail below: declare the index or create it, and its test fails until its line here goes.
DRIFT = {
    "remove_index ix_app_catalog_vuln_ids": "b8d4f1a6c2e7 creates it; AppCatalogEntry does not declare it",
    "remove_index ix_app_catalog_vuln_served": "a7c21e9f4b83 creates it; AppCatalogEntry does not declare it",
    "remove_index ix_observation_sections_entry_digests": "4a8c1f2e7b93 creates it; ObservationSection does not declare it",
    "remove_index ix_observation_spans_section_digests": "4a8c1f2e7b93 creates it; ObservationSpan does not declare it",
    "add_index ix_devices_platform": "Device.platform says index=True; no migration creates it",
}


def _revisions(xfail: dict[str, str]) -> list:
    return [
        pytest.param(
            s.revision,
            id=s.revision,
            marks=pytest.mark.xfail(strict=True, reason=xfail[s.revision]) if s.revision in xfail else (),
        )
        for s in SCRIPTS
    ]


@asynccontextmanager
async def _database():
    """A database of its own, owned by the application role: its URL as that role, and an engine on it."""
    url = make_url(settings.database_url).set(database=f"looninspect_round_trip_{uuid.uuid4().hex[:12]}")
    admin = create_async_engine(
        make_url(ADMIN_URL).set(drivername="postgresql+asyncpg"), isolation_level="AUTOCOMMIT", poolclass=NullPool
    )
    async with admin.connect() as connection:
        await connection.execute(text(f'CREATE DATABASE "{url.database}" OWNER "{url.username}" TEMPLATE template0'))
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        yield url.render_as_string(hide_password=False), engine
    finally:
        await engine.dispose()
        async with admin.connect() as connection:
            await connection.execute(text(f'DROP DATABASE "{url.database}" WITH (FORCE)'))
        await admin.dispose()


async def _alembic(url: str, verb: str, target: str) -> None:
    """`alembic <verb> <target>` on `url`. migrations/env.py reads the URL from settings, so that is what moves."""

    def run() -> None:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(settings, "database_url", url)
            getattr(command, verb)(database._alembic_config(), target)

    await asyncio.to_thread(run)  # env.py runs its own event loop


def _back(script) -> str:
    """One step down from `script`, the head of its branch whenever this is called. `@-1` is ambiguous at a merge,
    where naming either parent undoes the merge alone."""
    return script.down_revision[0] if script.is_merge_point else f"{script.revision}@-1"


async def _schema(engine) -> frozenset[tuple[str, str, str]]:
    async with engine.connect() as connection:
        rows = (await connection.execute(SCHEMA)).all()
    return frozenset((kind, name, definition) for kind, name, definition in rows if not name.startswith("alembic_version"))


def _unlike(expected: frozenset, found: frozenset, step: str) -> str | None:
    return None if found == expected else f"{step} left {sorted(found - expected)} and lacks {sorted(expected - found)}"


async def test_upgrade_head_downgrade_base_upgrade_head():
    async with _database() as (url, engine):
        await _alembic(url, "upgrade", "head")
        head = await _schema(engine)
        await _alembic(url, "downgrade", "base")
        assert await _schema(engine) == frozenset()
        await _alembic(url, "upgrade", "head")
        assert await _schema(engine) == head


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def stairway() -> dict[str, str | None]:
    """Each revision in turn on an empty database: up, down, up again, each step held to the schema it should leave."""
    found: dict[str, str | None] = {}
    async with _database() as (url, engine):
        before = await _schema(engine)
        for script in SCRIPTS:
            problems = []
            try:
                await _alembic(url, "upgrade", script.revision)
                after = await _schema(engine)
                await _alembic(url, "downgrade", _back(script))
                problems.append(_unlike(before, await _schema(engine), "the downgrade"))
                await _alembic(url, "upgrade", script.revision)
                problems.append(_unlike(after, await _schema(engine), "the second upgrade"))
            except Exception as exc:
                found[script.revision] = "; ".join(filter(None, [*problems, f"{type(exc).__name__}: {exc}"]))
                break  # every revision above it would fail the same way, so they report as not reached
            found[script.revision] = "; ".join(filter(None, problems)) or None
            before = await _schema(engine)
    return found


def _verdict(found: dict[str, str | None], revision: str) -> None:
    if revision not in found:
        pytest.skip("not reached: the walk stopped at a step that raised")
    assert found[revision] is None, found[revision]


@pytest.mark.parametrize("revision", _revisions({}))
async def test_each_downgrade_puts_back_the_schema_its_upgrade_found(stairway, revision):
    _verdict(stairway, revision)


def _sample(column, seeded: dict[str, dict]):
    """A value for `column`: the seeded row's key for a foreign key (none to its own table), else one of its type."""
    if (chosen := CHOSEN.get(f"{column.table.name}.{column.name}")) is not None:
        return chosen
    if column.foreign_keys:
        target = next(iter(column.foreign_keys)).column
        return None if target.table is column.table else seeded[target.table.name][target.name]
    kind = getattr(column.type, "impl_instance", column.type).python_type  # EncryptedString is a TypeDecorator
    return uuid.uuid4() if kind is uuid.UUID else SAMPLE[kind]


async def _seed(engine) -> None:
    """A row in every table the models declare, since the walk down drops or alters each, written through the models'
    tables as the application role; then each STEP_PAST row beside its table's first."""
    seeded: dict[str, dict] = {}
    async with engine.begin() as connection:
        for table in database.Base.metadata.sorted_tables:
            row = (await connection.execute(select(table).limit(1))).mappings().first()  # schema_release holds its stamp
            if row is None:
                values = {
                    column.name: _sample(column, seeded)
                    for column in table.columns
                    if column is not table.autoincrement_column and column.default is None and column.server_default is None
                }
                row = (await connection.execute(insert(table).values(values).returning(*table.columns))).mappings().one()
            seeded[table.name] = dict(row)
            if table.name == "tenants":  # every other row is stamped with it, and row-level security checks the stamp
                await connection.execute(
                    text("SELECT set_config(:guc, :tenant, true)"), {"guc": TENANT_GUC, "tenant": str(row["id"])}
                )
        for name, beside, _, _ in STEP_PAST.values():
            table = database.Base.metadata.tables[name]
            keys = set(table.primary_key.columns.keys())
            await connection.execute(insert(table).values({k: v for k, v in seeded[name].items() if k not in keys} | beside))


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def stepped_back() -> dict[str, str | None]:
    """Upgrade head, seed, step down one revision at a time to base, upgrade head: what each step down said."""
    found: dict[str, str | None] = {}
    async with _database() as (url, engine):
        await _alembic(url, "upgrade", "head")
        await _seed(engine)
        for script in reversed(SCRIPTS):
            try:
                await _alembic(url, "downgrade", _back(script))
                found[script.revision] = None
            except Exception as exc:
                found[script.revision] = f"{type(exc).__name__}: {exc}"
                if script.revision not in STEP_PAST:
                    break
                table, _, where, _ = STEP_PAST[script.revision]
                async with engine.begin() as connection:
                    await connection.execute(
                        text("SELECT set_config(:guc, (SELECT id::text FROM tenants LIMIT 1), true)"), {"guc": TENANT_GUC}
                    )
                    await connection.execute(text(f"DELETE FROM {table} WHERE {where}"))
                await _alembic(url, "downgrade", _back(script))
        else:
            await _alembic(url, "upgrade", "head")  # base holds no table, so this climb is the empty one's
    return found


@pytest.mark.parametrize("revision", _revisions({revision: why for revision, (*_, why) in STEP_PAST.items()}))
async def test_each_downgrade_steps_back_over_a_fleets_rows(stepped_back, revision):
    _verdict(stepped_back, revision)


def _word(difference) -> str:
    """('remove_index', Index) as 'remove_index <name>'; a column's grouped changes as 'modify_type <table>.<column>'."""
    if isinstance(difference, list):
        return "; ".join(_word(change[:4]) for change in difference)
    return f"{difference[0]} " + ".".join(str(getattr(part, "name", part)) for part in difference[1:] if part is not None)


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def drift() -> set[str]:
    """What `alembic check` compares at head, configured as migrations/env.py configures it, worded."""
    async with _database() as (url, engine):
        await _alembic(url, "upgrade", "head")
        async with engine.connect() as connection:
            found = await connection.run_sync(
                lambda sync: compare_metadata(MigrationContext.configure(sync), database.Base.metadata)
            )
    return {_word(difference) for difference in found}


async def test_autogenerate_finds_nothing_beyond_the_listed_drift(drift):
    assert drift <= set(DRIFT), sorted(drift - set(DRIFT))


@pytest.mark.parametrize(
    "difference", [pytest.param(d, marks=pytest.mark.xfail(strict=True, reason=why)) for d, why in DRIFT.items()]
)
async def test_the_models_and_the_migrations_agree_on(drift, difference):
    assert difference not in drift
