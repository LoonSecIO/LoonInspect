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
from sqlalchemy import CheckConstraint, MetaData, insert, make_url, select, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core import database
from app.core.config import settings
from app.core.tenancy import OPERATIONAL_TENANT_ID, ROOT_TENANT_ID, ROOT_TENANT_SLUG, TENANT_GUC
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
TABLES = text("SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'")
# The operational tenant, bound for the transaction: row-level security reads it, and a tenant's row takes it as its
# stamp. Every row the walk writes is its, as an install's operational data is (app/core/bootstrap.py).
BIND = text("SELECT set_config(:guc, :tenant, true)").bindparams(guc=TENANT_GUC, tenant=str(OPERATIONAL_TENANT_ID))

NOW = datetime.now(UTC)
SAMPLE = {bool: True, int: 1, float: 1.0, Decimal: Decimal(1), bytes: b"x", dict: {}, datetime: NOW, date: NOW.date()}
UNBOUNDED = 4096  # characters for a string column without a width: more than any VARCHAR the chain declares
CHOSEN = {
    "tenants.id": OPERATIONAL_TENANT_ID,
    "vuln_corpus_acquisitions.basis": "delivery",  # what their CHECKs allow
    "submission_cases.kind": "coverage",
    # A list as a destination holds it at head: a9d4c7e1f3b8 and bd51c7a9e402 take their event types out on the way down.
    "destinations.subscribed_events": ["run.failed", "subject.departure", "subject.returned"],
}
# The install's other tenant, written beside the first: the management-only root, which owns no other row. A downgrade
# that takes one tenant from `tenants` meets two, as on every install.
ROOT = ("tenants", {"id": ROOT_TENANT_ID, "slug": ROOT_TENANT_SLUG, "kind": "root"})
# Rows a fleet holds that three downgrades cannot step back over: (table, the row written beside its first, what the
# walk deletes to step past, words the step's error carries, why). A refused downgrade rolls back, so nothing is lost by
# trying. A step that fails with other words fails its test.
IPAD = ({"platform": "ipados"}, "platform <> 'macos'")
ASSESSMENT = ({"source_id": None}, "source_id IS NULL")  # a point that assessed held inventory (#621)
STEP_PAST = {
    "c621f4a8e902": (
        "device_history_points",
        *ASSESSMENT,
        "Assessment history exists",
        "refuses, by design, to drop assessment history",
    ),
    "c7d2f9a4b6e1": (
        "app_catalog",
        *IPAD,
        '"uq_app_catalog_version"',
        "restores a key without platform; a universal app's Mac and iPad rows share it",
    ),
    "b3c9e7d1a5f2": (
        "devices",
        *IPAD,
        '"uq_device_connection_external_id"',
        "restores a key without platform; a Mac and an iPad with one Jamf id share it",
    ),
}
# Where the models and the migrations disagree, as autogenerate words it, and a CHECK only the migrations or only the
# models name (autogenerate compares none). None is marked deliberate, so each is a strict xfail below: declare it on its
# model or create it, and its test fails until its line here goes.
DRIFT = {
    "remove_index ix_app_catalog_vuln_ids": "b8d4f1a6c2e7 creates it; AppCatalogEntry does not declare it",
    "remove_index ix_app_catalog_vuln_served": "a7c21e9f4b83 creates it; AppCatalogEntry does not declare it",
    "remove_index ix_observation_sections_entry_digests": "4a8c1f2e7b93 creates it; ObservationSection does not declare it",
    "remove_index ix_observation_spans_section_digests": "4a8c1f2e7b93 creates it; ObservationSpan does not declare it",
    "add_index ix_devices_platform": "Device.platform says index=True; no migration creates it",
    "migrations_only_check vuln_library_epoch.ck_vuln_library_epoch_single_row": (
        "d1f8b6a34e07 creates it; VulnLibraryEpoch does not declare it"
    ),
}


def _xfail(reason: str):
    """Strict, and for a failed assertion alone: a test that fails any other way, its fixture included, fails."""
    return pytest.mark.xfail(strict=True, raises=AssertionError, reason=reason)


def _revisions(xfail: dict[str, str]) -> list:
    return [
        pytest.param(s.revision, id=s.revision, marks=_xfail(xfail[s.revision]) if s.revision in xfail else ()) for s in SCRIPTS
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


async def _schema(connection) -> frozenset[tuple[str, str, str]]:
    rows = (await connection.execute(SCHEMA)).all()
    await connection.rollback()  # holds nothing while Alembic migrates
    return frozenset((kind, name, definition) for kind, name, definition in rows if not name.startswith("alembic_version"))


def _unlike(expected: frozenset, found: frozenset, step: str) -> str | None:
    return None if found == expected else f"{step} left {sorted(found - expected)} and lacks {sorted(expected - found)}"


async def test_upgrade_head_downgrade_base_upgrade_head():
    async with _database() as (url, engine), engine.connect() as catalog:
        await _alembic(url, "upgrade", "head")
        head = await _schema(catalog)
        await _alembic(url, "downgrade", "base")
        assert await _schema(catalog) == frozenset()
        await _alembic(url, "upgrade", "head")
        assert await _schema(catalog) == head


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def stairway() -> tuple[dict[str, str | None], dict[str, frozenset]]:
    """Each revision in turn on an empty database: up, down, up again, each step held to the schema it should leave.
    What each revision's steps left wrong, and the schema below each revision: what stepping past it has to leave."""
    found: dict[str, str | None] = {}
    below: dict[str, frozenset] = {}
    async with _database() as (url, engine), engine.connect() as catalog:
        before = await _schema(catalog)
        for script in SCRIPTS:
            below[script.revision] = before
            problems = []
            try:
                await _alembic(url, "upgrade", script.revision)
                after = await _schema(catalog)
                await _alembic(url, "downgrade", _back(script))
                problems.append(_unlike(before, await _schema(catalog), "the downgrade"))
                await _alembic(url, "upgrade", script.revision)
                before = await _schema(catalog)  # what the next revision's downgrade has to put back
                problems.append(_unlike(after, before, "the second upgrade"))
            except Exception as exc:
                found[script.revision] = "; ".join(filter(None, [*problems, f"{type(exc).__name__}: {exc}"]))
                break  # every revision above it would fail the same way, so they report as not reached
            found[script.revision] = "; ".join(filter(None, problems)) or None
    return found, below


def _verdict(found: dict[str, str | None], revision: str, says: str | None = None) -> None:
    if revision not in found:
        pytest.skip("not reached: the walk stopped at an earlier step")
    if says and found[revision] and says not in found[revision]:
        pytest.fail(f"listed as failing with {says}, it failed otherwise: {found[revision]}")  # no xfail absorbs this
    assert found[revision] is None, found[revision]


@pytest.mark.parametrize("revision", _revisions({}))
async def test_each_downgrade_puts_back_the_schema_its_upgrade_found(stairway, revision):
    _verdict(stairway[0], revision)


def _sample(column, written: dict[str, dict]):
    """A value for `column`: the written row's key for a foreign key (none to its own table), else one of its type. A
    string fills its column's width, so a downgrade that narrows the column meets a value it has to empty or convert."""
    if (chosen := CHOSEN.get(f"{column.table.name}.{column.name}")) is not None:
        return chosen
    if column.foreign_keys:
        target = next(iter(column.foreign_keys)).column
        return None if target.table is column.table else written[target.table.name][target.name]
    kind = getattr(column.type, "impl_instance", column.type)  # EncryptedString is a TypeDecorator
    if kind.python_type is str:
        return "x" * (getattr(kind, "length", None) or UNBOUNDED)
    return uuid.uuid4() if kind.python_type is uuid.UUID else SAMPLE[kind.python_type]


async def _fill(connection, tables) -> dict[str, dict]:
    """A row in each of `tables` that holds none, written as the application role; each table's first row, by name."""
    written: dict[str, dict] = {}
    for table in tables:
        row = (await connection.execute(select(table).limit(1))).mappings().first()  # schema_release holds its stamp
        if row is None:
            values = {
                column.name: _sample(column, written)
                for column in table.columns
                if column is not table.autoincrement_column and column.default is None and column.server_default is None
            }
            row = (await connection.execute(insert(table).values(values).returning(*table.columns))).mappings().one()
        written[table.name] = dict(row)
        if table.name == "tenants":  # every other row is stamped with it, and row-level security checks the stamp
            await connection.execute(BIND)
    return written


async def _refill(engine) -> None:
    """A row in each table the last step created or emptied, written through the tables as reflected: the step that drops
    or alters it meets a row, as it would once the application had run at this revision."""
    async with engine.begin() as connection:
        names = set((await connection.execute(TABLES)).scalars()) - {"alembic_version"}
        if "tenants" not in names:  # base
            return
        await connection.execute(BIND)
        held = " UNION ALL ".join(f"SELECT '{name}' WHERE NOT EXISTS (SELECT FROM \"{name}\")" for name in names)
        if empty := (await connection.execute(text(held))).scalars().all():
            left = MetaData()
            await connection.run_sync(left.reflect, only=empty)  # and the tables they refer to, whose rows they take
            await _fill(connection, left.sorted_tables)


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def stepped_back(stairway) -> tuple[dict[str, str | None], dict[str, str], list[frozenset]]:
    """Upgrade head and write a row in every table through the models' tables, then the rows written beside their
    table's first; step down to base one revision at a time, each step held to the schema the stairway found below its
    revision and refilled after; upgrade head. What each step said, what it left wrong, and the schema at head, at base
    and at head again."""
    found: dict[str, str | None] = {}
    wrong: dict[str, str] = {}
    _, below = stairway
    async with _database() as (url, engine), engine.connect() as catalog:
        await _alembic(url, "upgrade", "head")
        ends = [await _schema(catalog)]
        async with engine.begin() as connection:
            written = await _fill(connection, database.Base.metadata.sorted_tables)
            for name, beside, *_ in [ROOT, *STEP_PAST.values()]:
                table = database.Base.metadata.tables[name]
                keys = set(table.primary_key.columns.keys())
                await connection.execute(insert(table).values({k: v for k, v in written[name].items() if k not in keys} | beside))
        for script in reversed(SCRIPTS):
            if script.revision not in below:
                break  # the stairway stopped below it, and says why
            try:
                await _alembic(url, "downgrade", _back(script))
                found[script.revision] = None
            except Exception as exc:
                found[script.revision] = f"{type(exc).__name__}: {exc}"
                if script.revision not in STEP_PAST:
                    break
                table, _, where, *_ = STEP_PAST[script.revision]
                async with engine.begin() as connection:
                    await connection.execute(BIND)
                    await connection.execute(text(f"DELETE FROM {table} WHERE {where}"))
                await _alembic(url, "downgrade", _back(script))
            if problem := _unlike(below[script.revision], await _schema(catalog), "stepping past it"):
                wrong[script.revision] = problem
                break  # every step below it would start from the wrong schema
            await _refill(engine)
        else:
            ends.append(await _schema(catalog))
            await _alembic(url, "upgrade", "head")  # base holds no table, so this climb is the empty one's
            ends.append(await _schema(catalog))
    return found, wrong, ends


@pytest.mark.parametrize("revision", _revisions({revision: why for revision, (*_, why) in STEP_PAST.items()}))
async def test_each_downgrade_steps_back_over_a_fleets_rows(stepped_back, revision):
    found, wrong, _ = stepped_back
    if revision in wrong:
        pytest.fail(wrong[revision])  # no xfail absorbs this: the step was listed for what it raises, not what it leaves
    _verdict(found, revision, STEP_PAST[revision][3] if revision in STEP_PAST else None)


async def test_the_walk_over_rows_leaves_nothing_at_base_and_climbs_back_to_its_head(stepped_back):
    *_, ends = stepped_back
    if len(ends) < 3:
        pytest.skip("not reached: the walk stopped above base")
    head, base, again = ends
    assert base == frozenset(), sorted(base)
    assert again == head, _unlike(head, again, "the climb back")


def _word(difference) -> str:
    """('remove_index', Index) as 'remove_index <name>'; a column's grouped changes as 'modify_type <table>.<column>'."""
    if isinstance(difference, list):
        return "; ".join(_word(change[:4]) for change in difference)
    return f"{difference[0]} " + ".".join(str(getattr(part, "name", part)) for part in difference[1:] if part is not None)


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def drift() -> set[str]:
    """What `alembic check` compares at head, configured as migrations/env.py configures it, worded; and each CHECK
    only the migrations or only the models name."""
    async with _database() as (url, engine):
        await _alembic(url, "upgrade", "head")
        async with engine.connect() as connection:
            found = await connection.run_sync(
                lambda sync: compare_metadata(MigrationContext.configure(sync), database.Base.metadata)
            )
            built = {name for kind, name, how in await _schema(connection) if kind == "constraint" and how.startswith("CHECK")}
    tables = database.Base.metadata.tables.values()
    declared = {f"{t.name}.{c.name}" for t in tables for c in t.constraints if isinstance(c, CheckConstraint)}
    checks = {f"migrations_only_check {n}" for n in built - declared} | {f"models_only_check {n}" for n in declared - built}
    return {_word(difference) for difference in found} | checks


async def test_nothing_differs_beyond_the_listed_drift(drift):
    assert drift <= set(DRIFT), sorted(drift - set(DRIFT))


@pytest.mark.parametrize("difference", [pytest.param(d, marks=_xfail(why)) for d, why in DRIFT.items()])
async def test_the_models_and_the_migrations_agree_on(drift, difference):
    assert difference not in drift
