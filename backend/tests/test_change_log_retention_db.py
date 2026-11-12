"""The change log's clock against a real Postgres (#785).

What is pinned: the purge deletes rows observed longer ago than the window and no others, works
through its batches rather than stopping after one, deletes nothing at the default of 0, and —
the security property — reaches no other tenant's rows, because the session it runs in is scoped
to one tenant by row-level security. Rows are inserted directly, as test_changes_search_db.py
does: the derive path is covered elsewhere, and the subject here is the delete.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# A tenant of this file's own, beside the operational one, so the tenancy assertion has a
# neighbour whose old rows must survive.
NEIGHBOUR_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000785")
LABEL = "change-log retention"
NOW = datetime.now(UTC)


def _change(connection_id: int, age_days: int, subject_id: str):
    from app.models.schema import DeviceChange

    observed = NOW - timedelta(days=age_days)
    return DeviceChange(
        mdm_connection_id=connection_id,
        subject_kind="computer",
        subject_id=subject_id,
        entry_label=LABEL,
        observed_at=observed,
        collected_at=observed,
        trigger="sweep",
        section="applications",
        change="added",
        level="normal",
        policy_version="v0",
    )


async def _connection(db, name: str) -> int:
    from app.models.schema import MdmConnection

    row = MdmConnection(name=f"{name} {uuidlib.uuid4().hex[:8]}", provider="jamf", base_url=f"https://{name}.example.com")
    db.add(row)
    await db.flush()
    return row.id


async def _count(db) -> int:
    from app.models.schema import DeviceChange

    mine = select(func.count()).select_from(DeviceChange).where(DeviceChange.entry_label == LABEL)
    return (await db.execute(mine)).scalar_one()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def neighbour(tenant_ready) -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import unscoped_session
    from app.models.schema import Tenant

    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, NEIGHBOUR_TENANT_ID) is None:
            db.add(Tenant(id=NEIGHBOUR_TENANT_ID, slug="retention-neighbour", name="Retention Neighbour", kind="operational"))
            await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def rows(neighbour):
    """Four rows in the operational tenant (400, 100, 40 and 1 day old) and one 400-day-old row
    in the neighbour's; all of them gone afterwards, with the connections that own them."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import DeviceChange, MdmConnection

    connections: dict[uuidlib.UUID, int] = {}
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        connections[OPERATIONAL_TENANT_ID] = await _connection(db, "retention-mine")
        db.add_all([_change(connections[OPERATIONAL_TENANT_ID], age, f"mine-{age}") for age in (400, 100, 40, 1)])
        await db.commit()
    async with session_for_tenant(NEIGHBOUR_TENANT_ID) as db:
        connections[NEIGHBOUR_TENANT_ID] = await _connection(db, "retention-theirs")
        db.add(_change(connections[NEIGHBOUR_TENANT_ID], 400, "theirs-400"))
        await db.commit()
    try:
        yield connections
    finally:
        for tenant_id, connection_id in connections.items():
            async with session_for_tenant(tenant_id) as db:
                await db.execute(delete(DeviceChange).where(DeviceChange.entry_label == LABEL))
                await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
                await db.commit()


async def test_rows_older_than_the_window_go_and_the_rest_stay(rows) -> None:
    from app.changes.retention import purge_changes
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import DeviceChange

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert await purge_changes(db, 90) == 2  # the 400- and 100-day rows
        left = (await db.execute(select(DeviceChange.subject_id).where(DeviceChange.entry_label == LABEL))).scalars().all()
    assert sorted(left) == ["mine-1", "mine-40"]


async def test_the_purge_works_through_its_batches(rows) -> None:
    """A batch smaller than the backlog is a loop, not a stop: with one row a statement, every
    old row still goes in the one call."""
    from app.changes.retention import purge_changes
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert await purge_changes(db, 30, batch_rows=1) == 3  # 400, 100 and 40 days old
        assert await _count(db) == 1


async def test_the_default_of_zero_deletes_nothing(rows) -> None:
    from app.changes.retention import purge_changes
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert await purge_changes(db, 0) == 0
        assert await _count(db) == 4


async def test_one_tenants_purge_reaches_no_other_tenants_rows(rows) -> None:
    """The neighbour's 400-day-old row is older than any window used here, and survives a purge
    run for the operational tenant: the session is scoped, and the delete with it."""
    from app.changes.retention import purge_changes
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert await purge_changes(db, 1) == 4
    async with session_for_tenant(NEIGHBOUR_TENANT_ID) as db:
        assert await _count(db) == 1
