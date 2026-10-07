# ruff: noqa: F811 — imported fixtures are injected by pytest.
"""Catch-up claims keep one owner and recover after bounded acquisition contention."""

import asyncio
from datetime import UTC, datetime

from sqlalchemy import select, update

from app.core.database import session_for_tenant
from app.core.runs import LOCK_CATALOG, AcquisitionBusy
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.mdm import collections
from app.models.schema import Collection
from tests.test_collections import connection, pytestmark  # noqa: F401

pytestmark = pytestmark
NOW = datetime(2026, 10, 7, 16, tzinfo=UTC)


async def due_rows(db, connection, count=1):
    rows = [
        Collection(
            mdm_connection_id=connection.id,
            name=f"catch-up {n}",
            kind="catalog",
            enabled=True,
            sections=[],
            frequency="daily",
            timezone="UTC",
            at_hour=2,
            at_minute=0,
            next_due_at=datetime(2026, 10, 1, 2, tzinfo=UTC),
        )
        for n in range(count)
    ]
    db.add_all(rows)
    await db.commit()
    return rows


async def test_competing_claimers_share_one_latest_occurrence(db, connection):
    (row,) = await due_rows(db, connection)
    row_id = row.id

    async def claim():
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            return [(c.id, due) for c, due, _ in await collections.claim_due(session, NOW) if c.id == row_id]

    results = await asyncio.gather(claim(), claim())
    assert [value for result in results for value in result] == [(row_id, datetime(2026, 10, 7, 2, tzinfo=UTC))]
    await db.refresh(row)
    assert row.next_due_at == datetime(2026, 10, 8, 2, tzinfo=UTC)


async def test_tick_restores_claims_and_continues_after_rollback(db, connection, monkeypatch):
    rows = await due_rows(db, connection, 2)
    ids = [row.id for row in rows]
    seen = []
    original_claim = collections.claim_due

    async def claim(session, now):
        return [(c, due, following) for c, due, following in await original_claim(session, now) if c.id in ids]

    async def busy(session, collection, **kwargs):
        seen.append(collection.id)
        raise AcquisitionBusy(collection.mdm_connection_id, LOCK_CATALOG)

    monkeypatch.setattr(collections, "claim_due", claim)
    monkeypatch.setattr(collections, "run_one_collection", busy)
    results = await collections.tick_tenant(db, NOW)
    assert sorted(seen) == sorted(ids)
    assert len(results) == 2 and all(not result.ok for result in results)
    values = await db.scalars(select(Collection.next_due_at).where(Collection.id.in_(ids)))
    assert list(values) == [datetime(2026, 10, 7, 2, tzinfo=UTC)] * 2


async def test_contention_restore_preserves_an_edit_after_claim(db, connection, monkeypatch):
    (row,) = await due_rows(db, connection)
    row_id = row.id
    edited_due = datetime(2026, 10, 9, 5, tzinfo=UTC)
    original = collections.claim_due

    async def claim(session, now):
        claimed = [values for values in await original(session, now) if values[0].id == row_id]
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as editor:
            await editor.execute(update(Collection).where(Collection.id == row_id).values(next_due_at=edited_due, at_hour=5))
            await editor.commit()
        return claimed

    async def busy(session, collection, **kwargs):
        raise AcquisitionBusy(collection.mdm_connection_id, LOCK_CATALOG)

    monkeypatch.setattr(collections, "claim_due", claim)
    monkeypatch.setattr(collections, "run_one_collection", busy)
    await collections.tick_tenant(db, NOW)
    await db.refresh(row)
    assert row.next_due_at == edited_due and row.at_hour == 5


async def test_competing_tickers_claim_multiple_rows_without_deadlock(db, connection):
    rows = await due_rows(db, connection, 3)
    ids = {row.id for row in rows}

    async def claim():
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            async with asyncio.timeout(5):
                return [row.id for row, _, _ in await collections.claim_due(session, NOW) if row.id in ids]

    results = await asyncio.gather(claim(), claim())
    claimed = [key for values in results for key in values]
    assert len(claimed) == len(set(claimed)) == 3 and set(claimed) == ids
