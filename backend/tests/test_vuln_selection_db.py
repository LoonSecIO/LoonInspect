"""Tenant acquisition/selection boundaries and rollback against forced PostgreSQL RLS (#621)."""

from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.core.database import session_for_tenant, unscoped_session
from app.core.tenancy import OPERATIONAL_TENANT_ID, reset_tenant_id, set_tenant_id
from app.core.vuln_library import load_epoch_if_new
from app.core.vuln_selection import CorpusSelectionRefused, record_acquisition, select_after_assessment, selected_signature
from app.models.schema import AppCatalogEntry, DataSharingSettings, VulnCorpusAcquisition, VulnCorpusRelease, VulnCorpusSelection
from tests.test_vuln_library import BUNDLE, SIGNATURE, WIRESHARK_BUILD, WIRESHARK_TITLE, _rewritten, _row
from tests.test_vuln_library_db import FOREIGN_TENANT_ID, _pointer, _serving, acting_tenant, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import retained  # noqa: F401 — fixtures

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


@contextmanager
def acting(tenant):
    token = set_tenant_id(tenant)
    try:
        yield
    finally:
        reset_tenant_id(token)


async def no_assessment(db, signature):
    """Storage-only transitions in tests that exercise grants rather than judge integration."""


@pytest_asyncio.fixture(loop_scope="session")
async def releases(db, retained, foreign_tenant):  # noqa: F811
    sessions = (db, foreign_tenant)
    for session in sessions:
        await session.execute(delete(VulnCorpusSelection))
        await session.execute(delete(VulnCorpusAcquisition))
        await session.commit()
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    newer, signature = _rewritten(rows=[_row()])
    await load_epoch_if_new(db, _pointer(signature), transport=_serving(newer))
    try:
        yield signature
    finally:
        for session in sessions:
            await session.rollback()
            await session.execute(delete(VulnCorpusSelection))
            await session.execute(delete(VulnCorpusAcquisition))
            await session.execute(delete(AppCatalogEntry).where(AppCatalogEntry.name == "selection-transaction-test"))
            await session.commit()


async def test_a_retains_its_selection_while_b_acquires_newer_and_raw_sql_cannot_bypass(db, releases, foreign_tenant):  # noqa: F811
    assert await selected_signature(db) is None  # global possession is not a selection
    assert await record_acquisition(db, SIGNATURE)
    clock = await db.scalar(select(VulnCorpusAcquisition.acquired_at))
    assert not await record_acquisition(db, SIGNATURE)
    assert await db.scalar(select(VulnCorpusAcquisition.acquired_at)) == clock
    await select_after_assessment(db, SIGNATURE, assess=no_assessment)
    await db.commit()
    with acting(FOREIGN_TENANT_ID):
        assert await selected_signature(foreign_tenant) is None
        await record_acquisition(foreign_tenant, releases)
        await select_after_assessment(foreign_tenant, releases, assess=no_assessment)
        await foreign_tenant.commit()
        assert await selected_signature(foreign_tenant) == releases
    await db.execute(update(DataSharingSettings).values(tier="off"))
    assert await selected_signature(db) == SIGNATURE  # consent cannot delete a held selection
    assert (await db.execute(select(VulnCorpusAcquisition.signature))).scalars().all() == [SIGNATURE]
    assert (await db.execute(select(VulnCorpusSelection.signature))).scalars().all() == [SIGNATURE]
    with pytest.raises(CorpusSelectionRefused, match="has not acquired"):
        await select_after_assessment(db, releases, assess=no_assessment)
    with pytest.raises(IntegrityError):
        async with db.begin_nested():
            await db.execute(update(VulnCorpusSelection).values(signature=releases))
    with pytest.raises(DBAPIError):
        async with db.begin_nested():
            await db.execute(
                insert(VulnCorpusAcquisition).values(tenant_id=FOREIGN_TENANT_ID, signature=SIGNATURE, basis="delivery")
            )
    assert await selected_signature(db) == SIGNATURE


async def test_selection_and_answer_rollback_together_and_outer_transaction_remains_usable(db, releases):
    for signature in (SIGNATURE, releases):
        await record_acquisition(db, signature)
    await select_after_assessment(db, SIGNATURE, assess=no_assessment)
    now = datetime.now(UTC)
    await db.execute(
        insert(AppCatalogEntry).values(
            name="selection-transaction-test",
            bundle_id="test.selection",
            version="1",
            app_hash="6" * 32,
            version_hash="7" * 32,
            key_title=WIRESHARK_TITLE,
            key_full=WIRESHARK_BUILD,
            first_seen_at=now,
            last_seen_at=now,
            vuln_signature=SIGNATURE,
        )
    )
    await db.commit()

    async def assessment(session, signature):
        assert await selected_signature(session) == SIGNATURE
        await session.execute(
            update(AppCatalogEntry).where(AppCatalogEntry.name == "selection-transaction-test").values(vuln_signature=signature)
        )

    async def broken(session, signature):
        await assessment(session, signature)
        raise ValueError("assessment failed")

    with pytest.raises(ValueError, match="assessment failed"):
        await select_after_assessment(db, releases, assess=broken)
    assert await selected_signature(db) == SIGNATURE
    assert (
        await db.scalar(select(AppCatalogEntry.vuln_signature).where(AppCatalogEntry.name == "selection-transaction-test"))
        == SIGNATURE
    )
    assert await select_after_assessment(db, releases, assess=assessment)
    await db.rollback()  # a caller's failed outer transaction must undo even a successful assessment
    assert await selected_signature(db) == SIGNATURE
    assert await select_after_assessment(db, releases, assess=assessment)
    # A repeat must not assess or restamp; broken would raise if called.
    assert not await select_after_assessment(db, releases, assess=broken)
    await db.commit()
    assert await selected_signature(db) == releases
    with pytest.raises(IntegrityError):
        async with db.begin_nested():
            await db.execute(delete(VulnCorpusAcquisition).where(VulnCorpusAcquisition.signature == releases))
    assert await select_after_assessment(db, SIGNATURE, assess=no_assessment)  # deliberate rollback is allowed
    await db.commit()
    assert await selected_signature(db) == SIGNATURE


async def test_missing_or_mismatched_context_and_unretained_release_are_refused(db, releases, foreign_tenant):  # noqa: F811
    with pytest.raises(CorpusSelectionRefused, match="not been retained"):
        await record_acquisition(db, "f" * 64)
    with pytest.raises(CorpusSelectionRefused, match="organization context"):
        await selected_signature(foreign_tenant)
    with acting(None), pytest.raises(CorpusSelectionRefused, match="organization context"):
        await record_acquisition(db, SIGNATURE)
    await record_acquisition(db, SIGNATURE)
    await db.commit()
    async with unscoped_session() as unbound:
        with pytest.raises(DBAPIError):
            await unbound.execute(select(VulnCorpusAcquisition))


async def test_transitions_serialize_before_first_selection_and_pin_acquired_release(db, releases):
    for signature in (SIGNATURE, releases):
        await record_acquisition(db, signature)
    await db.commit()
    entered, proceed = asyncio.Event(), asyncio.Event()
    order = []

    async def first(session, signature):
        order.append("first")
        entered.set()
        await asyncio.wait_for(proceed.wait(), timeout=5)

    async def second(session, signature):
        assert await selected_signature(session) == SIGNATURE
        order.append("second")

    async def transition(signature, assess):
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            await select_after_assessment(session, signature, assess=assess)
            await session.commit()

    a = asyncio.create_task(transition(SIGNATURE, first))
    await asyncio.wait_for(entered.wait(), timeout=5)
    b = asyncio.create_task(transition(releases, second))
    proceed.set()
    await asyncio.wait_for(asyncio.gather(a, b), timeout=5)
    assert order == ["first", "second"]
    assert await selected_signature(db) == releases
    # An acquired release with no rows cannot be pruned either: the grant itself pins it.
    from app.models.schema import VulnCorpusReleaseRow, VulnCorpusReleaseTitle

    with pytest.raises(IntegrityError):
        async with db.begin_nested():
            await db.execute(delete(VulnCorpusReleaseRow).where(VulnCorpusReleaseRow.signature == SIGNATURE))
            await db.execute(delete(VulnCorpusReleaseTitle).where(VulnCorpusReleaseTitle.signature == SIGNATURE))
            await db.execute(delete(VulnCorpusRelease).where(VulnCorpusRelease.signature == SIGNATURE))
