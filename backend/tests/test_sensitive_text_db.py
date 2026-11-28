import asyncio
import os

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, text

from app.core.config import settings
from app.core.database import session_for_tenant
from app.core.rekey import RekeySummary, rekey_session
from app.core.sensitive_text import SCRIPT_DIGEST, purge_unreferenced_text, read_text, store_text
from app.core.tenancy import OPERATIONAL_TENANT_ID, ROOT_TENANT_ID
from app.models.schema import ObservationSection

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def test_reference_keeps_deduplicated_text_until_last_definition_goes(db):
    body = "synthetic inventory rule"
    digest = await store_text(db, body)
    assert await store_text(db, body) == digest
    for version in ("older", "newer"):
        db.add(ObservationSection(section="definition", digest=version, body={SCRIPT_DIGEST: digest}))
    unused = await store_text(db, "unused synthetic rule")
    await db.flush()
    await purge_unreferenced_text(db)
    assert await read_text(db, unused) is None
    rows = (await db.scalars(select(ObservationSection).where(ObservationSection.body[SCRIPT_DIGEST].astext == digest))).all()
    for row in rows:
        assert await read_text(db, digest) == body
        await db.delete(row)
        await db.flush()
        await purge_unreferenced_text(db)
    assert len(rows) == 2
    assert await read_text(db, digest) is None


async def test_encryption_rotation_and_isolation(db, monkeypatch):
    # Seed the fixture under a temporary previous key, never change the lane's key.
    previous_key = Fernet.generate_key().decode()
    body = "synthetic rotation sample"
    with monkeypatch.context() as temp:
        temp.setattr(settings, "encryption_key", previous_key)
        digest = await store_text(db, body)
        await db.commit()
    stored = text("SELECT body FROM sensitive_text WHERE digest = :digest")
    try:
        before = await db.scalar(stored, {"digest": digest})
        assert before.startswith("k1:") and body not in before
        async with session_for_tenant(ROOT_TENANT_ID) as other:
            assert await read_text(other, digest) is None
        monkeypatch.setattr(settings, "encryption_key_previous", previous_key)
        summary = RekeySummary()
        await rekey_session(db, summary)
        assert summary.rewritten >= 1
        assert await db.scalar(stored, {"digest": digest}) != before
        monkeypatch.setattr(settings, "encryption_key_previous", None)
        assert await read_text(db, digest) == body
    finally:
        await db.execute(text("DELETE FROM sensitive_text WHERE digest = :digest"), {"digest": digest})
        await db.commit()


async def test_cleanup_waits_for_a_reused_body_to_gain_a_reference(db):
    digest = await store_text(db, "synthetic shared rule")
    await db.commit()
    try:
        await store_text(db, "synthetic shared rule")
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as cleaner:
            pid = await cleaner.scalar(text("SELECT pg_backend_pid()"))
            cleanup = asyncio.create_task(purge_unreferenced_text(cleaner))
            try:
                # Wait until Postgres sees the lock conflict, independently of machine speed.
                async with asyncio.timeout(5):
                    while not await db.scalar(text("SELECT cardinality(pg_blocking_pids(:pid))"), {"pid": pid}):
                        if cleanup.done():
                            pytest.fail("cleanup passed a writer with a pending owner")
                        await asyncio.sleep(0.01)
                db.add(ObservationSection(section="definition", digest="synthetic-reference", body={SCRIPT_DIGEST: digest}))
                await db.commit()
            finally:
                await db.rollback()
                await cleanup
            await cleaner.commit()
        assert await read_text(db, digest) == "synthetic shared rule"
    finally:
        await db.execute(text("DELETE FROM observation_sections WHERE digest = 'synthetic-reference'"))
        await db.execute(text("DELETE FROM sensitive_text WHERE digest = :digest"), {"digest": digest})
        await db.commit()
