import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.ai_usage import add, queue_event, usage_report
from app.core.database import session_for_tenant
from app.models.schema import AIUsageDaily as Daily
from app.models.schema import Tenant

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires PostgreSQL"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def test_multiday_attempts_partial_reporting_and_queue(db):
    import uuid

    provider = "usage-" + uuid.uuid4().hex[:8]
    first = datetime.now(UTC) - timedelta(days=2)
    last = first + timedelta(days=1)
    attrs = {"feature": "test", "provider": provider, "requested": "alias", "kind": "call"}
    await add(db, **attrs, outcome="answered", reported="resolved", input_tokens=5, input_reports=1, at=first)
    await add(db, **attrs, outcome="answered", reported="resolved", at=last)
    await add(db, **attrs, outcome="timeout", at=first)
    for state in ("received", "received", "started", "retry", "cached", "expired"):
        await queue_event(db, provider, state, first if state == "received" else last)
    await db.commit()
    result = await usage_report(db, first.date(), last.date())
    calls = [r for r in result["calls"] if r["provider"] == provider]
    assert sum(r["events"] for r in calls) == 3
    success = next(r for r in calls if r["reported"] == "resolved")
    assert (success["requested"], success["input_tokens"], success["input_reports"], success["events"]) == ("alias", 5, 1, 2)
    assert {r["outcome"]: r["events"] for r in result["queue"] if r["provider"] == provider} == {
        "received": 2,
        "started": 1,
        "retry": 1,
        "cached": 1,
        "expired": 1,
    }
    other = await db.scalar(select(Tenant.id).where(Tenant.id != db.info["tenant_id"]).limit(1))
    assert other is not None
    async with session_for_tenant(other) as other_db:
        assert await other_db.scalar(select(Daily.events).where(Daily.provider == provider)) is None
