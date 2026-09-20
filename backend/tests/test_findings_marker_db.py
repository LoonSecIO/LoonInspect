# ruff: noqa: F811 — imported pytest fixtures are injected by name.
"""The device detail exposes a clean first finding check independently of ledger rows (#599)."""

import os
from datetime import UTC, datetime, timedelta

import pytest

from app.core.findings import reconcile_device_findings
from tests.test_findings_db import mac  # noqa: F401
from tests.test_sweep_costs_db import connection  # noqa: F401
from tests.test_tenant_switch_db import accounts, admin, second_tenant  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def test_device_detail_distinguishes_unchecked_from_clean_and_preserves_first_check(db, mac, admin):
    url = f"/api/devices/{mac.id}"
    response = await admin.get(url)
    assert response.status_code == 200
    assert response.json()["findingsReconciledAt"] is None
    first = datetime(2026, 9, 20, 12, tzinfo=UTC)
    await reconcile_device_findings(db, device=mac, rows=[], observed_at=first)
    await db.commit()
    await reconcile_device_findings(db, device=mac, rows=[], observed_at=first + timedelta(days=1))
    await db.commit()
    response = await admin.get(url)
    assert response.status_code == 200
    assert datetime.fromisoformat(response.json()["findingsReconciledAt"]) == first
