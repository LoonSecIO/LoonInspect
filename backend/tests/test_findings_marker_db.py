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
    # The Mac last reported a day before the pod looked (#646): the marker is the look, not the report.
    reported = datetime(2026, 9, 20, 12, tzinfo=UTC)
    checked = datetime(2026, 9, 21, 12, tzinfo=UTC)
    await reconcile_device_findings(db, device=mac, rows=[], observed_at=reported, checked_at=checked)
    await db.commit()
    await reconcile_device_findings(
        db, device=mac, rows=[], observed_at=reported + timedelta(days=2), checked_at=checked + timedelta(days=2)
    )
    await db.commit()
    response = await admin.get(url)
    assert response.status_code == 200
    marker = datetime.fromisoformat(response.json()["findingsReconciledAt"])
    assert marker == checked
    assert marker != reported


async def test_first_check_marker_defaults_to_the_pod_clock(db, mac):
    reported = datetime(2026, 9, 18, 22, 34, 19, tzinfo=UTC)  # the demo pod's Mac, #646
    before = datetime.now(UTC)
    await reconcile_device_findings(db, device=mac, rows=[], observed_at=reported)
    await db.commit()
    assert mac.findings_reconciled_at is not None
    assert before <= mac.findings_reconciled_at <= datetime.now(UTC)
    assert mac.findings_reconciled_at != reported
