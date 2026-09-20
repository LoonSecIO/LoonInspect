"""Finding closure at the fleet departure boundary, through both census paths (#607)."""

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.findings import close_departed_device_findings
from app.core.vuln_read import detection
from app.models.schema import Device, DeviceFinding, Run, RunLogLine, SubjectDeparture
from app.observations.departure import DEPARTURE_TAIL
from tests.test_findings_db import CVE, DAY1, DAY2, OTHER, WIRESHARK, _app, _ledger, _sync, mac  # noqa: F401
from tests.test_sweep_costs_db import connection  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]
AT = datetime(2026, 9, 20, 12, tzinfo=UTC)


def departure(device, at, **kwargs):
    return SubjectDeparture(
        mdm_connection_id=device.mdm_connection_id,
        subject_kind="computer",
        subject_id=device.external_id,
        departed_at=at,
        **kwargs,
    )


@pytest.mark.parametrize("path", ["clean", "scoped", "failed", "refused"])
async def test_census_closes_findings_at_tail_end_and_reports_why(db, mac, connection, monkeypatch, path):  # noqa: F811
    from app.mdm import census

    class Clock:
        @staticmethod
        def now(tz):
            return AT

    monkeypatch.setattr(census, "datetime", Clock)
    mac.last_seen_at = DAY2
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE, OTHER])], DAY1, new=True)
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE])], DAY2)
    before = {
        r.finding_id: (r.id, r.resolved_at, r.resolved_reason, r.last_observed_at) for r in (await _ledger(db, mac)).values()
    }
    db.add(departure(mac, AT - DEPARTURE_TAIL))
    run = Run(
        mdm_connection_id=connection.id,
        lock_class="device_sweep",
        trigger="manual",
        comparison="delta",
        status="running",
        window_start=AT,
    )
    db.add(run)
    await db.commit()
    args = {
        "observed_ids": [] if path == "refused" else ["present-mac"],
        "observed_lineage": None,
        "selector": "some-slice" if path == "scoped" else None,
        "devices_failed": int(path == "failed"),
    }
    await census._reconcile_device_census(db, connection, run, **args)
    rows = {r.finding_id: r for r in (await _ledger(db, mac)).values()}
    closed = rows[CVE]
    assert (closed.resolved_at, closed.resolved_reason, closed.last_observed_at) == (AT, "device_departed", DAY2)
    assert (closed.id, closed.first_observed_at) == (before[CVE][0], DAY1)
    old = rows[OTHER]
    assert (old.id, old.resolved_at, old.resolved_reason, old.last_observed_at) == before[OTHER]
    answer = await detection(db, CVE)
    assert answer.devices_open == 0 and answer.last_detected_at == DAY2
    line = (
        (await db.execute(select(RunLogLine).where(RunLogLine.run_id == run.id).order_by(RunLogLine.id.desc()))).scalars().first()
    )
    assert line.fields["findingsClosed"] == 1
    assert "this does not mean fixed" in line.message and "last observation" in line.message
    await census._reconcile_device_census(db, connection, run, **args)
    line = (
        (await db.execute(select(RunLogLine).where(RunLogLine.run_id == run.id).order_by(RunLogLine.id.desc()))).scalars().first()
    )
    assert line.fields["findingsClosed"] == 0
    assert (await _ledger(db, mac))[(closed.carrier_key, CVE)].resolved_at == AT


@pytest.mark.parametrize("state", ["present", "tail", "returned", "retired", "unknown-clock"])
async def test_departure_membership_clocks_and_return(db, mac, state):  # noqa: F811
    mac.last_seen_at = None if state == "unknown-clock" else DAY2
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE], truncated=True)], DAY1, new=True)
    gone = None
    if state != "present":
        gone = departure(mac, AT - DEPARTURE_TAIL + (timedelta(seconds=1) if state == "tail" else timedelta()))
        if state == "returned":
            gone.returned_at = AT - timedelta(hours=1)
        if state == "retired":
            gone.prior_jamf_pro_id = mac.external_id
            gone.subject_id = "replacement-id"
            gone.returned_at = AT - timedelta(hours=1)
        db.add(gone)
        await db.commit()
    expected = state in {"retired", "unknown-clock"}
    assert await close_departed_device_findings(db, connection_id=mac.mdm_connection_id, at=AT) == int(expected)
    await db.commit()
    (row,) = (await _ledger(db, mac)).values()
    assert (row.resolved_at is not None) == expected
    if not expected:
        return
    assert row.last_observed_at == mac.last_seen_at
    # A genuinely returning observation reopens the same finding on its original first clock.
    gone.prior_jamf_pro_id = None
    gone.subject_id = mac.external_id
    gone.returned_at = AT
    mac.last_seen_at = AT
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE], truncated=True)], AT)
    (reopened,) = (await _ledger(db, mac)).values()
    assert (reopened.id, reopened.first_observed_at, reopened.resolved_at, reopened.last_observed_at) == (
        row.id,
        DAY1,
        None,
        None,
    )
    assert await close_departed_device_findings(db, connection_id=mac.mdm_connection_id, at=AT) == 0


async def test_departure_close_is_connection_scoped_tenant_scoped_and_transactional(db, mac):  # noqa: F811
    from app.core.database import session_for_tenant
    from app.core.tenancy import ROOT_TENANT_ID

    mac.last_seen_at = DAY2
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE])], DAY1, new=True)
    db.add(departure(mac, AT - DEPARTURE_TAIL))
    await db.commit()
    assert await close_departed_device_findings(db, connection_id=-1, at=AT) == 0
    async with session_for_tenant(ROOT_TENANT_ID) as other:
        assert await close_departed_device_findings(other, connection_id=mac.mdm_connection_id, at=AT) == 0
        await other.commit()
    assert await close_departed_device_findings(db, connection_id=mac.mdm_connection_id, at=AT) == 1
    await db.rollback()
    (row,) = (await db.execute(select(DeviceFinding).join(Device).where(Device.external_id == "4242"))).scalars().all()
    assert row.resolved_at is None, "the caller owns the transaction"
