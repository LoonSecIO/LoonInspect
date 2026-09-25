"""Initial finding backfill uses device observation history only when build history is missing (#608)."""

import os
from datetime import timedelta

import pytest
from sqlalchemy import delete

from app.core.content_keys import app_title_key
from app.core.findings import BASIS_BACKFILL, BASIS_OBSERVED, backfill_clocks
from app.models.schema import MdmConnection, ObservationSpan
from tests.test_findings_db import (
    CVE,
    DAY1,
    DAY2,
    DAY3,
    OTHER,
    SAFARI,
    WIRESHARK,
    _app,
    _arrival,
    _ledger,
    _sync,
    mac,  # noqa: F401 — shared fixture
)
from tests.test_sweep_costs_db import connection, statements  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


def span(device, at, **overrides):
    values = {
        "mdm_connection_id": device.mdm_connection_id,
        "subject_kind": "computer",
        "subject_id": device.external_id,
        "contract_version": "v1",
        "aperture_digest": "v1:backfill-aperture",
        "head_digest": "v1:backfill-head",
        "section_digests": {},
        "first_observed_at": at,
        "last_observed_at": at,
        "first_collected_at": DAY3,
        "last_collected_at": DAY3,
        "last_trigger": "sweep",
        "is_current": False,
    }
    return ObservationSpan(**(values | overrides))


def history_reads(seen):
    return [s for s in seen if s.lstrip().startswith("SELECT") and "observation_spans" in s]


async def test_initial_backfill_prefers_build_arrival_then_earliest_device_observation(db, mac):  # noqa: F811 — imported pytest fixture
    db.add_all([span(mac, DAY2, is_current=True), span(mac, DAY1)])
    # Latest arrival wins for this build; the device's earlier history is only the fallback.
    db.add_all([_arrival(mac, WIRESHARK, "4.2.0", at=DAY1), _arrival(mac, WIRESHARK, "4.2.0", at=DAY2)])
    await db.commit()
    apps = [_app(WIRESHARK, "4.2.0", [CVE]), _app(SAFARI, "18.0", [OTHER])]
    with statements() as seen:
        await _sync(db, mac, apps, DAY3)
    assert len(history_reads(seen)) == 1, "one fallback read for the device, not one per build or finding"
    rows = await _ledger(db, mac)
    wireshark, safari = rows[(app_title_key(*WIRESHARK), CVE)], rows[(app_title_key(*SAFARI), OTHER)]
    assert (wireshark.first_observed_at, wireshark.first_seen_basis) == (DAY2, BASIS_BACKFILL)
    assert (safari.first_observed_at, safari.first_seen_basis) == (DAY1, BASIS_BACKFILL)
    # The marker is the pod's clock at this first check, never the observation's DAY3 (#646).
    assert mac.findings_reconciled_at is not None and mac.findings_reconciled_at != DAY3
    # More history arriving later cannot rewrite existing findings or backdate a newly reported id.
    db.add(span(mac, DAY1 - timedelta(days=30)))
    await db.commit()
    later = DAY3 + timedelta(days=1)
    with statements() as seen:
        await _sync(db, mac, [apps[0], _app(SAFARI, "18.0", [OTHER, CVE])], later)
    assert history_reads(seen) == []
    rows = await _ledger(db, mac)
    assert rows[(app_title_key(*SAFARI), OTHER)].first_observed_at == DAY1
    added = rows[(app_title_key(*SAFARI), CVE)]
    assert (added.first_observed_at, added.first_seen_basis) == (later, BASIS_OBSERVED)


async def test_backfill_with_complete_arrival_history_does_not_query_observation_spans(db, mac):  # noqa: F811 — imported pytest fixture
    db.add_all([span(mac, DAY1), _arrival(mac, WIRESHARK, "4.2.0", at=DAY2)])
    await db.commit()
    with statements() as seen:
        await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE])], DAY3)
    assert history_reads(seen) == []
    (row,) = (await _ledger(db, mac)).values()
    assert (row.first_observed_at, row.first_seen_basis) == (DAY2, BASIS_BACKFILL)


@pytest.mark.parametrize("previously_clean", [False, True])
async def test_measured_findings_do_not_read_or_backfill_device_history(db, mac, previously_clean):  # noqa: F811 — imported pytest fixture
    db.add(span(mac, DAY1))
    await db.commit()
    with statements() as seen:
        if previously_clean:
            await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [])], DAY2)
        await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE])], DAY3, new=not previously_clean)
    assert history_reads(seen) == []
    (row,) = (await _ledger(db, mac)).values()
    assert (row.first_observed_at, row.first_seen_basis) == (DAY3, BASIS_OBSERVED)


async def test_fallback_ignores_other_subjects_connections_and_tenants(db, mac):  # noqa: F811 — imported pytest fixture
    from app.core.database import session_for_tenant
    from app.core.tenancy import ROOT_TENANT_ID

    other = MdmConnection(name="backfill neighbour", provider="jamf", base_url="https://backfill.test")
    db.add(other)
    await db.commit()
    other_id = other.id
    try:
        db.add_all(
            [
                span(mac, DAY1, subject_id="another-mac"),
                span(mac, DAY1, subject_kind="computer_group"),
                span(mac, DAY1, mdm_connection_id=other_id),
            ]
        )
        await db.commit()
        apps = [_app(WIRESHARK, "4.2.0", [CVE])]
        assert await backfill_clocks(db, device=mac, rows=apps) == {}
        db.add(span(mac, DAY2))
        await db.commit()
        async with session_for_tenant(ROOT_TENANT_ID) as other_tenant:
            assert await backfill_clocks(other_tenant, device=mac, rows=apps) == {}
        assert await backfill_clocks(db, device=mac, rows=apps) == {apps[0].key_full: DAY2}
    finally:
        await db.rollback()
        await db.execute(delete(MdmConnection).where(MdmConnection.id == other_id))
        await db.commit()
