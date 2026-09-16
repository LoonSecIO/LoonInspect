"""Objects depart (#181): a smart group or an extension-attribute definition absent from a
clean census is gone, as derived state on the object — and the circuit breaker that keeps
a refused or collapsed census from departing everyone at once.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

from tests.jamf_fake import HOST, FakeJamf  # noqa: E402

GROUP = "computer_group"
DEFINITION = "extension_attribute_definition"
COMPUTER = "computer"


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """A Jamf connection, removed with everything under it afterwards; spans, apertures
    and departures cascade in the database."""
    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"departure {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def _departures(db, connection_id: int, kind: str) -> list:
    from app.models.schema import SubjectDeparture

    return (
        (
            await db.execute(
                select(SubjectDeparture)
                .where(SubjectDeparture.mdm_connection_id == connection_id, SubjectDeparture.subject_kind == kind)
                .order_by(SubjectDeparture.id)
            )
        )
        .scalars()
        .all()
    )


def _group(index: int) -> dict:
    return {"id": str(100 + index), "name": f"Rollout wave {index}", "siteId": "-1", "criteria": []}


async def test_a_deleted_group_departs_once_and_returns_when_it_is_named_again(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import run_jamf_catalog, sync_connection
    from app.models.schema import ObservationSpan

    jamf.smart_groups.append(_group(1))
    assert (await sync_connection(db, connection)).ok
    assert await _departures(db, connection.id, GROUP) == []

    # Deleted in Jamf: absent from the next census, gone — and its span is untouched.
    jamf.smart_groups = [group for group in jamf.smart_groups if group["id"] != "101"]
    catalog = await run_jamf_catalog(db, connection, trigger="manual")
    assert catalog.ok, catalog
    (gone,) = await _departures(db, connection.id, GROUP)
    assert gone.subject_id == "101" and gone.returned_at is None and gone.departed_at is not None
    span = (
        await db.execute(
            select(ObservationSpan).where(
                ObservationSpan.mdm_connection_id == connection.id,
                ObservationSpan.subject_kind == GROUP,
                ObservationSpan.subject_id == "101",
            )
        )
    ).scalar_one()
    assert span.is_current is True, "absence opens and closes no span"

    # The next census finds it gone again and writes nothing new.
    assert (await run_jamf_catalog(db, connection, trigger="manual")).ok
    assert len(await _departures(db, connection.id, GROUP)) == 1

    # Recreated with the same id: the return closes the row; a second deletion is a second row.
    jamf.smart_groups.append(_group(1))
    assert (await run_jamf_catalog(db, connection, trigger="manual")).ok
    (returned,) = await _departures(db, connection.id, GROUP)
    assert returned.returned_at is not None
    jamf.smart_groups = [group for group in jamf.smart_groups if group["id"] != "101"]
    assert (await run_jamf_catalog(db, connection, trigger="manual")).ok
    rows = await _departures(db, connection.id, GROUP)
    assert len(rows) == 2 and rows[-1].returned_at is None and rows[0].returned_at is not None


async def test_a_deleted_definition_departs_and_a_refused_read_departs_nobody(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import sync_connection

    assert (await sync_connection(db, connection)).ok
    jamf.extension_attribute_definitions = [d for d in jamf.extension_attribute_definitions if d["id"] != "12"]
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, DEFINITION)
    assert gone.subject_id == "12"

    # Not allowed to look is not "everything departed": the open row stays as it was.
    jamf.extension_attribute_definitions = None
    assert (await sync_connection(db, connection)).ok
    rows = await _departures(db, connection.id, DEFINITION)
    assert [row.subject_id for row in rows] == ["12"] and rows[0].returned_at is None


async def test_an_empty_census_departs_nobody(db, jamf: FakeJamf, connection) -> None:
    """`fetch_smart_groups` answers an empty list for a lost privilege as well as for a
    tenant with no groups; the zero rule is what keeps that from departing every group."""
    from app.mdm.service import sync_connection

    assert (await sync_connection(db, connection)).ok
    jamf.smart_groups = []
    result = await sync_connection(db, connection)
    assert result.ok and result.observations.get("group_new") is None
    assert await _departures(db, connection.id, GROUP) == []


async def test_a_collapsed_census_departs_nobody_but_a_real_deletion_still_does(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import sync_connection
    from app.observations.departure import COLLAPSE_RATIO, MIN_POPULATION_FOR_COLLAPSE

    jamf.smart_groups = [_group(i) for i in range(MIN_POPULATION_FOR_COLLAPSE + 2)]
    assert (await sync_connection(db, connection)).ok
    population = len(jamf.smart_groups)

    # Fewer than half named: refused, and nobody departs.
    jamf.smart_groups = jamf.smart_groups[: int(population * COLLAPSE_RATIO) - 1]
    assert (await sync_connection(db, connection)).ok
    assert await _departures(db, connection.id, GROUP) == []

    # All but one named: one real deletion, and it departs.
    jamf.smart_groups = [_group(i) for i in range(1, population)]
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, GROUP)
    assert gone.subject_id == _group(0)["id"]


async def test_the_cost_page_says_which_group_is_gone(db, jamf: FakeJamf, connection) -> None:
    from app.api.smart_groups import smart_group_cost
    from app.mdm.service import run_jamf_catalog, sync_connection

    jamf.smart_groups.append(_group(7))
    assert (await sync_connection(db, connection)).ok
    jamf.smart_groups = [group for group in jamf.smart_groups if group["id"] != "107"]
    assert (await run_jamf_catalog(db, connection, trigger="manual")).ok

    board = await smart_group_cost(db=db)
    by_id = {item.id: item for item in board.items if item.mdm_connection_id == connection.id}
    assert by_id["107"].departed_at is not None, "still listed — its definition is current — and marked gone"
    assert by_id["1"].departed_at is None


# --- a Mac is its own category (#183) ------------------------------------------------------


async def test_a_deleted_mac_departs_on_a_clean_census_and_a_return_closes_the_row(db, jamf: FakeJamf, connection) -> None:
    """The sweep is the heartbeat: a census closes a sweep that succeeded, carried no
    selector and lost no device, and a Mac it did not name is gone."""
    from app.mdm.service import sync_connection

    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await sync_connection(db, connection)).ok
    assert await _departures(db, connection.id, COMPUTER) == []

    jamf._extra = []
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)
    assert gone.subject_id == clone["id"] and gone.returned_at is None and gone.departed_at is not None

    # Re-enrolled under the same Jamf id inside the tail: named again, so the row closes
    # and the Mac was never out of the fleet.
    jamf._extra = [clone]
    assert (await sync_connection(db, connection)).ok
    (returned,) = await _departures(db, connection.id, COMPUTER)
    assert returned.returned_at is not None


async def test_a_scoped_sweep_and_one_device_failure_depart_nobody(db, jamf: FakeJamf, connection, monkeypatch) -> None:
    """Rider 1: only a clean census judges. A scoped sweep never asked about the Macs its
    selector excluded, and a failed ingest leaves a stale `last_seen_at` through no fault
    of Jamf's."""
    from app.mdm import service

    jamf.seed(1)
    assert (await service.run_jamf(db, connection, trigger="sweep")).ok
    jamf._extra = []  # deleted in Jamf, and about to be unprovable twice over

    scoped = await service.run_jamf(db, connection, trigger="sweep", selector="general.remoteManagement.managed==true")
    assert scoped.ok, scoped
    assert await _departures(db, connection.id, COMPUTER) == [], "a scoped sweep is not a census"

    ingest = service.ingest_computer

    async def one_bad_device(session, conn, raw, **kwargs):
        if raw.get("id") == jamf.real["id"]:
            raise RuntimeError("ingest failed for this device")
        return await ingest(session, conn, raw, **kwargs)

    monkeypatch.setattr(service, "ingest_computer", one_bad_device)
    dirty = await service.run_jamf(db, connection, trigger="sweep")
    assert dirty.ok and dirty.devices_failed == 1, dirty
    assert await _departures(db, connection.id, COMPUTER) == [], "one failed device, and nobody departs"


async def test_a_stale_read_stamps_presence_and_keeps_the_mac_in_the_census(db, jamf: FakeJamf, connection) -> None:
    """Rider 3: the monotonic guard is about content, not existence. A read Jamf answered
    marks the Mac present even when the ledger refuses what it says."""
    from app.mdm.service import sync_connection
    from app.models.schema import Device, ObservationSpan

    assert (await sync_connection(db, connection)).ok
    external_id = jamf.real["id"]
    mine = (ObservationSpan.mdm_connection_id == connection.id, ObservationSpan.subject_id == external_id)
    device = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == external_id))
    ).scalar_one()
    span = (await db.execute(select(ObservationSpan).where(*mine, ObservationSpan.is_current.is_(True)))).scalar_one()
    # The ledger has already seen something newer than the next read carries, so that read
    # is refused before `process_sync` ever runs.
    span.last_observed_at = datetime.now(UTC) + timedelta(days=1)
    device.last_seen_at = datetime(2020, 1, 1, tzinfo=UTC)
    await db.commit()

    result = await sync_connection(db, connection)
    assert result.ok and result.observations.get("stale") == 1, result.observations
    await db.refresh(device)
    assert device.last_seen_at > datetime(2020, 1, 2, tzinfo=UTC), "the read reached us, so the Mac is here"
    assert await _departures(db, connection.id, COMPUTER) == [], "a stale-skipped read is presence"


async def test_the_breaker_refuses_a_collapsed_device_census(db, jamf: FakeJamf, connection) -> None:
    """The module's breaker, over Macs: a sweep that paged short cannot depart a fleet."""
    from app.mdm.service import sync_connection
    from app.observations.departure import COLLAPSE_RATIO, MIN_POPULATION_FOR_COLLAPSE

    jamf.seed(MIN_POPULATION_FOR_COLLAPSE - 2)  # the two fixture records round out the population
    clones = list(jamf._extra)
    assert (await sync_connection(db, connection)).ok

    jamf._extra = clones[: int(MIN_POPULATION_FOR_COLLAPSE * COLLAPSE_RATIO) - 3]
    assert (await sync_connection(db, connection)).ok
    assert await _departures(db, connection.id, COMPUTER) == [], "fewer than half named is a short read, not a mass deletion"

    jamf._extra = clones[1:]
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)
    assert gone.subject_id == clones[0]["id"]
