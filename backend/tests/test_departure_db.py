"""Objects depart (#181): a smart group or an extension-attribute definition absent from a
clean census is gone, as derived state on the object — and the circuit breaker that keeps
a refused or collapsed census from departing everyone at once.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib

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
        await db.execute(
            select(SubjectDeparture)
            .where(SubjectDeparture.mdm_connection_id == connection_id, SubjectDeparture.subject_kind == kind)
            .order_by(SubjectDeparture.id)
        )
    ).scalars().all()


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
