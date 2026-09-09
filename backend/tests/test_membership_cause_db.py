"""`criteriaChanged` on a group-membership change is judged against *this* sweep's
definitions (#136).

`_membership_cause` asks whether the group's current definition span opened after the
device was last observed. The sweep used to observe group definitions after the device
loop, so during the loop the current span was still the pre-edit one and every membership
change a criteria edit had caused since the last catalog observation read as device drift.
The only test of the key asserted that it existed, not what it said.

Two sweeps after the baseline: one where the group's criteria moved and the device joined
(criteria changed), one where nothing but the device moved (drift). Report dates are set
by hand on either side of the group observation, because a device span is stamped with
Jamf's `reportDate` while a group span is stamped with our clock, and the comparison is
between the two.

Needs a real Postgres and the fake Jamf tenant, like the other sweep suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

GROUP = "1"  # the fake tenant's one smart group, "All Managed Clients"


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    from app.models.schema import (
        ChangePolicy,
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"membership cause {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
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
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))  # changes cascade
        await db.execute(delete(ChangePolicy))
        await db.commit()


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _report(jamf: FakeJamf, at: datetime) -> None:
    jamf.real["general"]["reportDate"] = _stamp(at)


async def _membership_rows(db, connection_id: int, subject_id: str) -> list:
    from app.models.schema import DeviceChange

    rows = (
        await db.execute(
            select(DeviceChange)
            .where(DeviceChange.mdm_connection_id == connection_id, DeviceChange.subject_id == subject_id)
            .order_by(DeviceChange.id)
        )
    ).scalars().all()
    return [r for r in rows if r.entry_kind == "group_membership" and (r.entry_identity or {}).get("groupId") == GROUP]


async def test_a_membership_moved_by_a_criteria_edit_says_so_and_drift_does_not(db, connection, jamf: FakeJamf) -> None:
    from app.mdm.service import sync_connection

    real_id = jamf.real["id"]
    # Baseline: the Mac is not in the group. Jamf's reportDate a minute ago — before the
    # group definition this sweep will observe.
    jamf.real["groupMemberships"] = [g for g in jamf.real["groupMemberships"] if g["groupId"] != GROUP]
    _report(jamf, datetime.now(timezone.utc) - timedelta(minutes=1))
    first = await sync_connection(db, connection)
    assert first.ok and first.group_count == 1
    assert await _membership_rows(db, connection.id, real_id) == []

    # The admin edits the group's criteria, and the Mac is now a member. The reportDate
    # sits *after* the instant the sweep will observe the new definition, so the third
    # sweep below has a device observation newer than the definition to compare against.
    jamf.smart_group_criteria = [
        {"name": "Managed", "priority": 0, "andOr": "and", "searchType": "is", "value": "Managed"},
        {"name": "Operating System Version", "priority": 1, "andOr": "and", "searchType": "like", "value": "27."},
    ]
    jamf.real["groupMemberships"].append({"groupId": GROUP, "groupName": "All Managed Clients", "smartGroup": True})
    _report(jamf, datetime.now(timezone.utc) + timedelta(seconds=10))
    second = await sync_connection(db, connection)
    assert second.ok and second.observations.get("group_changed") == 1

    (joined,) = await _membership_rows(db, connection.id, real_id)
    assert joined.change == "added"
    assert joined.details["criteriaChanged"] is True, joined.details
    assert joined.details["groupDefinitionSpanId"]

    # Nothing moves but the Mac: it leaves the group under the same definition.
    jamf.real["groupMemberships"] = [g for g in jamf.real["groupMemberships"] if g["groupId"] != GROUP]
    _report(jamf, datetime.now(timezone.utc) + timedelta(seconds=20))
    third = await sync_connection(db, connection)
    assert third.ok and third.observations.get("group_changed") is None

    joined, left = await _membership_rows(db, connection.id, real_id)
    assert left.change == "removed"
    assert left.details["criteriaChanged"] is False, left.details
    assert left.details["groupDefinitionSpanId"] == joined.details["groupDefinitionSpanId"]


async def test_the_sweep_observes_the_definitions_before_the_first_device(db, connection, jamf: FakeJamf) -> None:
    """The order itself, read off the fake tenant's request log: the smart-group reads
    come before the first inventory page. A future reordering that put them back after
    the loop would pass the test above only by luck of the fixture's clocks."""
    from app.mdm.service import sync_connection

    _report(jamf, datetime.now(timezone.utc) - timedelta(minutes=1))
    assert (await sync_connection(db, connection)).ok
    paths = list(jamf.requests)
    first_group_read = next(i for i, path in enumerate(paths) if "smart-groups" in path)
    first_inventory_read = next(i for i, path in enumerate(paths) if "computers-inventory" in path)
    assert first_group_read < first_inventory_read, paths
