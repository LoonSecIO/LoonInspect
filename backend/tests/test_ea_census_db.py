"""The extension-attribute census (#178), through the paths that take it.

Definitions are observed in the catalog pass — the sweep's, and the catalog class on its
own — as their own subject, so a definition's departure has something to be absent from
(#181). The one thing the fetch must never do is read a refusal as an empty census:
a tenant whose client cannot read the endpoint skips the census and says so.

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

KIND = "extension_attribute_definition"


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """A Jamf connection, removed with everything under it afterwards; the spans and
    apertures cascade in the database."""
    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"ea census {uuidlib.uuid4().hex[:8]}",
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


async def _definition_spans(db, connection_id: int) -> dict[str, list]:
    """Current definition spans under the connection, by definition id."""
    from app.models.schema import ObservationSpan

    rows = (
        (
            await db.execute(
                select(ObservationSpan)
                .where(ObservationSpan.mdm_connection_id == connection_id, ObservationSpan.subject_kind == KIND)
                .order_by(ObservationSpan.id)
            )
        )
        .scalars()
        .all()
    )
    by_id: dict[str, list] = {}
    for row in rows:
        by_id.setdefault(row.subject_id, []).append(row)
    return by_id


async def test_a_sweep_records_every_definition_as_a_subject(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import sync_connection

    result = await sync_connection(db, connection)
    assert result.ok, result
    assert result.observations["ea_definition_new"] == 3
    spans = await _definition_spans(db, connection.id)
    assert set(spans) == {"5", "12", "27"}
    assert all(len(history) == 1 for history in spans.values())
    assert spans["27"][0].label == "Departments Served"
    assert "GET /api/v1/computer-extension-attributes" in jamf.requests

    # The same census again is unchanged for every definition — a definition carries no
    # observed-at of its own, so a later read of identical content extends the span the
    # way a group's does — and opens nothing.
    again = await sync_connection(db, connection)
    assert again.ok and again.observations.get("ea_definition_new") is None
    assert again.observations.get("ea_definition_unchanged") == 3
    assert all(len(history) == 1 for history in (await _definition_spans(db, connection.id)).values())


async def test_the_catalog_class_takes_the_census_too(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import run_jamf_catalog

    result = await run_jamf_catalog(db, connection, trigger="manual")
    assert result.ok, result
    assert result.observations["ea_definition_new"] == 3
    assert set(await _definition_spans(db, connection.id)) == {"5", "12", "27"}


async def test_a_change_to_meaning_opens_a_span_and_a_rename_does_not(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import sync_connection

    assert (await sync_connection(db, connection)).ok
    battery = next(d for d in jamf.extension_attribute_definitions if d["id"] == "5")
    battery["name"] = "Battery Cycles"
    renamed = await sync_connection(db, connection)
    assert renamed.ok and renamed.observations.get("ea_definition_changed") is None
    battery["enabled"] = False
    disabled = await sync_connection(db, connection)
    assert disabled.ok and disabled.observations.get("ea_definition_changed") == 1
    spans = await _definition_spans(db, connection.id)
    assert len(spans["5"]) == 2 and len(spans["12"]) == 1
    assert spans["5"][-1].label == "Battery Cycles", "the label follows the rename; the span did not"


async def test_a_refused_read_skips_the_census_rather_than_reading_it_as_empty(db, jamf: FakeJamf, connection) -> None:
    """The guard #181's circuit breaker stands on: None, never an empty list, so nothing
    downstream can take "not allowed to look" for "every definition departed at once"."""
    from app.mdm.service import sync_connection

    jamf.extension_attribute_definitions = None
    result = await sync_connection(db, connection)
    assert result.ok and result.device_count == 2, result
    assert not any(key.startswith("ea_definition_") for key in result.observations)
    assert await _definition_spans(db, connection.id) == {}
    assert result.observations.get("group_new") == 1, "the groups' census still ran"
