"""The change log end to end: a sweep, then the device changes, then the rows and events
the policy keeps — against a real Postgres and the fake Jamf tenant.

What it pins: the OS update collapses Apple system-app bumps into one count; a user app
update is one `updated`; a new local admin and a firewall flip are `high`; a group joined
carries the two-cause flag; a low field (purchasing) is not logged by default but is
under the "everything" preset; one `device.change` outbox event per row, written in one
batched INSERT per subject (#568); the legacy inventory event still flows. Gated on
RUN_DB_TESTS.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import delete, event, func, select

from app.core.outbox import _build_body
from app.core.runs import pull_event_id
from app.core.wire import ENVELOPE, instance_label
from app.core.wire_vocabulary import CHANGE_EVENT_TYPE, SECTION_WRAPPERS
from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


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
        name=f"changes jamf {uuidlib.uuid4().hex[:8]}",
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
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))  # changes cascade
        await db.execute(delete(ChangePolicy))  # this tenant's policy row, so the next run starts from defaults
        await db.commit()


def _second_inventory(jamf: FakeJamf) -> dict:
    """The Mac mini a day later: macOS updated (and with it every system app), Slack
    updated, a new local admin, the firewall turned on, a smart group joined, and a PO
    number typed into purchasing."""
    real = jamf.real
    real["general"]["reportDate"] = "2026-08-23T09:00:00.000Z"
    real["operatingSystem"]["version"] = "27.1"
    real["operatingSystem"]["build"] = "26A5416b"
    real["operatingSystem"]["supplementalBuildVersion"] = "26A5416b"
    for app in real["applications"]:
        if app["path"].startswith("/System/"):
            app["cfBundleVersion"] = f"{app['cfBundleVersion']}.1" if app.get("cfBundleVersion") else "1.1"
    slack = next(a for a in real["applications"] if a["bundleId"] == "com.tinyspeck.slackmacgap")
    slack["version"] = slack["cfBundleShortVersionString"] = "4.51.0"
    slack["cfBundleVersion"] = "451000000"
    real["localUserAccounts"].append(
        {
            "uid": "503",
            "userGuid": None,
            "username": "contractor",
            "fullName": "Contractor",
            "admin": True,
            "userAccountType": "LOCAL",
            "homeDirectory": "/Users/contractor",
            "homeDirectorySizeMb": -1,
            "fileVault2Enabled": False,
            "passwordMinLength": 4,
            "passwordMaxAge": None,
            "passwordMinComplexCharacters": None,
            "passwordRequireAlphanumeric": False,
            "passwordHistoryDepth": None,
            "computerAzureActiveDirectoryId": None,
            "userAzureActiveDirectoryId": None,
            "azureActiveDirectoryId": None,
        }
    )
    real["security"]["firewallEnabled"] = True
    real["groupMemberships"].append({"groupId": "1", "groupName": "All Managed Clients", "smartGroup": True})
    real["groupMemberships"].append({"groupId": "12", "groupName": "Devices out of Checkin Compliance", "smartGroup": True})
    real["purchasing"]["poNumber"] = "PO-2026-0042"
    return real


async def _rows(db, connection_id: int, subject_id: str):
    from app.models.schema import DeviceChange

    return (
        (
            await db.execute(
                select(DeviceChange)
                .where(DeviceChange.mdm_connection_id == connection_id, DeviceChange.subject_id == subject_id)
                .order_by(DeviceChange.id)
            )
        )
        .scalars()
        .all()
    )


async def test_changes_are_derived_under_the_default_policy(db, connection, jamf: FakeJamf) -> None:
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import Device, EventOutbox

    first = await sync_connection(db, connection)
    assert first.ok and first.observations.get("new") == 2
    real_id = jamf.real["id"]
    assert await _rows(db, connection.id, real_id) == []  # a first observation is a baseline, not a change

    # Deduplicate the group membership the fixture already has for group 1.
    jamf.real["groupMemberships"] = [g for g in jamf.real["groupMemberships"] if g["groupId"] != "1"]
    _second_inventory(jamf)
    events_before = (
        await db.execute(select(func.count()).select_from(EventOutbox).where(EventOutbox.event_type == "device.change"))
    ).scalar_one()
    result = await ingest_webhook(
        db, connection, {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": real_id}}
    )
    assert result is not None and result.outcome == "changed"

    rows = await _rows(db, connection.id, real_id)
    by_key = {(r.section, r.field, r.entry_kind, r.change, json.dumps(r.entry_identity, sort_keys=True)): r for r in rows}

    # OS update: version + build + supplemental, with the system-app bumps collapsed into
    # the version row as a count rather than sixty rows of their own.
    os_version = next(r for r in rows if r.section == "operating_system" and r.field == "version")
    assert os_version.level == "high" and os_version.change == "changed"
    assert os_version.old_value == {"value": "27.0"} and os_version.new_value == {"value": "27.1"}
    assert os_version.details["systemAppsUpdated"] >= 60
    os_build = next(r for r in rows if r.section == "operating_system" and r.field == "build")
    assert os_build.old_value == {"value": "26A5378n"} and os_build.new_value == {"value": "26A5416b"}

    system_updates = [
        r
        for r in rows
        if r.entry_kind == "application"
        and r.change == "updated"
        and (r.entry_identity or {}).get("path", "").startswith("/System/")
    ]
    assert system_updates == [], "system apps must collapse into the OS update by default"

    slack = next(
        r
        for r in rows
        if r.entry_kind == "application" and (r.entry_identity or {}).get("bundleId") == "com.tinyspeck.slackmacgap"
    )
    assert slack.change == "updated" and slack.level == "normal"
    assert slack.old_value["version"] == "4.50.143" and slack.new_value["version"] == "4.51.0"
    assert set(slack.details["changedFields"]) == {"version", "cfBundleShortVersionString", "cfBundleVersion"}

    contractor = next(
        r for r in rows if r.entry_kind == "local_user_account" and (r.entry_identity or {}).get("username") == "contractor"
    )
    assert contractor.change == "added" and contractor.level == "high" and contractor.new_value["admin"] is True

    firewall = next(r for r in rows if r.section == "security" and r.field == "firewallEnabled")
    assert firewall.level == "high" and firewall.old_value == {"value": False} and firewall.new_value == {"value": True}

    joined = next(r for r in rows if r.entry_kind == "group_membership" and (r.entry_identity or {}).get("groupId") == "12")
    assert joined.change == "added" and joined.entry_label == "Devices out of Checkin Compliance"
    assert "criteriaChanged" in joined.details

    assert not any(r.section == "purchasing" for r in rows), "purchasing is low and off by default"

    events_after = (
        await db.execute(select(func.count()).select_from(EventOutbox).where(EventOutbox.event_type == "device.change"))
    ).scalar_one()
    assert events_after - events_before == len(rows)
    latest = (
        await db.execute(
            select(EventOutbox).where(EventOutbox.event_type == "device.change").order_by(EventOutbox.id.desc()).limit(1)
        )
    ).scalar_one()
    # camelCase with `ID` uppercased (#188). The device is named in `deviceMeta` and
    # nowhere else since #308: the root copies of `jamfProID` / `serialNumber` came off,
    # because the inventory sub-event has no root identity at all and a customer's bare
    # `serialNumber=` therefore matched changes and silently missed every inventory event.
    assert latest.payload["deviceMeta"]["jamfProID"] == real_id
    assert latest.payload["deviceMeta"]["serialNumber"] == "LOONMINI0M4"
    assert {"jamfProID", "serialNumber", "trigger", "connectionID", "comparison"} & set(latest.payload) == set()
    assert latest.payload["policyVersion"] == "v0"
    # `jamfUrl` went with them: the instance is the envelope's `source` below, which
    # costs no licence volume (app.core.wire's opening doctrine).
    assert "jamfUrl" not in latest.payload

    # The envelope. Before this, device.change shipped with none, so a change observed
    # at Jamf's reportDate landed at whatever moment Splunk accepted the delivery.
    hints = latest.payload[ENVELOPE]
    assert hints["source"] == instance_label(HOST) == "e2e.jamfcloud.com"
    # A webhook run stamps the device's own reportDate (app.core.runs.event_time), which
    # is exactly what the row's observed_at was parsed from — so a change and the
    # inventory event from the same pull sit at one `_time` rather than two.
    row = next(r for r in rows if r.section == "operating_system" and r.field == "version")
    assert hints["time"] == row.observed_at.timestamp()
    assert hints["time"] == datetime(2026, 8, 23, 9, 0, tzinfo=UTC).timestamp()
    # `host` is the same string the inventory family ships as deviceMeta.hostName —
    # read off the device row here so the two families cannot drift to two spellings.
    hostname = (
        await db.execute(select(Device.hostname).where(Device.mdm_connection_id == connection.id, Device.external_id == real_id))
    ).scalar_one()
    assert hints["host"] == hostname and hostname
    # And it is transport: popped for every destination before anything is delivered.
    body = _build_body(SimpleNamespace(type="splunk_hec"), latest.payload)
    assert body["host"] == hostname and body["time"] == hints["time"]
    assert ENVELOPE not in body["event"]
    assert _build_body(SimpleNamespace(type="webhook"), latest.payload).get(ENVELOPE) is None
    # The `:change` sourcetype (#223), on the webhook path — one entity's string, taken
    # from the wrapper table, and only for Splunk: a sourcetype is part of the delivery,
    # not part of the event.
    assert body["sourcetype"] == f"loon:jamf:mac:{SECTION_WRAPPERS[latest.payload['section']]}:change"
    assert "sourcetype" not in _build_body(SimpleNamespace(type="webhook"), latest.payload)
    # #189's block, on a webhook run: the same names and the same values the inventory
    # event from this pull carries, so a change joins to its pull on `deviceMeta.eventID`
    # rather than on jobID + jamfProID (#243, question 4).
    meta = latest.payload["deviceMeta"]
    assert meta["jamfProID"] == real_id and meta["serialNumber"] == "LOONMINI0M4" and meta["hostName"] == hostname
    assert meta["eventID"] == pull_event_id(uuidlib.UUID(latest.payload["jobID"]), "macos", real_id)
    assert meta["trigger"] == "webhook"
    assert all(r.span_id is not None and r.previous_span_id is not None for r in rows)
    assert by_key  # sanity


async def test_everything_preset_logs_low_fields_and_system_apps(db, connection, jamf: FakeJamf) -> None:
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import ChangePolicy

    db.add(ChangePolicy(version="v0", overrides={"minimumLevel": "low", "systemAppsIndividually": True}))
    await db.commit()

    await sync_connection(db, connection)
    real_id = jamf.real["id"]
    jamf.real["groupMemberships"] = [g for g in jamf.real["groupMemberships"] if g["groupId"] != "1"]
    _second_inventory(jamf)
    result = await ingest_webhook(
        db, connection, {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": real_id}}
    )
    assert result is not None and result.outcome == "changed"

    rows = await _rows(db, connection.id, real_id)
    assert any(r.section == "purchasing" and r.field == "poNumber" and r.level == "low" for r in rows)
    system_updates = [
        r
        for r in rows
        if r.entry_kind == "application"
        and r.change == "updated"
        and (r.entry_identity or {}).get("path", "").startswith("/System/")
    ]
    assert len(system_updates) >= 60


async def test_high_only_preset_drops_inventory_changes(db, connection, jamf: FakeJamf) -> None:
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import ChangePolicy

    db.add(ChangePolicy(version="v0", overrides={"minimumLevel": "high"}))
    await db.commit()

    await sync_connection(db, connection)
    real_id = jamf.real["id"]
    jamf.real["groupMemberships"] = [g for g in jamf.real["groupMemberships"] if g["groupId"] != "1"]
    _second_inventory(jamf)
    await ingest_webhook(db, connection, {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": real_id}})

    rows = await _rows(db, connection.id, real_id)
    assert rows and all(r.level == "high" for r in rows)
    assert not any(r.entry_kind == "application" for r in rows)
    assert any(r.field == "firewallEnabled" for r in rows)
    assert any(r.entry_kind == "local_user_account" for r in rows)
    assert not any(r.entry_kind == "group_membership" for r in rows)


# --- one batched write per subject (#568) ---------------------------------------------


@contextmanager
def _statements() -> Iterator[list[tuple[str, tuple]]]:
    """Every statement the engine sends while the block runs, with the parameters it bound.

    The parameters are the point. Every `event_outbox` INSERT reads alike as SQL — the inventory
    families write to the same table on the same pull — so what tells a batch from a round trip per
    row is how many `device.change` rows one statement carried, and that is only in the binds."""
    from app.core.database import engine

    sent: list[tuple[str, tuple]] = []

    def record(conn, cursor, statement, parameters, context, executemany) -> None:
        sent.append((statement, tuple(parameters or ())))

    event.listen(engine.sync_engine, "before_cursor_execute", record)
    try:
        yield sent
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record)


def _change_event_inserts(sent: list[tuple[str, tuple]]) -> list[int]:
    """How many `device.change` rows each `event_outbox` INSERT carried, in order — counting only the
    statements that carried any. The inventory and run families write to the same table on the same
    pull, one row at a time, and they are not what this measures."""
    carried = (binds.count(CHANGE_EVENT_TYPE) for statement, binds in sent if "INSERT INTO event_outbox" in statement)
    return [count for count in carried if count]


async def _high_water(db) -> int:
    from app.models.schema import EventOutbox

    return (await db.execute(select(func.max(EventOutbox.id)))).scalar() or 0


async def _change_events(db, floor: int) -> list:
    from app.models.schema import EventOutbox

    rows = await db.execute(
        select(EventOutbox).where(EventOutbox.id > floor, EventOutbox.event_type == CHANGE_EVENT_TYPE).order_by(EventOutbox.id)
    )
    return list(rows.scalars().all())


def _install_apps(jamf: FakeJamf, count: int) -> None:
    """`count` third-party apps arriving on the reference Mac at once — a new hire's first afternoon,
    or a Self Service bundle. Nothing else about the record moves, so every row this derives is one
    of these, and the count of rows is the count of apps."""
    jamf.real["applications"].extend(
        {
            "name": f"Loon Fixture {n}.app",
            "path": f"/Applications/Loon Fixture {n}.app",
            "version": "1.0",
            "cfBundleShortVersionString": "1.0",
            "cfBundleVersion": "1",
            "macAppStore": False,
            "sizeMegabytes": 1,
            "bundleId": f"io.loonsec.fixture{n}",
            "updateAvailable": False,
            "externalVersionId": "0",
        }
        for n in range(count)
    )


async def test_a_subjects_change_events_go_in_on_one_insert(db, connection, jamf: FakeJamf) -> None:
    """#568: a Mac that installed 64 apps writes 64 change events in ONE INSERT, not 64 of them.

    The rows are unchanged — one outbox event per kept change row, as they always were. What goes is
    the round trip each one cost inside that device's transaction, which fell on exactly the devices
    with the most to say. Sixty-four is well under the 1,000-row page `add_all` plus one flush becomes,
    so one statement is the whole batch here; the page boundary itself is `test_departure_db`'s (#524)."""
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import EventOutbox

    installed = 64
    assert (await sync_connection(db, connection)).ok
    real_id = jamf.real["id"]
    _install_apps(jamf, installed)

    floor = await _high_water(db)
    try:
        with _statements() as sent:
            result = await ingest_webhook(
                db, connection, {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": real_id}}
            )
        assert result is not None and result.outcome == "changed"
        rows = await _rows(db, connection.id, real_id)
        assert len(rows) == installed, "the fixture moved: these are meant to be the only changes in the pull"

        assert _change_event_inserts(sent) == [installed], "64 change events is one batched INSERT, not one per row"
        assert len(await _change_events(db, floor)) == installed, "cheaper, not fewer: every kept row still has its event"
    finally:
        await db.execute(delete(EventOutbox).where(EventOutbox.id > floor))
        await db.commit()


async def test_the_batched_events_are_what_the_per_row_path_wrote(db, connection, jamf: FakeJamf, monkeypatch) -> None:
    """A change of writer, not of content. The producer hands one list of payloads; the batched twin
    and the `enqueue_event` loop it replaced are run against that same list, and the rows they leave
    are compared type for type, payload for payload, in order. A batching seam that reordered or
    dropped a payload would pass every count in the suite and be invisible until a customer's search
    came back short."""
    from app.changes import derive
    from app.core.outbox import enqueue_event, enqueue_events
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import EventOutbox

    handed: list[tuple[str, list[dict], str | None]] = []

    async def spy(session, event_type, payloads, *, request_id=None):
        handed.append((event_type, list(payloads), request_id))
        return await enqueue_events(session, event_type, payloads, request_id=request_id)

    monkeypatch.setattr(derive, "enqueue_events", spy)
    assert (await sync_connection(db, connection)).ok
    real_id = jamf.real["id"]
    _install_apps(jamf, 8)

    floor = await _high_water(db)
    try:
        result = await ingest_webhook(
            db, connection, {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": real_id}}
        )
        assert result is not None and result.outcome == "changed"
        await db.commit()
        assert len(handed) == 1, "one call per subject, whatever it derived"
        event_type, payloads, request_id = handed[0]
        assert event_type == CHANGE_EVENT_TYPE and len(payloads) == 8

        batched = await _change_events(db, floor)
        assert [e.payload for e in batched] == payloads, "same payloads, same order as the producer built them"

        mark = await _high_water(db)
        for payload in payloads:
            await enqueue_event(db, event_type, payload, request_id=request_id)
        await db.commit()
        per_row = await _change_events(db, mark)
        assert [(e.event_type, e.payload, e.request_id) for e in batched] == [
            (e.event_type, e.payload, e.request_id) for e in per_row
        ]
    finally:
        await db.execute(delete(EventOutbox).where(EventOutbox.id > floor))
        await db.commit()
