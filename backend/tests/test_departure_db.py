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
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

from tests.jamf_fake import HOST, FakeJamf  # noqa: E402

GROUP = "computer_group"
DEFINITION = "extension_attribute_definition"
COMPUTER = "computer"
_ROOT = Path(__file__).resolve().parents[2]
_BOTH = ((_ROOT / "backend/app/mdm/service.py").read_text(), (_ROOT / "docs/troubleshooting.md").read_text())


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
    # Recognised as itself, so there is no other id to name (#475).
    assert returned.matched_by == "jamfProID" and returned.prior_jamf_pro_id is None


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

    # A refusal and a healthy census are different sentences on the run log, and troubleshooting
    # path 16 quotes both (`diagnosability.md` rules 1, 2 and 4): reword one and this breaks first.
    for phrase in ("device census not taken", "device census refused: ", "fewer than half the fleet", "no Macs at all"):
        assert all(phrase in text for text in _BOTH), phrase


# --- a Mac that comes back is the same Mac (#475) -------------------------------------------
async def _in_the_fleet(db, connection_id: int, at: datetime) -> set[str]:
    """The Macs **Devices** lists and the Overview counts at `at`, through the list's own predicate."""
    from app.models.schema import Device
    from app.observations.departure import gone_for_good

    here = ~gone_for_good(Device.mdm_connection_id, Device.external_id, at=at)
    listed = select(Device.external_id).where(Device.mdm_connection_id == connection_id, here)
    return set((await db.execute(listed)).scalars().all())


async def _census_lines(db, connection_id: int) -> list[str]:
    from app.models.schema import Run, RunLogLine

    query = select(RunLogLine.message).join(Run, RunLogLine.run_id == Run.id).where(Run.mdm_connection_id == connection_id)
    return [line for line in (await db.execute(query.order_by(RunLogLine.id))).scalars().all() if "device census" in line]


def _re_enrolled(clone: dict) -> dict:
    """The same Mac after a wipe or a rebuild: a new computer id, the same board — so both hardware
    keys survive, which is §3's duplicate-record shape and not a new device."""
    reborn = json.loads(json.dumps(clone))
    reborn["id"] = f"8{uuidlib.uuid4().hex[:8]}"
    return reborn


async def test_a_mac_back_under_a_new_jamf_id_closes_its_departure_by_serial(db, jamf: FakeJamf, connection) -> None:
    """Kyle's R3: re-enrolment is the ordinary way a Mac returns, and it always brings a new
    computer id — matched on that alone the row never closes and the Mac leaves from a desk."""
    from app.mdm.service import sync_connection

    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await sync_connection(db, connection)).ok
    jamf._extra = []
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)
    assert gone.returned_at is None and gone.matched_by is None

    reborn = _re_enrolled(clone)
    jamf._extra = [reborn]
    assert (await sync_connection(db, connection)).ok
    await db.refresh(gone)
    assert gone.returned_at is not None, "same serial, same UDID, same connection is the same Mac"
    # Re-keyed to the life it came back under, naming — and retiring — the id it departed under.
    assert gone.matched_by == "serialNumber" and gone.subject_id == reborn["id"] != clone["id"]
    assert gone.prior_jamf_pro_id == clone["id"]
    assert any("1 by serial, under a new Jamf id" in line for line in await _census_lines(db, connection.id))

    # And the dead id stays dead: nothing in the ledger closes its span, so a population still counting
    # it would depart it again next census and close it again the pass after, forever.
    for _ in range(3):
        assert (await sync_connection(db, connection)).ok
    (still,) = await _departures(db, connection.id, COMPUTER)
    assert still.id == gone.id and still.returned_at is not None, "one departure, closed, and no second"
    assert clone["id"] in await _in_the_fleet(db, connection.id, still.departed_at), "in its tail, not erased"
    assert clone["id"] not in await _in_the_fleet(db, connection.id, still.departed_at + timedelta(days=8))

    # But dead is Jamf's to say: a census naming that id takes the retirement back, or a reused id — or
    # one serial on two records — strands a live Mac outside the fleet under a page saying it is back.
    jamf._extra = [clone, reborn]
    for _ in range(2):
        assert (await sync_connection(db, connection)).ok
    (back,) = await _departures(db, connection.id, COMPUTER)
    assert back.subject_id == clone["id"] and back.prior_jamf_pro_id is None and back.matched_by == "jamfProID"
    assert {clone["id"], reborn["id"]} <= await _in_the_fleet(db, connection.id, back.departed_at + timedelta(days=8))


async def test_a_board_swap_keeps_the_serial_and_is_not_a_return(db, jamf: FakeJamf, connection) -> None:
    """The two hardware keys fail in different directions (§3): a logic-board repair keeps the serial
    and *changes* the UDID, so same serial under a new UDID is a lineage event, not this Mac back."""
    from app.mdm.service import sync_connection

    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await sync_connection(db, connection)).ok
    jamf._extra = []
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)

    swapped = _re_enrolled(clone) | {"udid": str(uuidlib.uuid4()).upper()}
    jamf._extra = [swapped]
    assert (await sync_connection(db, connection)).ok
    await db.refresh(gone)
    assert gone.returned_at is None and gone.matched_by is None, "a new board is not a return"
    assert any("0 by serial, under a new Jamf id" in line for line in await _census_lines(db, connection.id))


async def test_a_census_without_hardware_matches_on_the_id_alone_and_says_which(db, jamf: FakeJamf, connection) -> None:
    """The aperture caveat: no `hardware` is no serial to census with, so a re-enrolled Mac is not
    recognised and the line says so, never the healthy sentence over a narrower match (rule 2)."""
    from app.mdm import service
    from app.models.schema import Collection

    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await service.sync_connection(db, connection)).ok
    narrow = [s for s in service.V0_SECTIONS if s not in {"hardware", "extension_attributes"}]
    await db.execute(update(Collection).where(Collection.mdm_connection_id == connection.id).values(sections=narrow))
    await db.commit()

    jamf._extra = []
    assert (await service.sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)

    jamf._extra = [_re_enrolled(clone)]
    assert (await service.sync_connection(db, connection)).ok
    await db.refresh(gone)
    assert gone.returned_at is None, "no serial in this census, so nothing to recognise it by"
    lines = await _census_lines(db, connection.id)
    assert any(service._MATCHED_BY_ID_ONLY in line for line in lines), lines
    # Path 16 quotes both (the second to its colon, where the doc wraps): reword one and this fails.
    for phrase in (service._MATCHED_BY_ID_AND_SERIAL, service._MATCHED_BY_ID_ONLY.split(":")[0]):
        assert all(phrase in text for text in _BOTH), phrase


async def test_a_serial_carried_by_another_connection_closes_nothing(db, jamf: FakeJamf, connection) -> None:
    """Two Jamf Pro servers hand out the same small computer ids, so the lookup is connection-scoped."""
    from app.mdm.service import sync_connection
    from app.models.schema import MdmConnection, ObservationSpan
    from app.observations.departure import reconcile_census

    jamf.seed(1)
    assert (await sync_connection(db, connection)).ok
    jamf._extra = []
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)

    other = MdmConnection(name=f"other {uuidlib.uuid4().hex[:8]}", provider="jamf", base_url=HOST, credentials_encrypted="{}")
    db.add(other)
    await db.commit()
    # The same small computer id on that other Jamf Pro, carrying hardware keys of its own.
    now = datetime.now(UTC)
    clocks = dict.fromkeys(("first_observed_at", "last_observed_at", "first_collected_at", "last_collected_at"), now)
    span = {"subject_kind": COMPUTER, "subject_id": gone.subject_id, "udid": "U1", "serial_number": "X1"}
    digests = {"aperture_digest": "a", "head_digest": "h", "section_digests": {}, "last_trigger": "s", "contract_version": "v0"}
    db.add(ObservationSpan(mdm_connection_id=other.id, **span, **digests, **clocks))
    await db.commit()
    ids = [jamf.real["id"], jamf.synthetic["id"]]
    census = {"connection_id": connection.id, "subject_kind": COMPUTER, "observed_ids": ids, "at": now}
    verdict = await reconcile_census(db, **census, observed_lineage={("X1", "U1"): "77001"})
    await db.commit()
    await db.refresh(gone)
    assert gone.returned_at is None and verdict.returned_by_serial == 0
    await db.execute(delete(MdmConnection).where(MdmConnection.id == other.id))
    await db.commit()


# --- the wire (#179): two types, one sourcetype, the ruled bodies -------------------


async def _events(db, high_water: int, event_type: str) -> list:
    from app.models.schema import EventOutbox

    rows = await db.execute(
        select(EventOutbox).where(EventOutbox.id > high_water, EventOutbox.event_type == event_type).order_by(EventOutbox.id)
    )
    return list(rows.scalars().all())


async def _high_water(db) -> int:
    from sqlalchemy import func

    from app.models.schema import EventOutbox

    return (await db.execute(select(func.coalesce(func.max(EventOutbox.id), 0)))).scalar_one()


async def test_a_departed_group_emits_the_ruled_body_and_a_return_closes_it_on_departed_at(
    db, jamf: FakeJamf, connection
) -> None:
    """The group case of 4.3 and the return of 4.6, on the rows the outbox actually holds.

    Asserted on the stored payload rather than on the builder, because the event has to land
    in the same transaction as the departure row: a builder test would pass even if the
    emitter were never called at all.

    The group departed is the one this fixture's Mac belongs to, so `deviceCount` exercises
    the two-hop ledger read rather than returning a zero that any bug would also return. A
    second group is added first and left alone — an EMPTY census departs nobody by design.
    """
    from types import SimpleNamespace

    from app.core.outbox import _build_body
    from app.core.wire import ENVELOPE
    from app.core.wire_vocabulary import DEPARTURE_SOURCETYPE, ordered_event_keys
    from app.mdm.service import sync_connection

    jamf.smart_groups.append(_group(1))
    assert (await sync_connection(db, connection)).ok
    mark = await _high_water(db)

    jamf.smart_groups = [group for group in jamf.smart_groups if group["id"] != "1"]
    assert (await sync_connection(db, connection)).ok
    (event,) = await _events(db, mark, "subject.departure")
    body = event.payload

    assert set(body) - {ENVELOPE} == {
        "subjectKind",
        "subjectLabel",
        "state",
        "noticeDay",
        "departedAt",
        "occurredAt",
        "lastSeenAt",
        "deviceCount",
        "event",
        "jobID",
        "deviceMeta",
    }
    # `event_outbox.payload` is jsonb and Postgres normalises key order, so what a delivery
    # can promise is the trailing three (#286) — the family's own keys lead, then these.
    assert list(ordered_event_keys({key: value for key, value in body.items() if key != ENVELOPE}))[-3:] == [
        "event",
        "jobID",
        "deviceMeta",
    ]
    assert body["subjectKind"] == GROUP and body["subjectLabel"] == "All Managed Clients"
    assert body["state"] == "departed" and body["noticeDay"] == 1
    assert body["departedAt"] == body["occurredAt"]
    # LoonInspect's own count, read out of the ledger — Jamf cannot be asked for a group it
    # no longer has. Exactly ONE of this fixture's two Macs carries group `1`: the real record
    # is in `All Managed Clients` and the synthetic one is in `3`/`17`/`40`. `>= 1` would pass
    # just as well for a read that counted the fleet and ignored the membership, which is the
    # bug worth catching — a SIEM reading `deviceCount` reads it as "Macs that carried this".
    assert body["deviceCount"] == 1, "the two ledger hops, not a count of every current Mac"
    # The object half of `deviceMeta`: the run half, the object's own id, the schema — and no
    # eventID, no hostName, no serialNumber, because a group is not a Mac and was not pulled.
    assert set(body["deviceMeta"]) == {"jobID", "trigger", "connectionID", "shortDate", "jamfProID", "schemaVersion"}
    assert body["deviceMeta"]["jamfProID"] == "1" and body["deviceMeta"]["jobID"] == body["jobID"]
    # `host` absent, `source` the instance — the ruling that keeps a group's name out of `host`.
    assert "host" not in body[ENVELOPE] and body[ENVELOPE]["source"]
    assert _build_body(SimpleNamespace(type="splunk_hec"), body)["sourcetype"] == DEPARTURE_SOURCETYPE
    assert "sourcetype" not in _build_body(SimpleNamespace(type="webhook"), body)

    # The return is its own type (#135 R3) and repeats the departure it closes verbatim, so
    # pairing is exact under repetition rather than "the most recent open departure".
    mark = await _high_water(db)
    jamf.smart_groups.append({"id": "1", "name": "All Managed Clients", "siteId": "-1"})
    assert (await sync_connection(db, connection)).ok
    (back,) = await _events(db, mark, "subject.returned")
    assert back.payload["departedAt"] == body["departedAt"]
    assert back.payload["absentForDays"] == 0 and back.payload["matchedBy"] == "jamfProID"
    # No `priorJamfProID` — that is the Mac's wipe-and-re-enrol case — and no `eventID`,
    # because an object's return coincides with a census, not with a pull of that object.
    assert "priorJamfProID" not in back.payload and "eventID" not in back.payload["deviceMeta"]
    assert _build_body(SimpleNamespace(type="splunk_hec"), back.payload)["sourcetype"] == DEPARTURE_SOURCETYPE
    # The casing law, on the one type the cross-family suite cannot reach: a return needs a
    # THIRD census (depart, then come back), and `test_wire_casing`'s fixture runs two sweeps.
    # So the predicate is borrowed rather than reimplemented — one spelling of the law, and a
    # `subject_kind` or `absentFor_days` here fails against the same regex the other five face.
    from tests.test_wire_casing import _offences

    assert _offences(back.payload) == []


async def test_a_departed_definition_emits_the_same_body_with_its_own_device_count(db, jamf: FakeJamf, connection) -> None:
    """4.4: identical shape, only `subjectKind` differs — and `deviceCount` is one indexed
    COUNT over the per-device EA rows rather than a second derivation of the group read."""
    from app.mdm.service import sync_connection

    assert (await sync_connection(db, connection)).ok
    mark = await _high_water(db)
    jamf.extension_attribute_definitions = [d for d in jamf.extension_attribute_definitions if d["id"] != "12"]
    assert (await sync_connection(db, connection)).ok

    (event,) = await _events(db, mark, "subject.departure")
    body = event.payload
    assert body["subjectKind"] == DEFINITION and body["deviceMeta"]["jamfProID"] == "12"
    assert body["subjectLabel"] == "Crowdstrike Sensor Version"
    assert body["state"] == "departed" and body["noticeDay"] == 1
    # One of the two Macs reports a value for definition `12` and the other does not, so the
    # count is what LoonInspect last held for THIS definition rather than a count of devices:
    # `>= 1` would not tell those apart, and the COUNT is the only thing 4.4 asks of this kind.
    assert body["deviceCount"] == 1, "distinct devices carrying this definition, not the fleet"
    assert "eventID" not in body["deviceMeta"] and "hostName" not in body["deviceMeta"]


async def test_a_refused_census_emits_nothing_at_all(db, jamf: FakeJamf, connection) -> None:
    """The breaker's own guarantee, carried onto the wire: a census that departs nobody must
    not enqueue anything either, or "every group departed at once" arrives at the SIEM."""
    from app.mdm.service import sync_connection

    assert (await sync_connection(db, connection)).ok
    mark = await _high_water(db)
    jamf.smart_groups = []
    jamf.extension_attribute_definitions = None
    assert (await sync_connection(db, connection)).ok
    assert await _events(db, mark, "subject.departure") == []
    # Both types, not just the one the breaker withholds. A census that names nobody closes no
    # return either, so "nothing at all" is the whole claim — note that a COLLAPSED census is
    # different on purpose: it still closes returns for the subjects it did name, because a
    # subject the census named is present whatever else the census says (`departure.py` rule 1).
    assert await _events(db, mark, "subject.returned") == []
    assert await _events(db, mark, "subject.returned") == []


# --- a departed Mac's latches close with it (#476) -------------------------------------


async def test_a_departed_macs_open_latch_closes_at_the_terminal_exit(db, jamf: FakeJamf, connection) -> None:
    """#476: the one exception to "the latch closes itself". `process_sync` opens and closes a
    latch and only runs against Macs a sweep returns, so a Mac Jamf deleted would keep its latch
    open for ever; the census is the pass that knows the tail ran out. Three properties: it
    closes at the **terminal exit** and not on the first missed census; it deletes nothing; and
    it stamps a **reason**, the only thing telling this close from an uninstall afterwards."""
    from app.alerts.service import CLOSED_DEVICE_DEPARTED, NEW_APP
    from app.mdm.service import sync_connection
    from app.models.schema import Alert, Device, InstalledApp, SubjectDeparture

    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await sync_connection(db, connection)).ok
    device = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == clone["id"]))
    ).scalar_one()
    apps_before = (await db.execute(select(InstalledApp.id).where(InstalledApp.device_id == device.id))).scalars().all()

    app = {"app_hash": "d" * 32, "app_name": "Wireshark", "bundle_id": "org.wireshark.Wireshark"}
    db.add(Alert(kind=NEW_APP, level="high", device_id=device.id, opened_at=datetime.now(UTC) - timedelta(days=30), **app))
    await db.commit()

    async def latch() -> Alert:
        return (await db.execute(select(Alert).where(Alert.device_id == device.id))).scalars().one()

    # Missed by one clean census: the tail starts and nothing closes — a Mac in its tail is
    # still in the fleet, and an alert about it is still true of the fleet.
    jamf._extra = []
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)
    assert (await latch()).closed_at is None, "a latch closing on day one would be the tail said twice"

    # The tail runs out. The next census is the seam.
    await db.execute(
        update(SubjectDeparture).where(SubjectDeparture.id == gone.id).values(departed_at=datetime.now(UTC) - timedelta(days=8))
    )
    await db.commit()
    assert (await sync_connection(db, connection)).ok

    closed = await latch()
    assert closed.closed_at is not None and closed.closed_reason == CLOSED_DEVICE_DEPARTED
    assert closed.closed_run_id is not None, "the census run stamps this close, as the sweep stamps the other"
    # NOTHING ELSE WENT — the app-gone close takes the `installed_apps` row with it, this one
    # takes nothing, which is why the reason has to be on the row. And it is said out loud, on
    # the census line an operator is already reading (path 16, step 5).
    assert apps_before, "the fixture Mac must carry apps for the next line to mean anything"
    assert (await db.execute(select(InstalledApp.id).where(InstalledApp.device_id == device.id))).scalars().all() == apps_before
    assert any("alert latch" in line and "nothing was deleted" in line for line in await _census_lines(db, connection.id))

    # Idempotent: the next census finds nothing left to close and says nothing about it.
    assert (await sync_connection(db, connection)).ok
    assert (await latch()).closed_at == closed.closed_at
    assert sum("alert latch" in line for line in await _census_lines(db, connection.id)) == 1


# --- a Mac's tail on the wire (#495, #179 4.5) -----------------------------------------------
async def _age(db, row, days: int) -> None:
    """Push one departure back in time: the only way to reach day four without waiting three days."""
    row.departed_at = datetime.now(UTC) - timedelta(days=days)
    await db.commit()


async def test_a_departed_mac_notices_once_a_day_and_the_tail_closes_with_removed(db, jamf: FakeJamf, connection) -> None:
    """4.5 on the rows the outbox holds: `noticeDay` one per UTC day, capped, then the terminal."""
    from app.core.wire import ENVELOPE
    from app.mdm.service import sync_connection
    from app.models.schema import Device
    from app.observations.departure import DEPARTURE_TAIL_DAYS

    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await sync_connection(db, connection)).ok
    hostname = await db.scalar(select(Device.hostname).filter_by(mdm_connection_id=connection.id, external_id=clone["id"]))
    mark = await _high_water(db)

    jamf._extra = []
    assert (await sync_connection(db, connection)).ok
    (event,) = await _events(db, mark, "subject.departure")
    body = event.payload
    assert body["subjectKind"] == COMPUTER and body["state"] == "departed" and body["noticeDay"] == 1
    assert body["subjectLabel"] == hostname and body[ENVELOPE]["host"] == hostname and "deviceCount" not in body
    # The whole block as the Device row last knew it, minus the one key that would name a pull.
    assert {"serialNumber", "hostName", "lastReportDate", "managed"} <= set(body["deviceMeta"])
    assert body["deviceMeta"]["jamfProID"] == clone["id"]
    assert "eventID" not in body["deviceMeta"], "a departure is derived from an absence; no read happened"

    # The same UTC day, a second census: still day one, so nothing goes out — a fifteen-minute
    # schedule must not send ninety-six notices about one Mac.
    mark = await _high_water(db)
    assert (await sync_connection(db, connection)).ok
    assert await _events(db, mark, "subject.departure") == []

    # Three quiet days are not backfilled: the next census emits the day it is actually on.
    (gone,) = await _departures(db, connection.id, COMPUTER)
    await _age(db, gone, 3)
    assert (await sync_connection(db, connection)).ok
    (fourth,) = await _events(db, mark, "subject.departure")
    assert fourth.payload["state"] == "departed" and fourth.payload["noticeDay"] == 4

    # Seven days up, to the boundary `left_the_fleet` counts: one terminal, and nothing after it.
    mark = await _high_water(db)
    await _age(db, gone, DEPARTURE_TAIL_DAYS)
    for _ in range(2):
        assert (await sync_connection(db, connection)).ok
    (terminal,) = await _events(db, mark, "subject.departure")
    assert terminal.payload["state"] == "removed" and terminal.payload["noticeDay"] == DEPARTURE_TAIL_DAYS
    assert "eventID" not in terminal.payload["deviceMeta"]


async def test_the_clock_runs_out_without_a_clean_census_and_the_mac_still_leaves(db, jamf: FakeJamf, connection) -> None:
    """4.5's guarantee: **Devices** drops the Mac on the wall clock, so the wire must too."""
    from app.mdm import service

    scoped = {"trigger": "sweep", "selector": "general.remoteManagement.managed==true"}
    jamf.seed(1)
    assert (await service.run_jamf(db, connection, trigger="sweep")).ok
    jamf._extra = []
    assert (await service.run_jamf(db, connection, trigger="sweep")).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)
    await _age(db, gone, 8)

    mark = await _high_water(db)
    assert (await service.run_jamf(db, connection, **scoped)).ok
    (terminal,) = await _events(db, mark, "subject.departure")
    assert terminal.payload["state"] == "removed", "a sweep that judges nobody still closes an expired tail"

    mark = await _high_water(db)
    assert (await service.run_jamf(db, connection, **scoped)).ok
    assert await _events(db, mark, "subject.departure") == [], "the terminal is emitted exactly once"


async def _not_a_census_lines(db, connection_id: int) -> list:
    """The *device census not taken…* lines, whole — message, fields and the run that wrote them."""
    from app.models.schema import Run, RunLogLine

    query = (
        select(RunLogLine)
        .join(Run, RunLogLine.run_id == Run.id)
        .where(Run.mdm_connection_id == connection_id, RunLogLine.message.like("device census not taken%"))
        .order_by(RunLogLine.id)
    )
    return list((await db.execute(query)).scalars().all())


async def _scope_the_sweeps(db, connection_id: int, selector: str | None) -> None:
    """Point this connection's collections at a slice of the fleet — or back at all of it."""
    from app.models.schema import Collection

    await db.execute(update(Collection).where(Collection.mdm_connection_id == connection_id).values(selector=selector))
    await db.commit()


async def test_a_scoped_sweep_closes_the_latch_with_the_terminal_it_sends(db, jamf: FakeJamf, connection, monkeypatch) -> None:
    """#512, ruled 2026-09-17 (R10 option 1): one act, one guarantee. The terminal fires above the
    census gate on the wall clock, and the latch close rides with it — so a connection whose sweeps
    are all scoped, or all short a failed device, cannot ship `state: removed` to the SIEM while
    `GET /api/alerts?open=true` goes on listing the Mac. Both dirty reasons run; the day-seven sweep
    is the scoped one, and its own run-log line carries `latchesClosed` and says so in words."""
    from app.alerts.service import CLOSED_DEVICE_DEPARTED, NEW_APP
    from app.mdm import service
    from app.models.schema import Alert, Device

    selector = "general.remoteManagement.managed==true"
    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await service.sync_connection(db, connection)).ok
    device = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == clone["id"]))
    ).scalar_one()
    app = {"app_hash": "e" * 32, "app_name": "Wireshark", "bundle_id": "org.wireshark.Wireshark"}
    db.add(Alert(kind=NEW_APP, level="high", device_id=device.id, opened_at=datetime.now(UTC) - timedelta(days=30), **app))
    await db.commit()

    async def latch() -> Alert:
        return (await db.execute(select(Alert).where(Alert.device_id == device.id))).scalars().one()

    # ONE clean census opens the tail. Every sweep after it is scoped or dirty — which on a
    # selector-only schedule is the whole of the Mac's remaining life here.
    jamf._extra = []
    assert (await service.sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)

    await _scope_the_sweeps(db, connection.id, selector)
    assert (await service.sync_connection(db, connection)).ok
    assert (await latch()).closed_at is None, "mid-tail the Mac is still in the fleet, and so is its alert"

    # The other way a sweep is not a census, on the same tail: a device Jamf returned that we
    # failed to ingest. Nothing to close yet, and the branch still runs.
    await _scope_the_sweeps(db, connection.id, None)
    ingest = service.ingest_computer

    async def one_bad_device(session, conn, raw, **kwargs):
        if raw.get("id") == jamf.real["id"]:
            raise RuntimeError("ingest failed for this device")
        return await ingest(session, conn, raw, **kwargs)

    monkeypatch.setattr(service, "ingest_computer", one_bad_device)
    dirty = await service.sync_connection(db, connection)
    assert dirty.ok and dirty.devices_failed == 1, dirty
    monkeypatch.setattr(service, "ingest_computer", ingest)  # not undo(): the fake Jamf is patched in too
    assert {line.fields["reason"] for line in await _not_a_census_lines(db, connection.id)} == {"selector", "device_failures"}
    assert all(line.fields["latchesClosed"] == 0 for line in await _not_a_census_lines(db, connection.id))
    assert (await latch()).closed_at is None, "a failed ingest is not day seven either"

    # Day seven, and the only sweep that runs is scoped. One act: the terminal and the close.
    await _scope_the_sweeps(db, connection.id, selector)
    await _age(db, gone, 8)
    mark = await _high_water(db)
    assert (await service.sync_connection(db, connection)).ok
    (terminal,) = await _events(db, mark, "subject.departure")
    assert terminal.payload["state"] == "removed"

    closed = await latch()
    assert closed.closed_at is not None and closed.closed_reason == CLOSED_DEVICE_DEPARTED
    line = (await _not_a_census_lines(db, connection.id))[-1]
    assert closed.closed_run_id == line.run_id, "the sweep that sent the terminal is the one that stamped the close"
    assert line.fields["latchesClosed"] == 1 and line.fields["macsRemoved"] == 1
    # Said out loud on the line the operator reads, not left to a number that moved (path 16, step 5).
    assert "open alert latch closed" in line.message and "nothing was deleted" in line.message

    # Idempotent: the next scoped sweep finds nothing left to close and says nothing about it.
    assert (await service.sync_connection(db, connection)).ok
    lines = await _not_a_census_lines(db, connection.id)
    assert (await latch()).closed_at == closed.closed_at
    assert lines[-1].fields["latchesClosed"] == 0 and "alert latch" not in lines[-1].message
    assert sum("alert latch" in row.message for row in lines) == 1


async def test_a_returning_mac_carries_its_pull_and_the_id_it_departed_under(db, jamf: FakeJamf, connection) -> None:
    """4.6 for a Mac: `matchedBy` and `priorJamfProID` off the row #475 writes, and `deviceMeta`
    WITH `eventID` — the one asymmetry, because a return coincides with a real pull."""
    from app.core.runs import pull_event_id
    from app.mdm.service import sync_connection
    from app.models.schema import Device

    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await sync_connection(db, connection)).ok
    jamf._extra = []
    assert (await sync_connection(db, connection)).ok
    (departed,) = await _departures(db, connection.id, COMPUTER)
    await _age(db, departed, 3)  # mid-tail, so an unsuppressed notice for the retired half would go out here

    mark = await _high_water(db)
    reborn = _re_enrolled(clone)
    jamf._extra = [reborn]
    assert (await sync_connection(db, connection)).ok
    (back,) = await _events(db, mark, "subject.returned")
    (row,) = await _departures(db, connection.id, COMPUTER)
    assert await _events(db, mark, "subject.departure") == [], "returned and still-absent must not go out together"
    assert back.payload["matchedBy"] == "serialNumber" and back.payload["absentForDays"] == 3
    assert back.payload["priorJamfProID"] == clone["id"], "the only join back to the departure it closes"
    assert back.payload["deviceMeta"]["jamfProID"] == reborn["id"] and back.payload["departedAt"] == row.departed_at.isoformat()
    platform = await db.scalar(select(Device.platform).filter_by(mdm_connection_id=connection.id, external_id=reborn["id"]))
    job = uuidlib.UUID(back.payload["jobID"])
    assert back.payload["deviceMeta"]["eventID"] == pull_event_id(job, platform, reborn["id"])

    # The retired id serves out the tail it started (troubleshooting §16 path 3), so the SIEM sees that
    # half close too — under the id the departure went out with, not the one it came back as.
    await _age(db, row, 8)
    mark = await _high_water(db)
    assert (await sync_connection(db, connection)).ok
    (terminal,) = await _events(db, mark, "subject.departure")
    assert terminal.payload["state"] == "removed" and terminal.payload["deviceMeta"]["jamfProID"] == clone["id"]


async def test_a_mac_this_sweep_names_after_its_deadline_is_not_told_it_was_removed(db, jamf: FakeJamf, connection) -> None:
    """The terminal belongs to the population, not to the clock alone: the sweep that first runs after the
    seven days may name the Mac, and a `removed` beside its own `subject.returned` asserts what that census disproves."""
    from app.mdm.service import sync_connection

    jamf.seed(1)
    (clone,) = jamf._extra
    assert (await sync_connection(db, connection)).ok
    jamf._extra = []
    assert (await sync_connection(db, connection)).ok
    (gone,) = await _departures(db, connection.id, COMPUTER)
    await _age(db, gone, 8)

    mark, jamf._extra = await _high_water(db), [clone]
    assert (await sync_connection(db, connection)).ok
    assert await _events(db, mark, "subject.departure") == [], "this census named it; it never left"
    (back,) = await _events(db, mark, "subject.returned")
    assert back.payload["matchedBy"] == "jamfProID" and back.payload["departedAt"] == gone.departed_at.isoformat()
