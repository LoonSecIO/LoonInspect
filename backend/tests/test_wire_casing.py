"""The casing law, held against every event family at once (#188).

`docs/runs.md` has said since #189 that casing on the wire is "camelCase throughout with
the token `ID` uppercased on LoonInspect's own keys". It was applied to exactly one
block — `deviceMeta` on `device.inventory.changed` — and the other three families kept
snake_case. What that cost was not cosmetic: one Splunk index, one sourcetype, and the
same run UUID arriving as `deviceMeta.jobID`, `job_id` and `run_id`, with the type
discriminator split between `event` and `event_type` so no single predicate could select
LoonInspect events at all.

This suite exists because per-family tests could not catch that. Each family's own test
asserted its own key set and passed; the defect was only visible across families, which
is precisely the view a customer's SPL has. So this module drives all five producers in
one transaction sequence and then judges the payloads *together*:

1. Every emitted key on every family is camelCase with `ID` uppercased.
2. One discriminator, `event`, selects all five types with one predicate.
3. The run UUID has exactly one name, `jobID` — and the documented join works, with the
   one nesting caveat pinned honestly rather than glossed.
4. The three device families carry ONE `deviceMeta` block, agreeing key for key on the
   pull they all describe — the snapshot's (#241) equal to the delta's, `eventID`
   included — and every `device.change` is delivered under the `:change` sourcetype its
   entity was minted (#223, on the family #243 ruled). Casing was only the first half of
   that ruling: a change event that spelled every key correctly and carried no block at
   all was still outside the vocabulary.

The fifth family, `device.inventory`, is the per-device snapshot (#241): fourteen section
wrapper keys whose VALUES are Jamf's own objects under Jamf's spelling. The law judges
the keys LoonInspect minted — the head and `deviceMeta` — and the wrapper keys themselves,
which are the frozen registry's and pass on their own; it does not descend into a
vendor's object, so `bundleId` inside `app[].app` is never an offence.

It asserts on the serialized payload rows the outbox actually holds, never on the source
that built them: a rename that changed a literal in one producer and not another would
pass a code-shaped test and fail this one.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import re
import uuid as uuidlib
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

from app.core.outbox import _build_body, hec_events
from app.core.wire import ENVELOPE
from app.core.wire_vocabulary import (
    ASSERTION_SOURCETYPE,
    SECTION_WRAPPERS,
    SUB_EVENT_KEYS,
    SUBJECT_WRAPPERS,
    change_rows,
    registry_rows,
)
from tests.jamf_fake import HOST, FakeJamf
from tests.test_device_meta import SHIPPED_ELEVEN

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

FAMILIES = {"device.inventory", "device.inventory.changed", "device.change", "run.completed", "run.failed"}

# camelCase: a lower-case first word, then letters and digits only. Underscores are the
# whole point of the rule, so they are rejected by construction rather than by a second
# check.
_CAMEL = re.compile(r"^[a-z][A-Za-z0-9]*$")
# The `ID` token, mis-cased. `Id` at the end of a name (`jobId`) or before another word
# (`IdList`) is the spelling the law forbids; `jobID` and `identity` are untouched by it.
_LOWERCASE_ID_TOKEN = re.compile(r"Id(?:[A-Z]|$)")

# Keys whose *values* are objects full of a vendor's own vocabulary — Jamf writes
# `bundleId`, and the law says a vendor's native key keeps the vendor's spelling. Only
# LoonInspect-minted key names are judged here, so these are not descended into. The
# snapshot's fourteen section wrappers (#241) are listed by reference to the registry:
# they would pass the regex on their own, but the exemption is then documented rather
# than accidental, and a wrapper the registry stops naming stops being exempt.
_VENDOR_VALUED = {"entryIdentity", "old", "new", "details", "addedApps", "removedApps", *SECTION_WRAPPERS.values()}


def _loon_keys(payload: dict) -> set[str]:
    """Every key on one event that LoonInspect minted.

    The top level, plus `deviceMeta` — whose keys are LoonInspect's own (#189) even
    though it is a nested object. `_envelope` is dropped: it is outbox transport that
    `_build_body` pops before any destination sees it, so it is not wire vocabulary and
    judging it here would make this test fail for a reason it does not mean.
    """
    keys = {key for key in payload if key != ENVELOPE}
    meta = payload.get("deviceMeta")
    if isinstance(meta, dict):
        keys |= set(meta)
    return keys


def _offences(payload: dict) -> list[str]:
    return [
        key
        for key in _loon_keys(payload)
        if key not in _VENDOR_VALUED and (not _CAMEL.match(key) or _LOWERCASE_ID_TOKEN.search(key))
    ]


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


@pytest.fixture
def jamf(monkeypatch: pytest.MonkeyPatch) -> FakeJamf:
    from app.mdm.jamf.client import JamfClient

    fake = FakeJamf()

    @asynccontextmanager
    async def _mock_http(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as client:
            yield client

    monkeypatch.setattr(JamfClient, "http", _mock_http)
    return fake


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    from app.models.schema import (
        AppCatalogEntry,
        ChangePolicy,
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"wire casing jamf {uuidlib.uuid4().hex[:8]}",
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
        await db.execute(delete(ChangePolicy))
        # Keyed by tenant rather than by connection, so it survives the cascade above and
        # would otherwise fail test_catalog_db on the next local run against this database.
        await db.execute(delete(AppCatalogEntry))
        await db.commit()


def _second_inventory(jamf: FakeJamf) -> None:
    """The Mac a day later. Deliberately small — this suite judges key names, and the
    change-log semantics are pinned in test_changes_db.py — but it must move an *app*
    as well as a scalar: `process_sync` emits `device.inventory.changed` only when the
    app list moved, so an OS-only change would produce a `device.change` with no
    inventory event beside it and leave the cross-family join untested.
    """
    jamf.real["general"]["reportDate"] = "2026-08-23T09:00:00.000Z"
    jamf.real["operatingSystem"]["version"] = "27.1"
    jamf.real["security"]["firewallEnabled"] = True
    jamf.real["applications"].append(
        {
            "name": "Loon Inspector.app", "path": "/Applications/Loon Inspector.app", "version": "0.1",
            "cfBundleShortVersionString": "0.1", "cfBundleVersion": "7", "macAppStore": False,
            "bundleId": "io.loonsec.inspector", "updateAvailable": False, "externalVersionId": "0",
        }
    )


@pytest_asyncio.fixture(loop_scope="session")
async def five_families(db, jamf: FakeJamf, connection):
    """One run of every producer on the wire, returned as the rows the outbox holds.

    The shape matters as much as the coverage. The four non-alarm families are produced
    by ONE sweep — the second, where the fleet has moved — so all four carry the same
    run and the cross-family join has something real to join. Producing the changes
    through the webhook path instead would open a second run, and the events would
    legitimately carry two different jobIDs: a green test that proved nothing.

    Rows are selected by `id` above a high-water mark taken after the baseline sweep,
    rather than by recency or by a payload key. The local database accumulates events
    across the whole suite, and filtering on a payload key would mean reading the very
    vocabulary under test.
    """
    from app.core.runs import LOCK_CATALOG, TRIGGER_SWEEP, acquire, finish
    from app.mdm.service import sync_connection
    from app.models.schema import EventOutbox

    # The baseline. A first observation is not a change, so this sweep's events are not
    # what we judge — it exists to give the second sweep something to diff against.
    baseline = await sync_connection(db, connection)
    assert baseline.ok, baseline

    high_water = (await db.execute(select(func.coalesce(func.max(EventOutbox.id), 0)))).scalar_one()

    # The sweep that produces four of the five families under one run: a snapshot per
    # device, an inventory delta for the app that appeared, a device.change per derived
    # row, and the run.completed that closes over all of them.
    _second_inventory(jamf)
    sweep = await sync_connection(db, connection)
    assert sweep.ok, sweep

    # A failed run is the only producer of run.failed. Under the catalog lock class on
    # purpose: a failed device sweep OR webhook run also emits run.completed (#224 widened
    # the webhook case to match — every lock class that closes over real inventory does,
    # succeeded or failed), which would put a second run's jobID into the set the join
    # test reads. LOCK_CATALOG is the one lock class #224 left outside run.completed.
    failed = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_CATALOG)
    failed_run_id = failed.run.id
    await finish(db, failed.run, ok=False, error="Jamf returned 502 at page 41")

    rows = (
        await db.execute(
            select(EventOutbox)
            .where(EventOutbox.id > high_water, EventOutbox.event_type.in_(FAMILIES))
            .order_by(EventOutbox.id)
        )
    ).scalars().all()
    return rows, failed_run_id


async def test_every_family_is_produced_so_the_judgements_below_are_not_vacuous(five_families) -> None:
    """The guard on the other three tests. If a producer ever stops firing in this
    sequence, the casing assertions would pass by having nothing to judge — the exact
    failure mode that let three families drift out of the law for a year."""
    rows, _ = five_families
    assert {row.event_type for row in rows} == FAMILIES, "every family must be exercised here"


async def test_every_emitted_key_on_every_family_is_camel_case_with_id_uppercased(five_families) -> None:
    """The law itself, over the serialized payloads.

    Judged per family so a failure names which producer drifted, and reported as the
    offending keys rather than a bare False — the useful output of this test is the
    list of names to fix.
    """
    rows, _ = five_families
    offences = {}
    for row in rows:
        bad = _offences(row.payload)
        if bad:
            offences.setdefault(row.event_type, set()).update(bad)
    assert offences == {}, f"keys outside the casing law: {offences}"

    # And the rule has teeth: the spellings this PR removed are exactly what it rejects.
    assert _offences({"run_id": "x"}) == ["run_id"]
    assert _offences({"jobId": "x"}) == ["jobId"]
    assert _offences({"eventIdList": []}) == ["eventIdList"]
    # While a vendor's own key inside a value object is untouched by it — Jamf writes
    # `bundleId`, and the wire keeps the vendor's spelling.
    assert _offences({"addedApps": [{"bundleId": "com.example"}]}) == []


async def test_one_predicate_selects_all_five_types(five_families) -> None:
    """`event=...` is the whole discriminator, on every family.

    Before this, device events said `event` and run events said `event_type`, so
    `event=run.failed` returned zero rows and `event_type=device.change` returned zero
    rows — silently, because SPL has no unknown-field error. This is the change most
    visible to a customer's saved searches, and it is worth its own assertion that no
    second discriminator survives anywhere on the wire.
    """
    rows, _ = five_families
    selected = {row.payload["event"] for row in rows if "event" in row.payload}
    assert selected == FAMILIES
    assert len(selected) == len({row.event_type for row in rows})
    for row in rows:
        assert row.payload["event"] == row.event_type, "the body must agree with the outbox row's type"
        assert "event_type" not in row.payload and "eventType" not in row.payload


async def test_the_run_uuid_has_one_name_and_the_documented_join_works(five_families) -> None:
    """docs/runs.md promises the run id is "joinable against every event the run
    produced". Under three names it was not joinable at all; under one name and two paths
    it took two terms; under the #220 hoist it is a bare `jobID=$id$`.

    What changed here on 2026-09-02: this test used to pin the caveat — that the
    inventory family carried the id *only* under `deviceMeta`, so a top-level predicate
    missed it. #220 ruled that closed, option 1 of four: the id is hoisted to the event
    root and `deviceMeta.jobID` stays, because a customer's SPL may already name it and
    SPL fails silently on an unknown field. So both paths are asserted below — the
    duplicate is the ruling, and a copy that can go missing on one path is worse than no
    copy at all.
    """
    rows, failed_run_id = five_families

    def carriers(payload: dict, value: str) -> set[str]:
        """Every key path on one event holding this UUID."""
        found = {key for key, held in payload.items() if key != ENVELOPE and held == value}
        meta = payload.get("deviceMeta")
        if isinstance(meta, dict):
            found |= {f"deviceMeta.{key}" for key, held in meta.items() if held == value}
        return found

    sweep_events = [row for row in rows if row.event_type != "run.failed"]
    sweep_id = next(row.payload["jobID"] for row in sweep_events if row.event_type == "run.completed")

    # One name, across every family: the leaf of every path holding the run UUID is
    # `jobID`, and `run_id` / `job_id` appear nowhere.
    names = {path.rsplit(".", 1)[-1] for row in rows for path in carriers(row.payload, sweep_id)}
    names |= {path.rsplit(".", 1)[-1] for row in rows for path in carriers(row.payload, str(failed_run_id))}
    assert names == {"jobID"}

    # The join, as a customer would write it: one bare top-level term, no
    # `deviceMeta.jobID` alternate and no coalesce. Every event the sweep produced is
    # selected — inventory, changes and the closing run event alike — which is the
    # docs/runs.md claim, now true without a qualification attached.
    joined = [row for row in sweep_events if row.payload.get("jobID") == sweep_id]
    assert {row.event_type for row in joined} == {
        "device.inventory", "device.inventory.changed", "device.change", "run.completed",
    }
    assert len(joined) == len(sweep_events), "no event of this sweep is left out of the join"

    # The hoist itself, both halves, on both inventory families. The root copy is what the
    # bare join above selects on; `deviceMeta.jobID` is kept because removing it would
    # break existing SPL in the silent direction, and it is what every fan-out sub-event
    # will still carry (#242) — the snapshot is the event that fan-out expands, so the
    # bare `jobID` join has to hold for it from its first byte.
    inventory = [row for row in sweep_events if row.event_type in ("device.inventory", "device.inventory.changed")]
    assert {row.event_type for row in inventory} == {"device.inventory", "device.inventory.changed"}
    assert all(row.payload["jobID"] == sweep_id for row in inventory)
    assert all(row.payload["deviceMeta"]["jobID"] == sweep_id for row in inventory)

    # The run's failure event names the run the same way — a different run id, the same
    # key, so an alert and a heartbeat join to the run log through one field.
    alarms = [row for row in rows if row.event_type == "run.failed"]
    assert alarms and all(row.payload["jobID"] == str(failed_run_id) for row in alarms)


async def test_the_two_device_families_agree_on_the_device_not_merely_on_casing(five_families) -> None:
    """The half of the ruling that "both camelCase" would not have delivered.

    A `device.change` and the `device.inventory.changed` from the same pull now spell the
    Jamf Pro id and the serial with the same names as `deviceMeta` does, carrying the
    same values — so correlating a change to its inventory pass is a join on keys, not a
    translation table.
    """
    rows, _ = five_families
    # A computer subject specifically: `derive_and_record` also runs for computer_group
    # subjects, whose jamfProID is a group's id and has no inventory event to agree with.
    change = next(
        row for row in rows if row.event_type == "device.change" and row.payload["subjectKind"] == "computer"
    )
    inventory = [row for row in rows if row.event_type == "device.inventory.changed"]
    match = next(row for row in inventory if row.payload["deviceMeta"]["jamfProID"] == change.payload["jamfProID"])
    assert match.payload["deviceMeta"]["serialNumber"] == change.payload["serialNumber"]
    assert match.payload["deviceMeta"]["jobID"] == change.payload["jobID"]


async def test_the_snapshot_and_the_delta_from_one_pull_share_the_block_the_time_and_the_envelope(
    five_families,
) -> None:
    """#241: a `device.inventory` and the `device.inventory.changed` from the same pull share
    `occurredAt`, `jobID`, the whole `deviceMeta` block — `eventID` included, one id per
    device per pull (#81 ruling 4) — and the envelope hints, by design. Asserted on the
    rows the outbox holds rather than on the builder, because the two are built by two
    calls in `process_sync` and the failure this exists for is those calls drifting."""
    rows, _ = five_families
    snapshots = [row for row in rows if row.event_type == "device.inventory"]
    deltas = [row for row in rows if row.event_type == "device.inventory.changed"]
    assert snapshots and deltas
    # Every device of the sweep has a snapshot; only the one whose app list moved has a delta.
    assert len(snapshots) == 2 and len(deltas) == 1
    (delta,) = deltas
    match = next(row for row in snapshots if row.payload["deviceMeta"]["jamfProID"] == delta.payload["deviceMeta"]["jamfProID"])

    assert match.payload["deviceMeta"] == delta.payload["deviceMeta"]
    assert match.payload["deviceMeta"]["eventID"] == delta.payload["deviceMeta"]["eventID"]
    assert match.payload["jobID"] == delta.payload["jobID"]
    assert match.payload["occurredAt"] == delta.payload["occurredAt"]
    assert match.payload[ENVELOPE] == delta.payload[ENVELOPE]
    # The snapshot's own shape, on a real row: the head, then the registry's wrappers.
    assert set(match.payload) - {ENVELOPE, "event", "jobID", "occurredAt", "deviceMeta"} == set(SECTION_WRAPPERS.values())
    # The app the second sweep added is in the snapshot's state and in the delta's `addedApps`.
    assert "io.loonsec.inspector" in {item["app"].get("bundleId") for item in match.payload["app"]}
    assert [app["bundleId"] for app in delta.payload["addedApps"]] == ["io.loonsec.inspector"]
    # And the other device — unchanged — has a snapshot with no delta beside it.
    other = next(row for row in snapshots if row is not match)
    assert other.payload["deviceMeta"]["jamfProID"] not in {row.payload["deviceMeta"]["jamfProID"] for row in deltas}


async def test_the_change_family_carries_the_inventory_familys_own_device_block(five_families) -> None:
    """#223, ruled on #243: `device.change` was outside the vocabulary in a way casing
    alone could not fix — it carried no `deviceMeta` at all, so a change joined to its own
    inventory pass through `jobID` + `jamfProID`, the two-term join #189 rejected because
    it "can be half-used, returning a plausible superset with no error".

    Judged here rather than only in `tests/test_device_meta.py` because the two blocks are
    built by two functions from two sources — the inventory family from the `Device` row
    after `process_sync` writes it, the change family from the observation and the run — and
    the failure this test exists for is exactly the one a per-producer test cannot see: two
    blocks describing the same pull that disagree about the device.
    """
    rows, _ = five_families
    changes = [row for row in rows if row.event_type == "device.change"]
    inventory = [row for row in rows if row.event_type == "device.inventory.changed"]
    assert changes and inventory

    for row in changes:
        meta = row.payload["deviceMeta"]
        # #189's names and no others, and nothing null: the block a customer's
        # `| fields deviceMeta.*` expands is one vocabulary across both families.
        assert set(meta) <= set(SHIPPED_ELEVEN), f"unruled deviceMeta keys: {set(meta) - set(SHIPPED_ELEVEN)}"
        assert all(value is not None for value in meta.values())
        # #220's three, which this event now carries in full — though a change is not a
        # fan-out sub-event: it was already at sub-event grain.
        assert set(SUB_EVENT_KEYS) <= set(row.payload)

    change = next(row for row in changes if row.payload["subjectKind"] == "computer")
    match = next(row for row in inventory if row.payload["deviceMeta"]["jamfProID"] == change.payload["jamfProID"])
    change_meta, inventory_meta = change.payload["deviceMeta"], match.payload["deviceMeta"]

    # The correlation key #189 named and #243 ruled onto this family: derived, not minted,
    # so two producers of one pull arrive at one value without either passing it along.
    assert change_meta["eventID"] == inventory_meta["eventID"]
    # And every other key agrees, key for key. Asserted in this direction because the
    # change family may legitimately carry fewer — a section outside the aperture is
    # absence of observation, and the null-drop rule covers it — but never a different
    # answer about the same device on the same pull.
    assert {key: change_meta[key] for key in change_meta} == {key: inventory_meta[key] for key in change_meta}
    # This fixture sweeps the full v0 aperture, so "fewer" is empty here and the two blocks
    # are the same set. A narrower aperture is pinned in tests/test_device_meta.py.
    assert set(change_meta) == set(inventory_meta)


async def test_every_change_is_delivered_under_its_entitys_change_sourcetype(five_families) -> None:
    """The stamp, on the events a real sweep produced (#223).

    `device.change` is the first sourcetype the product ever sends. The string is the whole
    contract — a `props.conf` stanza keys on it exactly and takes no wildcards — so it is
    asserted against the wrapper table rather than against the function that builds it, and
    on the delivered HEC body rather than on the payload, because a sourcetype is part of
    the delivery and not part of the event.
    """
    rows, _ = five_families
    changes = [row for row in rows if row.event_type == "device.change"]
    assert changes

    minted = {stype for _subject, _wrapper, stype in change_rows()}
    seen: set[str] = set()
    for row in changes:
        payload = row.payload
        # The entity segment names the subject where the subject is not a device section
        # (a smart group's definition), and the section otherwise.
        wrapper = SUBJECT_WRAPPERS.get(payload["subjectKind"]) or SECTION_WRAPPERS[payload["section"]]
        expected = f"loon:jamf:mac:{wrapper}:change"
        body = _build_body(SimpleNamespace(type="splunk_hec"), payload)

        assert body["sourcetype"] == expected
        assert expected in minted, "a string outside the registry is a stanza nobody was told to write"
        seen.add(expected)
        # Splunk's routing dimension, not the event: every other destination gets the
        # canonical body.
        assert "sourcetype" not in _build_body(SimpleNamespace(type="webhook"), payload)

    assert len(seen) > 1, "the sweep must move more than one section, or this proves one string"
    # The change rule stamps nothing else. What the other families carry, on real rows:
    # the run family `loon:run`; the delta nothing (no ruled string); and the snapshot is
    # fanned out (#242) into sub-events every one of which carries a registry string —
    # `eventID` included, which only a real run produces.
    assert any(row.event_type == "device.inventory" for row in rows)
    registry = {stype for _section, _key, _wrapper, stype in registry_rows()}
    for row in rows:
        if row.event_type == "device.change":
            continue
        if row.event_type == "device.inventory":
            sub_events = hec_events(row.payload)
            assert sub_events and {sub["sourcetype"] for sub in sub_events} <= registry
            assert {sub["event"]["deviceMeta"]["eventID"] for sub in sub_events} == {row.payload["deviceMeta"]["eventID"]}
            assert all(set(SUB_EVENT_KEYS) <= set(sub["event"]) for sub in sub_events)
            continue
        body = _build_body(SimpleNamespace(type="splunk_hec"), row.payload)
        if row.event_type in ("run.completed", "run.failed"):
            assert body["sourcetype"] == ASSERTION_SOURCETYPE
        else:
            assert "sourcetype" not in body
