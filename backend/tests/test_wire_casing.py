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
is precisely the view a customer's SPL has. So this module drives all four producers in
one transaction sequence and then judges the payloads *together*:

1. Every emitted key on every family is camelCase with `ID` uppercased.
2. One discriminator, `event`, selects all four types with one predicate.
3. The run UUID has exactly one name, `jobID` — and the documented join works, with the
   one nesting caveat pinned honestly rather than glossed.

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

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

from app.core.wire import ENVELOPE
from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

FAMILIES = {"device.inventory.changed", "device.change", "run.completed", "run.failed"}

# camelCase: a lower-case first word, then letters and digits only. Underscores are the
# whole point of the rule, so they are rejected by construction rather than by a second
# check.
_CAMEL = re.compile(r"^[a-z][A-Za-z0-9]*$")
# The `ID` token, mis-cased. `Id` at the end of a name (`jobId`) or before another word
# (`IdList`) is the spelling the law forbids; `jobID` and `identity` are untouched by it.
_LOWERCASE_ID_TOKEN = re.compile(r"Id(?:[A-Z]|$)")

# Keys whose *values* are objects full of a vendor's own vocabulary — Jamf writes
# `bundleId`, and the law says a vendor's native key keeps the vendor's spelling. Only
# LoonInspect-minted key names are judged here, so these are not descended into.
_VENDOR_VALUED = {"entryIdentity", "old", "new", "details", "addedApps", "removedApps"}


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
async def four_families(db, jamf: FakeJamf, connection):
    """One run of every producer on the wire, returned as the rows the outbox holds.

    The shape matters as much as the coverage. The three non-alarm families are produced
    by ONE sweep — the second, where the fleet has moved — so all three carry the same
    run and the cross-family join has something real to join. Producing the changes
    through the webhook path instead would open a second run, and the events would
    legitimately carry two different jobIDs: a green test that proved nothing.

    Rows are selected by `id` above a high-water mark taken after the baseline sweep,
    rather than by recency or by a payload key. The local database accumulates events
    across the whole suite, and filtering on a payload key would mean reading the very
    vocabulary under test.
    """
    from app.core.runs import LOCK_WEBHOOK, TRIGGER_WEBHOOK, acquire, finish
    from app.mdm.service import sync_connection
    from app.models.schema import EventOutbox

    # The baseline. A first observation is not a change, so this sweep's events are not
    # what we judge — it exists to give the second sweep something to diff against.
    baseline = await sync_connection(db, connection)
    assert baseline.ok, baseline

    high_water = (await db.execute(select(func.coalesce(func.max(EventOutbox.id), 0)))).scalar_one()

    # The sweep that produces three of the four families under one run: an inventory
    # event for the app that appeared, a device.change per derived row, and the
    # run.completed that closes over both.
    _second_inventory(jamf)
    sweep = await sync_connection(db, connection)
    assert sweep.ok, sweep

    # A failed run is the only producer of run.failed. Under the webhook lock class on
    # purpose: a failed *device sweep* also emits run.completed (#92 — every sweep that
    # closes does, succeeded or failed), which would put a second run's jobID into the
    # set the join test reads.
    failed = await acquire(db, connection, trigger=TRIGGER_WEBHOOK, lock_class=LOCK_WEBHOOK)
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


async def test_every_family_is_produced_so_the_judgements_below_are_not_vacuous(four_families) -> None:
    """The guard on the other three tests. If a producer ever stops firing in this
    sequence, the casing assertions would pass by having nothing to judge — the exact
    failure mode that let three families drift out of the law for a year."""
    rows, _ = four_families
    assert {row.event_type for row in rows} == FAMILIES, "every family must be exercised here"


async def test_every_emitted_key_on_every_family_is_camel_case_with_id_uppercased(four_families) -> None:
    """The law itself, over the serialized payloads.

    Judged per family so a failure names which producer drifted, and reported as the
    offending keys rather than a bare False — the useful output of this test is the
    list of names to fix.
    """
    rows, _ = four_families
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


async def test_one_predicate_selects_all_four_types(four_families) -> None:
    """`event=...` is the whole discriminator, on every family.

    Before this, device events said `event` and run events said `event_type`, so
    `event=run.failed` returned zero rows and `event_type=device.change` returned zero
    rows — silently, because SPL has no unknown-field error. This is the change most
    visible to a customer's saved searches, and it is worth its own assertion that no
    second discriminator survives anywhere on the wire.
    """
    rows, _ = four_families
    selected = {row.payload["event"] for row in rows if "event" in row.payload}
    assert selected == FAMILIES
    assert len(selected) == len({row.event_type for row in rows})
    for row in rows:
        assert row.payload["event"] == row.event_type, "the body must agree with the outbox row's type"
        assert "event_type" not in row.payload and "eventType" not in row.payload


async def test_the_run_uuid_has_one_name_and_the_documented_join_works(four_families) -> None:
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
    rows, failed_run_id = four_families

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
    assert {row.event_type for row in joined} == {"device.inventory.changed", "device.change", "run.completed"}
    assert len(joined) == len(sweep_events), "no event of this sweep is left out of the join"

    # The hoist itself, both halves. The root copy is what the bare join above selects on;
    # `deviceMeta.jobID` is kept because removing it would break existing SPL in the
    # silent direction, and it is what every fan-out sub-event will still carry (#242).
    inventory = [row for row in sweep_events if row.event_type == "device.inventory.changed"]
    assert inventory
    assert all(row.payload["jobID"] == sweep_id for row in inventory)
    assert all(row.payload["deviceMeta"]["jobID"] == sweep_id for row in inventory)

    # The run's failure event names the run the same way — a different run id, the same
    # key, so an alert and a heartbeat join to the run log through one field.
    alarms = [row for row in rows if row.event_type == "run.failed"]
    assert alarms and all(row.payload["jobID"] == str(failed_run_id) for row in alarms)


async def test_the_two_device_families_agree_on_the_device_not_merely_on_casing(four_families) -> None:
    """The half of the ruling that "both camelCase" would not have delivered.

    A `device.change` and the `device.inventory.changed` from the same pull now spell the
    Jamf Pro id and the serial with the same names as `deviceMeta` does, carrying the
    same values — so correlating a change to its inventory pass is a join on keys, not a
    translation table.
    """
    rows, _ = four_families
    # A computer subject specifically: `derive_and_record` also runs for computer_group
    # subjects, whose jamfProID is a group's id and has no inventory event to agree with.
    change = next(
        row for row in rows if row.event_type == "device.change" and row.payload["subjectKind"] == "computer"
    )
    inventory = [row for row in rows if row.event_type == "device.inventory.changed"]
    match = next(row for row in inventory if row.payload["deviceMeta"]["jamfProID"] == change.payload["jamfProID"])
    assert match.payload["deviceMeta"]["serialNumber"] == change.payload["serialNumber"]
    assert match.payload["deviceMeta"]["jobID"] == change.payload["jobID"]
