"""Two per-device costs on the sweep's hot path, pinned by statement count (#142).

Both were modest at hundreds of devices and wrong at the 40k design target, and neither
shows up in a functional test because both produce the right rows — they just produce
them expensively:

1. `record_device_apps` asked the database whether the Jamf Patch catalog had moved
   (`SELECT count(*), max(synced_at) FROM jamf_patch_titles`) once per device with
   apps, forty thousand times a sweep to re-check an object that changes hourly at
   most. The catalog is now trusted for `CATALOG_PROBE_INTERVAL` between probes, so a
   sweep asks a handful of times rather than once per device.
2. `process_sync` replaced a device's extension-attribute rows wholesale on every read
   that covered the section — DELETE, flush, INSERT — including a repeat observation
   that changed nothing. It now diffs against the rows it already loaded, and a repeat
   sweep writes no EA row at all.

Counting statements rather than timing them: a statement count is the same on a
laptop and in CI, and "zero writes on a repeat" is a fact a stopwatch cannot state.

The opt-in benchmark at the bottom is the measurement the issue asked for first —
`LOON_BENCH_DEVICES=1000 RUN_DB_TESTS=1 uv run pytest tests/test_sweep_costs_db.py -k bench -s`
drives the FakeJamf harness at that fleet size and prints per-sweep statement counts
and wall time. It asserts nothing, so a slow CI runner can never fail it.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import time
import uuid as uuidlib
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
import pytest_asyncio
from sqlalchemy import delete, event, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

from tests.jamf_fake import HOST, FakeJamf  # noqa: E402


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """A Jamf connection with credentials, removed with everything under it afterwards
    (the same shape as test_jamf_sync_e2e's, for the same reasons)."""
    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"sweep costs {uuidlib.uuid4().hex[:8]}",
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


@contextmanager
def statements() -> Iterator[list[str]]:
    """Every SQL statement the engine sends while the block runs, in order."""
    from app.core.database import engine

    seen: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany) -> None:
        seen.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record)


def catalog_probes(seen: list[str]) -> list[str]:
    """The signature check `load_catalog` runs against `jamf_patch_titles`."""
    return [s for s in seen if "jamf_patch_titles" in s and "count(" in s]


def ea_writes(seen: list[str]) -> dict[str, int]:
    """INSERT / UPDATE / DELETE statements against `device_extension_attributes`, counted
    by verb. An `executemany` counts once — the point is whether a verb ran at all."""
    counts = {"INSERT": 0, "UPDATE": 0, "DELETE": 0}
    for statement in seen:
        verb = statement.lstrip().split(" ", 1)[0].upper()
        if verb in counts and "device_extension_attributes" in statement:
            counts[verb] += 1
    return counts


async def _ea_rows(db, connection_id: int) -> dict[tuple[int, str], tuple[int, str | None, list, str, bool | None]]:
    """Every EA row under the connection, keyed by (device, definition), with its row id —
    the id is how "untouched" is told apart from "deleted and re-inserted identically"."""
    from app.models.schema import Device, DeviceExtensionAttribute

    rows = (
        await db.execute(
            select(DeviceExtensionAttribute)
            .join(Device, Device.id == DeviceExtensionAttribute.device_id)
            .where(Device.mdm_connection_id == connection_id)
        )
    ).scalars().all()
    return {(r.device_id, r.definition_id): (r.id, r.name, list(r.values), r.source, r.enabled) for r in rows}


# --- the catalog probe ---------------------------------------------------------------


async def test_the_catalog_is_probed_once_per_sweep_not_once_per_device(db, jamf: FakeJamf, connection) -> None:
    """Eight devices, every one carrying apps: one signature check, not eight. The
    first device after a cold cache pays it; the rest trust the cache for the interval."""
    from app.mdm.patch.matching import reset_catalog_cache
    from app.mdm.service import sync_connection
    from app.models.schema import Device, InstalledApp

    jamf.seed(6)
    reset_catalog_cache()
    with statements() as seen:
        result = await sync_connection(db, connection)
    assert result.ok and result.device_count == 8, result

    assert len(catalog_probes(seen)) == 1, catalog_probes(seen)

    # Cheaper, not skipped: every app row still carries a judged answer.
    unjudged = (
        await db.execute(
            select(InstalledApp)
            .join(Device, Device.id == InstalledApp.device_id)
            .where(Device.mdm_connection_id == connection.id, InstalledApp.last_patch_check_at.is_(None))
        )
    ).scalars().all()
    assert unjudged == []


async def test_a_cold_cache_is_probed_and_a_reset_forces_the_next_probe(db, jamf: FakeJamf, connection) -> None:
    """The interval is a trust window, not a blindfold: `reset_catalog_cache` — what the
    in-process catalog writers call — makes the very next device pay the probe again."""
    from app.mdm.patch.matching import reset_catalog_cache
    from app.mdm.service import sync_connection

    reset_catalog_cache()
    with statements() as first:
        await sync_connection(db, connection)
    assert len(catalog_probes(first)) == 1

    with statements() as warm:
        await sync_connection(db, connection)
    assert catalog_probes(warm) == [], "a warm cache inside the interval is trusted"

    reset_catalog_cache()
    with statements() as after_reset:
        await sync_connection(db, connection)
    assert len(catalog_probes(after_reset)) == 1


# --- the extension-attribute churn -----------------------------------------------------


async def test_a_repeat_sweep_writes_no_extension_attribute_row(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import sync_connection

    first = await sync_connection(db, connection)
    assert first.ok and first.device_count == 2, first
    before = await _ea_rows(db, connection.id)
    assert before, "the fixture records carry extension attributes"

    with statements() as seen:
        second = await sync_connection(db, connection)
    assert second.ok and second.device_count == 2, second

    assert ea_writes(seen) == {"INSERT": 0, "UPDATE": 0, "DELETE": 0}
    # Same ids, same content: the rows were left alone, not rebuilt to look the same.
    assert await _ea_rows(db, connection.id) == before


async def test_only_the_extension_attributes_that_moved_are_written(db, jamf: FakeJamf, connection) -> None:
    """One value changed, one definition gone, one new: one UPDATE, one DELETE, one INSERT,
    and every other row — on this device and the other one — keeps its id."""
    from app.mdm.service import sync_connection

    await sync_connection(db, connection)
    before = await _ea_rows(db, connection.id)

    top_level = jamf.synthetic["extensionAttributes"]
    changed = top_level[0]
    changed["values"] = ["moved"]
    gone = top_level.pop(1)
    added = json.loads(json.dumps(changed))
    added["definitionId"] = "142142"
    added["name"] = "Sweep cost census"
    added["values"] = ["new"]
    top_level.append(added)

    with statements() as seen:
        result = await sync_connection(db, connection)
    assert result.ok, result
    assert ea_writes(seen) == {"INSERT": 1, "UPDATE": 1, "DELETE": 1}

    after = await _ea_rows(db, connection.id)
    device_id = next(dev for (dev, definition) in before if definition == str(changed["definitionId"]))
    changed_key = (device_id, str(changed["definitionId"]))
    gone_key = (device_id, str(gone["definitionId"]))
    added_key = (device_id, "142142")

    assert after[changed_key][0] == before[changed_key][0], "updated in place, same row id"
    assert after[changed_key][2] == ["moved"]
    assert gone_key not in after
    assert after[added_key][2] == ["new"]
    untouched = set(before) - {changed_key, gone_key}
    assert {key: after[key] for key in untouched} == {key: before[key] for key in untouched}


# --- the measurement -----------------------------------------------------------------


@pytest.mark.skipif(not os.environ.get("LOON_BENCH_DEVICES"), reason="opt-in: set LOON_BENCH_DEVICES=<fleet size>")
async def test_bench_sweep_costs(db, jamf: FakeJamf, connection) -> None:
    """Not a test: the FakeJamf harness driven at a chosen fleet size, printing what each
    sweep cost. Run with `-s` to see it. The clones carry the synthetic record's twelve
    apps and seven extension attributes each."""
    from app.mdm.patch.matching import reset_catalog_cache
    from app.mdm.service import sync_connection

    fleet = int(os.environ["LOON_BENCH_DEVICES"])
    jamf.seed(max(fleet - 2, 0))
    reset_catalog_cache()
    for label in ("first sweep", "repeat sweep"):
        with statements() as seen:
            started = time.perf_counter()
            result = await sync_connection(db, connection)
            elapsed = time.perf_counter() - started
        assert result.ok, result
        writes = ea_writes(seen)
        print(
            f"\n[bench] {label}: devices={result.device_count} seconds={elapsed:.1f} "
            f"statements={len(seen)} catalog_probes={len(catalog_probes(seen))} "
            f"ea_insert={writes['INSERT']} ea_update={writes['UPDATE']} ea_delete={writes['DELETE']}"
        )
