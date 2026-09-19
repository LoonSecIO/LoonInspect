"""Three per-object costs on the sweep's hot path, pinned by statement count (#142, #569).

All three were modest at hundreds of objects and wrong at the design target, and none
shows up in a functional test because all three produce the right rows — they just
produce them expensively:

1. `record_device_apps` asked the database whether the Jamf Patch catalog had moved
   (`SELECT count(*), max(synced_at) FROM jamf_patch_titles`) once per device with
   apps, forty thousand times a sweep to re-check an object that changes hourly at
   most. The catalog is now trusted for `CATALOG_PROBE_INTERVAL` between probes, so a
   sweep asks a handful of times rather than once per device.
2. `process_sync` replaced a device's extension-attribute rows wholesale on every read
   that covered the section — DELETE, flush, INSERT — including a repeat observation
   that changed nothing. It now diffs against the rows it already loaded, and a repeat
   sweep writes no EA row at all.
3. The catalog censuses — smart groups, extension-attribute definitions — asked the
   ledger for the current span once per object. A tenant with 300 groups paid 300
   selects on every one of the day's 25 passes, for objects that rarely move. Each
   census now loads its kind's current spans in one select and hands each observation
   its own. A read loaded before the loop cannot see what the loop writes, so the last
   test here pins the one case where that matters: a census that names the same new
   subject twice has to finish, the way the per-object read let it.

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

from app.core.runs import TRIGGER_SWEEP  # noqa: E402
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
        (
            await db.execute(
                select(DeviceExtensionAttribute)
                .join(Device, Device.id == DeviceExtensionAttribute.device_id)
                .where(Device.mdm_connection_id == connection_id)
            )
        )
        .scalars()
        .all()
    )
    return {(r.device_id, r.definition_id): (r.id, r.name, list(r.values), r.source, r.enabled) for r in rows}


# --- the catalog probe ---------------------------------------------------------------


async def test_the_catalog_is_probed_once_per_sweep_not_once_per_device(db, jamf: FakeJamf, connection) -> None:
    """Eight devices, every one carrying apps: one signature check, not eight. The
    first device after a cold cache pays it; the rest trust the cache for the interval."""
    from app.mdm.collections import run_enabled_collections
    from app.mdm.patch.matching import reset_catalog_cache
    from app.models.schema import Device, InstalledApp

    jamf.seed(6)
    reset_catalog_cache()
    with statements() as seen:
        result = await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
    assert result.ok and result.device_count == 8, result

    assert len(catalog_probes(seen)) == 1, catalog_probes(seen)

    # Cheaper, not skipped: every app row still carries a judged answer.
    unjudged = (
        (
            await db.execute(
                select(InstalledApp)
                .join(Device, Device.id == InstalledApp.device_id)
                .where(Device.mdm_connection_id == connection.id, InstalledApp.last_patch_check_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert unjudged == []


async def test_a_cold_cache_is_probed_and_a_reset_forces_the_next_probe(db, jamf: FakeJamf, connection) -> None:
    """The interval is a trust window, not a blindfold: `reset_catalog_cache` — what the
    in-process catalog writers call — makes the very next device pay the probe again."""
    from app.mdm.collections import run_enabled_collections
    from app.mdm.patch.matching import reset_catalog_cache

    reset_catalog_cache()
    with statements() as first:
        await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
    assert len(catalog_probes(first)) == 1

    with statements() as warm:
        await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
    assert catalog_probes(warm) == [], "a warm cache inside the interval is trusted"

    reset_catalog_cache()
    with statements() as after_reset:
        await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
    assert len(catalog_probes(after_reset)) == 1


# --- the extension-attribute churn -----------------------------------------------------


async def test_a_repeat_sweep_writes_no_extension_attribute_row(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.collections import run_enabled_collections

    first = await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
    assert first.ok and first.device_count == 2, first
    before = await _ea_rows(db, connection.id)
    assert before, "the fixture records carry extension attributes"

    with statements() as seen:
        second = await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
    assert second.ok and second.device_count == 2, second

    assert ea_writes(seen) == {"INSERT": 0, "UPDATE": 0, "DELETE": 0}
    # Same ids, same content: the rows were left alone, not rebuilt to look the same.
    assert await _ea_rows(db, connection.id) == before


async def test_only_the_extension_attributes_that_moved_are_written(db, jamf: FakeJamf, connection) -> None:
    """One value changed, one definition gone, one new: one UPDATE, one DELETE, one INSERT,
    and every other row — on this device and the other one — keeps its id."""
    from app.mdm.collections import run_enabled_collections

    await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
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
        result = await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
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


# --- the catalog censuses' per-object span read ----------------------------------------


def _group(index: int) -> dict:
    return {"id": str(100 + index), "name": f"Rollout wave {index}", "siteId": "-1", "criteria": []}


def _definition(index: int) -> dict:
    return {
        "id": str(200 + index),
        "name": f"Census probe {index}",
        "description": "",
        "dataType": "STRING",
        "enabled": True,
        "inventoryDisplayType": "GENERAL",
        "inputType": {"type": "SCRIPT", "script": "#!/bin/sh"},
    }


def span_reads_by_subject(seen: list[str]) -> list[str]:
    """SELECTs that fetch ONE span by its subject id — what each census ran once per
    object. A sweep still runs one per device on purpose, so this is only nil for a
    catalog-only pass."""
    return [s for s in seen if "FROM observation_spans" in s and "observation_spans.subject_id = " in s]


def span_census_reads(seen: list[str]) -> list[str]:
    """SELECTs that fetch every current span of one kind, whole rows, in one statement.
    `head_digest` in the select list is what tells this apart from `reconcile_census`'s
    id-only read of the same rows; the absent `subject_id = ` is what tells it from the
    per-object read above."""
    return [
        s
        for s in seen
        if "FROM observation_spans" in s and "observation_spans.head_digest" in s and "observation_spans.subject_id = " not in s
    ]


async def test_a_catalog_pass_reads_the_spans_once_per_kind_not_once_per_object(db, jamf: FakeJamf, connection) -> None:
    """Twelve groups and eleven definitions: two census reads and no per-object read at
    all — on the pass that mints the spans and on the pass that finds them unchanged.
    Before #569 this pass cost twenty-three single-subject selects, both times."""
    from app.mdm.service import run_jamf_catalog

    jamf.smart_groups.extend(_group(index) for index in range(1, 12))
    jamf.extension_attribute_definitions.extend(_definition(index) for index in range(1, 9))

    with statements() as minting:
        first = await run_jamf_catalog(db, connection, trigger="manual")
    assert first.ok and first.group_count == 12, first
    assert first.observations["group_new"] == 12
    assert first.observations["ea_definition_new"] == 11
    assert len(span_census_reads(minting)) == 2, span_census_reads(minting)
    assert span_reads_by_subject(minting) == []

    with statements() as repeat:
        second = await run_jamf_catalog(db, connection, trigger="manual")
    assert second.ok, second
    # The outcome is the proof the cheap read found the same spans the dear one did: a
    # preloaded span that missed its subject would read as `new` and mint a second span.
    assert second.observations["group_unchanged"] == 12
    assert second.observations["ea_definition_unchanged"] == 11
    assert len(span_census_reads(repeat)) == 2, span_census_reads(repeat)
    assert span_reads_by_subject(repeat) == []


async def test_the_batched_span_still_tells_an_object_that_moved_from_one_that_did_not(db, jamf: FakeJamf, connection) -> None:
    """One group's criteria edited and one definition disabled between two passes: one
    `changed` each, every other object `unchanged`, and the new spans point back at the
    ones the batch loaded."""
    from app.mdm.service import run_jamf_catalog
    from app.models.schema import ObservationSpan

    jamf.smart_groups.extend(_group(index) for index in range(1, 12))
    jamf.extension_attribute_definitions.extend(_definition(index) for index in range(1, 9))
    assert (await run_jamf_catalog(db, connection, trigger="manual")).ok

    jamf.smart_group_criteria = [{"name": "Managed", "priority": 0, "andOr": "and", "searchType": "is not", "value": "Managed"}]
    jamf.extension_attribute_definitions[0]["enabled"] = False

    with statements() as seen:
        moved = await run_jamf_catalog(db, connection, trigger="manual")
    assert moved.ok, moved
    assert moved.observations["group_changed"] == 1 and moved.observations["group_unchanged"] == 11
    assert moved.observations["ea_definition_changed"] == 1 and moved.observations["ea_definition_unchanged"] == 10
    assert len(span_census_reads(seen)) == 2, span_census_reads(seen)
    assert span_reads_by_subject(seen) == []

    # A closed span and a current one that names it: the batch handed `record_observation`
    # the row it closes, not a copy of it.
    history = (
        (
            await db.execute(
                select(ObservationSpan)
                .where(ObservationSpan.mdm_connection_id == connection.id, ObservationSpan.subject_id == "1")
                .order_by(ObservationSpan.first_observed_at)
            )
        )
        .scalars()
        .all()
    )
    assert [row.is_current for row in history] == [False, True]
    assert history[1].previous_id == history[0].id


async def test_a_census_that_names_one_new_subject_twice_still_completes(db, jamf: FakeJamf, connection) -> None:
    """The duplicate a batched read has to survive, on the pass where it hurts most: the
    subject is new, so the map read before the loop has no span for it either time.

    Both endpoints are offset-paginated over a live tenant and neither dedupes, so one
    object listed on two pages is the ordinary hazard, not a contrivance. Handing the
    same `None` out twice would take `record_observation`'s `new` branch twice and the
    second insert would violate `uq_observation_spans_current_subject`, which
    `run_jamf_catalog` catches as a failed pass — losing the groups, the definitions, the
    org units and the departure reconciliation with it. `CensusSpans.take` answers
    `current_loaded=False` on the repeat instead, so the second read finds the row the
    first one wrote, exactly as the per-object read did before #569.
    """
    from app.mdm.service import run_jamf_catalog
    from app.models.schema import ObservationSpan

    jamf.smart_groups.extend(_group(index) for index in range(1, 4))
    jamf.smart_groups.append(jamf.smart_groups[-1])
    jamf.extension_attribute_definitions.extend(_definition(index) for index in range(1, 3))
    jamf.extension_attribute_definitions.append(jamf.extension_attribute_definitions[-1])

    with statements() as seen:
        result = await run_jamf_catalog(db, connection, trigger="manual")
    assert result.ok, result.error
    # One group and one definition listed twice: the second sighting reads as `unchanged`
    # against the span the first one opened — the outcome the per-object read gave, on the
    # fixture's one base group and three base definitions plus what this test added.
    assert result.observations["group_new"] == 4
    assert result.observations["group_unchanged"] == 1
    assert result.observations["ea_definition_new"] == 5
    assert result.observations["ea_definition_unchanged"] == 1

    # The win is intact: the duplicate buys back one per-object read, and one only.
    assert len(span_census_reads(seen)) == 2, span_census_reads(seen)
    assert len(span_reads_by_subject(seen)) == 2, span_reads_by_subject(seen)

    current = (
        (
            await db.execute(
                select(ObservationSpan.subject_id).where(
                    ObservationSpan.mdm_connection_id == connection.id,
                    ObservationSpan.subject_kind == "computer_group",
                    ObservationSpan.is_current.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    assert sorted(current) == sorted(set(current)), "the duplicate minted a second current span"


async def test_the_batch_read_refuses_the_kind_that_is_streamed(db, connection) -> None:
    """40k device spans are what the sweep's paging exists to avoid holding at once, so
    the device kind is refused rather than merely discouraged — before a second MDM's
    catalog pass copies the seam and reaches for it."""
    from app.mdm.jamf.contract import SUBJECT_COMPUTER
    from app.observations.ledger import current_spans

    with pytest.raises(ValueError, match="streamed"):
        await current_spans(db, connection_id=connection.id, subject_kind=SUBJECT_COMPUTER)


# --- the measurement -----------------------------------------------------------------


@pytest.mark.skipif(not os.environ.get("LOON_BENCH_DEVICES"), reason="opt-in: set LOON_BENCH_DEVICES=<fleet size>")
async def test_bench_sweep_costs(db, jamf: FakeJamf, connection) -> None:
    """Not a test: the FakeJamf harness driven at a chosen fleet size, printing what each
    sweep cost. Run with `-s` to see it. The clones carry the synthetic record's twelve
    apps and seven extension attributes each."""
    from app.mdm.collections import run_enabled_collections
    from app.mdm.patch.matching import reset_catalog_cache

    fleet = int(os.environ["LOON_BENCH_DEVICES"])
    jamf.seed(max(fleet - 2, 0))
    reset_catalog_cache()
    for label in ("first sweep", "repeat sweep"):
        with statements() as seen:
            started = time.perf_counter()
            result = await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
            elapsed = time.perf_counter() - started
        assert result.ok, result
        writes = ea_writes(seen)
        print(
            f"\n[bench] {label}: devices={result.device_count} seconds={elapsed:.1f} "
            f"statements={len(seen)} catalog_probes={len(catalog_probes(seen))} "
            f"ea_insert={writes['INSERT']} ea_update={writes['UPDATE']} ea_delete={writes['DELETE']}"
        )
