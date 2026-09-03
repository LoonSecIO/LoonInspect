"""The `deviceMeta` block against the ruling that spent its slots (#189).

#189 ruled the starting keys on 2026-08-31: **twelve of thirteen slots spent, the
thirteenth held open deliberately** — adding a key costs one release, removing one is a
breaking change to every saved search a customer ever wrote. PR #191 built the block and
carried two keys the ruling's own *Refused* table had cut, `comparison` and
`collectionID`, because the code they came from (`run_meta`) predated the ruling and
nothing held it to the table. This suite is that mechanism.

It matters more than the two keys. `deviceMeta` is the one object whose cost is measured
in fields x events x devices x syncs: it is stamped onto every app, every extension
attribute, every certificate and every profile a device produces, and the fan-out
([#242](https://github.com/LoonSecIO/LoonInspect/issues/242)) multiplies it again. A key
that drifts in here is not one wrong field, it is one wrong field written a hundred-odd
times per device per sync — and after the public flip it can never be taken back, because
additive-only clause 3 (`docs/splunk-wire-vocabulary.md` §5) says a key that ships is
never removed.

Pure logic, no database: `_device_meta` reads a `RunContext` out of a ContextVar and a
`Device` row, and both can be built in hand. `tests/test_runs.py` asserts the same block
end to end against a real sweep, and `tests/test_wire_casing.py` judges the casing of
every family at once; this file is the one that judges the *membership* of the set.
"""

from __future__ import annotations

import uuid as uuidlib
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core.runs import (
    LOCK_DEVICE_SWEEP,
    TRIGGER_SWEEP,
    RunContext,
    reset_run,
    run_meta,
)
from app.core.runs import set_run as _set_run
from app.mdm.service import _device_meta
from app.models.schema import Device
from app.schemas.payload import WIRE_SCHEMA_VERSION

# The ruling's table, in its own order, in the casing the wire ships today. The table was
# written the day before #188 froze `ID` uppercase on LoonInspect-minted names, so it
# spells slots 5 and 7 `jobId` and `connectionId`; #188 ruled the narrow uppercase clause
# and the code, `docs/runs.md` and `docs/splunk-wire-vocabulary.md` §4 all carry `jobID`
# and `connectionID`. The names are the ruling's; the casing is #188's.
RULED_TWELVE: tuple[str, ...] = (
    "serialNumber",  # 1  identity   — the join key across every sourcetype
    "jamfProID",  # 2  identity   — the only identity that costs zero aperture
    "hostName",  # 3  identity   — what every OTHER sourcetype in the customer's Splunk knows
    "eventID",  # 4  correlation— one device's one pull, exactly
    "jobID",  # 5  provenance — the run (`jobId` in the ruling's table, #188 recased)
    "shortDate",  # 6  correlation— the cheap daily grain
    "connectionID",  # 7  scope      — a security control, not readability (#188 recased)
    "trigger",  # 8  provenance — sweep | manual | webhook
    "lastReportDate",  # 9  freshness  — current app list, or six weeks stale
    "managed",  # 10 scope      — the compliance filter, two values fleet-wide
    "schemaVersion",  # 11 integrity
    "custom",  # 12 reserved   — NAME ONLY, zero bytes in v0
)

# Slot 12 reserves a name and ships nothing: "Reserve the name, freeze the shape, ship no
# code." The feature is its own issue for the first post-flip release. Reserving is what
# closes the 2029 hazard structurally — with customer keys in the flat namespace a
# customer who picks `osVersion` in 2026 permanently blocks the product from adding it.
RESERVED = "custom"
SHIPPED_ELEVEN: tuple[str, ...] = tuple(key for key in RULED_TWELVE if key != RESERVED)

# The ruling's *Refused* table, plus the two this file exists for. Each was cut on its own
# argument and each has a stated home elsewhere; what is asserted here is only that none
# of them is in `deviceMeta`.
REFUSED: dict[str, str] = {
    # The two that shipped anyway in PR #191, and the reason this suite exists.
    "comparison": "describes run history, not the row — `_comparison_for` returns "
    "`delta` for every device of every run after the first. Rides `run.completed`, "
    "joined by jobID.",
    "collectionID": "verified null on the entire webhook path, so a BY clause over it "
    "produces a null bucket that silently means `webhook`. Belongs on the run's own "
    "event, joined by jobID.",
    # The rest of the refused table, pinned so a later round has to re-argue rather than
    # rediscover.
    "assignedUser": "drags USER_AND_LOCATION into the mandatory aperture — serial-keyed lookup",
    "department": "structurally empty (Jamf 11.31 returns departmentId) — lookup",
    "building": "structurally empty (Jamf 11.31 returns buildingId) — lookup",
    "site": 'Jamf\'s no-site sentinel is the literal string "None" — connectionID, then custom.groups',
    "udid": "the closest call — lineage is the observation ledger's job, not Splunk's",
    "osVersion": "mortgages OPERATING_SYSTEM permanently — the os sub-event",
    "supervised": "already first-class on the general sub-event",
    "lastReportDays": "decays into a lie the day after indexing — compute at search time",
    "daysSince": "same, and unreachable at delivery anyway",
    "tenantID": "one constant repeated millions of times a night — the index and the token",
    "apertureDigest": "a property of the run — loon:run, joined by jobID",
    "contractVersion": "a property of the run — loon:run, joined by jobID",
    "collectorVersion": "a property of the run — loon:run, joined by jobID",
    "occurredAt": "already on the payload top level and in the HEC time envelope",
    "jamfHost": "~104 GB/yr for legibility the HEC `source` slot gives away",
}

_RUN_ID = uuidlib.UUID("6f1b6f7e-6d2b-4d4a-9c6d-0f4c2a7f9c11")
_WINDOW = datetime(2026, 8, 31, 2, 0, tzinfo=timezone.utc)


@pytest.fixture
def run() -> Iterator[RunContext]:
    """A sweep run with BOTH refused values populated.

    Deliberately not null: a test whose fixture happened to carry `collection_id=None`
    would pass against the null-dropping rule rather than against the ruling, and would
    keep passing the day someone put the key back.
    """
    context = RunContext(
        id=_RUN_ID,
        connection_id=1,
        collection_id=4,
        trigger=TRIGGER_SWEEP,
        comparison="delta",
        lock_class=LOCK_DEVICE_SWEEP,
        window_start=_WINDOW,
    )
    token = _set_run(context)
    try:
        yield context
    finally:
        reset_run(token)


def _device(**overrides) -> Device:
    """A device with every ruled key's source populated, so the emitted set is the whole
    shipped eleven rather than whatever survived the null drop."""
    fields = {
        "external_id": "1743",
        "serial_number": "C02XL0THJGH5",
        "hostname": "kyle-mbp",
        "last_inventory_at": datetime(2026, 8, 31, 21, 44, 3, tzinfo=timezone.utc),
        "managed": True,
    }
    return Device(**(fields | overrides))


def test_the_block_is_exactly_the_ruled_eleven(run: RunContext) -> None:
    """The whole ruling in one assertion: the names, and nothing but the names.

    Equality, not containment, in both directions. A subset check would miss the defect
    this suite was written for — `comparison` and `collectionID` were *extra*, not
    missing — and a superset check would miss a key silently dropped.

    A set, not a sequence: JSON objects carry no order and Splunk's extraction does not
    see one, so pinning the emitted order would be a test asserting something the wire
    does not promise.
    """
    assert set(_device_meta(_device())) == set(SHIPPED_ELEVEN)


def test_the_two_keys_the_ruling_cut_are_gone(run: RunContext) -> None:
    """#189's *Refused* table, held against the block PR #191 actually built.

    The run context above carries a real `comparison` and a real `collection_id`, so this
    fails on the code rather than on the fixture.
    """
    meta = _device_meta(_device())
    for key, why in REFUSED.items():
        assert key not in meta, f"#189 refused `{key}`: {why}"
    assert {"comparison", "collectionID"} & set(meta) == set()


def test_the_run_half_is_four_keys_not_six(run: RunContext) -> None:
    """`run_meta()` is the producer, so the refusal is enforced where the keys were born.

    Removing them at `_device_meta` and leaving `run_meta` spreading six would put the
    block one `**` away from carrying them again.
    """
    assert set(run_meta()) == {"jobID", "trigger", "connectionID", "shortDate"}
    assert set(run_meta()) < set(SHIPPED_ELEVEN)


def test_the_reserved_slot_ships_no_bytes(run: RunContext) -> None:
    """Slot 12 is a name, not a key. `custom` is ruled and emitted by nothing in v0 — the
    shape (`custom.groups`, `custom.ea`) is frozen precisely so that adding it later is
    not a shape change to `| fields deviceMeta.*`."""
    assert RESERVED in RULED_TWELVE
    assert RESERVED not in _device_meta(_device())


def test_the_cap_holds_with_room_for_the_open_slot(run: RunContext) -> None:
    """Thirteen keys, twelve spent, one held open. The unspent slot is the only insurance
    against being wrong about something nobody has thought of yet, so the assertion is on
    the cap and on the ruling's own budget, not just on today's count."""
    assert len(RULED_TWELVE) == 12
    assert len(_device_meta(_device())) == 11
    assert len(_device_meta(_device())) <= 13


def test_nulls_are_dropped_rather_than_shipped(run: RunContext) -> None:
    """The rule that pays for the block being over half the raw feed. A device Jamf has
    never completed inventory on ships without `lastReportDate`, not with a null — and the
    emitted set stays a subset of the ruled names either way."""
    meta = _device_meta(_device(last_inventory_at=None, hostname="", managed=None))
    assert "lastReportDate" not in meta
    assert "hostName" not in meta
    assert "managed" not in meta
    assert all(value is not None for value in meta.values())
    assert set(meta) < set(SHIPPED_ELEVEN)


def test_the_values_are_the_ruled_ones(run: RunContext) -> None:
    """Names alone are not the contract — a key carrying the wrong value is the same
    zero-rows-with-no-error failure as a misspelled one.

    `eventID` is asserted as its derivation rather than as a literal: it is derived, not
    minted, ON PURPOSE, so a retry recomputes the same id and any other producer of this
    pull can arrive at it without either side passing it along.
    """
    meta = _device_meta(_device())
    assert meta["jobID"] == str(_RUN_ID)
    assert meta["trigger"] == TRIGGER_SWEEP
    assert meta["connectionID"] == 1
    assert meta["shortDate"] == "2026-08-31"
    assert meta["eventID"] == str(uuidlib.uuid5(_RUN_ID, "1743"))
    assert meta["serialNumber"] == "C02XL0THJGH5"
    assert meta["jamfProID"] == "1743"
    assert meta["hostName"] == "kyle-mbp"
    assert meta["lastReportDate"] == "2026-08-31T21:44:03+00:00"
    assert meta["managed"] is True
    assert meta["schemaVersion"] == WIRE_SCHEMA_VERSION


def test_outside_a_run_the_block_is_the_device_half_alone() -> None:
    """No run fixture. `run_meta()` returns `{}` outside a run, so the block degrades to
    the device's own keys instead of raising — and `eventID`, which needs the run, drops
    out under the null rule rather than shipping a half-derived id."""
    meta = _device_meta(_device())
    assert "eventID" not in meta
    assert set(meta) == {"serialNumber", "jamfProID", "hostName", "lastReportDate", "managed", "schemaVersion"}
    assert set(meta) < set(SHIPPED_ELEVEN)


def test_the_docs_name_the_same_keys() -> None:
    """`docs/runs.md` §4 carries the block's own JSON example, and it is what a reader
    reaches for before the code. It drifting is how PR #191's two extra keys stayed
    invisible for three days."""
    docs = Path(__file__).resolve().parents[2] / "docs" / "runs.md"
    text = docs.read_text()
    example = text.split('The `deviceMeta` block on `device.inventory.changed`, ruled in #189:', 1)[1]
    example = example.split("```", 2)[1]
    assert set(REFUSED) & set(RULED_TWELVE) == set()
    for key in SHIPPED_ELEVEN:
        assert f'"{key}"' in example, f"docs/runs.md's deviceMeta example is missing {key}"
    for key in ("comparison", "collectionID"):
        assert f'"{key}"' not in example, f"docs/runs.md still shows the refused key {key}"
