"""The daily exchange's sad paths against a real Postgres (INSPECT-0082, -0083).

`post_exchange` and the due-ness arithmetic are covered without a database in
test_sharing.py. What needs one is the property those tests cannot see: what the
share-log row ends up saying. A failed exchange must still land a row, because the
row is what consumes the day — an upstream answering 200 with a non-JSON body used
to raise past `db.add` entirely, so `exchange_due` said yes again on the next tick
and the once-a-day exchange became a crash loop. And since #624 no exchange answers a
reveal request: the row shows what was asked beside the empty `reveals` that left.
Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def _reset(db) -> None:
    """Clear this suite's exchange rows and put the tier back to "reveal".

    Not the shipped default any more — that is "off", so an unanswered install shares
    nothing (test_sharing_consent_db.py). This suite is about what a *consented*
    instance puts on the wire, so it sets the tier the consent would have set. Other
    suites share the tenant, so only what this suite touches is cleared — the AI rows
    (tier "ai") share the log and are left alone."""
    from app.core.sharing import get_or_create_settings
    from app.models.schema import ShareLog

    await db.rollback()
    await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
    # get-or-create rather than "update it if it happens to be there": with the default
    # at "off", a row this suite does not find is a row that would silently short-circuit
    # every exchange below into a no-op, and a suite about the wire would pass by never
    # reaching it.
    row = await get_or_create_settings(db)
    row.tier = "reveal"
    row.pending_reveal_keys = []
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db):
    await _reset(db)
    yield
    await _reset(db)


async def test_exclude_globs_cover_the_reveal_path(db, clean) -> None:
    """The operator's exclude list must gag the plaintext path, not just the hashes.

    Until INSPECT-0174 `_excluded` had one call site — build_exchange_request — so an
    excluded app vanished from the snapshot (and from the preview button, which is the
    trust feature) while its NAME still crossed the wire the moment the server asked
    about the title. The snapshot leaks a hash; this path leaks "Acme Payroll". Both
    apps below are pending reveals; only the unexcluded one may come back.
    """
    import uuid as uuidlib

    from app.core.sharing import build_reveals
    from app.models.schema import DataSharingSettings, Device, InstalledApp

    suffix = uuidlib.uuid4().hex[:8]
    device = Device(
        mdm_provider="jamf",
        external_id=f"reveal-{suffix}",
        serial_number=f"SER{suffix}",
        hostname=f"host-{suffix}",
    )
    db.add(device)
    await db.commit()

    secret_key = f"v1:secret{suffix}"[:67]
    public_key = f"v1:public{suffix}"[:67]

    def app(name, bundle_id, key):
        return InstalledApp(
            device_id=device.id,
            name=name,
            bundle_id=bundle_id,
            version="1.0",
            app_hash=uuidlib.uuid4().hex,
            version_hash=uuidlib.uuid4().hex,
            key_title=key,
            key_full=key,
        )

    db.add_all(
        [
            app(f"Acme Payroll {suffix}", "com.acme.payroll", secret_key),
            app(f"Google Chrome {suffix}", "com.google.Chrome", public_key),
        ]
    )
    await db.commit()

    row = (await db.execute(select(DataSharingSettings))).scalar_one()
    row.tier = "reveal"
    row.pending_reveal_keys = [secret_key, public_key]
    row.exclude_globs = ["com.acme.*"]
    await db.commit()

    try:
        reveals = await build_reveals(db, row)
    finally:
        row.exclude_globs = []
        row.pending_reveal_keys = []
        await db.commit()
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id == device.id))
        await db.execute(delete(Device).where(Device.id == device.id))
        await db.commit()

    titles = {entry["title"] for entry in reveals}
    assert public_key in titles, "an unexcluded pending title must still be revealed"
    assert secret_key not in titles, "an excluded bundle id leaked its title through the reveal path"
    # The name is the thing that must not travel; assert on it directly rather than
    # trusting that filtering the title was enough.
    names = {entry["app_name"] for entry in reveals}
    assert not any(name.startswith("Acme Payroll") for name in names), f"plaintext name leaked: {names}"


async def test_hardware_rows_count_models_and_a_device_without_one_has_no_row(db, clean) -> None:
    """#481: the first `hardware` list this container has ever assembled, and the one row
    it must never produce.

    `hw` identifies a machine by its model alone, so a device whose model identifier has
    not been read is **absent** from the list rather than hashed over the empty string —
    one shared digest for every unidentified Mac, counted by the corpus as one machine
    (`app_bundle_key` makes the same argument for the app domain). That device is still an
    `os` row, which is the half that has to keep working while the columns fill in: they
    are un-backfilled, so until a sweep has covered a fleet, some of its devices have a
    model and some do not.

    The SQL is the subject here, so this needs a real Postgres: the stub-session tests in
    test_sharing.py cannot see a WHERE clause. The fixture values are unique to the run
    because other suites share this tenant's `devices` table — what the real record
    actually carries is pinned by the normalizer test in test_jamf_observation_contract.py.
    """
    import uuid as uuidlib

    from app.core.content_keys import hw_key, os_key
    from app.core.sharing import build_exchange_request, get_or_create_settings
    from app.models.schema import Device

    suffix = uuidlib.uuid4().hex[:8]
    version, build, model = f"15.6.1-{suffix}", f"24G{suffix}", f"Mac16,{suffix}"

    def _device(n: int, **columns) -> Device:
        return Device(
            mdm_provider="jamf",
            external_id=f"hw-{suffix}-{n}",
            serial_number=f"SER{suffix}{n}",
            hostname=f"host-{suffix}-{n}",
            os_version=version,
            os_build=build,
            **columns,
        )

    rows = [
        _device(1, model_identifier=model, cpu_arch="arm64"),
        _device(2, model_identifier=model, cpu_arch="arm64"),
        # Read for its OS and not yet for its hardware — the state every device is in
        # between the upgrade and its next sweep.
        _device(3),
    ]
    db.add_all(rows)
    await db.commit()

    try:
        snapshot = (await build_exchange_request(db, await get_or_create_settings(db)))["snapshot"]
    finally:
        for row in rows:
            await db.delete(row)
        await db.commit()

    # Two of the three are identified, and the third is not a row — not a row with a key
    # over "", and not a row with a null key.
    assert [row for row in snapshot["hardware"] if row["key"] == hw_key(model, "arm64")] == [
        {"key": hw_key(model, "arm64"), "count": 2, "platform": "macos"}
    ], snapshot["hardware"]
    assert all(row["key"] != hw_key("", None) for row in snapshot["hardware"]), snapshot["hardware"]
    # All three are one os row, keyed on the build the container actually read.
    assert [row for row in snapshot["os"] if row["key"] == os_key("macos", version, build)] == [
        {"key": os_key("macos", version, build), "count": 3, "platform": "macos"}
    ], snapshot["os"]


async def _exchange_rows(db) -> list:
    from app.models.schema import ShareLog

    return (await db.execute(select(ShareLog).where(ShareLog.tier != "ai"))).scalars().all()


async def test_a_200_that_is_not_json_is_logged_and_consumes_the_day(db, clean, monkeypatch) -> None:
    """The captive-portal shape: 200, text/html, undecodable. It must behave exactly
    like any other failed attempt — no exception out of run_exchange, one share-log
    row recording the failure, and a day that is now spent rather than retried on
    the scheduler's next tick."""
    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import _due, _last_attempt_at, run_exchange

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>Sign in to the guest network</html>")

    # Midnight as the jittered slot, so "due" is decided by the log alone and not by
    # where in the day the suite happens to run.
    now = datetime.now(UTC)
    assert await _last_attempt_at(db) is None
    assert _due(now, None, minute_of_day=0) is True

    await run_exchange(db, transport=httpx.MockTransport(handler))

    (row,) = await _exchange_rows(db)
    assert row.outcome == "failed"
    assert row.error  # the decode error, recorded rather than swallowed
    assert row.payload is not None  # exactly what would have left, logged as always

    last = await _last_attempt_at(db)
    assert last is not None
    assert _due(datetime.now(UTC), last, minute_of_day=0) is False
    # Nothing was shed on this run, and a failed row never claims one was.
    assert row.reveals_shed is False


async def test_no_reveal_leaves_and_a_queued_request_is_dropped(db, clean, monkeypatch) -> None:
    """#624: "Suppress/clear pending reveal replies in v2". An instance upgraded with a request
    an older build queued, and a service that asks again: two exchanges, neither carrying a
    reveal. The queued request is dropped, the new ask is recorded and never stored, and the
    `reveal` tier still uploads its keys and counts under the tier the operator chose."""
    import json
    import uuid as uuidlib

    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import get_or_create_settings, run_exchange
    from app.models.schema import Device, InstalledApp

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)

    suffix = uuidlib.uuid4().hex[:8]
    title, name = f"v1:paused{suffix}", f"Paused Payroll {suffix}"
    device = Device(mdm_provider="jamf", external_id=f"paused-{suffix}", serial_number=f"SER{suffix}", hostname=f"h-{suffix}")
    db.add(device)
    await db.commit()
    db.add(
        InstalledApp(
            device_id=device.id,
            name=name,
            # Matched by no exclusion another suite might hold, so only the pause keeps `name` home.
            bundle_id=f"io.example.paused{suffix}",
            version="1.0",
            app_hash=uuidlib.uuid4().hex,
            version_hash=uuidlib.uuid4().hex,
            key_title=title,
            key_full=title,
        )
    )
    # Queued by an older build, which would have answered it with `name` in plaintext.
    (await get_or_create_settings(db)).pending_reveal_keys = [title]
    await db.commit()

    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"contract": "v1", "reveal_requests": [title]})

    device_id = device.id  # the rollback below expires `device`
    try:
        for _ in range(2):
            await run_exchange(db, transport=httpx.MockTransport(handler))
    finally:
        await db.rollback()
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id == device_id))
        await db.execute(delete(Device).where(Device.id == device_id))
        await db.commit()

    assert len(sent) == 2
    for body in sent:
        assert body["reveals"] == [] and name not in json.dumps(body)
        assert body["tier"] == "reveal" and title in {app["title"] for app in body["snapshot"]["apps"]}
    # The ask is on the record, beside the empty answer that left, and nothing was shed.
    rows = [(r.outcome, r.payload["reveals"], r.reveals_shed, r.reveal_requests) for r in await _exchange_rows(db)]
    assert rows == [("sent", [], False, [title])] * 2
    row = await get_or_create_settings(db)
    assert row.pending_reveal_keys == [] and row.tier == "reveal"


async def test_a_failed_exchange_drops_a_queued_request_too(db, clean, monkeypatch) -> None:
    """The request is dropped before the post, so a day that fails drops it as well. With no
    reveals left to shed, a `413` is an ordinary failure: every attempt carries the same
    reveal-less body and the row claims no shed (docs/data-sharing.md, the `413` rule)."""
    import json

    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import get_or_create_settings, run_exchange

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)
    (await get_or_create_settings(db)).pending_reveal_keys = ["v1:aa"]
    await db.commit()

    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(413)

    await run_exchange(db, transport=httpx.MockTransport(handler))

    assert [body["reveals"] for body in sent] == [[], [], [], []]
    (log,) = await _exchange_rows(db)
    assert (log.outcome, log.reveals_shed, log.payload["reveals"]) == ("failed", False, [])
    await db.rollback()  # read the row back from the database, not from this session's memory
    row = await get_or_create_settings(db)
    assert row.pending_reveal_keys == [] and row.tier == "reveal"


async def test_an_ordinary_day_leaves_the_marker_false(db, clean, monkeypatch) -> None:
    """The marker is only worth reading if it is quiet on every normal exchange."""
    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import run_exchange

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"contract": "v1"})

    await run_exchange(db, transport=httpx.MockTransport(handler))

    (row,) = await _exchange_rows(db)
    assert row.outcome == "sent"
    assert row.reveals_shed is False
