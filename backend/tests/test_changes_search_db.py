"""Searching the change feed by the artifact that changed, over HTTP and a real Postgres.

The investigation this pins runs artifact-first: "which Macs installed Wireshark, and
when" — the direction `q` (device name, serial, Jamf id) cannot answer at all. What is
asserted here is that `artifact` finds the devices that touched the thing, does not
return the ones that did not, composes with every existing filter rather than replacing
it, leaves `q` behaving exactly as before, and — the security property — cannot be made
to reach across a tenant boundary.

Rows are inserted directly rather than derived from a sweep: the derive path is already
covered end to end by test_changes_db.py, and what is under test here is the query, so
the fixture states plainly what each row's `entry_identity` holds. Gated on RUN_DB_TESTS
because row-level security is the mechanism carrying the tenancy assertion and SQLite
has no opinion about it.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

# One event loop for the module, for the reason spelled out in test_tenancy_sweep.py:
# app.core.database's engine is created at import and its pooled connections belong to
# whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# A tenant of this file's own, distinct from the one test_tenancy_sweep.py seeds, so the
# two files can share a database without either owning the other's rows.
NEIGHBOUR_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000a7")

ADMIN = ("admin@artifact-search.example.com", "artifact-search-password")

BASE = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

# Two stamps that differ in every key (app.changes.derive.DEVICE_META_KEYS), and the span two
# rows of one observation share.
# The tokens the derive path keys per tenant (app.changes.person_token), literal for the reason
# the rest of the fixture is: the query is under test, not the derivation. The third is on no row.
DANA_TOKEN, OPS_TOKEN, STRANGER_TOKEN = "u_DanaTokenAAAAAAX", "u_OpsTokenBBBBBBBX", "u_NobodyTokenCCCCX"

AIR = {
    "model": "MacBook Air (M3, 2024)",
    "osVersion": "26.6.2",
    "fileVault": "BOOT_ENCRYPTED",
    "departmentId": "5",
    "managed": True,
    "username": "dana",
    "realName": "Dana Okonkwo",
    "email": "dana@example.com",
    "userToken": DANA_TOKEN,
}
MINI = {
    "model": "Mac mini (2024) M4",
    "osVersion": "27.0",
    "fileVault": "NOT_ENCRYPTED",
    "departmentId": "9",
    "managed": False,
    "username": "ops",
    "realName": "Ops Service",
    "email": "ops@example.com",
    "userToken": OPS_TOKEN,
}
WEBHOOK_SPAN = uuidlib.UUID("2f6c1e4a-7b93-4d21-9a05-6c1d8e3f4b77")


def _change(connection_id: int, **kwargs):
    from app.models.schema import DeviceChange

    defaults = {
        "mdm_connection_id": connection_id,
        "subject_kind": "computer",
        "observed_at": BASE,
        "collected_at": BASE,
        "trigger": "sweep",
        "change": "added",
        "level": "normal",
        "policy_version": "v0",
    }
    return DeviceChange(**{**defaults, **kwargs})


def _app(name: str, bundle_id: str) -> dict:
    """An application row's identity, exactly as app.changes.policy's rule builds it."""
    return {"name": name, "bundleId": bundle_id, "path": f"/Applications/{name}.app"}


def _span(connection_id: int, subject_id: str, span_id):
    """The observation two change rows of one pull point at — `span_id` is a real foreign key,
    and the id is fixed here so a test can name it."""
    from app.models.schema import ObservationSpan

    return ObservationSpan(
        id=span_id,
        mdm_connection_id=connection_id,
        subject_kind="computer",
        subject_id=subject_id,
        contract_version="v1",
        aperture_digest="v1:" + "e" * 64,
        head_digest="v1:" + "a" * 64,
        section_digests={"applications": "v1:" + "0" * 64},
        first_observed_at=BASE,
        last_observed_at=BASE,
        first_collected_at=BASE,
        last_collected_at=BASE,
        last_trigger="webhook",
        is_current=False,
    )


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded():
    """Two tenants, each with a connection and a handful of changes — including a
    Wireshark install in *both*, which is what makes the tenancy assertion mean
    something. Without the neighbour's Wireshark row, a leak would be invisible."""
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, MdmConnection, Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, NEIGHBOUR_TENANT_ID) is None:
            db.add(Tenant(id=NEIGHBOUR_TENANT_ID, slug="artifact-neighbour", name="Artifact Neighbour", kind="operational"))
            await db.commit()

    ids: dict[str, int] = {}
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        account = (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first()
        if account is None:
            await create_account(db, email=ADMIN[0], display_name="artifact search", password=ADMIN[1], roles=("admin",))
        mine = MdmConnection(
            name=f"artifact search jamf {uuidlib.uuid4().hex[:8]}",
            provider="jamf",
            base_url="https://artifact-search.jamfcloud.com",
        )
        db.add(mine)
        await db.flush()
        ids["mine"] = mine.id
        db.add(_span(mine.id, "108", WEBHOOK_SPAN))
        await db.flush()
        db.add_all(
            [
                # The needle, on two different Macs an hour apart. Both carry the dimensions
                # the derive path stamps (#447), and they differ in every one of them, so a
                # filter that matches both is not filtering.
                _change(
                    mine.id,
                    subject_id="101",
                    subject_label="design-mbp",
                    serial_number="ARTSER101",
                    section="applications",
                    entry_kind="application",
                    entry_identity=_app("Wireshark", "org.wireshark.Wireshark"),
                    device_meta=AIR,
                ),
                _change(
                    mine.id,
                    subject_id="102",
                    subject_label="finance-mini",
                    serial_number="ARTSER102",
                    section="applications",
                    entry_kind="application",
                    device_meta=MINI,
                    observed_at=BASE + timedelta(hours=1),
                    collected_at=BASE + timedelta(hours=1),
                    entry_identity=_app("Wireshark", "org.wireshark.Wireshark"),
                ),
                # A high-level Wireshark-adjacent row, for the level composition check.
                _change(
                    mine.id,
                    subject_id="103",
                    subject_label="lab-mbp",
                    serial_number="ARTSER103",
                    section="applications",
                    entry_kind="application",
                    level="high",
                    entry_identity=_app("WiresharkChmodBPF", "org.wireshark.ChmodBPF"),
                ),
                # Devices that did NOT install it.
                _change(
                    mine.id,
                    subject_id="104",
                    subject_label="design-mbp-two",
                    serial_number="ARTSER104",
                    section="applications",
                    entry_kind="application",
                    entry_identity=_app("Slack", "com.tinyspeck.slackmacgap"),
                ),
                # An entry kind whose name lives in entry_label, not in the identity.
                _change(
                    mine.id,
                    subject_id="105",
                    subject_label="hr-mba",
                    serial_number="ARTSER105",
                    section="group_memberships",
                    entry_kind="group_membership",
                    entry_identity={"groupId": "12"},
                    entry_label="Packet Capture Operators",
                ),
                # A local account, named only in the identity.
                _change(
                    mine.id,
                    subject_id="106",
                    subject_label="ops-mini",
                    serial_number="ARTSER106",
                    section="local_user_accounts",
                    entry_kind="local_user_account",
                    level="high",
                    entry_identity={"uid": "503", "username": "pcap_service"},
                ),
                # What the webhook brought, in one observation of one Mac: two rows sharing a
                # span, a version moved to, and the only row with `trigger=webhook` (#447).
                _change(
                    mine.id,
                    subject_id="108",
                    subject_label="webhook-mba",
                    serial_number="ARTSER108",
                    section="applications",
                    entry_kind="application",
                    change="updated",
                    trigger="webhook",
                    span_id=WEBHOOK_SPAN,
                    device_meta=AIR,
                    entry_identity=_app("Google Chrome", "com.google.Chrome"),
                    old_value={"version": "152.0.6999.11"},
                    new_value={"version": "153.0.7049.84"},
                ),
                _change(
                    mine.id,
                    subject_id="108",
                    subject_label="webhook-mba",
                    serial_number="ARTSER108",
                    section="operating_system",
                    field="version",
                    change="changed",
                    trigger="webhook",
                    span_id=WEBHOOK_SPAN,
                    device_meta=AIR,
                    old_value={"value": "26.6.1"},
                    new_value={"value": "26.6.2"},
                ),
                # A field change: no entry at all, so `artifact` must never surface it.
                _change(
                    mine.id,
                    subject_id="107",
                    subject_label="wireshark-lab-mac",
                    serial_number="ARTSER107",
                    section="security",
                    field="firewallEnabled",
                    change="changed",
                    level="high",
                    old_value={"value": True},
                    new_value={"value": False},
                ),
            ]
        )
        await db.commit()

    async with session_for_tenant(NEIGHBOUR_TENANT_ID) as db:
        theirs = MdmConnection(
            name=f"neighbour jamf {uuidlib.uuid4().hex[:8]}",
            provider="jamf",
            base_url="https://neighbour.jamfcloud.com",
        )
        db.add(theirs)
        await db.flush()
        ids["theirs"] = theirs.id
        db.add_all(
            [
                _change(
                    theirs.id,
                    subject_id="901",
                    subject_label="neighbour-mbp",
                    serial_number="NBRSER901",
                    section="applications",
                    entry_kind="application",
                    entry_identity=_app("Wireshark", "org.wireshark.Wireshark"),
                ),
                _change(
                    theirs.id,
                    subject_id="902",
                    subject_label="neighbour-mini",
                    serial_number="NBRSER902",
                    section="local_user_accounts",
                    entry_kind="local_user_account",
                    entry_identity={"uid": "504", "username": "pcap_service"},
                ),
            ]
        )
        await db.commit()

    try:
        yield ids
    finally:
        from app.models.schema import MdmConnection as Conn

        for tenant_id, key in ((OPERATIONAL_TENANT_ID, "mine"), (NEIGHBOUR_TENANT_ID, "theirs")):
            async with session_for_tenant(tenant_id) as db:
                await db.execute(delete(Conn).where(Conn.id == ids[key]))  # changes cascade
                await db.commit()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def client(seeded):
    """Signed in as the operational tenant's admin, CSRF armed. https, because the
    session cookie is Secure and a plain-http client silently discards it."""
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://artifact-search.example.com") as c:
        response = await c.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
        c.headers["X-CSRF-Token"] = c.cookies.get("loon_csrf", "")
        yield c


async def _feed(client, query: str) -> dict:
    """The whole feed, unscoped — the shape the tenancy assertion needs."""
    response = await client.get(f"/api/changes?{query}")
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def feed(client, seeded):
    """Every assertion but the tenancy one runs scoped to this file's own connection.
    The test database is shared with the rest of the suite, and a set-equality assertion
    over the whole feed would pass or fail on whatever another module left behind."""

    async def _scoped(query: str) -> dict:
        return await _feed(client, f"connectionId={seeded['mine']}&pageSize=200&{query}")

    return _scoped


# `userFilter` is null unless a `user` filter was applied (#446) — "nothing was asked" rather
# than "asked, and nothing resolved it", which is the pair of nulls inside it.
EMPTY = {"items": [], "total": 0, "page": 1, "pageSize": 200, "userFilter": None}


def _subjects(body: dict) -> set[str]:
    return {row["subjectId"] for row in body["items"]}


# --- the query the feed could not answer ------------------------------------------


async def test_artifact_finds_the_devices_that_installed_it(feed) -> None:
    """The whole point: start at the app, fan out to the Macs. Every device that
    installed Wireshark, in one query, with no idea up front which devices to ask
    about — the direction `q` cannot express at all."""
    body = await feed("artifact=Wireshark")
    assert _subjects(body) == {"101", "102", "103"}
    assert all(row["entryKind"] == "application" for row in body["items"])
    # Newest first is unchanged by the filter, so "and when" is answered by the order.
    # 101 and 103 share an observed_at; the tiebreak is id DESC, which is why this reads
    # the timestamps rather than pinning a total order the fixture does not fix.
    stamps = [row["observedAt"] for row in body["items"]]
    assert stamps == sorted(stamps, reverse=True) and body["items"][0]["subjectId"] == "102"


async def test_artifact_does_not_return_devices_that_did_not(feed) -> None:
    """The negative half. The Slack Mac is in the same feed, the same connection, and
    the same section — and a Wireshark search must not reach it."""
    assert "104" not in _subjects(await feed("artifact=Wireshark"))
    assert _subjects(await feed("artifact=slackmacgap")) == {"104"}


async def test_artifact_matches_bundle_id_label_and_username(feed) -> None:
    """The three places a row can say what changed: an application's bundle id, the
    label a group/profile/EA carries, and a local account's username."""
    assert _subjects(await feed("artifact=org.wireshark.Wireshark")) == {"101", "102"}
    assert _subjects(await feed("artifact=Packet%20Capture")) == {"105"}
    assert _subjects(await feed("artifact=pcap_service")) == {"106"}


async def test_artifact_never_matches_a_field_change(feed) -> None:
    """Device 107 is named "wireshark-lab-mac" and its change is a firewall flip with no
    entry at all. `artifact` asks what changed, not who it changed on: a NULL
    entry_identity must not match, or every scalar change on a suggestively named Mac
    turns into noise in an artifact search."""
    assert "107" not in _subjects(await feed("artifact=wireshark"))
    # ...and `q`, which does ask who, still finds it.
    assert "107" in _subjects(await feed("q=wireshark-lab-mac"))


async def test_artifact_is_case_insensitive_and_substring(feed) -> None:
    """Operators type "wireshark", not "Wireshark" and never the full bundle id. The
    strip() matters because the frontend hands over whatever was pasted."""
    assert _subjects(await feed("artifact=WIRESHARK")) == {"101", "102", "103"}
    assert _subjects(await feed("artifact=%20%20shark%20%20")) == {"101", "102", "103"}


# --- composition, not replacement --------------------------------------------------


async def test_artifact_composes_with_the_existing_filters(feed) -> None:
    """Every existing filter narrows an artifact search rather than being ignored by it,
    and — the reason this is a second parameter and not a widened `q` — `q` AND
    `artifact` means "this device AND this app", which one needle cannot express."""
    assert _subjects(await feed("artifact=Wireshark&level=high")) == {"103"}
    assert _subjects(await feed("artifact=Wireshark&section=applications")) == {"101", "102", "103"}
    assert await feed("artifact=Wireshark&section=security") == EMPTY
    assert _subjects(await feed("artifact=Wireshark&subjectId=102")) == {"102"}
    assert _subjects(await feed("artifact=Wireshark&subjectKind=computer")) == {"101", "102", "103"}
    assert await feed("artifact=Wireshark&subjectKind=computer_group") == EMPTY

    since = (BASE + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    assert _subjects(await feed(f"artifact=Wireshark&since={since}")) == {"102"}

    # The AND that has no single-needle equivalent: a widened `q` could only ever have
    # answered this as an OR, and would have returned all four devices.
    assert _subjects(await feed("q=finance&artifact=Wireshark")) == {"102"}
    assert await feed("q=finance&artifact=Slack") == EMPTY


async def test_q_is_unchanged_for_existing_callers(feed) -> None:
    """The regression guard on the decision not to widen `q`. If a later change folds
    the artifact needle into `q`, the last two assertions fail — which is the point:
    every bookmarked feed URL and the frontend's own search box would start returning
    rows they did not return before, silently."""
    # `q` still matches the device by name, serial, and Jamf id...
    assert _subjects(await feed("q=design-mbp")) == {"101", "104"}
    assert _subjects(await feed("q=ARTSER105")) == {"105"}
    assert _subjects(await feed("q=106")) == {"106"}
    # ...and still matches nothing by what changed. Every seeded Wireshark row belongs
    # to a device whose name, serial and id say nothing about Wireshark.
    assert await feed("q=org.wireshark.Wireshark") == EMPTY
    assert _subjects(await feed("q=pcap_service")) == set()


async def test_q_finds_a_mac_name_typed_with_either_apostrophe(feed, seeded) -> None:
    """macOS names a Mac with U+2019, the typographic apostrophe, and Jamf reports the
    name as the Mac has it; an operator types the ASCII one, and so does a model. `q`
    folds it on both sides, so either spelling finds the Mac. The row is this test's own
    and is gone afterwards, so the assertions around it keep their seed."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import DeviceChange

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        row = _change(
            seeded["mine"],
            subject_id="108",
            subject_label="Kyle\u2019s Mac mini",
            serial_number="ARTSER108",
            section="general",
            field="name",
            change="changed",
            old_value={"value": "Mac mini"},
            new_value={"value": "Kyle\u2019s Mac mini"},
        )
        db.add(row)
        await db.commit()
        row_id = row.id
    try:
        assert _subjects(await feed("q=Kyle%27s%20Mac%20mini")) == {"108"}
        assert _subjects(await feed("q=kyle%27s")) == {"108"}
        # The typographic spelling still finds it, and still matches only it.
        assert _subjects(await feed("q=Kyle%E2%80%99s%20Mac")) == {"108"}
        assert _subjects(await feed("q=Mac%20mini")) == {"108"}
    finally:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(delete(DeviceChange).where(DeviceChange.id == row_id))
            await db.commit()


async def test_total_counts_the_filtered_set_not_the_feed(feed, client, seeded) -> None:
    """`total` drives pagination; a filter that reached the rows but not the count would
    offer a page 2 of a Wireshark search that is empty when you click it."""
    body = await feed("artifact=Wireshark")
    assert body["total"] == len(body["items"]) == 3
    paged = await _feed(client, f"connectionId={seeded['mine']}&artifact=Wireshark&pageSize=2")
    assert paged["total"] == 3 and len(paged["items"]) == 2


# --- the security property ---------------------------------------------------------


async def test_artifact_search_cannot_cross_a_tenant_boundary(client, seeded) -> None:
    """THE test of this change. The neighbouring tenant installed the same Wireshark on
    the same day and has a local account with the same username; the new filter is a new
    way to reach `device_changes`, and it must inherit row-level security exactly as the
    old one does — in the rows AND in the count, since a `total` that includes a
    neighbour's rows leaks their fleet's size for any artifact an attacker can name.

    Asserted through the authenticated HTTP client, not a scoped session, so it fails if
    the endpoint ever acquires its session any way other than the tenant-scoped one.
    """
    from app.core.database import session_for_tenant
    from app.models.schema import DeviceChange

    theirs = seeded["theirs"]

    mine = seeded["mine"]

    for needle in ("Wireshark", "org.wireshark.Wireshark", "pcap_service", "shark"):
        body = await _feed(client, f"artifact={needle}&pageSize=200")
        # An assertion about absence is worthless if the search returned nothing at all,
        # so each needle first has to prove it reached this tenant's own matching rows.
        assert any(row["mdmConnectionId"] == mine for row in body["items"]), needle
        assert all(row["mdmConnectionId"] != theirs for row in body["items"]), needle
        assert not (_subjects(body) & {"901", "902"}), needle
        assert body["total"] == len(body["items"]), f"{needle}: total must count only the visible rows"

    # Naming the neighbour's connection id outright is not a way in either.
    assert await _feed(client, f"artifact=Wireshark&connectionId={theirs}&pageSize=200") == EMPTY
    assert await _feed(client, f"connectionId={theirs}&pageSize=200") == EMPTY

    # And the neighbour's rows are still there — this is invisibility, not deletion —
    # while the partition holds in the other direction too: from inside their tenant the
    # whole of device_changes is their two rows, artifact predicate or not.
    async with session_for_tenant(NEIGHBOUR_TENANT_ID) as db:
        rows = (await db.execute(select(DeviceChange))).scalars().all()
        assert {r.subject_id for r in rows} == {"901", "902"}
        assert all(r.mdm_connection_id == theirs for r in rows)


# --- #107: minLevel, the range filter three surfaces need -----------------------------
#
# `level` is exact-match and stays that way — it is what the Changes page's dropdown
# means and what a bookmarked URL already carries. `minLevel` is "this and above", the
# filter the Overview feed needs to show notable-and-above without naming two levels.
#
# This file's seed carries `high` and `normal` rows and no `low`, which is enough to pin
# the wiring: `minLevel=high` must exclude the normal rows, and `minLevel=normal` must
# include them. The ordering itself — including `low` — is exhaustively unit-tested in
# test_change_policy.py, where it needs no database.


async def test_min_level_high_returns_only_high(feed) -> None:
    body = await feed("minLevel=high")
    assert {row["level"] for row in body["items"]} == {"high"}
    # And it is a real narrowing of this seed, not a filter that happened to match all.
    assert _subjects(body) == {"103", "106", "107"}


async def test_min_level_normal_is_notable_and_above(feed) -> None:
    body = await feed("minLevel=normal")
    assert {row["level"] for row in body["items"]} == {"high", "normal"}
    # Every seeded row, because this seed has no `low` — which is exactly why the
    # widening direction is asserted on the levels present rather than on a count.
    assert _subjects(body) >= {"101", "102", "103", "104", "105", "106", "107"}


async def test_min_level_composes_with_the_other_filters(feed) -> None:
    """It narrows alongside `artifact` rather than replacing it — the same property
    `level` has, so a caller can move from one to the other without losing a filter."""
    # `artifact` is a substring match, so "Wireshark" also reaches 103's
    # WiresharkChmodBPF — the level is what separates them, not the needle.
    assert _subjects(await feed("artifact=Wireshark&minLevel=normal")) == {"101", "102", "103"}
    # At `high`, only 103 survives — the same answer `level=high` gives one test above,
    # which is the point: moving from exact to range must not change what a filter means.
    assert _subjects(await feed("artifact=Wireshark&minLevel=high")) == {"103"}


async def test_level_and_min_level_together_are_refused(client, seeded) -> None:
    """Composed they are well-defined and useless — `level=low&minLevel=normal` is "low
    changes that are at least normal", always empty — and an empty feed reads as "nothing
    happened". Refused rather than answered with a silent zero."""
    response = await client.get(f"/api/changes?connectionId={seeded['mine']}&level=low&minLevel=normal")
    assert response.status_code == 422
    assert "mutually exclusive" in response.text


async def test_an_unknown_min_level_is_refused_like_an_unknown_level(client, seeded) -> None:
    response = await client.get(f"/api/changes?connectionId={seeded['mine']}&minLevel=notable")
    assert response.status_code == 422
    assert "minLevel must be one of" in response.text


# --- the Change filter (2026-09-14): the kind of change, exact -------------------------
#
# What the Changes page's Change dropdown means, and what the Prompt bar sets for "new
# installs": an entry is added, removed or updated, a field is changed. This seed's
# entries are all installs and its one field change is 107's firewall flip.


async def test_change_narrows_to_one_kind(feed, seeded) -> None:
    """An install and an update of the same app, told apart by the kind alone. The
    update is this test's own row, on a Mac of its own, and is gone afterwards, so the
    assertions around it keep their seed."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import DeviceChange

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        row = _change(
            seeded["mine"],
            subject_id="109",
            subject_label="qa-mini",
            serial_number="ARTSER109",
            section="applications",
            entry_kind="application",
            change="updated",
            entry_identity=_app("Wireshark", "org.wireshark.Wireshark"),
        )
        db.add(row)
        await db.commit()
        row_id = row.id
    try:
        assert _subjects(await feed("artifact=Wireshark")) == {"101", "102", "103", "109"}
        assert _subjects(await feed("artifact=Wireshark&change=added")) == {"101", "102", "103"}
        assert _subjects(await feed("artifact=Wireshark&change=updated")) == {"109"}
        assert await feed("artifact=Wireshark&change=removed") == EMPTY
        # Alone it narrows the whole feed, rows and count alike.
        installs = await feed("change=added")
        assert {row["change"] for row in installs["items"]} == {"added"}
        assert _subjects(installs) == {"101", "102", "103", "104", "105", "106"}
        assert installs["total"] == len(installs["items"])
        # 107's firewall field and 108's OS version, the one this file's webhook observation
        # carries beside an app update (#447).
        assert _subjects(await feed("change=changed")) == {"107", "108"}
        # And it composes: the field change is `changed` in its section, and only there.
        assert _subjects(await feed("section=security&change=changed")) == {"107"}
        assert await feed("section=security&change=added") == EMPTY
    finally:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(delete(DeviceChange).where(DeviceChange.id == row_id))
            await db.commit()


async def test_an_unknown_change_is_refused_like_an_unknown_level(client, seeded) -> None:
    """A typo is a sentence naming the four kinds, not an empty feed that reads as
    "nothing was installed"."""
    response = await client.get(f"/api/changes?connectionId={seeded['mine']}&change=installed")
    assert response.status_code == 422
    assert response.json()["detail"] == "change must be one of added, removed, updated, changed"


# --- what is filterable is wider than what the table shows (#447) --------------------------------


async def test_the_trigger_that_found_a_change_is_a_filter(feed) -> None:
    """Every row carries what started the observation it was found in, and nothing could ask.
    "What did the webhook bring in?" is one predicate now."""
    assert _subjects(await feed("trigger=webhook")) == {"108"}
    assert "108" not in _subjects(await feed("trigger=sweep"))
    assert await feed("trigger=manual") == EMPTY


async def test_an_unknown_trigger_is_refused_rather_than_answered_empty(client, seeded) -> None:
    response = await client.get(f"/api/changes?connectionId={seeded['mine']}&trigger=cron")
    assert response.status_code == 422
    assert response.json()["detail"] == "trigger must be one of sweep, manual, webhook"


async def test_one_observation_is_a_filter_so_what_else_moved_is_one_query(feed, client, seeded) -> None:
    """`spanId` is the local `deviceMeta.eventID`: everything found in one pull of one Mac. The
    two webhook rows share theirs — an app version and the OS version in the same observation."""
    body = await feed(f"spanId={WEBHOOK_SPAN}")
    assert {row["section"] for row in body["items"]} == {"applications", "operating_system"}
    assert body["total"] == 2
    assert all(row["spanId"] == str(WEBHOOK_SPAN) for row in body["items"])
    bad = await client.get(f"/api/changes?connectionId={seeded['mine']}&spanId=not-a-uuid")
    assert bad.status_code == 422
    assert bad.json()["detail"] == "spanId must be a UUID"


async def test_the_version_a_change_moved_to_is_a_filter_by_prefix(feed) -> None:
    """ "Who moved to Chrome 153" — a marketing version against a build string, which is the
    shape of the question. The value it moved *from* stays unsearchable."""
    assert _subjects(await feed("version=153")) == {"108"}
    assert _subjects(await feed("version=153.0.7049.84")) == {"108"}
    # 152 is the old value on that same row: a filter on it finds nothing.
    assert await feed("version=152") == EMPTY


async def test_each_stamped_dimension_narrows_the_feed(feed) -> None:
    """The Mac as its own observation saw it. Both Wireshark rows match the app; they differ in
    every dimension, so each filter has to pick exactly one of them."""
    assert _subjects(await feed("artifact=Wireshark")) == {"101", "102", "103"}
    # A model an operator half-remembers, anywhere in the value.
    assert _subjects(await feed("artifact=Wireshark&model=Air")) == {"101"}
    assert _subjects(await feed("artifact=Wireshark&model=mac mini")) == {"102"}
    # A version prefix: 26 covers 26.6.2 and leaves 27.0 out.
    assert _subjects(await feed("artifact=Wireshark&osVersion=26")) == {"101"}
    assert _subjects(await feed("artifact=Wireshark&osVersion=27")) == {"102"}
    # Exact, for what Jamf's own catalog numbers and for a boolean.
    assert _subjects(await feed("artifact=Wireshark&department=5")) == {"101"}
    assert _subjects(await feed("artifact=Wireshark&managed=false")) == {"102"}
    assert _subjects(await feed("artifact=Wireshark&managed=true")) == {"101"}
    assert _subjects(await feed("artifact=Wireshark&fileVault=NOT_ENCRYPTED")) == {"102"}
    # Any of the three names the ledger holds for the assigned person.
    assert _subjects(await feed("user=dana")) == {"101", "108"}
    assert _subjects(await feed("user=Okonkwo")) == {"101", "108"}
    assert _subjects(await feed("user=dana@example.com")) == {"101", "108"}
    assert _subjects(await feed("user=ops")) == {"102"}


async def test_the_person_filters_as_a_token_and_the_response_says_who(feed) -> None:
    """#446: the value a shared link carries, and the echo that lets a chip read as a person.

    A `u_…` matches the row's own `userToken` exactly, reaching the Macs `user=dana` reaches and
    naming nobody on the way, while typed text is untouched. Exact, not contains: one character
    off finds nothing, and so does a token from before a key rotation — a stale link gets an empty
    feed and a chip saying so, not a refusal. The echo costs no new table and no scan over
    persons: typed text matching one person comes back as that person's token, which is how a
    name stops travelling, and text matching two comes back as neither.
    """
    dana = {"token": DANA_TOKEN, "display": "Dana Okonkwo"}
    assert _subjects(await feed(f"user={DANA_TOKEN}")) == {"101", "108"}
    assert _subjects(await feed(f"user={OPS_TOKEN}")) == {"102"}
    assert _subjects(await feed("user=dana")) == {"101", "108"}
    # Not `EMPTY`: a `user` query carries a `userFilter` even when nothing matched. The third is
    # a row with no stamp at all, out of reach of either shape.
    for query in (f"user={DANA_TOKEN[:-1]}A", f"user={STRANGER_TOKEN}", "artifact=Slack&user=dana"):
        assert (await feed(query))["total"] == 0
    assert (await feed(f"user={DANA_TOKEN}"))["userFilter"] == dana
    assert (await feed("user=Okonkwo"))["userFilter"] == dana
    assert (await feed("user=ops"))["userFilter"] == {"token": OPS_TOKEN, "display": "Ops Service"}
    assert (await feed("user=example.com"))["userFilter"] == {"token": None, "display": None}
    assert (await feed(f"user={STRANGER_TOKEN}"))["userFilter"] == {"token": STRANGER_TOKEN, "display": None}
    assert (await feed("artifact=Wireshark"))["userFilter"] is None


async def test_dimensions_compose_with_each_other_and_with_the_rest(feed) -> None:
    assert _subjects(await feed("model=Air&trigger=webhook")) == {"108"}
    assert await feed("model=Air&trigger=sweep&version=153") == EMPTY
    assert _subjects(await feed("model=Air&section=operating_system")) == {"108"}


async def test_a_row_with_no_stamp_matches_no_dimension(feed) -> None:
    """Rows derived before the stamp existed carry none — and so do subjects that are not
    devices. They are absent from a dimension filter rather than counted as "not a MacBook Air",
    which is the bound `list_changes` states and the page says beneath an empty table."""
    unstamped = _subjects(await feed("artifact=Slack"))
    assert unstamped == {"104"}
    assert await feed("artifact=Slack&model=Air") == EMPTY
    assert await feed("artifact=Slack&managed=true") == EMPTY
    assert await feed("artifact=Slack&managed=false") == EMPTY
    # The same row is still there without the dimension, so the filter narrowed, not the seed.
    assert _subjects(await feed("artifact=Slack&trigger=sweep")) == {"104"}


async def test_the_udid_is_a_fourth_name_for_a_device(feed) -> None:
    """A link from another system carries the UDID, which was on every row and reachable from
    nowhere."""
    assert _subjects(await feed("q=ARTSER101")) == {"101"}
    assert await feed("q=00008132-000C28101485801E") == EMPTY
