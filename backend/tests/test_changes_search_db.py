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
from datetime import datetime, timedelta, timezone

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

BASE = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


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
        db.add_all(
            [
                # The needle, on two different Macs an hour apart.
                _change(mine.id, subject_id="101", subject_label="design-mbp", serial_number="ARTSER101",
                        section="applications", entry_kind="application",
                        entry_identity=_app("Wireshark", "org.wireshark.Wireshark")),
                _change(mine.id, subject_id="102", subject_label="finance-mini", serial_number="ARTSER102",
                        section="applications", entry_kind="application", observed_at=BASE + timedelta(hours=1),
                        collected_at=BASE + timedelta(hours=1),
                        entry_identity=_app("Wireshark", "org.wireshark.Wireshark")),
                # A high-level Wireshark-adjacent row, for the level composition check.
                _change(mine.id, subject_id="103", subject_label="lab-mbp", serial_number="ARTSER103",
                        section="applications", entry_kind="application", level="high",
                        entry_identity=_app("WiresharkChmodBPF", "org.wireshark.ChmodBPF")),
                # Devices that did NOT install it.
                _change(mine.id, subject_id="104", subject_label="design-mbp-two", serial_number="ARTSER104",
                        section="applications", entry_kind="application",
                        entry_identity=_app("Slack", "com.tinyspeck.slackmacgap")),
                # An entry kind whose name lives in entry_label, not in the identity.
                _change(mine.id, subject_id="105", subject_label="hr-mba", serial_number="ARTSER105",
                        section="group_memberships", entry_kind="group_membership",
                        entry_identity={"groupId": "12"}, entry_label="Packet Capture Operators"),
                # A local account, named only in the identity.
                _change(mine.id, subject_id="106", subject_label="ops-mini", serial_number="ARTSER106",
                        section="local_user_accounts", entry_kind="local_user_account", level="high",
                        entry_identity={"uid": "503", "username": "pcap_service"}),
                # A field change: no entry at all, so `artifact` must never surface it.
                _change(mine.id, subject_id="107", subject_label="wireshark-lab-mac", serial_number="ARTSER107",
                        section="security", field="firewallEnabled", change="changed", level="high",
                        old_value={"value": True}, new_value={"value": False}),
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
                _change(theirs.id, subject_id="901", subject_label="neighbour-mbp", serial_number="NBRSER901",
                        section="applications", entry_kind="application",
                        entry_identity=_app("Wireshark", "org.wireshark.Wireshark")),
                _change(theirs.id, subject_id="902", subject_label="neighbour-mini", serial_number="NBRSER902",
                        section="local_user_accounts", entry_kind="local_user_account",
                        entry_identity={"uid": "504", "username": "pcap_service"}),
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


EMPTY = {"items": [], "total": 0, "page": 1, "pageSize": 200}


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
