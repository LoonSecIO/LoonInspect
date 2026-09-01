"""GET /api/smart-groups/cost against a real Postgres, through the real ledger.

Two things are under test and only one of them is the ranking.

The security property is tenancy. The endpoint's query names no tenant: it joins
`observation_spans` to `observation_sections` on a digest, and a digest is content —
two tenants that both run a group called "All Managed" with identical criteria hold the
*same digest* in two rows. Nothing but row-level security keeps that join inside one
tenant, so this file seeds a second tenant whose group would sort to the very top of a
leaked answer, and asserts it is invisible: over HTTP as tenant one, and by running the
endpoint's own query under each tenant's session. It needs a non-superuser role for the
same reason the tenancy sweep does — a superuser bypasses RLS and every assertion here
would pass while proving nothing.

The rest pins the promise on the page: most expensive first, deterministically, and an
honest empty answer for a tenant that has never observed a group.

Gated on RUN_DB_TESTS; the tenancy sweep's docstring has the local incantation.
"""

from __future__ import annotations

import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# Distinct from the tenancy sweep's second tenant and from any other file's, so this
# module can be run alone or beside them without inheriting their rows.
TENANT_B_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000c1")
# A tenant that is deliberately never written to: the empty-answer case.
TENANT_EMPTY_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000c2")

ADMIN = ("sgcost-admin@cost.example.com", "smart-group-cost-password")

RUN = uuidlib.uuid4().hex[:8]  # unique subject ids, so a local re-run starts clean


def _group(group_id: str, name: str, criteria: list[dict]) -> dict:
    """A /v3/computer-groups/smart-groups/{id} object, as Jamf returns it."""
    return {"id": group_id, "name": name, "siteId": "-1", "isSmart": True, "criteria": criteria}


def _criterion(priority: int, name: str, search_type: str, value: str, **parens) -> dict:
    return {
        "name": name,
        "priority": priority,
        "andOr": "and" if priority else "",
        "searchType": search_type,
        "value": value,
        "openingParen": parens.get("opening", False),
        "closingParen": parens.get("closing", False),
    }


# Tenant A's five groups, cheapest last once ranked. The names carry no secrets; the
# one that must never cross is tenant B's.
GROUPS_A: list[dict] = [
    _group(
        f"{RUN}-1",
        "Serial regex sweep",
        [
            _criterion(0, "Serial Number", "matches regex", "^C02[A-Z0-9]+$"),
            _criterion(1, "Application Title", "matches regex", ".*(Chrome|Firefox).*"),
            _criterion(2, "Operating System Version", "is", "26.1"),
        ],
    ),
    _group(f"{RUN}-2", "One regex", [_criterion(0, "Antivirus Version", "matches regex", "^7\\.")]),
    _group(
        f"{RUN}-3",
        "Substring apps",
        [
            _criterion(0, "Application Title", "like", "Adobe", opening=True),
            _criterion(1, "Application Title", "like", "Microsoft", closing=True),
        ],
    ),
    _group(f"{RUN}-4", "Nested membership", [_criterion(0, "Computer Group", "member of", "All Managed")]),
    _group(f"{RUN}-5", "Exact site", [_criterion(0, "Building", "is", "HQ")]),
    _group(f"{RUN}-6", "No criteria at all", []),
]

# Tenant B's one group. Three regex criteria, so a leak would not merely appear in
# tenant A's answer — it would appear at the top of it.
GROUP_B = _group(
    f"{RUN}-b1",
    "TENANT B PRIVATE — executive laptops",
    [_criterion(i, "Serial Number", "matches regex", f"^X{i}") for i in range(3)],
)


async def _observe(db, connection_id: int, aperture_digest: str, raw: dict) -> None:
    from app.mdm.jamf.contract import canonicalize_smart_group
    from app.observations.ledger import record_observation

    await record_observation(
        db,
        connection_id=connection_id,
        observation=canonicalize_smart_group(raw),
        aperture_digest=aperture_digest,
        trigger="catalog",
    )


async def _seed_tenant(tenant_id, *, name: str, groups: list[dict], extension_attribute: str | None = None) -> int:
    from app.core.database import session_for_tenant
    from app.mdm.jamf.contract import V0_SECTIONS, build_aperture
    from app.models.schema import MdmConnection, ObservationEntry
    from app.observations.ledger import ensure_aperture

    async with session_for_tenant(tenant_id) as db:
        connection = MdmConnection(name=name, provider="jamf", base_url=f"https://{RUN}.jamfcloud.com")
        db.add(connection)
        await db.commit()
        digest = await ensure_aperture(
            db,
            connection_id=connection.id,
            aperture=build_aperture(
                host=f"{RUN}.jamfcloud.com", jamf_version="11.16.0", sections=V0_SECTIONS, inventory_collection={}
            ),
        )
        for raw in groups:
            await _observe(db, connection.id, digest, raw)
        if extension_attribute:
            # One EA the fleet has reported, so the endpoint can flag the criterion that
            # tests it. Written directly: the sweep that would normally produce it is a
            # whole device inventory, and none of this test needs a device.
            db.add(
                ObservationEntry(
                    digest=f"v0:{RUN}{'0' * (64 - len(RUN))}",
                    kind="extension_attribute",
                    body={"definitionId": "77", "values": ["7.1.0"]},
                    label=extension_attribute,
                )
            )
        await db.commit()
        return connection.id


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded():
    """Schema, three tenants, an admin who can sign in, and the groups above."""
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, MdmConnection, ObservationEntry, Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        for tenant_id, slug in ((TENANT_B_ID, "cost-second"), (TENANT_EMPTY_ID, "cost-empty")):
            if await db.get(Tenant, tenant_id) is None:
                db.add(Tenant(id=tenant_id, slug=slug, name=slug, kind="operational"))
        await db.commit()

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        if (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first() is None:
            await create_account(db, email=ADMIN[0], display_name="cost admin", password=ADMIN[1], roles=("admin",))
            await db.commit()

    connection_a = await _seed_tenant(
        OPERATIONAL_TENANT_ID, name=f"cost jamf a {RUN}", groups=GROUPS_A, extension_attribute="Antivirus Version"
    )
    connection_b = await _seed_tenant(TENANT_B_ID, name=f"cost jamf b {RUN}", groups=[GROUP_B])

    yield {"a": connection_a, "b": connection_b}

    # Deleting the connection cascades its spans; the content rows are shared and
    # content-addressed, so only the entry this file invented is removed.
    for tenant_id, connection_id in ((OPERATIONAL_TENANT_ID, connection_a), (TENANT_B_ID, connection_b)):
        async with session_for_tenant(tenant_id) as db:
            await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
            await db.execute(delete(ObservationEntry).where(ObservationEntry.digest.like(f"v0:{RUN}%")))
            await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def client(seeded):
    """Signed in as the operational tenant's admin, over https so the Secure cookie sticks."""
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://cost.example.com") as c:
        response = await c.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
        c.headers["X-CSRF-Token"] = c.cookies.get("loon_csrf", "")
        yield c


async def _mine(client, connection_id: int) -> list[dict]:
    response = await client.get("/api/smart-groups/cost")
    assert response.status_code == 200, response.text
    return [row for row in response.json()["items"] if row["mdmConnectionId"] == connection_id]


# --- what the page promises ---------------------------------------------------------


async def test_groups_come_back_most_expensive_first(client, seeded) -> None:
    rows = await _mine(client, seeded["a"])
    assert [row["name"] for row in rows] == [
        "Serial regex sweep",  # two regex criteria
        "One regex",  # one
        "Substring apps",  # like
        "Nested membership",  # member of: cheap rung, but above a plain equality
        "Exact site",
        "No criteria at all",
    ]
    assert [row["band"] for row in rows] == ["regex", "regex", "substring", "dependent", "exact", "none"]


async def test_the_criteria_come_back_as_jamf_reported_them(client, seeded) -> None:
    rows = {row["name"]: row for row in await _mine(client, seeded["a"])}

    heaviest = rows["Serial regex sweep"]
    assert heaviest["criteriaCount"] == 3
    assert heaviest["classCounts"] == {"exact": 1, "regex": 2}
    assert [c["operator"] for c in heaviest["criteria"]] == ["matches regex", "matches regex", "is"]
    assert [c["priority"] for c in heaviest["criteria"]] == [0, 1, 2]
    assert heaviest["criteria"][0]["value"] == "^C02[A-Z0-9]+$"

    # The parentheses Jamf reports, read back as depth.
    assert rows["Substring apps"]["maxDepth"] == 1
    assert rows["Serial regex sweep"]["maxDepth"] == 0

    # The EA the fleet reported is recognised as the tested field; the group whose
    # criterion tests a built-in inventory field is not flagged.
    assert rows["One regex"]["criteria"][0]["extensionAttribute"] is True
    assert rows["Exact site"]["criteria"][0]["extensionAttribute"] is False

    assert rows["Nested membership"]["dependentCount"] == 1
    assert rows["No criteria at all"]["criteria"] == []


async def test_the_answer_says_it_is_advisory_and_names_its_heuristic(client) -> None:
    """The claim is about someone else's product, so the disclaimer travels with the
    payload — an API consumer that never opens the page still gets it."""
    from app.mdm.jamf.group_cost import RANKING_VERSION

    body = (await client.get("/api/smart-groups/cost")).json()
    assert body["ranking"] == RANKING_VERSION
    assert "not a measurement" in body["advisory"]


async def test_the_order_is_the_same_on_every_request(client, seeded) -> None:
    first = [row["id"] for row in await _mine(client, seeded["a"])]
    second = [row["id"] for row in await _mine(client, seeded["a"])]
    assert first == second and len(first) == len(GROUPS_A)


async def test_a_tenant_with_no_groups_gets_an_empty_answer_not_an_error() -> None:
    from app.api.smart_groups import smart_group_cost
    from app.core.database import session_for_tenant

    async with session_for_tenant(TENANT_EMPTY_ID) as db:
        answer = await smart_group_cost(db=db)
    assert answer.total == 0 and answer.items == []


# --- the security property ----------------------------------------------------------


async def test_tenant_b_group_never_appears_in_tenant_a_answer(client, seeded) -> None:
    """The whole point. Tenant B's group is three regex criteria — if the digest join
    crossed the boundary it would be row one of tenant A's ranking, not a footnote."""
    body = (await client.get("/api/smart-groups/cost")).json()
    assert body["total"] == len(body["items"])
    assert all(row["mdmConnectionId"] != seeded["b"] for row in body["items"])
    assert all("TENANT B PRIVATE" not in (row["name"] or "") for row in body["items"])
    assert all(row["id"] != GROUP_B["id"] for row in body["items"])
    for row in body["items"]:
        for criterion in row["criteria"]:
            assert criterion["value"] not in {"^X0", "^X1", "^X2"}


async def test_the_endpoints_own_query_is_scoped_by_rls_in_both_directions(seeded) -> None:
    """Run the endpoint against each tenant's session directly. Tenant B has no HTTP
    login of its own (identity resolution is pinned to the operational tenant), so this
    is the only way to prove the boundary holds from B's side too — and it proves RLS
    is what holds it, since the query itself names no tenant."""
    from app.api.smart_groups import smart_group_cost
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        mine = await smart_group_cost(db=db)
    async with session_for_tenant(TENANT_B_ID) as db:
        theirs = await smart_group_cost(db=db)

    theirs_by_id = {row.id: row for row in theirs.items}
    assert GROUP_B["id"] in theirs_by_id
    assert theirs_by_id[GROUP_B["id"]].band == "regex"
    assert theirs_by_id[GROUP_B["id"]].criteria_count == 3
    assert {row.mdm_connection_id for row in theirs.items} == {seeded["b"]}

    mine_by_id = {row.id: row for row in mine.items}
    assert seeded["a"] in {row.mdm_connection_id for row in mine.items}
    assert GROUP_B["id"] not in mine_by_id
    # Not an equality on the whole set: other modules in the same session leave their
    # own connections (and their own groups) in the operational tenant. What must hold
    # is that none of tenant B's rows are among them.
    assert seeded["b"] not in {row.mdm_connection_id for row in mine.items}


async def test_identical_definitions_in_two_tenants_do_not_share_a_row(seeded) -> None:
    """The join is on a content digest, and content is identical across tenants by
    design — the same group definition in two Jamf tenants hashes the same. This asserts
    the duplication is real (one section row per tenant) rather than one shared row that
    RLS happens to hide, because a shared row would make the join a leak the moment RLS
    were bypassed for any reason."""
    from app.api.smart_groups import smart_group_cost
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.mdm.jamf.contract import GROUP_DEFINITION_SECTION, canonicalize_smart_group
    from app.models.schema import ObservationSection
    from app.observations.ledger import ensure_aperture, record_observation

    shared = _group(f"{RUN}-shared", "All Managed", [_criterion(0, "Building", "is", "HQ")])
    digest = canonicalize_smart_group(shared).sections[GROUP_DEFINITION_SECTION].digest

    async with session_for_tenant(TENANT_B_ID) as db:
        from app.mdm.jamf.contract import V0_SECTIONS, build_aperture

        aperture = await ensure_aperture(
            db,
            connection_id=seeded["b"],
            aperture=build_aperture(
                host=f"{RUN}.jamfcloud.com", jamf_version="11.16.0", sections=V0_SECTIONS, inventory_collection={}
            ),
        )
        await record_observation(
            db,
            connection_id=seeded["b"],
            observation=canonicalize_smart_group(shared),
            aperture_digest=aperture,
            trigger="catalog",
        )
        await db.commit()
        assert len((await db.execute(select(ObservationSection).where(ObservationSection.digest == digest))).all()) == 1

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        # Tenant A never observed this group. It must see neither the span nor the
        # section, even though the digest is one it could compute for itself.
        assert (await db.execute(select(ObservationSection).where(ObservationSection.digest == digest))).all() == []
        answer = await smart_group_cost(db=db)
    assert all(row.name != "All Managed" for row in answer.items)


async def test_the_endpoint_requires_a_session(seeded) -> None:
    """Unauthenticated callers get nothing. The route is under /api/, so it inherits the
    session requirement — this asserts nobody added it to the public list by accident."""
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://cost.example.com") as anonymous:
        response = await anonymous.get("/api/smart-groups/cost")
    assert response.status_code == 401


async def test_read_only_no_writes_leak_into_the_ledger(client, seeded) -> None:
    """The feature is a read. Nothing it does may open a span, and nothing it does may
    reach Jamf — the whole answer is assembled from rows already stored."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import ObservationSpan

    async def spans() -> list[tuple]:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            rows = (
                await db.execute(
                    select(ObservationSpan.subject_id, ObservationSpan.last_collected_at).where(
                        ObservationSpan.mdm_connection_id == seeded["a"]
                    )
                )
            ).all()
            return sorted((row[0], row[1]) for row in rows)

    before = await spans()
    assert (await client.get("/api/smart-groups/cost")).status_code == 200
    assert await spans() == before
