"""Every route the app serves, asked the tenancy contract's questions against a real Postgres.

The routes are `app.routes`, walked at collection with FastAPI's own walk of included routers, so a route
added tomorrow is swept the day it lands and nothing here names a count. tests/test_tenancy_sweep.py pins
the boundary by hand for the routes it names; its two tenants and their rows are reused here.

- Signed out: 401 or 404, never a success and never a 5xx, unless app.core.auth's own allowlist
  (`is_public_path`, read here rather than copied) makes the path public.
- As one tenant against the other's ids: 404, byte for byte the answer an id nobody holds gets, and the
  other tenant's row, with every row that points at it, unchanged; and no read carries a string only the
  other tenant holds. Both directions: the operational tenant is where an unbound request lands, so a
  second tenant asking for its ids is the sharper probe.
- As a tenant against its own ids: never a 5xx, and the request reaches its handler — neither the gate's
  refusal nor FastAPI's own 422, whose list of fields means this file's body or value is wrong.

Sessions are minted in their tenant, as tests/test_identity_resolution_db.py mints them, and nothing a
route sends leaves the process. The own lane acts as the second tenant, which only the tenancy sweep
shares, and a DELETE of a row there acts on one made for it. SKIP holds what a lane cannot drive, with the
reason; KNOWN holds failures that are not tenancy ones as strict xfails, so a fix turns this red.
"""

from __future__ import annotations

import os
import re
import uuid as uuidlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
from fastapi.routing import APIRoute, iter_route_contexts
from sqlalchemy import delete, select

from app.core.auth import MFA_ENROLMENT_REQUIRED, is_public_path
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.main import app
from tests.test_tenancy_sweep import ADMIN1, ADMIN2, two_tenant_rows

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# The model of the tenant's row a path or query parameter names, by parameter name.
OWNED = {
    "account_id": "Account",
    "case_id": "SubmissionCase",
    "collection_id": "Collection",
    "connection_id": "MdmConnection",
    "destination_id": "Destination",
    "device_id": "Device",
    "job_id": "Run",
    "token_id": "ApiToken",
}
# Parameters that name no tenant's row: one value any tenant may send. A route with a parameter in
# neither table fails `test_every_parameter_has_a_value` until it is added to one.
SHARED = {
    "full_path": "devices",
    "key": "jamf_patch",
    "point": "s:0",
    "provider": "openai_compatible",
    "title_id": "route-sweep",
    "vuln_id": "CVE-2024-3094",
}
PASSWORD = "route-sweep-password"
JAMF = {"provider": "jamf", "baseUrl": "https://192.0.2.10"}
MODEL = {"provider": "openai_compatible", "baseUrl": "https://192.0.2.10/v1"}
HOURLY = {"frequency": "hourly", "atMinute": 5, "timezone": "UTC"}
SUBMISSION = {"kind": "coverage", "appName": "Route Sweep", "platform": "macos", "versions": ["1.0"]}
# A body each route accepts, by "METHOD path"; a route with a required body and no entry sends `{}`.
# Harmless to the own lane's tenant: renames none of its rows, and sets nothing the other lanes rely on.
BODIES: dict[str, dict] = {
    "POST /api/auth/setup": {"claimToken": "x", "email": "setup@sweep.example.com", "displayName": "s", "password": PASSWORD},
    "POST /api/auth/login": {"email": ADMIN2[0], "password": ADMIN2[1]},
    "POST /api/auth/login/mfa": {"challenge": "route-sweep", "code": "000000"},
    "POST /api/auth/change-password": {"currentPassword": "not-the-password", "newPassword": PASSWORD},
    "POST /api/auth/switch-tenant": {"tenantId": str(OPERATIONAL_TENANT_ID)},
    "POST /api/auth/mfa/confirm": {"code": "000000"},
    "POST /api/auth/mfa/recovery-codes": {"code": "000000"},
    "POST /api/accounts": {"email": "route-sweep@sweep.example.com", "displayName": "route sweep", "password": PASSWORD},
    "POST /api/accounts/{account_id}/reset-password": {"newPassword": ADMIN2[1]},
    "POST /api/auth/tokens": {"name": "route sweep"},
    "POST /api/mdm/connections": {"name": "route sweep", **JAMF, "credentials": {"clientId": "c", "clientSecret": "s"}},
    "POST /api/mdm/connections/test": {**JAMF, "clientId": "c"},
    "POST /api/mdm/connections/{connection_id}/collections": {"name": "route sweep", "kind": "catalog", **HOURLY},
    "POST /api/changes/prompt": {"question": "What changed?"},
    "POST /api/destinations": {"name": "route sweep", "url": "https://siem.sweep.example/hook"},
    "PUT /api/settings/patching-policy": {"statement": "Patch within thirty days."},
    "PUT /api/settings/mfa-policy": {"mfaRequired": "off"},
    "POST /api/system/ai/models": MODEL,
    "POST /api/system/ai/test": {**MODEL, "model": "m", "prompt": "hi"},
    "PUT /api/system/ai/configs/{provider}": {"baseUrl": MODEL["baseUrl"], "model": "m"},
    "PUT /api/settings/patching-policy/overrides/{title_id}": {"exempt": True},
    "PUT /api/devices/{device_id}/history/preferences": {"slots": []},
    "PATCH /api/feature-flags/{key}": {"enabled": False},
    "POST /api/vulnerabilities/prompt": {"question": "What is exposed?"},
    "POST /api/system/data-sharing/exclusion-ranking": {"provider": "openai_compatible"},
    "POST /api/system/intelligence/activate": {"secret": "route-sweep"},
    "POST /api/submissions/preview": SUBMISSION,
    "POST /api/submissions": SUBMISSION,
}
# What app.core.auth's gate answers before any handler runs; the own lane's admin must never hear it.
GATE = {"Not authenticated", "Insufficient permissions", "Invalid CSRF token", MFA_ENROLMENT_REQUIRED}
# A lane a route is not driven in, with the reason; keyed (lane, "METHOD path").
SKIP: dict[tuple[str, str], str] = {}
# A lane a route fails for a reason that is not tenancy: a strict xfail, so the fix turns this file red
# until its entry goes. Keyed (lane, "METHOD path").
KNOWN: dict[tuple[str, str], str] = {
    ("own", "POST /api/jamf-patch/sync"): "an unreachable patch catalog is a 500, not a sentence naming what failed",
}


def _walk() -> list[tuple[str, str, APIRoute]]:
    """(method, path, route) for every route `app.routes` serves, included routers walked."""
    return [
        (method, context.path, context.original_route)
        for context in iter_route_contexts(app.routes)
        if isinstance(context.original_route, APIRoute)
        for method in sorted(context.methods)
    ]


ROUTES = _walk()


def _query(route: APIRoute) -> list:
    return [p for p in route.dependant.query_params if p.field_info.is_required()]


def _parameters(path: str, route: APIRoute) -> set[str]:
    """What a request has to name: the path's parameters and the required query ones."""
    return set(re.findall(r"{(\w+)", path)) | {p.name for p in _query(route)}


def _public(path: str) -> bool:
    return is_public_path(re.sub(r"{\w+(?::\w+)?}", "1", path))


def _cases(lane: str, routes: list[tuple[str, str, APIRoute]]) -> list:
    cases = []
    for method, path, route in routes:
        key = (lane, f"{method} {path}")
        marks = [pytest.mark.skip(reason=SKIP[key])] if key in SKIP else []
        marks += [pytest.mark.xfail(strict=True, reason=KNOWN[key])] if key in KNOWN else []
        cases.append(pytest.param(method, path, route, id=f"{method} {path}", marks=marks))
    return cases


# --- the walk, checked ---------------------------------------------------------------


async def test_the_walk_reaches_every_route_the_api_documents() -> None:
    """A vacuity guard: a walk that missed the included routers would pass every lane below."""
    documented = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}
    assert documented <= {(method, re.sub(r":\w+}", "}", path)) for method, path, _ in ROUTES}
    kinds = {type(c.original_route).__name__ for c in iter_route_contexts(app.routes)}
    assert kinds == {"APIRoute"}, f"_walk sweeps APIRoutes only; teach it {kinds - {'APIRoute'}}"


async def test_every_parameter_has_a_value() -> None:
    missing = {f"{m} {p}": sorted(_parameters(p, r) - OWNED.keys() - SHARED.keys()) for m, p, r in ROUTES}
    assert not {route: names for route, names in missing.items() if names}, "add each to OWNED or SHARED"


# --- the plumbing ----------------------------------------------------------------------


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every real connection refused, as an unreachable host refuses it: a route that calls out meets that."""

    async def refused(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("the route sweep opens no connections", request=request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", refused)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenants() -> dict[str, dict]:
    return await two_tenant_rows(outbox_events=False)


@pytest_asyncio.fixture(scope="module", loop_scope="session", autouse=True)
async def tidy(tenants):
    """The sessions, tokens and destinations the sweep made, gone afterwards, and the second tenant's change
    policy with them: tests/test_tenancy_sweep.py asserts that tenant holds none."""
    from app.core.database import session_for_tenant
    from app.models.schema import ApiToken, ChangePolicy, Destination, OutboxDelivery, UserSession

    started = datetime.now(UTC)
    yield
    for label, tenant in tenants.items():
        async with session_for_tenant(tenant["tenant_id"]) as db:
            mine = UserSession.account_id == tenant["account_id"], UserSession.created_at >= started
            await db.execute(delete(UserSession).where(*mine))
            await db.execute(delete(ApiToken).where(ApiToken.name.like("route sweep%")))
            made = select(Destination.id).where(Destination.name.like("route sweep%"))
            await db.execute(delete(OutboxDelivery).where(OutboxDelivery.destination_id.in_(made)))
            await db.execute(delete(Destination).where(Destination.name.like("route sweep%")))
            if label == "t2":
                await db.execute(delete(ChangePolicy))
            await db.commit()


@asynccontextmanager
async def _client(tenant: dict | None):
    """Signed in as `tenant`'s admin with a session minted in its tenant, or signed out for None."""
    from app.core.auth import create_session
    from app.core.database import session_for_tenant
    from app.models.schema import Account

    cookies, headers = {}, {}
    if tenant is not None:
        async with session_for_tenant(tenant["tenant_id"]) as db:
            session, raw = await create_session(db, await db.get(Account, tenant["account_id"]), identity_id=None)
            cookies, headers = {"loon_session": raw}, {"X-CSRF-Token": session.csrf_token}
            await db.commit()
    # The status a client sees, a crash included: the app's own "request failed" log line carries the traceback.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="https://sweep.example", cookies=cookies, headers=headers) as c:
        yield c


def _values(tenant: dict) -> dict[str, object]:
    return {**SHARED, **{name: tenant[name] for name in OWNED}}


async def _send(client: httpx.AsyncClient, method: str, path: str, route: APIRoute, values: dict) -> httpx.Response:
    url = re.sub(r"{(\w+)(?::\w+)?}", lambda m: str(values[m[1]]), path)
    query = {p.alias: values[p.name] for p in _query(route)}
    needs_body = route.body_field is not None and route.body_field.field_info.is_required()
    body = BODIES.get(f"{method} {path}", {} if needs_body else None)
    return await client.request(method, url, params=query, json=body)


def _said(method: str, path: str, response: httpx.Response) -> str:
    return f"{method} {path} answered {response.status_code}: {response.text[:400]}"


# --- 1. Signed out: 401 or 404 -----------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "route"), _cases("signed-out", [r for r in ROUTES if not _public(r[1])]))
async def test_a_signed_out_caller_gets_401_or_404(tenants, method, path, route) -> None:
    async with _client(None) as client:
        response = await _send(client, method, path, route, _values(tenants["t1"]))
    assert response.status_code in (401, 404), _said(method, path, response)


# --- 2. The other tenant: its ids 404 as an id nobody holds, nothing of it moves, no read carries it --


def _absent(value: object) -> object:
    if isinstance(value, uuidlib.UUID):
        return uuidlib.UUID(int=0xDEAD)
    return 2_147_483_647 if isinstance(value, int) else "route-sweep-absent"


async def _held(tenant: dict, names: set[str]) -> dict[str, list[str]]:
    """The rows `names` point at in `tenant`, and every row pointing at one, read in that tenant's session."""
    from app.core.database import Base, session_for_tenant
    from app.models import schema

    held: dict[str, list[str]] = {}
    async with session_for_tenant(tenant["tenant_id"]) as db:
        for name in sorted(names):
            table = getattr(schema, OWNED[name]).__table__
            columns = [table.c.id] + [
                fk.parent for t in Base.metadata.sorted_tables for fk in t.foreign_keys if fk.column is table.c.id
            ]
            for column in columns:
                rows = (await db.execute(select(column.table).where(column == tenant[name]))).all()
                assert rows or column is not table.c.id, f"the fixture holds no {table.name} row {tenant[name]}"
                held[f"{column.table.name}.{column.name}"] = sorted(map(repr, rows))
    return held


CROSS = [r for r in ROUTES if not _public(r[1]) and _parameters(r[1], r[2]) & OWNED.keys()]
DIRECTIONS = pytest.mark.parametrize(("actor", "owner"), [("t1", "t2"), ("t2", "t1")], ids=["t1-asks-t2", "t2-asks-t1"])


@DIRECTIONS
@pytest.mark.parametrize(("method", "path", "route"), _cases("cross-tenant", CROSS))
async def test_another_tenants_ids_are_404_and_left_alone(tenants, method, path, route, actor, owner) -> None:
    theirs = _values(tenants[owner])
    nobody = {name: _absent(value) if name in OWNED else value for name, value in theirs.items()}
    named = _parameters(path, route) & OWNED.keys()
    before = await _held(tenants[owner], named)
    async with _client(tenants[actor]) as client:
        foreign = await _send(client, method, path, route, theirs)
        absent = await _send(client, method, path, route, nobody)
    assert foreign.status_code == 404, _said(method, path, foreign)
    assert foreign.content == absent.content, f"{method} {path}: a foreign id must read as one nobody holds"
    assert await _held(tenants[owner], named) == before, f"{method} {path} changed the other tenant's rows"


def _marks(tenants: dict, label: str) -> list[str]:
    """Strings only `label`'s tenant holds, named as tests/test_tenancy_sweep.py names its rows."""
    tenant = tenants[label]
    email = {"t1": ADMIN1, "t2": ADMIN2}[label][0]
    ids = (tenant[name] for name in ("account_id", "job_id", "case_id"))
    return [email, f"com.{label}.app", f"{label}SERIAL", tenant["destination_name"], *map(str, ids)]


@DIRECTIONS
@pytest.mark.parametrize(("method", "path", "route"), _cases("reads", [r for r in ROUTES if r[0] == "GET" and not _public(r[1])]))
async def test_no_read_carries_the_other_tenants_rows(tenants, method, path, route, actor, owner) -> None:
    async with _client(tenants[actor]) as client:
        response = await _send(client, method, path, route, _values(tenants[actor]))
    assert response.status_code < 500, _said(method, path, response)
    seen = [mark for mark in _marks(tenants, owner) if mark in response.text]
    assert not seen, f"{method} {path} answered {actor} with {owner}'s {seen}"


# --- 3. A tenant's own ids: never a 5xx -----------------------------------------------------


async def _doomed(tenant: dict, name: str) -> object:
    """A row of `name`'s kind made for one DELETE, so the rows the other lanes read survive the sweep."""
    from app.core.database import session_for_tenant
    from app.models.schema import ApiToken, Collection, Destination, MdmConnection

    tag = uuidlib.uuid4().hex[:8]
    label = f"route sweep {tag}"
    made = {
        "collection_id": lambda: Collection(mdm_connection_id=tenant["connection_id"], name=label, kind="catalog"),
        "connection_id": lambda: MdmConnection(name=label, provider="jamf", base_url="https://doomed.jamfcloud.com"),
        "destination_id": lambda: Destination(name=label, type="generic_webhook", url="https://doomed.example", auth_type="none"),
        "token_id": lambda: ApiToken(id=f"sweep{tag}", account_id=tenant["account_id"], name=label, token_hash=tag * 8),
    }
    if name not in made:
        return tenant[name]
    async with session_for_tenant(tenant["tenant_id"]) as db:
        row = made[name]()
        db.add(row)
        await db.commit()
        return row.id


@pytest.mark.parametrize(("method", "path", "route"), _cases("own", ROUTES))
async def test_a_tenant_never_gets_a_5xx_for_its_own_ids(tenants, method, path, route) -> None:
    mine = tenants["t2"]
    values = _values(mine)
    if method == "DELETE":
        values |= {name: await _doomed(mine, name) for name in _parameters(path, route) & OWNED.keys()}
    async with _client(mine) as client:
        response = await _send(client, method, path, route, values)
    assert response.status_code < 500, _said(method, path, response)
    answer = response.json() if response.content and response.headers.get("content-type") == "application/json" else None
    detail = answer.get("detail") if isinstance(answer, dict) else None
    unreached = detail in GATE if isinstance(detail, str) else response.status_code == 422
    assert not unreached, f"the request never reached its handler; fix this file's body or value: {_said(method, path, response)}"
