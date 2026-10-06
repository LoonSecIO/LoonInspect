"""Every route the app serves, asked the tenancy contract's questions against a real Postgres.

The routes are `app.routes`, walked at collection with FastAPI's own walk of included routers, so a route
added tomorrow is swept the day it lands and nothing here names a count. tests/test_tenancy_sweep.py pins
the boundary by hand for the routes it names; its two tenants and their rows are reused here, and `_seed`
adds, for this module's run, the rows a parameter names that the seed lacks.

- Signed out: 401 or 404, never a success and never a 5xx, unless app.core.auth's own allowlist
  (`is_public_path`, read here rather than copied) makes the path public.
- As one tenant, naming one of the other's rows wherever a request carries its id (path, query or body,
  one id at a time, everything else the asker's own): byte for byte the answer an id nobody holds gets,
  and 404 when the id is in the path or a required query parameter; the other tenant's row, with every
  row that points at it, unchanged; and no read carries a string only the other tenant holds. Both
  directions: the operational tenant is where an unbound request lands, so a second tenant asking for
  its ids is the sharper probe.
- As a tenant against its own ids: never a 5xx, and the request reaches its handler — neither the gate's
  refusal nor FastAPI's own 422, whose list of fields means this file's body or value is wrong.

Sessions are minted in their tenant, as tests/test_identity_resolution_db.py mints them, and nothing a
route sends leaves the process. The own lane acts as the second tenant, which only the tenancy sweep
shares; a write there acts on a row made for it, and what the sweep makes is tidied away either side of
the module. SKIP holds what a lane cannot drive, with the reason; STOPS, the own lane's routes that end at
a designed refusal; KNOWN, crashes that are not tenancy ones, as strict xfails, so any other answer turns
this file red.
"""

from __future__ import annotations

import os
import re
import typing
import uuid as uuidlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
from fastapi.encoders import jsonable_encoder
from fastapi.routing import APIRoute, iter_route_contexts
from pydantic import BaseModel
from sqlalchemy import delete, select

from app.core.auth import MFA_ENROLMENT_REQUIRED, is_public_path
from app.main import app
from tests.test_tenancy_sweep import ADMIN1, ADMIN2, two_tenant_rows

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# The model of the tenant's row each id names, by the key the `tenants` fixture holds it under.
OWNED = {
    "account_id": "Account",
    "case_id": "SubmissionCase",
    "collection_id": "Collection",
    "connection_id": "MdmConnection",
    "destination_id": "Destination",
    "device_id": "Device",
    "job_id": "Run",
    "span_id": "ObservationSpan",
    "tenant_id": "Tenant",
    "token_id": "ApiToken",
}
# A parameter naming one of those rows by another name or spelling: (its OWNED key, its value as a template
# over the `tenants` fixture's keys).
ALIASES = {
    "mdm_connection_id": ("connection_id", "{connection_id}"),
    "point": ("span_id", "s:{span_id}"),  # an observation, as /history spells one
    "subject_id": ("device_id", "{subject}"),  # the device, by the Jamf id the change feed names it by
}
# Parameters that name no tenant's row: one value any tenant may send.
SHARED = {
    "bundle_id": "com.example.sweep",
    "client_id": "c",
    "full_path": "devices",
    "key": "jamf_patch",
    "provider": "openai_compatible",
    "title_id": "route-sweep",
    "vuln_id": "CVE-2024-3094",
}
# An id's name. A parameter carrying one, in the path, the query or the body, and every path or required
# query parameter, is in one of the three tables above, or `test_every_parameter_has_a_value` fails.
ID = re.compile(r"(?:^|_)ids?$")
PASSWORD = "route-sweep-password"
JAMF = {"provider": "jamf", "baseUrl": "https://192.0.2.10"}
MODEL = {"provider": "openai_compatible", "baseUrl": "https://192.0.2.10/v1"}
HOURLY = {"frequency": "hourly", "atMinute": 5, "timezone": "UTC"}
SUBMISSION = {"kind": "coverage", "appName": "Route Sweep", "platform": "macos", "versions": ["1.0"]}
# A body each route accepts, by "METHOD path", ids aside: those come from the tables above. A route with a
# required body and no entry sends `{}`. Harmless to the own lane's tenant: renames none of its rows, and
# sets nothing the other lanes rely on.
BODIES: dict[str, dict] = {
    "POST /api/auth/setup": {"claimToken": "x", "email": "setup@sweep.example.com", "displayName": "s", "password": PASSWORD},
    "POST /api/auth/login": {"email": ADMIN2[0], "password": ADMIN2[1]},
    "POST /api/auth/login/mfa": {"challenge": "route-sweep", "code": "000000"},
    "POST /api/auth/change-password": {"currentPassword": "not-the-password", "newPassword": PASSWORD},
    "POST /api/auth/mfa/confirm": {"code": "000000"},
    "POST /api/auth/mfa/recovery-codes": {"code": "000000"},
    "POST /api/accounts": {"email": "route-sweep@sweep.example.com", "displayName": "route sweep", "password": PASSWORD},
    "POST /api/accounts/{account_id}/reset-password": {"newPassword": PASSWORD},
    "POST /api/auth/tokens": {"name": "route sweep"},
    "POST /api/mdm/connections": {"name": "route sweep", **JAMF, "credentials": {"clientId": "c", "clientSecret": "s"}},
    "POST /api/mdm/connections/test": JAMF,
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
# A lane a route is not driven in, with the reason; keyed (lane, test id).
SKIP: dict[tuple[str, str], str] = {}
# A lane a route crashes in for a reason that is not tenancy: a strict xfail on exactly that crash, so a fix
# that answers anything else, another 5xx included, turns this file red until its entry goes. Keyed
# (lane, test id).
KNOWN: dict[tuple[str, str], str] = {
    ("own", "POST /api/jamf-patch/sync"): "an unreachable patch catalog is a 500, not a sentence naming what failed",
}
# The own lane's routes that end at a designed refusal, by what the second tenant lacks for their main path.
# Asserted both ways: a route that starts refusing, or stops, moves in or out of this table.
STOPS = {
    "a credential the sweep does not hold: a password, code, sign-in challenge or webhook secret": [
        "POST /api/auth/login",  # the second tenant signs in by a minted session only (tests/test_tenancy_sweep.py)
        *("POST /api/auth/login/mfa", "POST /api/auth/change-password", "POST /api/auth/mfa/confirm"),
        "POST /webhooks/jamf/{connection_id}",
    ],
    "setup is done, and the account holds no second factor": [
        *("POST /api/auth/setup", "POST /api/auth/mfa/recovery-codes", "DELETE /api/accounts/{account_id}/mfa"),
    ],
    "AI features are off and no provider is saved": [
        *("GET /api/system/ai/providers", "GET /api/system/ai/host", "POST /api/system/ai/models", "POST /api/system/ai/test"),
        *("PUT /api/system/ai/configs/{provider}", "DELETE /api/system/ai/configs/{provider}"),
        *("POST /api/system/data-sharing/exclusion-ranking", "POST /api/changes/prompt"),
        "POST /api/settings/patching-policy/rule/draft",
    ],
    "no vulnerability corpus is loaded": ["POST /api/vulnerabilities/prompt", "GET /api/vulnerabilities/{vuln_id}"],
    "the paid preview is off": [
        *("POST /api/system/intelligence/activate", "POST /api/system/intelligence/rotate"),
        *("POST /api/system/intelligence/refresh", "POST /api/submissions/preview", "POST /api/submissions"),
    ],
    "sharing is off": ["POST /api/system/data-sharing/send"],
    "no Jamf patch title: titles are global, and the sweep loads none": [
        *("GET /api/jamf-patch/titles/{title_id}", "PUT /api/settings/patching-policy/overrides/{title_id}"),
    ],
    "the connection holds no Jamf credential": ["POST /api/devices/{device_id}/refresh"],
}
STOPPED = {route: why for why, routes in STOPS.items() for route in routes}


class Crash(AssertionError):
    """A 500 with Starlette's own body: an exception no handler caught."""


def _walk() -> list[tuple[str, str, APIRoute]]:
    """(method, path, route) for every route `app.routes` serves, included routers walked."""
    return [
        (method, context.path, context.original_route)
        for context in iter_route_contexts(app.routes)
        if isinstance(context.original_route, APIRoute)
        for method in sorted(context.methods)
    ]


ROUTES = _walk()


def _params(path: str, route: APIRoute) -> list[tuple[str, str, str, bool]]:
    """(where, name, its name on the wire, required) for each parameter this file gives a value: every path
    and required query one, and, query or body, every one with an id's name or naming a tenant's row."""
    body = route.body_field.field_info.annotation if route.body_field else None
    model = next((t for t in (body, *typing.get_args(body)) if isinstance(t, type) and issubclass(t, BaseModel)), None)
    every = [
        *(("path", name, name, True) for name in re.findall(r"{(\w+)", path)),
        *(("query", p.name, p.alias, p.field_info.is_required()) for p in route.dependant.query_params),
        *(("body", name, f.alias or name, f.is_required()) for name, f in (model.model_fields if model else {}).items()),
    ]
    return [p for p in every if (p[0] != "body" and p[3]) or ID.search(p[1]) or p[1] in OWNED.keys() | ALIASES.keys()]


def _probes(path: str, route: APIRoute) -> list[tuple[str, str, str, bool]]:
    """The parameters naming a tenant's row: each is asked across tenants on its own."""
    return [p for p in _params(path, route) if p[1] in OWNED.keys() | ALIASES.keys()]


def _public(path: str) -> bool:
    return is_public_path(re.sub(r"{\w+(?::\w+)?}", "1", path))


def _cases(lane: str, items: list[tuple]) -> list:
    cases = []
    for method, path, route, *probe in items:
        case = f"{method} {path}" + "".join(f" {where}:{wire}" for where, _, wire, _ in probe if where != "path")
        marks = [pytest.mark.skip(reason=SKIP[lane, case])] if (lane, case) in SKIP else []
        marks += [pytest.mark.xfail(strict=True, raises=Crash, reason=KNOWN[lane, case])] if (lane, case) in KNOWN else []
        cases.append(pytest.param(method, path, route, *probe, id=case, marks=marks))
    return cases


# --- the walk, checked ---------------------------------------------------------------


async def test_the_walk_reaches_every_route_the_api_documents() -> None:
    """A vacuity guard: a walk that missed the included routers would pass every lane below."""
    documented = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}
    assert documented <= {(method, re.sub(r":\w+}", "}", path)) for method, path, _ in ROUTES}
    kinds = {type(c.original_route).__name__ for c in iter_route_contexts(app.routes)}
    assert kinds == {"APIRoute"}, f"_walk sweeps APIRoutes only; teach it {kinds - {'APIRoute'}}"


async def test_every_entry_names_a_route() -> None:
    """An entry for a route that is gone, or misspelt, would be asked nothing."""
    served = {f"{m} {p}" for m, p, _ in ROUTES}
    named = {" ".join(case.split(" ")[:2]) for _, case in (*SKIP, *KNOWN)} | STOPPED.keys() | BODIES.keys()
    assert named <= served, sorted(named - served)


async def test_every_parameter_has_a_value() -> None:
    """Every path and required query parameter, and every one with an id's name, names a tenant's row or
    none: a route that brings a new one fails here until someone decides which."""
    known = OWNED.keys() | ALIASES.keys() | SHARED.keys()
    missing = {f"{m} {p}": sorted({name for _, name, _, _ in _params(p, r)} - known) for m, p, r in ROUTES}
    assert not {route: names for route, names in missing.items() if names}, "add each to OWNED, ALIASES or SHARED"


# --- the plumbing ----------------------------------------------------------------------


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every real connection refused, as an unreachable host refuses it: a route that calls out meets that."""

    async def refused(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("the route sweep opens no connections", request=request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", refused)


async def _seed(tenant: dict) -> dict:
    """What this module adds to a tenant while it runs: an observation of the device and a change found in
    it, the rows /history's `point` and the change feed's subjectId and spanId name; and a stored client
    secret on the connection, which is what POST /api/mdm/connections/test reads of a connection it names
    (with no client id beside it, nothing can call out with it)."""
    from app.core.database import session_for_tenant
    from app.mdm.jamf.contract import digest
    from app.models.schema import Device, DeviceChange, MdmConnection, ObservationSpan

    now, secret = datetime.now(UTC), '{"client_secret": "route-sweep"}'
    async with session_for_tenant(tenant["tenant_id"]) as db:
        connection = await db.get(MdmConnection, tenant["connection_id"])
        stored = None if connection.credentials_encrypted == secret else connection.credentials_encrypted
        stored, connection.credentials_encrypted = (stored, connection.updated_at), secret
        device = await db.get(Device, tenant["device_id"])
        subject = {"mdm_connection_id": device.mdm_connection_id, "subject_kind": "computer", "subject_id": device.external_id}
        span = (await db.execute(select(ObservationSpan).filter_by(**subject, is_current=True))).scalars().first()
        if span is None:
            times = dict.fromkeys(("first_observed_at", "last_observed_at", "first_collected_at", "last_collected_at"), now)
            empty = digest("route-sweep", "{}")
            span = ObservationSpan(**subject, **times, contract_version="v0", aperture_digest=empty, head_digest=empty)
            span.section_digests, span.last_trigger, span.serial_number = {}, "sweep", device.serial_number
            db.add(span)
            await db.flush()
        change = (await db.execute(select(DeviceChange).filter_by(span_id=span.id))).scalars().first()
        if change is None:
            at = {"observed_at": now, "collected_at": now, "trigger": "sweep", "policy_version": "v0"}
            change = DeviceChange(**subject, **at, span_id=span.id, section="applications", change="added", level="normal")
            change.serial_number = device.serial_number
            db.add(change)
            await db.flush()
        await db.commit()
        return {"span_id": span.id, "subject": device.external_id, "change_id": change.id, "stored": stored}


async def _tidy(rows: dict[str, dict], since: datetime) -> None:
    """What the sweep and `_seed` made, gone, and the connections' stored credential put back; the second
    tenant's change policy and history slots go too (tests/test_tenancy_sweep.py asserts that tenant holds no
    change policy). Run before the sweep as well, so a run cut short leaves nothing the next one meets."""
    from app.core.database import session_for_tenant
    from app.models import schema as s

    for tenant in rows.values():
        async with session_for_tenant(tenant["tenant_id"]) as db:
            mine = s.UserSession.account_id == tenant["account_id"], s.UserSession.created_at >= since
            await db.execute(delete(s.UserSession).where(*mine))
            # The own lane's sign-in counts against the operational tenant, as a failed one.
            await db.execute(delete(s.LoginAttempt).where(s.LoginAttempt.identifier == ADMIN2[0]))
            await db.execute(delete(s.DeviceChange).where(s.DeviceChange.id == tenant.get("change_id")))
            await db.execute(delete(s.ObservationSpan).where(s.ObservationSpan.id == tenant.get("span_id")))
            if "stored" in tenant:
                connection = await db.get(s.MdmConnection, tenant["connection_id"])
                connection.credentials_encrypted, connection.updated_at = tenant["stored"]
            await db.commit()
    async with session_for_tenant(rows["t2"]["tenant_id"]) as db:
        accounts = select(s.Account.id).where(s.Account.email.like("route-sweep%@sweep.example.com"))
        for model in (s.UserSession, s.ApiToken, s.AuthIdentity, s.AccountRole):
            await db.execute(delete(model).where(model.account_id.in_(accounts)))
        await db.execute(delete(s.Account).where(s.Account.id.in_(accounts)))
        totp = s.AuthIdentity.account_id == rows["t2"]["account_id"], s.AuthIdentity.provider == "totp"
        await db.execute(delete(s.AuthIdentity).where(*totp))
        destinations = select(s.Destination.id).where(s.Destination.name.like("route sweep%"))
        await db.execute(delete(s.OutboxDelivery).where(s.OutboxDelivery.destination_id.in_(destinations)))
        for model, column in ((s.Destination, "name"), (s.ApiToken, "name"), (s.SubmissionCase, "app_name")):
            await db.execute(delete(model).where(getattr(model, column).like("route sweep%")))
        await db.execute(delete(s.Run).where(s.Run.started_at >= since))
        await db.execute(delete(s.Collection).where(s.Collection.name.like("route sweep%")))
        connections = select(s.MdmConnection.id).where(s.MdmConnection.name.like("route sweep%"))
        await db.execute(delete(s.MdmSyncState).where(s.MdmSyncState.mdm_connection_id.in_(connections)))
        await db.execute(delete(s.MdmConnection).where(s.MdmConnection.id.in_(connections)))
        await db.execute(delete(s.EventOutbox).where(s.EventOutbox.created_at >= since))
        await db.execute(delete(s.PostureSnapshot).where(s.PostureSnapshot.captured_at >= since))
        await db.execute(delete(s.ChangePolicy))
        await db.execute(delete(s.DeviceHistoryPreference))
        await db.commit()


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def tenants():
    """The tenancy sweep's two tenants and rows, with what `_seed` adds, tidied either side."""
    rows = await two_tenant_rows(outbox_events=False)
    await _tidy(rows, datetime.now(UTC))
    started = datetime.now(UTC)
    for tenant in rows.values():
        tenant |= await _seed(tenant)
    yield rows
    await _tidy(rows, started)


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
    """Each parameter's value as `tenant`: its rows' ids, under every name a route gives them."""
    spelt = {name: template.format(**tenant) for name, (_, template) in ALIASES.items()}
    return {**SHARED, **{name: tenant[name] for name in OWNED}, **spelt}


async def _send(client: httpx.AsyncClient, method: str, path: str, route: APIRoute, values: dict, also=()) -> httpx.Response:
    """The request `values` names: every required parameter, and an optional one only when `also` names it."""
    sent = [(where, wire, values[name]) for where, name, wire, required in _params(path, route) if required or name in also]
    url = re.sub(r"{(\w+)(?::\w+)?}", lambda m: str(values[m[1]]), path)
    query = {wire: value for where, wire, value in sent if where == "query"}
    ids = {wire: value for where, wire, value in sent if where == "body"}
    needs_body = route.body_field is not None and route.body_field.field_info.is_required()
    body = BODIES.get(f"{method} {path}", {} if needs_body else None)
    body = jsonable_encoder({**(body or {}), **ids}) if ids else body
    return await client.request(method, url, params=query, json=body)


def _said(method: str, path: str, response: httpx.Response) -> str:
    return f"{method} {path} answered {response.status_code}: {response.text[:400]}"


def _no_5xx(method: str, path: str, response: httpx.Response) -> None:
    if response.status_code == 500 and response.text == "Internal Server Error":
        raise Crash(_said(method, path, response))
    assert response.status_code < 500, _said(method, path, response)


# --- 1. Signed out: 401 or 404 -----------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "route"), _cases("signed-out", [r for r in ROUTES if not _public(r[1])]))
async def test_a_signed_out_caller_gets_401_or_404(tenants, method, path, route) -> None:
    async with _client(None) as client:
        response = await _send(client, method, path, route, _values(tenants["t1"]))
    _no_5xx(method, path, response)
    assert response.status_code in (401, 404), _said(method, path, response)


# --- 2. The other tenant: its ids answer as ids nobody holds, nothing of it moves, no read carries it --


def _absent(value: object) -> object:
    if isinstance(value, uuidlib.UUID):
        return uuidlib.UUID(int=0xDEAD)
    return 2_147_483_647 if isinstance(value, int) else "route-sweep-absent"


async def _held(tenant: dict, key: str) -> dict[str, list[str]]:
    """The row `key` names in `tenant`, and every row pointing at it, read in that tenant's session: not
    through the tenant_id every row carries, which from the tenant's own row would read all of it."""
    from app.core.database import Base, session_for_tenant
    from app.models import schema

    table = getattr(schema, OWNED[key]).__table__
    columns = [table.c.id] + [
        fk.parent
        for t in Base.metadata.sorted_tables
        for fk in t.foreign_keys
        if fk.column is table.c.id and fk.parent.name != "tenant_id"
    ]
    held: dict[str, list[str]] = {}
    async with session_for_tenant(tenant["tenant_id"]) as db:
        for column in columns:
            rows = (await db.execute(select(column.table).where(column == tenant[key]))).all()
            assert rows or column is not table.c.id, f"the fixture holds no {table.name} row {tenant[key]}"
            held[f"{column.table.name}.{column.name}"] = sorted(map(repr, rows))
    return held


CROSS = [(m, p, r, probe) for m, p, r in ROUTES if not _public(p) for probe in _probes(p, r)]
DIRECTIONS = pytest.mark.parametrize(("actor", "owner"), [("t1", "t2"), ("t2", "t1")], ids=["t1-asks-t2", "t2-asks-t1"])


@DIRECTIONS
@pytest.mark.parametrize(("method", "path", "route", "probe"), _cases("cross-tenant", CROSS))
async def test_another_tenants_id_answers_as_an_absent_one(tenants, method, path, route, probe, actor, owner) -> None:
    where, name, _, required = probe
    mine, key = _values(tenants[actor]), ALIASES.get(name, (name,))[0]
    theirs = mine | {name: _values(tenants[owner])[name]}
    nobody = mine | {name: _values({k: _absent(v) for k, v in tenants[owner].items()})[name]}
    before = await _held(tenants[owner], key)
    async with _client(tenants[actor]) as client:
        foreign = await _send(client, method, path, route, theirs, {name})
        absent = await _send(client, method, path, route, nobody, {name})
    if where != "body" and required:
        assert foreign.status_code == 404, _said(method, path, foreign)
    said = f"{_said(method, path, foreign)}; for an id nobody holds, {absent.status_code}: {absent.text[:400]}"
    assert (foreign.status_code, foreign.content) == (absent.status_code, absent.content), said
    assert await _held(tenants[owner], key) == before, f"{method} {path} changed the other tenant's rows"


def _marks(tenants: dict, label: str) -> list[str]:
    """Strings only `label`'s tenant holds: the seed's names for its rows, and its observation's id."""
    tenant = tenants[label]
    email = {"t1": ADMIN1, "t2": ADMIN2}[label][0]
    ids = (tenant[name] for name in ("account_id", "job_id", "case_id", "span_id"))
    return [email, f"com.{label}.app", f"{label}SERIAL", tenant["destination_name"], *map(str, ids)]


@DIRECTIONS
@pytest.mark.parametrize(("method", "path", "route"), _cases("reads", [r for r in ROUTES if r[0] == "GET" and not _public(r[1])]))
async def test_no_read_carries_the_other_tenants_rows(tenants, method, path, route, actor, owner) -> None:
    async with _client(tenants[actor]) as client:
        response = await _send(client, method, path, route, _values(tenants[actor]))
    _no_5xx(method, path, response)
    seen = [mark for mark in _marks(tenants, owner) if mark in response.text]
    assert not seen, f"{method} {path} answered {actor} with {owner}'s {seen}"


# --- 3. A tenant's own ids: never a 5xx -----------------------------------------------------


async def _doomed(tenant: dict, name: str) -> object:
    """A row of `name`'s kind made for the write its path names, so no write changes a row another lane reads."""
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.submissions import mint_case_key
    from app.models.schema import ApiToken, Collection, Destination, MdmConnection, SubmissionCase

    tag = uuidlib.uuid4().hex[:8]
    label = f"route sweep {tag}"
    made = {
        "case_id": lambda: SubmissionCase(
            kind="coverage", app_name=label, platform="macos", versions=["1.0"], case_key=mint_case_key()
        ),
        "collection_id": lambda: Collection(
            mdm_connection_id=tenant["connection_id"], name=label, kind="catalog", frequency="hourly", timezone="UTC"
        ),
        "connection_id": lambda: MdmConnection(name=label, provider="jamf", base_url="https://doomed.jamfcloud.com"),
        "destination_id": lambda: Destination(name=label, type="generic_webhook", url="https://doomed.example", auth_type="none"),
        "token_id": lambda: ApiToken(id=f"sweep{tag}", account_id=tenant["account_id"], name=label, token_hash=tag * 8),
    }
    if name not in made and name != "account_id":
        return tenant[name]
    async with session_for_tenant(tenant["tenant_id"]) as db:
        if name == "account_id":
            row, _ = await create_account(db, email=f"route-sweep-{tag}@sweep.example.com", display_name=label, password=PASSWORD)
        else:
            row = made[name]()
            db.add(row)
        await db.commit()
        return row.id


@pytest.mark.parametrize(("method", "path", "route"), _cases("own", ROUTES))
async def test_a_tenant_never_gets_a_5xx_for_its_own_ids(tenants, method, path, route) -> None:
    mine = tenants["t2"]
    values = _values(mine)
    if method != "GET":
        values |= {name: await _doomed(mine, name) for where, name, _, _ in _probes(path, route) if where == "path"}
    async with _client(mine) as client:
        response = await _send(client, method, path, route, values, {name for _, name, _, _ in _params(path, route)})
    _no_5xx(method, path, response)
    answer = response.json() if response.content and response.headers.get("content-type") == "application/json" else None
    detail = answer.get("detail") if isinstance(answer, dict) else None
    unreached = detail in GATE if isinstance(detail, str) else response.status_code == 422
    assert not unreached, f"the request never reached its handler; fix this file's body or value: {_said(method, path, response)}"
    refused, listed = response.status_code >= 400, f"{method} {path}" in STOPPED
    assert refused == listed, f"{_said(method, path, response)}: {'listed in' if listed else 'not in'} STOPS"
