"""The actual MCP protocol enforces scoped credentials, live revocation, consent, and Postgres tenant isolation."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from mcp.types import LATEST_PROTOCOL_VERSION
from sqlalchemy import delete, select, text, update

from app.core.permissions import Permission
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.mcp.policy import MCP_ACCESS_FLAG

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

READ_SCOPES = [
    Permission.MCP_CONNECT.value,
    Permission.DEVICE_READ.value,
    Permission.APP_READ.value,
    Permission.VULN_READ.value,
    Permission.CONNECTION_READ.value,
    Permission.SYSTEM_READ.value,
    Permission.DESTINATION_READ.value,
    Permission.AUDIT_READ.value,
]
BASE_URL = "https://127.0.0.1:8000"
CLASSIC_PROTOCOL = "2025-11-25"


async def _raw_token(tenant_id, account_id, *, scopes=None, expires=True):
    from app.core.database import session_for_tenant
    from app.core.security import hash_token
    from app.core.tokens import generate_token
    from app.models.schema import ApiToken, ApiTokenTenant

    minted = generate_token()
    async with session_for_tenant(tenant_id) as db:
        db.add(
            ApiToken(
                id=minted.token_id,
                account_id=account_id,
                name="MCP database test",
                token_hash=hash_token(minted.secret),
                scopes=READ_SCOPES if scopes is None else scopes,
                expires_at=datetime.now(UTC) + timedelta(days=1) if expires else None,
            )
        )
        await db.flush()
        db.add(ApiTokenTenant(token_hash=hash_token(minted.secret), tenant_id=tenant_id))
        await db.commit()
    return {"id": minted.token_id, "token": minted.raw}


async def _mint(browser, *, scopes=None, expires=1, tenant_id=OPERATIONAL_TENANT_ID):
    response = await browser.post(
        "/api/auth/tokens",
        json={"name": "MCP database test", "scopes": READ_SCOPES if scopes is None else scopes, "expiresInDays": expires},
        headers={"X-Expected-Tenant-ID": str(tenant_id)},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _rpc(client, token, method, params=None, *, protocol=CLASSIC_PROTOCOL):
    parameters = dict(params or {})
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": protocol,
    }
    if protocol == LATEST_PROTOCOL_VERSION:
        parameters["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": protocol,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        headers["Mcp-Method"] = method
        if method == "tools/call":
            headers["Mcp-Name"] = parameters["name"]
    return await client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": uuid4().hex, "method": method, "params": parameters},
    )


async def _call(client, token, name, arguments=None):
    response = await _rpc(client, token, "tools/call", {"name": name, "arguments": arguments or {}})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "result" in payload, payload
    return payload["result"]


async def _flag(tenant_id, key, enabled):
    from app.core.database import session_for_tenant
    from app.models.schema import FeatureFlag

    async with session_for_tenant(tenant_id) as db:
        row = await db.get(FeatureFlag, (tenant_id, key))
        if row is None:
            db.add(FeatureFlag(key=key, enabled=enabled))
        else:
            row.enabled = enabled
        await db.commit()


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def mcp_env(tenant_ready):
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant, unscoped_session
    from app.main import app
    from app.models.schema import Account, ApiToken, Device, FeatureFlag, LoginAttempt, ShareLog, Tenant, UserSession

    suffix = uuid4().hex[:12]
    other_id = uuid4()
    password = f"mcp-test-password-{suffix}"
    email = f"mcp-test-{suffix}@example.com"
    saved_flags = {}
    account_ids = {}
    device_ids = {}
    async with unscoped_session() as db:
        role = (await db.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).one()
        assert not role.rolsuper and not role.rolbypassrls, "MCP isolation must be tested with RLS enforced."
        db.add(Tenant(id=other_id, slug=f"mcp-test-{suffix}", name="MCP second tenant", kind="operational"))
        await db.commit()
    for tenant_id in (OPERATIONAL_TENANT_ID, other_id):
        async with session_for_tenant(tenant_id) as db:
            account, _ = await create_account(
                db,
                email=email if tenant_id == OPERATIONAL_TENANT_ID else f"mcp-other-{suffix}@example.com",
                display_name="MCP test operator",
                password=password,
                roles=("admin",),
            )
            account_ids[tenant_id] = account.id
            device = Device(
                mdm_provider="jamf",
                external_id=f"mcp-{suffix}",
                serial_number=f"mcp-serial-{tenant_id.hex[:4]}-{suffix}",
                hostname=f"mcp-private-{suffix}-{'home' if tenant_id == OPERATIONAL_TENANT_ID else 'other'}",
                platform="macos",
            )
            db.add(device)
            await db.flush()
            device_ids[tenant_id] = device.id
            for key in ("ai_features", MCP_ACCESS_FLAG):
                flag = await db.get(FeatureFlag, (tenant_id, key))
                saved_flags[(tenant_id, key)] = flag.enabled if flag else None
                if flag is None:
                    db.add(FeatureFlag(key=key, enabled=True))
                else:
                    flag.enabled = True
            await db.commit()

    browser = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
    ready, stopped = asyncio.Event(), asyncio.Event()

    async def serve():
        # AnyIO's task-group cancel scope must enter and leave in one task. Pytest's
        # async-generator fixture setup and teardown run in different tasks.
        async with app.state.mcp.lifespan():
            ready.set()
            await stopped.wait()

    serving = asyncio.create_task(serve())
    try:
        login = await browser.post("/api/auth/login", json={"email": email, "password": password})
        assert login.status_code == 200, login.text
        browser.headers["X-CSRF-Token"] = browser.cookies.get("loon_csrf", "")
        await asyncio.wait_for(ready.wait(), timeout=5)
        yield {
            "app": app,
            "browser": browser,
            "client": client,
            "other": other_id,
            "accounts": account_ids,
            "devices": device_ids,
            "prefix": f"mcp-private-{suffix}",
        }
    finally:
        stopped.set()
        await serving
        await browser.aclose()
        await client.aclose()
        for tenant_id in (OPERATIONAL_TENANT_ID, other_id):
            async with session_for_tenant(tenant_id) as db:
                token_ids = (await db.scalars(select(ApiToken.id).where(ApiToken.account_id == account_ids[tenant_id]))).all()
                await db.execute(delete(ShareLog).where(ShareLog.endpoint.in_([f"mcp-client:{token}" for token in token_ids])))
                await db.execute(delete(ApiToken).where(ApiToken.account_id == account_ids[tenant_id]))
                await db.execute(delete(UserSession).where(UserSession.account_id == account_ids[tenant_id]))
                await db.execute(delete(Device).where(Device.id == device_ids[tenant_id]))
                account = await db.get(Account, account_ids[tenant_id])
                await db.delete(account)
                await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
                for key in ("ai_features", MCP_ACCESS_FLAG):
                    old = saved_flags[(tenant_id, key)]
                    if old is None:
                        await db.execute(delete(FeatureFlag).where(FeatureFlag.key == key))
                    else:
                        await db.execute(update(FeatureFlag).where(FeatureFlag.key == key).values(enabled=old))
                await db.commit()
        async with unscoped_session() as db:
            await db.execute(delete(Tenant).where(Tenant.id == other_id))
            await db.commit()


async def test_protocol_initialize_list_and_fleet_read(mcp_env):
    token = await _mint(mcp_env["browser"])
    initialized = await _rpc(
        mcp_env["client"],
        token["token"],
        "initialize",
        {"protocolVersion": CLASSIC_PROTOCOL, "capabilities": {}, "clientInfo": {"name": "MCP test", "version": "1"}},
    )
    assert initialized.status_code == 200, initialized.text
    assert initialized.json()["result"]["serverInfo"]["name"] == "LoonInspect"
    listed = await _rpc(mcp_env["client"], token["token"], "tools/list")
    assert listed.status_code == 200, listed.text
    tools = {tool["name"]: tool for tool in listed.json()["result"]["tools"]}
    assert {"list_devices", "get_vulnerability", "get_evidence_report", "get_run"} <= set(tools)
    assert "start_inventory_sync" not in tools
    assert tools["list_devices"]["annotations"]["readOnlyHint"] is True
    result = await _call(mcp_env["client"], token["token"], "list_devices", {"q": mcp_env["prefix"]})
    assert result.get("isError") is not True, result
    structured = result["structuredContent"]
    assert structured["organizationId"] == str(OPERATIONAL_TENANT_ID)
    assert [row["id"] for row in structured["data"]["items"]] == [mcp_env["devices"][OPERATIONAL_TENANT_ID]]
    assert structured["data"]["corpusAsOf"] is None


async def test_current_stateless_protocol_uses_the_same_authenticated_fleet_path(mcp_env):
    token = await _mint(mcp_env["browser"])
    response = await _rpc(
        mcp_env["client"],
        token["token"],
        "tools/call",
        {"name": "list_devices", "arguments": {"q": mcp_env["prefix"]}},
        protocol=LATEST_PROTOCOL_VERSION,
    )
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert result.get("isError") is not True, result
    assert result["structuredContent"]["organizationId"] == str(OPERATIONAL_TENANT_ID)


async def test_read_grant_cannot_execute_writes_or_create_credentials(mcp_env):
    token = await _mint(mcp_env["browser"])
    for name, arguments in (
        ("start_inventory_sync", {"connection_id": 1}),
        ("refresh_patch_catalog", {}),
        ("create_api_token", {"name": "replacement"}),
    ):
        result = await _call(mcp_env["client"], token["token"], name, arguments)
        assert result["isError"] is True
        assert "unavailable" in result["structuredContent"]["error"]
    response = await mcp_env["client"].post(
        "/api/auth/tokens",
        headers={"Authorization": f"Bearer {token['token']}"},
        json={"name": "replacement"},
    )
    assert response.status_code == 403


async def test_authorized_sync_returns_before_worker_and_duplicate_request_joins_run(mcp_env, monkeypatch):
    from app.api import connections
    from app.core.database import session_for_tenant
    from app.core.runs import finish
    from app.models.schema import MdmConnection, MdmSyncState, Run, RunLogLine

    release, worker_done = asyncio.Event(), asyncio.Event()

    async def held_worker(connection_id, actor, tenant_id, job_id):
        try:
            await release.wait()
            async with session_for_tenant(tenant_id) as db:
                run = await db.get(Run, job_id)
                await finish(db, run, ok=True)
        finally:
            worker_done.set()

    monkeypatch.setattr(connections, "_run_connection_sync", held_worker)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        connection = MdmConnection(name="MCP synthetic sync", provider="jamf", base_url="https://example.invalid", is_active=True)
        db.add(connection)
        await db.commit()
        connection_id = connection.id
    try:
        token = await _mint(mcp_env["browser"], scopes=[*READ_SCOPES, Permission.DEVICE_SYNC.value])
        first = await asyncio.wait_for(
            _call(mcp_env["client"], token["token"], "start_inventory_sync", {"connection_id": connection_id}), timeout=3
        )
        assert first.get("isError") is not True, first
        assert first["structuredContent"]["data"]["started"] is True
        assert not worker_done.is_set(), "The MCP response must not wait for Starlette's background worker."
        second = await _call(mcp_env["client"], token["token"], "start_inventory_sync", {"connection_id": connection_id})
        assert second.get("isError") is not True, second
        assert second["structuredContent"]["data"]["started"] is False
        job_id = first["structuredContent"]["data"]["jobId"]
        assert second["structuredContent"]["data"]["jobId"] == job_id
        release.set()
        await asyncio.wait_for(worker_done.wait(), timeout=3)
        result = await _call(mcp_env["client"], token["token"], "get_run", {"job_id": job_id})
        assert result["structuredContent"]["data"]["status"] == "succeeded"
    finally:
        release.set()
        # If the request reached its worker, let it close the same row cleanup removes.
        if mcp_env["app"].state.mcp.dispatcher.tasks:
            await asyncio.wait_for(worker_done.wait(), timeout=3)
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            runs = select(Run.id).where(Run.mdm_connection_id == connection_id)
            await db.execute(delete(RunLogLine).where(RunLogLine.run_id.in_(runs)))
            await db.execute(delete(Run).where(Run.mdm_connection_id == connection_id))
            await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
            await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
            await db.commit()


async def test_mcp_credentials_cannot_bypass_gates_with_rest_or_forged_dispatch_headers(mcp_env):
    token = await _mint(mcp_env["browser"])
    for extra in ({}, {"looninspect.mcp_dispatch": "true", "X-LoonInspect-MCP-Dispatch": "true"}):
        response = await mcp_env["client"].get(
            "/api/devices",
            headers={"Authorization": f"Bearer {token['token']}", **extra},
            params={"q": mcp_env["prefix"]},
        )
        assert response.status_code == 403
        assert "only be used through the MCP endpoint" in response.json()["detail"]
        assert mcp_env["prefix"] not in response.text


async def test_nonloopback_plain_http_is_refused_even_with_forged_forwarding_headers(mcp_env):
    token = await _mint(mcp_env["browser"])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mcp_env["app"], client=("198.51.100.20", 41000)),
        base_url="http://127.0.0.1:8000",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"},
    ) as remote:
        response = await _rpc(remote, token["token"], "tools/list")
    assert response.status_code == 400
    assert "require HTTPS" in response.json()["detail"]


async def test_each_token_is_bound_to_its_own_tenant_and_ids_do_not_cross(mcp_env):
    home = await _mint(mcp_env["browser"])
    other_id = mcp_env["other"]
    other = await _raw_token(other_id, mcp_env["accounts"][other_id])
    for grant, tenant_id, forbidden in (
        (home, OPERATIONAL_TENANT_ID, other_id),
        (other, other_id, OPERATIONAL_TENANT_ID),
    ):
        result = await _call(mcp_env["client"], grant["token"], "list_devices", {"q": mcp_env["prefix"]})
        assert result.get("isError") is not True, result
        assert result["structuredContent"]["organizationId"] == str(tenant_id)
        assert [row["id"] for row in result["structuredContent"]["data"]["items"]] == [mcp_env["devices"][tenant_id]]
        missing = await _call(mcp_env["client"], grant["token"], "get_device", {"device_id": mcp_env["devices"][forbidden]})
        assert missing["isError"] is True
        assert "not found in this organization" in missing["structuredContent"]["error"]
        assert mcp_env["prefix"] not in json.dumps(missing)


async def test_browser_revocation_invalidates_next_mcp_request(mcp_env):
    token = await _mint(mcp_env["browser"])
    assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 200
    revoked = await mcp_env["browser"].delete(
        f"/api/auth/tokens/{token['id']}", headers={"X-Expected-Tenant-ID": str(OPERATIONAL_TENANT_ID)}
    )
    assert revoked.status_code == 204, revoked.text
    refused = await _rpc(mcp_env["client"], token["token"], "tools/list")
    assert refused.status_code == 401
    assert "revoked" in refused.json()["detail"]


async def test_owner_demotion_and_disabling_apply_without_reconnecting(mcp_env):
    from app.core.database import session_for_tenant
    from app.models.schema import Account, AccountRole

    token = await _mint(mcp_env["browser"])
    account_id = mcp_env["accounts"][OPERATIONAL_TENANT_ID]
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(delete(AccountRole).where(AccountRole.account_id == account_id))
        db.add(AccountRole(account_id=account_id, role="viewer", source="manual"))
        await db.commit()
    try:
        assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 403
    finally:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(delete(AccountRole).where(AccountRole.account_id == account_id))
            db.add(AccountRole(account_id=account_id, role="admin", source="manual"))
            await db.execute(update(Account).where(Account.id == account_id).values(status="disabled"))
            await db.commit()
    try:
        assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 401
    finally:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(update(Account).where(Account.id == account_id).values(status="active"))
            await db.commit()


@pytest.mark.parametrize(("scopes", "expires"), [([], True), (["device:read"], True), (READ_SCOPES, False)])
async def test_ordinary_inherited_or_unexpiring_tokens_are_not_mcp_grants(mcp_env, scopes, expires):
    token = await _raw_token(OPERATIONAL_TENANT_ID, mcp_env["accounts"][OPERATIONAL_TENANT_ID], scopes=scopes, expires=expires)
    response = await _rpc(mcp_env["client"], token["token"], "tools/list")
    assert response.status_code == 403
    assert "not an MCP grant" in response.json()["detail"]


async def test_expired_token_is_rejected_before_protocol_dispatch(mcp_env):
    from app.core.database import session_for_tenant
    from app.models.schema import ApiToken

    token = await _mint(mcp_env["browser"])
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(
            update(ApiToken).where(ApiToken.id == token["id"]).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db.commit()
    assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 401


@pytest.mark.parametrize("key", ["ai_features", MCP_ACCESS_FLAG])
async def test_disabling_either_gate_refuses_existing_grants(mcp_env, key):
    token = await _mint(mcp_env["browser"])
    assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 200
    await _flag(OPERATIONAL_TENANT_ID, key, False)
    try:
        response = await _rpc(mcp_env["client"], token["token"], "tools/list")
        assert response.status_code == 403
        assert "off" in response.json()["detail"]
    finally:
        await _flag(OPERATIONAL_TENANT_ID, key, True)


async def test_successful_result_logs_fields_without_raw_inventory_or_search(mcp_env):
    from app.core.database import session_for_tenant
    from app.models.schema import ShareLog

    token = await _mint(mcp_env["browser"])
    result = await _call(mcp_env["client"], token["token"], "list_devices", {"q": mcp_env["prefix"]})
    assert result.get("isError") is not True, result
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        rows = (await db.scalars(select(ShareLog).where(ShareLog.endpoint == f"mcp-client:{token['id']}"))).all()
        assert len(rows) == 1
        disclosure = rows[0].payload
        assert disclosure["feature"] == "mcp.list_devices"
        assert "serial numbers" in disclosure["fields"]
        assert disclosure["model"] is None
        serialized = json.dumps(disclosure)
        assert mcp_env["prefix"] not in serialized
        assert token["token"] not in serialized
        assert "mcp-serial-" not in serialized


async def test_grant_creation_requires_current_organization_and_finite_allowed_scopes(mcp_env):
    body = {"name": "MCP refused test", "scopes": READ_SCOPES, "expiresInDays": 1}
    browser = mcp_env["browser"]
    assert (await browser.post("/api/auth/tokens", json=body)).status_code == 409
    mismatch = await browser.post("/api/auth/tokens", json=body, headers={"X-Expected-Tenant-ID": str(mcp_env["other"])})
    assert mismatch.status_code == 409
    headers = {"X-Expected-Tenant-ID": str(OPERATIONAL_TENANT_ID)}
    assert (await browser.post("/api/auth/tokens", json={**body, "expiresInDays": None}, headers=headers)).status_code == 422
    dangerous = {**body, "scopes": [*READ_SCOPES, "account:write"]}
    assert (await browser.post("/api/auth/tokens", json=dangerous, headers=headers)).status_code == 422


async def test_revocation_during_a_tool_withholds_result_and_does_not_log_it_as_disclosed(mcp_env, monkeypatch):
    from app.core.database import session_for_tenant
    from app.mcp.tools import TOOLS
    from app.models.schema import ApiToken, ShareLog

    token = await _mint(mcp_env["browser"])

    async def revoke_while_running(arguments, request):
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(update(ApiToken).where(ApiToken.id == token["id"]).values(revoked_at=datetime.now(UTC)))
            await db.commit()
        return {"private": "must not be returned after revocation"}

    monkeypatch.setitem(TOOLS, "list_devices", replace(TOOLS["list_devices"], execute=revoke_while_running))
    result = await _call(mcp_env["client"], token["token"], "list_devices")
    assert result["isError"] is True
    assert "must not be returned" not in json.dumps(result)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert not (await db.scalars(select(ShareLog).where(ShareLog.endpoint == f"mcp-client:{token['id']}"))).all()


@pytest_asyncio.fixture(loop_scope="session")
async def switched_operator(mcp_env):
    """An independent home administrator acting as an analyst in the other organization."""
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.models.schema import Account, AccountTenant, ApiToken, LoginAttempt, ShareLog, UserSession

    suffix = uuid4().hex[:12]
    email = f"mcp-switched-{suffix}@example.com"
    password = f"mcp-switched-password-{suffix}"
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        account, _ = await create_account(
            db, email=email, display_name="Switched MCP operator", password=password, roles=("admin",)
        )
        account_id = account.id
        db.add(AccountTenant(account_id=account_id, tenant_id=mcp_env["other"], roles=["analyst"]))
        await db.commit()

    browser = httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp_env["app"]), base_url=BASE_URL)
    try:
        login = await browser.post("/api/auth/login", json={"email": email, "password": password})
        assert login.status_code == 200, login.text
        browser.headers["X-CSRF-Token"] = browser.cookies.get("loon_csrf", "")
        switched = await browser.post("/api/auth/switch-tenant", json={"tenantId": str(mcp_env["other"])})
        assert switched.status_code == 200, switched.text
        assert switched.json()["roles"] == ["analyst"]
        browser.headers["X-CSRF-Token"] = browser.cookies.get("loon_csrf", "")
        yield {"browser": browser, "account_id": account_id, "tenant_id": mcp_env["other"]}
    finally:
        await browser.aclose()
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            token_ids = (await db.scalars(select(ApiToken.id).where(ApiToken.account_id == account_id))).all()
        for tenant_id in (OPERATIONAL_TENANT_ID, mcp_env["other"]):
            async with session_for_tenant(tenant_id) as db:
                await db.execute(delete(ShareLog).where(ShareLog.endpoint.in_([f"mcp-client:{token}" for token in token_ids])))
                await db.commit()
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(delete(ApiToken).where(ApiToken.account_id == account_id))
            await db.execute(delete(UserSession).where(UserSession.account_id == account_id))
            await db.execute(delete(AccountTenant).where(AccountTenant.account_id == account_id))
            account = await db.get(Account, account_id)
            await db.delete(account)
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
            await db.commit()


async def test_switched_grant_stays_with_home_owner_and_reads_only_its_acting_organization(mcp_env, switched_operator):
    from app.core.database import session_for_tenant
    from app.models.schema import ApiToken, ApiTokenTenant

    acting = switched_operator["tenant_id"]
    token = await _mint(switched_operator["browser"], tenant_id=acting)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        stored = await db.get(ApiToken, token["id"])
        assert stored is not None and stored.tenant_id == OPERATIONAL_TENANT_ID
        index = await db.get(ApiTokenTenant, stored.token_hash)
        assert index.tenant_id == acting
        assert index.home_tenant_id == OPERATIONAL_TENANT_ID
    async with session_for_tenant(acting) as db:
        assert await db.get(ApiToken, token["id"]) is None, "The credential itself must stay protected by home RLS."
    result = await _call(mcp_env["client"], token["token"], "list_devices", {"q": mcp_env["prefix"]})
    assert result.get("isError") is not True, result
    assert result["structuredContent"]["organizationId"] == str(acting)
    assert [row["id"] for row in result["structuredContent"]["data"]["items"]] == [mcp_env["devices"][acting]]


async def test_switched_token_list_and_revoke_are_filtered_to_active_organization(mcp_env, switched_operator):
    acting, browser = switched_operator["tenant_id"], switched_operator["browser"]
    target_token = await _mint(browser, tenant_id=acting)
    home_token = await _raw_token(OPERATIONAL_TENANT_ID, switched_operator["account_id"])
    headers = {"X-Expected-Tenant-ID": str(acting)}
    listed = await browser.get("/api/auth/tokens", headers=headers)
    assert listed.status_code == 200, listed.text
    assert [token["id"] for token in listed.json()] == [target_token["id"]]
    assert (await browser.delete(f"/api/auth/tokens/{home_token['id']}", headers=headers)).status_code == 404
    assert (await browser.delete(f"/api/auth/tokens/{target_token['id']}", headers=headers)).status_code == 204
    assert (await _rpc(mcp_env["client"], target_token["token"], "tools/list")).status_code == 401
    switched = await browser.post("/api/auth/switch-tenant", json={"tenantId": str(OPERATIONAL_TENANT_ID)})
    assert switched.status_code == 200, switched.text
    browser.headers["X-CSRF-Token"] = browser.cookies.get("loon_csrf", "")
    listed = await browser.get("/api/auth/tokens", headers={"X-Expected-Tenant-ID": str(OPERATIONAL_TENANT_ID)})
    assert listed.status_code == 200, listed.text
    assert [token["id"] for token in listed.json()] == [home_token["id"]]


async def test_switched_token_scopes_use_acting_roles_at_issuance_and_on_every_call(mcp_env, switched_operator):
    from app.core.database import session_for_tenant
    from app.models.schema import AccountRole, AccountTenant

    acting, browser = switched_operator["tenant_id"], switched_operator["browser"]
    scopes = [*READ_SCOPES, Permission.DEVICE_SYNC.value]
    token = await _mint(browser, tenant_id=acting, scopes=scopes)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(
            update(AccountTenant)
            .where(AccountTenant.account_id == switched_operator["account_id"], AccountTenant.tenant_id == acting)
            .values(roles=["auditor"])
        )
        await db.commit()
    denied = await browser.post(
        "/api/auth/tokens",
        json={"name": "too wide", "scopes": scopes, "expiresInDays": 1},
        headers={"X-Expected-Tenant-ID": str(acting)},
    )
    assert denied.status_code == 422, denied.text  # Home admin must not lend its write permissions.
    denied_regular = await browser.post(
        "/api/auth/tokens", json={"name": "ordinary too wide", "scopes": ["connection:write"], "expiresInDays": 1}
    )
    assert denied_regular.status_code == 422
    listed = await _rpc(mcp_env["client"], token["token"], "tools/list")
    assert listed.status_code == 200, listed.text
    assert "start_inventory_sync" not in {tool["name"] for tool in listed.json()["result"]["tools"]}
    refused = await _call(mcp_env["client"], token["token"], "start_inventory_sync", {"connection_id": 1})
    assert refused["isError"] is True
    # Home role changes must not replace the distinct, current role in the target organization.
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(delete(AccountRole).where(AccountRole.account_id == switched_operator["account_id"]))
        db.add(AccountRole(account_id=switched_operator["account_id"], role="viewer", source="manual"))
        await db.commit()
    listed = await _rpc(mcp_env["client"], token["token"], "tools/list")
    assert listed.status_code == 200, listed.text
    assert "get_posture" in {tool["name"] for tool in listed.json()["result"]["tools"]}


async def test_removing_membership_revokes_switched_token_even_if_membership_returns(mcp_env, switched_operator):
    from app.core.database import session_for_tenant
    from app.models.schema import AccountTenant

    acting = switched_operator["tenant_id"]
    token = await _mint(switched_operator["browser"], tenant_id=acting)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(
            delete(AccountTenant).where(
                AccountTenant.account_id == switched_operator["account_id"], AccountTenant.tenant_id == acting
            )
        )
        await db.commit()
    assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 401
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        db.add(AccountTenant(account_id=switched_operator["account_id"], tenant_id=acting, roles=["analyst"]))
        await db.commit()
    assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 401


async def test_account_disable_revokes_home_and_switched_grants_permanently(mcp_env, switched_operator):
    target = await _mint(switched_operator["browser"], tenant_id=switched_operator["tenant_id"])
    home = await _raw_token(OPERATIONAL_TENANT_ID, switched_operator["account_id"])
    path = f"/api/accounts/{switched_operator['account_id']}"
    disabled = await mcp_env["browser"].patch(path, json={"status": "disabled"})
    assert disabled.status_code == 200, disabled.text
    for token in (home, target):
        assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 401
    enabled = await mcp_env["browser"].patch(path, json={"status": "active"})
    assert enabled.status_code == 200, enabled.text
    for token in (home, target):
        assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 401


async def test_switched_grant_checks_consent_in_acting_organization(mcp_env, switched_operator):
    acting = switched_operator["tenant_id"]
    token = await _mint(switched_operator["browser"], tenant_id=acting)
    await _flag(OPERATIONAL_TENANT_ID, MCP_ACCESS_FLAG, False)
    try:
        assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 200
        await _flag(acting, MCP_ACCESS_FLAG, False)
        assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 403
    finally:
        await _flag(OPERATIONAL_TENANT_ID, MCP_ACCESS_FLAG, True)
        await _flag(acting, MCP_ACCESS_FLAG, True)


async def test_ordinary_scoped_bearer_also_honors_switched_organization(mcp_env, switched_operator):
    acting = switched_operator["tenant_id"]
    token = await _mint(switched_operator["browser"], tenant_id=acting, scopes=[Permission.DEVICE_READ.value])
    response = await mcp_env["client"].get(
        "/api/devices", params={"q": mcp_env["prefix"]}, headers={"Authorization": f"Bearer {token['token']}"}
    )
    assert response.status_code == 200, response.text
    assert [row["id"] for row in response.json()["items"]] == [mcp_env["devices"][acting]]
    assert (await _rpc(mcp_env["client"], token["token"], "tools/list")).status_code == 403
