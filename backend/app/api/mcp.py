"""Browser-only consent and credential checks for external MCP clients."""

from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, SecretStr
from pydantic.alias_generators import to_camel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ai import ai_features_enabled
from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db, session_for_tenant
from app.core.permissions import Permission
from app.core.tenancy import reset_tenant_id, set_tenant_id
from app.mcp.access import access_enabled, resolve_grant
from app.mcp.policy import DISCLOSURE, MCP_ACCESS_FLAG, SCOPE_DESCRIPTIONS
from app.mcp.tools import TOOLS
from app.models.schema import FeatureFlag

router = APIRouter(prefix="/api/mcp", tags=["mcp"], dependencies=[Depends(require(Permission.TOKEN_CREATE))])


class _Model(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class MCPScope(_Model):
    value: str
    label: str
    description: str


class MCPSettings(_Model):
    organization_id: UUID
    enabled: bool
    ai_features_enabled: bool
    can_manage: bool
    endpoint: str = "/mcp"
    scopes: list[MCPScope]
    required_scopes: list[str] = [Permission.MCP_CONNECT.value]
    disclosure: str = DISCLOSURE


class MCPUpdate(_Model):
    enabled: bool


class MCPTest(_Model):
    token: SecretStr


class MCPTestResult(_Model):
    ok: bool = True
    tool_count: int
    organization_id: UUID


def browser_write(
    expected: UUID = Header(alias="X-Expected-Tenant-ID"), principal: Principal = Depends(current_principal)
) -> Principal:
    if principal.auth_method != "session":
        raise HTTPException(403, "Manage AI connections from a signed-in browser session.")
    if expected != principal.tenant_id:
        raise HTTPException(409, "Your active organization changed. Reload AI connections before continuing.")
    return principal


async def settings_for(principal: Principal, db: AsyncSession) -> MCPSettings:
    return MCPSettings(
        organization_id=principal.tenant_id,
        enabled=await access_enabled(db),
        ai_features_enabled=await ai_features_enabled(db),
        can_manage=Permission.SYSTEM_WRITE in principal.permissions,
        scopes=[
            MCPScope(value=permission.value, label=words[0], description=words[1])
            for permission, words in SCOPE_DESCRIPTIONS.items()
            if permission in principal.permissions
        ],
    )


@router.get("/settings", response_model=MCPSettings)
async def get_settings(
    response: Response,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
    expected: UUID | None = Header(default=None, alias="X-Expected-Tenant-ID"),
) -> MCPSettings:
    if expected is not None and expected != principal.tenant_id:
        raise HTTPException(409, "Your active organization changed. Reload AI connections before continuing.")
    response.headers["Cache-Control"] = "private, no-store"
    return await settings_for(principal, db)


@router.patch("/settings", response_model=MCPSettings, dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
async def update_settings(
    payload: MCPUpdate, response: Response, principal: Principal = Depends(browser_write), db: AsyncSession = Depends(get_db)
) -> MCPSettings:
    flag = await db.scalar(select(FeatureFlag).where(FeatureFlag.key == MCP_ACCESS_FLAG))
    if flag is None:
        db.add(FeatureFlag(key=MCP_ACCESS_FLAG, enabled=payload.enabled))
    else:
        flag.enabled = payload.enabled
    await db.commit()
    audit(AuditAction.MCP_ACCESS_CHANGED, target_type="mcp_access", target_id=MCP_ACCESS_FLAG, enabled=payload.enabled)
    response.headers["Cache-Control"] = "private, no-store"
    return await settings_for(principal, db)


@router.post("/test", response_model=MCPTestResult)
async def test_connection(payload: MCPTest, response: Response, principal: Principal = Depends(browser_write)) -> MCPTestResult:
    raw = payload.token.get_secret_value()
    if len(raw) > 1024:
        raise HTTPException(400, "The credential could not be checked. Paste the token shown when this connection was created.")
    tenant_token = set_tenant_id(principal.tenant_id)
    try:
        async with session_for_tenant(principal.tenant_id) as db:
            try:
                checked = await resolve_grant(db, raw)
            except HTTPException as exc:
                # A bad test credential is not an expired browser session.
                raise HTTPException(400 if exc.status_code == 401 else exc.status_code, exc.detail) from None
            if checked.tenant_id != principal.tenant_id or checked.account.id != principal.account.id:
                raise HTTPException(403, "This credential does not belong to your account in the active organization.")
            count = sum(set(tool.permissions) <= checked.permissions for tool in TOOLS.values())
    finally:
        reset_tenant_id(tenant_token)
    response.headers["Cache-Control"] = "private, no-store"
    return MCPTestResult(tool_count=count, organization_id=principal.tenant_id)
