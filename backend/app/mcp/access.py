"""Recheck a bearer grant and the organization's consent before any MCP data is returned."""

from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ai import AI_SHARE_TIER, ai_features_enabled
from app.core.auth import Principal, _authenticate_bearer
from app.core.permissions import Permission
from app.mcp.policy import ALLOWED_SCOPES, MCP_ACCESS_FLAG
from app.models.schema import FeatureFlag, ShareLog


async def access_enabled(db: AsyncSession) -> bool:
    return bool(await db.scalar(select(FeatureFlag.enabled).where(FeatureFlag.key == MCP_ACCESS_FLAG)))


async def resolve_grant(db: AsyncSession, raw: str, *, require_enabled: bool = True) -> Principal:
    principal = await _authenticate_bearer(db, raw)
    if principal is None:
        raise HTTPException(401, "MCP credential is missing, expired or revoked. Create a new connection in AI connections.")
    token = principal.token
    if (
        token is None
        or token.expires_at is None
        or Permission.MCP_CONNECT not in principal.permissions
        or Permission.MCP_CONNECT.value not in (token.scopes or [])
        or not set(token.scopes) <= ALLOWED_SCOPES
    ):
        raise HTTPException(403, "This token is not an MCP grant. Create an expiring, scoped connection in AI connections.")
    if require_enabled:
        if not await ai_features_enabled(db):
            raise HTTPException(403, "AI features are off. An administrator can enable them in Settings > Feature Flags.")
        if not await access_enabled(db):
            raise HTTPException(
                403, "MCP access is off for this organization. Review and enable it in Settings > AI connections."
            )
    return principal


async def disclose(db: AsyncSession, principal: Principal, tool: str, fields: tuple[str, ...]) -> None:
    """Commit field categories before returning data; the downstream model is explicitly unknown."""
    now = datetime.now(UTC)
    db.add(
        ShareLog(
            occurred_at=now,
            tier=AI_SHARE_TIER,
            endpoint=f"mcp-client:{principal.token.id}",
            outcome="sent",
            payload={
                "feature": f"mcp.{tool}",
                "fields": sorted(set(fields)),
                "connection": principal.token.name,
                "model": None,
                "recipient": "user-configured MCP client; downstream provider and model unknown",
            },
        )
    )
    await db.execute(delete(ShareLog).where(ShareLog.occurred_at < now - timedelta(days=90)))
    await db.commit()
