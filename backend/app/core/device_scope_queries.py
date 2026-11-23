"""Validate EA regex with the query engine and bound its work on inventory routes."""

from contextlib import asynccontextmanager

from fastapi import Depends, HTTPException
from sqlalchemy import literal, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, get_snapshot_db, get_vuln_read_db
from app.schemas.patch_plans import ScopeGroup


@asynccontextmanager
async def guard_scope_queries(db):
    try:
        yield
    except DBAPIError as exc:
        state = getattr(exc.orig, "sqlstate", None)
        if db.info.get("scope_regex") and state == "2201B":
            raise HTTPException(
                422, "The EA regular expression is invalid. Check brackets and escapes, or use 'like' for a literal substring."
            ) from exc
        if db.info.get("scope_regex") and state == "57014":
            raise HTTPException(
                408,
                "The regex device filter exceeded the database time limit. "
                "Simplify the expression or select a narrower Jamf connection and retry.",
            ) from exc
        raise


async def prepare_scope(db, scope):
    if scope is None:
        return
    pending, patterns = list(scope.rules), set()
    while pending:
        rule = pending.pop()
        if isinstance(rule, ScopeGroup):
            pending.extend(rule.rules)
        elif rule.operator in {"matches_regex", "does_not_match_regex"}:
            patterns.add(rule.value)
    if not patterns:
        return
    db.info["scope_regex"] = True
    async with guard_scope_queries(db):
        # LOCAL settings disappear at commit/rollback and cannot leak through the pool.
        existing = int(await db.scalar(text("SELECT setting FROM pg_settings WHERE name = 'statement_timeout'")))
        await db.execute(
            text("SELECT set_config('statement_timeout', :limit, true)"), {"limit": str(min(existing or 5000, 5000))}
        )
        for pattern in sorted(patterns):
            await db.scalar(select(literal("").regexp_match(pattern, flags="i")))


async def get_scope_db(db: AsyncSession = Depends(get_db)):
    async with guard_scope_queries(db):
        yield db


async def get_scope_snapshot_db(db: AsyncSession = Depends(get_snapshot_db)):
    async with guard_scope_queries(db):
        yield db


async def get_scope_vuln_read_db(db: AsyncSession = Depends(get_vuln_read_db)):
    async with guard_scope_queries(db):
        yield db
