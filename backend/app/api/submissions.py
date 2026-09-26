"""Request coverage and Report an incorrect match (#623; docs/troubleshooting.md §21). Every route needs
SYSTEM_WRITE, as Send now does: view permission is not permission to disclose. Previewing and sending are
refused while INTELLIGENCE_ACCESS is off; reading, status and withdrawal are not, as stopping paid updates
is not, so the switch never strands a withdrawal. No answer carries a case key."""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime
from fnmatch import fnmatch

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.config import settings
from app.core.database import get_db
from app.core.intelligence import locked_settings
from app.core.permissions import Permission
from app.core.sharing import get_or_create_settings
from app.core.submissions import POLL_FLOOR, mint_case_key, payload_for, refresh, send, withdraw
from app.models.schema import DataSharingSettings, SubmissionCase
from app.schemas.submissions import SubmissionCaseOut, SubmissionCasesOut, SubmissionIn, SubmissionPreviewOut

router = APIRouter(prefix="/api/submissions", tags=["submissions"], dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
transport_override: httpx.AsyncBaseTransport | None = None  # a test's stand-in for the intelligence service
OPEN = ("pending", "received", "reviewing", "needs_information", "accepted")
SAME = ("kind", "app_name", "bundle_id", "platform", "versions", "public_url", "text", "contact", "finding", "finding_release")


def _draft(body: SubmissionIn, row: DataSharingSettings) -> tuple[SubmissionCase, str | None]:
    """The case the body describes, and the exclusion pattern its bundle identifier matches, as the exchange does."""
    if not settings.intelligence_access:
        raise HTTPException(409, "Nothing was sent: submissions belong to the v2 preview, and INTELLIGENCE_ACCESS is off here.")
    named = (body.finding, body.finding_release)
    if not (all(named) if body.kind == "correction" else not any(named)):
        raise HTTPException(422, "A correction names the finding and the release that produced it; a coverage request, neither.")
    excluded = next((glob for glob in row.exclude_globs or [] if body.bundle_id and fnmatch(body.bundle_id, glob)), None)
    return SubmissionCase(**body.model_dump(include=set(SAME)), state="pending"), excluded


def _audit(action: AuditAction, case: SubmissionCase, done: bool) -> None:
    what = {"kind": case.kind, "app_name": case.app_name, "bundle_id": case.bundle_id, "platform": case.platform}
    audit(action, outcome="success" if done else "failure", target_type="submission_case", target_id=case.id, **what)


async def _case(db: AsyncSession, case_id: uuid.UUID) -> SubmissionCase:
    if (case := await db.get(SubmissionCase, case_id)) is None:
        raise HTTPException(404, "This organization has no such case.")
    return case


@router.get("", response_model=SubmissionCasesOut)
async def cases(db: AsyncSession = Depends(get_db)) -> SubmissionCasesOut:
    rows = await db.scalars(select(SubmissionCase).order_by(SubmissionCase.created_at.desc(), SubmissionCase.id.desc()))
    return SubmissionCasesOut(enabled=settings.intelligence_access, cases=[SubmissionCaseOut.model_validate(r) for r in rows])


@router.post("/preview", response_model=SubmissionPreviewOut)
async def preview(body: SubmissionIn, db: AsyncSession = Depends(get_db)) -> SubmissionPreviewOut:
    """Exactly what Send puts on the wire, from the same builder, less the case key Send mints."""
    case, excluded = _draft(body, await get_or_create_settings(db))
    return SubmissionPreviewOut(payload=payload_for(case), excluded_by=excluded)


@router.post("", status_code=202, response_model=SubmissionCaseOut)
async def submit(
    body: SubmissionIn, principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)
) -> SubmissionCase:
    """Store the case under a fresh key and send it; the same fields while it is pending or open, and not
    withdrawn here, answer it instead, sent again with its key unless the service asked for a pause. The consent
    row lock serializes; `send` holds the case row, so racing clicks dial once, and the audit records the one
    that created it. A withdrawal the service has not confirmed is settled by withdrawing again, never by Send."""
    draft, excluded = _draft(body, await locked_settings(db))
    if not body.permission:
        raise HTTPException(422, "Nothing was sent: give permission to send this one case, after reading its preview.")
    if excluded and not body.excluded_override:
        rule = f'{body.bundle_id} matches "{excluded}" on this organization\'s data-sharing exclusion list'
        raise HTTPException(409, f"Nothing was sent: {rule}. This one case needs the one-time override; the list stays.")
    same = (getattr(SubmissionCase, name) == getattr(draft, name) for name in SAME)
    live = SubmissionCase.state.in_(OPEN), SubmissionCase.withdrawn_at.is_(None)  # withdrawn here, confirmed or not: done
    case = await db.scalar(select(SubmissionCase).where(*live, *same).limit(1))
    created = case is None
    if created:
        case = draft
        case.case_key, case.permission_at, case.excluded_override = mint_case_key(), datetime.now(UTC), bool(excluded)
        case.submitted_by_account_id = principal.account.id
        db.add(case)
    if case.state == "pending" and not (case.retry_at and case.retry_at > datetime.now(UTC)):
        case = await send(db, case, transport=transport_override)
    if created:
        _audit(AuditAction.SUBMISSION_SENT, case, case.state != "pending")
    if created and excluded:
        _audit(AuditAction.SUBMISSION_EXCLUDED_OVERRIDE, case, case.state != "pending")
    return case


@router.post("/{case_id}/status", response_model=SubmissionCaseOut)
async def status(case_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> SubmissionCase:
    """Where the case stands: asked once a minute at most, and never before a time the service gave."""
    case = await _case(db, case_id)
    floor = case.last_status_at and case.last_status_at + POLL_FLOOR
    wait = max(((at - datetime.now(UTC)).total_seconds() for at in (floor, case.retry_at) if at), default=0)
    if wait > 0 and case.state not in ("pending", "expired"):
        seconds = math.ceil(wait)
        why = "Asked too soon: a case's status is read once a minute, and not before a time the service gave."
        raise HTTPException(429, f"{why} Try again in {seconds} seconds.", headers={"Retry-After": str(seconds)})
    return await refresh(db, case, transport=transport_override)


@router.post("/{case_id}/withdraw", response_model=SubmissionCaseOut)
async def withdraw_case(case_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> SubmissionCase:
    """The service deletes the case's content and contact at once; this instance clears what was written."""
    if (case := await _case(db, case_id)).state != "withdrawn":
        case = await withdraw(db, case, transport=transport_override)
        _audit(AuditAction.SUBMISSION_WITHDRAWN, case, case.state == "withdrawn")
    return case
