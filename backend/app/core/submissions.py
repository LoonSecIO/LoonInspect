"""Coverage requests and match corrections, the client half of Support's docs/contracts/submissions.md (#623).

A case's key is its idempotency key, status capability and withdrawal capability at once: minted before
the first request, stored encrypted like a contribution receipt, sent only in a request body, never logged
or shown, and never joined by a credential, receipt or submission UUID. Sending belongs to the v2 preview
INTELLIGENCE_ACCESS gates; status and withdrawal do not, so switching it off never strands a withdrawal.
Outcomes land on the case (`state`, `last_error`), quoting the service's one bounded sentence.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.intelligence import AccessFailure, endpoint
from app.models.schema import SubmissionCase

logger = logging.getLogger(__name__)

# 32 bytes fill 256 of the 258 bits in 43 characters, so the last one sets no spare bit.
KEY = re.compile(r"loon_case_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")
RELEASE = re.compile(r"[0-9a-f]{64}")
STATES = {"received", "reviewing", "needs_information", "accepted", "declined", "published", "withdrawn"}
FIELDS = ("kind", "app_name", "bundle_id", "platform", "versions", "public_url", "text", "contact")
TYPED = ("public_url", "text", "contact")  # what the administrator wrote; withdrawal clears it here too
POLL_FLOOR = timedelta(seconds=60)  # the service answers a faster status read with 429
SAID = 1000  # characters of the service's sentence quoted; its longest, the public_url rule, has 387
Transport = httpx.AsyncBaseTransport | None


def mint_case_key() -> str:
    key = "loon_case_" + secrets.token_urlsafe(32)  # 32 bytes from the operating system's random source
    if not KEY.fullmatch(key):
        raise RuntimeError("secrets.token_urlsafe(32) did not give 43 canonical base64url characters")
    return key


def payload_for(case: SubmissionCase) -> dict:
    """The intake body: exactly the contract's fields, an empty one left out as the contract reads null."""
    names = FIELDS + (("finding", "finding_release") if case.kind == "correction" else ())
    body = {"contract": "v2", "case_key": case.case_key} | {name: getattr(case, name) for name in names}
    return {name: value for name, value in body.items() if value not in (None, "")}


def _stamp(value) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timezone missing")
    return parsed.astimezone(UTC)


def _waiting(*until: datetime | None) -> bool:
    return any(at is not None and datetime.now(UTC) < at for at in until)


def _failed(case: SubmissionCase, sentence: str) -> None:
    case.last_error = sentence
    logger.warning("submission case not settled", extra={"case": str(case.id), "state": case.state, "detail": sentence})


def _host() -> str:
    return urlsplit(settings.intelligence_endpoint).hostname or "(no host)"  # never a password or a path


def _refused(case: SubmissionCase, code: int, said: str) -> None:
    when = f"after {case.retry_at:%Y-%m-%d %H:%M} UTC" if case.retry_at else "later"
    if code == 400:
        sentence = f"The intelligence service refused the request (HTTP 400).{said} Nothing was stored; correct it in a new case."
    elif code in (403, 404) and not said:
        sentence = f"No submissions service answers at {_host()} (HTTP {code}). Check INTELLIGENCE_ENDPOINT with support."
    else:
        sentence = f"The intelligence service answered HTTP {code}.{said} Try again {when}; the case keeps its key."
    _failed(case, sentence)


async def _post(case: SubmissionCase, route: str, body: dict, transport: Transport) -> tuple[int, dict | None, str] | None:
    """POST only `body`, with no credential, query, redirect or proxy: (status, answer, the service's sentence)."""
    raw = bytearray()
    try:
        async with (
            httpx.AsyncClient(transport=transport, timeout=10, follow_redirects=False, trust_env=False) as client,
            client.stream("POST", endpoint("submissions" + route), json=body) as response,
        ):
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 65536:
                    break
    except (AccessFailure, httpx.HTTPError, httpx.InvalidURL):
        sentence = f"No answer came from the intelligence service at {_host()}. "
        _failed(case, sentence + "Check DNS, network access and INTELLIGENCE_ENDPOINT, then try again; the case keeps its key.")
        return None
    wait = response.headers.get("retry-after", "")
    seconds = min(max(int(wait), 1), 86400) if wait.isascii() and wait.isdigit() else None  # a day's budget: to midnight
    case.retry_at = datetime.now(UTC) + timedelta(seconds=seconds) if seconds else None
    try:
        answer = json.loads(raw)
    except ValueError:
        answer = None
    said = answer.get("error") if isinstance(answer, dict) else None
    said = said if isinstance(said, str) and said.isprintable() else ""
    said = said if len(said) <= SAID else said[:SAID] + "…"  # cut, never dropped: a refusal names its rule first
    return response.status_code, answer if isinstance(answer, dict) else None, f' It said: "{said}"' if said else ""


def _settled(case: SubmissionCase, answer: dict | None, state: str | None = None) -> bool:
    try:
        received, closed = _stamp(answer["received_at"]), answer.get("closed_at")
        release, words = answer.get("release"), (answer.get("coverage"), answer.get("note"))
        if answer["contract"] != "v2" or answer["state"] not in STATES or state not in (None, answer["state"]):
            return False
        if not (release is None or RELEASE.fullmatch(release)) or not all(isinstance(w, str | None) for w in words):
            return False
        closed = None if closed is None else _stamp(closed)
    except (KeyError, TypeError, ValueError):
        return False
    case.state, case.received_at, case.closed_at, case.release = answer["state"], received, closed, release
    (case.coverage, case.note), case.last_error = words, None
    if case.state == "withdrawn":  # a status read may hear it first: after a lost answer, or on a copied database
        _forget(case)
    return True


def _forget(case: SubmissionCase) -> None:
    """Withdrawal's local half, whichever answer brings it: the first date stays, what the administrator wrote goes."""
    case.withdrawn_at = case.withdrawn_at or datetime.now(UTC)
    for name in TYPED:
        setattr(case, name, None)


async def _locked(db: AsyncSession, case: SubmissionCase) -> SubmissionCase:
    query = select(SubmissionCase).where(SubmissionCase.id == case.id).with_for_update()
    return (await db.execute(query.execution_options(populate_existing=True))).scalar_one()


async def send(db: AsyncSession, case: SubmissionCase, *, transport: Transport = None) -> SubmissionCase:
    """Send a pending case, storing its key before it leaves: a retry is the identical request, which gets the
    original 202. A 409 gets one fresh key, stored before it is sent. The row stays locked meanwhile. A case
    withdrawn here is never sent, whether or not the service has confirmed the withdrawal."""
    await db.commit()
    case = await _locked(db, case)
    for fresh in (False, True):
        if case.state != "pending" or case.withdrawn_at or _waiting(case.retry_at):
            break
        if not settings.intelligence_access or case.permission_at is None:
            why = "no permission is recorded; confirm the case's preview" if settings.intelligence_access else ""
            _failed(case, f"Nothing was sent: {why or 'INTELLIGENCE_ACCESS, the v2 preview switch, is off'}.")
            break
        if (reply := await _post(case, "", payload_for(case), transport)) is None:
            break
        code, answer, said = reply
        if code == 409 and not fresh:
            case.case_key = mint_case_key()
            await db.commit()
            case = await _locked(db, case)
            continue
        if code == 409:
            _failed(case, f"The service refused this case's key and a fresh one (HTTP 409).{said} Contact support.")
        elif not (code == 202 and _settled(case, answer, "received")):
            _refused(case, code, said)
        break
    await db.commit()
    return case


async def refresh(db: AsyncSession, case: SubmissionCase, *, transport: Transport = None) -> SubmissionCase:
    """Read a sent case's status at most once a minute; the service's own 404 means the case expired there."""
    case = await _locked(db, case)
    floor = case.last_status_at and case.last_status_at + POLL_FLOOR
    if case.state not in ("pending", "expired") and not _waiting(case.retry_at, floor):
        case.last_status_at = datetime.now(UTC)
        if reply := await _post(case, "/status", {"contract": "v2", "case_key": case.case_key}, transport):
            code, answer, said = reply
            if code == 404 and said:
                case.state, case.last_error = "expired", None
            elif not (code == 200 and _settled(case, answer)):
                _refused(case, code, said)
    await db.commit()
    return case


async def withdraw(db: AsyncSession, case: SubmissionCase, *, transport: Transport = None) -> SubmissionCase:
    """Withdraw the case there, and clear what was written here. The act is stored before the request leaves,
    so a lost answer can neither keep the words nor leave the case to be sent, and asking again settles it (a
    repeat withdrawal is 200). The service's own 404 means it holds nothing under the key."""
    case = await _locked(db, case)
    _forget(case)
    await db.commit()
    case = await _locked(db, case)
    body = {"contract": "v2", "case_key": case.case_key}
    if case.state != "withdrawn" and (reply := await _post(case, "/withdraw", body, transport)):
        code, answer, said = reply
        if code == 404 and said:
            case.state, case.last_error = "withdrawn", None
        elif not (code == 200 and _settled(case, answer, "withdrawn")):
            _refused(case, code, said)
    await db.commit()
    return case
