"""Contribution receipts for the community exchange (#622).

The contract is Support's `docs/contracts/participation.md`. Default off: receipts need
`CONTRIBUTION_RECEIPTS=true` plus the two v2 corpus flags that paid access also needs.
When on, a consenting exchange asks for a receipt with the literal
`"participation_receipt": true`, and the receipt an accepted contribution earns is stored
encrypted on the tenant's consent row. It never reaches the share log, a log line, or a
response to the browser.

Consent is local first. Turning sharing off (or resetting the submission UUID) stops
uploads at once and marks the held receipt for withdrawal, and the scheduler withdraws it
within a tick. An upload waits until that withdrawal is acknowledged, so a withdrawal that
arrives late can never cancel the receipt a later re-consent earns: the contract's
serialization rule. Redeeming a receipt for an inventory-free corpus retry is the next
slice; this one earns, keeps and withdraws them.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.version import get_app_version
from app.models.schema import DataSharingSettings

logger = logging.getLogger(__name__)

# 256 random bits, URL-safe base64 (Support mints `loon_rcpt_` + token_urlsafe(32)).
RECEIPT = re.compile(r"loon_rcpt_[A-Za-z0-9_-]{43}")
# The scheduler ticks every five minutes; an unacknowledged withdrawal is retried at most
# this often from the tick. Send now always tries at once.
WITHDRAWAL_RETRY = timedelta(minutes=10)

HELD = (
    "Upload held: sharing was switched off earlier, and the service that issued this instance's contribution "
    "receipt has not yet acknowledged withdrawing it. Nothing left this instance. The withdrawal is retried first "
    "on every attempt, and the Data sharing status (participation.error) says why it has not landed. See "
    'docs/troubleshooting.md, "Contribution receipts".'
)


class Unresolved(Exception):
    """A withdrawal attempt that did not settle anything; the message is operator text."""


def enabled() -> bool:
    return settings.contribution_receipts and settings.vuln_tenant_selection and settings.vuln_release_retention


def service_origin() -> str | None:
    """The origin of the service the exchange talks to, which is the service that issues
    receipts. None when that address could not safely carry a bearer."""
    parsed = urlsplit(settings.sharing_endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return f"https://{parsed.netloc}"


def _stamp(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp missing")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timezone missing")
    return parsed.astimezone(UTC)


def pending(row: DataSharingSettings) -> bool:
    return (row.participation_status or {}).get("state") == "withdrawal_pending"


def opt_in(row: DataSharingSettings, request_body: dict) -> None:
    """Ask for a receipt only when receipts are on, the service address can carry a
    bearer, and nothing is waiting to be withdrawn."""
    if enabled() and service_origin() and not pending(row):
        request_body["participation_receipt"] = True


def parse(response: dict) -> dict | None:
    """The receipt block of an accepted exchange, validated, or None. Never logs the
    receipt: a malformed block is reported by its shape only."""
    block = response.get("participation") if isinstance(response, dict) else None
    if block is None:
        return None
    try:
        receipt = block["receipt"]
        accepted, until = _stamp(block["accepted_at"]), _stamp(block["updates_until"])
        if not isinstance(receipt, str) or not RECEIPT.fullmatch(receipt) or until <= accepted:
            raise ValueError("receipt block")
    except (KeyError, TypeError, ValueError):
        logger.warning(
            "contribution receipt ignored",
            extra={
                "detail": "The exchange was accepted, but its receipt block does not match the participation contract, "
                "so any receipt already held stays in use. Contact support if this repeats; nothing needs "
                "to be done here (docs/troubleshooting.md, Contribution receipts)."
            },
        )
        return None
    return {"receipt": receipt, "accepted_at": accepted.isoformat(), "updates_until": until.isoformat()}


async def locked_row(db: AsyncSession) -> DataSharingSettings:
    """The tenant's consent row, locked until the caller commits. The row must exist."""
    return (
        await db.execute(select(DataSharingSettings).with_for_update().execution_options(populate_existing=True))
    ).scalar_one()


def mark_withdrawal(row: DataSharingSettings) -> None:
    """Consent just ended here, or the submission identity was reset: stop using the held
    receipt now and withdraw it next. Call with the row locked."""
    status = dict(row.participation_status or {})
    if row.participation_receipt is None or status.get("state") == "withdrawal_pending":
        return
    now = datetime.now(UTC)
    try:
        ended = _stamp(status.get("updates_until")) <= now
    except ValueError:
        ended = False
    if ended:
        # Its eligibility is over, so the service would refuse to withdraw with it anyway.
        row.participation_receipt = None
        row.participation_status = {**status, "state": "ended", "error": None}
        return
    row.participation_status = {
        **status,
        "state": "withdrawal_pending",
        "withdrawal_requested_at": now.isoformat(),
        "error": None,
    }


async def after_exchange(db: AsyncSession, block: dict | None) -> None:
    """Keep the newest receipt an accepted exchange earned, and make sure a receipt held
    after consent ended is marked for withdrawal.

    Consent can change while an exchange is in flight, so this re-reads the row under a
    lock. Autoflush writes the caller's own unsaved changes (a server revoke, the reveal
    list) before the read, so reloading the row loses none of them. The lock is held until
    the caller commits the day's share-log row.
    """
    row = await locked_row(db)
    tier, status = row.tier, dict(row.participation_status or {})
    if block is not None:
        # The newest receipt is always the one to keep: it can withdraw every older one.
        row.participation_receipt = block["receipt"]
        base = {
            "accepted_at": block["accepted_at"],
            "updates_until": block["updates_until"],
            "service": service_origin(),
            "error": None,
        }
        if tier == "off" or status.get("state") == "withdrawal_pending":
            # Consent ended while this exchange was in flight: withdraw the new receipt too.
            row.participation_status = {
                **status,
                **base,
                "state": "withdrawal_pending",
                "withdrawal_requested_at": status.get("withdrawal_requested_at") or datetime.now(UTC).isoformat(),
            }
        else:
            row.participation_status = {**base, "state": "contributing"}
    elif tier == "off":
        # A server revoke (apply_response) turned consent off: withdraw what is held.
        mark_withdrawal(row)


async def withdrawal_due(db: AsyncSession) -> bool:
    row = (await db.execute(select(DataSharingSettings))).scalar_one_or_none()
    if row is None or not pending(row):
        return False
    last = (row.participation_status or {}).get("last_withdrawal_attempt_at")
    try:
        return datetime.now(UTC) - _stamp(last) >= WITHDRAWAL_RETRY
    except ValueError:
        return True


async def _post_withdrawal(origin: str, receipt: str, transport: httpx.AsyncBaseTransport | None) -> str:
    """One withdrawal request. Returns "withdrawn", or "ended" when the service no longer
    knows the receipt as a live one; raises Unresolved with the operator's sentence."""
    url = origin.rstrip("/") + "/v2/contribution/withdraw"
    body = {"contract": "v2", "client_version": get_app_version()}
    try:
        async with (
            httpx.AsyncClient(transport=transport, timeout=10, follow_redirects=False, trust_env=False) as client,
            client.stream("POST", url, json=body, headers={"Authorization": f"Bearer {receipt}"}) as response,
        ):
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 65536:
                    raise Unresolved(
                        f"{origin} answered the withdrawal with an oversized reply. Retry; contact support if it repeats."
                    )
            code = response.status_code
    except httpx.HTTPError:
        raise Unresolved(
            f"Could not reach {origin} to withdraw. Check DNS and network access; the withdrawal is retried "
            "automatically, and uploads stay held until it is acknowledged."
        ) from None
    try:
        answer = json.loads(raw)
    except ValueError:
        answer = None
    state = answer.get("state") if isinstance(answer, dict) else None
    if code == 200 and state == "withdrawn":
        return "withdrawn"
    if code == 401 or (code == 403 and state == "expired"):
        # Unknown or past its deadline: there is nothing left that this receipt can
        # authorize or withdraw. The contract bounds every older receipt the same way.
        return "ended"
    if code == 404 or (code == 403 and state is None):
        raise Unresolved(
            f"No contribution-receipt service answers at {origin} (HTTP {code}). The receipt was issued by that "
            "service; if its address moved, contact support. Uploads stay held until the withdrawal is acknowledged."
        )
    if code == 409:
        raise Unresolved(f"{origin} reported a concurrent change (HTTP 409). The withdrawal is retried automatically.")
    if code == 400:
        raise Unresolved(
            f"{origin} rejected the withdrawal request as outside its contract (HTTP 400). Check that this LoonInspect "
            "build is current, then contact support."
        )
    raise Unresolved(
        f"{origin} could not withdraw right now (HTTP {code}); its receipt preview may be switched off or its store "
        "unavailable. The withdrawal is retried automatically, and uploads stay held until it is acknowledged."
    )


async def withdraw(db: AsyncSession, *, transport: httpx.AsyncBaseTransport | None = None) -> bool:
    """One withdrawal attempt, never holding the row lock across the network. Returns
    True once nothing is waiting to be withdrawn."""
    row = await locked_row(db)
    status = dict(row.participation_status or {})
    receipt = row.participation_receipt
    if status.get("state") != "withdrawal_pending":
        await db.commit()
        return True
    if receipt is None:
        row.participation_status = {**status, "state": "withdrawn", "error": None}
        await db.commit()
        return True
    origin = status.get("service") or service_origin()
    row.participation_status = {**status, "last_withdrawal_attempt_at": datetime.now(UTC).isoformat()}
    await db.commit()
    try:
        if origin is None:
            raise Unresolved(
                "The receipt's service address is not HTTPS, so the receipt cannot be sent to withdraw it. Check "
                "SHARING_ENDPOINT; uploads stay held until the withdrawal is acknowledged."
            )
        outcome = await _post_withdrawal(origin, receipt, transport)
    except Unresolved as exc:
        row = await locked_row(db)
        row.participation_status = {**(row.participation_status or {}), "error": str(exc)}
        await db.commit()
        logger.warning("contribution withdrawal not acknowledged", extra={"detail": str(exc)})
        return False
    row = await locked_row(db)
    if row.participation_receipt != receipt:
        # A newer receipt arrived while this one was being withdrawn (an exchange that was
        # already in flight). It may belong to a later generation: withdraw it as well.
        await db.commit()
        return False
    now = datetime.now(UTC).isoformat()
    row.participation_receipt = None
    row.participation_status = {
        **(row.participation_status or {}),
        "state": "withdrawn",
        "withdrawn_at": now,
        "withdrawal_outcome": outcome,
        "error": None,
    }
    await db.commit()
    logger.info("contribution receipts withdrawn", extra={"outcome": outcome})
    return True


def summary(row: DataSharingSettings) -> dict:
    """What the Data sharing page may know: presence and dates, never the receipt."""
    status = row.participation_status or {}
    return {
        "enabled": enabled(),
        "receipt_present": row.participation_receipt is not None,
        "state": status.get("state") or "none",
        "accepted_at": status.get("accepted_at"),
        "updates_until": status.get("updates_until"),
        "withdrawal_requested_at": status.get("withdrawal_requested_at"),
        "last_withdrawal_attempt_at": status.get("last_withdrawal_attempt_at"),
        "withdrawn_at": status.get("withdrawn_at"),
        "error": status.get("error"),
    }
