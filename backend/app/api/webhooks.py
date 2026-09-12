from __future__ import annotations

import base64
import logging
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import generate_token, tokens_equal
from app.mdm.service import ingest_webhook
from app.models.schema import MdmConnection

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Compared against whenever there is no configured secret to compare with, so that a
# request naming a nonexistent connection costs the same comparison as one naming a
# real connection with the wrong secret. Same reasoning as `_DUMMY_HASH` in
# app.core.security: without it, the compare is skipped entirely in one branch and
# response timing becomes a connection-enumeration oracle.
_DUMMY_SECRET = generate_token()

# Why a webhook was refused, in the operator's words. Every one of these answers the
# caller with the same 401 (docs/auth-design.md §4.7) — the difference would enumerate
# connection ids — so the reason goes to the container log and nowhere else. The log is
# the surface a refused webhook has: it happens before any run exists to write to
# (docs/diagnosability.md §4). Each sentence names the next check (rule 2), and
# docs/troubleshooting.md §7 walks them.
REJECTIONS: dict[str, str] = {
    "unknown_connection": (
        "no connection has this id. The address in Jamf Pro must be the one shown under Set up "
        "on the connection's Webhook collection (Settings › Connections)"
    ),
    "connection_inactive": (
        "the connection is inactive, and an inactive connection refuses every webhook. Settings › Connections shows its status"
    ),
    "receiving_off": (
        "receiving webhooks is off for this connection. Turn it on under Set up on the "
        "connection's Webhook collection (Settings › Connections)"
    ),
    "no_secret_set": (
        "the connection has no webhook secret, so every webhook is refused. Generate one under "
        "Set up on the connection's Webhook collection, then paste the header it shows into each "
        "Jamf Pro webhook"
    ),
    "no_header": (
        "the request carried no X-API-Key header. In Jamf Pro, set the webhook's Authentication "
        "Type to Header Authentication and paste the header from Set up exactly as it is shown"
    ),
    "wrong_secret": (
        "the secret the request carried is not this connection's. Jamf Pro holds an old header "
        "(the secret was rotated) or another connection's: paste the current header into each "
        "Jamf Pro webhook, or Rotate under Set up and paste the new one"
    ),
}


def extract_presented_secret(api_key: str | None, authorization: str | None) -> str | None:
    """Pull the shared secret out of the request headers.

    `X-API-Key` is the primary scheme and the one `docs/auth-design.md` §4.7 specifies.
    Jamf Pro's Header Authentication takes a JSON object of header names to values, so
    what an admin pastes there is `{"X-API-Key": "<secret>"}` — the object the setup
    panel under the connection's Webhook collection shows, once, when the secret is set
    (#406).

    `Authorization` is accepted as a fallback for senders configured with Basic auth
    instead — `Basic base64(user:secret)`, username ignored, since what is stored is one
    opaque secret rather than a credential pair. `Bearer` works too, for any sender that
    can set an arbitrary header and for testing by hand. All three paths end at the same
    constant-time comparison.

    The secret deliberately does not travel in the URL path. Jamf webhooks do not sign
    their payloads, so this value is the entire authentication, and a path segment ends
    up in proxy access logs, `Referer` headers, and anything that records a URL.
    """
    if api_key and api_key.strip():
        return api_key.strip()

    if not authorization:
        return None

    scheme, _, value = authorization.partition(" ")
    value = value.strip()
    if not value:
        return None

    match scheme.lower():
        case "bearer":
            return value
        case "basic":
            try:
                decoded = base64.b64decode(value, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return None
            _, separator, password = decoded.partition(":")
            # No colon at all is a malformed Basic credential, not a passwordless one.
            return password if separator else None
        case _:
            return None


def presented_scheme(api_key: str | None, authorization: str | None) -> str:
    """Which credential header a request carried, by name and never by value — the half
    of a rejection that says what Jamf Pro was configured to send. A webhook left on
    Basic authentication, or on a header object naming some other header, is otherwise
    indistinguishable in the log from one sending nothing at all."""
    if api_key and api_key.strip():
        return "x-api-key"
    if authorization and authorization.strip():
        scheme = authorization.strip().partition(" ")[0].lower()
        return f"authorization-{scheme}" if scheme in ("basic", "bearer") else "authorization-other"
    return "none"


def secret_matches(presented: str | None, expected: str | None) -> bool:
    """Constant-time check that fails closed.

    `expected` is None when the connection does not exist, is inactive, has webhooks
    disabled, or simply has no secret configured. Every one of those must be rejected,
    and all four must be indistinguishable from a wrong secret — hence one comparison
    against a dummy rather than an early return.

    Fail-closed on an unconfigured secret is the deliberate part: an operator who has
    not set one gets a webhook endpoint that rejects everything, rather than one that
    accepts everything.
    """
    matched = tokens_equal(presented or "", expected or _DUMMY_SECRET)
    return matched and presented is not None and expected is not None


def rejection_reason(connection: MdmConnection | None, expected: str | None, presented: str | None) -> str:
    """Which of the refusals in `REJECTIONS` this was, checked in the order an operator
    fixes them: this side's settings first, since no header Jamf Pro sends can be right
    before a secret exists to match it.

    Only ever called after `secret_matches` has said no, so the constant-time comparison
    has already run on every path and nothing decided here reaches the caller: the
    response is the same 401 whichever key comes back.
    """
    if connection is None:
        return "unknown_connection"
    if not connection.is_active:
        return "connection_inactive"
    if not connection.capability_webhooks:
        return "receiving_off"
    if not expected:
        return "no_secret_set"
    if presented is None:
        return "no_header"
    return "wrong_secret"


@router.post(
    "/jamf/{connection_id}",
    # The body is parsed by hand, after authentication, so FastAPI no longer infers it;
    # say what it is for the schema's readers.
    openapi_extra={"requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}}},
)
async def jamf_webhook(
    connection_id: int,
    request: Request,
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Ingest one device from a Jamf Pro webhook.

    Authenticated by a per-connection shared secret rather than a signature: Jamf Pro
    does not sign webhook payloads, so there is nothing to verify cryptographically.
    Set the secret under Set up on the connection's Webhook collection, then paste the
    header object it shows — `{"X-API-Key": "<secret>"}` — into the Jamf Pro webhook's
    Header Authentication. Basic authentication with the secret as the password works
    too.

    This authenticates the *caller*, not the payload — see `docs/auth-design.md` §4.7.
    A static header value carries no body integrity and no replay protection, so TLS is
    load-bearing here rather than defence in depth.

    The body is read only once the caller has proved the secret. An unauthenticated
    request is refused before its body is parsed, so a malformed one gets the same 401
    as any other; an authenticated one that is not JSON (a Jamf webhook left on XML)
    gets a 422 that says so.
    """
    connection = await db.get(MdmConnection, connection_id)

    usable = connection is not None and connection.is_active and connection.capability_webhooks
    expected = connection.webhook_secret_encrypted if usable else None
    presented = extract_presented_secret(x_api_key, authorization)

    if not secret_matches(presented, expected):
        # One response for every rejection. An unknown connection id, an inactive one,
        # one without the webhook capability, one with no secret set, and a wrong
        # secret all answer identically — otherwise the difference enumerates valid
        # connection ids, which are small sequential integers. The log says which.
        reason = rejection_reason(connection, expected, presented)
        logger.warning(
            "rejected jamf webhook: %s",
            REJECTIONS[reason],
            extra={
                "connection_id": connection_id,
                "reason": reason,
                "presented": presented_scheme(x_api_key, authorization),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="jamf-webhook"'},
        )

    try:
        payload = await request.json()
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        logger.warning(
            "refused jamf webhook: the body is not a JSON object. In Jamf Pro, set this webhook's content type to JSON",
            extra={"connection_id": connection_id, "content_type": request.headers.get("content-type")},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The webhook body must be a JSON object. In Jamf Pro, set the webhook's content type to JSON.",
        )

    # The payload names a computer; the inventory is fetched by id. Jamf's computer
    # webhooks carry no application list, so normalizing the payload directly would
    # diff an empty inventory against the stored one and report everything removed.
    try:
        result = await ingest_webhook(db, connection, payload)
    except httpx.HTTPError:
        logger.warning(
            "jamf webhook accepted, but reading that computer from Jamf Pro failed. The "
            "traceback's last line names the status and the address: on /api/oauth/token it is the "
            "connection's credentials or base URL (Test connection checks both); 403 is the API "
            'Role, which needs "Read Computers" (README §3); 404 on the computer is one deleted '
            "since the event; a timeout or connection error is Jamf Pro unreachable from this container",
            extra={"connection_id": connection_id},
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Inventory fetch from Jamf Pro failed",
        ) from None

    if result is None:
        return {"status": "ignored"}
    return {"status": "accepted", "outcome": result.outcome}
