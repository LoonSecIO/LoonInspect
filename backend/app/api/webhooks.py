from __future__ import annotations

import base64
import logging
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, status
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


def extract_presented_secret(api_key: str | None, authorization: str | None) -> str | None:
    """Pull the shared secret out of the request headers.

    `X-API-Key` is the primary scheme and the one `docs/auth-design.md` §4.7 specifies:
    Jamf Pro supports Header Authentication natively, so an admin pastes the value in
    as a header name and static value.

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


@router.post("/jamf/{connection_id}")
async def jamf_webhook(
    connection_id: int,
    payload: dict,
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Ingest one device from a Jamf Pro webhook.

    Authenticated by a per-connection shared secret rather than a signature: Jamf Pro
    does not sign webhook payloads, so there is nothing to verify cryptographically.
    Set the secret on the connection, then configure the same value in Jamf Pro as the
    webhook's `X-API-Key` header (or as its Basic authentication password).

    This authenticates the *caller*, not the payload — see `docs/auth-design.md` §4.7.
    A static header value carries no body integrity and no replay protection, so TLS is
    load-bearing here rather than defence in depth.
    """
    connection = await db.get(MdmConnection, connection_id)

    usable = connection is not None and connection.is_active and connection.capability_webhooks
    expected = connection.webhook_secret_encrypted if usable else None

    if not secret_matches(extract_presented_secret(x_api_key, authorization), expected):
        # One response for every rejection. An unknown connection id, an inactive one,
        # one without the webhook capability, one with no secret set, and a wrong
        # secret all answer identically — otherwise the difference enumerates valid
        # connection ids, which are small sequential integers.
        logger.warning(
            "rejected unauthenticated jamf webhook",
            extra={"connection_id": connection_id},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="jamf-webhook"'},
        )

    # The payload names a computer; the inventory is fetched by id. Jamf's computer
    # webhooks carry no application list, so normalizing the payload directly would
    # diff an empty inventory against the stored one and report everything removed.
    try:
        result = await ingest_webhook(db, connection, payload)
    except httpx.HTTPError:
        logger.warning(
            "jamf webhook accepted but the inventory fetch failed",
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
