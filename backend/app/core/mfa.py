"""Time-based one-time passwords on local accounts (#653; docs/auth-design.md §3.1).

A second factor is a second `auth_identities` row, provider `totp`: the secret encrypted at
rest, recovery codes as argon2id hashes, when a code confirmed it, the last accepted step.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

import pyotp

from app.core.crypto import get_encryption_key
from app.models.schema import Account, AuthIdentity

PROVIDER = "totp"
ISSUER = "LoonInspect"
STEP_SECONDS = 30
DIGITS = 6
# How long the password step's challenge stays redeemable: long enough to open the app.
CHALLENGE_TTL_SECONDS = 300
METHOD_TOTP = "password+totp"


def identity_for(account: Account) -> AuthIdentity | None:
    return next((row for row in account.identities if row.provider == PROVIDER), None)


def confirmed(account: Account) -> AuthIdentity | None:
    """The account's TOTP identity, once a code has proved it; an unconfirmed enrolment
    does not change how the account signs in."""
    identity = identity_for(account)
    return identity if identity is not None and identity.confirmed_at is not None else None


def mint_secret() -> str:
    return pyotp.random_base32()


def otpauth_url(secret: str, email: str) -> str:
    return pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS).provisioning_uri(name=email, issuer_name=ISSUER)


def verify_code(secret: str, code: str, last_step: int | None, *, now: datetime | None = None) -> int | None:
    """The 30-second step `code` is valid for, or None. One step either side of now is
    accepted, for a phone's clock; a step at or before the last accepted one is refused,
    so a code is single-use."""
    digits = "".join(ch for ch in code if ch.isdigit())
    if len(digits) != DIGITS or not secret:
        return None
    current = int((now or datetime.now(UTC)).timestamp()) // STEP_SECONDS
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS)
    for step in (current, current - 1, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.at(step * STEP_SECONDS), digits):
            return step
    return None


def _challenge_key() -> bytes:
    return hashlib.sha256(b"looninspect.mfa-challenge:" + get_encryption_key()).digest()


def challenge_token(account_id: str, *, now: datetime | None = None) -> str:
    """What the password step hands back instead of a session: account, expiry, and an HMAC
    over both under a key derived from ENCRYPTION_KEY. Stateless and single-purpose."""
    expires = int((now or datetime.now(UTC)).timestamp()) + CHALLENGE_TTL_SECONDS
    message = f"{account_id}.{expires}"
    return f"{message}.{hmac.new(_challenge_key(), message.encode(), hashlib.sha256).hexdigest()}"


def challenge_account_id(token: str, *, now: datetime | None = None) -> str | None:
    """The account a challenge names, or None when it is forged, damaged or expired."""
    account_id, _, rest = token.partition(".")
    expires, _, signature = rest.partition(".")
    if not account_id or not expires.isdigit() or not signature:
        return None
    expected = hmac.new(_challenge_key(), f"{account_id}.{expires}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    if int(expires) <= int((now or datetime.now(UTC)).timestamp()):
        return None
    return account_id
