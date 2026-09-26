"""Time-based one-time passwords on local accounts (#653; docs/auth-design.md §3.1).

A second factor is a second `auth_identities` row, provider `totp`: the secret encrypted at
rest, recovery codes as argon2id hashes, when a code confirmed it, the last accepted step.
The tenant's `Policy` says whose sign-in must end in one.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from collections.abc import Collection
from datetime import UTC, datetime
from typing import Literal

import pyotp
from argon2 import PasswordHasher
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import get_encryption_key
from app.core.permissions import Role
from app.core.security import verify_password
from app.models.schema import Account, AuthIdentity, Tenant

PROVIDER = "totp"
ISSUER = "LoonInspect"
STEP_SECONDS = 30
DIGITS = 6
# How long the password step's challenge stays redeemable: long enough to open the app.
CHALLENGE_TTL_SECONDS = 300
RECOVERY_CODES = 10
METHOD_TOTP = "password+totp"
METHOD_RECOVERY = "password+recovery"
# `tenants.mfa_required`: who must hold a second factor. Break-glass accounts are exempt from all three.
Policy = Literal["off", "admins", "everyone"]
# What a recovery code is spelled from: lowercase, no 0/o or 1/l/i to misread over a call.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
# Hashed like passwords, but not passwords: eleven characters from a 31-letter alphabet is
# 49 bits, and the policy floor that guards a chosen password does not apply to a minted one.
_hasher = PasswordHasher()


def identity_for(account: Account) -> AuthIdentity | None:
    return next((row for row in account.identities if row.provider == PROVIDER), None)


def confirmed(account: Account) -> AuthIdentity | None:
    """The account's TOTP identity, once a code has proved it; an unconfirmed enrolment
    does not change how the account signs in."""
    identity = identity_for(account)
    return identity if identity is not None and identity.confirmed_at is not None else None


async def policy_asks(db: AsyncSession, roles: Collection[str], tenant_id: uuid.UUID) -> bool:
    """Whether `tenant_id`'s policy asks holders of `roles` for a second factor (`tenants` is outside RLS)."""
    tenant = await db.get(Tenant, tenant_id)
    policy = tenant.mfa_required if tenant is not None else "off"
    return policy == "everyone" or (policy == "admins" and Role.admin.value in roles)


async def enrolment_required(db: AsyncSession, account: Account, roles: Collection[str], tenant_id: uuid.UUID) -> bool:
    """The gate's question: the policy asks and nothing confirmed answers. Break-glass is the way back in, so exempt."""
    if account.is_break_glass or confirmed(account) is not None:
        return False
    return await policy_asks(db, roles, tenant_id)


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


def mint_recovery_codes() -> tuple[list[str], list[str]]:
    """Ten codes and their argon2id hashes. The codes are shown once; only the hashes are stored."""
    codes = ["".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10)) for _ in range(RECOVERY_CODES)]
    codes = [f"{code[:5]}-{code[5:]}" for code in codes]
    return codes, [_hasher.hash(code) for code in codes]


def consume_recovery_code(identity: AuthIdentity, code: str) -> bool:
    """Spend one recovery code. Hyphens, spaces and case are forgiven; a code works once."""
    given = code.strip().lower().replace("-", "").replace(" ", "")
    if len(given) != 10:
        return False
    given = f"{given[:5]}-{given[5:]}"
    remaining = list(identity.recovery_codes or [])
    for index, stored in enumerate(remaining):
        if verify_password(stored, given):
            del remaining[index]
            identity.recovery_codes = remaining
            return True
    return False


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
