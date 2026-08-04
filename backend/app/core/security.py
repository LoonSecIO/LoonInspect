from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# NIST SP 800-63B: length is the control that matters. No composition rules and no
# forced expiry — both push people toward predictable mutations.
MIN_PASSWORD_LENGTH = 12

# Uncapped input to a memory-hard KDF is a cheap denial of service, and the login
# route is unauthenticated, so everything it hashes is attacker-supplied.
MAX_PASSWORD_LENGTH = 128

_hasher = PasswordHasher()

# Verified against whenever no account matches, so a login attempt for an unknown
# address costs the same wall-clock time as one for a real account. Without it,
# response timing is an account enumeration oracle.
_DUMMY_HASH = _hasher.hash("looninspect-timing-equalizer")


class PasswordPolicyError(ValueError):
    """Raised when a proposed password fails the length policy."""


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")


def hash_password(password: str) -> str:
    validate_password(password)
    return _hasher.hash(password)


def verify_password(secret_hash: str | None, password: str) -> bool:
    """Check a password, spending the same effort whether or not the identity exists.

    `secret_hash` is None for an account that has no local password — an SSO-only user
    once OIDC lands. That still burns a verify against the dummy hash rather than
    returning early, so "no password set" is indistinguishable from "wrong password".
    """
    if len(password) > MAX_PASSWORD_LENGTH:
        # Refuse before hashing; this is the DoS guard, not a policy check.
        return False

    try:
        _hasher.verify(secret_hash or _DUMMY_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

    return secret_hash is not None


def generate_token() -> str:
    """A 256-bit URL-safe secret for session cookies and CSRF tokens."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 of a token, for storage.

    Fast on purpose, unlike passwords: these values are 256 bits of CSPRNG output, so
    there is nothing to brute force, and they're verified on every single request. An
    argon2 lookup per request would be a self-inflicted denial of service.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
