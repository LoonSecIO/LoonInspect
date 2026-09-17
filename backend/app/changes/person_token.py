"""The assigned person as a token, for the one surface that travels (#446, R13 option a).

A change row's stamp holds the person's `username`, `realName` and `email` so the feed can be
filtered by them (#447) — and a filter value goes in the URL an operator pastes into Slack, so it
travels as `userToken`, an opaque `u_…` reading back as the same person within a tenant and
saying nothing outside it. Not a wire change: `userAndLocation` ships the names by design
(#188)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import unicodedata
import uuid
from collections.abc import Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.crypto import get_encryption_key

# Recognisable at a glance in a URL, the argument `app.core.tokens` makes for `loon_pat_`, over
# 96 bits of the HMAC. U+001F joins the field name to its value, so a username equal to someone
# else's email is not the same person (`app.core.content_keys` namespaces its domains so).
TOKEN_PREFIX = "u_"
TOKEN_CHARS = 16
_TOKEN_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_SEPARATOR = "\x1f"
_INFO = b"looninspect/change-feed/person-token/v1/"
_IDENTITY_FIELDS = ("username", "email", "realName")


def canonical_identity(stamp: Mapping[str, object]) -> str | None:
    """The one string standing for the person, or None when none is assigned.

    **The rule: the `username` if there is one, else the lower-cased `email`, else `realName`**
    (R15 option b, 2026-09-17). The username decides because in Jamf's User and Location section
    the username *is* the assignment: real name, email, position and phone are attributes the
    directory lookup fills in from it or an admin types, so an org with no directory integration
    has usernames and no emails — and email-first made one such person two tokens across two Macs
    with nothing on screen saying so. A username rename becomes a new token, which is the same
    re-keying Jamf itself does. The email is still lower-cased, its case not being significant
    where Jamf's copy and the IdP's disagree. All three NFC-normalised and stripped, each tagged
    with the field that answered so two people cannot collide across them."""
    for field in _IDENTITY_FIELDS:
        value = stamp.get(field)
        if isinstance(value, str) and (name := unicodedata.normalize("NFC", value).strip().replace(_SEPARATOR, "")):
            return field + _SEPARATOR + (name.lower() if field == "email" else name)
    return None


def person_token(stamp: Mapping[str, object], *, tenant_id: uuid.UUID | None) -> str | None:
    """`u_…` for the person this stamp names: stable within a tenant, different across tenants.

    Keyed, not merely hashed, since a bare hash of a mail address falls to a name list: an HMAC
    under a key derived per call from `ENCRYPTION_KEY` for one tenant and never written down, so
    there is no second secret. A row is stamped once and never rewritten, so rotating that key
    changes only the tokens on rows written after it (#541): a link made before the rotation keeps
    filtering over the rows from before it. None with no person, and none with no tenant to key it
    to — an unkeyed token is the guessable hash this replaced."""
    identity = canonical_identity(stamp)
    if identity is None or tenant_id is None:
        return None
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO + str(tenant_id).encode()).derive(get_encryption_key())
    digest = hmac.new(key, identity.encode("utf-8"), hashlib.sha256).digest()
    return TOKEN_PREFIX + base64.urlsafe_b64encode(digest).decode().rstrip("=")[:TOKEN_CHARS]


def is_person_token(value: str) -> bool:
    """Whether a `user=` value is one of ours rather than text someone typed. Strict on length
    and alphabet, so a name is never read as a token and answered with an empty exact match."""
    body = value[len(TOKEN_PREFIX) :] if value.startswith(TOKEN_PREFIX) else ""
    return len(body) == TOKEN_CHARS and all(char in _TOKEN_ALPHABET for char in body)
