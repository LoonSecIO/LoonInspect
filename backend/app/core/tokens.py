from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass

# Recognisable at a glance in a log, a config file, or a leaked gist — which is the
# point. A token that looks like generic base64 is one nobody reports.
TOKEN_PREFIX = "loon_pat_"


@dataclass(frozen=True, slots=True)
class NewToken:
    token_id: str
    secret: str
    raw: str


@dataclass(frozen=True, slots=True)
class ParsedToken:
    token_id: str
    secret: str


def generate_token() -> NewToken:
    """Mint a token. The raw value exists only in this return — only the secret's hash
    is ever stored, so it cannot be shown again."""
    token_id = uuid.uuid4().hex
    secret = secrets.token_urlsafe(32)
    return NewToken(token_id=token_id, secret=secret, raw=f"{TOKEN_PREFIX}{token_id}_{secret}")


def parse_token(raw: str) -> ParsedToken | None:
    """Split a presented token into its lookup id and secret.

    Returns None for anything malformed rather than raising, since this runs on
    attacker-supplied input on every request.

    The secret half is base64url and may itself contain underscores, so the split is
    on the *first* underscore after the prefix — the id is pure hex and can't contain
    one.
    """
    if not raw.startswith(TOKEN_PREFIX):
        return None

    token_id, separator, secret = raw[len(TOKEN_PREFIX) :].partition("_")
    if not separator or not token_id or not secret:
        return None

    # The id is a lookup key that goes straight into a query; constrain it to what
    # generate_token() actually produces.
    if len(token_id) != 32 or not all(char in "0123456789abcdef" for char in token_id):
        return None

    return ParsedToken(token_id=token_id, secret=secret)
