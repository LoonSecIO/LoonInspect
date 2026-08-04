from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic.alias_generators import to_camel

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"

# Depth guard so a pathological or cyclic-looking structure can't turn one log line
# into an unbounded walk.
_MAX_DEPTH = 8

# Substrings that mark a key as sensitive regardless of which provider it came from.
#
# Deliberately does NOT include a bare "key": DeviceExtensionAttribute rows are
# literally {"key": ..., "value": ...} pairs, and redacting on "key" would blank out
# ordinary inventory data while teaching everyone to ignore [REDACTED].
_SECRET_KEY_TOKENS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "api_key",
        "apikey",
        "authorization",
        "private_key",
        "license_key",
        "cookie",
        "session_id",
    }
)


@lru_cache(maxsize=1)
def _schema_secret_fields() -> frozenset[str]:
    """Field names each MDM provider marks `secret: True`, in both snake_case and the
    camelCase alias used on the wire.

    Derived from CREDENTIAL_SCHEMAS rather than hardcoded so a provider added later is
    covered without anyone remembering to update this module. Imported lazily because
    app.mdm.credentials pulls in the schema package, and this module is imported by the
    logging setup that runs before most of the app exists.
    """
    from app.mdm.credentials import CREDENTIAL_SCHEMAS

    names: set[str] = set()
    for schema in CREDENTIAL_SCHEMAS.values():
        for name, field in schema.model_fields.items():
            extra = field.json_schema_extra if isinstance(field.json_schema_extra, dict) else {}
            if extra.get("secret"):
                names.add(name.lower())
                names.add((field.alias or to_camel(name)).lower())
    return frozenset(names)


def is_secret_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _schema_secret_fields():
        return True
    return any(token in lowered for token in _SECRET_KEY_TOKENS)


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively replace values under sensitive keys with a placeholder.

    Matching is on key names, never on value shape — guessing at "this looks like a
    secret" produces false positives on real inventory data and false negatives on
    anything unusual.
    """
    if _depth >= _MAX_DEPTH:
        return TRUNCATED

    if isinstance(value, dict):
        return {
            key: REDACTED if isinstance(key, str) and is_secret_key(key) else redact(item, _depth + 1)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [redact(item, _depth + 1) for item in value]

    return value
