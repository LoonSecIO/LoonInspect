from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from app.core.config import settings

# One key, from ENCRYPTION_KEY, and now the envelope says which one: every value written
# here is `k1:` and then the Fernet token. The prefix is not rotation; it is what keeps
# rotation possible. A rekey (#144) can read which key wrote a row out of the row itself,
# instead of a side table, a flag column, or a stop-the-world re-encrypt of values only
# the right key can open. `k1` is the only key id this build knows, and
# `get_encryption_key()` is still the only place the key comes from. Values written before
# the prefix existed are `k1` values and are read as such — no migration, no backfill; a
# row restamps itself the next time something writes it, and never has to.
KEY_ID = "k1"

# What failed, why, and what to check, in the operator's vocabulary (#374,
# docs/diagnosability.md rule 3). It is the request's `detail`, the one log line, and
# the sentence docs/troubleshooting.md §4 quotes — so it lives here, once.
STORED_VALUE_UNREADABLE = (
    "Stored credentials cannot be read: the ENCRYPTION_KEY in the environment is not the one "
    "this database was written under. Restore the original key (docs/operations.md §1), or "
    "re-enter each connection's and destination's secret (KNOWN_ISSUES.md §5)."
)


# The other way a stored value can be unreadable, and it deserves its own words: the key
# is fine and the image is old. Answering it with the sentence above would send an
# operator to their secret store for a key that was never the problem.
STORED_VALUE_UNKNOWN_KEY_ID = (
    "Stored credentials cannot be read: this value carries key id {key_id}, which this build does "
    "not know. The running image is older than the database that wrote the value. Roll forward to "
    "the newer image, or restore the dump taken before the upgrade (docs/operations.md §5)."
)


class StoredValueUnreadable(RuntimeError):
    """A Fernet token the configured key cannot open — the shape of every restore that
    brought the dump and not the key (KNOWN_ISSUES.md §5). A RuntimeError still, so a
    caller that handled the old bare one keeps working; a type of its own so the API can
    answer it with a sentence and a 503 rather than a traceback and a bare 500 (#374)."""

    def __init__(self, message: str = STORED_VALUE_UNREADABLE) -> None:
        super().__init__(message)


class StoredValueUnknownKeyId(StoredValueUnreadable):
    """An envelope written under a key id this build does not know. A
    `StoredValueUnreadable` still, so the 503 and the once-per-process log line hold; its
    own sentence, because the fix is the image and not the key."""

    def __init__(self, key_id: str) -> None:
        super().__init__(STORED_VALUE_UNKNOWN_KEY_ID.format(key_id=key_id))


def get_encryption_key() -> bytes:
    if not settings.encryption_key:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Generate one with:\n"
            '  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    return settings.encryption_key.encode()


def validate_encryption_key() -> None:
    try:
        Fernet(get_encryption_key())
    except (ValueError, RuntimeError) as exc:
        raise RuntimeError(
            "ENCRYPTION_KEY is missing or not a valid Fernet key. Generate one with:\n"
            '  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        ) from exc


class EncryptedString(TypeDecorator):
    """Fernet-encrypted at rest, transparent to every reader and writer.

    Stored as TEXT rather than a bounded VARCHAR, and that is not cosmetic. What
    lands in the column is a key id and a Fernet token — `k1:`, then base64 of a
    57-byte envelope plus the plaintext padded to the AES block size — so a
    2048-character secret needs about
    2830 characters of storage. Under SQLite the declared length was decoration
    (VARCHAR(n) is not enforced there), so the columns were sized against the
    plaintext and nothing ever complained. Postgres enforces it, and would have
    started rejecting the longest credential blobs with `value too long` on write.
    TEXT has no length to get wrong and costs nothing: Postgres stores TEXT and
    VARCHAR identically.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        return f"{KEY_ID}:{Fernet(get_encryption_key()).encrypt(value.encode()).decode()}"

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        # A Fernet token is urlsafe base64 — `A-Z a-z 0-9 - _ =`, no colon — so a value
        # written before the prefix existed can never be read as a prefixed one, and a
        # prefixed one can never be mistaken for a token. Split on the first colon.
        key_id, _, token = value.partition(":")
        if not token:
            key_id, token = KEY_ID, value
        if key_id != KEY_ID:
            raise StoredValueUnknownKeyId(key_id)
        try:
            return Fernet(get_encryption_key()).decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise StoredValueUnreadable() from exc
