from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from app.core.config import settings

# Single static key from ENCRYPTION_KEY for now. Rotating or versioning this key
# (e.g. re-encrypting existing rows under a new key) is a deliberate future TODO.

# What failed, why, and what to check, in the operator's vocabulary (#374,
# docs/diagnosability.md rule 3). It is the request's `detail`, the one log line, and
# the sentence docs/troubleshooting.md §4 quotes — so it lives here, once.
STORED_VALUE_UNREADABLE = (
    "Stored credentials cannot be read: the ENCRYPTION_KEY in the environment is not the one "
    "this database was written under. Restore the original key (docs/operations.md §1), or "
    "re-enter each connection's and destination's secret (KNOWN_ISSUES.md §5)."
)


class StoredValueUnreadable(RuntimeError):
    """A Fernet token the configured key cannot open — the shape of every restore that
    brought the dump and not the key (KNOWN_ISSUES.md §5). A RuntimeError still, so a
    caller that handled the old bare one keeps working; a type of its own so the API can
    answer it with a sentence and a 503 rather than a traceback and a bare 500 (#374)."""

    def __init__(self) -> None:
        super().__init__(STORED_VALUE_UNREADABLE)


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
    lands in the column is a Fernet token — base64 of a 57-byte envelope plus the
    plaintext padded to the AES block size — so a 2048-character secret needs about
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
        return Fernet(get_encryption_key()).encrypt(value.encode()).decode()

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        try:
            return Fernet(get_encryption_key()).decrypt(value.encode()).decode()
        except InvalidToken as exc:
            raise StoredValueUnreadable() from exc
