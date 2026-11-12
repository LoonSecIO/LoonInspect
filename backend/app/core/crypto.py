from __future__ import annotations

from typing import Literal

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from app.core.config import settings

# One key, from ENCRYPTION_KEY, and the envelope says which one: every value written here is
# `k1:` and then the Fernet token. A rotation (#144) is a second key for a while, not a second
# key id: ENCRYPTION_KEY_PREVIOUS holds the key the database was written under, every value
# opens under either, and startup rewrites the ones still under the old key (app.core.rekey)
# until none remain and the operator unsets it. The id stays `k1` through all of that on
# purpose — an older image, which knows one key and one id, reads a rewritten row like any
# other, so the one-step-back rollback holds once the rewrite has finished. The id is still
# what keeps a *format* change possible later, and a value written before the prefix existed
# is a `k1` value and is read as such — no migration, no backfill; a row restamps itself the
# next time something writes it, and never has to.
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

_GENERATE = 'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'

# The two ways a rotation can be set up wrong, refused at start rather than discovered at the
# first read (docs/troubleshooting.md §4 quotes both).
PREVIOUS_KEY_MALFORMED = (
    "ENCRYPTION_KEY_PREVIOUS is set but is not a valid Fernet key. It is the key this database was "
    "written under before the rotation (docs/operations.md §1): copy it exactly from where it was "
    "stored, or unset it if no rotation is under way."
)
PREVIOUS_KEY_IS_CURRENT = (
    "ENCRYPTION_KEY_PREVIOUS is the same key as ENCRYPTION_KEY, so there is nothing to rotate to. A "
    "rotation needs a new key in ENCRYPTION_KEY and the key the database was written under in "
    "ENCRYPTION_KEY_PREVIOUS (docs/operations.md §1). Generate the new one with:\n  " + _GENERATE
)


class StoredValueUnreadable(RuntimeError):
    """A Fernet token the configured key cannot open — the shape of every restore that
    brought the dump and not the key (KNOWN_ISSUES.md §5). A RuntimeError still, so a
    caller that handled the old bare one keeps working; a type of its own so the API can
    answer it with a sentence and a 503 rather than a traceback and a bare 500 (#374)."""

    def __init__(self, message: str = STORED_VALUE_UNREADABLE) -> None:
        super().__init__(message)


def _readable_key_id(key_id: str) -> str:
    """What the sentence is allowed to say the key id was.

    The key id is whatever stands before the first colon of a column value, so it is the
    one part of this failure that comes out of the database — and it goes straight into a
    503 body and a log line. A corrupt or hostile row would otherwise put a megabyte, a
    newline, or terminal control characters into both. A key id is short and plain by
    construction (`k1`), so anything else is spelled `?`, and anything past 16 characters
    is dropped: enough to read `k2` back, never enough to fill a log."""
    if not key_id:
        return "(empty)"
    shown = "".join(c if c.isascii() and (c.isalnum() or c in "._-") else "?" for c in key_id[:16])
    return f"{shown}…" if len(key_id) > 16 else shown


class StoredValueUnknownKeyId(StoredValueUnreadable):
    """An envelope written under a key id this build does not know. A
    `StoredValueUnreadable` still, so the 503 and the once-per-process log line hold; its
    own sentence, because the fix is the image and not the key."""

    def __init__(self, key_id: str) -> None:
        super().__init__(STORED_VALUE_UNKNOWN_KEY_ID.format(key_id=_readable_key_id(key_id)))


def get_encryption_key() -> bytes:
    if not settings.encryption_key:
        raise RuntimeError(f"ENCRYPTION_KEY is not set. Generate one with:\n  {_GENERATE}")
    return settings.encryption_key.encode()


def get_previous_encryption_key() -> bytes | None:
    """The key a rotation is moving away from, or None outside one. Compose passes an unset
    optional setting as the empty string, and empty means unset here."""
    if not settings.encryption_key_previous:
        return None
    return settings.encryption_key_previous.encode()


def validate_encryption_key() -> None:
    try:
        Fernet(get_encryption_key())
    except (ValueError, RuntimeError) as exc:
        raise RuntimeError(f"ENCRYPTION_KEY is missing or not a valid Fernet key. Generate one with:\n  {_GENERATE}") from exc
    previous = get_previous_encryption_key()
    if previous is None:
        return
    try:
        Fernet(previous)
    except ValueError as exc:
        raise RuntimeError(PREVIOUS_KEY_MALFORMED) from exc
    if previous == get_encryption_key():
        raise RuntimeError(PREVIOUS_KEY_IS_CURRENT)


def encrypt_value(plaintext: str) -> str:
    """The column value for a secret: the key id, a colon, and the token under the current key."""
    return f"{KEY_ID}:{Fernet(get_encryption_key()).encrypt(plaintext.encode()).decode()}"


def open_stored(value: str) -> tuple[str, Literal["current", "previous"]]:
    """A column value back to its secret, and which key opened it.

    A Fernet token is urlsafe base64 — `A-Z a-z 0-9 - _ =`, no colon — so a value written
    before the prefix existed can never be read as a prefixed one, and a prefixed one can
    never be mistaken for a token. Split on the first colon. During a rotation the previous
    key is tried after the current one; the second item is what `app.core.rekey` reads to know
    which rows still need rewriting."""
    key_id, _, token = value.partition(":")
    if not token:
        key_id, token = KEY_ID, value
    if key_id != KEY_ID:
        raise StoredValueUnknownKeyId(key_id)
    try:
        return Fernet(get_encryption_key()).decrypt(token.encode()).decode(), "current"
    except InvalidToken as exc:
        previous = get_previous_encryption_key()
        if previous is None:
            raise StoredValueUnreadable() from exc
    try:
        return Fernet(previous).decrypt(token.encode()).decode(), "previous"
    except InvalidToken as exc:
        raise StoredValueUnreadable() from exc


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
        return encrypt_value(value)

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        return open_stored(value)[0]
