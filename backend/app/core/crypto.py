from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

from app.core.config import settings

# Single static key from ENCRYPTION_KEY for now. Rotating or versioning this key
# (e.g. re-encrypting existing rows under a new key) is a deliberate future TODO.


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
    impl = String
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
            raise RuntimeError("Failed to decrypt stored value — ENCRYPTION_KEY may have changed") from exc
