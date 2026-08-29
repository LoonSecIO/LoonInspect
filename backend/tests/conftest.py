"""Shared fixtures.

Deliberately has no database fixture. #11 originally scoped one as "an in-memory
SQLite session fixture", which #29 made impossible: `Settings._require_asyncpg`
rejects any non-`postgresql+asyncpg://` URL outright (`config.py`), and the schema
carries `JSONB` columns SQLite cannot express at all. Everything wired here serves
the pure-logic lane, which needs no session. The DB-backed tests exist now — the
files gated on `RUN_DB_TESTS` bring their own session fixtures against a real
Postgres (a `services:` container in CI) — and they deliberately keep those fixtures
local rather than hoisting them here, so importing this file never implies a
database.

Nothing here touches `app.core.database.engine`. `create_async_engine` is lazy, so
importing the modules under test never opens a connection; that is what keeps this
suite runnable with no database present.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings


@pytest.fixture
def encryption_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """A valid Fernet key installed on the live settings object.

    `get_encryption_key()` reads `settings.encryption_key` on every call rather than
    caching it at import, so patching the attribute is sufficient and needs no reload.
    """
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "encryption_key", key)
    return key


@pytest.fixture
def no_encryption_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicitly unset the key.

    Not a no-op: `Settings` reads `backend/.env` if one exists, so a developer with
    `ENCRYPTION_KEY` set locally would otherwise see the missing-key tests fail while
    CI passed. Asserting the absence rather than assuming it keeps the two identical.
    """
    monkeypatch.setattr(settings, "encryption_key", None)
