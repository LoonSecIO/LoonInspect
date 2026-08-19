"""`EncryptedString` is what keeps MDM credentials encrypted at rest.

Two failure modes are worth catching here specifically. A round-trip that silently
stops encrypting would store credentials in plaintext while every reader still worked.
And a decrypt failure that escaped as `InvalidToken` rather than the wrapped
`RuntimeError` would surface to a caller as an unhandled cryptography exception
instead of the "ENCRYPTION_KEY may have changed" message that tells an operator what
actually went wrong.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.core.crypto import EncryptedString, get_encryption_key, validate_encryption_key

_SECRET = "jamf-api-client-secret-value"


def test_round_trip(encryption_key: str) -> None:
    column = EncryptedString()
    stored = column.process_bind_param(_SECRET, None)

    assert stored != _SECRET, "value was written without being encrypted"
    assert _SECRET not in stored
    assert column.process_result_value(stored, None) == _SECRET


def test_ciphertext_differs_between_writes(encryption_key: str) -> None:
    """Fernet embeds a timestamp and a random IV, so equal plaintexts must not produce
    equal ciphertexts — otherwise the column would leak which connections share a
    credential."""
    column = EncryptedString()
    assert column.process_bind_param(_SECRET, None) != column.process_bind_param(_SECRET, None)


def test_none_passes_through_both_directions(encryption_key: str) -> None:
    column = EncryptedString()
    assert column.process_bind_param(None, None) is None
    assert column.process_result_value(None, None) is None


def test_long_value_round_trips(encryption_key: str) -> None:
    """The bug the TEXT column type exists to prevent.

    A Fernet token is roughly 1.4x the plaintext once base64 and the 57-byte envelope
    are counted, so a 2048-character secret needs about 2830 characters of storage.
    Under a bounded VARCHAR sized against the plaintext, Postgres rejects the longest
    credentials on write with `value too long` — see the `EncryptedString` docstring.
    """
    long_secret = "k" * 2048
    column = EncryptedString()
    stored = column.process_bind_param(long_secret, None)

    assert len(stored) > 2048
    assert column.process_result_value(stored, None) == long_secret


def test_decrypt_under_a_different_key_raises_runtime_error(encryption_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Key rotation without re-encrypting stored rows is the realistic trigger, and
    `crypto.py` notes rotation is an open TODO. The wrapped error is what makes that
    diagnosable."""
    column = EncryptedString()
    stored = column.process_bind_param(_SECRET, None)

    monkeypatch.setattr(settings, "encryption_key", Fernet.generate_key().decode())

    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY may have changed"):
        column.process_result_value(stored, None)


def test_get_encryption_key_without_a_key_raises(no_encryption_key: None) -> None:
    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY is not set"):
        get_encryption_key()


def test_validate_rejects_a_missing_key(no_encryption_key: None) -> None:
    with pytest.raises(RuntimeError, match="missing or not a valid Fernet key"):
        validate_encryption_key()


def test_validate_rejects_a_malformed_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Startup calls this so a bad key fails the boot rather than every later write."""
    monkeypatch.setattr(settings, "encryption_key", "not-a-fernet-key")

    with pytest.raises(RuntimeError, match="missing or not a valid Fernet key"):
        validate_encryption_key()


def test_validate_accepts_a_real_key(encryption_key: str) -> None:
    validate_encryption_key()
