"""`EncryptedString` is what keeps MDM credentials encrypted at rest.

Two failure modes are worth catching here specifically. A round-trip that silently
stops encrypting would store credentials in plaintext while every reader still worked.
And a decrypt failure that escaped as `InvalidToken` rather than the wrapped
`RuntimeError` would surface to a caller as an unhandled cryptography exception
instead of the "ENCRYPTION_KEY may have changed" message that tells an operator what
actually went wrong.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.core.crypto import EncryptedString, get_encryption_key, validate_encryption_key

_SECRET = "jamf-api-client-secret-value"
_DOCS = Path(__file__).resolve().parents[2] / "docs"


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


def test_a_new_write_carries_the_key_id(encryption_key: str) -> None:
    """#480: the envelope names the key that wrote it, so a later rekey can tell which
    rows are under which key by reading the row."""
    assert EncryptedString().process_bind_param(_SECRET, None).startswith("k1:gAAAAA")


def test_a_legacy_unprefixed_value_still_decrypts(encryption_key: str) -> None:
    """No migration and no backfill: a value written before the prefix existed *is* a `k1`
    value and is read as one. A Fernet token is urlsafe base64, an alphabet with no colon
    in it, so the two spellings can never be confused."""
    legacy = Fernet(get_encryption_key()).encrypt(_SECRET.encode()).decode()

    assert ":" not in legacy
    assert EncryptedString().process_result_value(legacy, None) == _SECRET


def test_an_unknown_key_id_is_refused_in_its_own_words(encryption_key: str) -> None:
    """The day a rollback runs an older image against a newer database. Reading it as `k1`
    anyway would answer with the wrong sentence and send an operator to their secret store
    for a key that was never the problem."""
    from app.core.crypto import STORED_VALUE_UNREADABLE, StoredValueUnknownKeyId

    stored = "k2:" + Fernet(get_encryption_key()).encrypt(_SECRET.encode()).decode()

    with pytest.raises(StoredValueUnknownKeyId, match="older than the database") as caught:
        EncryptedString().process_result_value(stored, None)
    assert "k2" in str(caught.value) and str(caught.value) != STORED_VALUE_UNREADABLE


def test_the_quoted_key_id_is_bounded_and_plain(encryption_key: str) -> None:
    """The key id is the one part of this failure that comes out of the database, and it
    lands in a 503 body and a log line. A corrupt or hostile row must not be able to put a
    megabyte, a newline or terminal control characters into either."""
    from app.core.crypto import STORED_VALUE_UNKNOWN_KEY_ID, StoredValueUnknownKeyId

    hostile = "k\n\x1b[2J" + "9" * 5000
    sentence = str(StoredValueUnknownKeyId(hostile))

    assert len(sentence) < len(STORED_VALUE_UNKNOWN_KEY_ID) + 32
    assert "\n" not in sentence and "\x1b" not in sentence
    assert "key id k???2J9999999999…," in sentence, "the escape sequence survived, or the length did not"
    # An empty key id (a value that opens with a colon) still reads as a sentence.
    assert "(empty)" in str(StoredValueUnknownKeyId(""))


def test_the_unknown_key_id_sentence_has_its_step_through() -> None:
    """`docs/diagnosability.md` rule 4: the words ship with the step-through. Rewording the
    sentence without the document fails here, and so does the reverse."""
    from app.core.crypto import STORED_VALUE_UNKNOWN_KEY_ID

    opening = STORED_VALUE_UNKNOWN_KEY_ID.split("{key_id}")[0].strip()
    document = (_DOCS / "troubleshooting.md").read_text()

    assert opening in document
    assert "docs/operations.md §5" in STORED_VALUE_UNKNOWN_KEY_ID
    assert "### A downgrade does not un-write what the newer image wrote" in (_DOCS / "operations.md").read_text()


# `docs/operations.md` §1 carries a one-liner whose whole job is to answer *does the key in
# `.env` open this database* before an operator needs it, and KNOWN_ISSUES.md §5 sends them
# to it. Nothing pinned it, so #480's prefix made it answer *does NOT match* for the right
# key: it handed `k1:gAAAAA…` to Fernet, which refuses anything that is not urlsafe base64.
# These four run the documented snippet itself, so the runbook cannot drift from the seam it
# is checking.
def _runbook_check(stored: str, key: str) -> subprocess.CompletedProcess[str]:
    """The snippet out of the document, fed as the runbook pipes it: the raw column on
    stdin, the key in the environment. `python -c` rather than a heredoc for the reason the
    document gives — the heredoc would *be* stdin."""
    found = re.findall(r"python -c '(.*?)'\n```", (_DOCS / "operations.md").read_text(), re.S)
    assert len(found) == 1, "the runbook's break-glass check is not where this test reads it from"
    return subprocess.run(
        [sys.executable, "-c", found[0]],
        input=stored,
        capture_output=True,
        text=True,
        env={**os.environ, "ENCRYPTION_KEY": key},
    )


def test_the_runbook_check_matches_a_value_this_build_wrote(encryption_key: str) -> None:
    written = EncryptedString().process_bind_param(_SECRET, None)

    result = _runbook_check(written, encryption_key)

    assert written.startswith("k1:")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ENCRYPTION_KEY matches this database"


def test_the_runbook_check_matches_a_value_written_before_the_prefix(encryption_key: str) -> None:
    """The check reads one row, and the lowest `id` in a database may predate #480."""
    legacy = Fernet(get_encryption_key()).encrypt(_SECRET.encode()).decode()

    result = _runbook_check(legacy, encryption_key)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ENCRYPTION_KEY matches this database"


def test_the_runbook_check_refuses_another_key(encryption_key: str) -> None:
    result = _runbook_check(EncryptedString().process_bind_param(_SECRET, None), Fernet.generate_key().decode())

    assert result.returncode == 1
    assert "ENCRYPTION_KEY does NOT match this database" in result.stderr


def test_the_runbook_check_does_not_call_a_newer_row_a_wrong_key(encryption_key: str) -> None:
    """The check is read as *the key is wrong*, and for a row from a newer build that answer
    is false in the expensive direction — it sends an operator to their secret store. Same
    reasoning as `StoredValueUnknownKeyId`, on the runbook's side."""
    newer = "k2:" + Fernet(get_encryption_key()).encrypt(_SECRET.encode()).decode()

    result = _runbook_check(newer, encryption_key)

    assert result.returncode == 1
    assert "key id k2" in result.stderr and "older than the database" in result.stderr
    assert "ENCRYPTION_KEY does NOT match" not in result.stderr


def test_decrypt_under_a_different_key_raises_runtime_error(encryption_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Key rotation without re-encrypting stored rows is the realistic trigger: the
    envelope now names the key that wrote it, but `k1` is still the only one there is
    (#144). The wrapped error is what makes that diagnosable."""
    column = EncryptedString()
    stored = column.process_bind_param(_SECRET, None)

    monkeypatch.setattr(settings, "encryption_key", Fernet.generate_key().decode())

    with pytest.raises(RuntimeError, match="not the one this database was written under") as caught:
        column.process_result_value(stored, None)
    # Its own type (#374), so the API can answer it with a sentence and a 503; still a
    # RuntimeError, so nothing that handled the bare one is broken.
    from app.core.crypto import STORED_VALUE_UNREADABLE, StoredValueUnreadable

    assert isinstance(caught.value, StoredValueUnreadable) and str(caught.value) == STORED_VALUE_UNREADABLE


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


# --- a rotation (#144): two keys for a while, one key id throughout ------------------------


def test_a_value_under_the_previous_key_still_opens_during_a_rotation(
    encryption_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The old key goes in ENCRYPTION_KEY_PREVIOUS beside the new one, and a row written under
    it reads as before — which is what lets the rewrite run on a live instance."""
    from app.core.crypto import open_stored

    column = EncryptedString()
    stored = column.process_bind_param(_SECRET, None)  # under the key the fixture installed

    monkeypatch.setattr(settings, "encryption_key_previous", encryption_key)
    monkeypatch.setattr(settings, "encryption_key", Fernet.generate_key().decode())

    assert column.process_result_value(stored, None) == _SECRET
    assert open_stored(stored) == (_SECRET, "previous")
    rewritten = column.process_bind_param(_SECRET, None)
    assert rewritten.startswith("k1:") and open_stored(rewritten) == (_SECRET, "current")


def test_a_value_under_neither_key_is_still_unreadable(encryption_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.crypto import StoredValueUnreadable

    stored = EncryptedString().process_bind_param(_SECRET, None)
    monkeypatch.setattr(settings, "encryption_key_previous", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "encryption_key", Fernet.generate_key().decode())

    with pytest.raises(StoredValueUnreadable, match="not the one this database was written under"):
        EncryptedString().process_result_value(stored, None)


def test_validate_refuses_a_malformed_previous_key(encryption_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "encryption_key_previous", "not-a-fernet-key")
    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY_PREVIOUS is set but is not a valid Fernet key"):
        validate_encryption_key()


def test_validate_refuses_a_previous_key_equal_to_the_current_one(encryption_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "encryption_key_previous", encryption_key)
    with pytest.raises(RuntimeError, match="the same key as ENCRYPTION_KEY, so there is nothing to rotate to"):
        validate_encryption_key()


def test_an_empty_previous_key_means_no_rotation(encryption_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Compose passes an unset optional setting as the empty string (test_compose_settings.py)."""
    from app.core.crypto import get_previous_encryption_key

    monkeypatch.setattr(settings, "encryption_key_previous", "")
    validate_encryption_key()
    assert get_previous_encryption_key() is None


def test_the_rotation_sentences_have_their_step_through() -> None:
    """Both startup refusals are quoted in troubleshooting §4 (docs/diagnosability.md rule 4)."""
    from app.core.crypto import PREVIOUS_KEY_IS_CURRENT, PREVIOUS_KEY_MALFORMED

    doc = (Path(__file__).resolve().parents[2] / "docs" / "troubleshooting.md").read_text()
    assert PREVIOUS_KEY_MALFORMED.split(". ")[0] in doc
    assert PREVIOUS_KEY_IS_CURRENT.split(", so")[0] in doc
