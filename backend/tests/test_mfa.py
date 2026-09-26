"""TOTP (#653) without a database: the code window, the replay rule, recovery codes, and the
challenge the password step hands back."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pyotp

from app.core import mfa

NOW = datetime(2026, 9, 26, 4, 0, tzinfo=UTC)
STEP = int(NOW.timestamp()) // mfa.STEP_SECONDS


def _wrong(code: str) -> str:
    return str((int(code) + 1) % 1_000_000).zfill(6)


def test_a_code_is_good_for_its_step_and_one_either_side_and_spaces_are_forgiven():
    secret = mfa.mint_secret()
    totp = pyotp.TOTP(secret)
    assert mfa.verify_code(secret, totp.at(STEP * 30), None, now=NOW) == STEP
    assert mfa.verify_code(secret, totp.at((STEP - 1) * 30), None, now=NOW) == STEP - 1
    assert mfa.verify_code(secret, totp.at((STEP + 1) * 30), None, now=NOW) == STEP + 1
    assert mfa.verify_code(secret, totp.at((STEP + 2) * 30), None, now=NOW) is None
    assert mfa.verify_code(secret, _wrong(totp.at(STEP * 30)), None, now=NOW) is None
    code = totp.at(STEP * 30)
    assert mfa.verify_code(secret, f"{code[:3]} {code[3:]}", None, now=NOW) == STEP
    assert mfa.verify_code(secret, "12345", None, now=NOW) is None
    assert mfa.verify_code("", code, None, now=NOW) is None


def test_a_step_at_or_before_the_last_accepted_one_is_refused():
    secret = mfa.mint_secret()
    totp = pyotp.TOTP(secret)
    assert mfa.verify_code(secret, totp.at(STEP * 30), STEP, now=NOW) is None
    assert mfa.verify_code(secret, totp.at((STEP - 1) * 30), STEP, now=NOW) is None
    assert mfa.verify_code(secret, totp.at((STEP + 1) * 30), STEP, now=NOW) == STEP + 1


class Row:
    def __init__(self, codes: list[str]) -> None:
        self.recovery_codes = codes


def test_recovery_codes_are_ten_distinct_and_each_is_spent_once():
    codes, hashes = mfa.mint_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(len(code) == 11 and code[5] == "-" and code.islower() for code in codes)
    assert all(not stored.startswith(code[:5]) for stored, code in zip(hashes, codes, strict=True))
    row = Row(hashes)
    assert mfa.consume_recovery_code(row, codes[3].upper().replace("-", " ")) is True
    assert len(row.recovery_codes) == 9
    assert mfa.consume_recovery_code(row, codes[3]) is False
    assert mfa.consume_recovery_code(row, "nope") is False
    assert mfa.consume_recovery_code(Row([]), codes[0]) is False


def test_the_challenge_names_its_account_until_it_expires_and_never_when_touched(encryption_key):
    token = mfa.challenge_token("acct-1", now=NOW)
    assert mfa.challenge_account_id(token, now=NOW) == "acct-1"
    assert mfa.challenge_account_id(token, now=NOW + timedelta(seconds=299)) == "acct-1"
    assert mfa.challenge_account_id(token, now=NOW + timedelta(seconds=300)) is None
    flipped = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert mfa.challenge_account_id(flipped, now=NOW) is None
    assert mfa.challenge_account_id("acct-2" + token[len("acct-1") :], now=NOW) is None
    assert mfa.challenge_account_id("garbage", now=NOW) is None
    assert mfa.challenge_account_id("", now=NOW) is None
