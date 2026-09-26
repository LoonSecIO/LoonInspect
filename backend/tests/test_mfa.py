"""TOTP (#653) without a database: the code window, the replay rule, and the challenge the
password step hands back."""

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
