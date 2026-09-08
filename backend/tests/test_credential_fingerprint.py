"""`credential_fingerprint`: the tag a stored secret wears in public (#316).

The tag is returned to every role with CONNECTION_READ, so the property that matters is
negative — it carries nothing of the secret — and the property that makes it useful is
that two secrets get two tags. Both are pinned here without a database.
"""

from __future__ import annotations

import hashlib

from app.mdm.credentials import FINGERPRINT_LENGTH, credential_fingerprint, fingerprint_field
from app.schemas.payload import MdmProvider

SECRET = "S3cret-Value!With-Punctuation-and-CAPS"


def test_it_is_twelve_hex_characters_of_sha256() -> None:
    tag = credential_fingerprint(SECRET)
    assert len(tag) == FINGERPRINT_LENGTH == 12
    assert tag == hashlib.sha256(SECRET.encode()).hexdigest()[:12]
    assert set(tag) <= set("0123456789abcdef")


def test_it_carries_nothing_of_the_secret() -> None:
    """The defect this replaces was `secret[:3]`. A hash prefix cannot be that, and cannot
    be any other run of the secret's characters either — the capitals and punctuation
    above are not hex, so no substring of three or more can appear in the tag."""
    tag = credential_fingerprint(SECRET)
    assert tag != SECRET[:3]
    assert SECRET[:3] not in tag
    assert all(SECRET[i : i + 3] not in tag for i in range(len(SECRET) - 2))


def test_it_is_deterministic_and_distinguishes_secrets() -> None:
    assert credential_fingerprint(SECRET) == credential_fingerprint(SECRET)
    assert credential_fingerprint(SECRET) != credential_fingerprint(SECRET + "x")
    # The old scheme could not tell these apart at all.
    assert credential_fingerprint("abc-one") != credential_fingerprint("abc-two")


def test_it_is_unicode_safe() -> None:
    assert len(credential_fingerprint("pässwörd-ünïcode")) == 12


def test_jamf_still_fingerprints_the_client_secret() -> None:
    assert fingerprint_field(MdmProvider.jamf) == "client_secret"
