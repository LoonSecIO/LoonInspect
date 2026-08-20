"""`app.core.content_keys` is cross-codebase contract, frozen in docs/data-sharing.md.

The same keys are computed independently by every shipped container and by the LoonSec
cloud; the reveal threshold counts distinct submitters per *identical* key, and feed
lookups join on them. Serialization drift between implementations does not fail loudly
— it starves the threshold and produces silent false negatives in vulnerability
matching. So, exactly like test_hashing.py, these assert the **literal digests**
published in the design doc rather than recomputing them the way the implementation
does: a test that follows the source can only prove self-consistency, which is the one
property that does not matter for a contract.

If a change here breaks a vector, the change is wrong — not the test. The contract
evolves only behind a new version prefix.
"""

from __future__ import annotations

import unicodedata

from app.core.content_keys import app_full_key, app_title_key, hw_key, os_key

# The vector table from docs/data-sharing.md, verbatim.

def test_app_title_vector() -> None:
    assert (
        app_title_key("Google Chrome", "com.google.Chrome")
        == "v1:be346ceb600488c11f502c5b8cccd213941d12e783c798ce9ef901a0b88a0830"
    )


def test_app_full_vector() -> None:
    assert (
        app_full_key("Google Chrome", "com.google.Chrome", "6478.127", "126.0.6478.127")
        == "v1:7ffc73c1311760fa2de0b52b84865940380264906a8f63d4c5fb2075fbde7378"
    )


def test_null_short_version_vector() -> None:
    assert (
        app_full_key("Contoso Deploy", "com.contoso.deploy", "1.4", None)
        == "v1:333332009338fd345dfdc481009910bc729ef2cf965ad33a90df297e2f4d9592"
    )


def test_os_vector() -> None:
    assert (
        os_key("macos", "14.6.1", "23G93")
        == "v1:f74565fbdda8b8036799e1e3a67b22ee909acac8840f2a6ae040b3d5a4e18867"
    )


def test_hw_vector() -> None:
    assert (
        hw_key("Mac15,7", "arm64")
        == "v1:efaeacc74866d7664560069b9b8f5b63f3cbd30f2d410cad4358ded71d3a2840"
    )


# Semantic rules the vectors alone cannot pin down.

_CAFE_KEY = "v1:1db5e02b18524033fd33aa36d27b3f26e70953a13f57de3cb45729e91e7e36bb"


def test_nfd_and_nfc_inputs_collapse_to_one_key() -> None:
    """macOS delivers NFD from some paths and NFC from others; both spellings of the
    same name must land on the doc's published digest, or one app becomes two keys
    depending on which MDM read it."""
    nfc = unicodedata.normalize("NFC", "Café Tool")
    nfd = unicodedata.normalize("NFD", "Café Tool")
    assert nfc != nfd  # the fixture is only meaningful if the spellings differ
    assert app_title_key(nfc, "io.example.cafetool") == _CAFE_KEY
    assert app_title_key(nfd, "io.example.cafetool") == _CAFE_KEY


def test_null_and_empty_short_version_are_one_key() -> None:
    """Jamf sends null where the HEC payload sends a real value; when the value is
    absent either way, the key must not depend on which spelling of absence arrived."""
    assert app_full_key("X", "com.x", "1", None) == app_full_key("X", "com.x", "1", "")


def test_whitespace_is_stripped_before_hashing() -> None:
    assert app_title_key("  Google Chrome  ", "com.google.Chrome") == app_title_key(
        "Google Chrome", "com.google.Chrome"
    )


def test_separator_in_input_cannot_forge_a_boundary() -> None:
    """U+001F is the field joiner; a hostile or broken source supplying it in data
    must not be able to shift fields into each other."""
    assert app_title_key("A\x1fB", "com.x") == app_title_key("AB", "com.x")


def test_domains_never_collide() -> None:
    """Identical field values under different domains are different keys — an OS
    tuple can never masquerade as an app."""
    assert os_key("a", "b", "c") != hw_key("a", "b") != app_title_key("a", "b")
