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

from app.core.content_keys import app_bundle_key, app_full_key, app_title_key, hw_key, os_key

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


def test_app_bundle_vector() -> None:
    assert (
        app_bundle_key("com.google.Chrome", "6478.127") == "v1:d1cced6faaa7eb9549f07208bbff3c58cb00e3453c395c349b57734d460448f1"
    )


def test_null_short_version_vector() -> None:
    assert (
        app_full_key("Contoso Deploy", "com.contoso.deploy", "1.4", None)
        == "v1:333332009338fd345dfdc481009910bc729ef2cf965ad33a90df297e2f4d9592"
    )


def test_os_vector() -> None:
    assert os_key("macos", "14.6.1", "23G93") == "v1:f74565fbdda8b8036799e1e3a67b22ee909acac8840f2a6ae040b3d5a4e18867"


def test_hw_vector() -> None:
    assert hw_key("Mac15,7", "arm64") == "v1:efaeacc74866d7664560069b9b8f5b63f3cbd30f2d410cad4358ded71d3a2840"


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
    assert app_title_key("  Google Chrome  ", "com.google.Chrome") == app_title_key("Google Chrome", "com.google.Chrome")


def test_separator_in_input_cannot_forge_a_boundary() -> None:
    """U+001F is the field joiner; a hostile or broken source supplying it in data
    must not be able to shift fields into each other."""
    assert app_title_key("A\x1fB", "com.x") == app_title_key("AB", "com.x")


def test_domains_never_collide() -> None:
    """Identical field values under different domains are different keys — an OS
    tuple can never masquerade as an app."""
    assert os_key("a", "b", "c") != hw_key("a", "b") != app_title_key("a", "b")
    # `app.bundle` and `app.title` are both two-field app domains, so this pair is the
    # one that would actually collide without the namespace.
    assert app_bundle_key("a", "b") != app_title_key("a", "b")


# --- the rename-proof key (#245) --------------------------------------------------


def test_a_renamed_app_keeps_its_bundle_key_and_loses_its_title_key() -> None:
    """The whole reason `app.bundle` exists. Two fleets run the same build of the same
    software; one administrator renamed it in place. Their `app.title` and `app.full`
    keys can never match, so the corpus's reveal threshold counts one submitter for each
    spelling forever and neither crosses it — the software reads as somebody's internal
    tool. On `app.bundle` they are one row.

    Stamped through `apply_hashes`, not by calling the key functions twice: the property
    under test is that renaming survives *the ingest path*, and every ingest path funnels
    through that one site. A test that called `app_bundle_key` directly would still pass
    on the day someone stopped stamping the column.
    """
    from app.mdm.service import apply_hashes
    from app.schemas.payload import NormalizedApp

    def _app(name: str) -> NormalizedApp:
        return apply_hashes(
            NormalizedApp(
                name=name,
                bundle_id="com.jamf.management.SelfService",
                version="11.9.1",
                short_version="11.9.1",
            )
        )

    original = _app("Self Service")
    renamed = _app("Contoso App Store")

    assert original.key_bundle == renamed.key_bundle
    assert original.key_bundle == app_bundle_key("com.jamf.management.SelfService", "11.9.1")
    assert original.key_title != renamed.key_title
    assert original.key_full != renamed.key_full


def test_an_app_with_no_bundle_identifier_has_no_bundle_key() -> None:
    """Never hash an empty identity. `_canonical_field` folds null and empty together,
    which is right for a missing `short_version` and catastrophic here: the bundle id is
    the whole identity, so hashing its absence would land every nameless app at one
    version on ONE digest and report them to the corpus as a single popular product.
    Both spellings of absence answer None — Jamf's client substitutes the app's name when
    `bundleId` is missing, which can leave a blank behind as easily as a null."""
    assert app_bundle_key(None, "1.0") is None
    assert app_bundle_key("", "1.0") is None
    assert app_bundle_key("   ", "1.0") is None
    assert app_bundle_key("com.x", "1.0") is not None


def test_the_bundle_key_does_not_reach_the_splunk_wire() -> None:
    """Kyle, 2026-09-02 on #81: LoonInspect's minted identity fields stay off the wire —
    "we can add keys later but we can't take them away." The key rides `NormalizedApp`
    only as far as the `installed_apps` row, and the delta's `addedApps[]` /
    `removedApps[]` ARE wire, so `exclude=True` is the entire mechanism keeping the
    ruling. This is the test that notices when a tidy-up hands it a `serialization_alias`
    to match its two neighbours."""
    from app.schemas.payload import NormalizedApp

    app = NormalizedApp(name="Self Service", bundle_id="com.jamf.management.SelfService", version="11.9.1")
    app.key_bundle = "v1:whatever"
    dumped = app.model_dump(mode="json", by_alias=True)
    assert "keyBundle" not in dumped
    assert "key_bundle" not in dumped
    # The two that were ruled onto the delta are still there — this is the narrow
    # exclusion, not a quiet reversal of the earlier decision.
    assert {"keyTitle", "keyFull"} <= set(dumped)


def test_the_bundle_key_still_splits_on_the_version() -> None:
    """Rename-proof, not version-proof: it is a *build* key, so two versions of one
    bundle stay two rows. A key that collapsed versions too would answer "is this
    software here", which `app.title` already answers.

    The other half of the pair — that it ignores the *name* — cannot be asserted here,
    because the function takes no name to ignore; it is proved end to end, through the
    ingest site that stamps the column, by
    `test_a_renamed_app_keeps_its_bundle_key_and_loses_its_title_key` above.
    """
    assert app_bundle_key("com.x", "1.0") != app_bundle_key("com.x", "2.0")
