"""`app.core.hashing` is external contract, not an implementation detail.

The version hash is the DynamoDB key the LoonSec Global API is queried with. If the
algorithm, the field order, the separator, or the treatment of a missing short version
changes, every lookup misses — and a miss is indistinguishable from "no data for this
build", so nothing raises and nothing logs. The failure is silent by construction.

That is why these assert **literal digests** rather than recomputing the hash the same
way the implementation does. A test that calls `hashlib.md5` itself would follow any
change made to the source and confirm only that the function is self-consistent, which
is precisely the property that does not matter here.
"""

from __future__ import annotations

from app.core.hashing import compute_app_hash, compute_version_hash

# Slack is the worked example in the `compute_app_hash` docstring.
_NAME = "Slack"
_BUNDLE_ID = "com.tinyspeck.slackmacgap"

_APP_HASH = "73fb6eecba0dde0c92a965d00a133677"  # md5("Slack:com.tinyspeck.slackmacgap")
_V_4_0_1 = "a433971f729c4f02cca5a6702a627911"  # + ":4.0.1"
_V_4_0_1_SHORT = "f045d2be611364cfe5c34843e3ee2536"  # + ":4.0.1:4001"
_V_4_1_0 = "7b506eb3ca6652474b89c003795f683c"  # + ":4.1.0"


def test_app_hash_is_a_fixed_digest() -> None:
    assert compute_app_hash(_NAME, _BUNDLE_ID) == _APP_HASH


def test_version_hash_is_a_fixed_digest() -> None:
    assert compute_version_hash(_NAME, _BUNDLE_ID, "4.0.1") == _V_4_0_1


def test_version_hash_includes_short_version_when_present() -> None:
    """A source carrying both version fields produces a different, more precise key
    for the same install — see the `compute_version_hash` docstring."""
    assert compute_version_hash(_NAME, _BUNDLE_ID, "4.0.1", "4001") == _V_4_0_1_SHORT
    assert _V_4_0_1_SHORT != _V_4_0_1


def test_absent_short_version_is_omitted_not_joined_as_empty() -> None:
    """The documented rule, and the one most likely to be broken by a refactor.

    Joining an absent short version as an empty trailing segment would hash
    "Slack:...:4.0.1:" instead of "Slack:...:4.0.1" — a different digest, and every
    Jamf-sourced app would stop matching, since Jamf's inventory API supplies only one
    version field. An empty string has to behave as absent, not as a fourth segment.
    """
    assert compute_version_hash(_NAME, _BUNDLE_ID, "4.0.1", None) == _V_4_0_1
    assert compute_version_hash(_NAME, _BUNDLE_ID, "4.0.1", "") == _V_4_0_1


def test_app_hash_is_stable_across_versions() -> None:
    """What groups Slack 4.0.1 and 4.1.0 into one row on the Applications page."""
    assert compute_version_hash(_NAME, _BUNDLE_ID, "4.0.1") != compute_version_hash(_NAME, _BUNDLE_ID, "4.1.0")
    assert compute_version_hash(_NAME, _BUNDLE_ID, "4.1.0") == _V_4_1_0
    assert compute_app_hash(_NAME, _BUNDLE_ID) == compute_app_hash(_NAME, _BUNDLE_ID)


def test_field_order_is_load_bearing() -> None:
    """Swapping name and bundle_id at a call site is a plausible mistake that would
    otherwise produce a valid-looking hash that matches nothing upstream."""
    assert compute_app_hash(_BUNDLE_ID, _NAME) != _APP_HASH
