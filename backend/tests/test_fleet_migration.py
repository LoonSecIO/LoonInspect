"""`fleet_match`'s truth table (#895): when one Fleet title can stand for an installed identity."""

import pytest

from app.core.fleet_migration import fleet_match

BUNDLE, ONE, TWO = "com.example.alpha", ["alpha"], ["gamma", "gamma@6+"]


@pytest.mark.parametrize(
    ("bundle_id", "candidates", "assumed", "jamf_titles", "complete", "expected"),
    [
        pytest.param(BUNDLE, ONE, False, 1, True, "exact", id="one-title-complete"),
        pytest.param(BUNDLE, [], False, 0, True, "none", id="no-title-complete"),
        pytest.param(BUNDLE, TWO, False, 0, True, "ambiguous", id="several-titles-complete"),
        pytest.param(BUNDLE, TWO, False, 0, False, "ambiguous", id="several-titles-partial"),
        pytest.param(BUNDLE, ONE, True, 0, True, "ambiguous", id="ea-assumed-build"),
        pytest.param(BUNDLE, ONE, False, 2, True, "ambiguous", id="two-jamf-titles"),
        pytest.param(BUNDLE, ONE, False, 0, False, "unknown", id="one-title-partial"),
        pytest.param(BUNDLE, [], False, 0, False, "unknown", id="no-title-partial"),
        pytest.param("Alpha", ONE, False, 0, True, "unknown", id="bundle-id-is-the-name"),
        pytest.param("  ", ONE, False, 0, True, "unknown", id="blank-bundle-id"),
    ],
)
def test_fleet_match(bundle_id, candidates, assumed, jamf_titles, complete, expected) -> None:
    match = fleet_match(bundle_id, "Alpha", candidates, assumed=assumed, jamf_titles=jamf_titles, catalog_complete=complete)
    assert match == expected
