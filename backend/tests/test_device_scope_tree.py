"""Nested filter validation and readable evidence preserve operator parentheses."""

import pytest
from pydantic import ValidationError

from app.core.device_scope import scope_description
from app.schemas.patch_plans import DeviceScope

MANAGED = {"field": "managed", "operator": "is", "value": "true"}
CONTACT = {"field": "contact", "operator": "within", "value": "14"}


def test_flat_scopes_still_round_trip():
    scope = DeviceScope.model_validate({"match": "all", "rules": [MANAGED]})
    assert scope.model_dump(by_alias=True)["rules"][0]["field"] == "managed"
    assert DeviceScope.model_validate(scope.model_dump()).rules == scope.rules


def test_nested_groups_keep_parentheses_in_evidence():
    scope = DeviceScope.model_validate(
        {"rules": [MANAGED, {"match": "any", "rules": [CONTACT, {"field": "ea", "key": "Ring", "value": "Pilot"}]}]}
    )
    lines = scope_description(scope)
    assert "OR (" in lines and "  contact within 14 days" in lines and ")" in lines


@pytest.mark.parametrize(
    "invalid",
    [
        {"rules": [{"match": "any", "rules": []}]},
        {"rules": [{"match": "some", "rules": [MANAGED]}]},
        {"rules": [{"match": "all", "connectionId": 2, "rules": [MANAGED]}]},
        {"rules": [{"field": "managed", "value": "true", "injected": "ignored"}]},
        {"rules": [{"match": "all", "rules": [MANAGED] * 11}] * 2},
    ],
)
def test_invalid_or_over_budget_groups_are_refused(invalid):
    with pytest.raises(ValidationError):
        DeviceScope.model_validate(invalid)


def test_depth_is_bounded_before_recursive_model_validation():
    node = MANAGED
    for _ in range(100):
        node = {"match": "any", "rules": [node]}
    with pytest.raises(ValidationError, match="four group levels"):
        DeviceScope.model_validate(node)


def test_unknown_comparison_does_not_print_an_ignored_old_value():
    scope = DeviceScope.model_validate({"rules": [{"field": "contact", "operator": "unknown", "value": "14"}]})
    assert scope_description(scope)[-1] == "contact unknown"
