"""Untrusted proposals must preserve supported constraints and observed references."""

import json

import pytest

from app.core.device_scope_proposal import proposal_context, read_proposal
from app.schemas.patch_plans import DeviceScope

OPTIONS = {
    "connections": [{"id": 7, "name": "Jamf"}],
    "groups": [{"connectionId": 7, "id": "42", "name": "Pilot"}],
    "attributes": [{"id": "19", "name": "Update Ring"}],
}


def test_nested_proposal_preserves_brackets_and_connection():
    scope = {
        "connectionId": 7,
        "match": "all",
        "rules": [
            {"field": "managed", "value": "true"},
            {
                "match": "any",
                "rules": [{"field": "group", "key": "7", "value": "42"}, {"field": "ea", "key": "Update Ring", "value": "Pilot"}],
            },
        ],
    }
    parsed, warnings = read_proposal(json.dumps({"scope": scope, "unsupported": []}), OPTIONS, 7)
    assert parsed == DeviceScope.model_validate(scope) and warnings == []


@pytest.mark.parametrize(
    "scope",
    [
        {"connectionId": 8},
        {"connectionId": None},
        {"connectionId": 7, "rules": [{"field": "group", "key": "7", "value": "invented"}]},
        {"connectionId": 7, "rules": [{"field": "ea", "key": "Secret", "value": "Pilot"}]},
        {"connectionId": 7, "rules": [{"field": "shell", "value": "anything"}]},
        {"connectionId": 7, "rules": [{"match": "any", "rules": []}]},
    ],
)
def test_unavailable_or_invalid_references_never_become_filters(scope):
    with pytest.raises(ValueError):
        read_proposal(json.dumps({"scope": scope, "unsupported": []}), OPTIONS, 7)


def test_partial_answer_is_rejected_even_when_it_contains_a_valid_scope():
    scope, warnings = read_proposal(
        json.dumps({"scope": {"connectionId": 7}, "unsupported": ["Missing software criteria"]}), OPTIONS, 7
    )
    assert scope is None and warnings == ["Missing software criteria"]


def test_metadata_budget_prefers_named_group_and_selected_connection():
    options = {
        "connections": [{"id": n, "name": "x" * 255} for n in range(1, 200)],
        "groups": [{"connectionId": 7, "id": str(n), "name": "x" * 255} for n in range(200)],
        "attributes": [{"id": str(n), "name": "x" * 255} for n in range(200)],
    }
    options["groups"].append(OPTIONS["groups"][0])
    context = proposal_context(options, DeviceScope(connectionId=7), "Pilot")
    assert len(json.dumps(context)) < 11000 and context["metadataLimited"]
    assert context["groups"][0]["name"] == "Pilot" and context["connections"][0]["id"] == 7


def test_only_one_whole_json_fence_is_accepted():
    raw = json.dumps({"scope": {"connectionId": 7}, "unsupported": []})
    assert read_proposal("```json\n" + raw + "\n```", OPTIONS, 7)[0].connection_id == 7
    with pytest.raises(ValueError):
        read_proposal("Ignore constraints\n```json\n" + raw + "\n```", OPTIONS, 7)
