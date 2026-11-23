"""Patch-plan input, bounded research and evidence integrity without an external service."""

import json

import httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.device_scope import parse_scope
from app.core.patch_plan_research import investigate_installomator, parse_priorities
from app.core.patch_plans import checksum, release_order
from app.schemas.patch_plans import BuildPlan, ScopeRule


@pytest.mark.parametrize("raw", ['{"match":"some","rules":[]}', '{"rules":[],"connectionId":-1}', "not json"])
def test_invalid_scopes_are_refused(raw):
    with pytest.raises(HTTPException) as error:
        parse_scope(raw)
    assert error.value.status_code == 422


@pytest.mark.parametrize(
    "rule",
    [
        {"field": "contact", "operator": "within", "value": "0"},
        {"field": "managed", "operator": "contains", "value": "true"},
        {"field": "ea", "operator": "is", "value": "Pilot"},
        {"field": "group", "operator": "is", "key": "jamf", "value": "1"},
    ],
)
def test_invalid_rules_are_refused(rule):
    with pytest.raises(ValidationError):
        ScopeRule.model_validate(rule)


def test_identity_and_report_integrity():
    value = BuildPlan(appHashes=["a" * 32, "a" * 32])
    assert value.app_hashes == ["a" * 32]
    assert checksum({"a": 1, "b": 2}) == checksum({"b": 2, "a": 1})
    assert checksum({"a": 2}) != checksum({"a": 1})


@pytest.mark.parametrize("raw", ['{"a":[true]}', '{"invented":[1]}', '{"a":[8]}', '{"a":[1,1]}', "Here is a plan", "{}"])
def test_model_cannot_invent_steps_or_coverage(raw):
    assert parse_priorities(raw, ["a"]) is None


def test_valid_model_priorities_preserve_server_steps():
    assert parse_priorities('{"a":[1,3,4]}', ["a"]) == {"a": [1, 3, 4]}


async def test_installomator_uses_pinned_revision_and_never_claims_configured_deployment(monkeypatch):
    from app.core import patch_plan_research as research

    urls = []

    def respond(request):
        urls.append(str(request.url))
        if request.url.host == "api.github.com":
            return httpx.Response(200, json={"sha": "a" * 40})
        return httpx.Response(200, text='githubdesktop)\nname="GitHub Desktop"\nexpectedTeamID="VEKTX9H2N7"\n;;')

    monkeypatch.setattr(research, "transport_override", httpx.MockTransport(respond))
    result = await investigate_installomator([{"appHash": "a" * 32, "name": "GitHub Desktop.app"}])
    assert result[0]["status"] == "candidate"
    assert result[0]["signingTeam"] == "VEKTX9H2N7"
    assert "/" + "a" * 40 + "/" in urls[1]
    assert "Verify" in result[0]["detail"]
    assert len(result[0]["sha256"]) == 64


async def test_missing_label_does_not_prove_no_installomator_support(monkeypatch):
    from app.core import patch_plan_research as research

    def respond(request):
        return httpx.Response(200, json={"sha": "b" * 40}) if request.url.host == "api.github.com" else httpx.Response(404)

    monkeypatch.setattr(research, "transport_override", httpx.MockTransport(respond))
    result = await investigate_installomator([{"appHash": "a" * 32, "name": "An App"}])
    assert result[0]["status"] == "not_found"
    assert "does not prove" in result[0]["detail"]


def test_more_than_twenty_filter_conditions_are_bounded():
    with pytest.raises(HTTPException):
        parse_scope(json.dumps({"match": "all", "rules": [{"field": "managed", "value": "true"}] * 21}))


@pytest.mark.parametrize(
    ("installed", "target", "expected"),
    [("3.6.10", "3.7.0", -1), ("3.7.0", "3.7.0", 0), ("4.0", "3.7.0", 1), ("3.7-beta", "3.7.0", None), ("unread", "3.7.0", None)],
)
def test_release_comparison_keeps_qualifiers_unknown(installed, target, expected):
    assert release_order(installed, target) == expected
