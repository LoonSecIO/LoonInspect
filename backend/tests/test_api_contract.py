"""The API's shape, read off the OpenAPI document with no database (#137).

Before the macOS client freezes habits against this API, three things the fresh-eyes
survey verified: every paged list is the same envelope under the same parameter names,
the search parameter is `q` everywhere it exists, and the change-policy routes carry a
real schema rather than `{}`. All three are facts about `app.openapi()`, so they are
pinned here in the pure lane, where a contract that drifts fails on every laptop.
"""

from __future__ import annotations

import pytest

from app.changes.policy import EffectivePolicy, Overrides
from app.main import app
from app.schemas.changes import ChangePolicyOut

PAGED_LISTS = [
    "/api/devices",
    "/api/changes",
    "/api/alerts",
    "/api/applications",
    "/api/catalog",
    "/api/jamf-patch/titles",
    "/api/runs",
]
SEARCHED_LISTS = ["/api/devices", "/api/changes", "/api/applications", "/api/catalog", "/api/jamf-patch/titles"]
RETIRED_NAMES = {"limit", "offset", "search"}


def _spec() -> dict:
    return app.openapi()


def _response_schema(spec: dict, path: str, method: str = "get") -> dict:
    ref = spec["paths"][path][method]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    return spec["components"]["schemas"][ref.rsplit("/", 1)[1]]


def _query_parameters(spec: dict, path: str) -> dict[str, dict]:
    return {p["name"]: p for p in spec["paths"][path]["get"].get("parameters", []) if p["in"] == "query"}


@pytest.mark.parametrize("path", PAGED_LISTS)
def test_every_paged_list_answers_in_the_one_envelope(path: str) -> None:
    spec = _spec()
    properties = _response_schema(spec, path)["properties"]
    assert {"items", "total", "page", "pageSize"} <= set(properties), sorted(properties)
    assert properties["items"]["type"] == "array"


@pytest.mark.parametrize("path", PAGED_LISTS)
def test_every_paged_list_is_asked_with_page_and_page_size(path: str) -> None:
    parameters = _query_parameters(_spec(), path)
    assert {"page", "pageSize"} <= set(parameters), sorted(parameters)
    assert not (RETIRED_NAMES & set(parameters)), sorted(RETIRED_NAMES & set(parameters))
    # 1-based, and every page size has a ceiling: a client cannot ask for the whole fleet.
    assert parameters["page"]["schema"]["minimum"] == 1
    assert parameters["pageSize"]["schema"]["maximum"] >= 1


@pytest.mark.parametrize("path", SEARCHED_LISTS)
def test_search_is_q_wherever_a_list_searches(path: str) -> None:
    parameters = _query_parameters(_spec(), path)
    assert "q" in parameters and "search" not in parameters, sorted(parameters)


def test_the_policy_routes_carry_a_schema() -> None:
    spec = _spec()
    for method in ("get", "put"):
        schema = _response_schema(spec, "/api/changes/policy", method)
        assert {"version", "minimumLevel", "sections", "entries", "knownGroups", "updatedAt"} <= set(schema["properties"])


def test_the_described_policy_round_trips_through_its_model() -> None:
    """`describe()` builds plain dicts and `ChangePolicyOut` names their fields; if either
    side moves, this is the test that says so. The dump has to reproduce every key the
    document carried plus the three the route adds, so nothing is quietly dropped."""
    document = EffectivePolicy(Overrides.from_document(None)).describe()
    out = ChangePolicyOut.model_validate({**document, "knownGroups": [], "knownExtensionAttributes": [], "updatedAt": None})
    dumped = out.model_dump(by_alias=True, mode="json")
    assert set(dumped) == set(document) | {"knownGroups", "knownExtensionAttributes", "updatedAt"}
    assert dumped["sections"] == document["sections"]
    assert dumped["entries"] == document["entries"]
    assert dumped["minimumLevel"] == "normal"
    assert any(field["default"] for section in dumped["sections"] for field in section["fields"])
