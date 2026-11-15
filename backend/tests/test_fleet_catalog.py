"""Fleet's maintained-apps catalogue (#794): what is read out of GitHub's answers, and what
each kind of bad answer is called.

The pure half: the four parsers, the one GET every request goes through, and the clock. The
bodies are hand-made in the shape of Fleet's files (`apps.json`, `<slug>/darwin.json`) and
of GitHub's listings; none of Fleet's files is copied here. What a whole check does to the
stored titles is `test_fleet_catalog_db.py`.

The manifest fixture carries an installer address, a script and a query on purpose: the
parser's promise is that it reads past them, and `parse_manifest` returning one string is
that promise in a type.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core import fleet_catalog as fc
from app.models.schema import FleetCatalogState

TREE_SHA = "a" * 40
BLOB = "b" * 40


def _body(value) -> bytes:
    return json.dumps(value).encode()


MANIFEST = {
    "versions": [
        {
            "version": "8.12.44",
            "queries": {"exists": "SELECT 1 FROM apps WHERE bundle_identifier = 'com.example.app';"},
            "installer_url": "https://downloads.example.com/App.pkg",
            "install_script_ref": "ab3f7792",
            "sha256": "no_check",
        }
    ],
    "refs": {"ab3f7792": '#!/bin/bash\ninstaller -pkg "$INSTALLER_PATH" -target /\n'},
}


def test_the_outputs_tree_is_named_by_the_folder_listing() -> None:
    listing = [
        {"name": "README.md", "type": "file", "sha": "c" * 40},
        {"name": "outputs", "type": "dir", "sha": TREE_SHA},
    ]
    assert fc.parse_contents(_body(listing)) == TREE_SHA


@pytest.mark.parametrize(
    "body",
    [
        _body({"message": "Not Found"}),  # an object where the listing is a list
        _body([{"name": "inputs", "type": "dir", "sha": TREE_SHA}]),  # the folder, without outputs
        _body([{"name": "outputs", "type": "file", "sha": TREE_SHA}]),  # outputs, and not a folder
        _body([{"name": "outputs", "type": "dir", "sha": "not-a-sha"}]),
        b"<html>Sign in to the guest network</html>",
    ],
)
def test_a_listing_that_is_not_the_catalogue_folder_is_unexpected(body: bytes) -> None:
    with pytest.raises(fc.CheckFailed) as caught:
        fc.parse_contents(body)
    assert caught.value.outcome == fc.OUTCOME_UNEXPECTED
    assert "Nothing was changed" in caught.value.detail


def test_the_tree_gives_each_mac_manifest_its_blob_sha_and_nothing_else() -> None:
    tree = {
        "sha": TREE_SHA,
        "truncated": False,
        "tree": [
            {"path": "apps.json", "type": "blob", "sha": "1" * 40},
            {"path": "1password", "type": "tree", "sha": "2" * 40},
            {"path": "1password/darwin.json", "type": "blob", "sha": BLOB},
            {"path": "1password/windows.json", "type": "blob", "sha": "3" * 40},
            {"path": "box-drive/darwin.json", "type": "blob", "sha": "4" * 40},
            {"path": "../etc/darwin.json", "type": "blob", "sha": "5" * 40},  # not a slug: never a URL
            {"path": "nested/deeper/darwin.json", "type": "blob", "sha": "6" * 40},
        ],
    }
    assert fc.parse_tree(_body(tree)) == {"1password": BLOB, "box-drive": "4" * 40}


def test_a_listing_github_cut_short_is_refused_whole() -> None:
    """Half a listing would read as Fleet having dropped the other half's titles."""
    tree = {"truncated": True, "tree": [{"path": "1password/darwin.json", "type": "blob", "sha": BLOB}]}
    with pytest.raises(fc.CheckFailed) as caught:
        fc.parse_tree(_body(tree))
    assert caught.value.outcome == fc.OUTCOME_UNEXPECTED
    assert "cut its listing" in caught.value.detail


def test_a_tree_with_no_mac_manifest_is_not_the_catalogue() -> None:
    with pytest.raises(fc.CheckFailed):
        fc.parse_tree(_body({"tree": [{"path": "apps.json", "type": "blob", "sha": BLOB}]}))


def test_the_index_names_the_mac_titles_by_their_directory() -> None:
    index = {
        "version": 2,
        "apps": [
            {
                "name": "1Password",
                "slug": "1password/darwin",
                "platform": "darwin",
                "unique_identifier": "com.1password.1password",
            },
            {"name": "1Password", "slug": "1password/windows", "platform": "windows", "unique_identifier": "1Password"},
            {"name": " Box Drive ", "slug": "box-drive/darwin", "platform": "darwin", "unique_identifier": "com.box.desktop"},
            {"name": "No Identifier", "slug": "nameless/darwin", "platform": "darwin"},
            {"name": "x" * 300, "slug": "too-long/darwin", "platform": "darwin", "unique_identifier": "com.example.long"},
        ],
    }
    assert fc.parse_index(_body(index)) == {
        "1password": ("1Password", "com.1password.1password"),
        "box-drive": ("Box Drive", "com.box.desktop"),
    }


def test_an_index_with_no_mac_app_is_not_the_catalogue() -> None:
    with pytest.raises(fc.CheckFailed) as caught:
        fc.parse_index(_body({"version": 2, "apps": [{"name": "X", "slug": "x/windows", "platform": "windows"}]}))
    assert caught.value.outcome == fc.OUTCOME_UNEXPECTED


def test_a_manifest_gives_its_current_version_and_only_that() -> None:
    assert fc.parse_manifest(_body(MANIFEST)) == "8.12.44"


@pytest.mark.parametrize(
    "manifest",
    [
        {"versions": []},
        {"versions": [{"installer_url": "https://downloads.example.com/App.pkg"}]},
        {"versions": [{"version": 8}]},
        {"versions": [{"version": "   "}]},
        {"versions": [{"version": "9" * 65}]},  # past the column: left out, never cut to fit
        {"refs": {}},
        ["not", "an", "object"],
    ],
)
def test_a_manifest_without_a_version_this_container_can_hold_is_unreadable(manifest) -> None:
    assert fc.parse_manifest(_body(manifest)) is None
    assert fc.parse_manifest(b"<html>") is None


def _state(outcome: str | None, checked_ago: timedelta | None) -> FleetCatalogState:
    now = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
    return FleetCatalogState(id=1, outcome=outcome, checked_at=None if checked_ago is None else now - checked_ago)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (None, True),  # never checked
        (_state(None, None), True),
        (_state(fc.OUTCOME_OK, timedelta(hours=1)), False),
        (_state(fc.OUTCOME_UNCHANGED, timedelta(hours=23)), False),
        (_state(fc.OUTCOME_UNCHANGED, timedelta(hours=24)), True),  # once a day
        (_state(fc.OUTCOME_REFUSED, timedelta(minutes=30)), False),
        (_state(fc.OUTCOME_REFUSED, timedelta(hours=1)), True),  # within the hour after a failure
        (_state(fc.OUTCOME_UNREACHABLE, timedelta(hours=1)), True),
        (_state(fc.OUTCOME_UNEXPECTED, timedelta(hours=1)), True),
    ],
)
def test_a_check_is_due_once_a_day_and_within_the_hour_after_a_failure(state, expected: bool) -> None:
    assert fc.due(state, datetime(2026, 11, 15, 12, 0, tzinfo=UTC)) is expected


def test_skipped_manifests_are_named_five_at_most() -> None:
    assert fc._skipped_sentence([]) is None
    one = fc._skipped_sentence(["zoom"])
    assert one is not None and one.startswith("1 of Fleet's Mac manifests") and "was left as held: zoom." in one
    many = fc._skipped_sentence([f"app-{n}" for n in range(8)])
    assert many is not None and "were left as held: app-0, app-1, app-2, app-3, app-4 and 3 more." in many


# --- the one GET ---------------------------------------------------------------------------


def _get(handler, url: str = fc.CONTENTS_URL, ceiling: int = 1024) -> tuple[bytes | Exception, fc._Tally]:
    tally = fc._Tally()

    async def run() -> bytes:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
            return await fc._get(client, url, ceiling=ceiling, what="the folder", tally=tally)

    try:
        return asyncio.run(run()), tally
    except (fc.CheckFailed, fc._Missing) as exc:
        return exc, tally


def test_a_rate_limit_is_refused_and_says_whose_limit_it_is() -> None:
    result, tally = _get(lambda request: httpx.Response(403, headers={"x-ratelimit-remaining": "0"}))
    assert isinstance(result, fc.CheckFailed) and result.outcome == fc.OUTCOME_REFUSED
    assert "60 an hour for each address" in result.detail and "within the hour" in result.detail
    assert tally.api_requests == 1 and tally.raw_requests == 0


def test_a_raw_host_limit_does_not_claim_the_api_budget() -> None:
    result, tally = _get(lambda request: httpx.Response(429), url=f"{fc._RAW}/apps.json")
    assert isinstance(result, fc.CheckFailed) and result.outcome == fc.OUTCOME_REFUSED
    assert "60 an hour" not in result.detail and fc.RAW_HOST in result.detail
    assert tally.raw_requests == 1 and tally.api_requests == 0


def test_a_proxys_403_is_unreachable_not_a_rate_limit() -> None:
    """A 403 with none of GitHub's limit headers is a proxy's page, and calling it the shared
    budget would send its operator to the wrong fix (`update_check._rate_limited`)."""
    result, _ = _get(lambda request: httpx.Response(403, text="Access denied"))
    assert isinstance(result, fc.CheckFailed) and result.outcome == fc.OUTCOME_UNREACHABLE
    assert "answered 403" in result.detail and "egress firewall" in result.detail


def test_a_redirect_is_not_followed() -> None:
    result, tally = _get(lambda request: httpx.Response(302, headers={"location": "http://169.254.169.254/"}))
    assert isinstance(result, fc.CheckFailed) and result.outcome == fc.OUTCOME_UNEXPECTED
    assert "redirect" in result.detail
    assert tally.api_requests == 1  # one request, and not a second to wherever it pointed


def test_a_404_is_the_callers_to_name() -> None:
    result, _ = _get(lambda request: httpx.Response(404, json={"message": "Not Found"}))
    assert isinstance(result, fc._Missing)


def test_a_body_past_the_ceiling_is_stopped_while_it_streams() -> None:
    result, _ = _get(lambda request: httpx.Response(200, content=b"x" * 5000), ceiling=1024)
    assert isinstance(result, fc.CheckFailed) and result.outcome == fc.OUTCOME_UNEXPECTED
    assert "the read was stopped there" in result.detail


def test_no_answer_names_the_host_and_the_next_check() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Name or service not known", request=request)

    result, _ = _get(refuse)
    assert isinstance(result, fc.CheckFailed) and result.outcome == fc.OUTCOME_UNREACHABLE
    assert result.detail.startswith(f"No answer from {fc.API_HOST} (Name or service not known).")
    assert "docs/troubleshooting.md" in result.detail


def test_the_request_names_the_product_and_nothing_else_of_this_instance() -> None:
    seen: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=[])

    async def run() -> None:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": fc.build_user_agent("fleet-catalog")}
        async with httpx.AsyncClient(transport=httpx.MockTransport(answer), headers=headers) as client:
            await fc._get(client, fc.CONTENTS_URL, ceiling=1024, what="the folder", tally=fc._Tally())

    asyncio.run(run())
    [request] = seen
    assert str(request.url) == "https://api.github.com/repos/fleetdm/fleet/contents/ee/maintained-apps?ref=main"
    assert request.headers["user-agent"].endswith(" fleet-catalog")
    assert "authorization" not in request.headers and "cookie" not in request.headers
    assert request.content == b""
