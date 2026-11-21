"""Fleet's version history (#838) without a database: which versions a run of changes dates,
how the list of changes is read, and what GitHub's allowance headers say."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core import fleet_catalog as fc
from app.core import fleet_history as fh

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _changes(*versions: str | None) -> list[tuple[str, datetime, str | None]]:
    """One reading per version, a day apart, oldest first, with made-up shas."""
    return [(f"{n:040x}", T0 + timedelta(days=n), version) for n, version in enumerate(versions)]


def _dated(readings, *, first: bool) -> list[tuple[str, int, str | None]]:
    """(version, the day it was dated, the version it replaced)."""
    return [(v, (at - T0).days, before) for v, at, _, before in fh.date_versions(readings, from_first_change=first)]


def test_a_version_is_dated_where_it_replaces_another_and_at_the_titles_first_change() -> None:
    readings = _changes("1.0", "1.0", "1.5", "2.0", "2.0")
    assert _dated(readings, first=True) == [("1.0", 0, None), ("1.5", 2, "1.0"), ("2.0", 3, "1.5")]


def test_the_middle_of_the_story_leaves_its_first_version_undated() -> None:
    # A capped read, or one that resumed: the first change in hand is not where 1.0 arrived.
    readings = _changes("1.0", "1.5")
    assert _dated(readings, first=False) == [("1.5", 1, "1.0")]


def test_a_change_that_could_not_be_read_leaves_the_next_arrival_undated() -> None:
    # 1.9 may have arrived at the unreadable change or at the one after it: no date for it.
    readings = _changes("1.0", "1.5", None, "1.9", "2.0")
    assert _dated(readings, first=True) == [("1.0", 0, None), ("1.5", 1, "1.0"), ("2.0", 4, "1.9")]


def test_a_manifest_that_was_missing_and_came_back_dates_its_return_with_nothing_replaced() -> None:
    readings = _changes("1.0", fh.ABSENT, "3.0")
    assert _dated(readings, first=True) == [("1.0", 0, None), ("3.0", 2, None)]


def test_a_version_seen_undated_is_not_dated_by_a_later_return() -> None:
    # 1.0 opens a resumed window undated; Fleet then moves to 1.1 and back. 1.0's return is not
    # its arrival, and dating it there would say it is newer than 1.1.
    readings = _changes("1.0", "1.1", "1.0")
    assert _dated(readings, first=False) == [("1.1", 1, "1.0")]


def test_the_list_of_changes_is_read_as_sha_and_commit_date() -> None:
    body = json.dumps(
        [
            {"sha": "a" * 40, "commit": {"committer": {"date": "2026-11-18T02:27:27Z"}, "message": "x"}},
            {"sha": "b" * 40, "commit": {"committer": {"date": "2026-11-11T05:12:26+00:00"}}},
        ]
    ).encode()
    assert fh.parse_commits(body, "firefox") == [
        ("a" * 40, datetime(2026, 11, 18, 2, 27, 27, tzinfo=UTC)),
        ("b" * 40, datetime(2026, 11, 11, 5, 12, 26, tzinfo=UTC)),
    ]


@pytest.mark.parametrize(
    "body",
    [
        b"<html>sign in</html>",
        json.dumps({"message": "Not a list"}).encode(),
        json.dumps([{"sha": "short", "commit": {"committer": {"date": "2026-11-18T02:27:27Z"}}}]).encode(),
        json.dumps([{"sha": "a" * 40, "commit": {"committer": {"date": "yesterday"}}}]).encode(),
        json.dumps([{"sha": "a" * 40, "commit": {"committer": {"date": "2026-11-18T02:27:27"}}}]).encode(),
    ],
)
def test_a_list_that_is_not_githubs_is_unexpected_in_words(body: bytes) -> None:
    with pytest.raises(fc.CheckFailed) as raised:
        fh.parse_commits(body, "firefox")
    assert raised.value.outcome == fc.OUTCOME_UNEXPECTED and "firefox/darwin.json" in raised.value.detail


def test_the_list_is_asked_for_by_path_on_main_a_hundred_at_a_time() -> None:
    url = httpx.URL(fh.commits_url("firefox", 2, datetime(2026, 11, 1, tzinfo=UTC)))
    assert (url.host, url.path) == ("api.github.com", "/repos/fleetdm/fleet/commits")
    assert dict(url.params) == {
        "sha": "main",
        "path": "ee/maintained-apps/outputs/firefox/darwin.json",
        "per_page": "100",
        "page": "2",
        "since": "2026-11-01T00:00:00Z",
    }
    assert "since" not in httpx.URL(fh.commits_url("firefox", 1, None)).params


def test_the_allowance_is_what_githubs_last_answer_said_until_the_hour_resets() -> None:
    allowance = fc.Allowance()
    now = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
    assert allowance.left(now) is None  # nothing said yet

    reset = int((now + timedelta(minutes=30)).timestamp())
    allowance.note(httpx.Headers({"x-ratelimit-remaining": "21", "x-ratelimit-reset": str(reset)}))
    assert allowance.left(now) == 21
    assert allowance.left(now + timedelta(minutes=31)) is None  # the hour reset

    allowance.note(httpx.Headers({"content-type": "application/json"}))  # no headers: no news
    assert allowance.left(now) == 21
    allowance.note(httpx.Headers({"x-ratelimit-remaining": "lots", "x-ratelimit-reset": str(reset)}))
    assert allowance.left(now) == 21


def test_the_waiting_sentence_says_what_is_left_until_when_and_what_to_check() -> None:
    reset = datetime(2026, 11, 21, 14, 5, tzinfo=UTC)
    background = fh._waiting_sentence(20, reset, person=False)
    person = fh._waiting_sentence(20, reset, person=True)
    assert background.startswith("Paused until 14:05 UTC") and "troubleshooting.md §27" in background
    assert person.startswith("Not read:") and "Try again after 14:05 UTC" in person
    assert "20 of this address's 60 requests" in background and "the last 20" in person
