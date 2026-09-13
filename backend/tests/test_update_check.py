"""The update check against the latest published release (#407), end to end through its
own request code, with no network.

Kyle, 2026-09-11: `main` is staging, and publishing a GitHub Release is the release. The
check used to compare against `main`'s HEAD, so every merge — docs-only included — told
every install a newer build existed, and a pod built from a release said so the first
time anything landed after its tag. These tests pin the two-call replacement:
`releases/latest` for the tag, then `compare/<tag>...<build sha>` for whether this build
contains it.

The sharp edge from #176 survives the change of provider. A local build stamps the SHORT
sha (`docker-compose.yml`: `git rev-parse --short HEAD`) and CI stamps all 40
(`github.sha`). The compare API takes either as given — checked live, unauthenticated, on
2026-09-12 and again on 2026-09-13 — so the stamp goes into the path untouched, and every
verdict below runs under both widths.

httpx.MockTransport feeds GitHub-shaped bodies through the real parse; the handler records
each request so the order and the URLs are asserted, not assumed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

pytestmark = pytest.mark.asyncio

API = "https://api.github.com/repos/LoonSecIO/LoonInspect"
TAG = "v2026.09.17"
RELEASE_PAGE = f"https://github.com/LoonSecIO/LoonInspect/releases/tag/{TAG}"
RELEASE_SHA = "99361ed4b2c1a7f0e8d5c3b6a4917f2e0d8c5b3a"  # what the tag points at
BUILD_SHA = "c41e044d2f6b8a0e1c3d5f7a9b2c4e6f8a0b1c2d"  # what this build was stamped with
SHORT = f"2026.09.18+{BUILD_SHA[:7]}"  # the compose form
FULL = f"2026.09.18+{BUILD_SHA}"  # the CI form


def _release_body(tag: str = TAG, html_url: str = RELEASE_PAGE) -> dict:
    """`GET /repos/{owner}/{repo}/releases/latest`, trimmed. `target_commitish` is kept on
    purpose: it names the branch the tag was cut from ("main"), and reading it as the
    release's commit would be the plausible mistake."""
    return {
        "html_url": html_url,
        "id": 170000001,
        "tag_name": tag,
        "target_commitish": "main",
        "name": f"LoonInspect {tag}",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-09-17T15:00:00Z",
    }


def _compare_body(status: str) -> dict:
    """`GET /repos/{owner}/{repo}/compare/{base}...{head}`, trimmed. `merge_base_commit` is
    kept beside `base_commit` because they differ on `diverged`, and only the base is the
    release's own commit."""
    return {
        "status": status,
        "ahead_by": 0 if status in ("behind", "identical") else 3,
        "behind_by": 0 if status in ("ahead", "identical") else 5,
        "base_commit": {"sha": RELEASE_SHA, "commit": {"message": "INSPECT-0000: the release"}},
        "merge_base_commit": {"sha": "1111111111111111111111111111111111111111"},
        "commits": [],
    }


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """A cold cache, the check on, and the default provider for every test — the module
    caches across calls, so without this a test would assert another test's answer."""
    from app.core import update_check
    from app.core.config import settings

    monkeypatch.setattr(update_check, "_cache", None)
    monkeypatch.setattr(settings, "update_check", True)
    monkeypatch.setattr(settings, "update_check_url", "")
    yield
    monkeypatch.setattr(update_check, "_cache", None)


def _serve(monkeypatch, handler) -> list[httpx.Request]:
    """Point the module's httpx at a MockTransport, leaving its own request code — URLs,
    headers, redirects, the parse — running for real. Returns the request log."""
    from app.core import update_check

    seen: list[httpx.Request] = []
    # Bind the real class first: update_check.httpx IS the global httpx module, so the
    # setattr below rebinds httpx.AsyncClient everywhere — including inside this factory.
    real_client = httpx.AsyncClient

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(recording)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(update_check.httpx, "AsyncClient", client_factory)
    return seen


def _github(release: httpx.Response | None = None, compare: httpx.Response | None = None):
    """A handler answering the two paths the way GitHub does, each overridable."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/releases/latest"):
            return release or httpx.Response(200, json=_release_body())
        if "/compare/" in request.url.path:
            return compare or httpx.Response(200, json=_compare_body("ahead"))
        return httpx.Response(599, text=f"unexpected request: {request.url}")

    return handler


def _stamp(monkeypatch, version: str) -> None:
    from app.core import update_check

    monkeypatch.setattr(update_check, "get_app_version", lambda: version)


@pytest.mark.parametrize("stamp", [SHORT, FULL], ids=["7-char stamp", "40-char stamp"])
@pytest.mark.parametrize(
    ("status", "available"),
    [("ahead", False), ("identical", False), ("behind", True), ("diverged", True)],
)
async def test_the_verdict_for_every_compare_status_under_both_stamp_widths(monkeypatch, stamp, status, available) -> None:
    """`ahead`: this build is past the release (a pod built from main after the tag) —
    current, and the case #407 exists for. `diverged`: the build does not contain the
    release, so there is one to take."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, stamp)
    seen = _serve(monkeypatch, _github(compare=httpx.Response(200, json=_compare_body(status))))

    result = await get_update_status()

    assert result.update_available is available
    assert (result.latest_tag, result.release_url, result.latest_sha) == (TAG, RELEASE_PAGE, RELEASE_SHA)
    assert result.reason is None and result.enabled is True and result.current_version == stamp
    # The stamp goes into the path exactly as stamped: GitHub resolves either width.
    assert seen[1].url.path == f"/repos/LoonSecIO/LoonInspect/compare/{TAG}...{stamp.partition('+')[2]}"


async def test_it_asks_the_release_then_the_compare_and_identifies_itself(monkeypatch) -> None:
    from app.core.config import settings
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, SHORT)
    seen = _serve(monkeypatch, _github())
    await get_update_status()

    assert [str(request.url) for request in seen] == [f"{API}/releases/latest", f"{API}/compare/{TAG}...{BUILD_SHA[:7]}"]
    for request in seen:
        assert request.headers["accept"] == "application/vnd.github+json"
        # 60 requests an hour per address, shared by every instance behind it: the
        # User-Agent is what makes a rate-limited fleet attributable.
        assert request.headers["user-agent"].startswith(f"{settings.user_agent_product_name}/")
        assert request.headers["user-agent"].endswith(" update-check")


async def test_no_release_yet_is_named_and_nothing_is_compared(monkeypatch) -> None:
    """Today's state (2026-09-13): only a draft exists, and `releases/latest` answers 404.
    Unknown, so no banner — and the reason says it, rather than looking like being current."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, SHORT)
    seen = _serve(monkeypatch, _github(release=httpx.Response(404, json={"message": "Not Found"})))

    result = await get_update_status()

    assert (result.update_available, result.reason) == (None, "no_release")
    assert result.latest_tag is None and result.checked_at is not None
    assert len(seen) == 1


async def test_a_commit_github_does_not_know_is_named_and_the_release_is_still_named(monkeypatch) -> None:
    """A local or forked build: compare answers 404. The release exists and is worth
    naming on the Updates block, but whether this build contains it cannot be said."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, "2026.09.18+deadbee")
    _serve(monkeypatch, _github(compare=httpx.Response(404, json={"message": "Not Found"})))

    result = await get_update_status()

    assert (result.update_available, result.reason) == (None, "unknown_commit")
    assert (result.latest_tag, result.release_url, result.latest_sha) == (TAG, RELEASE_PAGE, None)


RATE_LIMITED = {
    # GitHub's primary limit: 403 with the budget's own headers saying it is spent.
    "primary 403": httpx.Response(
        403,
        headers={"x-ratelimit-limit": "60", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1789999999"},
        json={"message": "API rate limit exceeded for 203.0.113.7."},
    ),
    # Its secondary limit: 403 with Retry-After.
    "secondary 403": httpx.Response(
        403, headers={"retry-after": "60"}, json={"message": "You have exceeded a secondary rate limit."}
    ),
    # 429 is a limit wherever it comes from.
    "429": httpx.Response(429, json={"message": "Too Many Requests"}),
}


@pytest.mark.parametrize("limit", list(RATE_LIMITED), ids=list(RATE_LIMITED))
@pytest.mark.parametrize("which", ["release", "compare"])
async def test_a_rate_limit_is_named_not_swallowed_as_offline(monkeypatch, which, limit) -> None:
    """The shared 60-an-hour budget. Before #407 it was indistinguishable from being
    offline, and a fleet behind one NAT had no way to see why its check never said anything."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, SHORT)
    _serve(monkeypatch, _github(**{which: RATE_LIMITED[limit]}))

    result = await get_update_status()

    assert (result.update_available, result.reason) == (None, "refused")


@pytest.mark.parametrize("which", ["release", "compare"])
async def test_a_proxys_403_is_unreachable_not_the_rate_limit(monkeypatch, which) -> None:
    """A corporate proxy blocking api.github.com answers 403 with its own page and none of
    GitHub's rate-limit headers. Called `refused`, the Updates block would blame the shared
    budget and troubleshooting §10 would have the operator turn the check off everywhere
    but one instance; `unreachable` is the answer whose words name a proxy."""
    from app.core.update_check import get_update_status

    blocked = httpx.Response(
        403, headers={"content-type": "text/html"}, text="<html><h1>Access denied</h1>Policy: dev-tools</html>"
    )
    _stamp(monkeypatch, SHORT)
    _serve(monkeypatch, _github(**{which: blocked}))

    result = await get_update_status()

    assert (result.update_available, result.reason) == (None, "unreachable")


def _timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("timed out", request=request)


@pytest.mark.parametrize(
    "handler",
    [
        pytest.param(_timeout, id="a timeout"),
        pytest.param(_github(release=httpx.Response(500, json={})), id="the release answers 500"),
        pytest.param(_github(compare=httpx.Response(502, text="bad gateway")), id="the compare answers 502"),
        pytest.param(_github(release=httpx.Response(200, text="<html>sign in to the wifi</html>")), id="a captive portal"),
        pytest.param(_github(release=httpx.Response(200, json={"id": 1})), id="a release with no tag_name"),
        pytest.param(_github(compare=httpx.Response(200, json={"status": "sideways"})), id="a compare status nobody wrote"),
        # Not a string at all, from a provider that is not GitHub: no answer, never a
        # TypeError surfacing as a 500 on every page load.
        pytest.param(_github(compare=httpx.Response(200, json={"status": ["behind"]})), id="a compare status that is a list"),
        pytest.param(
            _github(compare=httpx.Response(200, json={"status": {"behind": 1}})), id="a compare status that is an object"
        ),
    ],
)
async def test_no_answer_is_unreachable_never_current(monkeypatch, handler) -> None:
    """None, never False: False claims "checked, and you are up to date", the one answer a
    security product must not invent when it does not know (#43)."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, SHORT)
    _serve(monkeypatch, handler)

    result = await get_update_status()

    assert (result.update_available, result.reason) == (None, "unreachable")


@pytest.mark.parametrize("stamp", ["0.0.0-dev+local", "2026.08.30+unknown", "2026.08.30", "2026.08.30+../../orgs"])
async def test_an_unidentifiable_build_is_named_and_never_calls_out(monkeypatch, stamp) -> None:
    """A dev build, an image built without GIT_SHA, and a stamp that is not a sha have
    nothing to compare, and the last must never reach a URL path."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, stamp)
    seen = _serve(monkeypatch, _github())

    result = await get_update_status()

    assert (result.update_available, result.reason, result.enabled) == (None, "dev_build", True)
    assert seen == [], "a build with no comparable sha still reached the network"


async def test_disabled_is_named_and_never_calls_out(monkeypatch) -> None:
    from app.core.config import settings
    from app.core.update_check import get_update_status

    monkeypatch.setattr(settings, "update_check", False)
    _stamp(monkeypatch, SHORT)
    seen = _serve(monkeypatch, _github())

    result = await get_update_status()

    assert (result.enabled, result.update_available, result.reason) == (False, None, "disabled")
    assert seen == []


async def test_one_check_is_two_calls_and_the_answer_is_cached(monkeypatch) -> None:
    """Every signed-in page load asks `/system/update-status`; without the cache that is
    two api.github.com calls per request and a 403 within the hour."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, SHORT)
    seen = _serve(monkeypatch, _github())

    first = await get_update_status()
    second = await get_update_status()

    assert len(seen) == 2
    assert first.checked_at == second.checked_at and second.update_available is False


@pytest.mark.parametrize(("reason", "asks_again"), [("refused", True), ("unreachable", True), ("no_release", False)])
async def test_a_failure_is_retried_within_the_hour_and_an_answer_is_kept_for_the_day(monkeypatch, reason, asks_again) -> None:
    """`no_release` is GitHub's answer, not a failure to get one, so it keeps the day's
    cache; a refusal or no answer at all is asked again after an hour."""
    from app.core import update_check

    two_hours_ago = datetime.now(UTC) - timedelta(hours=2)
    update_check._cache = update_check._CacheEntry(
        checked_at=two_hours_ago, answer=update_check._Answer(update_available=None, reason=reason)
    )
    _stamp(monkeypatch, SHORT)
    seen = _serve(monkeypatch, _github())

    result = await update_check.get_update_status()

    assert bool(seen) is asks_again
    assert result.reason == (None if asks_again else reason)


async def test_the_release_page_is_only_ever_an_https_link(monkeypatch) -> None:
    """`release_url` is rendered as an `href`, and the provider is whatever UPDATE_CHECK_URL
    names; anything but https is dropped and the rest of the answer stands."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, SHORT)
    _serve(monkeypatch, _github(release=httpx.Response(200, json=_release_body(html_url="javascript:alert(1)"))))

    result = await get_update_status()

    assert result.release_url is None and result.latest_tag == TAG and result.update_available is False


async def test_the_override_names_a_base_and_the_tag_is_quoted_into_the_path(monkeypatch) -> None:
    from app.core.config import settings
    from app.core.update_check import get_update_status

    monkeypatch.setattr(settings, "update_check_url", "https://mirror.example/repos/acme/inspect/")
    _stamp(monkeypatch, SHORT)
    seen = _serve(monkeypatch, _github(release=httpx.Response(200, json=_release_body(tag="v2026.09.17 rc/1"))))

    await get_update_status()

    assert str(seen[0].url) == "https://mirror.example/repos/acme/inspect/releases/latest"
    assert seen[1].url.raw_path == f"/repos/acme/inspect/compare/v2026.09.17%20rc%2F1...{BUILD_SHA[:7]}".encode()


async def test_the_route_passes_every_field_through(monkeypatch) -> None:
    """A field the dataclass carries and the route forgets is a name the page never sees."""
    from app.api import system
    from app.core.update_check import UpdateStatus

    checked = datetime(2026, 9, 18, 9, 0, tzinfo=UTC)

    async def status() -> UpdateStatus:
        return UpdateStatus(
            enabled=True,
            current_version=SHORT,
            update_available=True,
            latest_sha=RELEASE_SHA,
            checked_at=checked,
            latest_tag=TAG,
            release_url=RELEASE_PAGE,
            reason=None,
        )

    monkeypatch.setattr(system, "get_update_status", status)
    body = (await system.update_status()).model_dump(mode="json", by_alias=True)

    assert body == {
        "enabled": True,
        "currentVersion": SHORT,
        "updateAvailable": True,
        "latestSha": RELEASE_SHA,
        "checkedAt": "2026-09-18T09:00:00Z",
        "latestTag": TAG,
        "releaseUrl": RELEASE_PAGE,
        "reason": None,
    }
