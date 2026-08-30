"""The update check's success path, which has never run anywhere (INSPECT-0176).

`_GITHUB_HEAD_URL` points at this repository's commits API. While the repo is
private that URL 404s for an unauthenticated caller, `_fetch_head_sha` swallows the
error by design (#43: a failed check must be indistinguishable from being current),
and so `update_available` has been permanently None in every deployment that has
ever existed. The comparison, the parse, and the banner have never once executed.

Publication turns the endpoint on everywhere at once, in already-running containers,
with `update_check: bool = True` by default — the first real-world exercise would
otherwise be a customer's. These tests are that exercise, run here instead.

The sharp edge is the sha width. A local build stamps the SHORT sha
(`docker-compose.yml`: `git rev-parse --short HEAD`) while CI stamps the FULL 40
characters (`ci.yml`, `publish-images.yml`: `github.sha`), and GitHub always answers
with 40. `_status_from` handles both with `latest_sha.startswith(current_sha)` — it
is correct, and these tests exist so it stays correct, because an off-by-one here
reports every instance as permanently behind or permanently current and the silent
error handling guarantees nobody would notice.

No database and no network: httpx.MockTransport feeds a real GitHub response body
through the real parse.
"""

from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio

HEAD_SHA = "99361ed4b2c1a7f0e8d5c3b6a4917f2e0d8c5b3a"  # 40 chars, as GitHub returns


def _github_commit_body(sha: str) -> dict:
    """The shape api.github.com/repos/{owner}/{repo}/commits/main actually returns,
    trimmed to the fields near the one we read. The point of keeping the wrapper
    objects is that `.json().get("sha")` must pick the TOP-LEVEL sha, not
    `commit.tree.sha` — a plausible mistake that a bare {"sha": ...} would hide."""
    return {
        "sha": sha,
        "node_id": "C_kwDOABCD",
        "commit": {
            "message": "INSPECT-0000: a commit",
            "tree": {"sha": "0000000000000000000000000000000000000000"},
        },
        "parents": [{"sha": "1111111111111111111111111111111111111111"}],
    }


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Each test gets a cold cache and the check enabled.

    The module caches across calls with a TTL, so without this the second test in
    the file would silently assert against the first one's answer.
    """
    from app.core import update_check
    from app.core.config import settings

    monkeypatch.setattr(update_check, "_cache", None)
    monkeypatch.setattr(settings, "update_check", True)
    yield
    monkeypatch.setattr(update_check, "_cache", None)


def _serve(monkeypatch, handler) -> None:
    """Point the module's httpx at a MockTransport, leaving its own request code —
    URL, headers, raise_for_status, json parse — running for real."""
    from app.core import update_check

    # Bind the real class first: update_check.httpx IS the global httpx module, so
    # the setattr below rebinds httpx.AsyncClient everywhere — including inside this
    # factory, which would then call itself forever.
    real_client = httpx.AsyncClient

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(update_check.httpx, "AsyncClient", client_factory)


def _stamp(monkeypatch, version: str) -> None:
    from app.core import update_check

    monkeypatch.setattr(update_check, "get_app_version", lambda: version)


@pytest.mark.parametrize(
    ("stamp", "expected_available", "case"),
    [
        (f"2026.08.30+{HEAD_SHA[:7]}", False, "short stamp, same commit — the local-build form"),
        (f"2026.08.30+{HEAD_SHA}", False, "full stamp, same commit — the CI form"),
        ("2026.08.20+deadbee", True, "short stamp, older commit"),
        ("2026.08.20+" + "d" * 40, True, "full stamp, older commit"),
    ],
)
async def test_behindness_is_decided_correctly_for_both_stamp_widths(
    monkeypatch, stamp, expected_available, case
) -> None:
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, stamp)
    _serve(monkeypatch, lambda request: httpx.Response(200, json=_github_commit_body(HEAD_SHA)))

    status = await get_update_status()

    assert status.update_available is expected_available, case
    assert status.latest_sha == HEAD_SHA
    assert status.current_version == stamp
    assert status.enabled is True


async def test_it_asks_the_right_url_and_identifies_itself(monkeypatch) -> None:
    """The request that has never actually been sent to a server that answers."""
    from app.core.update_check import _GITHUB_HEAD_URL, get_update_status

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_github_commit_body(HEAD_SHA))

    _stamp(monkeypatch, f"2026.08.30+{HEAD_SHA[:7]}")
    _serve(monkeypatch, handler)
    await get_update_status()

    assert len(seen) == 1
    assert str(seen[0].url) == _GITHUB_HEAD_URL
    assert seen[0].headers["accept"] == "application/vnd.github+json"
    # Unauthenticated api.github.com is 60 requests/hour per IP, shared by every
    # instance behind one egress address. The User-Agent is what makes a
    # rate-limited fleet diagnosable, so pin that this call is attributable and says
    # which subsystem made it — build_user_agent's shape is "<product>/<version>
    # <comment>", where the product is settings.user_agent_product_name.
    from app.core.config import settings

    user_agent = seen[0].headers["user-agent"]
    assert user_agent.startswith(f"{settings.user_agent_product_name}/")
    assert user_agent.endswith(" update-check")


@pytest.mark.parametrize(
    ("status_code", "case"),
    [
        (404, "private repo, or renamed — today's behaviour everywhere"),
        (403, "rate limited: 60/hour per IP, shared by every instance behind one NAT"),
        (500, "provider having a bad day"),
    ],
)
async def test_an_unhappy_provider_is_unknown_not_current(monkeypatch, status_code, case) -> None:
    """None, never False. False claims "checked, and you are up to date" — the one
    answer a security product must not invent when it does not know (#43)."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, f"2026.08.30+{HEAD_SHA[:7]}")
    _serve(monkeypatch, lambda request: httpx.Response(status_code, json={}))

    status = await get_update_status()

    assert status.update_available is None, case
    assert status.latest_sha is None


async def test_a_malformed_body_is_unknown_not_current(monkeypatch) -> None:
    """A 200 carrying something that is not the commit object. Worth its own case:
    this is the shape a captive portal or a misconfigured proxy returns."""
    from app.core.update_check import get_update_status

    _stamp(monkeypatch, f"2026.08.30+{HEAD_SHA[:7]}")
    _serve(monkeypatch, lambda request: httpx.Response(200, text="<html>login</html>"))

    status = await get_update_status()

    assert status.update_available is None
    assert status.latest_sha is None


@pytest.mark.parametrize("stamp", ["0.0.0-dev+local", "2026.08.30+unknown", "2026.08.30"])
async def test_an_unidentifiable_build_never_calls_out(monkeypatch, stamp) -> None:
    """A dev build and an image built without GIT_SHA have nothing to compare, so the
    check must not fire at all — asserted on the transport, not just the verdict."""
    from app.core.update_check import get_update_status

    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json=_github_commit_body(HEAD_SHA))

    _stamp(monkeypatch, stamp)
    _serve(monkeypatch, handler)

    status = await get_update_status()

    assert status.update_available is None
    assert called is False, "a build with no comparable sha still reached the network"


async def test_the_answer_is_cached_rather_than_asked_every_time(monkeypatch) -> None:
    """Every signed-in page load hits /system/update-status; without the cache that
    would be one api.github.com call per request and a 403 within the hour."""
    from app.core.update_check import get_update_status

    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_github_commit_body(HEAD_SHA))

    _stamp(monkeypatch, f"2026.08.30+{HEAD_SHA[:7]}")
    _serve(monkeypatch, handler)

    first = await get_update_status()
    second = await get_update_status()

    assert calls == 1
    assert first.update_available is second.update_available is False
    assert first.checked_at == second.checked_at


async def test_disabled_means_disabled(monkeypatch) -> None:
    from app.core.config import settings
    from app.core.update_check import get_update_status

    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json=_github_commit_body(HEAD_SHA))

    monkeypatch.setattr(settings, "update_check", False)
    _stamp(monkeypatch, f"2026.08.30+{HEAD_SHA[:7]}")
    _serve(monkeypatch, handler)

    status = await get_update_status()

    assert status.enabled is False
    assert status.update_available is None
    assert called is False
