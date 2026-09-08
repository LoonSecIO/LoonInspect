"""Content-Security-Policy (#187): one policy for the shell the app built, a second
scoped to exactly /docs and /redoc, and a value — not a toggle — to override either.

What can be asserted without a docker build is the header string per route, the
exact-match guard, the override's three states, and two source-level facts the policy
depends on: the shell carries no inline script (the pre-paint theme script lives in its
own file), and the docs pages name no third party but jsdelivr. What cannot be asserted
here — that the built shell loads with zero console violations — is the manual pass the
pull request records.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.core.config import settings
from app.core.middleware import (
    APP_CONTENT_SECURITY_POLICY,
    DOCS_CONTENT_SECURITY_POLICY,
    content_security_policy_for,
    content_security_policy_mode,
)
from tests.test_security_headers import _FOUR_HEADERS, _client

REPO = Path(__file__).resolve().parents[2]


# --- the two policies, on the wire ---------------------------------------------------------


def test_an_app_route_gets_the_strict_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client(monkeypatch) as client:
        response = client.get("/api/health")
    assert response.headers["content-security-policy"] == APP_CONTENT_SECURITY_POLICY


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_the_docs_pages_get_the_page_scoped_policy(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    with _client(monkeypatch) as client:
        response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-security-policy"] == DOCS_CONTENT_SECURITY_POLICY


@pytest.mark.parametrize("path", ["/docsomething", "/redocs", "/redoc/x", "/api/docs"])
def test_the_docs_policy_is_an_exact_match_not_a_prefix(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    """`startswith("/docs")` would hand the CDN policy to /docsomething, which the SPA
    catch-all happily serves as the shell."""
    with _client(monkeypatch) as client:
        response = client.get(path)
    assert response.headers["content-security-policy"] == APP_CONTENT_SECURITY_POLICY


def test_the_trailing_slash_redirect_carries_the_strict_policy_and_its_target_the_docs_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`/docs/` is not `/docs`: the 307 that sends the browser to the real page gets the
    app policy, and only the page itself gets the CDN one."""
    with _client(monkeypatch) as client:
        redirect = client.get("/docs/", follow_redirects=False)
        assert redirect.status_code in (301, 307, 308)
        assert redirect.headers["content-security-policy"] == APP_CONTENT_SECURITY_POLICY
        assert client.get("/docs").headers["content-security-policy"] == DOCS_CONTENT_SECURITY_POLICY


def test_the_policy_rides_every_response_including_a_401_and_a_404(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client(monkeypatch) as client:
        for path, status in (("/protected", 401), ("/this-route-does-not-exist", 404)):
            response = client.get(path)
            assert response.status_code == status
            assert response.headers["content-security-policy"] == APP_CONTENT_SECURITY_POLICY


# --- what the strict policy says -------------------------------------------------------


def test_the_strict_policy_directive_by_directive() -> None:
    directives = dict(part.strip().split(" ", 1) for part in APP_CONTENT_SECURITY_POLICY.split(";"))
    assert directives["script-src"] == "'self'", "no inline script, no hash, no nonce: the theme script is a file"
    assert directives["style-src"] == "'self' 'unsafe-inline'", "the one accepted weakness, for the style attributes"
    assert directives["connect-src"] == "'self'"
    assert directives["frame-ancestors"] == "'none'"
    assert directives["frame-src"] == "'none'"
    assert directives["object-src"] == "'none'"
    assert directives["base-uri"] == "'self'"
    assert directives["form-action"] == "'self'"
    assert "upgrade-insecure-requests" not in APP_CONTENT_SECURITY_POLICY, "plain-HTTP deployments are supported"
    assert "report-uri" not in APP_CONTENT_SECURITY_POLICY and "report-to" not in APP_CONTENT_SECURITY_POLICY


def test_the_docs_policy_names_two_third_parties_and_nothing_google() -> None:
    """jsdelivr for the code and styles; cdn.redoc.ly for one image, ReDoc's footer logo,
    which the bundle loads on its own. Neither Google host, because main.py turns the
    fonts off; not fastapi.tiangolo.com, because main.py passes our own favicon."""
    directives = dict(part.strip().split(" ", 1) for part in DOCS_CONTENT_SECURITY_POLICY.split(";"))
    assert set(re.findall(r"https://[a-z0-9.-]+", directives["script-src"])) == {"https://cdn.jsdelivr.net"}
    assert set(re.findall(r"https://[a-z0-9.-]+", directives["style-src"])) == {"https://cdn.jsdelivr.net"}
    assert set(re.findall(r"https://[a-z0-9.-]+", directives["img-src"])) == {"https://cdn.redoc.ly"}
    assert set(re.findall(r"https://[a-z0-9.-]+", DOCS_CONTENT_SECURITY_POLICY)) == {
        "https://cdn.jsdelivr.net",
        "https://cdn.redoc.ly",
    }
    assert directives["worker-src"] == "'self' blob:", "ReDoc's search index runs in a blob-URL worker"
    assert "'unsafe-inline'" in directives["script-src"], "FastAPI's helpers emit an inline init script"


# --- the value, not the toggle ----------------------------------------------------------


def test_unset_means_the_built_in_policies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "content_security_policy", "")
    assert content_security_policy_mode() == "default"
    assert content_security_policy_for("/api/health") == APP_CONTENT_SECURITY_POLICY
    assert content_security_policy_for("/docs") == DOCS_CONTENT_SECURITY_POLICY


def test_a_custom_policy_is_sent_verbatim_on_every_route_and_replaces_both(monkeypatch: pytest.MonkeyPatch) -> None:
    custom = "default-src 'self'; connect-src 'self' https://api.example.com"
    monkeypatch.setattr(settings, "content_security_policy", custom)
    assert content_security_policy_mode() == "custom"
    with _client(monkeypatch) as client:
        assert client.get("/api/health").headers["content-security-policy"] == custom
        assert client.get("/docs").headers["content-security-policy"] == custom


@pytest.mark.parametrize("spelling", ["off", "OFF", " off "])
def test_off_sends_no_csp_and_keeps_the_other_headers(monkeypatch: pytest.MonkeyPatch, spelling: str) -> None:
    """The four-knob argument, answered: an operator whose page the CSP broke can drop
    it alone, without losing nosniff, the frame denial, the referrer policy or the
    permissions policy."""
    monkeypatch.setattr(settings, "content_security_policy", spelling)
    assert content_security_policy_mode() == "off"
    with _client(monkeypatch) as client:
        response = client.get("/api/health")
    assert "content-security-policy" not in response.headers
    for name, value in _FOUR_HEADERS.items():
        assert response.headers.get(name) == value


def test_the_one_knob_still_turns_everything_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "security_headers", False)
    with _client(monkeypatch) as client:
        response = client.get("/api/health")
    assert "content-security-policy" not in response.headers
    assert "x-frame-options" not in response.headers


# --- the two source-level facts the policy depends on --------------------------------


def test_the_shell_carries_no_inline_script() -> None:
    """The durable guard against a future contributor re-inlining something
    `script-src 'self'` will kill — the pre-auth theme flash would be the first sign."""
    shell = (REPO / "frontend" / "index.html").read_text()
    tags = re.findall(r"<script\b[^>]*>", shell)
    assert tags, "the shell has no script tags at all?"
    for tag in tags:
        assert re.search(r"\bsrc=", tag), f"inline script in index.html: {tag}"
    assert 'src="/theme.js"' in shell
    theme = REPO / "frontend" / "public" / "theme.js"
    assert theme.exists(), "index.html loads /theme.js, which frontend/public must carry"
    assert "prefers-color-scheme" in theme.read_text()


@pytest.mark.asyncio
async def test_the_docs_pages_name_no_third_party_but_jsdelivr() -> None:
    """The three arguments main.py passes keep the favicon and the fonts same-origin;
    without them the docs policy would have to name fastapi.tiangolo.com and two Google
    hosts as well."""
    from app.main import redoc_ui, swagger_ui

    for page in (await swagger_ui(), await redoc_ui()):
        body = page.body.decode()
        hosts = set(re.findall(r"https://([a-z0-9.-]+)", body))
        assert hosts == {"cdn.jsdelivr.net"}, hosts
        assert "/favicon.svg" in body
