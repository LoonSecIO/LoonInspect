"""SecurityHeadersMiddleware (#186, the v0 half of the #133 rulings): the four headers
the app can be sure of about its own artifact, plus a relayed Strict-Transport-Security
that only appears when the operator sets a max-age. CSP is deliberately not here — #187.

Mounted on a bare FastAPI app rather than importing app.main, matching
test_health.py's pattern: this suite needs no scheduler and no database.
`/api/health` is the real route (app.api.routes, `ping` mocked healthy); the 401 route
is synthetic, since a real 401 needs the full auth/session stack and only the
*middleware's* behaviour is under test here, not authentication itself. `/docs` and
`/redoc` are registered exactly as `app.main` registers them.

test_session_cookies_db.py is the precedent for the shape half of these need: it
asserts on `Set-Cookie` including its absence, which is exactly what the HSTS-off and
security_headers=False assertions below do for headers instead of cookies.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.testclient import TestClient

from app.api import routes
from app.core.config import settings
from app.core.middleware import SecurityHeadersMiddleware

_FOUR_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "same-origin",
    "permissions-policy": (
        "accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), midi=(), payment=(), usb=()"
    ),
}


async def _ok() -> None:
    return None


def _app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    api = FastAPI()
    api.include_router(routes.router)
    monkeypatch.setattr(routes, "ping", _ok)

    @api.get("/protected")
    async def protected() -> None:
        raise HTTPException(status_code=401, detail="not authenticated")

    # Registered exactly as app.main registers them (see main.py's /docs, /redoc).
    @api.get("/docs", include_in_schema=False)
    async def swagger_ui():
        return get_swagger_ui_html(openapi_url="/openapi.json", title="test")

    @api.get("/redoc", include_in_schema=False)
    async def redoc_ui():
        return get_redoc_html(openapi_url="/openapi.json", title="test")

    api.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # Registered last, same as main.py, so it ends up outermost and wraps CORS.
    api.add_middleware(SecurityHeadersMiddleware)
    return api


def _client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return TestClient(_app(monkeypatch), raise_server_exceptions=False)


def _assert_four_headers(headers) -> None:
    for name, value in _FOUR_HEADERS.items():
        assert headers.get(name) == value, f"{name}: got {headers.get(name)!r}"


class TestFourHeadersAlwaysPresent:
    def test_on_a_200(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with _client(monkeypatch) as client:
            response = client.get("/api/health")
        assert response.status_code == 200
        _assert_four_headers(response.headers)

    def test_on_a_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with _client(monkeypatch) as client:
            response = client.get("/protected")
        assert response.status_code == 401
        _assert_four_headers(response.headers)

    def test_on_a_404(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with _client(monkeypatch) as client:
            response = client.get("/this-route-does-not-exist")
        assert response.status_code == 404
        _assert_four_headers(response.headers)

    def test_on_a_cors_preflight(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with _client(monkeypatch) as client:
            response = client.options(
                "/api/health",
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "GET",
                },
            )
        assert response.status_code == 200
        _assert_four_headers(response.headers)

    def test_on_docs_and_redoc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with _client(monkeypatch) as client:
            for path in ("/docs", "/redoc"):
                response = client.get(path)
                assert response.status_code == 200, path
                _assert_four_headers(response.headers)

    def test_clipboard_write_is_deliberately_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ApiTokensPage.tsx copies a freshly minted API token to the clipboard on the
        one screen where the value is unrecoverable if not copied — a tidy-looking
        `clipboard-write=()` would break that. Regression guard, not a style check."""
        with _client(monkeypatch) as client:
            response = client.get("/api/health")
        assert "clipboard-write" not in response.headers["permissions-policy"]


class TestHSTSIsARelayNotADefault:
    def test_absent_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with _client(monkeypatch) as client:
            response = client.get("/api/health")
        assert "strict-transport-security" not in response.headers

    def test_present_with_exact_max_age_when_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "hsts_max_age", 31536000)
        with _client(monkeypatch) as client:
            response = client.get("/api/health")
        value = response.headers["strict-transport-security"]
        assert value == "max-age=31536000", value
        assert "includesubdomains" not in value.lower()
        assert "preload" not in value.lower()

    def test_zero_means_never_emit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "hsts_max_age", 0)
        with _client(monkeypatch) as client:
            response = client.get("/api/health")
        assert "strict-transport-security" not in response.headers


class TestSecurityHeadersIsOneKnob:
    def test_false_suppresses_all_five_including_hsts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The assertion that makes "one knob" true rather than aspirational: turning
        the boolean off must suppress HSTS too, even with a max-age configured."""
        monkeypatch.setattr(settings, "security_headers", False)
        monkeypatch.setattr(settings, "hsts_max_age", 31536000)

        with _client(monkeypatch) as client:
            response = client.get("/api/health")

        assert response.status_code == 200
        for name in (*_FOUR_HEADERS, "strict-transport-security"):
            assert name not in response.headers, f"{name} present with security_headers=False"

    def test_true_is_the_default(self) -> None:
        assert settings.security_headers is True
