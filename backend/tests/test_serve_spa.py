"""serve_spa's response policy (#172, split out of #170): validators that actually
earn a 304, Cache-Control per file class, HEAD handled (not 405), and a miss under
assets/ returning 404 instead of the SPA shell as 200.

No database. `backend/app/static/` does not exist in a checkout, so `app.main`'s
catch-all route is never registered against the real `app.main.app` — that's #170's
own finding (`static_dir.exists()` is False in every dev run and every backend test),
and it means no pytest can reach the *real, registered* route either. This suite
instead calls the three always-defined helpers (`_resolve_static_asset`,
`_not_modified`, `_static_response`) directly against a fake `static_dir` under
`tmp_path`, and separately mounts a thin route on a bare FastAPI app that calls those
same real helpers, to exercise the HTTP-level concerns (HEAD, status codes,
compression) through a real TestClient. The route wrapper duplicates serve_spa's
~10-line dispatch shape, but none of its actual logic — that all lives in the
imported, real, production helper functions.

Importing `app.main` for those helpers (not the `app` object, never wrapped in
`TestClient` as a context manager) never starts the scheduler or opens a database —
only `lifespan` does that, and nothing here triggers it.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.testclient import TestClient

from app import main as app_main


def _fake_request(headers: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
    }
    return Request(scope)


@pytest.fixture
def static_dir(tmp_path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "static"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<html>shell</html>")
    # Padded well past GZipMiddleware's default minimum_size=500 so compression tests
    # have something worth compressing.
    (root / "assets" / "app-abc123.js").write_text("console.log(1);\n" * 200)
    (root / "favicon.svg").write_text("<svg></svg>")
    monkeypatch.setattr(app_main, "static_dir", root)
    return root


def _spa_app(static_dir) -> FastAPI:
    """Same dispatch shape as app.main's serve_spa, calling the same real helpers —
    see the module docstring for why this wrapper exists instead of the real route."""
    api = FastAPI()
    api.add_middleware(GZipMiddleware)

    @api.api_route("/{full_path:path}", methods=["GET", "HEAD"])
    async def serve_spa(full_path: str, request: Request):
        if full_path.startswith("api/") or full_path.startswith("webhooks/"):
            raise HTTPException(status_code=404, detail="Not Found")

        asset = app_main._resolve_static_asset(full_path)
        if asset is not None:
            cache_control = (
                app_main._IMMUTABLE_CACHE_CONTROL
                if full_path.startswith(app_main._ASSETS_PREFIX)
                else app_main._NO_CACHE_CACHE_CONTROL
            )
            return app_main._static_response(request, asset, cache_control=cache_control)

        if full_path.startswith(app_main._ASSETS_PREFIX):
            raise HTTPException(status_code=404, detail="Not Found")

        return app_main._static_response(
            request, static_dir / "index.html", cache_control=app_main._NO_CACHE_CACHE_CONTROL
        )

    return api


class TestResolveStaticAsset:
    def test_resolves_a_real_asset(self, static_dir) -> None:
        resolved = app_main._resolve_static_asset("assets/app-abc123.js")
        assert resolved == static_dir / "assets" / "app-abc123.js"

    def test_none_for_a_missing_file(self, static_dir) -> None:
        assert app_main._resolve_static_asset("assets/does-not-exist.js") is None

    def test_none_for_traversal(self, static_dir) -> None:
        assert app_main._resolve_static_asset("../../../etc/passwd") is None

    def test_none_for_empty_path(self, static_dir) -> None:
        assert app_main._resolve_static_asset("") is None


class TestNotModified:
    """Pure logic, no filesystem — mirrors starlette.staticfiles.is_not_modified."""

    def test_matching_etag_is_not_modified(self) -> None:
        request = _fake_request({"if-none-match": '"abc123"'})
        assert app_main._not_modified('"abc123"', None, request) is True

    def test_mismatched_etag_is_modified(self) -> None:
        request = _fake_request({"if-none-match": '"other"'})
        assert app_main._not_modified('"abc123"', None, request) is False

    def test_weak_prefix_is_ignored(self) -> None:
        request = _fake_request({"if-none-match": 'W/"abc123"'})
        assert app_main._not_modified('"abc123"', None, request) is True

    def test_multiple_etags_in_if_none_match(self) -> None:
        request = _fake_request({"if-none-match": '"nope", "abc123", "also-not-it"'})
        assert app_main._not_modified('"abc123"', None, request) is True

    def test_if_modified_since_at_or_after_last_modified(self) -> None:
        request = _fake_request({"if-modified-since": "Wed, 01 Sep 2026 12:00:00 GMT"})
        assert app_main._not_modified(None, "Wed, 01 Sep 2026 12:00:00 GMT", request) is True

    def test_if_modified_since_before_last_modified(self) -> None:
        request = _fake_request({"if-modified-since": "Wed, 01 Sep 2026 11:00:00 GMT"})
        assert app_main._not_modified(None, "Wed, 01 Sep 2026 12:00:00 GMT", request) is False

    def test_no_validators_at_all_is_modified(self) -> None:
        request = _fake_request({})
        assert app_main._not_modified('"abc123"', "Wed, 01 Sep 2026 12:00:00 GMT", request) is False

    def test_if_none_match_wins_over_if_modified_since(self) -> None:
        """RFC 9110 §13.1.3: a client sending both means If-None-Match governs."""
        request = _fake_request(
            {"if-none-match": '"other"', "if-modified-since": "Wed, 01 Sep 2026 12:00:00 GMT"}
        )
        assert app_main._not_modified('"abc123"', "Wed, 01 Sep 2026 12:00:00 GMT", request) is False


class TestStaticResponse:
    def test_full_response_on_first_request(self, static_dir) -> None:
        response = app_main._static_response(_fake_request({}), static_dir / "index.html", cache_control="no-cache")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-cache"
        assert "etag" in response.headers
        assert "last-modified" in response.headers

    def test_304_on_a_matching_etag(self, static_dir) -> None:
        path = static_dir / "index.html"
        first = app_main._static_response(_fake_request({}), path, cache_control="no-cache")
        etag = first.headers["etag"]

        second = app_main._static_response(_fake_request({"if-none-match": etag}), path, cache_control="no-cache")

        assert second.status_code == 304
        assert second.headers["etag"] == etag
        assert second.headers["cache-control"] == "no-cache"
        assert "content-length" not in second.headers

    def test_200_when_the_file_changed_since_the_etag_was_issued(self, static_dir) -> None:
        path = static_dir / "index.html"
        first = app_main._static_response(_fake_request({}), path, cache_control="no-cache")
        stale_etag = first.headers["etag"]

        path.write_text("<html>a new build, deliberately a different length</html>")

        second = app_main._static_response(_fake_request({"if-none-match": stale_etag}), path, cache_control="no-cache")
        assert second.status_code == 200

    def test_cache_control_is_whatever_the_caller_passed(self, static_dir) -> None:
        path = static_dir / "assets" / "app-abc123.js"
        response = app_main._static_response(
            _fake_request({}), path, cache_control="public, max-age=31536000, immutable"
        )
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"


class TestHttpLevelResponsePolicy:
    def test_asset_hit_gets_immutable_cache_control(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            response = client.get("/assets/app-abc123.js")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"

    def test_index_gets_no_cache(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            response = client.get("/")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-cache"

    def test_asset_miss_is_404_not_the_spa_shell(self, static_dir) -> None:
        """The bug #172 exists to fix: a stale reference used to get the SPA shell
        back as 200 text/html instead of a 404."""
        with TestClient(_spa_app(static_dir)) as client:
            response = client.get("/assets/does-not-exist-abc999.js")
        assert response.status_code == 404
        assert "text/html" not in response.headers.get("content-type", "")

    def test_client_side_route_still_falls_back_to_the_shell(self, static_dir) -> None:
        """Not under assets/ — React Router's territory, unchanged by #172."""
        with TestClient(_spa_app(static_dir)) as client:
            response = client.get("/devices/123")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-cache"
        assert b"shell" in response.content

    def test_api_and_webhooks_prefixes_still_404(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            for path in ("/api/whatever", "/webhooks/whatever"):
                response = client.get(path)
                assert response.status_code == 404, path

    def test_304_round_trip_over_http(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            first = client.get("/assets/app-abc123.js")
            etag = first.headers["etag"]
            second = client.get("/assets/app-abc123.js", headers={"If-None-Match": etag})
        assert second.status_code == 304
        assert second.content == b""


class TestHeadIsHandled:
    def test_head_on_root_is_200_not_405(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            response = client.head("/")
        assert response.status_code == 200
        assert response.content == b""
        assert response.headers.get("cache-control") == "no-cache"

    def test_head_on_an_asset_is_200_not_405(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            response = client.head("/assets/app-abc123.js")
        assert response.status_code == 200
        assert response.content == b""

    def test_head_on_an_asset_miss_is_404_not_405(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            response = client.head("/assets/does-not-exist-abc999.js")
        assert response.status_code == 404


class TestCompression:
    def test_asset_is_gzip_compressed_when_accepted(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            response = client.get("/assets/app-abc123.js", headers={"Accept-Encoding": "gzip"})
        assert response.status_code == 200
        assert response.headers.get("content-encoding") == "gzip"
        # httpx decodes transparently; content must still be the real, uncompressed body.
        assert response.text == "console.log(1);\n" * 200

    def test_not_compressed_when_identity_is_requested(self, static_dir) -> None:
        with TestClient(_spa_app(static_dir)) as client:
            response = client.get("/assets/app-abc123.js", headers={"Accept-Encoding": "identity"})
        assert response.status_code == 200
        assert "content-encoding" not in response.headers
