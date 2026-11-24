"""Update provider failures stay actionable and private (#836); only mocks and loopback."""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.core import update_check
from app.core.config import settings
from app.core.logging import ConsoleFormatter, JsonFormatter
from tests.test_update_check import _release_body, _serve

MARKER = "synthetic-private-update-value-836"


@pytest.fixture(autouse=True)
def isolate_proxy_settings(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


async def _attempt(shape, monkeypatch, base="https://127.0.0.1:1"):
    address = base + ("/v1/update" if shape == "service" else "/repos/example/project")
    monkeypatch.setattr(settings, "update_check_url", address)
    if shape == "service":
        _, reason = await update_check._ask_service(address, {"contract": "v1"})
        return reason
    return (await update_check._ask("abcdef1")).reason


def _one_safe_diagnostic(caplog, expected, level=logging.WARNING):
    records = [record for record in caplog.records if record.name == "app.core.update_check"]
    assert len(records) == 1
    assert expected in records[0].getMessage() and "retry in an hour" in records[0].getMessage()
    assert records[0].levelno == level
    assert MARKER not in caplog.text
    assert records[0].exc_info is None


@pytest.mark.parametrize("part", ["service", "release", "compare"])
async def test_deep_json_is_unreachable_and_names_response_format(monkeypatch, caplog, part):
    def answer(request):
        if part == "compare" and request.url.path.endswith("/releases/latest"):
            return httpx.Response(200, json=_release_body())
        return httpx.Response(200, text="[" * 100_000 + MARKER)

    _serve(monkeypatch, answer)
    assert await _attempt("service" if part == "service" else "github", monkeypatch) == "unreachable"
    _one_safe_diagnostic(caplog, "JSON nesting limit")


@pytest.mark.parametrize("shape", ["service", "github"])
@pytest.mark.parametrize("proxy", ["port", "socks"])
async def test_unusable_real_proxy_configuration_is_unreachable(monkeypatch, caplog, shape, proxy):
    # The provider and proxy both point at loopback; no real provider can be reached.
    if proxy == "socks":
        monkeypatch.setitem(sys.modules, "socksio", None)
        monkeypatch.setenv("ALL_PROXY", f"socks5://user:{MARKER}@127.0.0.1:99999")
    else:
        monkeypatch.setenv("HTTPS_PROXY", f"http://user:{MARKER}@127.0.0.1:99999")
    assert await _attempt(shape, monkeypatch) == "unreachable"
    _one_safe_diagnostic(caplog, "proxy transport is unavailable" if proxy == "socks" else "proxy port")


@pytest.mark.parametrize("target", ["http://127.0.0.1:99999/x", "http://127.0.0.1:-1/x", "//127.0.0.1:99999/x"])
async def test_real_redirect_with_impossible_port_is_unreachable(monkeypatch, caplog, target):
    async def redirect(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            location = target + "?credential=" + MARKER
            writer.write(f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async with await asyncio.start_server(redirect, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        assert await _attempt("github", monkeypatch, f"http://127.0.0.1:{port}") == "unreachable"
    _one_safe_diagnostic(caplog, "redirect or proxy")


@pytest.mark.parametrize("shape", ["service", "github"])
@pytest.mark.parametrize("cause", ["offline", "portal", "portal_latin1"])
async def test_no_route_or_a_page_that_is_not_json_logs_at_debug_only(monkeypatch, caplog, shape, cause):
    # An air-gapped instance meets these every hour forever: a configuration, not a fault (README: leave
    # UPDATE_CHECK on). A warning would fire log-based alerting 24 times a day for a supported setup.
    if cause != "offline":  # offline: a real client against loopback port 1, which refuses
        body = b"<html>" + MARKER.encode() + (b"\xe9" if cause == "portal_latin1" else b"") + b"</html>"
        _serve(monkeypatch, lambda request: httpx.Response(200, content=body, headers={"content-type": "text/html"}))
    with caplog.at_level(logging.DEBUG, logger="app.core.update_check"):
        assert await _attempt(shape, monkeypatch) == "unreachable"
    expected = "could not be reached" if cause == "offline" else "not JSON"
    _one_safe_diagnostic(caplog, expected, level=logging.DEBUG)


@pytest.mark.parametrize("shape", ["service", "github"])
@pytest.mark.parametrize("bundle", ["missing", "not_pem", "directory"])
async def test_unloadable_ca_bundle_is_unreachable_and_names_ssl_cert_file(monkeypatch, caplog, tmp_path, shape, bundle):
    # docs/splunk-setup.md §5 mounts a CA bundle through SSL_CERT_FILE; a wrong path or file is an operator's
    # setting, read when the real client is built, not an internal fault.
    path = tmp_path / MARKER
    if bundle == "not_pem":
        path.write_text("not a certificate\n")
    elif bundle == "directory":
        path.mkdir()
    monkeypatch.setenv("SSL_CERT_FILE", str(path if bundle != "missing" else path / "ca.pem"))
    assert await _attempt(shape, monkeypatch) == "unreachable"
    _one_safe_diagnostic(caplog, "SSL_CERT_FILE")


async def test_group_with_an_unexpected_failure_is_not_misreported_as_a_provider_failure(monkeypatch):
    def fail(request):
        raise ExceptionGroup(MARKER, [OverflowError(MARKER), RuntimeError(MARKER)])

    _serve(monkeypatch, fail)
    with pytest.raises(ExceptionGroup):
        await _attempt("github", monkeypatch)


async def test_cancellation_still_propagates(monkeypatch):
    def fail(request):
        raise asyncio.CancelledError()

    _serve(monkeypatch, fail)
    with pytest.raises(asyncio.CancelledError):
        await _attempt("github", monkeypatch)


@pytest.mark.parametrize("database", [True, False])
async def test_scheduler_only_names_database_for_database_failures(monkeypatch, caplog, database):
    from app import main

    monkeypatch.setattr(main.logger, "handlers", [caplog.handler])
    monkeypatch.setattr(main.logger, "propagate", False)
    exc = SQLAlchemyError("synthetic database unavailable") if database else RuntimeError(MARKER)
    monkeypatch.setattr(main, "update_check", AsyncMock(side_effect=exc))
    await main.update_check_tick()
    record = next(record for record in caplog.records if record.name == "app.main")
    assert ("database" in record.getMessage()) is database
    if not database:
        assert "RuntimeError" in record.getMessage() and "Settings" in record.getMessage()
        assert MARKER not in caplog.text and record.exc_info is None


@pytest.mark.parametrize("database", [True, False])
async def test_both_scheduler_lines_begin_with_the_phrase_the_docs_and_hint_quote(monkeypatch, caplog, database):
    # The Updates block's *Owed now* hint and docs/troubleshooting.md §10 send the operator to grep for it.
    from app import main

    monkeypatch.setattr(main.logger, "handlers", [caplog.handler])
    monkeypatch.setattr(main.logger, "propagate", False)
    exc = SQLAlchemyError("synthetic database unavailable") if database else RuntimeError(MARKER)
    monkeypatch.setattr(main, "update_check", AsyncMock(side_effect=exc))
    await main.update_check_tick()
    record = next(record for record in caplog.records if record.name == "app.main")
    assert record.getMessage().startswith("update check could not run")


async def test_unexpected_failure_logs_its_frames_but_not_its_text(monkeypatch, caplog):
    from app import main

    def deep_in_the_check():
        raise RuntimeError(MARKER)

    async def check():
        deep_in_the_check()

    monkeypatch.setattr(main.logger, "handlers", [caplog.handler])
    monkeypatch.setattr(main.logger, "propagate", False)
    monkeypatch.setattr(main, "update_check", check)
    await main.update_check_tick()
    record = next(record for record in caplog.records if record.name == "app.main")
    assert record.exc_info is None and record.error_type == "RuntimeError"
    assert all(re.fullmatch(r"[\w.-]+\.py:\d+:[\w<>]+", frame) for frame in record.stack)
    assert [frame.rsplit(":", 1)[1] for frame in record.stack] == ["update_check_tick", "check", "deep_in_the_check"]
    for formatter in (ConsoleFormatter(), JsonFormatter()):  # what reaches the container log
        line = formatter.format(record)
        assert "deep_in_the_check" in line and "stack locations" in line and MARKER not in line
