"""Database values do not become request diagnostics or persisted fetch errors."""

from __future__ import annotations

import io
import logging
import sys

import httpx
import pytest
from sqlalchemy.exc import StatementError

from app.core.database import engine
from app.core.diagnostics import database_error_message, error_text
from app.core.logging import ConsoleFormatter, ContextFilter, JsonFormatter
from app.core.middleware import RequestContextMiddleware
from app.mdm.jamf.errors import fetch_error

SECRET = "synthetic-db-secret-7da41e"
PERSON = "synthetic-person-7da41e@example.invalid"
PROMPT = "synthetic-private-prompt-7da41e"
MARKERS = (SECRET, PERSON, PROMPT)


class DriverFailure(Exception):
    sqlstate = "22001"


def database_failure() -> StatementError:
    # Hiding parameters alone cannot remove the driver detail or literal SQL text.
    return StatementError(
        f"driver rejected {PERSON}",
        f"SELECT '{PROMPT}'",
        {"secret": SECRET},
        DriverFailure(f"rejected value: {PERSON}"),
    )


@pytest.mark.parametrize("formatter", [JsonFormatter, ConsoleFormatter])
@pytest.mark.parametrize("wrapped", ["direct", "cause", "group", "http"])
async def test_middleware_database_exception_keeps_context_without_values(formatter, wrapped, monkeypatch):
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(formatter())
    handler.addFilter(ContextFilter())
    logger = logging.getLogger("app.request")
    monkeypatch.setattr(logger, "handlers", [handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "level", logging.INFO)

    async def app(scope, receive, send):
        try:
            raise database_failure()
        except StatementError as exc:
            if wrapped == "cause":
                raise RuntimeError(f"wrapper repeated {SECRET}") from exc
            if wrapped == "group":
                raise ExceptionGroup(PROMPT, [ValueError(PERSON), exc]) from None
            if wrapped == "http":
                raise httpx.HTTPError(f"HTTP wrapper repeated {SECRET}") from exc
            raise

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        pass

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/devices",
        "client": ("127.0.0.1", 12345),
        "query_string": f"q={PROMPT}".encode(),
        "headers": [(b"x-request-id", b"synthetic-request-7da41e")],
    }
    with pytest.raises((StatementError, RuntimeError, ExceptionGroup, httpx.HTTPError)):
        await RequestContextMiddleware(app)(scope, receive, send)

    rendered = output.getvalue()
    assert all(value not in rendered for value in MARKERS)
    assert "request failed" in rendered and "/api/devices" in rendered
    assert "synthetic-request-7da41e" in rendered or "syntheti" in rendered  # console abbreviates request IDs
    assert "StatementError; SQLSTATE 22001" in rendered
    assert "test_database_diagnostics.py" in rendered and "middleware.py" in rendered
    assert "Check database health" in rendered


def test_group_and_cyclic_context_do_not_reintroduce_database_values():
    failure = database_failure()
    wrapper = RuntimeError(SECRET)
    wrapper.__cause__ = failure
    failure.__context__ = wrapper
    group = ExceptionGroup(PROMPT, [ValueError(PERSON), wrapper])
    for exc in (failure, wrapper, group):
        for message in (database_error_message(exc), error_text(exc), fetch_error(exc)):
            assert all(value not in message for value in MARKERS)
            assert "StatementError; SQLSTATE 22001" in message


def test_driver_code_is_allowlisted_and_parameters_hidden():
    failure = database_failure()
    failure.orig.sqlstate = SECRET
    assert SECRET not in error_text(failure)
    assert "SQLSTATE" not in error_text(failure)
    assert engine.sync_engine.hide_parameters is True


def test_non_database_diagnostics_remain_actionable():
    message = "The API Role lacks Read Computers; grant it and retry."
    exc = ValueError(message)
    assert database_error_message(exc) is None
    assert error_text(exc) == message and fetch_error(exc) == message
    assert "Timed out reading computer inventory" in fetch_error(httpx.ReadTimeout(""))
    try:
        raise exc
    except ValueError:
        record = logging.LogRecord("test", logging.ERROR, __file__, 1, "operation failed", (), sys.exc_info())
    for formatter in (JsonFormatter(), ConsoleFormatter()):
        assert message in formatter.format(record)
