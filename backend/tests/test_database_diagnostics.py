"""Database values do not become request diagnostics or persisted fetch errors."""

from __future__ import annotations

import io
import logging
import sys
import uuid
from contextlib import asynccontextmanager

import httpx
import pytest
from sqlalchemy.exc import DBAPIError, IntegrityError, StatementError
from uvicorn import Config
from uvicorn.lifespan.on import LifespanOn

from app.core.database import engine
from app.core.diagnostics import database_error_message, error_text
from app.core.logging import ConsoleFormatter, ContextFilter, JsonFormatter
from app.core.middleware import RequestContextMiddleware
from app.core.runs import AcquisitionBusy
from app.mdm.concurrency import IngestBusy, lock_device
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


class LockNotAvailable(Exception):
    sqlstate = "55P03"


class UniqueViolation(Exception):
    sqlstate = "23505"


async def _ingest_busy() -> IngestBusy:
    """lock_device's own translation of Postgres refusing a contended lock wait."""

    class ContendedSession:
        def __init__(self):
            self.info = {"tenant_id": str(uuid.uuid4())}

        async def scalar(self, *args, **kwargs):
            return False

        @asynccontextmanager
        async def begin_nested(self):
            raise DBAPIError("SELECT pg_advisory_xact_lock(:key)", {"key": SECRET}, LockNotAvailable(PERSON))
            yield

    with pytest.raises(IngestBusy) as caught:
        await lock_device(ContendedSession(), 1, "macos", "1")
    return caught.value


def _acquisition_busy() -> AcquisitionBusy:
    """The shape runs.acquire raises when an active-run conflict has no visible holder."""
    try:
        try:
            raise IntegrityError(f"INSERT INTO runs VALUES ('{PROMPT}')", {"secret": SECRET}, UniqueViolation(PERSON))
        except IntegrityError:
            raise AcquisitionBusy(1, "sweep") from None
    except AcquisitionBusy as exc:
        return exc


@pytest.mark.parametrize("busy", ["ingest", "acquisition"])
async def test_a_suppressed_database_context_keeps_the_retry_instruction(busy):
    # `raise ... from None` hides the database error from Python's own traceback, and
    # the operator's sentence is the retry instruction, not a database health check.
    exc = await _ingest_busy() if busy == "ingest" else _acquisition_busy()
    assert isinstance(exc.__context__, DBAPIError) and exc.__suppress_context__
    assert database_error_message(exc) is None
    for message in (error_text(exc), fetch_error(exc)):
        assert message == str(exc) and "Retry shortly" in message
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "operation failed", (), (type(exc), exc, exc.__traceback__))
    for formatter in (JsonFormatter(), ConsoleFormatter()):
        rendered = formatter.format(record)
        assert "Retry shortly" in rendered and "The database operation failed" not in rendered
        assert all(value not in rendered for value in MARKERS)


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


@pytest.mark.parametrize("formatter", [JsonFormatter, ConsoleFormatter])
@pytest.mark.parametrize("phase", ["startup", "shutdown"])
@pytest.mark.parametrize("wrapped", ["direct", "cause", "group", "non_database"])
async def test_lifespan_database_failures_are_safe_before_uvicorn_formats_them(formatter, phase, wrapped, monkeypatch):
    from app import main

    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(formatter())
    for name in ("app.main", "uvicorn.error"):
        logger = logging.getLogger(name)
        monkeypatch.setattr(logger, "handlers", [handler])
        monkeypatch.setattr(logger, "propagate", False)
        monkeypatch.setattr(logger, "disabled", False)
        monkeypatch.setattr(logger, "level", logging.INFO)

    unrelated_message = "The TLS certificate is unreadable. Check its configured path."

    def fail():
        if wrapped == "non_database":
            raise ValueError(unrelated_message)
        try:
            raise database_failure()
        except StatementError as exc:
            if wrapped == "cause":
                raise RuntimeError(f"wrapper repeated {SECRET}") from exc
            if wrapped == "group":
                raise ExceptionGroup(PROMPT, [ValueError(PERSON), exc]) from None
            raise

    @asynccontextmanager
    async def synthetic_lifecycle(app):
        if phase == "startup":
            fail()
        yield
        if phase == "shutdown":
            fail()

    # Keep the real app lifespan wrapper and Starlette/Uvicorn protocol; replace
    # database, worker and provider work so this test never accesses a service.
    monkeypatch.setattr(main, "_application_lifespan", synthetic_lifecycle)
    server = LifespanOn(Config(main.app, lifespan="on", log_config=None))
    await server.startup()
    if phase == "shutdown":
        assert not server.startup_failed
        await server.shutdown()
    assert server.should_exit
    assert server.startup_failed if phase == "startup" else server.shutdown_failed

    rendered = output.getvalue()
    assert all(value not in rendered for value in MARKERS)
    if wrapped == "non_database":
        assert unrelated_message in rendered and "ValueError" in rendered
        assert "The database operation failed" not in rendered
    else:
        assert f"Application {phase} failed." in rendered
        assert "StatementError; SQLSTATE 22001" in rendered
        assert "Check database health" in rendered
        assert "Database failure stack (values withheld)" in rendered
        assert "test_database_diagnostics.py" in rendered
        assert "[SQL:" not in rendered and "[parameters:" not in rendered
