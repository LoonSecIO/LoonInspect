"""`/api/health` has to be able to say no.

The endpoint was `return {"status": "ok"}` and touched nothing, which was demonstrated
live: with the database holding zero tables and every authenticated endpoint returning
500, the probe still answered 200 and the container still reported healthy. The
Dockerfile HEALTHCHECK and the Fargate task definition both call this URL and nothing
else, so nothing would ever have restarted the container and no monitor watching the
documented endpoint would ever have fired.

Two properties are pinned here, and the second is the security one:

  * the verdict tracks the database, in both directions, and is bounded in time; and
  * the failure body says only *which* dependency is down. This route is in
    `_PUBLIC_EXACT` — anyone who can reach the port reads it, without a session — so a
    DSN, a password, a container hostname or a driver traceback in that body is free
    reconnaissance handed to an unauthenticated caller.

Mounts the router on a bare FastAPI app rather than importing `app.main`, which would
start a scheduler and open a database — the same pattern as test_webhook_auth.py.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError

from app.api import routes
from app.core.auth import is_public_path

# Everything a leak would look like, in one place. The DSN below is fictional and is
# never connected to; it exists so the assertions have a secret to look for.
_PASSWORD = "sup3rsecret-database-password"
_HOST = "db.internal.example.com"
_DSN = f"postgresql+asyncpg://looninspect_app:{_PASSWORD}@{_HOST}:5432/looninspect"


def _client(monkeypatch: pytest.MonkeyPatch, ping) -> TestClient:
    api = FastAPI()
    api.include_router(routes.router)
    monkeypatch.setattr(routes, "ping", ping)
    # raise_server_exceptions=False so an unhandled error becomes a 500 response the
    # test can read, rather than an exception raised into the test itself.
    return TestClient(api, raise_server_exceptions=False)


def _assert_body_is_clean(text: str) -> None:
    for secret in (_PASSWORD, _HOST, _DSN, "looninspect_app", "asyncpg", "Traceback", "sqlalchemy"):
        assert secret not in text, f"the unauthenticated failure body leaked {secret!r}: {text}"


async def _ok() -> None:
    return None


class TestHealthTracksTheDatabase:
    def test_ok_when_the_database_answers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The shape the CI image smoke test asserts on: `curl -fsS` and the
        HEALTHCHECK's `urlopen(...).read()` both require a 2xx, and both still get
        one against a healthy stack."""
        with _client(monkeypatch, _ok) as client:
            response = client.get("/api/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_503_when_the_connection_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A crashed Postgres, or a network partition: the socket never opens."""

        async def refused() -> None:
            raise ConnectionRefusedError(f"[Errno 111] Connect call failed to {_HOST}:5432")

        with _client(monkeypatch, refused) as client:
            response = client.get("/api/health")

        assert response.status_code == 503
        assert response.json() == {"status": "unavailable", "reason": "database"}

    def test_503_when_the_pool_is_exhausted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The outage that leaves the process healthy and the product dead. SQLAlchemy
        raises its own TimeoutError here, which is a SQLAlchemyError and not the
        builtin — a check that only caught the builtin would 500 on the single most
        likely production failure."""

        async def exhausted() -> None:
            raise SQLAlchemyTimeoutError("QueuePool limit of size 5 overflow 10 reached")

        with _client(monkeypatch, exhausted) as client:
            response = client.get("/api/health")

        assert response.status_code == 503
        assert response.json() == {"status": "unavailable", "reason": "database"}

    def test_503_when_the_database_hangs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A database that has stopped answering rather than refusing. Without the
        bound the request hangs until the probe's own client-side timeout, which marks
        the container unhealthy with no response and no log line naming the cause."""
        monkeypatch.setattr(routes, "_HEALTH_TIMEOUT_SECONDS", 0.05)

        async def hangs() -> None:
            await asyncio.sleep(30)

        with _client(monkeypatch, hangs) as client:
            response = client.get("/api/health")

        assert response.status_code == 503
        assert response.json() == {"status": "unavailable", "reason": "database"}

    def test_an_unexpected_error_is_not_dressed_up_as_an_outage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """503 means "the database is down", and has to keep meaning that. A bug in
        this process is a 500 — which fails the probe just as loudly, without telling
        the operator to go and look at Postgres."""

        async def broken() -> None:
            raise ValueError("a bug in the probe itself")

        with _client(monkeypatch, broken) as client:
            response = client.get("/api/health")

        assert response.status_code == 500


class TestHealthLeaksNothing:
    """The endpoint is unauthenticated. These are the assertions that keep it cheap to
    leave that way."""

    @pytest.mark.parametrize(
        "failure",
        [
            pytest.param(OSError(f"connection to {_HOST}:5432 refused"), id="oserror"),
            pytest.param(
                OperationalError(f"connect to {_DSN}", None, ConnectionRefusedError()),
                id="driver-error",
            ),
        ],
    )
    def test_the_failure_body_names_only_the_failure_class(
        self, monkeypatch: pytest.MonkeyPatch, failure: Exception
    ) -> None:
        async def fails() -> None:
            raise failure

        with _client(monkeypatch, fails) as client:
            response = client.get("/api/health")

        assert response.status_code == 503
        _assert_body_is_clean(response.text)
        assert response.json() == {"status": "unavailable", "reason": "database"}

    def test_a_real_driver_failure_leaks_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The synthetic exceptions above are only as good as the guess behind them, so
        this one is real: a genuine engine pointed at a closed port, with a password and
        a hostname in its DSN, connected through the actual `ping()`. Whatever asyncpg
        and SQLAlchemy put in that exception, none of it may reach the response.

        Port 1 rather than an unroutable address: it refuses immediately instead of
        spending the connect timeout, so this stays a fast test.
        """
        from sqlalchemy.ext.asyncio import create_async_engine

        from app.core import database

        dead = create_async_engine(
            f"postgresql+asyncpg://looninspect_app:{_PASSWORD}@127.0.0.1:1/looninspect"
        )
        monkeypatch.setattr(database, "engine", dead)

        api = FastAPI()
        api.include_router(routes.router)
        with TestClient(api, raise_server_exceptions=False) as client:
            response = client.get("/api/health")

        assert response.status_code == 503
        _assert_body_is_clean(response.text)
        assert response.json() == {"status": "unavailable", "reason": "database"}


def test_health_stays_reachable_without_a_session() -> None:
    """The probe presents no credential and cannot be given one — the HEALTHCHECK runs
    `python -c` inside the container with no cookie jar. If health ever leaves the
    public allowlist the container is unhealthy from its first probe, so this failing
    is the cheap way to find that out."""
    assert is_public_path("/api/health") is True
