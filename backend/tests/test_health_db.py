"""`/api/health` against a real Postgres, through the real app.

test_health.py substitutes `ping()` and so proves the endpoint's logic. What it cannot
prove is that the liveness query actually succeeds as the app's own non-superuser,
NOBYPASSRLS role, on a request that carries no session and therefore has no tenant
bound — which is every probe the container ever makes. A `SELECT 1` that needed a
tenant GUC, or a role that could not run it, would leave a healthy stack permanently
reporting 503 and restarting itself.

Needs a real Postgres like every session test; gated on RUN_DB_TESTS. See
test_tenancy_sweep.py for the local invocation pattern.
"""

from __future__ import annotations

import os

import httpx
import pytest
import pytest_asyncio

# One event loop for the whole module — the engine's pooled connections belong to
# whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"
    ),
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def migrated() -> None:
    from app.core.database import init_db

    await init_db()


def _client() -> httpx.AsyncClient:
    from app.main import app

    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://health.example.com"
    )


async def test_health_is_200_for_an_anonymous_caller_against_a_live_database(
    migrated: None,
) -> None:
    """The whole stack, no cookie, no header — exactly what the HEALTHCHECK sends.

    This is also the assertion that keeps the CI image smoke test honest: it runs
    `curl -fsS http://localhost:8001/api/health`, which fails the job on any non-2xx.
    """
    async with _client() as c:
        response = await c.get("/api/health")

    assert response.status_code == 200, response.text
    assert response.json() == {"status": "ok"}
