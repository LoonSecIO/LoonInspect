"""One tenant's failure does not end a scheduled tick for the tenants behind it (#466).

Six scheduled loops in `app.main` iterate every operational tenant. Three of them always
guarded the per-tenant body; the outbox tick and the two nightly purges did not, so the
first tenant whose work raised ended the pass for every tenant sorted after it — the
outbox tick indefinitely, every thirty seconds, with nothing in the container log naming
a tenant and `GET /api/destinations` reporting a rising `pendingCount` and
`lastError: null` for tenants nothing had been attempted for.

Pinned here in the pure lane on purpose: the tenant list and the per-tenant session are
stubbed, so what each test exercises is the loop's control flow and the words it logs,
which is the whole of the change. The tenancy of these jobs — that each tenant's work
happens in a session scoped to it — is `test_tenancy_sweep.py`'s subject and is not
restated here.
"""

from __future__ import annotations

import logging
import uuid as uuidlib
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest

from app import main

# Sorted by slug in the real loop; here simply first and second.
TENANT_A = uuidlib.UUID("00000000-0000-0000-0000-0000000004a6")
TENANT_B = uuidlib.UUID("00000000-0000-0000-0000-0000000004b6")


@pytest.fixture
def two_tenants(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two operational tenants, and a per-tenant job that reaches no database.

    The stub yields the tenant id where the real one yields an `AsyncSession`, so the
    collaborators below can tell whose pass they are in from the argument they are given.
    """

    async def tenant_ids() -> list[uuidlib.UUID]:
        return [TENANT_A, TENANT_B]

    @asynccontextmanager
    async def tenant_job(tenant_id: uuidlib.UUID) -> AsyncIterator[uuidlib.UUID]:
        yield tenant_id

    monkeypatch.setattr(main, "operational_tenant_ids", tenant_ids)
    monkeypatch.setattr(main, "tenant_job", tenant_job)


def _dies_for_a(seen: list[uuidlib.UUID], result: int = 0) -> Callable[..., Any]:
    """A collaborator that records whose pass called it and raises in tenant A's."""

    async def collaborator(db: uuidlib.UUID, *args: Any) -> int:
        seen.append(db)
        if db == TENANT_A:
            raise RuntimeError("this tenant's row is unusable")
        return result

    return collaborator


def _failure(caplog: pytest.LogCaptureFixture) -> logging.LogRecord:
    """The one ERROR the tick logged, asserted to be about tenant A and to keep its
    traceback — `logger.exception`, not a swallowed exception."""
    [record] = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.tenant_id == str(TENANT_A)
    assert record.exc_info is not None
    return record


async def test_the_outbox_tick_delivers_for_the_next_tenant(
    two_tenants: None, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fanned: list[uuidlib.UUID] = []
    delivered: list[uuidlib.UUID] = []
    monkeypatch.setattr(main, "fan_out_pending", _dies_for_a(fanned))
    monkeypatch.setattr(main, "deliver_pending", _dies_for_a(delivered))

    with caplog.at_level(logging.ERROR, logger="app.main"):
        await main.outbox_worker_tick()

    assert fanned == [TENANT_A, TENANT_B]
    assert delivered == [TENANT_B]  # A never got past its fan-out
    message = _failure(caplog).getMessage()
    assert message.startswith("outbox tick failed for this tenant")
    assert "Destinations page" in message  # the next check, in the operator's words


async def test_the_outbox_cleanup_purges_for_the_next_tenant(
    two_tenants: None, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    purged: list[uuidlib.UUID] = []
    monkeypatch.setattr(main, "purge_delivered_events", _dies_for_a(purged, result=3))

    with caplog.at_level(logging.INFO, logger="app.main"):
        await main.outbox_cleanup()

    assert purged == [TENANT_A, TENANT_B]
    assert _failure(caplog).getMessage().startswith("outbox cleanup failed for this tenant")
    # And tenant B's pass still reported what it removed, rather than A's count.
    [done] = [r for r in caplog.records if r.getMessage() == "purged old outbox events"]
    assert (done.tenant_id, done.count) == (str(TENANT_B), 3)


async def test_the_run_cleanup_purges_for_the_next_tenant(
    two_tenants: None, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    runs: list[uuidlib.UUID] = []
    alerts: list[uuidlib.UUID] = []
    monkeypatch.setattr(main, "purge_runs", _dies_for_a(runs, result=2))
    monkeypatch.setattr(main, "purge_closed_alerts", _dies_for_a(alerts, result=1))

    with caplog.at_level(logging.INFO, logger="app.main"):
        await main.run_cleanup()

    assert runs == [TENANT_A, TENANT_B]
    assert alerts == [TENANT_B]  # A never got past its runs
    assert _failure(caplog).getMessage().startswith("run cleanup failed for this tenant")
    assert [r.getMessage() for r in caplog.records if r.levelno == logging.INFO] == [
        "purged old runs",
        "purged closed alerts",
    ]
