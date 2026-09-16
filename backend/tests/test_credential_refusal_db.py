"""A stored credential that is not a credential (#393), against a real Postgres.

The fixtures that found this were two connections created for the tenant-switcher work
whose encrypted credentials decrypt to `{}`. They were active, so every sweep tick built
`JamfCredentials` from an empty object, wrote pydantic's two-paragraph report into
`runs.error`, and put a `run.failed` event on the outbox behind it — a diagnostic that
needs source code to read, repeating every ten minutes, for as long as nobody noticed.

Three things are asserted here and each is a separate promise:

1. the refusal is a sentence that names the connection and the missing field, and says
   nothing about pydantic;
2. the second refusal on the same connection in the same UTC day puts no second event on
   the outbox — the run row still records it, the alarm does not repeat;
3. the same sentence comes back on the connection's own row, so an operator finds it on
   Settings > Connections without opening a run.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

from tests.jamf_fake import HOST  # noqa: E402


@pytest_asyncio.fixture(loop_scope="session")
async def no_credential(db):
    """An active Jamf connection whose stored credentials decrypt to `{}` — the exact
    shape of the two fixtures the defect was found on. Deliberately written straight to
    the row: the create route validates, so this state is only reachable the way it was
    actually reached, by a row that predates the validation or was seeded around it.

    Note that no `jamf` fixture is needed anywhere in this file. That is the point of
    refusing at the sweep's start: nothing is ever fetched.
    """
    from app.models.schema import Collection, MdmConnection, MdmSyncState

    tag = uuidlib.uuid4().hex[:8]
    row = MdmConnection(
        name=f"credential refusal {tag}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({}),
    )
    # Its healthy twin, so "a usable credential reports nothing" is asserted against a row
    # this file owns rather than against whatever the shared database happens to hold.
    healthy = MdmConnection(
        name=f"credential fine {tag}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"client_id": "client", "client_secret": "secret"}),
    )
    db.add_all([row, healthy])
    await db.commit()
    ids = [row.id, healthy.id]
    try:
        yield row, healthy
    finally:
        # `runs`, `run_log` and the outbox rows the runs produced go by cascade or stay
        # as harmless history; the collections the sweep created do not cascade cleanly
        # into the next run of this suite, so they are removed by hand.
        await db.rollback()
        await db.execute(delete(Collection).where(Collection.mdm_connection_id.in_(ids)))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id.in_(ids)))
        await db.execute(delete(MdmConnection).where(MdmConnection.id.in_(ids)))
        await db.commit()


async def _runs_of(db, connection_id: int) -> list:
    from app.models.schema import Run

    return list(
        (await db.execute(select(Run).where(Run.mdm_connection_id == connection_id).order_by(Run.started_at))).scalars().all()
    )


async def _run_failed_events_of(db, connection_id: int) -> list:
    """Every run.failed event this connection produced, matched by payload rather than by
    recency — the shared local database accumulates events across tests."""
    from app.models.schema import EventOutbox

    rows = (
        (await db.execute(select(EventOutbox).where(EventOutbox.event_type == "run.failed").order_by(EventOutbox.id)))
        .scalars()
        .all()
    )
    return [row for row in rows if row.payload.get("connectionID") == connection_id]


async def _sweep(db, connection):
    from app.core.runs import TRIGGER_SWEEP
    from app.mdm.service import sync_connection

    return await sync_connection(db, connection, trigger=TRIGGER_SWEEP)


async def test_sweep_refuses_with_a_sentence_not_a_traceback(db, no_credential) -> None:
    """The run says what to do, for which connection, and which field is missing."""
    connection, _ = no_credential
    name = connection.name
    result = await _sweep(db, connection)

    assert result.ok is False
    assert result.error is not None
    assert name in result.error
    assert "clientId" in result.error
    assert "Settings › Connections" in result.error
    # The whole point of the issue: never the library's text. `pydantic` appears in the
    # class name, the URL it appends and the phrase "validation errors for" — checking
    # the one word covers the report however it is formatted.
    assert "pydantic" not in result.error.lower()
    assert "validation error" not in result.error.lower()

    runs = await _runs_of(db, connection.id)
    assert len(runs) == 1, "one refused sweep is one run"
    assert runs[0].status == "failed"
    assert runs[0].error == result.error


async def test_a_second_refusal_the_same_day_emits_no_second_event(db, no_credential) -> None:
    """The row records every refusal; the outbox gets one a day.

    Asserted on the events rather than on a flag, because the tick storm was the damage:
    a connection refusing every ten minutes put 144 identical alarms a day on every
    destination subscribed to run.failed.
    """
    connection, _ = no_credential
    await _sweep(db, connection)
    await _sweep(db, connection)

    runs = await _runs_of(db, connection.id)
    assert len(runs) == 2, "both refusals are recorded as runs"
    assert [row.status for row in runs] == ["failed", "failed"]

    events = await _run_failed_events_of(db, connection.id)
    assert len(events) == 1, "the second identical refusal today adds no alarm"
    assert events[0].payload["jobID"] == str(runs[0].id)
    assert connection.name in events[0].payload["error"]

    # And the suppression is recorded where an operator would look for the missing
    # alarm — the run's own log, not only in the process log.
    from app.models.schema import RunLogLine

    lines = (await db.execute(select(RunLogLine.message).where(RunLogLine.run_id == runs[1].id))).scalars().all()
    assert any("already reported this failure today" in line for line in lines)


async def test_the_connection_row_carries_the_same_sentence(db, no_credential) -> None:
    """Reportable state: Settings > Connections says it without anyone opening a run."""
    from app.api.connections import list_connections

    connection, healthy = no_credential
    rows = await list_connections(db=db)
    row = next(item for item in rows if item.id == connection.id)

    assert row.credential_problem is not None
    assert connection.name in row.credential_problem
    assert "clientId" in row.credential_problem
    assert "pydantic" not in row.credential_problem.lower()
    # camelCase on the wire, like every other key this response carries.
    assert row.model_dump(by_alias=True)["credentialProblem"] == row.credential_problem

    twin = next(item for item in rows if item.id == healthy.id)
    assert twin.credential_problem is None, "a usable credential reports nothing"
