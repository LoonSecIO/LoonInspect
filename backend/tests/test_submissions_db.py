"""Submission cases (#623) under PostgreSQL row-level security: a sent case stays in its tenant with its
key stored encrypted, while `send`, `refresh` and `withdraw` commit what they learn, and the nightly clock
clears what was written once the service's 90 days are up."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import delete, select, text, update

from tests.test_submissions import ACK, STATUS, WIRESHARK, WORDS, Stub, preview_on  # noqa: F401 (autouse here too)
from tests.test_vuln_library_db import foreign_tenant  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def test_a_sent_case_stays_in_its_tenant_with_its_key_stored_encrypted(db, foreign_tenant):  # noqa: F811
    from app.core import submissions
    from app.models.schema import SubmissionCase

    fields = {"kind": "coverage", "versions": ["3.6.2"], "text": "Seen on every Mac we run.", "permission_at": datetime.now(UTC)}
    db.add(case := SubmissionCase(**(WIRESHARK | fields | {"case_key": submissions.mint_case_key()})))
    stub = Stub(None, (202, ACK), (200, STATUS), (200, STATUS | {"state": "withdrawn"}))
    case = await submissions.send(db, case, transport=httpx.MockTransport(stub))
    stored = await db.scalar(text("SELECT case_key FROM submission_cases WHERE id = :id"), {"id": case.id})
    assert case.state == "received" and stored.startswith("k1:") and case.case_key not in stored
    assert (await foreign_tenant.execute(select(SubmissionCase))).scalars().all() == []
    assert (await foreign_tenant.execute(update(SubmissionCase).values(text="rewritten"))).rowcount == 0
    await foreign_tenant.commit()
    for act in (submissions.refresh, submissions.withdraw):
        await act(db, case, transport=httpx.MockTransport(stub))
    case = await db.get(SubmissionCase, case.id, populate_existing=True)
    assert (case.state, case.text) == ("withdrawn", None) and case.last_status_at and case.withdrawn_at
    await db.delete(case)
    await db.commit()


async def test_the_clock_clears_what_was_written_90_days_after_a_case_closed_and_nothing_else(db, foreign_tenant):  # noqa: F811
    from app.core import submissions
    from app.models.schema import SubmissionCase

    now = datetime.now(UTC)
    typed = {"public_url": "https://example.org/wireshark-3.6.2", "text": WORDS["text"], "contact": WORDS["contact"]}
    kept = ("app_name", "bundle_id", "versions", "state", "received_at", "closed_at", "release", "coverage", "note")

    def case(state: str, closed_days_ago: int | None = None, **changes) -> SubmissionCase:
        closed = None if closed_days_ago is None else now - timedelta(days=closed_days_ago)
        heard = {"state": state, "closed_at": closed, "received_at": now - timedelta(days=200), "note": "Seen."}
        fields = WIRESHARK | WORDS | typed | heard | {"release": "ab" * 32, "coverage": "Both builds."}
        return SubmissionCase(**(fields | {"case_key": submissions.mint_case_key()} | changes))

    rows = {
        "declined 91 days ago": case("declined", 91),
        "published 91 days ago": case("published", 91),
        "expired": case("expired"),
        "published 89 days ago": case("published", 89),
        "open a year": case("reviewing", created_at=now - timedelta(days=365)),
        "never sent": case("pending", received_at=None),
    }
    cleared = {"declined 91 days ago", "published 91 days ago", "expired"}
    db.add_all(rows.values())
    await db.commit()
    foreign_tenant.add(theirs := case("expired"))
    await foreign_tenant.commit()
    ids = [row.id for row in [*rows.values(), theirs]]  # read now: a rollback expires them
    before = {name: [getattr(row, field) for field in kept] for name, row in rows.items()}
    try:
        assert await submissions.forget_closed(db) == 3
        assert await submissions.forget_closed(db) == 0, "a second night finds nothing left to clear"
        await db.rollback()  # what was committed
        for name, row in rows.items():
            await db.refresh(row)
            assert {field: getattr(row, field) for field in typed} == (dict.fromkeys(typed) if name in cleared else typed), name
            assert [getattr(row, field) for field in kept] == before[name], name
        await foreign_tenant.refresh(theirs)
        assert theirs.text == typed["text"], "another tenant's cases wait for its own night"
    finally:
        for session in (db, foreign_tenant):
            await session.rollback()
            await session.execute(delete(SubmissionCase).where(SubmissionCase.id.in_(ids)))
            await session.commit()
