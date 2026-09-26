"""Submission cases (#623) under PostgreSQL row-level security: a sent case stays in its tenant with its
key stored encrypted, while `send`, `refresh` and `withdraw` commit what they learn."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select, text, update

from tests.test_submissions import ACK, STATUS, WIRESHARK, Stub, preview_on  # noqa: F401 (autouse here too)
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
