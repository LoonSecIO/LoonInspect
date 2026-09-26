"""The submission routes (#623) on PostgreSQL, the service a `Stub`; no answer may carry a case key."""

from __future__ import annotations

import asyncio
import json
import os
import uuid

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

from tests.test_sharing_send_now_db import _audit_events, _signed_in
from tests.test_submissions import ACK, STATUS, Stub, preview_on  # noqa: F401 (autouse here too)
from tests.test_vuln_library_db import foreign_tenant  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

APP = {"appName": "Wireshark", "bundleId": "org.wireshark.Wireshark", "platform": "macos", "versions": ["3.6.2"]}
BODY, WORDS = {"kind": "coverage"} | APP, {"text": "Seen on every Mac we run.", "contact": "security@example.com"}
SEND, EMAIL = BODY | WORDS | {"permission": True}, "submissions-{}@example.com"


async def _client(role: str) -> httpx.AsyncClient:
    async def keyless(response: httpx.Response) -> None:
        await response.aread()
        assert not any(word in response.text for word in ("loon_case_", "case_key", "caseKey")), response.text

    client = await _signed_in(EMAIL.format(role), EMAIL.format(role))
    client.event_hooks = {"response": [keyless]}
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def admin(db, monkeypatch):
    """An administrator's client and the stand-in service, an auditor and a viewer, no cases, no exclusions."""
    from app.api import submissions as api
    from app.core.bootstrap import create_account
    from app.core.intelligence import locked_settings
    from app.models.schema import Account, SubmissionCase

    for role in ("admin", "auditor", "viewer"):
        if (await db.execute(select(Account).where(Account.email == EMAIL.format(role)))).scalars().first() is None:
            await create_account(db, email=EMAIL.format(role), display_name=role, password=EMAIL.format(role), roles=(role,))
    monkeypatch.setattr(api, "transport_override", httpx.MockTransport(service := Stub(None)))
    await db.execute(delete(SubmissionCase))
    row = await locked_settings(db)
    kept, row.exclude_globs = row.exclude_globs, []
    await db.commit()
    client = await _client("admin")
    try:
        yield client, service
    finally:
        await client.aclose()
        await db.rollback()
        await db.execute(delete(SubmissionCase))
        (await locked_settings(db)).exclude_globs = kept
        await db.commit()


async def test_only_an_administrator_reaches_a_route(admin):
    """View permission is not permission to disclose: the auditor holds SYSTEM_READ, and is refused too."""
    for role in ("auditor", "viewer"):
        client = await _client(role)
        try:
            answers = [await client.get("/api/submissions")]
            for path in ("/preview", "", f"/{uuid.uuid4()}/status", f"/{uuid.uuid4()}/withdraw"):
                answers.append(await client.post("/api/submissions" + path, json=SEND))
        finally:
            await client.aclose()
        assert [answer.status_code for answer in answers] == [403] * 5, role
    assert admin[1].requests == []


async def test_a_case_from_its_preview_to_its_withdrawal(admin):
    client, service = admin
    withdrawn = STATUS | {"state": "withdrawn", "closed_at": "2026-09-27T00:00:00Z"}
    service.answers += [(202, ACK), (200, STATUS | {"state": "reviewing"}), (200, withdrawn)]
    preview = (await client.post("/api/submissions/preview", json=BODY | WORDS)).json()
    fields = {"kind": "coverage", "app_name": "Wireshark", "bundle_id": BODY["bundleId"], "platform": "macos"}
    assert preview == {"payload": {"contract": "v2", **fields, "versions": ["3.6.2"], **WORDS}, "excludedBy": None}
    sent = await client.post("/api/submissions", json=SEND)
    case, wire = sent.json(), json.loads(service.requests[0].content)
    assert sent.status_code == 202 and case["state"] == "received" and wire == preview["payload"] | {"case_key": wire["case_key"]}
    event = _audit_events("submission.sent")[-1]
    assert (event["target_id"], event["metadata"]["app_name"]) == (case["id"], "Wireshark") and wire["case_key"] not in str(event)
    assert (await client.post(f"/api/submissions/{case['id']}/status")).json()["state"] == "reviewing"
    again = await client.post(f"/api/submissions/{case['id']}/status")
    assert again.status_code == 429 and 58 <= int(again.headers["Retry-After"]) <= 60 and len(service.requests) == 2
    gone = (await client.post(f"/api/submissions/{case['id']}/withdraw")).json()
    assert (gone["state"], gone["text"], gone["contact"]) == ("withdrawn", None, None) and gone["withdrawnAt"]
    assert _audit_events("submission.withdrawn")[-1]["target_id"] == case["id"] and len(service.requests) == 3


async def test_nothing_leaves_without_permission_the_preview_or_the_override(admin, db, monkeypatch):
    from app.core.config import settings
    from app.core.intelligence import locked_settings

    client, service = admin
    assert "give permission" in (await client.post("/api/submissions", json=BODY | WORDS)).json()["detail"]
    assert (await client.post("/api/submissions/preview", json=BODY | {"kind": "correction"})).status_code == 422
    (await locked_settings(db)).exclude_globs = ["org.wireshark.*"]
    await db.commit()
    assert (await client.post("/api/submissions/preview", json=BODY)).json()["excludedBy"] == "org.wireshark.*"
    refused = await client.post("/api/submissions", json=SEND)
    assert refused.status_code == 409 and '"org.wireshark.*"' in refused.json()["detail"] and service.requests == []
    service.answers.append((202, ACK))
    sent = (await client.post("/api/submissions", json=SEND | {"excludedOverride": True})).json()
    assert sent["excludedOverride"] is True and _audit_events("submission.excluded-override")[-1]["target_id"] == sent["id"]
    assert (await locked_settings(db)).exclude_globs == ["org.wireshark.*"], "the override never edits the list"
    await db.commit()
    monkeypatch.setattr(settings, "intelligence_access", False)
    for path, body in (("/preview", BODY), ("", SEND | {"text": "A new case."})):
        off = await client.post("/api/submissions" + path, json=body)
        assert off.status_code == 409 and "INTELLIGENCE_ACCESS" in off.json()["detail"]
    listed = (await client.get("/api/submissions")).json()
    assert listed["enabled"] is False and [c["id"] for c in listed["cases"]] == [sent["id"]] and len(service.requests) == 1


async def test_a_correction_previews_its_finding_and_the_release_that_produced_it(admin):
    """Report an incorrect match's body, in the page's own names (frontend `bodyOf`): the payload adds the pair."""
    client, service = admin
    release, empty = "4f1c" * 16, {"publicUrl": None, "text": None, "contact": None}
    body = BODY | empty | {"kind": "correction", "finding": "CVE-2024-0208", "findingRelease": release}
    payload = (await client.post("/api/submissions/preview", json=body)).json()["payload"]
    assert (payload["kind"], payload["finding"], payload["finding_release"]) == ("correction", "CVE-2024-0208", release)
    assert service.requests == []


async def test_send_never_answers_a_withdrawal_the_service_has_not_confirmed(admin):
    """A lost withdrawal answer leaves `withdrawnAt` on a live state (§21 step 8), the words already cleared. The
    same word-less fields then make a new case rather than answer that one, and Withdraw again settles it."""
    client, service = admin
    withdrawn = (200, STATUS | {"state": "withdrawn"})
    for first, version in (((202, ACK), "3.6.2"), ("lost", "3.6.3")):  # received; pending, its send's answer lost too
        bare = BODY | {"versions": [version], "permission": True}
        service.answers += [first, "lost", (202, ACK), withdrawn]
        case = (await client.post("/api/submissions", json=bare)).json()
        left = (await client.post(f"/api/submissions/{case['id']}/withdraw")).json()
        assert left["withdrawnAt"] and left["state"] == case["state"] and "No answer came" in left["lastError"]
        anew = (await client.post("/api/submissions", json=bare)).json()
        assert anew["id"] != case["id"] and anew["state"] == "received", "Send never answers a case withdrawn here"
        gone = (await client.post(f"/api/submissions/{case['id']}/withdraw")).json()
        assert (gone["state"], gone["withdrawnAt"], gone["lastError"]) == ("withdrawn", left["withdrawnAt"], None)
    assert len(service.requests) == 8, "each case's own send and withdrawals, and nothing else"


async def test_a_second_click_answers_the_same_case(admin, db):
    """Two clicks at once. The sender's account row, held here, stops the first at its first commit (its case
    names the sender) with the consent row still locked, until the second waits too: on that row or, were there
    no consent lock, at a case of its own. Only then does the account row go, so the clicks truly overlap."""
    client, service = admin
    service.answers += [(202, ACK), (202, ACK)]
    await db.execute(text("SELECT 1 FROM accounts WHERE email = :email FOR UPDATE"), {"email": EMAIL.format("admin")})
    clicks = [asyncio.create_task(client.post("/api/submissions", json=SEND)) for _ in range(2)]
    waiting = text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'")
    while not any(click.done() for click in clicks) and await db.scalar(waiting) < 2:
        await db.execute(text("SELECT pg_stat_clear_snapshot()"))  # else the view is read once per transaction
        await asyncio.sleep(0.01)
    assert not any(click.done() for click in clicks), "the two clicks were never in flight together"
    await db.rollback()
    first, second = await asyncio.gather(*clicks)
    third = await client.post("/api/submissions", json=SEND)
    assert first.json()["id"] == second.json()["id"] == third.json()["id"] and len(service.requests) == 1
    assert [event["target_id"] for event in _audit_events("submission.sent")].count(first.json()["id"]) == 1
    other = await client.post("/api/submissions", json=SEND | {"text": "Another case."})
    assert other.json()["id"] != first.json()["id"] and len(service.requests) == 2
    listed = (await client.get("/api/submissions")).json()["cases"]
    assert [case["id"] for case in listed] == [other.json()["id"], first.json()["id"]], "newest first"


async def test_another_tenants_cases_are_out_of_reach(admin, foreign_tenant):  # noqa: F811
    from app.core.submissions import mint_case_key
    from app.models.schema import SubmissionCase

    client, service = admin
    theirs = SubmissionCase(kind="coverage", app_name="Wireshark", platform="macos", versions=["3.6.2"], case_key=mint_case_key())
    foreign_tenant.add(theirs)
    await foreign_tenant.commit()
    try:
        assert (await client.get("/api/submissions")).json()["cases"] == []
        for act in ("status", "withdraw"):
            assert (await client.post(f"/api/submissions/{theirs.id}/{act}")).status_code == 404
        assert service.requests == []
    finally:
        await foreign_tenant.execute(delete(SubmissionCase))
        await foreign_tenant.commit()
