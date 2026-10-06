"""Drafting a patching rule through the running route (`/api/settings/patching-policy/rule/draft`):
`system:write` alone, nothing dialled without a statement, the switches, one disclosure row
before the first byte, only the instructions and the statement on the wire, a number the
statement does not state dropped — and **no rule saved**, whatever came back.

The endpoint is a stand-in set through `app.api.patch_policy_rules.transport_override`,
answering the way an OpenAI-style server does. Gated on RUN_DB_TESTS.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete

from app.ai.patch_policy_rules import SYSTEM_INSTRUCTION
from app.models.schema import PatchingPolicy
from tests.test_changes_prompt_db import Recorder, _ai_rows, _reply, _reset, _saved, _switches
from tests.test_patching_policy_db import accounts, admin, viewer  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

DRAFT = "/api/settings/patching-policy/rule/draft"
STATEMENT = "We require every update to the latest version within two weeks."


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db):
    await _reset(db)
    await db.execute(delete(PatchingPolicy))
    await db.commit()
    yield
    await _reset(db)
    await db.execute(delete(PatchingPolicy))
    await db.commit()


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    recorder = Recorder()
    recorder.body = _reply(json.dumps({"days": 14, "releases": 1, "cannot": ["apps"]}))
    monkeypatch.setattr("app.api.patch_policy_rules.transport_override", httpx.MockTransport(recorder))
    return recorder


async def _ready(db, admin, statement: str = STATEMENT) -> None:  # noqa: F811
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    assert (await admin.put("/api/settings/patching-policy", json={"statement": statement})).status_code == 200


async def test_only_system_write_drafts_and_a_viewer_does_not_see_the_button(admin, viewer, db, clean, endpoint) -> None:  # noqa: F811
    await _ready(db, admin)
    assert (await viewer.get(DRAFT)).status_code == 403
    assert (await viewer.post(DRAFT, json={})).status_code == 403
    assert endpoint.requests == []
    status = await admin.get(DRAFT)
    assert status.status_code == 200 and status.json()["available"] is True


async def test_nothing_leaves_without_a_statement_or_with_a_switch_off(admin, db, clean, endpoint) -> None:  # noqa: F811
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    unstated = await admin.post(DRAFT, json={})
    assert unstated.status_code == 409 and "No patching policy is stated" in unstated.json()["detail"]

    assert (await admin.put("/api/settings/patching-policy", json={"statement": STATEMENT})).status_code == 200
    await _switches(db, flag=True, consent=False)
    refused = await admin.post(DRAFT, json={})
    assert refused.status_code == 409 and "consent" in refused.json()["detail"]
    assert (await admin.get(DRAFT)).json()["reason"] == "consent_off"
    assert endpoint.requests == [] and await _ai_rows(db) == []


async def test_an_apple_card_saved_naming_another_model_drafts_nothing(admin, db, clean, endpoint) -> None:  # noqa: F811
    """A row an older build saved naming `pcc`, Private Cloud Compute (#738): refused with the
    Save's own sentence before the gate, so the statement never leaves."""
    from app.api.ai import APPLE_FM_SYSTEM_ONLY

    await _ready(db, admin)
    await _saved(db, model="pcc")
    refused = await admin.post(DRAFT, json={})
    assert refused.status_code == 409 and refused.json()["detail"] == APPLE_FM_SYSTEM_ONLY
    assert endpoint.requests == [] and await _ai_rows(db) == []


async def test_a_draft_fills_the_boxes_from_the_statement_and_saves_no_rule(admin, db, clean, endpoint) -> None:  # noqa: F811
    await _ready(db, admin)
    response = await admin.post(DRAFT, json={})
    assert response.status_code == 200, response.text
    body = response.json()
    # 14 is in the statement. The model's "1 release" is not, so that box is empty and says why.
    assert body["outcome"] == "drafted"
    assert body["rule"] == {"maxDaysBehind": 14, "maxReleasesBehind": None, "maxDaysBehindSevere": None}
    assert body["cannot"] == [] and len(body["repairs"]) == 1 and "1 release" in body["repairs"][0]
    assert (body["provider"], body["model"], body["truncated"]) == ("apple_fm", "system", False)

    # One disclosure row, naming the field, committed before the call.
    rows = await _ai_rows(db)
    assert [(row.payload["feature"], row.payload["fields"]) for row in rows] == [("patch_policy_rules", ["policy_statement"])]
    assert rows[0].occurred_at <= endpoint.called_at

    # The instructions and the statement, and nothing else.
    sent = json.loads(endpoint.requests[0].content)
    assert [message["content"] for message in sent["messages"]] == [SYSTEM_INSTRUCTION, STATEMENT]
    assert sent["temperature"] == 0

    # And nothing was confirmed: a draft is not a rule.
    policy = (await admin.get("/api/settings/patching-policy")).json()
    assert policy["rules"]["default"] is None


async def test_a_refusal_an_unreadable_answer_and_a_dead_endpoint_are_outcomes_with_words(admin, db, clean, endpoint) -> None:  # noqa: F811
    await _ready(db, admin)
    endpoint.body = _reply('{"invalid":true}')
    invalid = (await admin.post(DRAFT, json={})).json()
    assert (invalid["outcome"], invalid["rule"]) == ("invalid", None)
    assert "does not read as being about keeping software up to date" in invalid["error"]["message"]

    endpoint.body = _reply("Sure! Here is your policy.")
    unparseable = (await admin.post(DRAFT, json={})).json()
    assert unparseable["outcome"] == "unparseable" and "not a rule draft" in unparseable["error"]["message"]

    endpoint.fail = httpx.ConnectError("refused")
    failed = (await admin.post(DRAFT, json={})).json()
    assert (failed["outcome"], failed["error"]["kind"]) == ("error", "unreachable")
