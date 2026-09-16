"""The Changes page's Prompt bar through the running routes (/api/changes/prompt): the
switches in order, the saved config chosen, one disclosure row before the first byte,
only the instructions and the question on the wire, the reply forced into the page's
vocabulary (and proposed rather than applied when a repair widened it), and a summary
counted by Postgres with the page's own WHERE clause.

The endpoint is stood in for by an `httpx.MockTransport` on
`app.api.changes_prompt.transport_override`, answering the way an OpenAI-style server
does. Change rows are inserted directly, as test_changes_search_db.py does: what is under
test is the route and the query, not the derive path. The test database is shared with
the rest of the suite, so assertions about the whole tenant compare the summary with the
page's own answer for the same filters, and the exact counts use names only this file
seeds. Gated on RUN_DB_TESTS like the other database suites.
"""

from __future__ import annotations

import json
import logging
import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("changes-prompt-admin@example.com", "changes-prompt-admin-password")
VIEWER = ("changes-prompt-viewer@example.com", "changes-prompt-viewer-password")

# Distinctive, so an absence assertion means what it says.
QUESTION = "which computers installed wireshark, asked by the vvq prompt probe"
# macOS names a Mac with U+2019; both of Kyle's minis carry the same name.
MAC_MINI = "Kyle\u2019s Mac mini"

# Every answer to the instructions carries a `change`, "any" when the question names none.
WIRESHARK = {
    "search": None, "filter": "Wireshark", "level": "any", "section": "Applications", "change": "any", "unsupported": None,
}  # fmt: skip
# A key saved on a card, for the restore that cannot open it, and the one typed again.
KEY = "sk-ant-changes-prompt-key-vvq-7d2e91"
REENTERED_KEY = "sk-ant-changes-prompt-reentered-vvq-40b8c5"


def _reply(content: str) -> dict:
    """An OpenAI-shaped completion carrying `content`, as `fm serve` answers."""
    return {"model": "system", "choices": [{"message": {"content": content}, "finish_reason": "stop"}]}


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts() -> None:
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role in ((ADMIN, "admin"), (VIEWER, "viewer")):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        await db.commit()


def _change(connection_id: int, **kwargs):
    from app.models.schema import DeviceChange

    now = datetime.now(UTC)
    defaults = {
        "mdm_connection_id": connection_id,
        "subject_kind": "computer",
        "observed_at": now,
        "collected_at": now,
        "trigger": "sweep",
        "change": "added",
        "level": "normal",
        "policy_version": "v0",
        "section": "applications",
        "entry_kind": "application",
    }
    return DeviceChange(**{**defaults, **kwargs})


def _app(name: str, bundle_id: str) -> dict:
    return {"name": name, "bundleId": bundle_id, "path": f"/Applications/{name}.app"}


def _span(connection_id: int, subject_id: str, *, observed_at: datetime, collected_at: datetime):
    """An observation a change moved away from: its last inventory time is the lower bound of
    the window the change happened in (#443). Never `is_current`, so several can share a
    subject without meeting the one-open-span index."""
    from app.models.schema import ObservationSpan

    return ObservationSpan(
        mdm_connection_id=connection_id,
        subject_kind="computer",
        subject_id=subject_id,
        contract_version="v1",
        aperture_digest="v1:" + "e" * 64,
        head_digest="v1:" + subject_id.rjust(64, "0"),
        section_digests={"applications": "v1:" + "0" * 64},
        first_observed_at=observed_at,
        last_observed_at=observed_at,
        first_collected_at=collected_at,
        last_collected_at=collected_at,
        last_trigger="sweep",
        is_current=False,
    )


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded(accounts):
    """One connection of this file's own. Two minis both named "Kyle's Mac mini" (the
    typographic apostrophe), one of which added Wireshark and one of which updated it an
    hour later; a Mac that added Slack and must never be counted; a probe app on one Mac
    and in one smart group's definition, for the rows that are not devices; and 26 Macs
    with one more probe, for the cap. Newer than anything else in the tenant, so this
    file's devices lead the newest-first list."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import MdmConnection

    base = datetime.now(UTC) + timedelta(hours=1)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        connection = MdmConnection(
            name=f"changes prompt jamf {uuidlib.uuid4().hex[:8]}", provider="jamf", base_url="https://prompt.jamfcloud.com"
        )
        db.add(connection)
        await db.flush()
        cid = connection.id
        wireshark = _app("Wireshark", "org.wireshark.Wireshark")
        # The observation each of those two moved away from. The mini's inventory time moved
        # half an hour before its update, so the window is the device's own; the Slack Mac's
        # did not move at all, so only our clock bounds that one.
        before_302 = _span(cid, "302", observed_at=base + timedelta(minutes=30), collected_at=base + timedelta(minutes=40))
        before_303 = _span(cid, "303", observed_at=base, collected_at=base - timedelta(hours=2))
        db.add_all([before_302, before_303])
        await db.flush()
        db.add_all(
            [
                _change(cid, subject_id="301", subject_label=MAC_MINI, serial_number="KY4QVD7430", entry_identity=wireshark,
                        observed_at=base, collected_at=base),
                _change(cid, subject_id="302", subject_label=MAC_MINI, serial_number="VKM73DMG47", entry_identity=wireshark,
                        change="updated", observed_at=base + timedelta(hours=1), collected_at=base + timedelta(hours=1),
                        previous_span_id=before_302.id),
                _change(cid, subject_id="303", subject_label="design-mbp", serial_number="PRMSER303",
                        entry_identity=_app("Slack", "com.tinyspeck.slackmacgap"), observed_at=base, collected_at=base,
                        previous_span_id=before_303.id),
                _change(cid, subject_id="304", subject_label="probe-mac", serial_number="PRMSER304",
                        entry_identity=_app("PromptProbeVvq", "io.example.promptprobe")),
                # Forty days back, for the one range the controls express: a start of 30d
                # leaves it out, and no start shows it (#443).
                _change(cid, subject_id="305", subject_label="old-mac", serial_number="PRMSER305",
                        entry_identity=_app("PromptOldVvq", "io.example.promptold"),
                        observed_at=base - timedelta(days=40), collected_at=base - timedelta(days=40)),
                _change(cid, subject_kind="computer_group", subject_id="g-prompt", subject_label="Probe owners",
                        section="definition", entry_kind="criterion", entry_identity=None,
                        entry_label="Application Title is PromptProbeVvq"),
                *(
                    _change(cid, subject_id=f"4{n:02d}", subject_label=f"many-{n:02d}", serial_number=f"PRMMANY{n:02d}",
                            entry_identity=_app("PromptManyVvq", "io.example.promptmany"),
                            observed_at=base - timedelta(minutes=n), collected_at=base - timedelta(minutes=n))
                    for n in range(26)
                ),
            ]
        )  # fmt: skip
        await db.commit()

    try:
        yield {"connection_id": cid, "base": base}
    finally:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(delete(MdmConnection).where(MdmConnection.id == cid))  # changes cascade
            await db.commit()


async def _signed_in(email: str, password: str) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://changes-prompt.example.com")
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    signed_in = await _signed_in(*ADMIN)
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def viewer(accounts):
    signed_in = await _signed_in(*VIEWER)
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def db(accounts):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


async def _reset(db) -> None:
    from app.core.ai import AI_SHARE_TIER
    from app.core.feature_flags import AI_FEATURES_FLAG
    from app.models.schema import AIProviderConfig, DataSharingSettings, FeatureFlag, ShareLog

    await db.rollback()
    await db.execute(delete(FeatureFlag).where(FeatureFlag.key == AI_FEATURES_FLAG))
    await db.execute(delete(ShareLog).where(ShareLog.tier == AI_SHARE_TIER))
    await db.execute(delete(AIProviderConfig))
    row = (await db.execute(select(DataSharingSettings))).scalar_one_or_none()
    if row is not None:
        row.ai_inference = False
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db, seeded):
    await _reset(db)
    yield
    await _reset(db)


async def _switches(db, *, flag: bool, consent: bool) -> None:
    from app.api.feature_flags import update_feature_flag
    from app.api.system import update_data_sharing
    from app.core.feature_flags import AI_FEATURES_FLAG
    from app.schemas.feature_flags import FeatureFlagUpdate
    from app.schemas.system import DataSharingUpdate

    if flag:
        await update_feature_flag(AI_FEATURES_FLAG, FeatureFlagUpdate(enabled=True), db)
    await update_data_sharing(DataSharingUpdate(ai_inference=consent), db)


async def _saved(db, provider: str = "apple_fm") -> None:
    """A card's Save, written the way the route writes it."""
    from app.ai.providers import Provider
    from app.core.ai_configs import save_config

    if provider == "apple_fm":
        values = {"base_url": "http://host.docker.internal:1976/v1", "model": "system", "reasoning_effort": None, "api_key": None}
    else:
        values = {"base_url": "http://host.docker.internal:11434/v1", "model": "qwen3.5:2b-mlx", "reasoning_effort": "none",
                  "api_key": None}  # fmt: skip
    await save_config(db, Provider(provider), host_reach=None, clear_key=False, updated_by=ADMIN[0], **values)


async def _ai_rows(db) -> list:
    from app.core.ai import AI_SHARE_TIER
    from app.models.schema import ShareLog

    await db.rollback()
    return (await db.execute(select(ShareLog).where(ShareLog.tier == AI_SHARE_TIER))).scalars().all()


class Recorder:
    def __init__(self) -> None:
        self.status = 200
        self.body: dict = _reply(json.dumps(WIRESHARK))
        self.fail: Exception | None = None
        self.requests: list[httpx.Request] = []
        self.called_at: datetime | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.called_at = datetime.now(UTC)
        if self.fail is not None:
            raise self.fail
        return httpx.Response(self.status, json=self.body)


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    recorder = Recorder()
    monkeypatch.setattr("app.api.changes_prompt.transport_override", httpx.MockTransport(recorder))
    return recorder


@pytest.fixture
def audit_records() -> list[dict]:
    """The tenant's audit events, read off the logger rather than the rotated file."""
    from app.core.audit import _audit_logger
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    captured: list[dict] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(json.loads(record.getMessage()))

    tenant_logger = _audit_logger(str(OPERATIONAL_TENANT_ID))
    handler = _Capture()
    tenant_logger.addHandler(handler)
    try:
        yield captured
    finally:
        tenant_logger.removeHandler(handler)


async def _ask(client, question: str = QUESTION, **extra) -> httpx.Response:
    return await client.post("/api/changes/prompt", json={"question": question, **extra})


def _wire(moment: datetime) -> str:
    """A time as the API writes it: ISO 8601 with the Z the app's encoder uses for UTC."""
    return moment.isoformat().replace("+00:00", "Z")


def _mine(summary: dict, seeded: dict) -> dict[str, dict]:
    return {d["subjectId"]: d for d in summary["devices"] if d["connectionId"] == seeded["connection_id"]}


# --- whether the bar is shown -------------------------------------------------------------------


async def test_the_status_names_the_first_switch_that_is_off(viewer, db, clean):
    async def status(who) -> dict:
        response = await who.get("/api/changes/prompt")
        assert response.status_code == 200, response.text
        return response.json()

    await _saved(db)
    assert await status(viewer) == {
        "available": False,
        "reason": "flag_off",
        "providers": [{"provider": "apple_fm", "model": "system"}],
    }

    await _switches(db, flag=True, consent=False)
    assert (await status(viewer))["reason"] == "consent_off"

    await _switches(db, flag=True, consent=True)
    await _saved(db, "openai_compatible")
    body = await status(viewer)
    assert body == {
        "available": True,
        "reason": None,
        "providers": [{"provider": "apple_fm", "model": "system"}, {"provider": "openai_compatible", "model": "qwen3.5:2b-mlx"}],
    }
    # Provider and model only: a viewer is never shown where the endpoint is.
    assert "host.docker.internal" not in json.dumps(body)


async def test_the_status_says_when_no_provider_is_saved(viewer, db, clean):
    await _switches(db, flag=True, consent=True)
    response = await viewer.get("/api/changes/prompt")
    assert response.status_code == 200, response.text
    assert response.json() == {"available": False, "reason": "no_provider", "providers": []}


# --- a question, answered ------------------------------------------------------------------------


async def test_a_question_comes_back_as_the_pages_filters_with_a_summary(
    client, db, clean, seeded, endpoint, audit_records, caplog
):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    with caplog.at_level(logging.DEBUG):
        response = await _ask(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "applied"
    assert body["filters"] == {
        "q": None, "artifact": "Wireshark", "level": None, "section": "applications", "change": None, "since": None,
    }  # fmt: skip
    assert body["unsupported"] is None
    assert body["repairs"] == []
    assert body["widening"] == []
    assert body["error"] is None
    assert body["provider"] == "apple_fm"
    assert body["model"] == "system"
    assert body["destination"] == "http://host.docker.internal:1976"
    assert isinstance(body["latencyMs"], int)

    # The two minis, by serial, each with the one change it made; the Slack Mac nowhere.
    summary = body["summary"]
    mine = _mine(summary, seeded)
    assert mine["301"] == {
        "connectionId": seeded["connection_id"], "subjectId": "301", "label": MAC_MINI, "serial": "KY4QVD7430",
        "added": 1, "removed": 0, "updated": 0, "changed": 0,
        "lastObservedAt": _wire(seeded["base"]),
    }  # fmt: skip
    assert mine["302"]["serial"] == "VKM73DMG47"
    assert (mine["302"]["added"], mine["302"]["updated"]) == (0, 1)
    assert "303" not in mine
    # Newest first: the update an hour after the install leads.
    assert list(mine) == ["302", "301"]

    # The count the box states is the count the page shows for the same filters.
    page = (await client.get("/api/changes?artifact=Wireshark&section=applications&pageSize=200")).json()
    assert summary["total"] == page["total"]
    if page["total"] <= 200:
        computers = {(r["mdmConnectionId"], r["subjectId"]) for r in page["items"] if r["subjectKind"] == "computer"}
        assert summary["devicesTotal"] == len(computers)

    # The wire: the static instructions and the question, and nothing else.
    assert len(endpoint.requests) == 1
    request = endpoint.requests[0]
    assert str(request.url) == "http://host.docker.internal:1976/v1/chat/completions"
    assert request.headers["host"] == "127.0.0.1:1976"
    sent = json.loads(request.content)
    from app.ai.changes_prompt import MAX_REPLY_TOKENS, SYSTEM_INSTRUCTION

    assert sent["messages"] == [{"role": "system", "content": SYSTEM_INSTRUCTION}, {"role": "user", "content": QUESTION}]
    assert sent["temperature"] == 0
    assert sent["stream"] is False
    assert sent["max_tokens"] == MAX_REPLY_TOKENS
    # No device row reached the model: the minis' second serial and their name are in
    # the database and not in the instructions, so either on the wire would be a leak.
    wire = json.dumps(sent, ensure_ascii=False)
    assert "VKM73DMG47" not in wire and MAC_MINI not in wire

    # One disclosure row, naming the destination and the one field that left, committed
    # before the endpoint saw the first byte.
    rows = await _ai_rows(db)
    assert len(rows) == 1
    assert rows[0].endpoint == "http://host.docker.internal:1976"
    assert rows[0].payload == {"feature": "changes_prompt", "fields": ["query_text"]}
    assert rows[0].occurred_at <= endpoint.called_at

    # On the trail: who asked where and how it went. Never the question.
    asked = [r for r in audit_records if r["action"] == "ai.changes-prompt.sent"]
    assert len(asked) == 1
    assert asked[0]["outcome"] == "applied"
    assert asked[0]["target_id"] == "http://host.docker.internal:1976"
    assert asked[0]["metadata"]["provider"] == "apple_fm"
    assert asked[0]["metadata"]["repairs"] == 0
    assert isinstance(asked[0]["metadata"]["latency_ms"], int)
    assert QUESTION not in json.dumps(audit_records)
    assert "wireshark, asked" not in json.dumps(audit_records)

    # And never in the application log, as a message or as an extra.
    assert QUESTION not in caplog.text
    assert all(QUESTION not in repr(vars(record)) for record in caplog.records)
    # Nor in the reply or the disclosure row.
    assert QUESTION not in response.text
    assert QUESTION not in repr(rows[0].payload)


async def test_the_summary_counts_exactly_what_the_filters_match(client, db, clean, seeded, endpoint):
    """Names only this file seeds, so the numbers are exact: two change rows, both
    computers, both named with the typographic apostrophe the model wrote as ASCII."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "search": "Kyle's Mac mini"}))
    body = (await _ask(client, "wireshark on Kyle's Mac mini")).json()
    assert body["filters"]["q"] == "Kyle's Mac mini"
    summary = body["summary"]
    assert (summary["total"], summary["devicesTotal"], summary["otherSubjects"], summary["truncated"]) == (2, 2, 0, False)
    assert [d["serial"] for d in summary["devices"]] == ["VKM73DMG47", "KY4QVD7430"]


async def test_the_change_the_model_names_narrows_the_summary(client, db, clean, seeded, endpoint):
    """New installs: the model says added, the filters carry it, and the mini that only
    updated Wireshark is not counted. The page, asked for the same filters, agrees."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "search": "Kyle's Mac mini", "change": "added"}))
    body = (await _ask(client, "new installs of wireshark on Kyle's Mac mini")).json()
    assert body["outcome"] == "applied", body
    assert body["filters"] == {
        "q": "Kyle's Mac mini", "artifact": "Wireshark", "level": None, "section": "applications", "change": "added",
        "since": None,
    }  # fmt: skip
    summary = body["summary"]
    assert (summary["total"], summary["devicesTotal"], summary["otherSubjects"], summary["truncated"]) == (1, 1, 0, False)
    assert [(d["serial"], d["added"], d["updated"]) for d in summary["devices"]] == [("KY4QVD7430", 1, 0)]

    page = await client.get(
        "/api/changes",
        params={"q": "Kyle's Mac mini", "artifact": "Wireshark", "section": "applications", "change": "added"},
    )
    assert page.status_code == 200, page.text
    assert [(r["serialNumber"], r["change"]) for r in page.json()["items"]] == [("KY4QVD7430", "added")]


async def test_the_summary_says_when_and_the_window_the_newest_change_happened_in(client, db, clean, seeded, endpoint):
    """Ruling R1 on #443: the observed time is Jamf's report time, so the box states it with
    the inventory before it — the change happened between the two — and never as an install."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    base = seeded["base"]
    endpoint.body = _reply(json.dumps({**WIRESHARK, "search": "Kyle's Mac mini"}))
    summary = (await _ask(client, "when was wireshark last touched on Kyle's Mac mini")).json()["summary"]
    assert summary["when"] == {
        # The update an hour after the install is the newest of the two; the install is the oldest.
        "observedAt": _wire(base + timedelta(hours=1)),
        "oldestObservedAt": _wire(base),
        "collectedAt": _wire(base + timedelta(hours=1)),
        "previousObservedAt": _wire(base + timedelta(minutes=30)),
        "previousCollectedAt": _wire(base + timedelta(minutes=40)),
        "deviceTimeMoved": True,
    }
    # Each Mac's line carries its own newest, which is the column the list is ordered by.
    mine = _mine(summary, seeded)
    assert mine["302"]["lastObservedAt"] == _wire(base + timedelta(hours=1))
    assert mine["301"]["lastObservedAt"] == _wire(base)
    # And it is the first row the page shows for the same filters.
    page = await client.get("/api/changes", params={"q": "Kyle's Mac mini", "artifact": "Wireshark"})
    assert page.json()["items"][0]["observedAt"] == summary["when"]["observedAt"]


async def test_a_change_whose_inventory_time_did_not_move_says_so(client, db, clean, seeded, endpoint):
    """Same report time on both reads: nothing on the Mac dated the change, so the window is
    our clock's and `deviceTimeMoved` is false rather than a window of zero length."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    base = seeded["base"]
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "Slack"}))
    summary = (await _ask(client, "when was slack installed")).json()["summary"]
    assert summary["when"]["deviceTimeMoved"] is False
    assert summary["when"]["previousObservedAt"] == summary["when"]["observedAt"] == _wire(base)
    assert summary["when"]["previousCollectedAt"] == _wire(base - timedelta(hours=2))
    assert summary["when"]["collectedAt"] == _wire(base)


async def test_a_change_whose_earlier_observation_is_gone_states_no_window(client, db, clean, seeded, endpoint):
    """The span carries the lower bound and may have been deleted (`ON DELETE SET NULL`).
    Then the box states the observed time and no window, never a guessed one."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "PromptManyVvq"}))
    when = (await _ask(client, "when did PromptManyVvq arrive")).json()["summary"]["when"]
    assert when["previousObservedAt"] is None and when["previousCollectedAt"] is None
    assert when["deviceTimeMoved"] is False
    assert when["observedAt"] > when["oldestObservedAt"]


async def test_nothing_matched_states_no_time(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "NoSuchAppVvq"}))
    summary = (await _ask(client, "when was NoSuchAppVvq installed")).json()["summary"]
    assert (summary["total"], summary["devicesTotal"]) == (0, 0)
    assert summary["when"] is None


async def test_a_start_narrows_the_summary_and_the_page_shows_the_same_rows(client, db, clean, seeded, endpoint):
    """Ruling R4 on #443: the model names a start from a closed list, the server resolves it,
    and it rides the page's own `since` key — so the count is of the rows the page then lists."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "PromptOldVvq", "since": "30d"}))
    body = (await _ask(client, "was PromptOldVvq installed in the last 30 days")).json()
    assert body["outcome"] == "applied", body
    since = body["filters"]["since"]
    assert since is not None and body["repairs"] == []
    # Forty days old: inside the log, outside the window.
    assert (body["summary"]["total"], body["summary"]["when"]) == (0, None)
    page = await client.get("/api/changes", params={"artifact": "PromptOldVvq", "since": since})
    assert page.status_code == 200, page.text
    assert page.json()["total"] == 0

    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "PromptOldVvq"}))
    whole = (await _ask(client, "when was PromptOldVvq installed")).json()
    assert whole["filters"]["since"] is None
    assert whole["summary"]["total"] == 1


async def test_today_starts_where_the_viewer_is(client, db, clean, seeded, endpoint):
    """ "Today" is the operator's day. Two viewers a day apart get two starts, and neither is
    the server's midnight unless that is theirs."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "since": "today"}))
    starts = set()
    for zone in ("America/Chicago", "Pacific/Kiritimati", "Mars/Olympus_Mons", None):
        body = (await _ask(client, "what changed today", timeZone=zone)).json()
        assert body["outcome"] == "applied", body
        starts.add(body["filters"]["since"])
    # Chicago, Kiritimati (UTC+14), and UTC for the zone that is not one and for none sent.
    assert len(starts) == 3


async def test_a_start_the_question_never_asked_for_is_not_applied(client, db, clean, seeded, endpoint):
    """The demo question with a start the model invented: dropped, and the answer is the one
    the question asked for rather than a week of it."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "change": "added", "since": "7d"}))
    body = (await _ask(client, "when was the last time someone installed wireshark")).json()
    assert body["outcome"] == "applied", body
    assert body["filters"]["since"] is None
    assert any("names no time to start from" in repair for repair in body["repairs"])
    assert body["widening"] == []
    assert body["summary"]["total"] == 1


async def test_rows_that_are_not_devices_are_counted_apart(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "PromptProbeVvq", "section": "any"}))
    summary = (await _ask(client, "who has PromptProbeVvq")).json()["summary"]
    assert (summary["total"], summary["devicesTotal"], summary["otherSubjects"]) == (2, 1, 1)
    assert [d["serial"] for d in summary["devices"]] == ["PRMSER304"]


async def test_the_device_list_stops_at_25_and_says_how_many_more(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "PromptManyVvq"}))
    summary = (await _ask(client, "which macs have PromptManyVvq")).json()["summary"]
    assert (summary["total"], summary["devicesTotal"], summary["truncated"]) == (26, 26, True)
    assert len(summary["devices"]) == 25
    # Newest first: many-00 is the newest of the 26, many-25 the one left off.
    assert summary["devices"][0]["serial"] == "PRMMANY00"
    assert "PRMMANY25" not in {d["serial"] for d in summary["devices"]}


async def test_a_viewer_can_ask(viewer, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    response = await _ask(viewer)
    assert response.status_code == 200, response.text
    assert response.json()["outcome"] == "applied"


async def test_the_provider_asked_for_is_the_one_dialled(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    await _saved(db, "openai_compatible")
    response = await _ask(client, provider="openai_compatible")
    assert response.status_code == 200, response.text
    assert response.json()["provider"] == "openai_compatible"
    assert str(endpoint.requests[0].url) == "http://host.docker.internal:11434/v1/chat/completions"
    assert json.loads(endpoint.requests[0].content)["reasoning_effort"] == "none"

    missing = await _ask(client, provider="anthropic")
    assert missing.status_code == 409
    assert missing.json()["detail"] == "The Anthropic card is not saved in Settings › AI. An admin saves it there."


async def test_an_apple_card_saved_with_a_reasoning_effort_never_sends_it(client, db, clean, seeded, endpoint):
    """A row saved before the Save refused an effort on the Apple card (app.api.ai),
    written here as it would stand. `fm serve` answers 400 to any effort on its system
    model, so sending the row as it is would fail every question: the bar leaves it out,
    for Apple alone (an OpenAI-compatible card sends its own, in the test above)."""
    from app.ai.providers import Provider
    from app.core.ai_configs import save_config

    await _switches(db, flag=True, consent=True)
    await save_config(
        db, Provider.apple_fm, host_reach=None, base_url="http://host.docker.internal:1976/v1", model="system",
        reasoning_effort="low", api_key=None, clear_key=False, updated_by=ADMIN[0],
    )  # fmt: skip
    response = await _ask(client)
    assert response.status_code == 200, response.text
    assert response.json()["outcome"] == "applied"
    assert "reasoning_effort" not in json.loads(endpoint.requests[0].content)


# --- a repair that widens the answer: proposed, not applied (ruled 1C, #436) -----------------------

# The whitelist's refusal, as the page shows it: what a name may hold, never what this one held.
REFUSED_FILTER = (
    "Dropped the model's value for Filter to one thing: a name here takes only letters and digits in any script, "
    "spaces, and . _ @ ' ’ ( ) + / - & # ! , : — it held another character."
)


def _asked(audit_records: list[dict]) -> list[tuple[str, int]]:
    return [(r["outcome"], r["metadata"]["repairs"]) for r in audit_records if r["action"] == "ai.changes-prompt.sent"]


async def test_a_name_the_whitelist_refuses_is_proposed_with_its_filters_and_summary(
    client, db, clean, seeded, endpoint, audit_records
):
    """Dropped, the name would leave every added application: more than the model named.
    The answer comes back as a proposal, with the filters and the summary an applied one
    carries, so the page can show both beside its Apply button."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    refused = 'Wireshark"; DROP TABLE devices;--'
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": refused, "change": "added"}))
    response = await _ask(client, "which macs installed wireshark")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "proposed"
    assert body["filters"] == {
        "q": None, "artifact": None, "level": None, "section": "applications", "change": "added", "since": None,
    }  # fmt: skip
    assert body["repairs"] == [REFUSED_FILTER]
    assert body["widening"] == [REFUSED_FILTER]
    assert body["error"] is None

    # The summary is the page's own count for the proposed filters, as for an applied answer.
    page = (await client.get("/api/changes", params={"section": "applications", "change": "added"})).json()
    assert body["summary"]["total"] == page["total"]
    assert "301" in _mine(body["summary"], seeded)

    # On the trail as a proposal. The refused value is nowhere: not the reply, not the trail.
    assert _asked(audit_records) == [("proposed", 1)]
    assert "DROP" not in response.text
    assert "DROP" not in json.dumps(audit_records)


async def test_a_section_the_page_does_not_have_is_proposed(client, db, clean, seeded, endpoint, audit_records):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "PromptProbeVvq", "section": "Apps"}))
    body = (await _ask(client, "who has PromptProbeVvq")).json()
    assert body["outcome"] == "proposed"
    assert body["filters"] == {
        "q": None, "artifact": "PromptProbeVvq", "level": None, "section": None, "change": None, "since": None,
    }  # fmt: skip
    assert body["widening"] == ["The model named a section this page does not have, so it was read as any section."]
    # Any section, proposed: the probe app on one Mac and in one smart group's definition.
    summary = body["summary"]
    assert (summary["total"], summary["devicesTotal"], summary["otherSubjects"]) == (2, 1, 1)
    assert _asked(audit_records) == [("proposed", 1)]


async def test_a_repair_that_narrows_is_still_applied(client, db, clean, seeded, endpoint, audit_records):
    """The serial the model missed, filled from the question: narrower, so it runs on Enter."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": None, "section": "any"}))
    body = (await _ask(client, "what happened on VKM73DMG47")).json()
    assert body["outcome"] == "applied"
    assert body["filters"] == {
        "q": "VKM73DMG47", "artifact": None, "level": None, "section": None, "change": None, "since": None,
    }  # fmt: skip
    assert body["repairs"] == ["Filled Search with the one serial-number-shaped word in the question."]
    assert body["widening"] == []
    assert "302" in _mine(body["summary"], seeded)
    assert _asked(audit_records) == [("applied", 1)]


async def test_a_name_in_any_script_is_applied_whole(client, db, clean, seeded, endpoint, audit_records):
    """#436's own question: the ASCII whitelist dropped the name and ran every added app."""
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({**WIRESHARK, "filter": "Café Manager", "change": "added"}))
    body = (await _ask(client, "which macs installed Café Manager")).json()
    assert body["outcome"] == "applied"
    assert body["filters"]["artifact"] == "Café Manager"
    assert (body["repairs"], body["widening"]) == ([], [])
    assert _asked(audit_records) == [("applied", 0)]


# --- text that is not a question about device changes: invalid (Kyle, 2026-09-15) -------------------


async def test_a_refusal_is_invalid_runs_nothing_and_says_why(client, db, clean, seeded, endpoint, audit_records):
    """Asked "What model are you?", the model answered every control any, and the page listed
    every device. Now the model refuses: no filters to run, no summary, the page's sentence."""
    from app.api.changes_prompt import NOT_A_CHANGES_QUESTION

    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply('{"invalid":true}')
    response = await _ask(client, "What model are you?")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "invalid"
    assert (body["filters"], body["summary"], body["unsupported"]) == (None, None, None)
    assert (body["repairs"], body["widening"]) == ([], [])
    assert body["error"] == {"kind": "not_about_changes", "message": NOT_A_CHANGES_QUESTION, "status": None}
    # The page's words, never the question's.
    assert "model are you" not in response.text.lower()

    # The question still left the box, so its disclosure row stands; the trail says invalid.
    assert len(await _ai_rows(db)) == 1
    asked = [r for r in audit_records if r["action"] == "ai.changes-prompt.sent"]
    assert [(r["outcome"], r["metadata"]["reason"]) for r in asked] == [("invalid", "not_about_changes")]
    assert "model are you" not in json.dumps(audit_records).lower()


async def test_a_refusal_beside_filters_still_runs_nothing(client, db, clean, seeded, endpoint, audit_records):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply(json.dumps({"invalid": True, **WIRESHARK, "change": "removed"}))
    body = (await _ask(client, "uninstall wireshark from every mac")).json()
    assert body["outcome"] == "invalid"
    assert (body["filters"], body["summary"]) == (None, None)


# --- what the endpoint gets wrong -----------------------------------------------------------------


async def test_an_endpoint_failure_is_an_outcome_not_an_error(client, db, clean, seeded, endpoint, audit_records):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.status = 500
    endpoint.body = {"error": {"message": "boom"}}
    response = await _ask(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "error"
    assert body["error"]["kind"] == "http_status"
    assert body["error"]["status"] == 500
    assert "boom" in body["error"]["message"]
    assert body["filters"] is None and body["summary"] is None
    # The attempt is on record: the row went in before the byte left.
    assert len(await _ai_rows(db)) == 1
    asked = [r for r in audit_records if r["action"] == "ai.changes-prompt.sent"]
    assert [(r["outcome"], r["metadata"]["error_kind"]) for r in asked] == [("error", "http_status")]


async def test_an_unreachable_endpoint_is_an_outcome_not_an_error(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.fail = httpx.ConnectError("connection refused")
    response = await _ask(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "error"
    assert body["error"]["kind"] == "unreachable"
    assert body["error"]["status"] is None
    assert body["filters"] is None and body["summary"] is None


async def test_an_answer_that_is_not_filters_applies_nothing(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply("I'm sorry, I can only help with questions about your fleet.")
    response = await _ask(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "unparseable"
    assert body["filters"] is None and body["summary"] is None and body["unsupported"] is None
    assert body["error"] == {
        "kind": "malformed",
        "message": "The model's answer was not the filter settings the Prompt bar needs. "
        "Rephrase the question, or use the filters directly.",
        "status": None,
    }
    # The reply itself never comes back.
    assert "I'm sorry" not in response.text


async def test_an_empty_answer_is_unparseable_by_its_own_kind(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    endpoint.body = _reply("")
    body = (await _ask(client)).json()
    assert body["outcome"] == "unparseable"
    assert body["error"]["kind"] == "empty"


# --- refusals --------------------------------------------------------------------------------------


async def test_no_saved_config_is_refused_with_the_way_out(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    response = await _ask(client)
    assert response.status_code == 409
    assert response.json()["detail"] == (
        "No AI provider is saved. An admin saves one in Settings › AI; then the Prompt bar can use it."
    )
    assert endpoint.requests == []


async def test_a_saved_key_this_instance_cannot_read_names_the_card_to_re_enter_it_on(
    client, db, clean, seeded, endpoint, monkeypatch, caplog
):
    """A restore that brought the database and not its ENCRYPTION_KEY: the key saved on
    the Anthropic card can no longer be opened. The refusal names that card and the way
    out, rather than the generic 503 about every connection's and destination's secret,
    and nothing is dialled or disclosed. Asked for by name or by default, the same."""
    from cryptography.fernet import Fernet

    from app.ai.providers import Provider
    from app.core.ai_configs import save_config
    from app.core.config import settings
    from app.core.crypto import STORED_VALUE_UNREADABLE

    await _switches(db, flag=True, consent=True)
    await save_config(
        db, Provider.anthropic, host_reach=None, base_url="https://api.anthropic.com", model="claude-fable-5-1",
        reasoning_effort=None, api_key=KEY, clear_key=False, updated_by=ADMIN[0],
    )  # fmt: skip
    monkeypatch.setattr(settings, "encryption_key", Fernet.generate_key().decode())

    caplog.set_level(logging.WARNING, logger="app.api.changes_prompt")
    for extra in ({}, {"provider": "anthropic"}):
        response = await _ask(client, **extra)
        assert response.status_code == 503, response.text
        assert response.json()["detail"] == (
            "The API key saved on the Anthropic card cannot be read: this server's ENCRYPTION_KEY is not the one it "
            "was saved under. An admin re-enters the key on that card in Settings › AI and saves it, or restores the "
            "original ENCRYPTION_KEY (docs/operations.md §1)."
        )
        assert response.json()["detail"] != STORED_VALUE_UNREADABLE
    # The container log says it too, naming the next check, since main.py's handler never sees it.
    warned = [r.getMessage() for r in caplog.records if r.name == "app.api.changes_prompt"]
    assert warned and all("ENCRYPTION_KEY" in m and "Settings › AI" in m and "Anthropic" in m for m in warned)
    assert endpoint.requests == []
    assert await _ai_rows(db) == []

    # The way out works: the card still lists, its Save never opens the stored key, and
    # the key re-entered there is written under the ENCRYPTION_KEY the environment holds,
    # so the next ask gets past it and dials with the new key.
    listed = await client.get("/api/system/ai/configs")
    assert [(c["provider"], c["hasKey"]) for c in listed.json()["configs"]] == [("anthropic", True)]
    reentered = await client.put(
        "/api/system/ai/configs/anthropic",
        json={"baseUrl": "https://api.anthropic.com", "model": "claude-fable-5-1", "apiKey": REENTERED_KEY},
    )
    assert reentered.status_code == 200, reentered.text
    again = await _ask(client)
    assert again.status_code == 200, again.text
    assert [r.headers["x-api-key"] for r in endpoint.requests] == [REENTERED_KEY]


async def test_the_flag_off_refuses_before_anything_is_dialled(client, db, clean, seeded, endpoint):
    await _saved(db)
    response = await _ask(client)
    assert response.status_code == 409
    assert "AI features are off" in response.json()["detail"]
    assert endpoint.requests == []
    assert await _ai_rows(db) == []


async def test_consent_off_refuses_before_anything_is_dialled(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=False)
    await _saved(db)
    response = await _ask(client)
    assert response.status_code == 409
    assert "consent is off" in response.json()["detail"]
    assert endpoint.requests == []
    assert await _ai_rows(db) == []


async def test_an_empty_question_is_refused(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    for question in ("", "   "):
        response = await _ask(client, question)
        assert response.status_code == 422, question
        assert response.json()["detail"] == "Type a question first."
    # Something was typed, and sanitising removed all of it: the sentence says what went.
    for question in ("\u200b\u202e\t\n", "<|im_start|><|im_end|>"):
        response = await _ask(client, question)
        assert response.status_code == 422, question
        assert response.json()["detail"].startswith("The question held only what the Prompt bar removes before sending")
    assert endpoint.requests == []


async def test_a_question_too_long_is_refused_without_being_echoed(client, db, clean, seeded, endpoint):
    await _switches(db, flag=True, consent=True)
    await _saved(db)
    question = "wireshark " * 201
    response = await _ask(client, question)
    assert response.status_code == 422
    assert "Shorten it" in response.json()["detail"]
    assert "wireshark wireshark" not in response.text
    assert endpoint.requests == []
