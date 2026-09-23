"""Paid activation and acquired intelligence under real forced PostgreSQL RLS."""

import json
import logging
import os

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

from app.core import intelligence
from app.core.sharing import get_or_create_settings
from app.core.vuln import NO_CORPUS
from app.core.vuln_library import earned_corpus
from app.models.schema import VulnCorpusAcquisition, VulnCorpusSelection
from tests.test_intelligence import ACT, KEY, answer
from tests.test_sharing_send_now_db import accounts  # noqa: F401
from tests.test_vuln_library import BUNDLE, CORPUS_URL, SIGNATURE
from tests.test_vuln_library_db import acting_tenant, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import retained  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(loop_scope="session")
async def paid(db, retained, monkeypatch):  # noqa: F811
    monkeypatch.setattr(intelligence.settings, "intelligence_access", True)
    monkeypatch.setattr(intelligence.settings, "vuln_tenant_selection", True)
    row = await get_or_create_settings(db)
    row.tier = "off"
    row.intelligence_credential = None
    row.intelligence_status = {}
    await db.commit()
    yield
    await db.rollback()
    await db.execute(delete(VulnCorpusSelection))
    await db.execute(delete(VulnCorpusAcquisition))
    row = await get_or_create_settings(db)
    row.intelligence_credential = None
    row.intelligence_status = {}
    await db.commit()


def service(request):
    if request.method == "GET":
        assert str(request.url) == CORPUS_URL
        assert "authorization" not in request.headers
        return httpx.Response(200, content=BUNDLE)
    assert set(json.loads(request.content)) <= {"contract", "client_version", "activation_secret", "channel"}
    if request.url.path.endswith("/activate") or request.url.path.endswith("/rotate"):
        return httpx.Response(200, json=answer(credential=KEY))
    return httpx.Response(200, json=answer(corpus={"url": CORPUS_URL, "signature": SIGNATURE, "asof": "2026-09-10T20:00:00Z"}))


async def test_paid_activation_with_sharing_off_encrypts_and_refreshes_only_this_tenant(db, paid, foreign_tenant):  # noqa: F811
    transport = httpx.MockTransport(service)
    activated = await intelligence.activate(db, ACT, transport=transport)
    assert activated["credentialPresent"] and activated["sharingTier"] == "off"
    assert KEY not in json.dumps(activated) and ACT not in json.dumps(activated)
    raw = await db.scalar(text("SELECT intelligence_credential FROM data_sharing_settings"))
    assert raw.startswith("k1:") and KEY not in raw
    updated = await intelligence.refresh(db, transport=transport)
    assert updated["selectedCorpus"] == SIGNATURE and updated["lastRefreshAt"]
    assert updated["sourceAsOf"] != updated["lastRefreshAt"]
    assert (await earned_corpus(db)) is not NO_CORPUS
    assert (await intelligence.status(foreign_tenant))["credentialPresent"] is False
    assert (await intelligence.status(foreign_tenant))["selectedCorpus"] is None
    assert (await foreign_tenant.execute(select(VulnCorpusAcquisition))).scalars().all() == []


@pytest.mark.parametrize("code,state", [(403, "expired"), (403, "revoked"), (503, "paid"), (401, "credential_invalid")])
async def test_expiry_and_outage_keep_selected_intelligence(db, paid, code, state):
    await intelligence.activate(db, ACT, transport=httpx.MockTransport(service))
    await intelligence.refresh(db, transport=httpx.MockTransport(service))
    failed = await intelligence.refresh(
        db, transport=httpx.MockTransport(lambda _: httpx.Response(code, json={"state": state, "error": KEY}))
    )
    assert failed["state"] == state
    assert failed["selectedCorpus"] == SIGNATURE and failed["lastRefreshAt"]
    assert failed["error"] and KEY not in failed["error"]
    assert (await earned_corpus(db)) is not NO_CORPUS


async def test_failed_activation_replacement_keeps_working_credential(db, paid):
    await intelligence.activate(db, ACT, transport=httpx.MockTransport(service))
    failed = await intelligence.activate(db, ACT, transport=httpx.MockTransport(lambda _: httpx.Response(401)))
    row = await get_or_create_settings(db)
    assert row.intelligence_credential == KEY and failed["state"] == "paid" and row.tier == "off"


async def test_daily_scheduler_and_disabled_preview_never_send_inventory(db, paid, monkeypatch):
    await intelligence.activate(db, ACT, transport=httpx.MockTransport(service))
    await intelligence.refresh(db, scheduled=True, transport=httpx.MockTransport(service))

    def never(_):
        pytest.fail("a second daily or disabled check must not dial")

    assert await intelligence.refresh(db, scheduled=True, transport=httpx.MockTransport(never)) is None
    monkeypatch.setattr(intelligence.settings, "intelligence_access", False)
    assert await intelligence.refresh(db, transport=httpx.MockTransport(never)) is None


async def test_corrupt_download_never_acquires_a_release(db, paid):
    await intelligence.activate(db, ACT, transport=httpx.MockTransport(service))
    result = await intelligence.refresh(
        db,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"broken") if request.method == "GET" else service(request)
        ),
    )
    assert result["selectedCorpus"] is None and result["lastRefreshAt"] is None
    # The specific sentence survives the refresh's catch-all, pointing at the corpus log line.
    assert "could not be downloaded, verified or stored" in result["error"]
    assert (await db.execute(select(VulnCorpusAcquisition))).scalars().all() == []


async def test_refused_activation_is_shown_and_logged_without_the_secret(db, paid, caplog):
    with caplog.at_level(logging.WARNING, logger="app.core.intelligence"):
        failed = await intelligence.activate(
            db, ACT, transport=httpx.MockTransport(lambda _: httpx.Response(404, json={"message": "Not Found"}))
        )
    assert failed["credentialPresent"] is False and failed["state"] == "not_activated"
    assert "HTTP 404" in failed["error"] and "INTELLIGENCE_ENDPOINT" in failed["error"] and "not used" in failed["error"]
    logged = [r for r in caplog.records if r.getMessage() == "paid intelligence request failed"]
    assert len(logged) == 1 and logged[0].operation == "activate" and logged[0].reason == "configuration_error"
    assert ACT not in caplog.text and ACT not in json.dumps(failed)


async def test_rotation_replaces_secret_and_disconnect_preserves_selection(db, paid):
    from app.api.intelligence import disconnect

    await intelligence.activate(db, ACT, transport=httpx.MockTransport(service))
    await intelligence.refresh(db, transport=httpx.MockTransport(service))
    replacement = "loon_key_" + "z" * 43

    def rotate(request):
        assert request.headers["authorization"] == "Bearer " + KEY
        assert "activation_secret" not in json.loads(request.content)
        return httpx.Response(200, json=answer(credential=replacement))

    await intelligence.activate(db, None, rotate=True, transport=httpx.MockTransport(rotate))
    assert (await get_or_create_settings(db)).intelligence_credential == replacement
    stopped = await disconnect(db)
    assert not stopped["credentialPresent"] and stopped["selectedCorpus"] == SIGNATURE
    assert (await earned_corpus(db)) is not NO_CORPUS

    def never(_):
        pytest.fail("disconnected tenant must not make paid requests")

    assert await intelligence.refresh(db, transport=httpx.MockTransport(never)) is None


async def test_permission_checks_precede_activation_or_rotation(accounts, monkeypatch):  # noqa: F811
    from tests.test_sharing_send_now_db import AUDITOR, _signed_in

    async def never(*args, **kwargs):
        pytest.fail("read-only actor reached paid mutation")

    monkeypatch.setattr(intelligence, "activate", never)
    client = await _signed_in(*AUDITOR)
    try:
        assert (await client.get("/api/system/intelligence")).status_code == 200
        for path in ("activate", "rotate", "refresh", "disconnect"):
            response = await client.post("/api/system/intelligence/" + path, json={"secret": ACT})
            assert response.status_code == 403
            assert ACT not in response.text
    finally:
        await client.aclose()
