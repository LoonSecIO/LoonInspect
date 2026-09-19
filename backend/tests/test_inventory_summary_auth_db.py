"""Inventory summary controls enforce the existing system permissions (#594)."""

import os
from contextlib import aclosing

import httpx
import pytest

from tests.test_ai_configs_db import ADMIN, VIEWER, _signed_in, accounts  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest.mark.usefixtures("accounts")
async def test_summary_settings_require_login_and_reject_viewer_writes():
    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://summary.example") as client:
        assert (await client.get("/api/inventory-summaries/settings")).status_code == 401
        assert (await client.get("/api/inventory-summaries/metrics")).status_code == 401
    async with aclosing(await _signed_in(*VIEWER)) as viewer:
        response = await viewer.put("/api/inventory-summaries/settings", json={"enabled": False})
        assert response.status_code == 403
    async with aclosing(await _signed_in(*ADMIN)) as admin:
        assert (await admin.get("/api/inventory-summaries/settings")).status_code == 200
        assert (await admin.get("/api/inventory-summaries/metrics")).status_code == 200
        invalid = await admin.put("/api/inventory-summaries/settings", json={"preprompt": "x" * 501})
        assert invalid.status_code == 422
