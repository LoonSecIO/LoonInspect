"""The second-factor policy, its gate, administrative removal and new recovery codes (#653), on Postgres."""

from __future__ import annotations

import json
import logging
import os
import time

import httpx
import pyotp
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from app.core import mfa
from app.core.auth import MFA_ENROLMENT_REQUIRED
from app.core.database import session_for_tenant
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.models.schema import Account, AuthIdentity, LoginAttempt, Tenant, UserSession

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]
PASSWORD = "mfa-policy-password"
ADMIN, OTHER, VIEWER, GLASS = (f"mfa-policy-{who}@example.com" for who in ("admin", "other", "viewer", "glass"))
POLICY = "/api/settings/mfa-policy"


async def _set_policy(word: str) -> None:
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(update(Tenant).where(Tenant.id == OPERATIONAL_TENANT_ID).values(mfa_required=word))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def people(tenant_ready):
    """Two admins, a viewer and a break-glass admin with no factor, session or lockout, policy `off`: before and after."""
    from app.core.bootstrap import create_account

    async def reset() -> dict[str, str]:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            ids = {}
            for email, role in ((ADMIN, "admin"), (OTHER, "admin"), (VIEWER, "viewer"), (GLASS, "admin")):
                account = (await db.execute(select(Account).where(Account.email == email))).scalars().first()
                if account is None:
                    account, _ = await create_account(db, email=email, display_name=email, password=PASSWORD, roles=(role,))
                account.is_break_glass, ids[email] = email == GLASS, account.id
            # Sessions point at the identity they were minted through, so they go first.
            await db.execute(delete(UserSession).where(UserSession.account_id.in_(ids.values())))
            await db.execute(
                delete(AuthIdentity).where(AuthIdentity.account_id.in_(ids.values()), AuthIdentity.provider == "totp")
            )
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier.in_(ids)))
            await db.commit()
        await _set_policy("off")
        return ids

    yield await reset()
    await reset()


@pytest.fixture
def audited() -> list[dict]:
    from app.core.audit import _audit_logger

    captured: list[dict] = []
    handler, tenant_logger = logging.Handler(), _audit_logger(str(OPERATIONAL_TENANT_ID))
    handler.emit = lambda record: captured.append(json.loads(record.getMessage()))
    tenant_logger.addHandler(handler)
    yield captured
    tenant_logger.removeHandler(handler)


def _client() -> httpx.AsyncClient:
    from app.main import app

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mfa-policy.example.com")


async def _sign_in(client: httpx.AsyncClient, email: str, code: str | None = None) -> httpx.Response:
    answer = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    if answer.status_code == 202:
        answer = await client.post("/api/auth/login/mfa", json={"challenge": answer.json()["challenge"], "code": code})
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return answer


@pytest.mark.parametrize("policy", ["off", "admins", "everyone"])
async def test_each_policy_word_gates_whom_it_names_and_never_break_glass_or_a_token(people, policy, caplog):
    async with _client() as admin:
        await _sign_in(admin, ADMIN)
        token = (await admin.post("/api/auth/tokens", json={"name": f"mfa-policy-{policy}"})).json()["token"]
    await _set_policy(policy)
    for email, asked in ((ADMIN, policy != "off"), (VIEWER, policy == "everyone"), (GLASS, False)):
        caplog.clear()
        async with _client() as client:
            with caplog.at_level(logging.INFO, logger="app.api.auth"):
                assert (await _sign_in(client, email)).json()["mfaEnrolmentRequired"] is asked
            assert (await client.get("/api/auth/me")).json()["mfaEnrolmentRequired"] is asked
            devices = await client.get("/api/devices?pageSize=1")
            assert devices.status_code == (403 if asked else 200)
            assert (devices.json().get("detail") == MFA_ENROLMENT_REQUIRED) is asked
            assert (await client.get("/api/auth/mfa")).status_code == 200
        # Never asked, and its sign-in says so whenever the policy asks anyone else.
        assert ("the policy exempts it" in caplog.text) is (email == GLASS and policy != "off")
    async with _client() as bearer:
        bearer.headers["Authorization"] = f"Bearer {token}"
        assert (await bearer.get("/api/devices?pageSize=1")).status_code == 200


async def test_set_the_policy_enrol_through_its_gate_replace_the_codes_and_have_the_factor_removed(people, audited):
    async with _client() as admin, _client() as viewer:
        await _sign_in(admin, ADMIN)
        await _sign_in(viewer, VIEWER)
        assert (await admin.get(POLICY)).json() == {"mfaRequired": "off"}
        assert (await viewer.get(POLICY)).status_code == 403
        assert (await viewer.put(POLICY, json={"mfaRequired": "admins"})).status_code == 403
        assert (await admin.put(POLICY, json={"mfaRequired": "sometimes"})).status_code == 422
        assert (await admin.put(POLICY, json={"mfaRequired": "admins"})).json() == {"mfaRequired": "admins"}
    async with _client() as other:
        await _sign_in(other, OTHER)
        assert (await other.get("/api/devices?pageSize=1")).json() == {"detail": MFA_ENROLMENT_REQUIRED}
        totp = pyotp.TOTP((await other.post("/api/auth/mfa/enrol")).json()["secret"])
        spent = totp.now()
        old = (await other.post("/api/auth/mfa/confirm", json={"code": spent})).json()["recoveryCodes"]
        assert (await other.get("/api/devices?pageSize=1")).status_code == 200
        # New recovery codes want a fresh code from the phone: not a wrong one, a spent one, or a recovery code.
        for refused in (str((int(spent) + 1) % 1_000_000).zfill(6), spent, old[0]):
            assert (await other.post("/api/auth/mfa/recovery-codes", json={"code": refused})).status_code == 401
        fresh = await other.post("/api/auth/mfa/recovery-codes", json={"code": totp.at(int(time.time()) + 30)})
        new = fresh.json()["recoveryCodes"]
        assert len(new) == 10 and not set(new) & set(old)
    async with _client() as other, _client() as glass:
        assert (await _sign_in(other, OTHER, old[1])).status_code == 401
        assert (await _sign_in(other, OTHER, new[0])).status_code == 200
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            factor = mfa.identity_for(await db.get(Account, people[OTHER]))
            # The session just minted through the factor holds it: the row cannot simply go first.
            with pytest.raises(IntegrityError):
                await db.execute(delete(AuthIdentity).where(AuthIdentity.id == factor.id))
        await _sign_in(glass, GLASS)
        assert "your own" in (await glass.delete(f"/api/accounts/{people[GLASS]}/mfa")).json()["detail"]
        assert "no second factor" in (await glass.delete(f"/api/accounts/{people[VIEWER]}/mfa")).json()["detail"]
        assert (await glass.post("/api/auth/mfa/recovery-codes", json={"code": "123456"})).status_code == 409
        assert (await glass.delete(f"/api/accounts/{people[OTHER]}/mfa")).status_code == 204
        assert (await other.get("/api/auth/me")).status_code == 401
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert await db.get(AuthIdentity, factor.id) is None
        sessions = (await db.execute(select(UserSession).where(UserSession.account_id == people[OTHER]))).scalars().all()
        # All revoked; the one minted through the factor let go of it (a password session holds the password's).
        assert all(row.revoked_at is not None for row in sessions) and None in {row.identity_id for row in sessions}
    trail = [
        (r["action"], r["actor_label"], r["metadata"]) for r in audited if r["action"].startswith(("auth.mfa.re", "settings"))
    ]
    assert trail == [
        ("settings.mfa_policy.changed", ADMIN, {"before": "off", "after": "admins"}),
        ("auth.mfa.recovery-codes.regenerated", OTHER, {"email": OTHER}),
        ("auth.mfa.recovery-code.used", OTHER, {"remaining": 9}),
        ("auth.mfa.removed", GLASS, {"email": OTHER}),
    ]
    # What happens next: the password alone signs in, and the policy asks for a factor again.
    async with _client() as other:
        assert (await _sign_in(other, OTHER)).json()["mfaEnrolmentRequired"] is True
