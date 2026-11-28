"""Passkeys (#955) against real Postgres: enrolment, a sign-in with the passkey alone, a replayed challenge, an
answer for the wrong origin or host, a removed passkey, a disabled account, the policy answered by a passkey, an
administrator's removal, the 1,023-byte credential id, and the address rules, behind a proxy too. The browser is
tests/soft_passkey.py, which answers the way `PublicKeyCredential.toJSON()` writes an answer."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from app.api.passkeys import SESSION_ONLY
from app.core import passkeys
from app.core.auth import MFA_ENROLMENT_REQUIRED
from app.core.database import session_for_tenant
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.models.schema import (
    Account,
    ApiToken,
    AuthIdentity,
    LoginAttempt,
    PasskeyChallenge,
    Tenant,
    UserSession,
)
from tests.soft_passkey import SoftPasskey, b64, unb64

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]
PASSWORD = "passkey-test-password"
ADMIN, VIEWER, OTHER = (f"passkey-{who}@example.com" for who in ("admin", "viewer", "other"))
ORIGIN = "https://passkeys.example.com"
HOST = "passkeys.example.com"
OPTIONS, SIGN_IN, MINE = "/api/auth/login/passkey/options", "/api/auth/login/passkey", "/api/auth/passkeys"


async def _set_policy(word: str) -> None:
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(update(Tenant).where(Tenant.id == OPERATIONAL_TENANT_ID).values(mfa_required=word))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def people(tenant_ready):
    """An admin, a viewer and a second admin this file owns, active, with no passkey, code, session, token or
    lockout, and the policy off: before and after."""
    from app.core.bootstrap import create_account

    async def reset() -> dict[str, str]:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            ids = {}
            for email, role in ((ADMIN, "admin"), (VIEWER, "viewer"), (OTHER, "admin")):
                account = (await db.execute(select(Account).where(Account.email == email))).scalars().first()
                if account is None:
                    account, _ = await create_account(db, email=email, display_name=email, password=PASSWORD, roles=(role,))
                account.status, ids[email] = "active", account.id
            # Sessions point at the identity they were minted through, so they go first.
            await db.execute(delete(UserSession).where(UserSession.account_id.in_(ids.values())))
            await db.execute(delete(ApiToken).where(ApiToken.account_id.in_(ids.values())))
            mine = AuthIdentity.account_id.in_(ids.values()), AuthIdentity.provider.in_((passkeys.PROVIDER, "totp"))
            await db.execute(delete(AuthIdentity).where(*mine))
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier.in_(ids)))
            await db.execute(delete(PasskeyChallenge).where(PasskeyChallenge.account_id.in_(ids.values())))
            await db.commit()
        await _set_policy("off")
        return ids

    yield await reset()
    await reset()


@pytest.fixture
def audited() -> list[dict]:
    from app.core.audit import SYSTEM_AUDIT_KEY, _audit_logger

    captured: list[dict] = []
    handler = logging.Handler()
    handler.emit = lambda record: captured.append(json.loads(record.getMessage()))
    loggers = [_audit_logger(str(OPERATIONAL_TENANT_ID)), _audit_logger(SYSTEM_AUDIT_KEY)]
    for tenant_logger in loggers:
        tenant_logger.addHandler(handler)
    yield captured
    for tenant_logger in loggers:
        tenant_logger.removeHandler(handler)


def _client(base: str = ORIGIN, **transport) -> httpx.AsyncClient:
    from app.main import app

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, **transport), base_url=base)


async def _sign_in(client: httpx.AsyncClient, email: str, password: str = PASSWORD) -> httpx.Response:
    answer = await client.post("/api/auth/login", json={"email": email, "password": password})
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return answer


async def _add(client: httpx.AsyncClient, key: SoftPasskey, name: str = "MacBook Pro", **create) -> httpx.Response:
    options = await client.post(f"{MINE}/options", json={"currentPassword": PASSWORD})
    assert options.status_code == 200, options.text
    answer = key.create(options.json()["publicKey"], origin=create.pop("origin", ORIGIN), **create)
    return await client.post(MINE, json={"name": name, "credential": answer})


async def _enrolled(email: str, key: SoftPasskey | None = None, base: str = ORIGIN) -> tuple[SoftPasskey, str]:
    """A passkey added to `email`'s account from a password session at `base`, which then signs out."""
    key = key or SoftPasskey()
    async with _client(base) as client:
        assert (await _sign_in(client, email)).status_code == 200
        added = await _add(client, key, origin=base)
        assert added.status_code == 201, added.text
        await client.post("/api/auth/logout")
    return key, added.json()["id"]


async def _passkey_sign_in(client: httpx.AsyncClient, key: SoftPasskey, origin: str = ORIGIN, **answer) -> httpx.Response:
    options = await client.post(OPTIONS)
    assert options.status_code == 200, options.text
    response = await client.post(SIGN_IN, json={"credential": key.get(options.json()["publicKey"], origin=origin, **answer)})
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return response


async def _sessions(account_id: str) -> list[UserSession]:
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        found = await db.execute(select(UserSession).where(UserSession.account_id == account_id).order_by(UserSession.created_at))
        return list(found.scalars().all())


# --- enrolment and the sign-in it makes possible -----------------------------------------------------------


async def test_add_a_passkey_with_the_password_then_sign_in_with_the_passkey_alone(people, audited):
    key = SoftPasskey()
    async with _client() as client:
        assert (await _sign_in(client, ADMIN)).status_code == 200
        assert (await client.get(MINE)).json() == []
        public = (await client.post(f"{MINE}/options", json={"currentPassword": PASSWORD})).json()["publicKey"]
        assert public["rp"] == {"name": "LoonInspect", "id": HOST}
        assert (unb64(public["user"]["id"]), public["user"]["name"]) == (people[ADMIN].encode(), ADMIN)
        selection = {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"}
        assert public["authenticatorSelection"] == selection
        assert (public["attestation"], public["timeout"], public["excludeCredentials"]) == ("none", 300_000, [])
        assert [param["alg"] for param in public["pubKeyCredParams"]] == [-7, -8, -257]
        added = await client.post(MINE, json={"name": "  MacBook   Pro ", "credential": key.create(public, origin=ORIGIN)})
        assert added.status_code == 201, added.text
        body = added.json()
        assert (body["name"], body["host"], body["lastUsedAt"]) == ("MacBook Pro", HOST, None)
        assert (await client.get(MINE)).json() == [body]
        # A second registration excludes the passkey this account already has here, and the same one is not added twice.
        again = (await client.post(f"{MINE}/options", json={"currentPassword": PASSWORD})).json()["publicKey"]
        assert [descriptor["id"] for descriptor in again["excludeCredentials"]] == [b64(key.credential_id)]
        twice = await client.post(MINE, json={"name": "Again", "credential": key.create(again, origin=ORIGIN)})
        assert (twice.status_code, twice.json()["detail"]) == (409, passkeys.ALREADY_ADDED)
        await client.post("/api/auth/logout")

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        row = await db.get(AuthIdentity, body["id"])
        stored = (row.provider, row.subject, row.credential_id, row.sign_count, row.rp_id, row.secret_hash)
        assert stored == (passkeys.PROVIDER, hashlib.sha256(key.credential_id).hexdigest(), key.credential_id, 0, HOST, None)
        # What the browser said it can reach the passkey over, the transports this code knows of; synced, so both flags.
        assert (row.transports, row.backup_eligible, row.backed_up) == (["hybrid", "internal"], True, True)
    # The password session that added it proved the device and the person just then.
    assert [s.auth_method for s in await _sessions(people[ADMIN])] == [passkeys.METHOD_ADDED]

    async with _client() as client:
        signed = await _passkey_sign_in(client, key)
        assert signed.status_code == 200, signed.text
        assert (signed.json()["email"], signed.json()["mfaEnrolmentRequired"]) == (ADMIN, False)
        assert (await client.get("/api/auth/me")).status_code == 200
        assert (await client.get(MINE)).json()[0]["lastUsedAt"] is not None
    newest = (await _sessions(people[ADMIN]))[-1]
    assert (newest.auth_method, newest.identity_id) == (passkeys.METHOD, body["id"])

    trail = [(r["action"], r["actor_label"], r["metadata"]) for r in audited if r["action"].startswith("auth.passkey")]
    assert trail == [
        ("auth.passkey.added", ADMIN, {"email": ADMIN, "passkey_id": body["id"], "name": "MacBook Pro", "host": HOST})
    ]
    signed_in = [r["metadata"] for r in audited if r["action"] == "auth.login.succeeded"]
    assert [(m["auth_method"], m.get("passkey_id")) for m in signed_in][-1] == (passkeys.METHOD, body["id"])


async def test_a_challenge_is_accepted_once_and_a_replayed_answer_signs_nobody_in(people):
    key, _ = await _enrolled(ADMIN)
    async with _client() as first:
        options = (await first.post(OPTIONS)).json()["publicKey"]
        challenge_row = hashlib.sha256(unb64(options["challenge"])).hexdigest()
        # The challenge is a row in the database, not something this process remembers.
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            assert (await db.get(PasskeyChallenge, challenge_row)).purpose == passkeys.SIGN_IN
        answer = key.get(options, origin=ORIGIN)
        assert (await first.post(SIGN_IN, json={"credential": answer})).status_code == 200
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert await db.get(PasskeyChallenge, challenge_row) is None
    async with _client() as replay:
        again = await replay.post(SIGN_IN, json={"credential": answer})
        assert (again.status_code, again.json()["detail"]) == (401, passkeys.SPENT[passkeys.SIGN_IN])
        assert "loon_session" not in replay.cookies

    # Two copies of one answer at once, each on its own connection: exactly one session.
    async with _client() as fetch:
        racing = key.get((await fetch.post(OPTIONS)).json()["publicKey"], origin=ORIGIN)
    before = len(await _sessions(people[ADMIN]))
    async with _client() as one, _client() as two:
        answers = await asyncio.gather(*(c.post(SIGN_IN, json={"credential": racing}) for c in (one, two)))
    assert sorted(a.status_code for a in answers) == [200, 401]
    assert len(await _sessions(people[ADMIN])) == before + 1


async def test_an_answer_for_another_origin_or_host_or_without_verification_is_refused_in_words(people, audited):
    key, _ = await _enrolled(ADMIN)
    async with _client() as client:
        foreign = await _passkey_sign_in(client, key, origin="https://evil.example.com")
        assert (foreign.status_code, foreign.json()["detail"]) == (
            401,
            passkeys.signed_origin_refusal("https://evil.example.com", ORIGIN),
        )
        assert "https://evil.example.com" in foreign.json()["detail"] and ORIGIN in foreign.json()["detail"]
        elsewhere = await _passkey_sign_in(client, key, rp_id="evil.example.com")
        assert (elsewhere.status_code, elsewhere.json()["detail"]) == (401, passkeys.NOT_ACCEPTED)
        unverified = await _passkey_sign_in(client, key, verified=False)
        assert (unverified.status_code, unverified.json()["detail"]) == (401, passkeys.NOT_VERIFIED)
        for junk in ({}, {"id": "AA", "rawId": "AA"}, {"id": "!", "rawId": "!", "response": {"clientDataJSON": "e30"}}):
            unread = await client.post(SIGN_IN, json={"credential": junk})
            assert (unread.status_code, unread.json()["detail"]) == (400, passkeys.UNREADABLE)
        assert "loon_session" not in client.cookies
    reasons = [r["metadata"]["reason"] for r in audited if r["action"] == "auth.passkey.refused"]
    assert reasons[:3] == ["origin_mismatch", "not_accepted", "not_verified"]


async def test_registration_refuses_another_host_no_verification_and_a_challenge_from_another_session(people):
    async with _client() as asker, _client() as elsewhere:
        await _sign_in(asker, ADMIN)
        await _sign_in(elsewhere, ADMIN)
        wrong = (({"rp_id": "evil.example.com"}, passkeys.OTHER_HOST), ({"verified": False}, passkeys.NOT_VERIFIED))
        for create, sentence in wrong:
            refused = await _add(asker, SoftPasskey(), **create)
            assert (refused.status_code, refused.json()["detail"]) == (409, sentence)
        public = (await asker.post(f"{MINE}/options", json={"currentPassword": PASSWORD})).json()["publicKey"]
        answer = SoftPasskey().create(public, origin=ORIGIN)
        stolen = await elsewhere.post(MINE, json={"name": "Stolen", "credential": answer})
        assert (stolen.status_code, stolen.json()["detail"]) == (409, passkeys.SPENT[passkeys.REGISTER])
        # The refused answer spent the challenge: the session that asked starts again too.
        assert (await asker.post(MINE, json={"name": "Late", "credential": answer})).status_code == 409
        for name in ("   ", "x" * (passkeys.MAX_NAME_LENGTH + 1)):
            unnamed = await _add(asker, SoftPasskey(), name=name)
            assert (unnamed.status_code, unnamed.json()["detail"]) == (422, passkeys.NAME_REQUIRED)
        assert (await asker.get(MINE)).json() == []


async def test_adding_a_passkey_wants_the_current_password_which_shares_the_lockout_a_passkey_does_not(people):
    key, _ = await _enrolled(ADMIN)
    async with _client() as client:
        await _sign_in(client, ADMIN)
        for _ in range(5):
            wrong = await client.post(f"{MINE}/options", json={"currentPassword": "not-the-password"})
            assert (wrong.status_code, wrong.json()["detail"]) == (401, "Current password is incorrect")
        locked = await client.post(f"{MINE}/options", json={"currentPassword": PASSWORD})
        assert (locked.status_code, locked.json()["detail"]) == (429, "Too many failed attempts. Try again later.")
    async with _client() as client:
        assert (await _sign_in(client, ADMIN)).status_code == 429
        # A signature over a fresh challenge is not a guess: the lockout neither holds a passkey back nor counts its refusals.
        assert (await _passkey_sign_in(client, key, verified=False)).status_code == 401
        assert (await _passkey_sign_in(client, key)).status_code == 200
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        attempt = (await db.execute(select(LoginAttempt).where(LoginAttempt.identifier == ADMIN))).scalars().one()
        assert attempt.failure_count == 5


async def test_a_bearer_token_lists_passkeys_but_never_adds_or_removes_one(people):
    _, passkey_id = await _enrolled(ADMIN)
    async with _client() as client:
        await _sign_in(client, ADMIN)
        token = (await client.post("/api/auth/tokens", json={"name": "passkey-probe"})).json()["token"]
    async with _client() as bearer:
        bearer.headers["Authorization"] = f"Bearer {token}"
        assert [row["id"] for row in (await bearer.get(MINE)).json()] == [passkey_id]
        for refused in (
            await bearer.post(f"{MINE}/options", json={"currentPassword": PASSWORD}),
            await bearer.post(MINE, json={"name": "Token", "credential": {}}),
            await bearer.delete(f"{MINE}/{passkey_id}"),
        ):
            assert (refused.status_code, refused.json()["detail"]) == (403, SESSION_ONLY)


# --- the challenge route, and the address it is asked at ---------------------------------------------------


async def test_the_sign_in_challenge_takes_no_email_and_answers_every_caller_alike(people):
    await _enrolled(ADMIN)
    async with _client() as anonymous, _client() as signed_in:
        await _sign_in(signed_in, ADMIN)
        answers = [
            (await anonymous.post(OPTIONS)).json(),
            (await anonymous.post(OPTIONS, json={"email": ADMIN})).json(),
            (await anonymous.post(OPTIONS, json={"email": "nobody-here@example.com"})).json(),
            (await signed_in.post(OPTIONS)).json(),
        ]
    challenges = {answer["publicKey"].pop("challenge") for answer in answers}
    assert len(challenges) == 4
    assert all(answer == {"publicKey": {"timeout": 300_000, "rpId": HOST, "userVerification": "required"}} for answer in answers)


@pytest.mark.parametrize(
    ("base", "sentence"),
    [
        ("http://10.0.0.5:8001", passkeys.ip_address_refusal),
        ("http://127.0.0.1:8001", passkeys.ip_address_refusal),
        ("http://[::1]:8001", passkeys.ip_address_refusal),
        ("https://192.0.2.7", passkeys.ip_address_refusal),
        ("http://inspect.corp.example:8001", passkeys.plain_http_refusal),
        ("http://looninspect.test:8001", passkeys.plain_http_refusal),
    ],
)
async def test_no_challenge_at_an_ip_address_or_over_plain_http_off_localhost(people, base, sentence):
    async with _client(base) as client:
        refused = await client.post(OPTIONS)
    expected = sentence(passkeys.parse_origin(base))
    assert (refused.status_code, refused.json()["detail"]) == (409, expected)
    # The sentence names the address the page was reached at, and what to open instead.
    assert passkeys.parse_origin(base).origin in expected and "localhost" in expected


@pytest.mark.parametrize("base", ["http://localhost:8001", "http://looninspect.localhost:8001", "https://inspect.corp.example"])
async def test_localhost_over_plain_http_and_any_https_host_name_get_a_challenge(people, base):
    async with _client(base) as client:
        answer = await client.post(OPTIONS, headers={"Origin": base})
    assert answer.status_code == 200, answer.text
    assert answer.json()["publicKey"]["rpId"] == passkeys.parse_origin(base).host


async def test_behind_a_proxy_the_signed_origin_is_the_one_expected_and_a_refusal_names_both(people):
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    from app.main import app

    proxied = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1")
    browser = "https://inspect.corp.example"
    key, _ = await _enrolled(ADMIN, base=browser)
    forwarded = {"X-Forwarded-Proto": "https", "Origin": browser}

    def through(peer: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxied, client=(peer, 40000)), base_url="http://inspect.corp.example"
        )

    # A proxy FORWARDED_ALLOW_IPS names terminated HTTPS and passed the Host through: the passkey signs in.
    async with through("127.0.0.1") as client:
        options = (await client.post(OPTIONS, headers=forwarded)).json()["publicKey"]
        answer = key.get(options, origin=browser)
        assert (await client.post(SIGN_IN, json={"credential": answer}, headers=forwarded)).status_code == 200
    # The same request from a peer it does not name: X-Forwarded-Proto is not believed, and both addresses are named.
    async with through("10.1.2.3") as client:
        refused = await client.post(OPTIONS, headers=forwarded)
    assert (refused.status_code, refused.json()["detail"]) == (
        409,
        passkeys.proxy_refusal(browser, "http://inspect.corp.example"),
    )
    # A proxy that rewrote the Host header on the way.
    async with _client("https://looninspect-app:8001") as client:
        rewritten = await client.post(OPTIONS, headers={"Origin": browser})
    assert rewritten.json()["detail"] == passkeys.proxy_refusal(browser, "https://looninspect-app:8001")


# --- removal, a disabled account, the policy -------------------------------------------------------------


async def test_a_removed_passkey_signs_nobody_in_and_the_sessions_it_signed_in_end(people, audited):
    phone_key, laptop_key = SoftPasskey(), SoftPasskey()
    async with _client() as owner:
        await _sign_in(owner, ADMIN)
        phone = (await _add(owner, phone_key, name="Phone")).json()["id"]
        assert (await _add(owner, laptop_key, name="Laptop")).status_code == 201
        async with _client() as on_phone, _client() as on_laptop, _client() as viewer:
            assert (await _passkey_sign_in(on_phone, phone_key)).status_code == 200
            assert (await _passkey_sign_in(on_laptop, laptop_key)).status_code == 200
            await _sign_in(viewer, VIEWER)
            # Not the viewer's: answered as a passkey nobody holds.
            assert (await viewer.delete(f"{MINE}/{phone}")).json() == {"detail": "Passkey not found"}
            assert (await owner.delete(f"{MINE}/{phone}")).status_code == 204
            assert (await on_phone.get("/api/auth/me")).status_code == 401
            assert (await on_laptop.get("/api/auth/me")).status_code == 200
            assert (await owner.get("/api/auth/me")).status_code == 200
        assert [row["name"] for row in (await owner.get(MINE)).json()] == ["Laptop"]
        assert (await owner.delete(f"{MINE}/{phone}")).status_code == 404
    async with _client() as client:
        refused = await _passkey_sign_in(client, phone_key)
        assert (refused.status_code, refused.json()["detail"]) == (401, passkeys.NOT_ACCEPTED)
    removed = [r["metadata"] for r in audited if r["action"] == "auth.passkey.removed"]
    assert removed == [{"email": ADMIN, "passkey_id": phone, "name": "Phone", "host": HOST, "by_administrator": False}]


async def test_a_disabled_accounts_passkey_is_refused_exactly_as_one_nobody_holds(people):
    key, _ = await _enrolled(VIEWER)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(update(Account).where(Account.id == people[VIEWER]).values(status="disabled"))
        await db.commit()
    async with _client() as client:
        disabled = await _passkey_sign_in(client, key)
        stranger = await _passkey_sign_in(client, SoftPasskey())
    assert disabled.status_code == stranger.status_code == 401
    assert disabled.content == stranger.content
    assert disabled.json() == {"detail": passkeys.NOT_ACCEPTED}


async def test_everyone_under_the_policy_is_answered_by_a_passkey_sign_in_and_a_held_session_can_add_one(people):
    key, _ = await _enrolled(VIEWER)
    await _set_policy("everyone")
    async with _client() as client:
        signed = await _passkey_sign_in(client, key)
        assert signed.json()["mfaEnrolmentRequired"] is False
        assert (await client.get("/api/devices?pageSize=1")).status_code == 200
    async with _client() as client:
        # Holding a passkey is not using one: the policy asks how this session signed in.
        assert (await _sign_in(client, VIEWER)).json()["mfaEnrolmentRequired"] is True
        assert (await client.get("/api/devices?pageSize=1")).json() == {"detail": MFA_ENROLMENT_REQUIRED}
        assert (await client.get(MINE)).status_code == 200
        # Adding a passkey is enrolment, so a held session reaches it, and the passkey it adds lets this session go.
        assert (await _add(client, SoftPasskey(), name="Second")).status_code == 201
        assert (await client.get("/api/auth/me")).json()["mfaEnrolmentRequired"] is False
        assert (await client.get("/api/devices?pageSize=1")).status_code == 200
    async with _client() as client:
        # An account with nothing yet: its first passkey, added in the held session, is its way in.
        assert (await _sign_in(client, OTHER)).json()["mfaEnrolmentRequired"] is True
        assert (await _add(client, SoftPasskey(), name="First")).status_code == 201
        assert (await client.get("/api/devices?pageSize=1")).status_code == 200


async def test_an_administrator_removes_every_passkey_of_another_account_and_every_session_it_has(people, audited):
    key, _ = await _enrolled(VIEWER)
    await _enrolled(VIEWER, SoftPasskey())
    async with _client() as by_passkey, _client() as by_password, _client() as admin:
        assert (await _passkey_sign_in(by_passkey, key)).status_code == 200
        assert (await _sign_in(by_password, VIEWER)).status_code == 200
        assert (await by_password.delete(f"/api/accounts/{people[OTHER]}/passkeys")).status_code == 403
        await _sign_in(admin, ADMIN)
        counts = {row["email"]: row["passkeys"] for row in (await admin.get("/api/accounts")).json() if row["email"] in people}
        assert counts == {ADMIN: 0, VIEWER: 2, OTHER: 0}
        own = await admin.delete(f"/api/accounts/{people[ADMIN]}/passkeys")
        assert own.json()["detail"] == "You cannot remove your own passkeys here. Remove them under My Account › Passkeys."
        none = await admin.delete(f"/api/accounts/{people[OTHER]}/passkeys")
        assert (none.status_code, none.json()["detail"]) == (409, "That account has no passkeys to remove.")
        assert (await admin.delete(f"/api/accounts/{people[VIEWER]}/passkeys")).status_code == 204
        assert (await by_passkey.get("/api/auth/me")).status_code == 401
        assert (await by_password.get("/api/auth/me")).status_code == 401
        listed = {row["email"]: row["passkeys"] for row in (await admin.get("/api/accounts")).json()}
        assert listed[VIEWER] == 0
    sessions = await _sessions(people[VIEWER])
    # Every session ended, and the one the passkey signed in let go of it before its row went.
    assert all(row.revoked_at is not None for row in sessions)
    assert {row.identity_id for row in sessions if row.auth_method == passkeys.METHOD} == {None}
    async with _client() as client:
        assert (await _passkey_sign_in(client, key)).json() == {"detail": passkeys.NOT_ACCEPTED}
        assert (await _sign_in(client, VIEWER)).status_code == 200
    trail = [(r["actor_label"], r["metadata"]) for r in audited if r["action"] == "auth.passkey.removed"]
    assert trail == [(ADMIN, {"email": VIEWER, "removed": 2, "by_administrator": True})]


# --- the credential id, the counter, the sweep ------------------------------------------------------------


async def test_a_credential_id_is_kept_whole_up_to_1023_bytes_and_refused_with_a_sentence_past_it(people):
    longest = SoftPasskey(credential_id=os.urandom(passkeys.MAX_CREDENTIAL_ID_BYTES))
    async with _client() as client:
        await _sign_in(client, ADMIN)
        assert (await _add(client, longest, name="Longest")).status_code == 201
        refused = await _add(client, SoftPasskey(credential_id=os.urandom(1024)), name="Too long")
        assert (refused.status_code, refused.json()["detail"]) == (422, passkeys.too_long(1024))
        assert "1,024 bytes" in refused.json()["detail"] and "1,023" in refused.json()["detail"]
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        found = select(AuthIdentity).where(AuthIdentity.subject == passkeys.subject_for(longest.credential_id))
        row = (await db.execute(found)).scalar_one()
        assert row.credential_id == longest.credential_id and len(row.credential_id) == 1023
        # The database holds the same line: a longer id written past the route is refused there too.
        with pytest.raises(IntegrityError, match="ck_auth_identities_credential_id_length"):
            past = AuthIdentity(account_id=people[ADMIN], provider=passkeys.PROVIDER, subject="f" * 64, credential_id=b"x" * 1024)
            db.add(past)
            await db.flush()
    async with _client() as client:
        assert (await _passkey_sign_in(client, longest)).status_code == 200
        # The password identity beside it is untouched.
        await client.post("/api/auth/logout")
        assert (await _sign_in(client, ADMIN)).status_code == 200


async def test_a_security_keys_counter_has_to_climb_and_a_synced_passkeys_zero_never_does(people, audited):
    security_key, _ = await _enrolled(ADMIN, SoftPasskey(synced=False))
    synced, _ = await _enrolled(ADMIN)
    async with _client() as client:
        for _ in range(2):
            assert (await _passkey_sign_in(client, security_key)).status_code == 200
            assert (await _passkey_sign_in(client, synced)).status_code == 200
        copied = await _passkey_sign_in(client, security_key, counter=security_key.counter)
        assert (copied.status_code, copied.json()["detail"]) == (401, passkeys.COUNTER)
        assert (await _passkey_sign_in(client, security_key, counter=security_key.counter + 5)).status_code == 200
    flagged = [r for r in audited if r["action"] == "auth.passkey.refused"]
    assert [(r["target_id"], r["metadata"]["reason"]) for r in flagged] == [(people[ADMIN], "counter_went_backwards")]


async def test_an_unanswered_challenge_is_swept_when_the_next_of_its_purpose_is_handed_out(people):
    stale = datetime.now(UTC) - timedelta(seconds=1)
    rows = {"a" * 64: passkeys.SIGN_IN, "b" * 64: passkeys.REGISTER}
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for digest, purpose in rows.items():
            await db.execute(delete(PasskeyChallenge).where(PasskeyChallenge.challenge_hash == digest))
            when = {"created_at": stale, "expires_at": stale}
            db.add(PasskeyChallenge(challenge_hash=digest, purpose=purpose, rp_id=HOST, origin=ORIGIN, **when))
        await db.commit()
    async with _client() as client:
        assert (await client.post(OPTIONS)).status_code == 200
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert await db.get(PasskeyChallenge, "a" * 64) is None
        assert await db.get(PasskeyChallenge, "b" * 64) is not None
        await db.execute(delete(PasskeyChallenge).where(PasskeyChallenge.challenge_hash == "b" * 64))
        await db.commit()
