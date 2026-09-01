"""Who consented to community data sharing, and what happens when nobody did.

docs/data-sharing.md rests the case for a pre-checked sharing default on one sentence:
"Every operator affirmatively sees it before the first byte leaves; nobody discovers it
in a traffic capture." That sentence was false on the path the README documents.
`bootstrap_accounts` returns as soon as INITIAL_ADMIN_EMAIL/PASSWORD provision an admin
— before the claim token is minted — so the wizard never renders, no consent row is
ever written, and an absent row used to mean tier "reveal": the most permissive one.
Every pod, every scripted deploy, every container in an MSP's fleet started shipping
application prevalence derived from identifiable employees' machines without anyone
being asked.

The rule these tests hold is "an install that was never asked does not share", and they
assert the *effective* tier and the *absence of a POST*, not merely a stored value —
the failure this guards against is bytes leaving the box, and only the exchange path
can testify to that. The pure-logic tripwire on the default literal lives in
test_sharing.py; what needs a real Postgres is everything below, because the consent row
is behind FORCEd row-level security and its birth is a database default.

Gated on RUN_DB_TESTS like the other database-backed suites; see test_tenancy_sweep.py
for the local invocation pattern.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import datetime, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

# One event loop for the whole module: the engine's pooled connections belong to
# whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"
    ),
    pytest.mark.asyncio(loop_scope="session"),
]

# Three tenants of this suite's own. Every test here needs an install with *zero*
# accounts — that is the state both bootstrap paths are defined on, and the one the
# setup endpoint is live in — and the operational tenant is seeded by half the suite.
# Fixed ids in the style of test_tenancy_sweep's second tenant.
ENV_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000c1")
WIZARD_YES_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000c2")
WIZARD_NO_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000c3")
# The backfill's two cases. One row per tenant is the whole table's shape (tenant_id is
# the primary key), so telling "never answered" apart from "answered yes" needs two.
UNRECORDED_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000c4")
RECORDED_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000c5")

_TENANTS = (
    (ENV_TENANT_ID, "consent-env"),
    (WIZARD_YES_TENANT_ID, "consent-wizard-yes"),
    (WIZARD_NO_TENANT_ID, "consent-wizard-no"),
    (UNRECORDED_TENANT_ID, "consent-unrecorded"),
    (RECORDED_TENANT_ID, "consent-recorded"),
)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenants_ready() -> None:
    """Migrated schema and three empty tenants — emptied on the way in, not the way
    out. A developer re-running this locally against a persistent database must find
    the unbootstrapped state these tests are about, and a crashed previous run must not
    leave an account behind that turns "the wizard is live" into a 409."""
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.models.schema import (
        Account,
        AccountRole,
        AuthIdentity,
        DataSharingSettings,
        ShareLog,
        Tenant,
        UserSession,
    )

    await init_db()

    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        existing = set(
            (await db.execute(select(Tenant.id).where(Tenant.id.in_([t[0] for t in _TENANTS]))))
            .scalars()
            .all()
        )
        for tenant_id, slug in _TENANTS:
            if tenant_id not in existing:
                db.add(Tenant(id=tenant_id, slug=slug, name=slug, kind="operational"))
        await db.commit()

    for tenant_id, _ in _TENANTS:
        async with session_for_tenant(tenant_id) as db:
            # Children before parents: sessions and identities carry the account FK.
            for model in (UserSession, AccountRole, AuthIdentity, Account, DataSharingSettings, ShareLog):
                await db.execute(delete(model))
            await db.commit()


def _db(tenant_id: uuidlib.UUID):
    from app.core.database import session_for_tenant

    return session_for_tenant(tenant_id)


class _Recorder:
    """A transport that fails the test if it is ever asked to send anything.

    The assertion is the point: "no exchange was attempted" is not observable from the
    share log alone, because `run_exchange` returns before it writes a row when the tier
    is off. Something has to be watching the socket."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(str(request.url))
        return httpx.Response(200, json={"contract": "v1"})

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


async def test_an_install_bootstrapped_from_env_is_never_asked_and_does_not_share(
    tenants_ready, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The finding, end to end, on the path the README documents.

    Three assertions in order, because each is a separate half-truth on its own: the
    wizard genuinely never renders (no claim token is minted), the effective tier is
    off, and `exchange_due` — the scheduler's own question, asked through the same
    lazily-created row — answers no.
    """
    from app.core.bootstrap import account_count, bootstrap_accounts, get_claim_token
    from app.core.config import settings
    from app.core.sharing import exchange_due, get_or_create_settings

    monkeypatch.setattr(settings, "initial_admin_email", "pod-admin@example.com")
    monkeypatch.setattr(settings, "initial_admin_password", "correct-horse-battery-staple")

    async with _db(ENV_TENANT_ID) as db:
        assert await account_count(db) == 0
        await bootstrap_accounts(db)
        assert await account_count(db) == 1

        # Fact one from the finding: this path returns before the token is minted, so
        # the SetupPage that carries the sharing question never gets a chance to render.
        assert get_claim_token() is None

        assert (await get_or_create_settings(db)).tier == "off"
        assert await exchange_due(db) is False


async def test_a_never_asked_install_attempts_no_exchange(tenants_ready) -> None:
    """The property that actually matters: no bytes leave.

    Deliberately routed through `run_exchange` rather than `exchange_due`, and with
    COMMUNITY_SHARING asserted *on* first, so the test cannot pass for the comfortable
    wrong reason. What must stop the request is the tier short-circuit at the top of
    `run_exchange` — the env override would have logged a `skipped_env` row instead, and
    that row would be the tell that the consent default was not what stopped it.
    """
    from app.core.config import settings
    from app.core.sharing import get_or_create_settings, run_exchange
    from app.models.schema import ShareLog

    assert settings.community_sharing is True

    recorder = _Recorder()
    async with _db(ENV_TENANT_ID) as db:
        assert (await get_or_create_settings(db)).tier == "off"
        await run_exchange(db, transport=recorder.transport)

        assert recorder.calls == []
        assert (await db.execute(select(ShareLog))).scalars().all() == []


async def _run_wizard(tenant_id: uuidlib.UUID, monkeypatch: pytest.MonkeyPatch, *, share: bool):
    """Drive the real first-run wizard against one empty tenant.

    The route function is called directly rather than over ASGI: the endpoint is live
    only while `account_count == 0`, and the tenancy middleware pins every HTTP request
    to the operational tenant, which other suites have already seeded. So the layer this
    exercises is the handler, its schema, and the database — everything except Starlette's
    routing. `bootstrap_accounts` runs first with no INITIAL_ADMIN_* set, which is what
    mints the claim token: the interactive path is entered the way a real container
    enters it, not by hand-setting the module global.
    """
    from fastapi import Response
    from starlette.requests import Request

    from app.api.auth import setup
    from app.core.bootstrap import bootstrap_accounts, get_claim_token
    from app.core.config import settings
    from app.schemas.auth import SetupRequest

    monkeypatch.setattr(settings, "initial_admin_email", None)
    monkeypatch.setattr(settings, "initial_admin_password", None)

    async with _db(tenant_id) as db:
        await bootstrap_accounts(db)
        token = get_claim_token()
        assert token is not None, "the interactive path must mint a claim token"

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/auth/setup",
                "headers": [(b"user-agent", b"consent-suite")],
                "query_string": b"",
                "client": ("127.0.0.1", 12345),
            }
        )
        payload = SetupRequest(
            claim_token=token,
            email=f"wizard-{'yes' if share else 'no'}@example.com",
            display_name="Wizard Admin",
            password="correct-horse-battery-staple",
            share_community_data=share,
        )
        await setup(payload, request, Response(), db)


async def test_the_wizard_records_a_yes_rather_than_assuming_one(
    tenants_ready, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The interactive path still consents — and now says so in the row.

    This is the test that stops the fix from becoming a different bug. A default of off
    is only correct if a ticked box is written down; if it were still inferred from
    silence, this change would have quietly ended community sharing for everyone rather
    than only for installs nobody asked. `updated_at` is asserted because it is what
    distinguishes an answered install from an unanswered one — the migration's backfill
    reads exactly that column.
    """
    from app.core.sharing import get_or_create_settings, run_exchange

    await _run_wizard(WIZARD_YES_TENANT_ID, monkeypatch, share=True)

    recorder = _Recorder()
    async with _db(WIZARD_YES_TENANT_ID) as db:
        row = await get_or_create_settings(db)
        assert row.tier == "reveal"
        assert row.updated_at is not None

        # And it still reaches the wire. `exchange_due` is deliberately not the
        # assertion here: its answer depends on a minute-of-day derived from a random
        # submission UUID, so a due-ness check would be a coin flip dressed as a test.
        await run_exchange(db, transport=recorder.transport)
        assert len(recorder.calls) == 1


async def test_the_wizard_records_a_no(tenants_ready, monkeypatch: pytest.MonkeyPatch) -> None:
    """The unticked box, which used to be the only answer that got written."""
    from app.core.sharing import get_or_create_settings, run_exchange
    from app.models.schema import ShareLog

    await _run_wizard(WIZARD_NO_TENANT_ID, monkeypatch, share=False)

    recorder = _Recorder()
    async with _db(WIZARD_NO_TENANT_ID) as db:
        row = await get_or_create_settings(db)
        assert row.tier == "off"
        assert row.updated_at is not None

        await run_exchange(db, transport=recorder.transport)
        assert recorder.calls == []
        assert (await db.execute(select(ShareLog))).scalars().all() == []


async def test_the_column_default_in_the_live_schema_is_off(tenants_ready) -> None:
    """The other half of the regression guard, asserted against the database rather
    than the model.

    The ORM supplies `tier` on every insert it makes, so this column default is only
    load-bearing for something that inserts without it — a hand-written statement, a
    future migration's backfill, a management API that builds rows in SQL. A schema
    whose stated default is the most permissive tier is a loaded gun left for whichever
    of those comes first, and this fails if migration d5b1e7c4a930 is reverted or a
    later one puts 'reveal' back.
    """
    async with _db(ENV_TENANT_ID) as db:
        default = (
            await db.execute(
                text(
                    "SELECT column_default FROM information_schema.columns "
                    "WHERE table_name = 'data_sharing_settings' AND column_name = 'tier'"
                )
            )
        ).scalar_one()

    assert default is not None
    assert default.startswith("'off'"), default


async def test_the_backfill_withdraws_consent_that_was_never_recorded(tenants_ready) -> None:
    """The upgrade's data half, run against real rows.

    The statement is imported from the revision file rather than restated here, so this
    cannot drift from what `alembic upgrade` executes — the same arrangement
    test_destinations uses for the run.failed backfill, and the tenant-bound session
    stands in for the migration's per-tenant `set_config` walk.

    What it pins is the *predicate*, which is the judgement call in this whole change:
    `updated_at IS NULL` is the closest thing the schema has to "nobody answered", and a
    backfill that ignored it would reach past never-asked installs and switch off
    operators who had genuinely chosen a tier. The second tenant below is that operator.
    """
    import importlib.util

    from app.models.schema import DataSharingSettings

    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "migrations",
        "versions",
        "d5b1e7c4a930_sharing_consent_defaults_off.py",
    )
    spec = importlib.util.spec_from_file_location("migration_d5b1e7c4a930", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    # The pre-migration world: a row that shares because a default said so, and a row
    # that shares because somebody said so.
    async with _db(UNRECORDED_TENANT_ID) as db:
        db.add(DataSharingSettings(tier="reveal", submission_uuid=uuidlib.uuid4(), exclude_globs=[]))
        await db.commit()
    async with _db(RECORDED_TENANT_ID) as db:
        db.add(
            DataSharingSettings(
                tier="reveal",
                submission_uuid=uuidlib.uuid4(),
                exclude_globs=[],
                updated_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    for tenant_id in (UNRECORDED_TENANT_ID, RECORDED_TENANT_ID):
        async with _db(tenant_id) as db:
            await db.execute(text(migration.WITHDRAW_UNRECORDED_CONSENT))
            await db.commit()

    # Columns, not entities: the raw UPDATE went around the ORM, and an entity select
    # would answer from the identity map's pre-migration state.
    async with _db(UNRECORDED_TENANT_ID) as db:
        assert (await db.execute(select(DataSharingSettings.tier))).scalar_one() == "off"
    async with _db(RECORDED_TENANT_ID) as db:
        assert (await db.execute(select(DataSharingSettings.tier))).scalar_one() == "reveal"
