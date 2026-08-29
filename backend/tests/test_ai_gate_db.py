"""The AI gate (INSPECT-0112) against a real Postgres: the socket refuses with the
flag off, consent gates off-pod calls only, a permitted call writes exactly one
disclosure line to the share log, and the consent round-trips through the same
system API the data-sharing tier uses. No AI feature exists yet — what is under
test is that the first one will arrive into plumbing that already refuses
correctly. Gated on RUN_DB_TESTS like the other database-backed suites."""

from __future__ import annotations

import json
import os

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

DESTINATION = "https://inference.example/v1/messages"


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


async def _reset(db) -> None:
    """Back to the shipped defaults: no flag row, consent off, no AI log rows.
    Other suites share the tenant, so only what this suite touches is cleared."""
    from app.core.ai import AI_SHARE_TIER
    from app.core.feature_flags import AI_FEATURES_FLAG
    from app.models.schema import DataSharingSettings, FeatureFlag, ShareLog

    await db.rollback()
    await db.execute(delete(FeatureFlag).where(FeatureFlag.key == AI_FEATURES_FLAG))
    await db.execute(delete(ShareLog).where(ShareLog.tier == AI_SHARE_TIER))
    row = (await db.execute(select(DataSharingSettings))).scalar_one_or_none()
    if row is not None:
        row.ai_inference = False
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db):
    await _reset(db)
    yield
    await _reset(db)


async def _flag_on(db) -> None:
    from app.api.feature_flags import update_feature_flag
    from app.core.feature_flags import AI_FEATURES_FLAG
    from app.schemas.feature_flags import FeatureFlagUpdate

    await update_feature_flag(AI_FEATURES_FLAG, FeatureFlagUpdate(enabled=True), db)


async def _consent_on(db) -> None:
    from app.api.system import update_data_sharing
    from app.schemas.system import DataSharingUpdate

    await update_data_sharing(DataSharingUpdate(ai_inference=True), db)


async def _ai_rows(db) -> list:
    from app.core.ai import AI_SHARE_TIER
    from app.models.schema import ShareLog

    return (
        (await db.execute(select(ShareLog).where(ShareLog.tier == AI_SHARE_TIER))).scalars().all()
    )


async def test_flag_defaults_off_and_the_gate_refuses(db, clean) -> None:
    """The master switch ships off — through the same listing the flags UI reads —
    and while it is off nothing AI runs, on-pod or off, and nothing is logged."""
    from app.api.feature_flags import list_feature_flags
    from app.core.ai import AIFeaturesDisabled, ai_features_enabled, require_ai
    from app.core.feature_flags import AI_FEATURES_FLAG

    flags = {f.key: f for f in await list_feature_flags(db)}
    assert flags[AI_FEATURES_FLAG].enabled is False

    assert await ai_features_enabled(db) is False
    with pytest.raises(AIFeaturesDisabled):
        await require_ai(db, feature="socket-test")
    with pytest.raises(AIFeaturesDisabled):
        await require_ai(db, feature="socket-test", destination=DESTINATION, fields=["app_name"])
    assert await _ai_rows(db) == []


async def test_consent_gates_off_pod_only(db, clean) -> None:
    """The flag turns the area on; consent governs egress. With the flag on and
    consent off, on-device work proceeds and not a byte may leave — unlogged
    refusals included: the log records what left, and nothing did."""
    from app.core.ai import AIConsentMissing, require_ai

    await _flag_on(db)

    await require_ai(db, feature="socket-test")  # on-pod: passes, logs nothing
    with pytest.raises(AIConsentMissing):
        await require_ai(db, feature="socket-test", destination=DESTINATION, fields=["app_name"])
    assert await _ai_rows(db) == []


async def test_permitted_off_pod_call_writes_one_disclosure_line(db, clean) -> None:
    """Both switches on: the call is permitted and the share log gains exactly one
    row — feature, destination, and the field names that left, deduplicated and
    sorted, with no payload contents — visible in the NDJSON download."""
    from app.api.system import download_share_log
    from app.core.ai import require_ai

    await _flag_on(db)
    await _consent_on(db)

    await require_ai(
        db,
        feature="socket-test",
        destination=DESTINATION,
        fields=["version", "app_name", "app_name"],
    )

    (row,) = await _ai_rows(db)
    assert row.endpoint == DESTINATION
    assert row.outcome == "sent"
    assert row.payload == {"feature": "socket-test", "fields": ["app_name", "version"]}

    response = await download_share_log(days=90, db=db)
    lines = [json.loads(line) for line in response.body.decode().splitlines()]
    ai_lines = [line for line in lines if line["tier"] == "ai"]
    assert len(ai_lines) == 1
    assert ai_lines[0]["endpoint"] == DESTINATION
    assert ai_lines[0]["payload"] == {"feature": "socket-test", "fields": ["app_name", "version"]}


async def test_off_pod_without_disclosure_is_a_programming_error(db, clean) -> None:
    """An off-pod call naming no fields is not a consent question — it is a caller
    trying to egress without disclosing, and the gate refuses it even with every
    switch on."""
    from app.core.ai import require_ai

    await _flag_on(db)
    await _consent_on(db)

    with pytest.raises(ValueError):
        await require_ai(db, feature="socket-test", destination=DESTINATION, fields=[])
    assert await _ai_rows(db) == []


async def test_an_ai_row_is_not_an_exchange_attempt(db, clean) -> None:
    """The rows share one log, but a permitted inference call must not read as a
    community exchange: due-ness would otherwise skip the day's exchange, and the
    Settings page would report an inference as "last exchange"."""
    from app.api.system import get_data_sharing
    from app.core.ai import require_ai
    from app.core.sharing import _last_attempt_at

    before_attempt = await _last_attempt_at(db)
    before_out = await get_data_sharing(db)

    await _flag_on(db)
    await _consent_on(db)
    await require_ai(db, feature="socket-test", destination=DESTINATION, fields=["app_name"])

    assert await _last_attempt_at(db) == before_attempt
    after_out = await get_data_sharing(db)
    assert after_out.last_exchange_at == before_out.last_exchange_at
    assert after_out.last_exchange_outcome == before_out.last_exchange_outcome


async def test_consent_round_trips_through_the_system_api(db, clean) -> None:
    """The consent lives on the same surface as the sharing tier: default off,
    settable and readable through the same routes, and orthogonal to the tier —
    updating one leaves the other alone."""
    from app.api.system import get_data_sharing, update_data_sharing
    from app.schemas.system import DataSharingUpdate, SharingTier

    original = await get_data_sharing(db)
    assert original.ai_inference is False  # the shipped default

    try:
        out = await update_data_sharing(DataSharingUpdate(ai_inference=True), db)
        assert out.ai_inference is True
        assert out.tier == original.tier

        out = await get_data_sharing(db)
        assert out.ai_inference is True

        out = await update_data_sharing(DataSharingUpdate(tier=SharingTier.keys), db)
        assert out.ai_inference is True  # tier update does not touch consent

        out = await update_data_sharing(DataSharingUpdate(ai_inference=False), db)
        assert out.ai_inference is False
    finally:
        await update_data_sharing(DataSharingUpdate(tier=original.tier, ai_inference=False), db)
