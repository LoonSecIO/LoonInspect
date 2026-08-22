"""The observation ledger's span semantics, against a real Postgres.

Needs a database: the partial unique index, the JSONB upserts, and row-level security
are the mechanisms under test. Gated on RUN_DB_TESTS like the tenancy sweep; CI provides
one, and locally the sweep's docstring has the incantation.

What a span *means* is the point of these tests — new, changed, unchanged, repeat,
stale, and an aperture change — because docs/jamf-observations.md promises those
semantics and the derived layers (events, flap detection) will be built on them.
"""

from __future__ import annotations

import copy
import json
import os
import uuid as uuidlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import func, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

FIXTURE = Path(__file__).parent / "fixtures" / "jamf" / "computer_inventory_detail.json"
TENANT2_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000a2")
T0 = datetime(2026, 8, 21, 7, 15, 42, tzinfo=timezone.utc)


def _raw(*, subject_id: str = "42", report_at: datetime = T0) -> dict:
    record = json.loads(FIXTURE.read_text())
    record["id"] = subject_id
    record["general"]["reportDate"] = report_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return record


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def connection_id() -> int:
    """Migrated schema, both tenants, and one Jamf connection in the operational tenant
    that every test here writes under. Unique subjects per test keep runs independent."""
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import MdmConnection, Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, TENANT2_ID) is None:
            db.add(Tenant(id=TENANT2_ID, slug="sweep-second", name="Sweep Second", kind="operational"))
            await db.commit()

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        row = (await db.execute(select(MdmConnection).where(MdmConnection.name == "ledger jamf"))).scalars().first()
        if row is None:
            row = MdmConnection(name="ledger jamf", provider="jamf", base_url="https://ledger.jamfcloud.com")
            db.add(row)
            await db.commit()
        return row.id


@pytest_asyncio.fixture(loop_scope="session")
async def db(connection_id):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


@pytest_asyncio.fixture(loop_scope="session")
async def aperture_digest(db, connection_id) -> str:
    from app.mdm.jamf.contract import V0_SECTIONS, build_aperture
    from app.observations.ledger import ensure_aperture

    aperture = build_aperture(host="ledger.jamfcloud.com", jamf_version="11.16.0", sections=V0_SECTIONS, inventory_collection={})
    digest = await ensure_aperture(db, connection_id=connection_id, aperture=aperture)
    await db.commit()
    return digest


def _subject() -> str:
    return f"t-{uuidlib.uuid4().hex[:10]}"


async def _record(db, connection_id, aperture_digest, raw, trigger="sweep"):
    from app.mdm.jamf.contract import canonicalize_computer
    from app.observations.ledger import record_observation

    result = await record_observation(
        db,
        connection_id=connection_id,
        observation=canonicalize_computer(raw),
        aperture_digest=aperture_digest,
        trigger=trigger,
    )
    await db.commit()
    return result


async def _span(db, span_id):
    """The row as the database has it now. Refreshed explicitly rather than via
    expire_all(): an expired object touched outside an awaited call lazy-loads, which
    under asyncio is MissingGreenlet rather than a query."""
    from app.models.schema import ObservationSpan

    span = await db.get(ObservationSpan, span_id)
    await db.refresh(span)
    return span


async def test_first_observation_opens_a_span_with_all_content(db, connection_id, aperture_digest) -> None:
    from app.models.schema import ObservationEntry, ObservationSection

    subject = _subject()
    result = await _record(db, connection_id, aperture_digest, _raw(subject_id=subject))

    assert result.outcome == "new"
    assert len(result.changed_sections) == 14
    span = await _span(db, result.span_id)
    assert span.is_current and span.observation_count == 1 and span.previous_id is None
    assert span.subject_id == subject and span.udid == "00008112-000A1D2E3F4G5H6I"
    assert span.first_observed_at == span.last_observed_at == T0
    assert span.last_trigger == "sweep"

    digests = set(span.section_digests.values())
    stored = (await db.execute(select(ObservationSection.digest).where(ObservationSection.digest.in_(digests)))).scalars().all()
    assert set(stored) == digests

    slack = (
        await db.execute(
            select(ObservationEntry).where(
                ObservationEntry.digest == "v0:3a9edfeecdef9d7bc6c5f66afcd5b477c324b617a11b4096946e2a85afdb26d5"
            )
        )
    ).scalar_one()
    assert slack.kind == "application" and slack.body["name"] == "Slack.app"


async def test_same_content_with_a_newer_report_extends_the_span(db, connection_id, aperture_digest) -> None:
    subject = _subject()
    first = await _record(db, connection_id, aperture_digest, _raw(subject_id=subject))
    later = _raw(subject_id=subject, report_at=T0 + timedelta(hours=6))
    second = await _record(db, connection_id, aperture_digest, later, trigger="webhook")

    assert second.outcome == "unchanged" and second.span_id == first.span_id
    span = await _span(db, first.span_id)
    assert span.observation_count == 2
    assert span.first_observed_at == T0 and span.last_observed_at == T0 + timedelta(hours=6)
    assert span.last_trigger == "webhook"


async def test_same_content_and_same_report_is_a_repeat(db, connection_id, aperture_digest) -> None:
    """A sweep that reads the record a webhook already ingested observes nothing new:
    Jamf served the same inventory submission twice."""
    subject = _subject()
    first = await _record(db, connection_id, aperture_digest, _raw(subject_id=subject))
    second = await _record(db, connection_id, aperture_digest, _raw(subject_id=subject))

    assert second.outcome == "repeat" and second.span_id == first.span_id
    assert (await _span(db, first.span_id)).observation_count == 1


async def test_a_changed_section_opens_a_new_span_linked_to_the_old(db, connection_id, aperture_digest) -> None:
    from app.models.schema import ObservationEntry, ObservationSection, ObservationSpan

    subject = _subject()
    first = await _record(db, connection_id, aperture_digest, _raw(subject_id=subject))

    later = _raw(subject_id=subject, report_at=T0 + timedelta(days=1))
    later["applications"].append(
        {
            "name": "Ledger Test.app", "path": "/Applications/Ledger Test.app", "version": "1.0",
            "bundleId": f"io.loon.{subject}", "macAppStore": False,
        }
    )
    second = await _record(db, connection_id, aperture_digest, later)

    assert second.outcome == "changed"
    assert second.changed_sections == ("applications",)
    assert second.span_id != first.span_id

    old, new = await _span(db, first.span_id), await _span(db, second.span_id)
    assert old.is_current is False and new.is_current is True
    assert new.previous_id == old.id
    assert new.first_observed_at == T0 + timedelta(days=1) and new.observation_count == 1
    assert old.section_digests["general"] == new.section_digests["general"]
    assert old.section_digests["applications"] != new.section_digests["applications"]

    current = (
        await db.execute(
            select(func.count()).select_from(ObservationSpan).where(
                ObservationSpan.subject_id == subject, ObservationSpan.is_current.is_(True)
            )
        )
    ).scalar_one()
    assert current == 1

    section = (
        await db.execute(select(ObservationSection).where(ObservationSection.digest == new.section_digests["applications"]))
    ).scalar_one()
    assert section.entry_count == 13 and len(section.entry_digests) == 13
    added = (
        await db.execute(
            select(func.count())
            .select_from(ObservationEntry)
            .where(ObservationEntry.body["bundleId"].astext == f"io.loon.{subject}")
        )
    ).scalar_one()
    assert added == 1


async def test_an_older_report_is_stale_and_ignored(db, connection_id, aperture_digest) -> None:
    """The monotonic guard: a sweep that read a device before a webhook wrote it cannot
    roll the record back, whatever it contains."""
    subject = _subject()
    first = await _record(db, connection_id, aperture_digest, _raw(subject_id=subject))

    older = _raw(subject_id=subject, report_at=T0 - timedelta(hours=1))
    older["applications"] = []
    result = await _record(db, connection_id, aperture_digest, older)

    assert result.outcome == "stale" and result.span_id == first.span_id
    span = await _span(db, first.span_id)
    assert span.is_current and span.observation_count == 1 and span.last_observed_at == T0


async def test_an_aperture_change_opens_a_new_span_with_no_section_changes(db, connection_id, aperture_digest) -> None:
    from app.mdm.jamf.contract import V0_SECTIONS, build_aperture
    from app.observations.ledger import ensure_aperture

    subject = _subject()
    first = await _record(db, connection_id, aperture_digest, _raw(subject_id=subject))

    narrower = build_aperture(host="ledger.jamfcloud.com", jamf_version="11.17.0", sections=V0_SECTIONS, inventory_collection={})
    other_digest = await ensure_aperture(db, connection_id=connection_id, aperture=narrower)
    second = await _record(db, connection_id, other_digest, _raw(subject_id=subject))

    assert second.outcome == "changed"
    assert second.changed_sections == ()
    new = await _span(db, second.span_id)
    assert new.previous_id == first.span_id and new.aperture_digest == other_digest
    assert new.section_digests == (await _span(db, first.span_id)).section_digests


async def test_entries_and_sections_are_shared_across_devices(db, connection_id, aperture_digest) -> None:
    from app.models.schema import ObservationEntry, ObservationSection

    a, b = _subject(), _subject()
    await _record(db, connection_id, aperture_digest, _raw(subject_id=a))

    sections_before = (await db.execute(select(func.count()).select_from(ObservationSection))).scalar_one()
    entries_before = (await db.execute(select(func.count()).select_from(ObservationEntry))).scalar_one()

    result = await _record(db, connection_id, aperture_digest, _raw(subject_id=b))
    assert result.outcome == "new"

    sections_after = (await db.execute(select(func.count()).select_from(ObservationSection))).scalar_one()
    entries_after = (await db.execute(select(func.count()).select_from(ObservationEntry))).scalar_one()
    # Device b differs from device a only in its id, which is not section content, so
    # every section and entry it needs already exists.
    assert sections_after == sections_before and entries_after == entries_before


async def test_labels_follow_renames_when_content_is_rewritten(db, connection_id, aperture_digest) -> None:
    from app.models.schema import ObservationEntry

    subject = _subject()
    raw = _raw(subject_id=subject)
    raw["groupMemberships"] = [{"groupId": f"9{subject[-4:]}", "groupName": "Before", "smartGroup": True}]
    await _record(db, connection_id, aperture_digest, raw)

    later = _raw(subject_id=subject, report_at=T0 + timedelta(days=1))
    later["groupMemberships"] = [
        {"groupId": f"9{subject[-4:]}", "groupName": "After", "smartGroup": True},
        {"groupId": f"8{subject[-4:]}", "groupName": "Another", "smartGroup": False},
    ]
    result = await _record(db, connection_id, aperture_digest, later)
    assert result.changed_sections == ("group_memberships",)

    db.expire_all()
    renamed = (
        await db.execute(select(ObservationEntry).where(ObservationEntry.body["groupId"].astext == f"9{subject[-4:]}"))
    ).scalar_one()
    assert renamed.label == "After"


async def test_smart_group_definitions_are_subjects_too(db, connection_id, aperture_digest) -> None:
    from app.mdm.jamf.contract import canonicalize_smart_group
    from app.observations.ledger import record_observation

    async def observe(definition: dict):
        result = await record_observation(
            db,
            connection_id=connection_id,
            observation=canonicalize_smart_group(definition),
            aperture_digest=aperture_digest,
            trigger="sweep",
        )
        await db.commit()
        return result

    group_id = f"g{uuidlib.uuid4().hex[:8]}"
    criterion = {"name": "Application Title", "priority": 0, "andOr": "and", "searchType": "is", "value": "Falcon.app"}
    definition = {"id": group_id, "name": "Ledger Group", "criteria": [criterion]}
    first = await observe(definition)
    assert first.outcome == "new"

    moved = copy.deepcopy(definition)
    moved["criteria"][0]["value"] = "Falcon Sensor.app"
    second = await observe(moved)
    assert second.outcome == "changed" and second.changed_sections == ("definition",)
    span = await _span(db, second.span_id)
    assert span.subject_kind == "computer_group" and span.label == "Ledger Group" and span.previous_id == first.span_id


async def test_ledger_rows_are_tenant_scoped(db, connection_id, aperture_digest) -> None:
    from app.core.database import session_for_tenant
    from app.models.schema import ObservationEntry, ObservationSection, ObservationSpan

    subject = _subject()
    result = await _record(db, connection_id, aperture_digest, _raw(subject_id=subject))
    assert result.outcome == "new"

    async with session_for_tenant(TENANT2_ID) as other:
        assert (await other.execute(select(ObservationSpan).where(ObservationSpan.subject_id == subject))).scalars().all() == []
        assert (
            await other.execute(select(ObservationSection).where(ObservationSection.digest == result.head_digest))
        ).scalars().all() == []
        slack = (
            await other.execute(
                select(func.count())
                .select_from(ObservationEntry)
                .where(ObservationEntry.body["bundleId"].astext == "com.tinyspeck.slackmacgap")
            )
        ).scalar_one()
        assert slack == 0
