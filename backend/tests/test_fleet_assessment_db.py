"""Scope, candidate identity and exact target keys in the real database, using synthetic Macs."""

import os
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.core import fleet_assessment
from app.core.content_keys import app_full_key, app_title_key
from app.models.schema import Device, FleetMaintainedApp, InstalledApp, VulnCorpusRelease, VulnCorpusReleaseRow
from app.schemas.fleet_migration import LocalApp

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs a disposable Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def test_scoped_comparisons_keep_local_identity_and_both_ends_in_one_release(db, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "vuln_tenant_selection", True)
    tag = uuid.uuid4().hex
    bundle = "com.example." + tag
    name = "One.app"
    title = FleetMaintainedApp(slug=tag, name="One", bundle_id=bundle, latest_version="3", manifest_sha="a" * 40)
    now = datetime.now(UTC)
    held, other = tag * 2, tag[::-1] * 2
    db.add_all(
        [
            title,
            *(
                VulnCorpusRelease(signature=stamp, epoch_id=stamp[:32], asof=now, loaded_at=now, row_count=3, title_count=1)
                for stamp in (held, other)
            ),
        ]
    )
    await db.flush()
    src, dst = (app_full_key(name, bundle, version, None) for version in ("1", "2"))
    cve = "CVE-2026-1001"

    def corpus_row(stamp, key, ids):
        return VulnCorpusReleaseRow(
            signature=stamp,
            key_full=key,
            ids=ids,
            truncated=False,
            counts={"total": len(ids), "kev": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            oldest_published={
                "total": "2026-01-01T00:00:00Z" if ids else None,
                "critical": None,
                "high": None,
                "medium": None,
                "low": None,
            },
        )

    db.add_all([corpus_row(held, src, [cve]), corpus_row(held, dst, []), corpus_row(other, dst, [cve])])
    devices = [
        Device(mdm_provider="jamf", external_id=f"{tag}-{i}", serial_number=f"{tag}-{i}", hostname=f"test-{i}") for i in range(2)
    ]
    db.add_all(devices)
    await db.flush()

    def install(device, app_name, app_hash, version_hash):
        return InstalledApp(
            device_id=device.id,
            name=app_name,
            bundle_id=bundle,
            version="1",
            app_hash=app_hash,
            version_hash=version_hash,
            key_full=app_full_key(app_name, bundle, "1", None),
            key_title=app_title_key(app_name, bundle),
        )

    hash_one, hash_two = tag, tag[::-1]
    db.add_all(
        [
            install(devices[0], name, hash_one, hash_one),
            install(devices[0], name, hash_one, hash_one),
            install(devices[1], name, hash_one, hash_one),
            install(devices[0], "Different.app", hash_two, hash_two),
        ]
    )
    await db.flush()

    async def gate(session):
        assert session is db
        return SimpleNamespace(as_of=now.date())

    monkeypatch.setattr(fleet_assessment, "earned_corpus", gate)
    monkeypatch.setattr(fleet_assessment, "loaded_epoch_signature", lambda: held)
    scope = select(Device.id).where(Device.id == devices[0].id).cte()
    matched = await fleet_assessment.app_assessments(
        db, {hash_one: title, hash_two: title}, eligible_devices=scope, include_builds=True, target_version="2"
    )
    first, second = matched[hash_one], matched[hash_two]
    assert first.target_version == "2" and first.addresses == first.exact_builds == 1
    assert first.builds[0].device_count == 1
    assert second.behind_builds == 1 and second.builds[0].comparison == "unknown_source"
    assert second.addresses is None
    aggregate = (await fleet_assessment.fleet_assessments(db, [title], eligible_devices=scope, target_version="2"))[tag]
    assert aggregate.behind_builds == 2 and aggregate.exact_builds == aggregate.unknown_builds == 1
    assert aggregate.builds == []
    identities = [
        LocalApp(
            app_hash=key,
            name=n,
            bundle_id=bundle,
            macs=1,
            version_count=1,
            match="none",
            has_jamf_match=False,
            jamf_evaluated=True,
            fleet_candidates=[],
        )
        for key, n in ((hash_one, name), (hash_two, "Different.app"))
    ]
    observed = await fleet_assessment.installed_evidence(db, scope, identities)
    assert observed[hash_one].as_of == now.date()
    assert (observed[hash_one].assessed_builds, observed[hash_one].affected_builds, observed[hash_one].unknown_builds) == (
        1,
        1,
        0,
    )
    assert (observed[hash_two].assessed_builds, observed[hash_two].affected_builds, observed[hash_two].unknown_builds) == (
        0,
        0,
        1,
    )
    # These fixtures are local to this transaction, including global catalogs.
    await db.rollback()
