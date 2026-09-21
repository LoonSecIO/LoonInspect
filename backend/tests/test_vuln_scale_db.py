# ruff: noqa: F811 — pytest injects imported fixtures by name.
"""Opt-in synthetic #621 measurement; run alone on disposable PostgreSQL with -s.

RUN_VULN_SCALE=1 RUN_DB_TESTS=1 enables it; VULN_SCALE_DEVICES chooses 100/1000/10000.
Seeds inventory directly, then runs real import, assessment, evidence, rollback and cleanup.
This is not an ingest, concurrent-reader or production throughput benchmark.
"""

import json
import os
import resource
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from time import perf_counter

import pytest
from sqlalchemy import delete, event, func, insert, select, text, true, update

from app.catalog.service import record_device_apps
from app.core.content_keys import app_full_key, app_title_key
from app.core.hashing import compute_app_hash, compute_version_hash
from app.core.vuln_library import load_epoch_if_new
from app.core.vuln_pruning import prune_releases
from app.core.vuln_selection import assess_and_select, record_acquisition
from app.models.schema import AppCatalogEntry, Device, DeviceHistoryPoint, InstalledApp, ObservationSpan, VulnCorpusAcquisition
from app.observations.assessment_evidence import capture_release_transition
from tests.test_assessment_evidence_db import observed  # noqa: F401
from tests.test_device_observation_db import connection  # noqa: F401
from tests.test_vuln_answer_db import NOW, acting_tenant, fleet  # noqa: F401
from tests.test_vuln_library import _rewritten, _row
from tests.test_vuln_library_db import _pointer, _serving, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import retained  # noqa: F401
from tests.test_vuln_selected_serving_db import selected  # noqa: F401
from tests.test_vuln_selection_db import pytestmark

pytestmark = [*pytestmark, pytest.mark.skipif(os.environ.get("RUN_VULN_SCALE") != "1", reason="opt-in scale measurement")]


@contextmanager
def _sql_timings():
    """Synthetic benchmark timings include cursor execution and transport, not ORM work."""
    from app.core.database import engine

    timings = []

    def before(conn, cursor, statement, parameters, context, executemany):
        context._scale_started = perf_counter()

    def after(conn, cursor, statement, parameters, context, executemany):
        timings.append((" ".join(statement.split())[:120], perf_counter() - context._scale_started))

    event.listen(engine.sync_engine, "before_cursor_execute", before)
    event.listen(engine.sync_engine, "after_cursor_execute", after)
    try:
        yield timings
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", before)
        event.remove(engine.sync_engine, "after_cursor_execute", after)


async def test_synthetic_assessment_rollback_cleanup(db, observed):
    devices = int(os.environ.get("VULN_SCALE_DEVICES", "100"))
    assert devices in (100, 1000, 10000)
    template = observed
    connection_id = template.mdm_connection_id
    report = {"devices": devices, "apps_per_device": 100, "corpus_builds": 10000, "phases": {}}

    async def measure(name, operation):
        start = perf_counter()
        with _sql_timings() as statements:
            result = await operation()
            await db.commit()
        report["phases"][name] = {
            "seconds": round(perf_counter() - start, 3),
            "sql_statements": len(statements),
            "cursor_seconds": round(sum(elapsed for _, elapsed in statements), 3),
            "slowest_statements": [
                {"sql_prefix": sql, "seconds": round(elapsed, 3)}
                for sql, elapsed in sorted(statements, key=lambda item: item[1], reverse=True)[:3]
            ],
        }
        print("VULN_SCALE_PHASE=" + json.dumps({"phase": name, **report["phases"][name]}, sort_keys=True), flush=True)
        return result

    async def seed():
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id == template.id))
        apps = []
        for index in range(100):
            name, bundle, version = f"Scale {index}.app", f"test.scale.{index}", "1.0"
            apps.append(
                {
                    "device_id": template.id,
                    "name": name,
                    "bundle_id": bundle,
                    "version": version,
                    "app_hash": compute_app_hash(name, bundle),
                    "version_hash": compute_version_hash(name, bundle, version, None),
                    "key_title": app_title_key(name, bundle),
                    "key_full": app_full_key(name, bundle, version, None),
                }
            )
        await db.execute(insert(InstalledApp), apps)
        await record_device_apps(db, template, now=NOW)
        for start in range(1, devices, 1000):
            rows = [
                {
                    "mdm_connection_id": connection_id,
                    "mdm_provider": "jamf",
                    "external_id": f"SCALE-{n}",
                    "serial_number": f"SCALE-{n}",
                    "hostname": f"scale-{n}",
                    "platform": "macos",
                    "managed": True,
                }
                for n in range(start, min(start + 1000, devices))
            ]
            await db.execute(insert(Device), rows)
            await db.execute(
                insert(ObservationSpan),
                [
                    {
                        "mdm_connection_id": connection_id,
                        "subject_kind": "computer",
                        "subject_id": row["external_id"],
                        "contract_version": "v1",
                        "aperture_digest": "a" * 64,
                        "head_digest": "b" * 64,
                        "section_digests": {"applications": "c" * 64},
                        "first_observed_at": NOW,
                        "last_observed_at": NOW,
                        "first_collected_at": NOW,
                        "last_collected_at": NOW,
                        "last_trigger": "sweep",
                    }
                    for row in rows
                ],
            )
        fields = [c.name for c in InstalledApp.__table__.columns if c.name not in ("id", "device_id")]
        targets = select(Device.id).where(Device.mdm_connection_id == connection_id, Device.id != template.id).subquery()
        await db.execute(
            insert(InstalledApp).from_select(
                ["device_id", *fields],
                select(targets.c.id, *(getattr(InstalledApp, name) for name in fields))
                .select_from(InstalledApp)
                .join(targets, true())
                .where(InstalledApp.device_id == template.id),
            )
        )
        return [app["key_full"] for app in apps]

    try:
        keys = await measure("seed", seed)
        # Verify the fixture without timing a separate join-planning exercise.
        # The production assessment and evidence queries below remain unchanged.
        seeded_ids = list(await db.scalars(select(Device.id).where(Device.mdm_connection_id == connection_id)))
        assert len(seeded_ids) == devices
        assert (
            await db.scalar(select(func.count()).select_from(InstalledApp).where(InstalledApp.device_id.in_(seeded_ids)))
            == devices * 100
        )
        # 90 covered builds per device and ten unknown; the remaining corpus is unused.
        rows = [_row(key_full=key) for key in keys[:90]]
        rows.extend(_row(key_full=f"v1:{n:064x}") for n in range(9910))
        releases = []
        for label, day in (("a", 11), ("b", 12), ("unused", 13)):
            bundle, signature = _rewritten(rows=rows, manifest={"asof": f"2026-09-{day}T20:00:00Z"})
            await measure(
                f"import_{label}", lambda b=bundle, s=signature: load_epoch_if_new(db, _pointer(s), transport=_serving(b))
            )
            await record_acquisition(db, signature)
            await db.commit()
            releases.append((bundle, signature))
        # Keep B active globally so the unused release is genuinely collectible.
        bundle, signature = releases[1]
        await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle))
        report["analyze_before_selection"] = os.environ.get("VULN_SCALE_ANALYZE") == "1"
        if report["analyze_before_selection"]:
            # Diagnostic comparison only, outside the timed assessment. Production
            # must not depend on this test's manual planner-statistics maintenance.
            await db.execute(text("ANALYZE installed_apps, devices, app_catalog"))
            await db.commit()
        baseline = await db.scalar(select(func.count()).select_from(DeviceHistoryPoint))
        for label, index in (("select_a", 0), ("select_b", 1), ("rollback_a", 0)):
            await measure(label, lambda i=index: assess_and_select(db, releases[i][1]))
        assert await db.scalar(select(func.count()).select_from(DeviceHistoryPoint)) == baseline + devices * 3
        point = await db.scalar(
            select(DeviceHistoryPoint)
            .where(DeviceHistoryPoint.device_id == template.id)
            .order_by(DeviceHistoryPoint.id.desc())
            .limit(1)
        )
        assert point.assessment["covered"] == 90 and point.assessment["outside"] == 10
        assert point.assessment["total"] == 90
        await measure("quiet_evidence_pass", lambda: capture_release_transition(db, releases[0][1]))
        assert await db.scalar(select(func.count()).select_from(DeviceHistoryPoint)) == baseline + devices * 3
        report["history_json_bytes"] = await db.scalar(select(func.sum(func.pg_column_size(DeviceHistoryPoint.assessment))))
        await db.execute(update(VulnCorpusAcquisition).values(acquired_at=datetime.now(UTC) - timedelta(days=60)))
        await db.commit()
        before = datetime.now(UTC)
        report["cleanup"] = await measure(
            "cleanup", lambda: prune_releases(db, before=before, apply=True, retire_acquisitions=True)
        )
        assert report["cleanup"]["acquisitionsRetired"] == report["cleanup"]["deleted"] == 2
        assert set(await db.scalars(select(VulnCorpusAcquisition.signature))) == {releases[0][1], releases[1][1]}
        assert await db.scalar(select(func.count()).select_from(DeviceHistoryPoint)) == baseline + devices * 3
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report["python_peak_rss_mib"] = round(peak / (1024**2 if sys.platform == "darwin" else 1024), 1)
        report["tenant_device_index_bytes_after_cleanup"] = await db.scalar(
            text("SELECT pg_relation_size(to_regclass('ix_installed_apps_tenant_device'))")
        )
        print("VULN_SCALE_RESULT=" + json.dumps(report, sort_keys=True))
    finally:
        await db.rollback()
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.bundle_id.like("test.scale.%")))
        await db.commit()
