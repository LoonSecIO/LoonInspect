"""`installed_evidence` (#896) on Postgres: each installed build's stored answer, counted once per build."""

import os
from contextlib import contextmanager
from datetime import date

import pytest
from sqlalchemy import event, select

from app.core.database import engine
from app.core.device_scope import scoped_devices
from app.core.fleet_assessment import installed_evidence
from app.core.hashing import compute_app_hash
from app.models.schema import InstalledApp
from app.schemas.fleet_migration import InstalledEvidence
from app.schemas.patch_plans import DeviceScope
from tests.patch_plan_fixtures import github, inventory  # noqa: F401
from tests.test_fleet_catalog_db import ALPHA

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires a disposable PostgreSQL database"),
    pytest.mark.asyncio(loop_scope="session"),
]

AS_OF, EPOCH = date(2026, 11, 24), "evidence-epoch"
ALPHA_BETA, UNMATCHED = compute_app_hash("Alpha Beta", ALPHA), compute_app_hash("Unmatched", "org.internal")


def counts(total, *, critical=0, high=0, kev=0):
    return {"total": total, "kev": kev, "critical": critical, "high": high, "medium": total - critical - high, "low": 0}


async def answer(db, app_hash, by_version):
    """Store `by_version`'s answers on the app's rows, as the judge pass does, signed by EPOCH."""
    rows = (await db.scalars(select(InstalledApp).where(InstalledApp.app_hash == app_hash))).all()
    for row in rows:
        if row.version in by_version:
            row.vuln_assessment, row.vuln_signature, row.vuln_counts = "covered", EPOCH, by_version[row.version]
    await db.commit()
    return rows


@contextmanager
def statements():
    seen = []

    def record(conn, cursor, statement, parameters, context, executemany):
        seen.append((statement, parameters))

    event.listen(engine.sync_engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record)


def _selected(source):
    return scoped_devices(DeviceScope(connection_id=source))  # Not the departed Mac, the other connection's or the iPad.


async def test_a_build_counts_once_on_the_selected_macs_and_findings_never_add(db, inventory):  # noqa: F811
    source, alpha, _ = inventory
    selected = {"1.0": counts(3, high=3), "2.0": counts(9, critical=1, kev=1), "unread": counts(0)}
    rows = await answer(db, alpha, selected | dict.fromkeys(("77", "88", "101"), counts(5, kev=5)))  # On Macs left out.
    await answer(db, UNMATCHED, {"1": counts(0)})
    two = next(row for row in rows if row.version == "2.0")  # On two selected Macs, and now twice on one of them.
    db.add(InstalledApp(**{c.name: getattr(two, c.name) for c in InstalledApp.__table__.columns if c.name != "id"}))
    await db.commit()
    evidence = await installed_evidence(db, _selected(source), as_of=AS_OF, epoch=EPOCH)
    assert evidence[alpha] == InstalledEvidence(
        assessment="covered", as_of=AS_OF, assessed_builds=3, affected_builds=2, high_or_critical_builds=2, kev_builds=1
    )
    assert 12 not in evidence[alpha].model_dump().values()  # 3 findings and 9 findings are two affected builds.
    assert evidence[UNMATCHED] == InstalledEvidence(
        assessment="covered", as_of=AS_OF, assessed_builds=1, affected_builds=0, high_or_critical_builds=0, kev_builds=0
    )
    assert evidence[ALPHA_BETA] == InstalledEvidence(assessment="unknown_app", as_of=AS_OF, unknown_builds=1)


async def test_stale_unreadable_and_half_copied_answers_are_unknown(db, inventory):  # noqa: F811
    source, alpha, _ = inventory
    rows = await answer(db, alpha, {"1.0": counts(3), "2.0": counts(9), "unread": counts(0)})
    stale = next(row for row in rows if row.version == "1.0")
    stale.vuln_signature = "earlier-epoch"  # Installed Apps reads this build as outside the corpus.
    next(row for row in rows if row.version == "unread").vuln_counts = counts(0) | {"total": "invalid"}
    half = next(row for row in rows if row.version == "2.0")  # Served on the other selected Mac, not yet copied here.
    half.vuln_assessment = half.vuln_signature = half.vuln_counts = None
    await db.commit()
    evidence = await installed_evidence(db, _selected(source), as_of=AS_OF, epoch=EPOCH)
    assert evidence[alpha] == InstalledEvidence(assessment="unknown_app", as_of=AS_OF, unknown_builds=3)
    stale.vuln_signature = EPOCH
    await db.commit()
    evidence = await installed_evidence(db, _selected(source), as_of=AS_OF, epoch=EPOCH)
    assert evidence[alpha] == InstalledEvidence(
        assessment="partial",
        as_of=AS_OF,
        assessed_builds=1,
        unknown_builds=2,
        affected_builds=1,
        high_or_critical_builds=0,
        kev_builds=0,
    )


async def test_nothing_answering_is_off_and_serves_no_unsigned_row(db, inventory):  # noqa: F811
    source, alpha, _ = inventory
    for row in await answer(db, alpha, {"1.0": counts(3), "2.0": counts(9), "unread": counts(0)}):
        row.vuln_signature = None  # `covered`, signed by no release.
    await db.commit()
    evidence = await installed_evidence(db, _selected(source), as_of=AS_OF, epoch=None)
    assert evidence[alpha] == InstalledEvidence(assessment="off", as_of=None, unknown_builds=3)
    for app_hash, found in evidence.items():
        assert found == InstalledEvidence(assessment="off", as_of=None, unknown_builds=found.unknown_builds), app_hash


async def test_named_apps_bind_as_one_array(db, inventory):  # noqa: F811
    source, alpha, _ = inventory
    hashes = [alpha, *(f"{n:032x}" for n in range(40000))]  # More than asyncpg's 32,767 parameters.
    with statements() as seen:
        evidence = await installed_evidence(db, _selected(source), as_of=AS_OF, epoch=EPOCH, app_hashes=hashes)
    assert list(evidence) == [alpha]
    ((statement, parameters),) = [(sql, args) for sql, args in seen if "installed_apps" in sql]
    assert statement.count("ANY (") == 1 and [value for value in parameters if isinstance(value, list)] == [hashes]
    assert len(parameters) < 1000
