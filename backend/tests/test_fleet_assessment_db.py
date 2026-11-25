"""`installed_evidence` (#896) and the target assessments (#898) on Postgres: each installed build's stored answer,
counted once per build, and a Fleet target's answer from the same release."""

import os
import uuid
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select

from app.api.jamf_patch import title_build_severity
from app.core.config import settings
from app.core.content_keys import app_full_key, app_title_key
from app.core.database import engine
from app.core.device_scope import scoped_devices
from app.core.fleet_assessment import _read, app_assessments, installed_evidence
from app.core.hashing import compute_app_hash, compute_version_hash
from app.mdm.patch.policy import Rule, Rules
from app.models.schema import (
    AppCatalogEntry,
    AppCatalogTitleMatch,
    Device,
    FleetMaintainedApp,
    InstalledApp,
    JamfPatchTitle,
    VulnCorpusRelease,
    VulnCorpusReleaseRow,
)
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


# --- the target assessments (#898). Seeded in one transaction and never committed, so nothing outlives the test.

CVE, NOW = "CVE-2026-1001", datetime.now(UTC)


def _keys(name, bundle, version):
    hashes = {"app_hash": compute_app_hash(name, bundle), "version_hash": compute_version_hash(name, bundle, version)}
    keys = {"key_title": app_title_key(name, bundle), "key_full": app_full_key(name, bundle, version, None)}
    return {"name": name, "bundle_id": bundle, "version": version, **hashes, **keys}


def _found(ids, high=0):
    """Counts and oldest dates for `ids`, `high` of them high and the rest medium, in the shape the library writes."""
    found = counts(len(ids), high=high)
    return found, {band: "2026-01-01T00:00:00Z" if n else None for band, n in found.items() if band != "kev"}


def catalog_row(name, bundle, version, ids, signature, high=0):
    """A catalog row whose stored answer the release `signature` names judged, as the judge pass writes it."""
    found, oldest = _found(ids, high)
    answer = {"vuln_counts": found, "vuln_oldest_published": oldest, "vuln_ids": ids, "vuln_ids_truncated": False}
    stamps = {"first_seen_at": NOW, "last_seen_at": NOW, "vuln_assessment": "covered", "vuln_signature": signature}
    return AppCatalogEntry(**_keys(name, bundle, version), **stamps, **answer)


def library_row(stamp, name, bundle, version, ids):
    found, oldest = _found(ids)
    key = app_full_key(name, bundle, version, None)
    return VulnCorpusReleaseRow(signature=stamp, key_full=key, ids=ids, truncated=False, counts=found, oldest_published=oldest)


def install(mac, name, bundle, version):
    return InstalledApp(device_id=mac.id, **_keys(name, bundle, version))


async def behind(db, entry, title_id, days):
    """`entry` matched to a Jamf title on its requirements, with a newer release listed `days` ago."""
    db.add(JamfPatchTitle(id=title_id, name=title_id, current_version="9", last_modified="x"))
    await db.flush()
    since = {"first_newer_released_at": NOW - timedelta(days=days), "releases_missed": 1, "installed_version": entry.version}
    match = {"basis": "requirements", "state": "behind", "version_known": True, "on_latest": False, "latest_version": "9"}
    db.add(AppCatalogTitleMatch(app_catalog_id=entry.id, title_id=title_id, **match, **since))
    await db.flush()


async def _estate(db, macs):
    """A fresh bundle with one Fleet title at version 3, and `macs` Macs. The reader sees the first, under a corpus."""
    tag = uuid.uuid4().hex
    title = FleetMaintainedApp(slug=tag, name="One", bundle_id=f"com.example.{tag}", latest_version="3", manifest_sha="a" * 40)
    devices = [Device(mdm_provider="jamf", external_id=f"{tag}-{n}", serial_number=tag, hostname=f"h{n}") for n in range(macs)]
    db.add_all([title, *devices])
    await db.flush()
    scope = select(Device.id).where(Device.id == devices[0].id).cte()
    return tag, title, devices, {"eligible_devices": scope, "corpus": SimpleNamespace(as_of=AS_OF)}


async def test_scoped_comparisons_keep_local_identity_and_both_ends_in_one_release(db, monkeypatch):
    monkeypatch.setattr(settings, "vuln_tenant_selection", True)
    tag, title, macs, seen = await _estate(db, 2)
    bundle, held, other = title.bundle_id, tag * 2, tag[::-1] * 2
    read = {**seen, "epoch": held, "rules": Rules(), "target_version": "2"}
    release = {"asof": NOW, "loaded_at": NOW, "row_count": 3, "title_count": 1}
    db.add_all(VulnCorpusRelease(signature=stamp, epoch_id=stamp[:32], **release) for stamp in (held, other))
    await db.flush()
    entry = catalog_row("One", bundle, "1", [CVE], held)  # The stored answer carries the finding.
    once = [install(macs[0], "One", bundle, "1"), install(macs[0], "One", bundle, "1"), install(macs[1], "One", bundle, "1")]
    # The library calls the installed build clean, and the target clean only under the answering release.
    rows = [library_row(held, "One", bundle, "1", []), library_row(held, "One", bundle, "2", [])]
    db.add_all([entry, *once, install(macs[0], "Two", bundle, "1"), *rows, library_row(other, "One", bundle, "2", [CVE])])
    await db.flush()
    one, two = compute_app_hash("One", bundle), compute_app_hash("Two", bundle)
    assessed = await app_assessments(db, {one: title, two: title}, include_builds=True, **read)
    assert assessed[one].addresses == assessed[one].exact_builds == 1 and assessed[one].builds[0].device_count == 1
    assert assessed[two].behind_builds == 1 and assessed[two].builds[0].comparison == "unknown_source"
    (by_slug,) = (await _read(db, {tag: title}, grain="slug", **read)).values()
    assert (by_slug.behind_builds, by_slug.exact_builds, by_slug.unknown_builds, by_slug.builds) == (2, 1, 1, [])
    db.add(install(macs[0], "One", bundle, "2"))  # A selected Mac carries the target: its stored answer, never the library's.
    carried = await app_assessments(db, {one: title}, include_builds=True, **read)
    db.add(catalog_row("One", bundle, "2", [], held))  # The carried target's own stored answer (#899).
    with statements() as asked:
        served = await app_assessments(db, {one: title}, include_builds=True, **read)
    assert served[one].builds[0].comparison == "exact" and not [sql for sql, _ in asked if "vuln_corpus_release_rows" in sql]
    entry.vuln_signature = other  # Judged by a release that is no longer answering.
    stale = await app_assessments(db, {one: title}, include_builds=True, **read)
    assert [found[one].builds[0].comparison for found in (carried, stale)] == ["unknown_target", "unknown_source"]
    entry.vuln_signature = None  # `covered` and signed by no release: with no epoch, `stored_corpus` is never asked.
    (unsigned,) = (await app_assessments(db, {one: title}, include_builds=True, **(read | {"epoch": None}))).values()
    assert unsigned.builds[0].comparison == "unknown_source"


async def test_a_builds_verdict_reads_the_severity_the_jamf_patch_title_page_reads(db):
    tag, title, (mac,), seen = await _estate(db, 1)
    entry = catalog_row("One", title.bundle_id, "1", [CVE], EPOCH, high=1)
    db.add_all([entry, install(mac, "One", title.bundle_id, "1")])
    await db.flush()
    await behind(db, entry, tag, days=30)
    rules = Rules(default=Rule(max_days_behind=90, max_days_behind_severe=14))

    async def build():
        read = {**seen, "epoch": EPOCH, "rules": rules}
        (assessed,) = (await app_assessments(db, {entry.app_hash: title}, include_builds=True, **read)).values()
        return assessed.builds[0], (await title_build_severity(db, tag, epoch=EPOCH))["1"]

    served, severity = await build()  # The title page's severity for version 1, read off the same stored answer.
    assert (served.policy_state, served.policy_verdict.limit_days, served.policy_verdict.severe) == ("out", 14, severity)
    assert severity is True
    entry.vuln_signature = "earlier-epoch"
    stale, severity = await build()
    assert (stale.policy_state, stale.policy_verdict.limit_days, stale.policy_verdict.severe) == ("within", 90, severity)
    assert severity is None
    # A bundle two Fleet titles share, with its one Jamf title matched on requirements (#914's verifier).
    esr = FleetMaintainedApp(slug=tag + "-esr", name="ESR", bundle_id=title.bundle_id, latest_version="3", manifest_sha="b" * 40)
    db.add(esr)
    shared, _ = await build()
    assert (shared.comparison, shared.policy_unassessed, shared.policy_title_id) == ("ambiguous", "identity", tag)
    await db.delete(esr)
    await behind(db, entry, tag + "-2", days=30)  # A second Jamf match on the same catalog row.
    twice, _ = await build()
    assert (twice.device_count, twice.policy_unassessed, twice.policy_title_id) == (1, "identity", None)
