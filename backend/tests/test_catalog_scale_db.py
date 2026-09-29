# ruff: noqa: F811 — pytest injects imported fixtures by name.
"""Opt-in synthetic #726 measurement; run alone on disposable PostgreSQL with -s.

RUN_CATALOG_SCALE=1 RUN_DB_TESTS=1 enables it; CATALOG_SCALE_DEVICES chooses 1000/8000/14000.
Seeds the fleet directly in SQL at about 110 apps a Mac, judges its catalog against a real
epoch, then times what the Catalog and Vulnerabilities pages ask of `GET /api/catalog`, through
the API, as #726 measured them: p95 over 20 loads after 2 warm-ups. It prints the timings and
the plan of every statement the Catalog page's request sends that reads installs or pages the
list, then fails where a page is over its budget. Run each size on a fresh database: a table
the last run filled and emptied is still as long, and a sequential scan reads all of it.
This is not an ingest, sweep, concurrent-writer or production throughput benchmark.
"""

import asyncio
import json
import math
import os
from contextlib import contextmanager
from datetime import date, timedelta
from time import perf_counter

import pytest
from sqlalchemy import delete, event, func, insert, select, text

from app.catalog.service import judge_vuln
from app.core.content_keys import app_full_key, app_title_key
from app.core.hashing import compute_app_hash, compute_version_hash
from app.core.vuln_library import load_epoch_if_new
from app.models.schema import AppCatalogEntry, Device, InstalledApp
from tests.test_device_observation_db import accounts, admin  # noqa: F401
from tests.test_vuln_answer_db import NOW, _pointer, acting_tenant, fleet  # noqa: F401
from tests.test_vuln_library import _rewritten, _row
from tests.test_vuln_library_db import _serving

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.skipif(os.environ.get("RUN_CATALOG_SCALE") != "1", reason="opt-in scale measurement"),
    pytest.mark.asyncio(loop_scope="session"),
]

# The mix #726 measured: a core every Mac carries, a mid-tail most carry some of, a long tail
# each Mac carries a few of. Only the core has more than one version in circulation, and the
# catalog keeps RETIRED more of each core app after the last Mac moved off them.
CORE, MID, TAIL, RETIRED = 40, 150, 3000, 5
BUNDLE_PREFIX = "test.catalogscale."
LOADS, WARMUPS = 20, 2
# Kyle's budgets of 2026-09-29 (#726), at p95, for the band of 1,000 to 8,000 Macs and up to
# 14,000: the Catalog is a list page, 1 s; the Vulnerabilities page is a heavy one, 2 s.
BUDGETS = {"catalog": 1.0, "vulnerabilities": 2.0}

# What the pages send, byte for byte: the Catalog tab's one request (`CatalogPage.tsx`, the page
# size `ALL_ROWS_PAGE_SIZE`), and the Vulnerabilities page's three, which it sends together.
CATALOG = "/api/catalog?pageSize=5000&jamf=all&installedOnly=true"
OLDEST = "/api/catalog?pageSize=10&vuln=findings&order=age"
VULNERABILITIES = (
    "/api/catalog?pageSize=10&vuln=findings&order=exposure&page=1",
    OLDEST,
    "/api/catalog?pageSize=10&vuln=patchable&order=payoff",
)
IDENTITY = ("name", "bundle_id", "version", "app_hash", "version_hash", "key_title", "key_full")


def _builds() -> list[dict]:
    """Every build the seed can install or catalog, keyed the way its picks name one: tier
    (0 core, 1 mid-tail, 2 long tail), app, and version index — 0 the newest."""
    builds = []
    for tier, apps, label in ((0, CORE, "core"), (1, MID, "mid"), (2, TAIL, "tail")):
        for app in range(apps):
            name, bundle_id = f"Scale {label.title()} {app}.app", f"{BUNDLE_PREFIX}{label}{app}"
            versions = 1 + app % 3 + RETIRED if tier == 0 else 1
            for ver in range(versions):
                version = f"{20 - ver}.0"
                builds.append(
                    {
                        "tier": tier,
                        "app": app,
                        "ver": ver,
                        "retired": tier == 0 and ver > app % 3,
                        "name": name,
                        "bundle_id": bundle_id,
                        "version": version,
                        "newest": "20.0",
                        "app_hash": compute_app_hash(name, bundle_id),
                        "version_hash": compute_version_hash(name, bundle_id, version, None),
                        "key_title": app_title_key(name, bundle_id),
                        "key_full": app_full_key(name, bundle_id, version, None),
                    }
                )
    return builds


def _answer(index: int, build: dict) -> dict | None:
    """The epoch's row for a build, or None where the corpus never assessed it (`unknown_app`).
    Every core build is assessed: the newest is clean for even apps, and each older one carries
    more, so an update closes findings and `vuln=patchable` has rows to rank. Some core apps
    carry a KEV finding; two thirds of the mid-tail and a tenth of the long tail are assessed."""
    tier, app, ver = build["tier"], build["app"], build["ver"]
    if tier == 0:
        total, kev = (app % 2 if ver == 0 else 2 * ver + app % 4), (1 if ver and app % 8 == 0 else 0)
    elif tier == 1 and app % 3 != 2:
        total, kev = app % 4, 0
    elif tier == 2 and app % 10 == 0:
        total, kev = app % 3, 0
    else:
        return None
    published = date(2026, 6, 1) - timedelta(days=37 * ver + 11 * (app % 50) + 400 * tier)
    stamp = f"{published.isoformat()}T00:00:00Z"
    counts = {"total": total, "kev": kev, "critical": kev, "high": total - kev, "medium": 0, "low": 0}
    oldest = {band: stamp if counts[band] else None for band in ("total", "critical", "high", "medium", "low")}
    ids = [f"CVE-2025-{10000 + 20 * index + finding}" for finding in range(total)]
    return _row(key_full=build["key_full"], ids=ids, counts=counts, oldest_published=oldest)


def _catalog_row(build: dict) -> dict:
    """The catalog row a sweep and the Jamf pass would have left for a build, as this read needs
    it: a Jamf title on the core apps, and on every core build behind its newest the target key
    (#482) the judge looks the newest up by."""
    core, behind = build["tier"] == 0, build["tier"] == 0 and build["ver"] > 0
    return {
        **{name: build[name] for name in IDENTITY},
        "first_seen_at": NOW - timedelta(days=90),
        "last_seen_at": NOW,
        "jamf_title_ids": [f"SCALE{build['app']}"] if core else None,
        "patch_state": ("behind" if behind else "latest") if core else None,
        "latest_version": build["newest"] if core else None,
        "vuln_target_key": app_full_key(build["name"], build["bundle_id"], build["newest"], None) if behind else None,
    }


_MACS = text(
    """
    INSERT INTO devices (mdm_connection_id, mdm_provider, external_id, serial_number, hostname, platform, managed)
    SELECT :connection, 'jamf', 'CATSCALE-' || n, 'CATSCALE-' || n, 'catscale-' || n, 'macos', true
    FROM generate_series(0, :last) AS n
    """
)

# Picks, not randomness: every Mac's apps follow from its index, so two runs seed the same fleet.
# `hashtext` is PostgreSQL's own and stable within a major version, which is all a rerun needs.
_INSTALL = text(
    """
    WITH builds AS (
        SELECT * FROM unnest(
            CAST(:tier AS int[]), CAST(:app AS int[]), CAST(:ver AS int[]), CAST(:name AS text[]),
            CAST(:bundle_id AS text[]), CAST(:version AS text[]), CAST(:app_hash AS text[]),
            CAST(:version_hash AS text[]), CAST(:key_title AS text[]), CAST(:key_full AS text[])
        ) AS b(tier, app, ver, name, bundle_id, version, app_hash, version_hash, key_title, key_full)
    ),
    macs AS (
        SELECT id, (row_number() OVER (ORDER BY id) - 1)::int AS n FROM devices
        WHERE mdm_connection_id = :connection AND external_id LIKE 'CATSCALE-%'
    ),
    picks AS (
        -- The core: all forty on every Mac, each at one of the versions in circulation.
        SELECT macs.id AS device_id, 0 AS tier, i AS app,
               mod(hashtext(macs.n || ':core:' || i)::bigint + 2147483648, 1 + mod(i, 3))::int AS ver
        FROM macs CROSS JOIN generate_series(0, 39) AS i
        UNION ALL
        -- The mid-tail: app j on a Mac with a chance falling from 80% to almost none, 60.4 a Mac.
        SELECT macs.id, 1, j, 0 FROM macs CROSS JOIN generate_series(0, 149) AS j
        WHERE mod(hashtext(macs.n || ':mid:' || j)::bigint + 2147483648, 150000) < 800 * (150 - j)
        UNION ALL
        -- The long tail: ten draws weighted toward its head. Two draws of one app are two
        -- installs of one build, as two copies of an app on one Mac are.
        SELECT macs.id, 2,
               floor(3000 * power(mod(hashtext(macs.n || ':tail:' || k)::bigint + 2147483648, 1000000) / 1e6, 2))::int, 0
        FROM macs CROSS JOIN generate_series(0, 9) AS k
    )
    INSERT INTO installed_apps (device_id, name, bundle_id, version, app_hash, version_hash, key_title, key_full)
    SELECT picks.device_id, b.name, b.bundle_id, b.version, b.app_hash, b.version_hash, b.key_title, b.key_full
    FROM picks JOIN builds AS b USING (tier, app, ver)
    """
)


async def seed(db, connection_id: int, devices: int) -> dict:
    """The fleet, its catalog and a judged epoch, committed; returns what was seeded.

    Written straight into the tables the read path reads rather than through a sweep, which
    would cost an hour at 14,000 Macs and measure the sweep. The catalog rows carry what the
    sweep and the Jamf pass would have left on them for this read: the target key (#482) on
    every core build behind its newest. The vulnerability answer itself is the real judge's,
    over a real epoch, so the stored shapes are the ones production writes.
    """
    builds = _builds()
    await db.execute(_MACS, {"connection": connection_id, "last": devices - 1})
    installed = [build for build in builds if not build["retired"]]
    picked = {name: [build[name] for build in installed] for name in ("tier", "app", "ver", *IDENTITY)}
    await db.execute(_INSTALL, {"connection": connection_id, **picked})
    await db.execute(insert(AppCatalogEntry), [_catalog_row(build) for build in builds])
    rows = [row for row in (_answer(index, build) for index, build in enumerate(builds)) if row is not None]
    bundle, signature = _rewritten(rows=rows)
    assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle)) is not None
    judged = await judge_vuln(db, None, now=NOW)
    await db.commit()
    seeded = select(Device.id).where(Device.mdm_connection_id == connection_id, Device.external_id.like("CATSCALE-%"))
    installs = await db.scalar(select(func.count()).select_from(InstalledApp).where(InstalledApp.device_id.in_(seeded)))
    return {
        "devices": devices,
        "installed_apps": installs,
        "catalog_builds": len(builds),
        "assessed_builds": len(rows),
        "judged": judged,
    }


async def _settle() -> None:
    """VACUUM and ANALYZE what was just written, outside any transaction, as autovacuum would
    have long before anyone opened the page on a fleet this size. Without it the plan timed is
    whichever one the daemon's progress allows when the timer starts, not the steady state's."""
    from app.core.database import engine

    async with engine.connect() as connection:
        connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
        await connection.execute(text("VACUUM (ANALYZE) installed_apps, app_catalog, devices"))


@contextmanager
def _sent():
    """Every statement the engine sends while the block runs: its text, parameters and time."""
    from app.core.database import engine

    sent = []

    def before(conn, cursor, statement, parameters, context, executemany):
        context._catalog_scale_started = perf_counter()

    def after(conn, cursor, statement, parameters, context, executemany):
        sent.append((statement, parameters, perf_counter() - context._catalog_scale_started))

    event.listen(engine.sync_engine, "before_cursor_execute", before)
    event.listen(engine.sync_engine, "after_cursor_execute", after)
    try:
        yield sent
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", before)
        event.remove(engine.sync_engine, "after_cursor_execute", after)


async def _timed(load) -> dict:
    """p50, p95 (nearest rank) and max of LOADS loads after WARMUPS, in seconds."""
    for _ in range(WARMUPS):
        await load()
    samples = []
    for _ in range(LOADS):
        started = perf_counter()
        await load()
        samples.append(perf_counter() - started)
    ordered = sorted(samples)
    return {
        "p50": round(ordered[len(ordered) // 2], 3),
        "p95": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
        "max": round(ordered[-1], 3),
    }


async def test_catalog_and_vulnerabilities_pages_at_fleet_scale(db, fleet, admin):
    devices = int(os.environ.get("CATALOG_SCALE_DEVICES", "1000"))
    assert devices in (100, 1000, 8000, 14000)
    connection, _ = fleet
    connection_id = connection.id
    try:
        started = perf_counter()
        report = await seed(db, connection_id, devices)
        await _settle()
        report["seed_seconds"] = round(perf_counter() - started, 1)
        print("CATALOG_SCALE_SEED=" + json.dumps(report, sort_keys=True), flush=True)

        async def get(url):
            response = await admin.get(url)
            assert response.status_code == 200, f"{url}: {response.status_code} {response.text[:500]}"
            return response.json()

        # The pages answer what was seeded before anything is timed: about 110 installs a Mac,
        # every installed build on one Catalog page with the retired ones counted but not
        # listed, and rows in all three of the Vulnerabilities page's lists.
        assert 105 * devices < report["installed_apps"] < 115 * devices
        listing = await get(CATALOG)
        assert listing["total"] == len(listing["items"]) == listing["summary"]["installed"]
        assert listing["summary"]["entries"] - listing["summary"]["installed"] >= CORE * RETIRED
        for url in VULNERABILITIES:
            assert (await get(url))["items"], url

        async def vulnerabilities():
            await asyncio.gather(*(get(url) for url in VULNERABILITIES))

        report["timings"] = {
            "catalog": await _timed(lambda: get(CATALOG)),
            "vulnerabilities": await _timed(vulnerabilities),
            "oldest_alone": await _timed(lambda: get(OLDEST)),
        }
        with _sent() as sent:
            await get(CATALOG)
        statements = [(sql, parameters, seconds) for sql, parameters, seconds in sent if sql.strip() != "SELECT 1"]
        report["catalog_request"] = {
            "statements": len(statements),
            "reading_installs": sum("installed_apps" in sql for sql, _, _ in statements),
            "slowest": [
                {"sql_prefix": " ".join(sql.split())[:160], "seconds": round(seconds, 3)}
                for sql, _, seconds in sorted(statements, key=lambda item: item[2], reverse=True)[:4]
            ],
        }
        print("CATALOG_SCALE_RESULT=" + json.dumps(report, sort_keys=True), flush=True)
        # Where the time goes, statement by statement, at every size: the plan changes with the
        # fleet. Re-run on this test's own tenant-bound session, so row-level security shapes each
        # plan as it shaped the request's.
        raw = await db.connection()
        for sql, parameters, _ in statements:
            if "installed_apps" in sql or "LIMIT" in sql:
                plan = (await raw.exec_driver_sql("EXPLAIN (ANALYZE, BUFFERS) " + sql, parameters)).scalars().all()
                print("CATALOG_SCALE_PLAN=" + " ".join(sql.split())[:200], *plan, sep="\n", flush=True)
        await db.rollback()
        for page, budget in BUDGETS.items():
            p95 = report["timings"][page]["p95"]
            assert p95 < budget, f"the {page} page's p95 is {p95} s at {devices} Macs, over its {budget} s budget (#726)"
    finally:
        await db.rollback()
        seeded = select(Device.id).where(Device.mdm_connection_id == connection_id, Device.external_id.like("CATSCALE-%"))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(seeded)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id, Device.external_id.like("CATSCALE-%")))
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.bundle_id.like(f"{BUNDLE_PREFIX}%")))
        await db.commit()
