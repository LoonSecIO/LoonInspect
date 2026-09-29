"""The catalog list with its device counts read once a request (#726), against the same list with
the counts joined as the subquery every statement walked before: equal, response for response,
across the asks the pages make. Gated on RUN_DB_TESTS.

The fleet lives in a tenant of this suite's own. The comparison is byte for byte and in order,
and order is promised only where an order's keys differ: two rows that tie on every key may come
back either way round under either plan. Rows another suite left in a shared tenant could tie
like that; this fleet has no such pair (see `MACS`).
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from itertools import product

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.tenancy import reset_tenant_id, set_tenant_id
from app.core.vuln import NO_CORPUS, forget_tenant_tiers, loaded_corpus
from app.core.vuln_library import load_epoch_if_new, refresh_from_db
from app.models.schema import (
    AppCatalogEntry,
    DataSharingSettings,
    Device,
    InstalledApp,
    JamfPatchTitle,
    MdmConnection,
    Tenant,
    VulnLibraryEpoch,
    VulnLibraryRow,
    VulnLibraryTitle,
)
from tests.test_catalog_db import _list
from tests.test_sweep_costs_db import statements  # the statement recorder, not a fixture
from tests.test_vuln_answer_db import APPS, TARGET_TITLE_ID, WIRESHARK_TARGET, _device, _judge, _pointer, _set_tier, _with_titles
from tests.test_vuln_library import _rewritten, _row
from tests.test_vuln_library_db import _serving

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000726")
WIRESHARK = ("Wireshark.app", "org.wireshark.Wireshark")
BUILDS = {
    "w420": (*WIRESHARK, "4.2.0"),
    "w400": (*WIRESHARK, "4.0.0"),
    "w360": (*WIRESHARK, "3.6.0"),
    "clean": APPS[1],
    "stale": APPS[2],
    "unknown": APPS[3],
    "retired": ("LoonVD Fixture Retired.app", "io.loonsec.fixture.retired", "9.0.0"),
}
# Six Macs, and every installed build on a different number of them (6, 5, 4, 3, 2, 1), so each
# order the list offers is decided by its keys alone. The second Mac carries the clean build
# twice, as two copies of an app are two installs, and `count(distinct device_id)` still says
# five. The retired build is the catalog row whose last Mac has moved off it: none carry it.
MACS = (
    ("w420", "clean", "stale", "unknown"),
    ("w420", "clean", "clean", "stale"),
    ("w420", "clean", "stale", "w400"),
    ("w420", "clean", "w400"),
    ("w420", "clean", "w400", "w360"),
    ("w420", "w400", "w360", "retired"),
)


def _answer(key: str, first: int, stamp: str | None, **counts: int) -> dict:
    """An epoch row with these counts, ids to match and one publication date, so every build with
    findings has an age of its own for `order=age` to rank."""
    counts = {"total": sum(counts.get(band, 0) for band in ("critical", "high", "medium", "low")), "kev": 0, **counts}
    counts = {name: counts.get(name, 0) for name in ("total", "kev", "critical", "high", "medium", "low")}
    oldest = {band: stamp if counts[band] else None for band in ("total", "critical", "high", "medium", "low")}
    ids = [f"CVE-2026-{first + index}" for index in range(counts["total"])]
    return _row(key_full=key, ids=ids, counts=counts, oldest_published=oldest)


def _key(build: str) -> str:
    from app.core.content_keys import app_full_key

    name, bundle_id, version = BUILDS[build]
    return app_full_key(name, bundle_id, version, None)


async def _clear(db) -> None:
    """This tenant's fleet, whatever a previous run left: the rows reference each other in this order."""
    connections = select(MdmConnection.id).where(MdmConnection.tenant_id == TENANT_ID)
    devices = select(Device.id).where(Device.mdm_connection_id.in_(connections))
    await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(devices)))
    await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.tenant_id == TENANT_ID))
    await db.execute(delete(Device).where(Device.mdm_connection_id.in_(connections)))
    await db.execute(delete(MdmConnection).where(MdmConnection.tenant_id == TENANT_ID))
    await db.execute(delete(DataSharingSettings).where(DataSharingSettings.tenant_id == TENANT_ID))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def counted(tenant_ready):
    """The fleet above, judged against an epoch that answers every filter the list has, in this
    suite's own tenant; yields the tenant's session. Wireshark matches a Jamf title whose latest
    release is clean, so its three builds are easily patchable. Torn down whole, the library and
    the global Jamf title included, as `test_vuln_answer_db.fleet` does for its own."""
    from app.core.database import session_for_tenant, unscoped_session
    from app.mdm.patch.matching import reset_catalog_cache

    async with unscoped_session() as unscoped:
        if (await unscoped.execute(select(Tenant).where(Tenant.id == TENANT_ID))).scalars().first() is None:
            unscoped.add(Tenant(id=TENANT_ID, slug="catalog-counts", name="catalog-counts", kind="operational"))
            await unscoped.commit()
    token = set_tenant_id(TENANT_ID)
    try:
        async with session_for_tenant(TENANT_ID) as db:
            await _clear(db)
            try:
                await _with_titles(db)
                await _set_tier(db, "keys")
                rows = [
                    _answer(_key("w420"), 1000, "2024-01-03T00:00:00Z", kev=1, critical=1, high=8, medium=8),
                    _answer(_key("w400"), 1100, "2023-05-01T00:00:00Z", high=30),
                    _answer(_key("w360"), 1200, "2022-02-02T00:00:00Z", high=1),
                    _answer(WIRESHARK_TARGET, 1300, None),
                    _answer(_key("clean"), 1400, None),
                    _answer(_key("stale"), 1500, "2020-03-04T00:00:00Z", high=5),
                    _answer(_key("retired"), 1600, "2025-07-07T00:00:00Z", medium=2),
                ]
                bundle, signature = _rewritten(rows=rows)
                assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle)) is not None
                connection = MdmConnection(
                    name=f"catalog counts {uuidlib.uuid4().hex[:8]}",
                    provider="jamf",
                    base_url="https://jamf.example.com",
                    credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
                )
                db.add(connection)
                await db.commit()
                for index, builds in enumerate(MACS, start=1):
                    device = await _device(db, connection, f"C02COUNT{index:04d}", [BUILDS[build] for build in builds])
                    await _judge(db, device)
                # The retired build's last install goes; its catalog row stays, as the catalog's rows do.
                await db.execute(delete(InstalledApp).where(InstalledApp.key_full == _key("retired")))
                await db.commit()
                yield db
            finally:
                await db.rollback()
                await _clear(db)
                await db.execute(delete(VulnLibraryRow))
                await db.execute(delete(VulnLibraryTitle))
                await db.execute(delete(VulnLibraryEpoch))
                await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == TARGET_TITLE_ID))
                await db.commit()
                await refresh_from_db(db)
                forget_tenant_tiers()
                reset_catalog_cache()
                assert loaded_corpus() is NO_CORPUS
    finally:
        reset_tenant_id(token)


async def _per_statement(db, app_hash=None):
    """The device counts as the list joined them before #726: the grouped subquery itself, which
    every statement naming it evaluated for itself."""
    from app.api import catalog

    return catalog._device_counts(app_hash)


VULNS = ("all", "findings", "kev", "unknown_app", "clean", "patchable")
ORDERS = ("exposure", "age", "payoff")
# The Catalog tab (all of it, installed or not, by Jamf match), the Vulnerabilities page (each
# filter, a search, the unmatched chip, a band) and the application record (one app's builds,
# installed or not). Pages: the whole list, a middle page, and a page past the end.
VARIANTS = (
    {},
    {"installed_only": False},
    {"q": "wire"},
    {"jamf": "unmatched"},
    {"band": "critical"},
    {"app_hash": "wireshark", "installed_only": False},
)
PAGES = ((1, 500), (2, 2), (9, 2))


async def test_the_list_reads_the_device_counts_once_and_answers_as_it_did(counted, monkeypatch) -> None:
    """Every ask, answered twice: with the counts read once and joined as rows, and with the
    subquery the three statements each walked. Same rows, same order, same device counts, same
    total and summary — and one read of `installed_apps` where there were three (two for one
    application's record, which carries no summary), still scoped to that one app (#299)."""
    from app.api import catalog
    from app.core.hashing import compute_app_hash

    db = counted
    wireshark = compute_app_hash(*WIRESHARK)

    async def ask(params: dict) -> tuple[dict, list[str]]:
        with statements() as sent:
            response = await _list(db, **params)
        return response.model_dump(mode="json", by_alias=True), [sql for sql in sent if "installed_apps" in sql]

    first = (await ask({"page_size": 500}))[0]
    assert [(item["version"], item["deviceCount"]) for item in first["items"]] == [
        ("4.2.0", 6),
        ("2.6.0", 5),
        ("4.0.0", 4),
        ("3.2.0", 3),
        ("3.6.0", 2),
        ("1.0.0", 1),
    ], "the fleet this suite means to compare over"
    assert first["summary"] == {"entries": 7, "installed": 6, "matched": 3, "unmatched": 4}
    for vuln in VULNS[1:]:
        assert (await ask({"vuln": vuln, "page_size": 500}))[0]["items"], f"vuln={vuln} answers nothing to compare"

    asked = 0
    for vuln, order, variant, (page, page_size) in product(VULNS, ORDERS, VARIANTS, PAGES):
        params = {"vuln": vuln, "order": order, **variant, "page": page, "page_size": page_size}
        if params.get("app_hash"):
            params["app_hash"] = wireshark
        once, reads = await ask(params)
        with monkeypatch.context() as patched:
            patched.setattr(catalog, "_device_counts_once", _per_statement)
            before, walks = await ask(params)
        assert once == before, params
        assert (len(reads), len(walks)) == (1, 2 if params.get("app_hash") else 3), params
        assert ("installed_apps.app_hash = " in reads[0]) == bool(params.get("app_hash")), params
        asked += 1
    assert asked == len(VULNS) * len(ORDERS) * len(VARIANTS) * len(PAGES)
