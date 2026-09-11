"""`sync_catalog` end to end: a fixture served as Jamf's patch server answers it, and the
rows it writes are the fixture again.

The sync is the one path in this product that turns a public catalog into rows every
other patch surface reads — the matcher, the lookup index, the Jamf Patch page — and
until #382 it had no test at all: a session and a network were both needed, so nothing
covered the loop that decides *which* titles to re-fetch, or what the fetched definition
becomes in a row. The source seam is what makes it testable, and this file is the reason
that seam is worth its lines: the same `JamfApiCatalogSource` the hourly job uses, over
an httpx mock transport, with `backend/tests/fixtures/jamf/patch_titles_subset.json`
served the way the real server serves it — flat `and`-linked requirements, the bulky
patch keys, the script on each extension attribute, all inside the signed envelope.

The fixture holds the *stored* shape, which is what makes it a good oracle here: it was
captured from real rows, so the sync is asserted against fifty-one titles' worth of
Jamf's real output rather than against something written to make the test pass.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"


def _configured_path() -> str:
    """The path half of whatever address the source is pointed at, trailing slash trimmed
    the way `JamfApiCatalogSource` trims it."""
    from app.core.config import settings

    return httpx.URL(settings.jamf_patch_base_url.rstrip("/")).path


_BULKY = {
    "standalone": True,
    "minimumOperatingSystem": "12.0",
    "reboot": False,
    "killApps": [{"bundleId": "com.example.app", "appName": "Example.app"}],
    "components": [{"name": "Example", "version": "1.0"}],
    "capabilities": [{"name": "Operating System Version", "operator": "greater than or equal", "value": "12.0"}],
}


def _summary(record: dict) -> dict:
    """What `/software` answers per title: enough for `_needs_refresh` and no definition."""
    return {
        "id": record["id"],
        "name": record["name"],
        "publisher": record["publisher"],
        "currentVersion": record["currentVersion"],
        "lastModified": record["lastModified"],
    }


def _flatten(groups: list[dict]) -> list[dict]:
    """The stored OR'd groups turned back into Jamf's flat list, which is the only shape
    the server has: every criterion carries `and`, and a `false` is where the previous
    group ended."""
    flat: list[dict] = []
    for index, group in enumerate(groups):
        for position, test in enumerate(group["tests"]):
            flat.append({**test, "and": not (index > 0 and position == 0)})
    return flat


def _definition(record: dict) -> dict:
    """One title as the server answers it — the stored row plus everything the sync is
    there to drop."""
    return {
        "id": record["id"],
        "name": record["name"],
        "publisher": record["publisher"],
        "appName": record["appName"],
        "bundleId": record["bundleId"],
        "currentVersion": record["currentVersion"],
        "lastModified": record["lastModified"],
        "patches": [{**patch, **_BULKY} for patch in record["patches"]],
        "requirements": _flatten(record["requirements"]),
        "extensionAttributes": [{**ea, "value": "IyEvYmluL3NoCmVjaG8gMQo="} for ea in record["extensionAttributes"]],
    }


def _envelope(definition: dict) -> str:
    """The signed wrapper: bytes before the JSON, a certificate after it — and a `]}` in
    the certificate, because six real titles carry one there."""
    return f"\x30\x82SIGNED{json.dumps(definition)}\x00\x82]}}\x1f\x10"


class _FakePatchServer:
    """Jamf's public patch server, over the fixture. Counts what was asked for and how
    much of it overlapped."""

    def __init__(self, records: list[dict]) -> None:
        self.records = {record["id"]: record for record in records}
        self.requested: list[str] = []
        self.in_flight = 0
        self.peak = 0

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        self.requested.append(request.url.path)
        try:
            # Two trips through the loop, so requests that are allowed to overlap do —
            # a handler that answers without awaiting makes any fan-out look serial.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            if request.url.path.endswith("/software"):
                return httpx.Response(200, json=[_summary(record) for record in self.records.values()])
            return httpx.Response(200, text=_envelope(_definition(self.records[request.url.path.rsplit("/", 1)[-1]])))
        finally:
            self.in_flight -= 1

    def details_requested(self) -> list[str]:
        return [path.rsplit("/", 1)[-1] for path in self.requested if "/patch/" in path]

    async def sync(self, db) -> int:
        from app.mdm.patch.jamf_catalog import JamfApiCatalogSource, sync_catalog

        # The default `settings.jamf_patch_base_url` is left alone: the transport answers
        # whatever host it is given, so the paths this records are the real ones.
        async with httpx.AsyncClient(transport=httpx.MockTransport(self.handler)) as client:
            return await sync_catalog(db, JamfApiCatalogSource(client))


@pytest_asyncio.fixture(loop_scope="session")
async def records() -> list[dict]:
    return json.loads((FIXTURES / "patch_titles_subset.json").read_text())


@pytest_asyncio.fixture(loop_scope="session")
async def server(db, records):
    """A cold catalog and the server that fills it. The fixture's ids are cleared either
    side: other files seed the same titles from the same fixture, so a row left behind
    would make this file's first sync a no-op on a re-run."""
    from app.mdm.patch.matching import reset_catalog_cache
    from app.models.schema import JamfPatchTitle

    ids = [record["id"] for record in records]
    await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id.in_(ids)))
    await db.commit()
    reset_catalog_cache()

    yield _FakePatchServer(records)

    await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id.in_(ids)))
    await db.commit()
    reset_catalog_cache()


async def _rows(db, ids: list[str]) -> dict:
    from app.models.schema import JamfPatchTitle

    result = await db.execute(select(JamfPatchTitle).where(JamfPatchTitle.id.in_(ids)))
    return {row.id: row for row in result.scalars().all()}


class TestColdSync:
    async def test_the_rows_are_the_fixture(self, db, server, records) -> None:
        """Fifty-one titles in, fifty-one rows out, field for field: the envelope opened,
        the requirements folded back into groups, the bulky patch keys and the extension
        attribute scripts gone."""
        synced = await server.sync(db)

        assert synced == len(records)
        rows = await _rows(db, [record["id"] for record in records])
        assert sorted(rows) == sorted(record["id"] for record in records)
        for record in records:
            row = rows[record["id"]]
            assert row.name == record["name"]
            assert row.publisher == record["publisher"]
            assert row.app_name == record["appName"]
            assert row.bundle_id == record["bundleId"]
            assert row.current_version == record["currentVersion"]
            assert row.last_modified == record["lastModified"]
            assert row.patches == record["patches"]
            assert row.requirements == record["requirements"]
            assert row.extension_attributes == record["extensionAttributes"]
            assert row.synced_at is not None

    async def test_one_summary_read_and_one_definition_per_title(self, db, server, records) -> None:
        await server.sync(db)

        # Derived, not spelled: the transport answers whatever host it is given, so this
        # file's recorded paths follow `settings.jamf_patch_base_url`. A lane with
        # JAMF_PATCH_BASE_URL exported would otherwise fail here for a reason that has
        # nothing to do with the sync.
        assert server.requested[0] == f"{_configured_path()}/software"
        assert sorted(server.details_requested()) == sorted(record["id"] for record in records)

    async def test_at_most_eight_definition_requests_are_in_flight(self, db, server) -> None:
        """The bound (#382), on the path a container actually runs: a fresh pod has no
        rows, so every title in the catalog is a definition to fetch, and before this the
        whole catalog was dialled at once."""
        from app.mdm.patch.jamf_catalog import DETAIL_CONCURRENCY

        await server.sync(db)

        assert server.peak == DETAIL_CONCURRENCY == 8


class TestSecondSync:
    async def test_an_unchanged_catalog_fetches_no_definitions(self, db, server, records) -> None:
        """What `_needs_refresh` buys, and the reason the fan-out is normally small: the
        hourly tick after a full sync reads one summary list and stops."""
        await server.sync(db)
        server.requested.clear()

        assert await server.sync(db) == 0
        assert server.requested == [f"{_configured_path()}/software"]

    async def test_one_moved_title_is_the_only_one_refetched(self, db, server, records) -> None:
        await server.sync(db)
        server.requested.clear()
        moved = records[0]["id"]
        server.records[moved] = {**server.records[moved], "currentVersion": "99.0.0", "lastModified": "2026-09-11T00:00:00Z"}

        assert await server.sync(db) == 1
        assert server.details_requested() == [moved]
        rows = await _rows(db, [moved])
        assert rows[moved].current_version == "99.0.0"
        assert rows[moved].last_modified == "2026-09-11T00:00:00Z"


class TestBadTitle:
    async def test_one_unreadable_definition_costs_only_that_title(self, db, server, records) -> None:
        """`return_exceptions=True` under the fan-out: the sync writes the other fifty and
        the skipped title stays absent, so the next tick fetches it again."""
        broken = records[3]["id"]
        handler = server.handler

        async def failing(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith(f"/patch/{broken}"):
                return httpx.Response(500)
            return await handler(request)

        server.handler = failing  # type: ignore[method-assign]

        synced = await server.sync(db)

        assert synced == len(records) - 1
        rows = await _rows(db, [record["id"] for record in records])
        assert broken not in rows
        assert len(rows) == len(records) - 1


class TestAnUnusableAddress:
    """What the hourly job does when `JAMF_PATCH_BASE_URL` holds something that is not an
    address — the one failure this change introduced, on the only surface the job has."""

    async def test_the_job_logs_the_sentence_once_with_no_traceback(self, db, monkeypatch) -> None:
        """`docker compose logs app` is where this job speaks: there is no run row and no
        page. One ERROR line that names the setting, no stack, and the job returns rather
        than letting APScheduler print a traceback that names httpx instead
        (`docs/diagnosability.md` rule 3; `docs/troubleshooting.md` section 6)."""
        import logging

        from app.core.config import settings
        from app.main import hourly_jamf_patch_sync

        # A handler of our own rather than `caplog`: importing `app.main` runs
        # `configure_logging`, which replaces the root handlers — so whether caplog's
        # survives depends on whether some earlier test imported the module first. This
        # attaches after that import and asserts the same three things.
        said: list[logging.LogRecord] = []

        class _Collect(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                said.append(record)

        monkeypatch.setattr(settings, "jamf_patch_base_url", "jamf-patch.jamfcloud.com/v1")
        collector = _Collect(level=logging.ERROR)
        logging.getLogger("app.main").addHandler(collector)
        try:
            await hourly_jamf_patch_sync()
        finally:
            logging.getLogger("app.main").removeHandler(collector)

        named = [record for record in said if "JAMF_PATCH_BASE_URL" in record.getMessage()]
        assert len(named) == 1
        assert named[0].levelno == logging.ERROR
        assert named[0].exc_info is None
        assert "jamf-patch.jamfcloud.com/v1" in named[0].getMessage()
        assert "docs/troubleshooting.md" in named[0].getMessage()

    async def test_nothing_is_written_when_the_address_is_refused(self, db, server, records, monkeypatch) -> None:
        """The rows the container already had keep answering: the refusal happens at
        source construction, before a request or a write."""
        from app.core.config import settings
        from app.mdm.patch.jamf_catalog import JamfPatchCatalogUnconfigured, sync_catalog

        await server.sync(db)
        before = {row_id: row.synced_at for row_id, row in (await _rows(db, [r["id"] for r in records])).items()}

        monkeypatch.setattr(settings, "jamf_patch_base_url", "")
        with pytest.raises(JamfPatchCatalogUnconfigured):
            await sync_catalog(db)

        after = {row_id: row.synced_at for row_id, row in (await _rows(db, [r["id"] for r in records])).items()}
        assert after == before
        assert len(after) == len(records)
