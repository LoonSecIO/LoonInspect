"""The local join, stored: judged once per distinct build, read as columns (#381).

#248 loads an epoch into three global tables and `test_vuln_library_db.py` pins that. This
suite pins what the tenant's own rows then do with it — the half the ruling is actually
about, and the half that has a cost model:

* **a row in the library is the verdict, and the only verdict** (ruling R-D). The fixture
  epoch's Wireshark 4.2.0 has a row and reads `covered` with that row's aggregates; the
  fixture's `3.2.0` build has no row and reads `unknown_app` **even though its `key_title`
  is in the epoch's coverage metadata** — the withdrawn branch is asserted absent, not
  merely unbuilt;
* **once per distinct build, never per device.** A device page with 250 apps issues no
  per-app lookup of any kind, and a new epoch re-judges distinct builds rather than
  installs — both pinned by counting statements, because both produce correct answers
  either way and only the cost tells them apart;
* **the gate is the tenant, and `off` is byte-identical.** A tenant whose data-sharing tier
  is `off` stores no corpus-derived answer at all and its snapshot matches, byte for byte,
  the one a container with no library emits;
* **what the night's tape makes of it** (#250). The last two tests read the same stored
  answers through the posture recorder: the fixture epoch's numbers on a judged tenant, and
  no `vuln.*` rows at all on a pod that was never assessed.

Gated on RUN_DB_TESTS like the other database-backed suites, and every test restores the
process to "no library loaded, tier off" afterwards — the corpus and the per-tenant tier are
process-level facts by design, and the suite that pins `assessment: off` runs in this same
process.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime

import pytest
import pytest_asyncio
from sqlalchemy import delete, event, select, update

from app.core.content_keys import app_full_key
from app.core.tenancy import OPERATIONAL_TENANT_ID, reset_tenant_id, set_tenant_id
from app.core.vuln import NO_CORPUS, forget_tenant_tiers, loaded_corpus
from app.core.vuln_library import CorpusPointer, load_epoch_if_new, refresh_from_db
from app.models.schema import (
    AppCatalogEntry,
    Device,
    InstalledApp,
    JamfPatchTitle,
    MdmConnection,
    VulnLibraryEpoch,
    VulnLibraryRow,
    VulnLibraryTitle,
)
from tests.test_catalog_db import _list as _list_catalog
from tests.test_vuln_library import (
    BUNDLE,
    CLEAN_BUILD,
    CORPUS_URL,
    SIGNATURE,
    STALE_TITLE,
    STALE_UNASSESSED_BUILD,
    UNKNOWN_BUILD,
    UNKNOWN_TITLE,
    WIRESHARK_BUILD,
    WIRESHARK_TITLE,
    _rewritten,
    _row,
)
from tests.test_vuln_library_db import _serving

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

TODAY = date(2026, 9, 10)
NOW = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)

# The four identities the fixture epoch is built from, as a device would report them. The
# names and bundle ids are what `content_keys` hashes, so these rows join the epoch or do
# not entirely on their own facts — nothing here restates a key as a literal.
APPS = (
    ("Wireshark.app", "org.wireshark.Wireshark", "4.2.0"),
    ("LoonVD Fixture Clean.app", "io.loonsec.fixture.clean", "2.6.0"),
    # A build the epoch did NOT assess, of a title it DID compile — the case ruling R-D is
    # about. `unknown_app`, never a clean bill.
    ("LoonVD Fixture Stale.app", "io.loonsec.fixture.stale", "3.2.0"),
    # In no object of the epoch at all.
    ("LoonVD Fixture Unknown.app", "io.loonsec.fixture.unknown", "1.0.0"),
)


def _pointer(signature: str = SIGNATURE) -> CorpusPointer:
    return CorpusPointer(signature=signature, asof=datetime(2026, 9, 10, 20, 0, tzinfo=UTC), url=CORPUS_URL)


@contextmanager
def _statements() -> Iterator[list[str]]:
    """Every SQL statement the engine sends while the block runs, in order.

    Counting rather than timing, for the reason `test_sweep_costs_db.py` gives: a statement
    count is the same on a laptop and in CI, and "no per-app lookup" is a fact a stopwatch
    cannot state.
    """
    from app.core.database import engine

    seen: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany) -> None:
        seen.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record)


@pytest_asyncio.fixture(loop_scope="session")
async def acting_tenant(db):
    """The tenancy contextvar every path that reaches the corpus gate binds — the request
    middleware, and the scheduler's `tenant_job`. The `db` fixture binds the tenant on the
    *session* (the GUC row-level security reads) and not in context, because no route does
    that by hand, and the gate reads the acting tenant from context."""
    token = set_tenant_id(OPERATIONAL_TENANT_ID)
    try:
        yield OPERATIONAL_TENANT_ID
    finally:
        reset_tenant_id(token)


async def _set_tier(db, tier: str) -> None:
    from app.core.sharing import get_or_create_settings, remember_tier

    row = await get_or_create_settings(db)
    row.tier = tier
    await db.commit()
    remember_tier(row)


@pytest_asyncio.fixture(loop_scope="session")
async def fleet(db, acting_tenant):
    """One connection, one Mac, the four fixture apps — and no library, tier `keys`.

    Torn down whole, library included, so the next test in this process starts where every
    container starts: nothing loaded, and `assessment: off`.
    """
    from app.mdm.patch.matching import reset_catalog_cache

    connection = MdmConnection(
        name=f"vuln answer {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url="https://jamf.example.com",
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
    )
    db.add(connection)
    await db.commit()
    # Read while the instance is certainly live: the rollback below expires every ORM
    # instance in the session, and an expired attribute read under asyncio raises
    # MissingGreenlet rather than lazily refreshing (#125).
    connection_id = connection.id
    device = await _device(db, connection, "C02VULN0001", APPS)
    await _set_tier(db, "keys")
    reset_catalog_cache()
    try:
        yield connection, device
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        hashes = select(InstalledApp.version_hash).where(InstalledApp.device_id.in_(device_ids))
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.execute(delete(VulnLibraryRow))
        await db.execute(delete(VulnLibraryTitle))
        await db.execute(delete(VulnLibraryEpoch))
        # And #482's Jamf title. `jamf_patch_titles` is GLOBAL — no tenant column, so no
        # rollback and no policy takes it away — and a title left behind matches an app in
        # another suite's fake catalog, which is a failure in a file nobody touched.
        await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == TARGET_TITLE_ID))
        await db.commit()
        await refresh_from_db(db)
        await _set_tier(db, "off")
        forget_tenant_tiers()
        reset_catalog_cache()
        assert loaded_corpus() is NO_CORPUS


async def _device(db, connection, serial: str, apps) -> Device:
    """A Mac carrying these apps, with the content keys the container stamps at ingest.

    Built through `app.core.content_keys` rather than with literals, for the reason the
    fixture epoch's README gives: two implementations of one hash do not fail loudly when
    they drift, they answer `unknown_app` for an app the corpus knows perfectly well.
    """
    from app.core.content_keys import app_full_key, app_title_key
    from app.core.hashing import compute_app_hash, compute_version_hash

    device = Device(
        mdm_connection_id=connection.id,
        mdm_provider="jamf",
        external_id=serial,
        serial_number=serial,
        hostname=serial.lower(),
        platform="macos",
        managed=True,
    )
    db.add(device)
    await db.flush()
    for name, bundle_id, version in apps:
        db.add(
            InstalledApp(
                device_id=device.id,
                name=name,
                bundle_id=bundle_id,
                version=version,
                short_version=None,
                app_hash=compute_app_hash(name, bundle_id),
                version_hash=compute_version_hash(name, bundle_id, version, None),
                key_title=app_title_key(name, bundle_id),
                key_full=app_full_key(name, bundle_id, version, None),
            )
        )
    await db.commit()
    return device


async def _judge(db, device) -> int:
    from app.catalog.service import record_device_apps

    judged = await record_device_apps(db, device, now=NOW)
    await db.commit()
    return judged


async def _entry(db, key_full: str) -> AppCatalogEntry:
    return (await db.execute(select(AppCatalogEntry).where(AppCatalogEntry.key_full == key_full))).scalars().one()


async def _installed(db, device, key_full: str) -> InstalledApp:
    return (
        (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device.id, InstalledApp.key_full == key_full)))
        .scalars()
        .one()
    )


async def _stored(db, device, key_full: str) -> tuple[str | None, str | None]:
    """One device row's stored answer **as the database holds it**, deliberately not as an
    ORM entity.

    The sessions here are `expire_on_commit=False` and every set-based copy runs
    `synchronize_session=False`, so re-`select`ing the entity hands back the identity map's
    cached instance with its *old* attribute values. A missing copy therefore hides from any
    assertion that reads objects — it reads whatever the last in-memory write left — and
    shows up only against the columns. Selecting columns bypasses the identity map.
    """
    return (
        await db.execute(
            select(InstalledApp.vuln_assessment, InstalledApp.vuln_signature).where(
                InstalledApp.device_id == device.id, InstalledApp.key_full == key_full
            )
        )
    ).one()


async def _block(db, device, key_full: str):
    """One installed app's `vuln{}` as the read path produces it — the stored answer through
    the same seam the wire uses."""
    from app.core.vuln import vuln_block
    from app.core.vuln_answer import stored_corpus
    from app.core.vuln_library import earned_corpus

    rows = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device.id))).scalars().all()
    corpus = stored_corpus(await earned_corpus(db), rows)
    row = next(row for row in rows if row.key_full == key_full)
    return vuln_block(corpus, key_title=row.key_title, key_full=row.key_full, as_of=TODAY)


# --- the verdict: a row, and only a row ------------------------------------------------


async def test_a_rowed_build_is_covered_with_the_rows_own_aggregates(db, fleet) -> None:
    """The whole point. The epoch's Wireshark row lands on the catalog row, is copied onto
    the device's app row, and reads `covered` with the counts the epoch published — not with
    counts recomputed from the capped id list, which is why `total` is asserted against the
    row and the ids against the row's own list."""
    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)

    entry = await _entry(db, WIRESHARK_BUILD)
    assert entry.vuln_assessment == "covered"
    assert entry.vuln_counts["total"] == 17
    assert entry.vuln_counts["high"] == 9
    assert entry.vuln_signature == SIGNATURE
    assert entry.vuln_evaluated_at == NOW

    # The copy, which is what every device page and every event actually reads.
    app = await _installed(db, device, WIRESHARK_BUILD)
    assert (app.vuln_assessment, app.vuln_signature) == ("covered", SIGNATURE)
    assert app.vuln_counts == entry.vuln_counts and app.vuln_ids == entry.vuln_ids

    block = await _block(db, device, WIRESHARK_BUILD)
    assert block.assessment == "covered"
    assert block.corpus_as_of == TODAY
    assert block.counts.total == 17 and block.counts.severity.high == 9
    assert block.days_oldest_published.total == (TODAY - date(2024, 1, 3)).days
    assert len(block.vuln_ids) == 17 and block.vuln_ids_truncated is False


async def test_an_assessed_and_clean_build_is_covered_with_no_findings(db, fleet) -> None:
    """`covered` with zero findings, because the epoch carries a ROW for it. That is the
    whole distinction §4f is built on: this is a clean bill, and the next test's build —
    which also has no findings in the epoch — is not."""
    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)

    block = await _block(db, device, CLEAN_BUILD)
    assert block.assessment == "covered"
    assert block.counts.total == 0
    assert block.vuln_ids == []
    assert block.days_oldest_published.total is None


async def test_a_rowless_build_of_a_compiled_title_is_unknown_app(db, fleet) -> None:
    """Ruling R-D, asserted as an absence.

    `LoonVD Fixture Stale 3.2.0` has no row in the epoch, and its **title is in the epoch's
    coverage metadata** — the exact state the withdrawn stamp rule would have turned into a
    clean bill. It reads `unknown_app`: dated, uncounted, and never `covered` with zeroes.
    The title row is asserted present so the test cannot pass by the metadata simply being
    missing.
    """
    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    compiled = (await db.execute(select(VulnLibraryTitle).where(VulnLibraryTitle.key_title == STALE_TITLE))).scalars().all()
    assert compiled, "the fixture epoch is supposed to compile this title — otherwise this test proves nothing"
    await _judge(db, device)

    entry = await _entry(db, STALE_UNASSESSED_BUILD)
    assert entry.vuln_assessment is None
    assert entry.vuln_counts is None and entry.vuln_ids is None
    # Judged, though: the signature says an epoch looked and found nothing, which is what
    # stops the next pass from re-judging it for nothing.
    assert entry.vuln_signature == SIGNATURE

    block = await _block(db, device, STALE_UNASSESSED_BUILD)
    assert block.assessment == "unknown_app"
    assert block.corpus_as_of == TODAY
    assert block.counts is None and block.vuln_ids is None


async def test_a_build_in_no_object_at_all_is_unknown_app(db, fleet) -> None:
    """The ordinary case, beside the ruled one: an application the epoch never saw. Same
    three words, same absence of numbers — a reader cannot tell the two apart and does not
    need to, because neither was assessed."""
    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)

    assert (await _entry(db, UNKNOWN_BUILD)).vuln_assessment is None
    block = await _block(db, device, UNKNOWN_BUILD)
    assert block.assessment == "unknown_app"
    assert block.model_dump(exclude_none=True) == {"assessment": "unknown_app", "corpus_as_of": TODAY}


# --- the cost model: once per build, never per device -----------------------------------


async def test_a_device_page_with_250_apps_issues_no_per_app_lookup(db, fleet) -> None:
    """The property that has to hold at fleet scale, counted rather than timed.

    A second Mac carrying 250 builds is judged once, and then its detail response is
    rendered twice — with the epoch loaded and without. Both cost the same handful of
    statements, and neither grows with the app count: the answers are columns the response
    already selected, so there is nothing left to look up.

    `len(issued) < 10` is the load-bearing assertion here; keep it. The `vuln_library_rows`
    one below it is a guard rail, not a property — the in-memory lookup this replaced never
    named that table either, so it would have passed before #381 as well. The assertion that
    actually pins "the corpus is never asked on the read path" lives in `test_vuln_read.py`
    (`assert loaded.calls == []`).
    """
    from app.api.devices import get_device

    connection, _ = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    many = [(f"Bulk {index}.app", f"io.loonsec.bulk{index}", "1.0.0") for index in range(250)]
    big = await _device(db, connection, "C02VULN0250", (*APPS, *many))
    await _judge(db, big)

    with _statements() as issued:
        detail = await get_device(big.id, db)
    assert len(detail.apps) == 254
    # Well under one per app, and flat: the page's cost is its own selects, not the corpus.
    assert len(issued) < 10, issued
    assert not any("vuln_library_rows" in statement for statement in issued)
    covered = [app for app in detail.apps if app.vuln.assessment == "covered"]
    assert len(covered) == 2  # Wireshark and the clean fixture; the 250 are in no epoch


async def test_a_new_epoch_re_judges_distinct_builds_not_devices(db, fleet) -> None:
    """A new epoch costs one pass over distinct builds.

    Three Macs carry the same four builds. A second epoch is imported — a different
    signature, one row — and the refresh that follows re-judges **four catalog rows in one
    statement**, not twelve installs one at a time, and copies the answer onto the twelve
    device rows in one more. The assertion is on the statements, because a per-row loop
    produces exactly the same answers.
    """
    from app.catalog.service import refresh_tenant

    connection, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)
    for serial in ("C02VULN0002", "C02VULN0003"):
        await _judge(db, await _device(db, connection, serial, APPS))
    assert (await _entry(db, WIRESHARK_BUILD)).vuln_assessment == "covered"

    # A second epoch carrying ONE row, for the build the first epoch did not assess.
    # Wireshark's row is gone, so its answer must go back to `unknown_app` rather than
    # linger — and the 3.2.0 build must become `covered`, so this is not just a clearing
    # pass wearing a join's clothes.
    smaller, signature = _rewritten(rows=[_row(key_full=STALE_UNASSESSED_BUILD)])
    assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(smaller)) is not None

    with _statements() as issued:
        await refresh_tenant(db)
        await db.commit()
    joins = [statement for statement in issued if "vuln_library_rows" in statement]
    copies = [statement for statement in issued if statement.lstrip().startswith("UPDATE installed_apps")]
    assert len(joins) == 1, joins
    assert len(copies) == 1, copies

    for key_full in (WIRESHARK_BUILD, CLEAN_BUILD):
        assert (await _entry(db, key_full)).vuln_assessment is None
        assert (await _installed(db, device, key_full)).vuln_assessment is None
        assert (await _block(db, device, key_full)).assessment == "unknown_app"
    # And the build the new epoch DOES carry is covered, on every Mac that has it — twelve
    # device rows moved by the one copy statement above.
    moved = (await db.execute(select(InstalledApp).where(InstalledApp.key_full == STALE_UNASSESSED_BUILD))).scalars().all()
    assert len(moved) == 3
    assert {(row.vuln_assessment, row.vuln_signature) for row in moved} == {("covered", signature)}
    assert (await _block(db, device, STALE_UNASSESSED_BUILD)).counts.total == 1


async def test_the_answer_is_on_the_rows_the_snapshot_is_built_from_before_any_commit(db, fleet) -> None:
    """The ordering `app.mdm.service` depends on, pinned where it can actually break.

    `process_sync` calls `record_device_apps` and then builds the snapshot from the very
    `InstalledApp` instances the session's identity map holds — no second query, mid
    transaction. So the join's answer has to reach those *objects*, not just their rows: it
    is written by one set-based UPDATE, read back through RETURNING onto the catalog
    entities, and copied onto the app rows by `copy_answer`. A judge pass that wrote only to
    the database would leave the snapshot emitting `unknown_app` for an app the container
    had just assessed, and every functional assertion after the commit would still pass.
    """
    from app.catalog.service import record_device_apps
    from app.core.vuln import vuln_block
    from app.core.vuln_answer import stored_corpus

    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    rows = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device.id))).scalars().all()
    await record_device_apps(db, device, now=NOW)

    corpus = stored_corpus(loaded_corpus(), rows)
    wireshark = next(row for row in rows if row.key_full == WIRESHARK_BUILD)
    block = vuln_block(corpus, key_title=wireshark.key_title, key_full=wireshark.key_full, as_of=TODAY)
    assert block.assessment == "covered" and block.counts.total == 17
    await db.commit()


async def test_a_second_sweep_under_an_unmoved_epoch_re_judges_nothing(db, fleet) -> None:
    """The other half of the cost model: nothing moved, nothing costs.

    A device processed twice under the same epoch and the same catalog issues no join at all
    on the second pass — the signature on every row it carries already names the epoch that
    is answering.
    """
    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)

    with _statements() as issued:
        await _judge(db, device)
    assert not any("vuln_library_rows" in statement for statement in issued), issued


# --- the copy reaches every device, not only the one that judged -------------------------


async def test_the_hourly_pass_copies_an_answer_another_macs_sweep_judged(db, fleet) -> None:
    """The pass that reaches a Mac nobody has swept since its builds were judged.

    Two Macs carry the same builds. The quiet one syncs before any epoch exists; then an
    epoch lands and the *other* Mac's check-in judges the catalog rows. From that instant the
    quiet Mac's rows are the only thing left holding no answer, and neither copier reaches
    them: `record_device_apps` copies onto the device whose own pass judged, and the quiet
    Mac is not syncing. So the hourly refresh has to copy whether or not it re-judged
    anything — and it re-judges nothing here, because the catalog rows already name the
    current epoch.

    Gating the copy on the re-judge count left the quiet Mac reading `unknown_app` on its
    device page and in `loon:jamf:mac:app` **permanently**: the next epoch reruns the same
    race, and nothing else in the system writes that copy. Read against the columns, not the
    entities — see `_stored`.
    """
    from app.catalog.service import refresh_tenant

    connection, quiet = fleet
    await _judge(db, quiet)  # synced before the corpus existed: no answer to carry
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, await _device(db, connection, "C02VULN0011", APPS))  # the other Mac judges

    assert (await _entry(db, WIRESHARK_BUILD)).vuln_assessment == "covered"
    assert await _stored(db, quiet, WIRESHARK_BUILD) == (None, None)

    await refresh_tenant(db)
    await db.commit()

    assert await _stored(db, quiet, WIRESHARK_BUILD) == ("covered", SIGNATURE)
    assert (await _block(db, quiet, WIRESHARK_BUILD)).assessment == "covered"


async def test_a_mac_that_syncs_after_another_judged_its_builds_gets_the_copy(db, fleet) -> None:
    """The other half of the same race, closed at the sync rather than at the hour.

    The quiet Mac from the test above does check in — and on the old copy condition that
    changed nothing: its rows are not new (`last_patch_check_at` is set from its first sync)
    and nothing this pass judged put its builds in `moved`, because the other Mac's sweep had
    already made the catalog rows current. The device's own sync has to notice that the epoch
    on its stored copy is not the epoch its catalog row now carries.
    """
    connection, quiet = fleet
    await _judge(db, quiet)
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, await _device(db, connection, "C02VULN0012", APPS))
    assert await _stored(db, quiet, WIRESHARK_BUILD) == (None, None)

    await _judge(db, quiet)  # this Mac checks in; nothing about the catalog moved

    assert await _stored(db, quiet, WIRESHARK_BUILD) == ("covered", SIGNATURE)
    assert (await _block(db, quiet, WIRESHARK_BUILD)).assessment == "covered"


async def test_a_quiet_tenant_pays_no_copy_it_does_not_need(db, fleet) -> None:
    """The cost of making the copy unconditional, stated: one no-op UPDATE an hour.

    Two refreshes back to back under an unmoved epoch. The second issues its join and its
    copy — they are unconditional now — and both match nothing, so no `installed_apps` row is
    written and the pass stays silent. `copy_vuln_answers`'s `is_distinct_from` predicate is
    what makes that true; without it an hourly pass would rewrite every app row of every
    tenant forever.
    """
    from app.catalog.service import copy_vuln_answers, refresh_tenant

    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)
    await refresh_tenant(db)
    await db.commit()

    assert await copy_vuln_answers(db) == 0
    with _statements() as issued:
        await refresh_tenant(db)
    copies = [statement for statement in issued if statement.lstrip().startswith("UPDATE installed_apps")]
    assert len(copies) == 1, copies


async def test_refresh_repairs_a_stored_answer_that_will_not_parse(db, fleet, caplog) -> None:
    """The remedy `docs/troubleshooting.md` §5 step 4 promises, held to its word.

    A stored answer is corrupted the way that step describes — a row that moved underneath
    the container. The read path declines to trust it, names it (`answer_unreadable`) and the
    app reads `unknown_app` rather than raising. *Refresh* — `refresh_tenant(force=True)`,
    what the Catalog tab's button calls — must rewrite it, and that is why a scope handed to
    `judge_vuln` is re-judged whatever its signature says: the corrupted row's signature still
    names the epoch that is answering, so a signature filter there would make this button
    powerless and step 4 a lie.
    """
    import logging

    from app.catalog.service import refresh_tenant
    from app.core.vuln import vuln_block
    from app.core.vuln_answer import stored_corpus

    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)

    async def _read():
        row = await _installed(db, device, WIRESHARK_BUILD)
        await db.refresh(row)
        corpus = stored_corpus(loaded_corpus(), [row])
        return vuln_block(corpus, key_title=row.key_title, key_full=row.key_full, as_of=TODAY)

    assert (await _read()).counts.total == 17

    # Corrupted on the entities as well as in the table, which is what a restored backup or a
    # hand-edited row looks like to a fresh process. An UPDATE alone would leave this
    # session's cached catalog entry holding the good answer, and the copy would then repair
    # the device row out of memory without the judge pass having done anything at all.
    broken = {"total": "seventeen", "kev": 1}
    (await _entry(db, WIRESHARK_BUILD)).vuln_counts = broken
    (await _installed(db, device, WIRESHARK_BUILD)).vuln_counts = broken
    await db.commit()

    with caplog.at_level(logging.WARNING):
        assert (await _read()).assessment == "unknown_app"
    assert [record.state for record in caplog.records if hasattr(record, "state")] == ["answer_unreadable"]

    await refresh_tenant(db, force=True)
    await db.commit()

    assert (await _read()).counts.total == 17


# --- the gate: the tenant, and `off` byte for byte --------------------------------------


async def test_a_tenant_whose_tier_is_off_stores_no_answer_and_reads_byte_identical_off(db, fleet) -> None:
    """#281's Option A, at judge time as well as at read time (docs/vulnerabilities.md §8).

    The container holds the epoch; this tenant has not consented. Nothing corpus-derived is
    written onto its rows, the library's rows are untouched, and the block it reads is byte
    for byte the one a container with no library at all emits.
    """
    _, device = fleet
    await _judge(db, device)
    before = (await _block(db, device, WIRESHARK_BUILD)).model_dump(by_alias=True)

    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _set_tier(db, "off")
    await _judge(db, device)

    assert (await _entry(db, WIRESHARK_BUILD)).vuln_assessment is None
    assert (await _entry(db, WIRESHARK_BUILD)).vuln_signature is None
    # The rows are KEPT: the artifact is the container's, and one tenant's consent does not
    # delete it.
    assert len((await db.execute(select(VulnLibraryRow))).scalars().all()) == 3
    after = (await _block(db, device, WIRESHARK_BUILD)).model_dump(by_alias=True)
    assert json.dumps(after, default=str) == json.dumps(before, default=str)
    assert after == {"assessment": "off"}


async def test_consenting_again_answers_from_the_epoch_already_held(db, fleet) -> None:
    """The other direction of §8, and the reason the tier is in the signature's company
    rather than in the stored answer: turning sharing back on makes every row stale, the
    next pass re-judges from the epoch this container already has, and nothing is
    downloaded."""
    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _set_tier(db, "off")
    await _judge(db, device)
    assert (await _block(db, device, WIRESHARK_BUILD)).assessment == "off"

    await _set_tier(db, "keys")
    await _judge(db, device)

    assert (await _entry(db, WIRESHARK_BUILD)).vuln_signature == SIGNATURE
    assert (await _block(db, device, WIRESHARK_BUILD)).assessment == "covered"


async def test_an_answer_judged_against_a_different_epoch_is_not_served_under_this_ones_date(db, fleet) -> None:
    """The freshness rule, stated as the failure it prevents.

    `corpusAsOf` names the epoch answering **now**. A stored answer whose signature names a
    different epoch is therefore not served under it — counts from one epoch under another's
    date is exactly the silent staleness the stamp exists to make visible. It reads
    `unknown_app` until the next pass rewrites it, which is the conservative direction and
    self-healing.
    """
    _, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)
    assert (await _block(db, device, WIRESHARK_BUILD)).assessment == "covered"

    # A new epoch arrives and nothing has re-judged yet — the window between an import and
    # the pass that follows it.
    smaller, signature = _rewritten(rows=[_row()])
    await load_epoch_if_new(db, _pointer(signature), transport=_serving(smaller))
    assert (await _installed(db, device, WIRESHARK_BUILD)).vuln_signature == SIGNATURE

    assert (await _block(db, device, WIRESHARK_BUILD)).assessment == "unknown_app"


async def test_the_title_metadata_is_never_a_verdict_input(db, fleet) -> None:
    """Ruling R-D as a property rather than as a case.

    An epoch that compiles four Jamf titles and assesses **no build at all** — every title
    row present, `rows.jsonl` empty. Nothing reads `covered`, including the two builds whose
    `key_title` the epoch carries. That is the whole withdrawn branch, asserted absent: a
    `key_title` is shared by many Jamf titles and a pod can hold builds the compiler never
    enumerated, so the metadata cannot decide anything, whatever it says.
    """
    _, device = fleet
    no_rows, signature = _rewritten(rows=[])
    assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(no_rows)) is not None
    await _judge(db, device)

    assert len((await db.execute(select(VulnLibraryTitle))).scalars().all()) == 4
    assert len((await db.execute(select(VulnLibraryRow))).scalars().all()) == 0
    for key_full in (WIRESHARK_BUILD, CLEAN_BUILD, STALE_UNASSESSED_BUILD, UNKNOWN_BUILD):
        assert (await _entry(db, key_full)).vuln_assessment is None
        assert (await _block(db, device, key_full)).assessment == "unknown_app"
    # The titles really do cover two of those builds' applications — so the assertion above
    # is about the rule and not about an empty table.
    compiled = {row.key_title for row in (await db.execute(select(VulnLibraryTitle))).scalars()}
    assert WIRESHARK_TITLE in compiled and STALE_TITLE in compiled and UNKNOWN_TITLE not in compiled


# --- the posture tape: what the stored answers become, once a night ----------------------


async def _snapshot(db, connection) -> dict[str, float]:
    """One posture capture against this fleet, as the recorder writes it.

    #250's four keys count the columns judged above — this is the one place in the suite
    where the join's output is read by something other than the wire, and the fixture epoch
    is what makes the numbers checkable rather than plausible.
    """
    from app.core.posture import record_full_sweep_snapshot
    from app.models.schema import PostureSnapshot, Run

    now = datetime.now(UTC)
    run = Run(
        id=uuidlib.uuid4(),
        mdm_connection_id=connection.id,
        trigger="sweep",
        comparison="delta",
        lock_class="device_sweep",
        status="succeeded",
        window_start=now,
        started_at=now,
        finished_at=now,
        heartbeat_at=now,
    )
    db.add(run)
    await db.commit()
    await record_full_sweep_snapshot(db, run_id=run.id)
    rows = (await db.execute(select(PostureSnapshot).where(PostureSnapshot.full_sweep_run_id == run.id))).scalars().all()
    captured = {row.metric_key: float(row.value) for row in rows}
    await db.execute(delete(PostureSnapshot).where(PostureSnapshot.full_sweep_run_id == run.id))
    await db.commit()
    return captured


async def test_the_posture_keys_count_the_fixture_epochs_answers(db, fleet) -> None:
    """#250, end to end: load the epoch, judge the builds, and the night's tape carries the
    four `vuln.*` keys with the epoch's own numbers.

    One Mac, four builds: Wireshark 4.2.0 has a row with 17 findings and no KEV listing, the
    clean fixture build has a row with none, and the other two have no row at all. So one
    affected build, no KEV, two unassessed, one affected device. The unassessed count is a
    floor rather than an equality — a lived-in local database carries other suites' builds,
    and every installed build nothing has answered for is legitimately `unknown_app` — so
    the exact arithmetic is pinned by the delta below, which a leftover row cannot move.
    """
    from app.core.posture import VULN_KEYS

    connection, device = fleet
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await _judge(db, device)

    captured = await _snapshot(db, connection)

    assert set(VULN_KEYS) <= set(captured), "a judged tenant records all four keys"
    assert captured["vuln.apps_affected"] == 1  # Wireshark 4.2.0; the clean build is covered and counts here nowhere
    assert captured["vuln.apps_kev_affected"] == 0  # assessed, and none of the 17 is KEV-listed: a real zero
    assert captured["vuln.devices_affected"] == 1
    assert captured["vuln.apps_unknown"] >= 2  # the rowless build of a compiled title, and the build in no object

    # A new build arrives that the epoch never assessed: exactly one more `unknown_app`, and
    # nothing moves in the other three.
    later = await _device(db, connection, "C02VULN0002", (("LoonVD Fixture Later.app", "io.loonsec.fixture.later", "9.9.9"),))
    await _judge(db, later)

    after = await _snapshot(db, connection)
    assert after["vuln.apps_unknown"] - captured["vuln.apps_unknown"] == 1
    assert after["vuln.apps_affected"] == captured["vuln.apps_affected"]
    assert after["vuln.apps_kev_affected"] == captured["vuln.apps_kev_affected"]
    assert after["vuln.devices_affected"] == captured["vuln.devices_affected"]


async def test_a_pod_that_was_never_assessed_writes_no_vuln_rows(db, fleet) -> None:
    """The rule, on the state every container starts in and most containers stay in: no
    library loaded, so nothing has judged this tenant and the four keys record **nothing**.

    Not zeros. A `vuln.apps_affected` of 0 from this pod would be a clean bill of health for
    a fleet nobody looked at — `assessment: off` (docs/vulnerabilities.md §4a) broken one
    layer down, in a tape nobody can re-date afterwards. `tests/test_posture_db.py` holds
    the same rule against the recorder's own fixtures; this one holds it against the real
    gate, with the fleet's apps present and genuinely unanswered.
    """
    from app.core.posture import ACTIVE_KEYS, VULN_KEYS

    connection, device = fleet
    await _judge(db, device)
    assert (await _block(db, device, WIRESHARK_BUILD)).assessment == "off"

    captured = await _snapshot(db, connection)

    assert not set(VULN_KEYS) & set(captured)
    assert set(captured) <= set(ACTIVE_KEYS) - set(VULN_KEYS)
    assert "devices.total" in captured, "the rest of the vocabulary is unaffected; only this family is gated"


# --- what an update would fix (#482) ----------------------------------------------------

# The build the patch answer points at, keyed the way the corpus keys it: this app's own
# name and bundle id with Jamf's latest version in the version slot, fourth slot None.
# Hashed here rather than written as a literal, for the reason `_device` gives — two
# implementations of one key do not fail loudly when they drift.
WIRESHARK_TARGET = app_full_key("Wireshark.app", "org.wireshark.Wireshark", "4.6.8", None)
# An id no other fixture uses, and deleted by the `fleet` teardown: `jamf_patch_titles` is
# global, so a title left behind is another suite's extra match.
TARGET_TITLE_ID = "LOON482"
# The lab's own numbers (#428): 4.2.0 is 17 findings and 4.6.0 is 94, so *update to latest*
# is not a synonym for *clean*, and the ids overlap only in part.
HERE = [f"CVE-2026-1{index:03d}" for index in range(17)]
THERE = [f"CVE-2026-2{index:03d}" for index in range(90)] + HERE[:4]


async def _with_titles(db) -> None:
    """A Jamf patch title for Wireshark whose latest release is 4.6.8, so the catalog row
    carries a real `latest_version` and forms a real target key. Merged rather than
    inserted, under an id no other fixture uses: `jamf_patch_titles` is global and another
    suite in this database may already hold the real catalog."""
    from app.mdm.patch.matching import reset_catalog_cache

    bundle_test = {"name": "Application Bundle ID", "operator": "is", "type": "recon", "value": "org.wireshark.Wireshark"}
    await db.merge(
        JamfPatchTitle(
            id=TARGET_TITLE_ID,
            name="Wireshark",
            current_version="4.6.8",
            last_modified="2026-08-13T09:34:31Z",
            patches=[
                {"version": "4.6.8", "releaseDate": "2026-08-12T19:18:22Z"},
                {"version": "4.2.0", "releaseDate": "2024-01-03T18:00:00Z"},
            ],
            requirements=[{"operator": "and", "tests": [bundle_test]}],
            extension_attributes=[],
        )
    )
    await db.commit()
    reset_catalog_cache()


def _dated(counts: dict) -> dict:
    """A publication stamp in every band the counts say has a finding and null in the rest
    — the epoch format refuses a row where the two disagree."""
    return {band: "2026-01-01T00:00:00Z" if counts[band] else None for band in ("total", "critical", "high", "medium", "low")}


async def _epoch_with_target(db, target: dict | None, *, extra: list[dict] | None = None) -> str:
    """An epoch holding Wireshark 4.2.0's 17 findings and, optionally, a row for the
    release Jamf calls latest. Returns the signature it was loaded under.

    `extra` is any further row, and exists to move the signature: an epoch is identified by
    its content, so "the same corpus, a pass later" needs something in it to differ."""
    counts = {"total": 17, "kev": 0, "critical": 0, "high": 9, "medium": 8, "low": 0}
    rows = [_row(key_full=WIRESHARK_BUILD, ids=HERE, counts=counts, oldest_published=_dated(counts))]
    if target is not None:
        rows.append(_row(key_full=WIRESHARK_TARGET, oldest_published=_dated(target["counts"]), **target))
    rows.extend(extra or [])
    bundle, signature = _rewritten(rows=rows)
    assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle)) is not None
    return signature


async def _update(db, device, key_full: str):
    """One installed row's update line as a page receives it — the stored columns through
    the read seam, never derived here."""
    from app.core.vuln_answer import stored_corpus
    from app.core.vuln_read import update_line

    rows = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device.id))).scalars().all()
    corpus = stored_corpus(loaded_corpus(), rows)
    return update_line(next(row for row in rows if row.key_full == key_full), corpus=corpus)


async def test_a_covered_target_is_judged_beside_the_build_and_reads_as_a_difference(db, fleet) -> None:
    """The whole point: the release Jamf names has its own row, its own answer, and the
    difference between the two is what a person reads.

    Both halves are asserted, and the second is why the issue exists: 4.6.8 carries 94
    findings against 4.2.0's 17, so "closes 17" alone would be the half of the sentence
    that sells an upgrade. The key is the build's own identity with the patch answer's
    version in it, which is why `vuln_target_key` is asserted against `content_keys` rather
    than against what the judge happened to write.
    """
    _, device = fleet
    await _with_titles(db)
    signature = await _epoch_with_target(
        db, {"ids": THERE, "counts": {"total": 94, "kev": 0, "critical": 1, "high": 26, "medium": 66, "low": 1}}
    )
    await _judge(db, device)

    entry = await _entry(db, WIRESHARK_BUILD)
    assert entry.latest_version == "4.6.8" and entry.vuln_target_key == WIRESHARK_TARGET
    assert entry.vuln_target_version == "4.6.8" and entry.vuln_target_assessment == "covered"
    assert entry.vuln_target_counts["total"] == 94 and entry.vuln_signature == signature

    # The copy, which is what a device page actually reads.
    app = await _installed(db, device, WIRESHARK_BUILD)
    assert (app.vuln_target_version, app.vuln_target_assessment) == ("4.6.8", "covered")
    assert app.vuln_target_ids == entry.vuln_target_ids

    line = await _update(db, device, WIRESHARK_BUILD)
    assert line is not None and line.version == "4.6.8" and line.assessment == "covered"
    # Exact, because neither stored row is truncated: 13 of the 17 are gone and 90 are new.
    assert (line.closes, line.opens, line.net) == (13, 90, None)


async def test_a_target_the_epoch_holds_no_row_for_reads_unknown_and_never_closes_them_all(db, fleet) -> None:
    """Ruling R-D, one release out. The epoch assessed 4.2.0 and never assessed 4.6.8, so
    the target is `unknown_app` — outside the corpus, dated — and carries no numbers at all.

    The wrong answer this prevents is the plausible one: with no row for the target, the
    arithmetic "17 minus nothing" says the update closes all seventeen, which is a clean
    bill for a build nobody assessed wearing a difference's clothes.
    """
    _, device = fleet
    await _with_titles(db)
    await _epoch_with_target(db, None)
    await _judge(db, device)

    entry = await _entry(db, WIRESHARK_BUILD)
    assert entry.vuln_assessment == "covered" and entry.vuln_target_key == WIRESHARK_TARGET
    # Judged, and the answer is that there is no row — which is a different fact from
    # "not judged for a target yet", and that is what the version column is for.
    assert entry.vuln_target_version == "4.6.8" and entry.vuln_target_assessment is None
    assert entry.vuln_target_counts is None and entry.vuln_target_ids is None

    line = await _update(db, device, WIRESHARK_BUILD)
    assert line is not None and line.assessment == "unknown_app" and line.version == "4.6.8"
    assert (line.closes, line.opens, line.net) == (None, None, None)


async def test_a_truncated_list_on_either_side_reads_as_a_net_difference_of_the_stored_totals(db, fleet) -> None:
    """Kyle's R9 default, ruled on #482: exact only when NEITHER row is truncated.

    The target's published list is capped, so the ids cannot answer — a set difference over
    a capped list under-reports, which is the trap §4f names. The line falls back to the
    difference of the uncapped `counts.total`, and it is `net` rather than `closes` so no
    surface can print it as an exact count. Negative here: the newer build carries more.
    """
    _, device = fleet
    await _with_titles(db)
    await _epoch_with_target(
        db,
        {
            "ids": THERE[:50],
            "truncated": True,
            "counts": {"total": 94, "kev": 0, "critical": 1, "high": 26, "medium": 66, "low": 1},
        },
    )
    await _judge(db, device)

    entry = await _entry(db, WIRESHARK_BUILD)
    assert entry.vuln_ids_truncated is False and entry.vuln_target_ids_truncated is True

    line = await _update(db, device, WIRESHARK_BUILD)
    assert line is not None and line.net == 17 - 94
    assert (line.closes, line.opens) == (None, None)


async def test_a_row_with_no_target_key_says_nothing_rather_than_not_in_the_corpus(db, fleet) -> None:
    """The migration window, which is every row of every tenant until the next catalog sync.

    `b3e7d1a9c5f0` adds `vuln_target_key` nullable with no backfill and only `_apply_summary`
    writes it — on the JAMF clock. The corpus moves on its own, and when it moves first
    `refresh_tenant` re-matches nothing (`evaluated_signature` is current) and goes straight
    to `judge_vuln(db, None, …)` over every epoch-stale row: NULL key, non-NULL
    `latest_version`. Writing the version there stored version-present / assessment-NULL,
    which `update_effect` reads as ruling R-D and the cell prints, in the warning colour, as
    *updating to 4.6.8: not in the corpus of …* — about a release nothing ever asked the
    corpus about, and about one the corpus in fact holds. The copy fans that out to every
    device carrying the build.

    So: judge normally, put the row back where the migration leaves it, then move the CORPUS
    clock and let the hourly pass run — the real sequence, not a hand-written state. The
    moved epoch still holds 4.6.8, which is the sharp part: the release is in the corpus and
    the row must still say nothing about it, because nothing looked it up. *No lookup* is not
    *no row*, and it is the version column, not the assessment, that carries the difference.
    """
    _, device = fleet
    await _with_titles(db)
    target = {"ids": THERE, "counts": {"total": 94, "kev": 0, "critical": 1, "high": 26, "medium": 66, "low": 1}}
    await _epoch_with_target(db, target)
    await _judge(db, device)
    assert (await _entry(db, WIRESHARK_BUILD)).vuln_target_assessment == "covered", "sanity: the epoch holds 4.6.8"

    from app.catalog.service import refresh_tenant

    # The migration's own state: the column exists and nothing backfilled it. Only
    # `_apply_summary` writes the key, and only a catalog sync runs it.
    await db.execute(update(AppCatalogEntry).where(AppCatalogEntry.key_full == WIRESHARK_BUILD).values(vuln_target_key=None))
    await db.commit()

    # And now the corpus moves first, which is the whole hazard: `refresh_tenant` re-matches
    # nothing (the Jamf catalog has not moved, so `evaluated_signature` is current and the
    # key stays NULL) and goes straight to `judge_vuln(db, None, …)` over every epoch-stale
    # row. One unrelated row carries the new signature; both Wireshark rows are unchanged.
    await _epoch_with_target(db, target, extra=[_row(key_full=STALE_UNASSESSED_BUILD)])
    await refresh_tenant(db, now=NOW)
    await db.commit()

    # Columns, not the ORM instance: `judge_vuln` and the copy both run
    # `synchronize_session=False`, so the identity map still holds the pre-window values and
    # an assertion that reads objects would pass while the database said otherwise.
    stored = (
        await db.execute(
            select(
                AppCatalogEntry.vuln_assessment, AppCatalogEntry.vuln_target_version, AppCatalogEntry.vuln_target_assessment
            ).where(AppCatalogEntry.key_full == WIRESHARK_BUILD)
        )
    ).one()
    assert stored.vuln_assessment == "covered", "the build's own answer is untouched by the target's absence"
    assert (stored.vuln_target_version, stored.vuln_target_assessment) == (None, None)

    copied = (
        await db.execute(
            select(InstalledApp.vuln_target_version, InstalledApp.vuln_target_assessment).where(
                InstalledApp.device_id == device.id, InstalledApp.key_full == WIRESHARK_BUILD
            )
        )
    ).one()
    assert (copied.vuln_target_version, copied.vuln_target_assessment) == (None, None)

    assert await _update(db, device, WIRESHARK_BUILD) is None, "nothing looked up, so the cell prints no line at all"


# --- the stored answer as a filter (#529) ------------------------------------------------

# A second epoch, published so ONE import can answer every filter this endpoint has. The
# shipped fixture epoch cannot: its Wireshark row is the only one carrying findings, is not
# KEV-listed and has no critical band, so `kev`, `band=` and the two orders would each be an
# assertion about a single row. Here the KEV row carries FEWER findings and a NEWER oldest
# publication than the plain one, so `exposure` and `age` cannot both be right by accident.
_KEV_COUNTS = {"total": 2, "kev": 1, "critical": 1, "high": 1, "medium": 0, "low": 0}
_PLAIN_COUNTS = {"total": 5, "kev": 0, "critical": 0, "high": 5, "medium": 0, "low": 0}
_NO_COUNTS = {"total": 0, "kev": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
NEWER, OLDER = "2026-06-01T00:00:00Z", "2020-03-04T00:00:00Z"
OURS = (WIRESHARK_BUILD, CLEAN_BUILD, STALE_UNASSESSED_BUILD, UNKNOWN_BUILD)


def _dates(total: str | None, critical: str | None = None, high: str | None = None) -> dict:
    """The format refuses a band whose date and count disagree about whether a finding
    exists, so every band with a count above carries one here."""
    return {"total": total, "critical": critical, "high": high, "medium": None, "low": None}


async def _filtering(db, device) -> str:
    """This fleet judged against that epoch, and the signature that is then answering."""
    bundle, signature = _rewritten(
        rows=[
            _row(
                key_full=WIRESHARK_BUILD,
                ids=["CVE-2026-0001", "CVE-2026-0002"],
                counts=_KEV_COUNTS,
                oldest_published=_dates(NEWER, critical=NEWER, high=NEWER),
            ),
            _row(
                key_full=STALE_UNASSESSED_BUILD,
                ids=[f"CVE-2020-000{index}" for index in range(5)],
                counts=_PLAIN_COUNTS,
                oldest_published=_dates(OLDER, high=OLDER),
            ),
            _row(key_full=CLEAN_BUILD, ids=[], counts=_NO_COUNTS, oldest_published=_dates(None)),
        ]
    )
    assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle)) is not None
    await _judge(db, device)
    return signature


async def _list(db, **overrides):
    """`GET /api/catalog` through its route function — the catalog suite's own helper, so the
    defaults a direct call has to supply live in one place."""
    return await _list_catalog(db, page_size=500, **overrides)


def _ours(response) -> list[str]:
    """The fixture's own builds, in the order the endpoint returned them. Membership rather
    than the whole page, because a lived-in local database carries other suites' builds and
    none of them is what these assertions are about."""
    return [item.key_full for item in response.items if item.key_full in OURS]


async def test_each_vuln_filter_selects_the_state_it_names(db, fleet) -> None:
    """The four filters over one judged tenant, each against the state §4a names.

    `clean` is the one that could not exist without ruling R-D: the clean fixture build has a
    ROW with no findings, and the build with no row is `unknown_app` in the same breath.
    """
    _, device = fleet
    await _filtering(db, device)

    assert set(_ours(await _list(db, vuln="findings"))) == {WIRESHARK_BUILD, STALE_UNASSESSED_BUILD}
    assert _ours(await _list(db, vuln="kev")) == [WIRESHARK_BUILD]
    assert _ours(await _list(db, vuln="clean")) == [CLEAN_BUILD]
    assert _ours(await _list(db, vuln="unknown_app")) == [UNKNOWN_BUILD]
    # A band narrows within `covered`, and is not a fifth state: the critical band belongs to
    # the KEV row alone, and the five-finding row is entirely high.
    assert _ours(await _list(db, vuln="findings", band="critical")) == [WIRESHARK_BUILD]
    assert set(_ours(await _list(db, vuln="findings", band="high"))) == {WIRESHARK_BUILD, STALE_UNASSESSED_BUILD}


async def test_a_row_judged_by_an_epoch_that_moved_filters_as_unknown_app(db, fleet) -> None:
    """SERVED, not stored — the rule `served()` is, held where a filter could quietly ignore
    it. The row still carries `covered` and two findings; its signature is no longer the one
    answering, so it is `unknown_app` to the filter exactly as it is to the cell, and it is
    absent from `findings` rather than counted there."""
    _, device = fleet
    await _filtering(db, device)
    await db.execute(
        update(AppCatalogEntry).where(AppCatalogEntry.key_full == WIRESHARK_BUILD).values(vuln_signature="not-this-epoch")
    )
    await db.commit()

    assert (await _entry(db, WIRESHARK_BUILD)).vuln_assessment == "covered"
    assert _ours(await _list(db, vuln="findings")) == [STALE_UNASSESSED_BUILD]
    assert set(_ours(await _list(db, vuln="unknown_app"))) == {WIRESHARK_BUILD, UNKNOWN_BUILD}


async def test_a_stored_answer_that_will_not_parse_filters_as_unknown_app(db, fleet) -> None:
    """The row `_unreadable` exists for, in a `WHERE`. It is served and `covered`, and its
    counts are not a number — so there is nothing to be right about, and it lists where the
    cell already puts it rather than being counted among the findings or among the clean.

    The same row also proves why `((vuln_counts->>'total')::int)` is not in the index the
    filter reads: an index over that expression refuses this write outright, which would turn
    a named `unknown_app` into a 500 (see the migration `a7c21e9f4b83`).
    """
    _, device = fleet
    await _filtering(db, device)
    await db.execute(
        update(AppCatalogEntry).where(AppCatalogEntry.key_full == WIRESHARK_BUILD).values(vuln_counts={"total": "two"})
    )
    await db.commit()

    assert _ours(await _list(db, vuln="findings")) == [STALE_UNASSESSED_BUILD]
    assert _ours(await _list(db, vuln="clean")) == [CLEAN_BUILD]
    assert set(_ours(await _list(db, vuln="unknown_app"))) == {WIRESHARK_BUILD, UNKNOWN_BUILD}


async def test_the_two_orders_rank_by_the_two_axes_a_mac_fleet_has(db, fleet) -> None:
    """`exposure` is KEV first; `age` is the oldest publication first. The two rows disagree
    on purpose — the KEV row has fewer findings and a newer oldest publication — so an
    ordering that fell back to either would put them the other way round."""
    _, device = fleet
    await _filtering(db, device)

    assert _ours(await _list(db, vuln="findings", order="exposure")) == [WIRESHARK_BUILD, STALE_UNASSESSED_BUILD]
    assert _ours(await _list(db, vuln="findings", order="age")) == [STALE_UNASSESSED_BUILD, WIRESHARK_BUILD]
    # `vuln=all` keeps the Catalog tab's own order, whatever `order` says.
    by_devices = await _list(db, order="age")
    assert [item.device_count for item in by_devices.items] == sorted(
        (item.device_count for item in by_devices.items), reverse=True
    )


async def test_vuln_judged_says_whether_the_loaded_epoch_has_judged_anything_here(db, fleet) -> None:
    """The hour after an epoch moves, before the join runs. The epoch is loaded and answering
    — `corpusAsOf` is a date — and not one row has been judged against it, so every row reads
    `unknown_app` and a list of them is honest only as *not yet judged*, never as *0 with
    findings* (§4a)."""
    _, device = fleet
    bundle, signature = _rewritten(rows=[_row(key_full=WIRESHARK_BUILD)])
    assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle)) is not None

    before = await _list(db)
    assert before.corpus_as_of is not None and before.vuln_judged is False

    await _judge(db, device)
    after = await _list(db)
    assert after.vuln_judged is True


async def test_a_vuln_filter_is_refused_where_nothing_answers(db, fleet) -> None:
    """Refused, never empty. An empty list under `vuln=findings` reads as *nothing found*,
    which is §4a's failure in a query string — so the filter is a `409` naming both of §8's
    causes, and the unfiltered list still answers."""
    from fastapi import HTTPException

    from app.api.catalog import NO_ANSWER

    _, device = fleet
    await _filtering(db, device)
    await _set_tier(db, "off")

    for filtered in ({"vuln": "findings"}, {"vuln": "kev"}, {"band": "critical"}):
        with pytest.raises(HTTPException) as refusal:
            await _list(db, **filtered)
        assert refusal.value.status_code == 409
        assert refusal.value.detail == NO_ANSWER
    assert "data sharing is off for this organization" in NO_ANSWER and "§8" in NO_ANSWER
    # And the catalog itself is not refused: `off` is a state the page renders, not an error.
    unfiltered = await _list(db)
    assert unfiltered.corpus_as_of is None and unfiltered.vuln_judged is False
    assert {item.vuln.assessment for item in unfiltered.items} == {"off"}


async def test_the_status_endpoint_answers_the_same_date_the_rows_are_stamped_with(db, fleet) -> None:
    """What the sidebar reads (#529). One fact, the same one `corpusAsOf` on the list is, so
    an entry can never be listed by a corpus the rows are not answering from."""
    from app.api.vulnerabilities import vulnerability_status

    _, device = fleet
    assert (await vulnerability_status(db)).corpus_as_of is None

    await _filtering(db, device)
    assert (await vulnerability_status(db)).corpus_as_of == (await _list(db)).corpus_as_of

    # A tenant whose sharing is off reads `null`, with the very same epoch loaded — which is
    # why a failed or `null` read may never be reported as "the corpus is off" anywhere.
    await _set_tier(db, "off")
    assert (await vulnerability_status(db)).corpus_as_of is None
