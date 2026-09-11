"""The corpus epoch against a real Postgres: stored whole, replaced whole, refused whole
(#248). Gated on RUN_DB_TESTS like the other database-backed suites.

`test_vuln_library.py` proves the verification without a database. What needs one is
everything the ruling actually promises about the *library*: that an epoch replaces its
predecessor atomically, that a refused epoch leaves the predecessor answering, that an
unmoved signature downloads nothing, and that the exchange — the whole path, from a
response body to `loaded_corpus()` — is what puts an answer behind the seam.

It also pins the **gate**: a loaded library answers for a tenant whose data-sharing tier
earns it and for no other (docs/vulnerabilities.md §8, ruled 2026-09-11), the rows survive
a tenant turning sharing off, nothing is answered outside a tenant context at all, the
tier the gate reads is the *acting* tenant's even when the session's row-level-security
scope names a different one, and the tier costs one query per unit of work rather than one
per app.

**Every test here restores the process to "no library loaded" afterwards.** The corpus and
the per-tenant tier are both process-level facts by design (`app.core.vuln.install_corpus`,
`install_tenant_tier`), and the suite that pins `assessment: off` byte-for-byte runs in the
same process.
"""

from __future__ import annotations

import contextvars
import gzip
import json
import os
import uuid as uuidlib
from contextlib import contextmanager
from datetime import UTC, date, datetime

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.tenancy import OPERATIONAL_TENANT_ID, get_tenant_id, reset_tenant_id, set_tenant_id
from app.core.vuln import NO_CORPUS, TIER_OFF, forget_tenant_tiers, loaded_corpus, vuln_block
from app.core.vuln_library import (
    ROWS_NAME,
    CorpusPointer,
    earned_corpus,
    load_epoch_if_new,
    read_tenant_tier,
    refresh_from_db,
    stored_signature,
)
from app.models.schema import DataSharingSettings, Tenant, VulnLibraryEpoch, VulnLibraryRow, VulnLibraryTitle
from tests.test_vuln_library import (
    BUNDLE,
    CORPUS_URL,
    SIGNATURE,
    WIRESHARK_BUILD,
    WIRESHARK_TITLE,
    _bundle,
    _members,
    _rewritten,
    _row,
)

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

TODAY = date(2026, 9, 10)


def _pointer(signature: str = SIGNATURE, *, url: str = CORPUS_URL) -> CorpusPointer:
    return CorpusPointer(signature=signature, asof=datetime(2026, 9, 10, 20, 0, tzinfo=UTC), url=url)


async def _count(db, model) -> int:
    return len((await db.execute(select(model))).scalars().all())


def _serving(payload: bytes, seen: list[str] | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        return httpx.Response(200, content=payload)

    return httpx.MockTransport(handler)


def _never_dials(request: httpx.Request) -> httpx.Response:  # pragma: no cover - the assertion is that it is not called
    raise AssertionError(f"an unmoved signature must not download anything, and dialled {request.url}")


async def _clear(db) -> None:
    await db.rollback()
    await db.execute(delete(VulnLibraryRow))
    await db.execute(delete(VulnLibraryTitle))
    await db.execute(delete(VulnLibraryEpoch))
    await db.commit()
    await refresh_from_db(db)


async def _set_tier(db, tier: str) -> None:
    """This tenant's data-sharing tier, written and told to the gate — the shape the API
    and the exchange both use (`app.core.sharing.remember_tier`)."""
    from app.core.sharing import get_or_create_settings, remember_tier

    row = await get_or_create_settings(db)
    row.tier = tier
    await db.commit()
    remember_tier(row)


@pytest_asyncio.fixture(loop_scope="session")
async def acting_tenant(db):
    """The tenancy contextvar the request middleware and the scheduler's `tenant_job` bind
    on every path that reaches `loaded_corpus()`.

    The `db` fixture binds the tenant on the *session* (the Postgres GUC that RLS reads)
    and not in context, because no route does that by hand. The corpus gate reads the
    acting tenant from context — there is nobody to have consented outside one — so a suite
    that exercises it has to stand where a request stands.
    """
    token = set_tenant_id(OPERATIONAL_TENANT_ID)
    try:
        yield OPERATIONAL_TENANT_ID
    finally:
        reset_tenant_id(token)


# A second tenant of this suite's own, for the one question a single tenant cannot ask:
# whose consent row did the gate read. Fixed id in the style of test_tenancy_sweep's.
FOREIGN_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000d1")


@pytest_asyncio.fixture(loop_scope="session")
async def foreign_tenant(db):
    """A second tenant that shares, and a session scoped to it.

    Yields the *session*, not the id: what the test needs is a database session whose
    row-level-security scope is somebody else's while the tenancy contextvar stays ours.
    Its consent row is `reveal` — deliberately not `off`, so reading the wrong row is a
    visible wrong answer rather than an accidentally right one.
    """
    from app.core.database import session_for_tenant, unscoped_session

    async with unscoped_session() as unscoped:
        if (await unscoped.execute(select(Tenant).where(Tenant.id == FOREIGN_TENANT_ID))).scalars().first() is None:
            slug = "vuln-library-foreign"
            unscoped.add(Tenant(id=FOREIGN_TENANT_ID, slug=slug, name=slug, kind="operational"))
            await unscoped.commit()

    async with session_for_tenant(FOREIGN_TENANT_ID) as session:
        await session.execute(delete(DataSharingSettings))
        session.add(DataSharingSettings(tier="reveal"))
        await session.commit()
        try:
            yield session
        finally:
            await session.rollback()
            await session.execute(delete(DataSharingSettings))
            await session.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def empty(db, acting_tenant):
    """No library and a consenting tenant, before and after — the state every other suite
    in this process assumes, plus the consent the gate now requires."""
    await _clear(db)
    await _set_tier(db, "keys")
    yield
    await _clear(db)
    await _set_tier(db, "off")
    forget_tenant_tiers()
    assert loaded_corpus() is NO_CORPUS


async def test_an_epoch_is_downloaded_verified_and_answers_from_stored_rows(db, empty) -> None:
    """The whole point, in one path: a pointer whose signature this container has not
    seen, a bundle over the exchange's transport, three rows and three titles stored, and
    `loaded_corpus()` answering `covered` for a build it now has a row for — where the
    same call answered `off` a moment earlier."""
    assert loaded_corpus() is NO_CORPUS
    library = await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))

    assert library is not None
    assert library.epoch_id == "0001"
    assert await stored_signature(db) == SIGNATURE
    assert await _count(db, VulnLibraryRow) == 3
    assert await _count(db, VulnLibraryTitle) == 4

    corpus = loaded_corpus()
    assert corpus is not NO_CORPUS
    assert corpus.as_of == TODAY
    block = vuln_block(corpus, key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY)
    assert block.assessment == "covered"
    assert block.counts.total == 17
    assert block.counts.severity.high == 9
    assert block.days_oldest_published.severity.medium == (TODAY - date(2024, 5, 14)).days


async def test_the_stored_row_survives_a_restart_with_the_same_answer(db, empty) -> None:
    """`loaded_corpus()` is a process-level cache and the database is the truth. A
    container that restarts reads the epoch row and answers identically — which is the
    whole of the refresh rule beside the importer itself."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    before = vuln_block(loaded_corpus(), key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY)

    library = await refresh_from_db(db)  # what app startup does

    assert library is not None and library.signature == SIGNATURE
    after = vuln_block(loaded_corpus(), key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY)
    assert json.dumps(after.model_dump(by_alias=True), default=str) == json.dumps(before.model_dump(by_alias=True), default=str)


async def test_an_unmoved_signature_downloads_nothing(db, empty) -> None:
    """The reason a daily conversation is affordable. Equality on the signature is the
    only operation, and a second exchange on the same epoch costs one SELECT."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    assert await load_epoch_if_new(db, _pointer(), transport=httpx.MockTransport(_never_dials)) is None
    assert await stored_signature(db) == SIGNATURE


async def test_a_refused_epoch_leaves_the_previous_one_answering(db, empty, caplog) -> None:
    """Stale and correct beats fresh and wrong. A second epoch whose object does not match
    its manifest is refused whole: no row is touched, the epoch row still names the epoch
    that verified, the seam still answers from it — and the container says so in a line
    that names the state and the next step."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    good = vuln_block(loaded_corpus(), key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY)

    tampered, signature = _rewritten(rows=[_row()])

    with caplog.at_level("WARNING"):
        assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(_corrupt_rows(tampered))) is None

    assert "vulnerability library not updated" in caplog.text
    assert "still answers from the epoch it had" in caplog.text
    assert await stored_signature(db) == SIGNATURE
    assert await _count(db, VulnLibraryRow) == 3
    after = vuln_block(loaded_corpus(), key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY)
    assert after.model_dump() == good.model_dump()


def _corrupt_rows(bundle: bytes) -> bytes:
    """A bundle whose rows object no longer matches the digest its manifest states — the
    truncated-download shape, built without touching the committed fixture."""
    members = _members(bundle)
    members[ROWS_NAME] = gzip.compress(members[ROWS_NAME] + b"\n", mtime=0)
    return _bundle(members)


async def test_a_new_epoch_replaces_the_previous_one_whole(db, empty) -> None:
    """An epoch is not merged into the library, it replaces it: the rows of the epoch that
    left are gone, not shadowed. A build the old epoch answered for and the new one does
    not must go back to `unknown_app` rather than keep an answer nobody is standing
    behind."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    assert loaded_corpus().findings(key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD) is not None

    smaller, signature = _rewritten(rows=[_row()])
    library = await load_epoch_if_new(db, _pointer(signature), transport=_serving(smaller))

    assert library is not None and len(library.rows) == 1
    assert await _count(db, VulnLibraryRow) == 1
    assert await stored_signature(db) == signature
    block = vuln_block(loaded_corpus(), key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY)
    assert block.assessment == "unknown_app"
    assert block.counts is None


async def test_the_exchange_is_what_loads_it_end_to_end(db, empty, monkeypatch) -> None:
    """The seam the ruling names: the daily exchange's response points at the corpus, and
    the container loads it in the same conversation. One transport serves both halves,
    which is exactly what a signed link on the exchange looks like from in here."""
    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import get_or_create_settings, run_exchange
    from app.models.schema import ShareLog

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)
    row = await get_or_create_settings(db)
    row.tier = "keys"
    await db.commit()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, content=BUNDLE)
        return httpx.Response(
            200,
            json={
                "contract": "v1",
                "corpus": {"signature": SIGNATURE, "asof": "2026-09-10T20:00:00Z", "url": CORPUS_URL},
            },
        )

    try:
        await run_exchange(db, transport=httpx.MockTransport(handler))
        assert await stored_signature(db) == SIGNATURE
        assert loaded_corpus().as_of == TODAY
        # The share log still records the day exactly as it did before the corpus channel
        # existed — and the signed link is nowhere in it.
        log = (await db.execute(select(ShareLog).where(ShareLog.tier != "ai"))).scalars().all()[-1]
        assert log.outcome == "sent"
        assert "corpus" not in json.dumps(log.payload)
    finally:
        row.tier = "off"
        await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
        await db.commit()


async def test_a_response_with_no_corpus_changes_nothing(db, empty, monkeypatch) -> None:
    """A V0 collector answers `{}` and stays a valid peer: no pointer, no download, no
    library, and every app still reads `off`."""
    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import get_or_create_settings, run_exchange
    from app.models.schema import ShareLog

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)
    row = await get_or_create_settings(db)
    row.tier = "keys"
    await db.commit()

    try:
        await run_exchange(db, transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"contract": "v1"})))
        assert await stored_signature(db) is None
        assert loaded_corpus() is NO_CORPUS
    finally:
        row.tier = "off"
        await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
        await db.commit()


# --- the gate: which tenant the loaded library answers for ------------------------------


async def test_a_tenant_whose_sharing_is_off_reads_off_while_the_pod_holds_an_epoch(db, empty) -> None:
    """#281's Option A, on a pod with more than one tenant (docs/vulnerabilities.md §8).

    The library is one **global** artifact — three non-tenant tables and one process cache
    — and the tier is a **per tenant** column, so the shape alone gates nothing: one
    consenting tenant's import would otherwise answer `covered` for a tenant that never
    exchanged, never consented and was never handed a link. Option A's own words are "a pod
    that has not earned the summary"; the unit that earns it is the tenant.
    """
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    assert vuln_block(loaded_corpus(), key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY).assessment == "covered"

    await _set_tier(db, "off")

    assert await earned_corpus(db) is NO_CORPUS
    block = vuln_block(loaded_corpus(), key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY)
    assert block.assessment == "off"
    assert block.corpus_as_of is None
    assert block.counts is None


async def test_the_rows_are_kept_when_a_tenant_turns_sharing_off_and_answer_again_when_it_returns(db, empty) -> None:
    """Kept, deliberately. Purging on tier-off would delete a global artifact every other
    tenant on the pod is entitled to, so one tenant's switch changes one tenant's answer and
    nothing else — and turning sharing back on answers again with no download at all."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))

    await _set_tier(db, "off")
    assert await earned_corpus(db) is NO_CORPUS
    assert await _count(db, VulnLibraryRow) == 3, "one tenant's switch must not delete a global artifact"
    assert await stored_signature(db) == SIGNATURE

    await _set_tier(db, "keys")
    assert await earned_corpus(db) is not NO_CORPUS
    assert vuln_block(loaded_corpus(), key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=TODAY).assessment == "covered"
    # And nothing was downloaded to get the answer back.
    assert await load_epoch_if_new(db, _pointer(), transport=httpx.MockTransport(_never_dials)) is None


async def test_a_tenant_with_no_settings_row_at_all_reads_off(db, empty) -> None:
    """An install nobody has answered for has not consented — `get_or_create_settings`'
    own argument, one layer out. The read path deliberately does not create the row
    either: manufacturing a consent record as a side effect of rendering a page is the
    failure that default used to have."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    await db.execute(delete(DataSharingSettings))
    await db.commit()
    forget_tenant_tiers()

    assert await earned_corpus(db) is NO_CORPUS
    assert (await db.execute(select(DataSharingSettings))).scalar_one_or_none() is None, "a read must not write consent"


async def test_nothing_is_answered_outside_any_tenant_context(db, empty) -> None:
    """The branch of the gate that has no tenant at all (`app.core.vuln.loaded_corpus`).

    Outside a tenant there is nobody to have consented — a scheduler job that forgot to
    bind one, a startup path, a process doing work for the whole pod — so the answer is
    `NO_CORPUS` however loaded the library is. A fresh `contextvars.Context` is exactly
    that condition and nothing else: the var is unset in it, so it reads its default.
    """
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    assert loaded_corpus() is not NO_CORPUS, "a consenting tenant is answered"

    assert contextvars.Context().run(loaded_corpus) is NO_CORPUS


async def test_a_session_scoped_to_another_tenant_cannot_answer_for_this_one(db, empty, foreign_tenant) -> None:
    """Which tenant did the gate actually read — the session's, or the context's?

    `read_tenant_tier` keys its cache on the tenancy contextvar and, before this test,
    sourced the row from whatever the session's RLS scope could see. On every path the
    application has, the two move together (`app.main.tenant_job`,
    `app.core.database.get_db`, `app.core.auth.authenticate`) and nothing asserted it —
    so the question could not be asked with one tenant. Held apart on purpose here: the
    session is the other tenant's, at tier `reveal`; the contextvar is ours.

    A consent gate must answer for the tenant it is keying the answer under. Reading the
    session's row would install `reveal` under *our* id and hand this tenant a summary
    another tenant paid for — the one direction this gate is not fail-closed in.
    """
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    assert get_tenant_id() == OPERATIONAL_TENANT_ID
    assert (await foreign_tenant.execute(select(DataSharingSettings.tier))).scalar_one() == "reveal"

    tier = await read_tenant_tier(foreign_tenant)

    assert tier != "reveal", "the other tenant's consent must never answer for this one"
    assert tier == TIER_OFF, "a row this query cannot reach is a tenant that has not consented"
    assert loaded_corpus() is NO_CORPUS, "and the fail-closed answer is what the gate then gives"


async def test_the_tier_is_read_once_for_a_unit_of_work_and_never_per_app(db, empty) -> None:
    """ "Cache, don't calculate", asserted rather than argued. The gate is consulted once
    per device on a sweep and once per row on a page; if it cost a query, a 40,000-device
    run would pay 40,000 of them for a fact that is one row and does not change mid-run."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))

    with _counting() as statements:
        corpus = await earned_corpus(db)
        for _ in range(200):
            assert loaded_corpus() is corpus

    assert sum("data_sharing_settings" in statement for statement in statements) == 1


@contextmanager
def _counting():
    """Every statement the engine sends while the block runs."""
    from sqlalchemy import event

    from app.core.database import engine

    statements: list[str] = []

    def before(conn, cursor, statement, parameters, context, executemany) -> None:
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", before)
    try:
        yield statements
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", before)


# --- what the stored epoch is keyed by ---------------------------------------------------


async def test_the_titles_table_is_keyed_on_title_id_and_carries_the_repeated_key(db, empty) -> None:
    """Ruling R-D in the schema: `title_id` is the primary key and `key_title` is an index.
    The fixture's two Wireshark titles (`5F6`, `612`) share one `key_title`, so a table
    keyed the other way would have stored one of them and silently lost the other."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))

    rows = (await db.execute(select(VulnLibraryTitle).order_by(VulnLibraryTitle.title_id))).scalars().all()
    assert [row.title_id for row in rows] == ["5F6", "612", "A17", "LoonVDFixtureClean"]
    wireshark = [row for row in rows if row.key_title == WIRESHARK_TITLE]
    assert len(wireshark) == 2, "one key_title, two Jamf titles, two rows"
    assert {row.catalog_last_modified for row in wireshark} == {"2025-10-09T08:24:33Z", "2026-08-13T09:34:31Z"}


async def test_an_epoch_carrying_an_object_this_container_does_not_read_imports_and_names_it(db, empty, caplog) -> None:
    """The additive-only clause end to end: the epoch lands, its rows answer, and the
    import line counts and names what was passed over — so an operator can see that the
    corpus grew an object this container is too old to read."""
    bundle, signature = _rewritten(extra={"verdicts.jsonl.gz": gzip.compress(b'{"key_full":"v1:00"}\n', mtime=0)})

    with caplog.at_level("INFO"):
        library = await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle))

    assert library is not None and library.ignored == ("verdicts.jsonl.gz",)
    assert await _count(db, VulnLibraryRow) == 3
    assert "verdicts.jsonl.gz" in caplog.text
    assert "a newer container reads them" in caplog.text
