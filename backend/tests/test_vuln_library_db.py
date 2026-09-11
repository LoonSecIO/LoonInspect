"""The corpus epoch against a real Postgres: stored whole, replaced whole, refused whole
(#248). Gated on RUN_DB_TESTS like the other database-backed suites.

`test_vuln_library.py` proves the verification without a database. What needs one is
everything the ruling actually promises about the *library*: that an epoch replaces its
predecessor atomically, that a refused epoch leaves the predecessor answering, that an
unmoved signature downloads nothing, and that the exchange — the whole path, from a
response body to `loaded_corpus()` — is what puts an answer behind the seam.

**Every test here restores the process to "no library loaded" afterwards.** The corpus is
a process-level fact by design (`app.core.vuln.install_corpus`), and the suite that pins
`assessment: off` byte-for-byte runs in the same process.
"""

from __future__ import annotations

import gzip
import json
import os
from datetime import UTC, date, datetime

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.vuln import NO_CORPUS, loaded_corpus, vuln_block
from app.core.vuln_library import ROWS_NAME, CorpusPointer, load_epoch_if_new, refresh_from_db, stored_signature
from app.models.schema import VulnLibraryEpoch, VulnLibraryRow, VulnLibraryTitle
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


@pytest_asyncio.fixture(loop_scope="session")
async def empty(db):
    """No library, before and after — the state every other suite in this process
    assumes."""
    await _clear(db)
    yield
    await _clear(db)
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
    assert await _count(db, VulnLibraryTitle) == 3

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
