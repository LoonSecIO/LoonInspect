"""LoonSec's patch-policy document against a real Postgres: received, kept, refused, gated (#614).

`test_patch_policy_feed.py` proves the check without a database. What needs one is what the
ruling promises about the copy held: it downloads only when the signature moves, a refused
document leaves the previous copy answering, the last two copies are kept, every attempt leaves
one state row, `PATCH_POLICY_FEED_FILE` stands in for the exchange on an instance with no
network, and an organization whose sharing tier is `off` reads the tier sentence and no
document while the container holds one. Gated on RUN_DB_TESTS like the other database suites.

The tables are global, so every test starts and ends with them empty and the tier back where
it was.
"""

from __future__ import annotations

import copy
import gzip
import json
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update

from app.core import patch_policy_feed as feed
from app.core.config import settings
from app.core.tenancy import OPERATIONAL_TENANT_ID, reset_tenant_id, set_tenant_id
from app.models.schema import PatchPolicyDoc, PatchPolicyFeedState
from tests.test_patch_policy_feed import DOC, GZ, LINK, published_checks
from tests.test_patching_policy_db import accounts, viewer  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


def _another(as_of: str = "2026-11-24T20:00:00Z", **changes) -> tuple[dict, bytes]:
    """A second valid document: the fixture a day later, re-signed."""
    doc = copy.deepcopy(DOC)
    doc["as_of"] = as_of
    doc.update(changes)
    doc["doc_id"] = feed.canonical_doc_id(doc)
    return doc, gzip.compress(json.dumps(doc).encode(), mtime=0)


def _offer(signature: str, url: str = LINK) -> feed.Offer:
    return feed.read_offer({"patch_walk/1": {"signature": signature, "asof": "2026-11-23T20:00:00Z", "url": url}})


def _serving(payload: bytes, seen: list[str] | None = None, status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        return httpx.Response(status, content=payload if status == 200 else b"")

    return httpx.MockTransport(handler)


def _never_dials(request: httpx.Request) -> httpx.Response:  # pragma: no cover - the assertion is that it is not called
    raise AssertionError(f"an unmoved signature must not download anything, and dialled {request.url.host}")


async def _empty(db) -> None:
    await db.rollback()
    await db.execute(delete(PatchPolicyDoc))
    await db.execute(delete(PatchPolicyFeedState))
    await db.commit()
    feed._parsed.clear()
    feed._file_seen = None


async def _tier(db, tier: str) -> str:
    from app.core.sharing import get_or_create_settings

    row = await get_or_create_settings(db)
    before = row.tier
    row.tier = tier
    await db.commit()
    return before


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db, monkeypatch):
    """No copy held, no state row, no feed file, a consenting organization in context."""
    monkeypatch.setattr(settings, "patch_policy_feed_file", "")
    token = set_tenant_id(OPERATIONAL_TENANT_ID)
    await _empty(db)
    before = await _tier(db, "keys")
    try:
        yield
    finally:
        await _empty(db)
        await _tier(db, before)
        reset_tenant_id(token)


async def _held(db) -> list[tuple[str, bool]]:
    rows = (await db.execute(select(PatchPolicyDoc.doc_id, PatchPolicyDoc.current).order_by(PatchPolicyDoc.fetched_at))).all()
    return [(doc_id, current) for doc_id, current in rows]


async def _state(db) -> PatchPolicyFeedState:
    db.expire_all()
    return await db.get(PatchPolicyFeedState, 1)


# --- delivery by signature -------------------------------------------------------------------


async def test_a_moved_signature_downloads_checks_and_stores_and_an_unmoved_one_dials_nothing(db, clean) -> None:
    seen: list[str] = []
    assert await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ, seen)) == feed.STORED
    assert seen == [LINK]
    assert await _held(db) == [(DOC["doc_id"], True)]
    state = await _state(db)
    assert (state.source, state.outcome, state.host) == ("exchange", "stored", "patch-policy.example-bucket.s3.amazonaws.com")

    stored = (await db.execute(select(PatchPolicyDoc))).scalar_one()
    assert stored.body_gz == GZ and stored.schema == 1 and stored.algorithm == "patch_walk/1"
    assert stored.as_of == datetime(2026, 11, 23, 20, tzinfo=UTC)

    # The same signature tomorrow: nothing is downloaded, and the state row says so.
    assert await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=httpx.MockTransport(_never_dials)) == "unchanged"
    assert (await _state(db)).outcome == "unchanged"

    # A new signature: the new document is downloaded and answers; the old one is kept beside it.
    newer, newer_gz = _another()
    assert await feed.deliver_from_exchange(db, _offer(newer["doc_id"]), transport=_serving(newer_gz)) == "stored"
    assert await _held(db) == [(DOC["doc_id"], False), (newer["doc_id"], True)]


async def test_only_the_last_two_copies_are_kept(db, clean) -> None:
    ids = []
    for day in ("2026-11-24T20:00:00Z", "2026-11-25T20:00:00Z", "2026-11-26T20:00:00Z"):
        doc, data = _another(as_of=day)
        ids.append(doc["doc_id"])
        assert await feed.deliver_from_exchange(db, _offer(doc["doc_id"]), transport=_serving(data)) == "stored"
    assert await _held(db) == [(ids[1], False), (ids[2], True)]


async def test_a_signature_that_moves_back_restores_the_copy_already_held(db, clean) -> None:
    """A rollback at LoonSec names the previous document again. Equality is the only operation, so
    it is downloaded and checked like any other, and the row already held becomes current."""
    newer, newer_gz = _another()
    await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ))
    await feed.deliver_from_exchange(db, _offer(newer["doc_id"]), transport=_serving(newer_gz))
    assert await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ)) == "stored"
    assert sorted(await _held(db)) == sorted([(DOC["doc_id"], True), (newer["doc_id"], False)])


# --- a refusal keeps the previous copy ----------------------------------------------------------


async def test_a_refused_document_is_not_stored_and_the_previous_copy_keeps_answering(db, clean, caplog) -> None:
    await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ))
    broken = copy.deepcopy(DOC)
    broken["schema"] = 2
    broken["doc_id"] = feed.canonical_doc_id(broken)
    data = json.dumps(broken).encode()

    assert await feed.deliver_from_exchange(db, _offer(broken["doc_id"]), transport=_serving(data)) == "invalid"
    assert await _held(db) == [(DOC["doc_id"], True)]
    state = await _state(db)
    assert (state.outcome, state.detail) == ("invalid", "its schema is 2; this build reads schema 1")
    assert "patch-policy data not updated (invalid" in caplog.text and "the copy dated 2026-11-23 still answers" in caplog.text
    assert "X-Amz-Signature" not in caplog.text

    view = await feed.feed_view(db, now=datetime(2026, 11, 24, tzinfo=UTC))
    assert view.state == "invalid" and view.doc_id == DOC["doc_id"] and view.document is not None
    assert view.sentence == (
        "LoonSec's patch-policy data failed its check (its schema is 2; this build reads schema 1), so it was not "
        "stored. The copy dated 2026-11-23 is still used."
    )


async def test_a_document_whose_doc_id_is_not_the_signature_is_refused(db, clean) -> None:
    """The link served a document, a valid one even, but not the one the exchange named."""
    newer, newer_gz = _another()
    assert await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(newer_gz)) == "invalid"
    assert await _held(db) == []
    assert (await _state(db)).detail.startswith(
        f"it is not the document the exchange named: its doc_id is {newer['doc_id'][:12]}"
    )


async def test_a_download_the_store_refuses_names_the_host_and_status_and_keeps_the_copy(db, clean) -> None:
    await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ))
    newer, _ = _another()
    assert await feed.deliver_from_exchange(db, _offer(newer["doc_id"]), transport=_serving(b"", status=403)) == "download_failed"
    state = await _state(db)
    assert (state.outcome, state.http_status, state.host) == (
        "download_failed",
        403,
        "patch-policy.example-bucket.s3.amazonaws.com",
    )
    assert await _held(db) == [(DOC["doc_id"], True)]
    view = await feed.feed_view(db, now=datetime(2026, 11, 24, tzinfo=UTC))
    assert view.sentence == (
        "The patch-policy file could not be downloaded from patch-policy.example-bucket.s3.amazonaws.com: the "
        "patch-policy download did not complete (HTTP 403). Showing the copy dated 2026-11-23."
    )


async def test_a_link_this_container_will_not_dial_is_a_failed_download_and_is_never_dialled(db, clean) -> None:
    offer = _offer("a" * 64, url="http://169.254.169.254/latest/")
    assert offer.kind == "unusable"
    assert await feed.deliver_from_exchange(db, offer, transport=httpx.MockTransport(_never_dials)) == "download_failed"
    state = await _state(db)
    assert state.host == "169.254.169.254" and state.detail.startswith("the exchange named a link this container refuses")


# --- what the exchange said when it said nothing usable ------------------------------------------


async def test_the_exchange_end_to_end_records_what_each_response_said(db, clean, monkeypatch) -> None:
    """The seam: `run_exchange` hands the response's `patch_policy` to the feed after the corpus.
    A pointer stores the document; an absent key is *not published*; a key for another algorithm
    only is *algorithm unknown*; and the share log carries no link."""
    from app.core import sharing
    from app.models.schema import ShareLog

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(settings, "community_sharing", True)

    def answering(body: dict) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, content=GZ)
            return httpx.Response(200, json=body)

        return httpx.MockTransport(handler)

    pointer = {"patch_walk/1": {"signature": DOC["doc_id"], "asof": "2026-11-23T20:00:00Z", "url": LINK}}
    try:
        await sharing.run_exchange(db, transport=answering({"contract": "v1", "patch_policy": pointer}))
        assert await _held(db) == [(DOC["doc_id"], True)]
        assert (await _state(db)).outcome == "stored"
        log = (await db.execute(select(ShareLog).where(ShareLog.tier != "ai"))).scalars().all()[-1]
        assert log.outcome == "sent" and "X-Amz-Signature" not in json.dumps(log.payload)

        await sharing.run_exchange(db, transport=answering({"contract": "v1"}))
        assert (await _state(db)).outcome == "not_published"
        view = await feed.feed_view(db, now=datetime(2026, 11, 24, tzinfo=UTC))
        assert view.state == "not_published" and view.sentence.endswith("Showing the copy dated 2026-11-23.")

        newer = {"patch_walk/2": {"signature": "b" * 64, "asof": "2026-11-23T20:00:00Z", "url": LINK}}
        await sharing.run_exchange(db, transport=answering({"contract": "v1", "patch_policy": newer}))
        state = await _state(db)
        assert (state.outcome, state.detail) == ("algorithm_unknown", "patch_walk/2")
        assert await _held(db) == [(DOC["doc_id"], True)]

        # A revoke brings nothing, and records nothing about the document either.
        await sharing.run_exchange(db, transport=answering({"contract": "v1", "revoke": True, "patch_policy": pointer}))
        assert (await _state(db)).outcome == "algorithm_unknown"
    finally:
        await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
        await db.commit()


# --- the tier gate -------------------------------------------------------------------------------


async def test_an_organization_whose_tier_is_off_reads_the_tier_sentence_while_a_copy_is_held(db, clean, viewer) -> None:  # noqa: F811
    await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ))
    await _tier(db, "off")

    view = await feed.feed_view(db)
    assert (view.state, view.sentence, view.doc_id, view.document) == ("tier_off", feed.TIER_OFF_SENTENCE, None, None)

    body = (await viewer.get("/api/patch-policy/apps")).json()
    assert body["apps"] is None
    assert body["feed"]["state"] == "tier_off" and body["feed"]["docId"] is None and body["feed"]["attemptedAt"] is None
    assert body["feed"]["sentence"] == feed.TIER_OFF_SENTENCE

    await _tier(db, "keys")
    body = (await viewer.get("/api/patch-policy/apps")).json()
    assert body["feed"]["docId"] == DOC["doc_id"] and [app["app"] for app in body["apps"]] == ["chrome", "wireshark", "vlc"]


async def test_the_route_answers_each_app_with_its_tracks_and_sources(db, clean, viewer) -> None:  # noqa: F811
    body = (await viewer.get("/api/patch-policy/apps")).json()
    assert body == {
        "feed": body["feed"] | {"state": "never", "sentence": feed.NEVER_SENTENCE},
        "apps": None,
    }
    assert body["feed"]["algorithm"] == "patch_walk/1" and body["feed"]["fromFile"] is False

    # The fixture as LoonVD publishes it, each track's `check` filled in: an app's sources are
    # offered only once the walk of LoonSec's own dates matches those totals (§33 step 7).
    checked = published_checks(DOC)
    payload = gzip.compress(json.dumps(checked).encode(), mtime=0)
    await feed.deliver_from_exchange(db, _offer(checked["doc_id"]), transport=_serving(payload))
    response = await viewer.get("/api/patch-policy/apps")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["feed"]["asOf"] == "2026-11-23T20:00:00Z" and body["feed"]["coverageSince"] == "2024-05-21"
    assert body["feed"]["until"] == "2026-11-22" and body["feed"]["source"] == "exchange"
    chrome = body["apps"][0]
    assert chrome["bundleIds"] == ["com.google.Chrome"]
    assert chrome["tracks"][0]["clock"] == {"detectableAt": 2, "published": 1}
    assert (chrome["tracks"][0]["listed"], chrome["tracks"][0]["excluded"], chrome["tracks"][0]["notDetectable"]) == (3, 1, 1)
    assert chrome["sources"]["public"]["available"] is True and chrome["sources"]["jamf"]["available"] is False


async def test_a_copy_more_than_three_days_old_reads_stale_with_the_day_the_walk_ends(db, clean) -> None:
    await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ))
    fresh = await feed.feed_view(db, now=datetime(2026, 11, 25, tzinfo=UTC))
    assert fresh.state == "current" and fresh.sentence == "Showing LoonSec's patch-policy data dated 2026-11-23."
    old = await feed.feed_view(db, now=datetime(2026, 11, 23, 20, tzinfo=UTC) + timedelta(days=3, minutes=1))
    assert old.state == "stale"
    assert old.sentence == "Showing patch-policy data dated 2026-11-23, more than three days old; the walk ends 2026-11-22."


async def test_a_fresh_build_over_a_four_day_old_copy_reads_stale_with_the_stalled_nvd_sentence(db, clean) -> None:
    """The exchange says LoonSec's publisher finished a build half an hour ago, over the same
    document: its NVD state has not advanced in four days. The copy's own date decides (stale), and
    the build only names the cause."""
    offer = feed.read_offer(
        {
            "patch_walk/1": {
                "signature": DOC["doc_id"],
                "asof": "2026-11-23T20:00:00Z",
                "url": LINK,
                "built_at": "2026-11-27T21:00:00Z",
            }
        }
    )
    assert await feed.deliver_from_exchange(db, offer, transport=_serving(GZ)) == "stored"
    view = await feed.feed_view(db, now=datetime(2026, 11, 27, 21, 30, tzinfo=UTC))
    assert view.built_at == datetime(2026, 11, 27, 21, tzinfo=UTC)
    assert view.state == "stale"
    assert view.sentence == (
        "Showing patch-policy data dated 2026-11-23, more than three days old: LoonSec's publisher last ran on 2026-11-27, "
        "but its NVD data has not advanced since 2026-11-23, and the walk ends 2026-11-22."
    )


# --- the air-gapped path -------------------------------------------------------------------------


async def test_the_feed_file_is_read_once_per_change_and_the_exchange_link_is_then_not_followed(
    db, clean, monkeypatch, tmp_path
) -> None:
    path = tmp_path / "patch-policy.json.gz"
    monkeypatch.setattr(settings, "patch_policy_feed_file", str(path))

    # Not there yet: a failed read naming the path and the reason, and no copy.
    assert await feed.load_feed_file(db) == "download_failed"
    state = await _state(db)
    assert (state.source, state.host) == ("file", str(path)) and state.detail.startswith("the file could not be read (")
    assert (await feed.feed_view(db)).sentence.startswith(f"The patch-policy file could not be read from {path}: the file")
    assert await feed.load_feed_file(db) is None  # unchanged since: nothing read, nothing written

    path.write_bytes(GZ)
    assert await feed.load_feed_file(db) == "stored"
    assert await _held(db) == [(DOC["doc_id"], True)]
    assert (await _state(db)).outcome == "stored"
    assert await feed.load_feed_file(db) is None

    # A file that changed into something that is not a document: refused, the copy kept.
    path.write_bytes(b"not a document at all")
    os.utime(path, ns=(1, 1))
    assert await feed.load_feed_file(db) == "invalid"
    assert await _held(db) == [(DOC["doc_id"], True)]

    # With the file set, the exchange's link is not followed at all and writes no state.
    assert await feed.deliver_from_exchange(db, _offer("c" * 64), transport=httpx.MockTransport(_never_dials)) is None
    assert (await _state(db)).outcome == "invalid"
    view = await feed.feed_view(db)
    assert view.from_file is True and view.source == "file"


async def test_a_malformed_feed_file_is_refused_in_words_and_read_once(db, clean, monkeypatch, tmp_path) -> None:
    """The file is read at container startup, so a document the check cannot even parse — here,
    JSON nested past the parser's depth — must come back as `invalid` with a state row, not as an
    exception out of the lifespan. And it is marked seen: an unchanged bad file is not re-read and
    re-logged every five minutes."""
    path = tmp_path / "patch-policy.json"
    path.write_bytes(b"[" * 200_000 + b"]" * 200_000)
    monkeypatch.setattr(settings, "patch_policy_feed_file", str(path))

    assert await feed.load_feed_file(db) == "invalid"
    state = await _state(db)
    assert (state.source, state.outcome, state.host) == ("file", "invalid", str(path))
    assert state.detail == "it is not JSON this container reads (it nests more deeply than any document does)"
    assert await feed.load_feed_file(db) is None
    assert await _held(db) == []


async def test_a_defect_while_taking_the_file_is_recorded_and_never_raised(db, clean, monkeypatch, tmp_path, caplog) -> None:
    """Belt and braces under the total check: anything else that goes wrong while the file is
    taken is logged as a line to report, recorded as `invalid`, and the copy held keeps answering."""
    await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ))
    path = tmp_path / "patch-policy.json.gz"
    path.write_bytes(_another()[1])
    monkeypatch.setattr(settings, "patch_policy_feed_file", str(path))

    async def defect(*_args):
        raise RuntimeError("a defect")

    monkeypatch.setattr(feed, "_take_file", defect)
    with caplog.at_level("ERROR"):
        assert await feed.load_feed_file(db) == "invalid"
    assert (
        caplog.records[-1]
        .getMessage()
        .startswith("patch-policy data not read from PATCH_POLICY_FEED_FILE: an unexpected failure (RuntimeError), not a refusal")
    )
    state = await _state(db)
    assert (state.outcome, state.detail) == ("invalid", "an unexpected failure (RuntimeError) that the container log reports")
    assert await _held(db) == [(DOC["doc_id"], True)]
    view = await feed.feed_view(db, now=datetime(2026, 11, 24, tzinfo=UTC))
    assert view.sentence == (
        "LoonSec's patch-policy data failed its check (an unexpected failure (RuntimeError) that the container log "
        "reports), so it was not stored. The copy dated 2026-11-23 is still used."
    )
    assert await feed.load_feed_file(db) is None


async def test_an_instance_with_the_file_set_and_nothing_read_yet_says_so(db, clean, monkeypatch) -> None:
    monkeypatch.setattr(settings, "patch_policy_feed_file", "/app/data/patch-policy.json.gz")
    view = await feed.feed_view(db)
    assert view.state == "never" and view.sentence == feed.NEVER_FILE_SENTENCE


# --- the store itself ----------------------------------------------------------------------------


async def test_the_database_holds_at_most_one_current_copy(db, clean) -> None:
    from sqlalchemy.exc import IntegrityError

    newer, newer_gz = _another()
    await feed.deliver_from_exchange(db, _offer(DOC["doc_id"]), transport=_serving(GZ))
    await feed.deliver_from_exchange(db, _offer(newer["doc_id"]), transport=_serving(newer_gz))
    with pytest.raises(IntegrityError):
        await db.execute(update(PatchPolicyDoc).values(current=True))
    await db.rollback()
