"""LoonSec's patch-policy document, checked without a database (#614).

`tests/fixtures/patch_policy/reference.json` is a hand-made `patch_policy_reference` (schema 1)
that follows the plan's data contract: three apps (two with public timelines, one whose versions
are undated), every exclusion reason, both CVE clocks, and fictional CVE ids (`CVE-2099-*`) so no
number in it reads as a fact about a real app. LoonVD's builder produces the real one; until then
this file is what the check is held to. Editing it means recomputing its `doc_id`, which the first
test here prints when it moves.

What needs a database — storing, keeping two copies, the state row, the tier gate and the
exchange end to end — is `test_patch_policy_feed_db.py`.
"""

from __future__ import annotations

import copy
import gzip
import json
import re
from pathlib import Path

import httpx
import pytest

from app.core import patch_policy_feed as feed
from app.core.vuln_library import CorpusRefused, download_signed

FIXTURE = Path(__file__).parent / "fixtures" / "patch_policy" / "reference.json"
RAW = FIXTURE.read_bytes()
DOC = json.loads(RAW)
GZ = gzip.compress(RAW, mtime=0)
LINK = "https://patch-policy.example-bucket.s3.amazonaws.com/patch-policy/patch_walk/1/docs/x.json.gz?X-Amz-Signature=secret"

_ROOT = Path(__file__).resolve().parents[2]
_EN_TS = (_ROOT / "frontend" / "src" / "i18n" / "en.ts").read_text()
_RUNBOOK = (_ROOT / "docs" / "troubleshooting.md").read_text()


def _resigned(doc: dict) -> bytes:
    """A document with its `doc_id` recomputed: a change the check must judge on its merits,
    not one the digest refuses first."""
    doc = copy.deepcopy(doc)
    doc["doc_id"] = feed.canonical_doc_id(doc)
    return json.dumps(doc).encode()


def _refusal(data: bytes, **kwargs) -> str:
    with pytest.raises(feed.DocumentRefused) as refused:
        feed.read_document(data, **kwargs)
    return str(refused.value)


# --- the fixture is the contract it stands in for -------------------------------------------


def test_the_fixture_is_checked_whole_and_its_doc_id_is_its_contents() -> None:
    assert feed.canonical_doc_id(DOC) == DOC["doc_id"], f"recompute the fixture's doc_id: {feed.canonical_doc_id(DOC)}"
    doc = feed.read_document(GZ, expected_doc_id=DOC["doc_id"])
    assert (doc.doc_id, doc.schema, doc.algorithm) == (DOC["doc_id"], 1, "patch_walk/1")
    assert doc.as_of.isoformat() == "2026-11-23T20:00:00+00:00"
    # The bytes as they arrived are what is kept, and what `sha256` names.
    assert doc.body_gz == GZ
    assert [app["app"] for app in doc.body["apps"]] == ["chrome", "wireshark", "vlc"]


def test_a_document_that_arrives_as_plain_json_is_read_and_kept_compressed() -> None:
    """A file an operator decompressed is the same document: same doc_id, kept as gzip."""
    doc = feed.read_document(RAW)
    assert doc.doc_id == DOC["doc_id"]
    assert gzip.decompress(doc.body_gz) == RAW


def test_the_fixture_names_no_mdm_source_anywhere_the_builder_gate_looks() -> None:
    """The plan's build gate, held on the stand-in too: no key anywhere, and no string under
    `sources` or an app's `identity`, names Jamf or Fleet, and every identity basis is one the
    allowlist names. CPE values are exempt; this fixture has none that match either."""
    pattern = re.compile(r"jamf|fleet", re.I)

    def keys(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                yield key
                yield from keys(inner)
        elif isinstance(value, list):
            for inner in value:
                yield from keys(inner)

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for inner in value.values():
                yield from strings(inner)
        elif isinstance(value, list):
            for inner in value:
                yield from strings(inner)

    assert not [key for key in keys(DOC) if pattern.search(key)]
    assert not [text for text in strings(DOC["sources"]) if pattern.search(text)]
    for app in DOC["apps"]:
        assert app["identity"]["basis"] in ("hand", "homebrew_cask")
        assert not [text for text in strings(app["identity"]) if pattern.search(text)]


# --- the check ----------------------------------------------------------------------------


def test_a_doc_id_that_is_not_what_the_body_hashes_to_is_refused() -> None:
    tampered = copy.deepcopy(DOC)
    tampered["apps"][0]["tracks"][0]["cves"][0]["published"] = "2025-10-01"
    said = _refusal(json.dumps(tampered).encode())
    assert said.startswith(f"its doc_id {DOC['doc_id'][:12]}… is not what its contents hash to")


def test_a_document_that_is_not_the_one_the_exchange_named_is_refused() -> None:
    said = _refusal(GZ, expected_doc_id="0" * 64)
    assert (
        said
        == f"it is not the document the exchange named: its doc_id is {DOC['doc_id'][:12]}… and the exchange named 000000000000…"
    )


@pytest.mark.parametrize(
    ("key", "value", "said"),
    [
        ("kind", "patch_policy_replay", 'its kind is "patch_policy_replay", not patch_policy_reference'),
        ("schema", 2, "its schema is 2; this build reads schema 1"),
        ("algorithm", "patch_walk/2", 'its algorithm is "patch_walk/2"; this build reads patch_walk/1'),
    ],
)
def test_a_kind_schema_or_algorithm_this_build_does_not_read_is_refused_by_name(key, value, said) -> None:
    other = copy.deepcopy(DOC)
    other[key] = value
    assert _refusal(_resigned(other)) == said


def _track(doc: dict, app: str = "wireshark", index: int = 0) -> dict:
    return next(a for a in doc["apps"] if a["app"] == app)["tracks"][index]


@pytest.mark.parametrize(
    ("change", "said"),
    [
        (lambda t: t["counts"].update(listed=5), "cves lists 2 ≠ counts.listed 5"),
        (lambda t: t["counts"].update(versions=3), "versions lists 4 ≠ counts.versions 3"),
        (lambda t: t["counts"].update(candidates=4), "counts.candidates 4 ≠ listed 2 + excluded 1 + not_detectable 0"),
        (lambda t: t["counts"]["clock"].update(published=0), "1 rows use the published clock ≠ counts.clock.published 0"),
        (lambda t: t["exclusions"]["by_reason"].update(rejected=1), "exclusions.by_reason sums to 2"),
        (lambda t: t["exclusions"]["by_reason"].pop("rejected"), "does not name exactly the document's exclusion_reasons"),
        (lambda t: t["not_detectable"].update(count=1), "not_detectable lists 0, says 1"),
        (lambda t: t["cves"][0].update(affected=[[0, 9]]), "has an affected run [0, 9] outside its 4 versions"),
        (lambda t: t["cves"][0].update(fixes=[{"line": "4.4", "index": 4}]), "has a fix index 4 outside its 4 versions"),
        (lambda t: t["cves"][1].update(clock="detectable_at"), "uses the detectable_at clock and has no detectable_at day"),
        (lambda t: t["exclusions"]["cves"][0].update(cve_id="CVE-2099-2001"), "a CVE is listed twice"),
        (lambda t: t["versions"][1].update(keys=["4.4.0"]), "a version key is listed twice"),
    ],
)
def test_counts_that_do_not_close_refuse_the_whole_document_naming_the_track(change, said) -> None:
    broken = copy.deepcopy(DOC)
    change(_track(broken))
    refused = _refusal(_resigned(broken))
    assert refused.startswith("its own counts disagree (wireshark wireshark/4.4: ")
    assert said in refused


def test_a_track_naming_a_timeline_the_document_does_not_describe_is_refused() -> None:
    broken = copy.deepcopy(DOC)
    _track(broken)["timeline"] = "somewhere-else"
    assert _refusal(_resigned(broken)) == "it lacks sources.timelines.somewhere-else, which wireshark wireshark/4.4 names"


def test_an_app_with_two_default_tracks_is_refused() -> None:
    broken = copy.deepcopy(DOC)
    _track(broken, index=1)["default"] = True
    assert _refusal(_resigned(broken)) == "its own counts disagree (wireshark has 2 default tracks, not 1)"


@pytest.mark.parametrize(
    ("data", "said"),
    [
        (b"\x1f\x8b not really gzip", "it is not a gzip file this container can read"),
        (GZ[:-12], "its gzip stream is cut short"),
        (b"<html>captive portal</html>", "it is not JSON (JSONDecodeError)"),
        (b"[]", "it is a JSON list, not an object"),
    ],
)
def test_bytes_that_are_not_a_document_are_refused_in_words(data, said) -> None:
    assert _refusal(data) == said


def test_a_document_that_decompresses_past_the_ceiling_is_stopped_there(monkeypatch) -> None:
    monkeypatch.setattr(feed, "_MAX_JSON_BYTES", 1024)
    assert _refusal(GZ) == "it decompresses past the 1024-byte ceiling this container accepts"


# --- the pointer the exchange carries --------------------------------------------------------


def test_the_pointer_is_read_tolerantly_and_says_which_of_four_things_it_is() -> None:
    assert feed.read_offer(None).kind == "not_published"
    assert feed.read_offer({}).kind == "not_published"

    newer = feed.read_offer({"patch_walk/2": {"signature": "a" * 64, "asof": "2026-11-23T20:00:00Z", "url": LINK}})
    assert (newer.kind, newer.algorithms) == ("algorithm_unknown", ("patch_walk/2",))

    offer = feed.read_offer({"patch_walk/1": {"signature": DOC["doc_id"], "asof": "2026-11-23T20:00:00Z", "url": LINK}})
    assert offer.kind == "pointer" and offer.pointer.signature == DOC["doc_id"] and offer.pointer.url == LINK
    # The signed link is a credential: never in a repr, so never in a log line by accident.
    assert "secret" not in repr(offer)

    for broken, said in (
        ([], "the exchange's patch_policy field is a list, not an object"),
        ({"patch_walk/1": {"url": LINK}}, "the exchange's patch_walk/1 entry carries no sha256 signature"),
        ({"patch_walk/1": {"signature": "a" * 64}}, "the exchange's patch_walk/1 entry carries no link"),
    ):
        unusable = feed.read_offer(broken)
        assert (unusable.kind, unusable.detail) == ("unusable", said)

    refused = feed.read_offer({"patch_walk/1": {"signature": "a" * 64, "url": "http://169.254.169.254/latest/"}})
    assert refused.kind == "unusable" and refused.host == "169.254.169.254"
    assert refused.detail.startswith("the exchange named a link this container refuses (the patch-policy link must be")


# --- the download it shares with the corpus ---------------------------------------------------


@pytest.mark.asyncio
async def test_the_patch_policy_download_says_patch_policy_and_keeps_the_status() -> None:
    """`download_signed` is the corpus's download, generalised: the same cap and per-hop redirect
    check, its own words, and the status the store answered with kept for the state row."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=GZ)

    data = await download_signed(LINK, what="patch-policy", max_bytes=1 << 20, transport=httpx.MockTransport(handler))
    assert data == GZ and "patch-policy" in seen[0].headers["user-agent"]

    with pytest.raises(CorpusRefused) as refused:
        await download_signed(
            LINK, what="patch-policy", max_bytes=1 << 20, transport=httpx.MockTransport(lambda _: httpx.Response(403))
        )
    assert str(refused.value) == "the patch-policy download did not complete (HTTP 403)"
    assert refused.value.http_status == 403 and "secret" not in str(refused.value)

    to_metadata = httpx.MockTransport(lambda _: httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/"}))
    with pytest.raises(CorpusRefused) as refused:
        await download_signed(LINK, what="patch-policy", max_bytes=1 << 20, transport=to_metadata)
    assert str(refused.value).startswith(
        "the patch-policy link redirected somewhere this container refuses: the patch-policy link must be"
    )

    with pytest.raises(CorpusRefused) as refused:
        await download_signed(LINK, what="patch-policy", max_bytes=16, transport=httpx.MockTransport(handler))
    assert str(refused.value).startswith("the patch-policy download passed the 16-byte ceiling")


# --- what an organization reads ---------------------------------------------------------------


def test_each_app_says_which_sources_can_date_it() -> None:
    apps = {app["app"]: app for app in feed.app_summaries(DOC)}
    chrome, wireshark, vlc = apps["chrome"], apps["wireshark"], apps["vlc"]

    assert chrome["sources"]["public"] == {
        "available": True,
        "first": "2025-09-30",
        "last": "2025-10-28",
        "sentence": None,
        "ids": ["chrome-mac-stable"],
    }
    assert wireshark["sources"]["public"]["ids"] == ["wireshark-tags"]
    assert [t["track"] for t in wireshark["tracks"]] == ["wireshark/4.4", "wireshark/newest"]
    assert wireshark["tracks"][1]["clock"] == {"detectable_at": 2, "published": 1}
    # Undated versions: LoonSec holds no public dates, and says so rather than an empty range.
    assert vlc["sources"]["public"] == {
        "available": False,
        "first": None,
        "last": None,
        "sentence": "LoonSec holds no public release dates for VLC media player yet.",
        "ids": [],
    }
    for app in apps.values():
        assert app["sources"]["jamf"]["available"] is False and app["sources"]["jamf"]["sentence"] == feed.JAMF_NOT_BUILT
        assert app["sources"]["fleet"]["available"] is False and app["sources"]["fleet"]["sentence"] == feed.FLEET_NOT_BUILT


@pytest.mark.parametrize("state", feed.FEED_STATES)
def test_every_state_has_its_sentence_on_the_page_and_its_step_in_the_runbook(state) -> None:
    """docs/diagnosability.md rule 4, held: each state's words are the backend's, the page's
    (`en.ts`) and §32's, and rewording one without the others fails here. What the three share is
    each sentence's opening, up to its first value or the end of its first sentence: the page
    holds the rest as templates, and the runbook quotes the opening and elides the rest."""
    from datetime import date

    sentence = feed.sentence_for(state, as_of=date(2026, 11, 23), source="exchange", host="store.example", detail="x")
    fixed = re.split(r"\b(?:2026-11-2\d|store\.example|patch_walk/1)\b|\(x\)|: x\.", sentence)[0]
    opening = fixed.split(". ")[0].strip().rstrip(".")
    assert len(opening) >= 15, f"{state}'s sentence starts with a value: {sentence!r}"
    assert opening in _EN_TS, f"the page does not say {state}'s sentence: {opening!r}"
    section = re.sub(r"\s+", " ", _RUNBOOK.split('\n## 32. "', 1)[1]).replace("*", "")
    if state != "current":  # an answer, not a path
        assert opening in section, f"§32 does not walk {state}: {opening!r}"
