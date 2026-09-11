"""The corpus epoch, from the wire to the seam (#248). Pure; no database, no network.

The library arrives as one published epoch — a signed link on the daily exchange, a
bundle, a manifest that digests every object in it. This suite drives the committed
fixture epoch (`tests/fixtures/epochs/0001/`, copied from LoonVD-Internal PR #12) through
the loader and asserts the three things the ruling is made of:

* **it is verified whole, or it is refused whole.** A tampered object, a manifest that is
  not the one the pointer signed, a member outside the epoch's directory, a row carrying
  an id in a namespace nothing mints — each is a named refusal, and each leaves the
  previous epoch answering;
* **a row is the only thing that means "clean".** A build with no row reads `None` —
  `unknown_app`, dated, never zero — even when the epoch knows the title, because the
  branch that turns that into a positive clean bill needs the pod's own Jamf stamp and is
  #381's;
* **the aggregates are the corpus's, not this container's.** The row carries a capped id
  list beside uncapped counts, so `vuln_block` reports what was counted rather than
  recounting a list the cap already bit — and the block it produces is byte-identical to
  the one the finding-by-finding path produces for the same numbers.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pytest

from app.core.content_keys import app_full_key, app_title_key
from app.core.egress import BlockedCorpusUrl, validate_corpus_url
from app.core.vuln import NO_CORPUS, AssessedBuild, VulnCorpus, VulnFinding, loaded_corpus, vuln_block
from app.core.vuln_library import (
    MANIFEST_NAME,
    ROWS_NAME,
    TITLES_NAME,
    CorpusRefused,
    LibraryCorpus,
    VulnLibrary,
    corpus_pointer,
    download_bundle,
    read_bundle,
)

EPOCH = Path(__file__).parent / "fixtures" / "epochs" / "0001"
BUNDLE = (EPOCH / "epoch-0001.tar.gz").read_bytes()
POINTER = json.loads((EPOCH / "current.json").read_text())
SIGNATURE = POINTER["signature"]

# The four identities the fixture is built from, keyed with THIS repository's frozen
# `content_keys` — the assertion that matters most in the file, because two
# implementations of one hash do not fail loudly when they drift; they answer
# `unknown_app` for an app the corpus knows perfectly well.
WIRESHARK_TITLE = app_title_key("Wireshark.app", "org.wireshark.Wireshark")
WIRESHARK_BUILD = app_full_key("Wireshark.app", "org.wireshark.Wireshark", "4.2.0", None)
CLEAN_BUILD = app_full_key("LoonVD Fixture Clean.app", "io.loonsec.fixture.clean", "2.6.0", None)
STALE_TITLE = app_title_key("LoonVD Fixture Stale.app", "io.loonsec.fixture.stale")
STALE_UNASSESSED_BUILD = app_full_key("LoonVD Fixture Stale.app", "io.loonsec.fixture.stale", "3.2.0", None)
UNKNOWN_TITLE = app_title_key("LoonVD Fixture Unknown.app", "io.loonsec.fixture.unknown")
UNKNOWN_BUILD = app_full_key("LoonVD Fixture Unknown.app", "io.loonsec.fixture.unknown", "1.0.0", None)

CORPUS_URL = "https://corpus.example.com/epochs/epoch-0001.tar.gz?signature=deadbeef"
AS_OF = date(2026, 9, 10)


def _members(bundle: bytes = BUNDLE) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tar:
        return {member.name.split("/")[-1]: tar.extractfile(member).read() for member in tar.getmembers()}


def _bundle(members: dict[str, bytes], *, top: str = "0001") -> bytes:
    """A bundle carrying exactly these members, under one top-level directory. The loader
    is what the test is about, so the writer here is deliberately dumb: it does not
    recompute a digest or a count."""
    return _raw_bundle({f"{top}/{name}": payload for name, payload in members.items()})


def _raw_bundle(paths: dict[str, bytes]) -> bytes:
    """A bundle whose member paths are written verbatim — the only way to hand the loader
    the paths a hostile publisher would."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, payload in paths.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _rewritten(*, rows: list[dict] | None = None, manifest: dict | None = None) -> tuple[bytes, str]:
    """A well-formed bundle with these rows, its manifest digests and counts corrected,
    and the signature a pointer would carry for it. The way an epoch that is *valid* but
    says something this container refuses gets built."""
    members = _members()
    if rows is not None:
        members[ROWS_NAME] = gzip.compress(b"".join(json.dumps(row).encode() + b"\n" for row in rows), mtime=0)
    described = json.loads(members[MANIFEST_NAME])
    for name in (ROWS_NAME, TITLES_NAME):
        payload = members[name]
        described["objects"][name] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
            "rows": len(gzip.decompress(payload).decode().splitlines()),
        }
    described.update(manifest or {})
    members[MANIFEST_NAME] = json.dumps(described, indent=2).encode()
    return _bundle(members), hashlib.sha256(members[MANIFEST_NAME]).hexdigest()


def _row(**overrides) -> dict:
    row = {
        "key_full": "v1:" + "a" * 64,
        "ids": ["CVE-2026-1000"],
        "truncated": False,
        "counts": {"total": 1, "kev": 0, "critical": 0, "high": 1, "medium": 0, "low": 0},
        "oldest_published": {
            "total": "2026-01-01T00:00:00Z",
            "critical": None,
            "high": "2026-01-01T00:00:00Z",
            "medium": None,
            "low": None,
        },
    }
    row.update(overrides)
    return row


def _library() -> VulnLibrary:
    epoch = read_bundle(BUNDLE, signature=SIGNATURE)
    return VulnLibrary(
        epoch_id=epoch.epoch_id,
        signature=epoch.signature,
        as_of=epoch.asof.date(),
        asof_at=epoch.asof,
        loaded_at=datetime.now(UTC),
        rows=epoch.rows,
        titles=epoch.titles,
    )


# --- the fixture epoch, read whole ------------------------------------------------------


def test_the_published_epoch_loads_and_is_what_it_says_it_is() -> None:
    """The happy path, end to end over the real artifact: the bundle's manifest is the one
    the pointer signed, every object matches its digest and its row count, and the epoch
    dates itself. `asof` is where `corpusAsOf` comes from, which is why it is asserted as a
    date rather than trusted."""
    epoch = read_bundle(BUNDLE, signature=SIGNATURE)
    assert epoch.epoch_id == "0001"
    assert epoch.asof == datetime(2026, 9, 10, 20, 0, 0, tzinfo=UTC)
    assert epoch.asof.date() == date(2026, 9, 10)
    assert len(epoch.rows) == 3
    assert len(epoch.titles) == 3
    # The manifest in the bundle is byte-identical to the published loose one — the
    # property that makes the bundle a transport rather than a second source of truth.
    assert _members()[MANIFEST_NAME] == (EPOCH / MANIFEST_NAME).read_bytes()


def test_the_wireshark_row_is_keyed_the_way_this_container_keys_an_installed_build() -> None:
    """The join is a string comparison between two hashes computed in two repositories,
    and nothing announces it when they stop agreeing — the answer just becomes
    `unknown_app` for an app the corpus knows. So the fixture's key is asserted against
    this repository's own `content_keys`, with `short_version=None` in the fourth slot
    (docs/vulnerabilities.md §4f)."""
    epoch = read_bundle(BUNDLE, signature=SIGNATURE)
    assert WIRESHARK_BUILD == "v1:c63d39b2960e648daa2def3aaa786e60f36e40f056947be5a31ec6b1171afd42"
    row = epoch.rows[WIRESHARK_BUILD]
    assert row.total == 17
    assert row.kev == 0
    assert row.severity == {"critical": 0, "high": 9, "medium": 8, "low": 0}
    assert row.oldest_published == date(2024, 1, 3)
    assert row.oldest_published_severity["medium"] == date(2024, 5, 14)
    assert row.oldest_published_severity["critical"] is None
    assert row.truncated is False
    assert len(row.ids) == 17
    assert row.ids[0] == "CVE-2025-1492"
    assert epoch.titles[WIRESHARK_TITLE].catalog_last_modified == "2026-09-09T04:11:00Z"


def test_assessed_and_clean_is_a_row_and_never_an_absent_one() -> None:
    """The format's load-bearing sentence, and §4f's one layer down: a build with no
    findings ships as a row with no ids. If clean and never-looked-at were both "no row",
    the honest answer for both would be `unknown_app` and a clean bill could never be
    given at all."""
    epoch = read_bundle(BUNDLE, signature=SIGNATURE)
    clean = epoch.rows[CLEAN_BUILD]
    assert clean.total == 0
    assert clean.ids == ()
    assert clean.oldest_published is None
    assert all(value is None for value in clean.oldest_published_severity.values())


# --- refusals: whole, or not at all -----------------------------------------------------


def test_a_tampered_object_is_refused_and_names_the_object() -> None:
    """The digest is over the object exactly as stored. A rows file swapped for another
    one — a truncated download, a substituted epoch — fails against the manifest that
    describes it, and nothing is imported."""
    members = _members()
    members[ROWS_NAME] = gzip.compress(b'{"key_full":"v1:00"}\n', mtime=0)
    with pytest.raises(CorpusRefused) as refused:
        read_bundle(_bundle(members), signature=SIGNATURE)
    assert refused.value.state == "digest_mismatch"
    assert ROWS_NAME in str(refused.value)
    assert "still answers from the epoch it had" in str(refused.value)


def test_a_manifest_that_is_not_the_one_the_pointer_signed_is_refused() -> None:
    """Equality against the signature, in the one direction that matters: this is the
    epoch the exchange named, or it is not imported. The check is what makes a link that
    was replayed, cached or substituted detectable at all."""
    with pytest.raises(CorpusRefused) as refused:
        read_bundle(BUNDLE, signature="0" * 64)
    assert refused.value.state == "signature_mismatch"


@pytest.mark.parametrize(
    "path",
    [
        "../escape.json",
        "0001/../../escape.json",
        "/etc/passwd",
        "0001/extra.txt",  # a fourth member the format does not list
        "manifest.json",  # no top-level directory at all
        "0002/manifest.json",  # a second top-level directory
    ],
)
def test_a_member_the_format_does_not_license_is_refused_before_it_is_read(path: str) -> None:
    """The bundle arrives over a link and `tarfile` writes wherever a member says.
    Nothing is ever extracted to disk here — the members are read in memory — and the
    format's own rule is enforced anyway, because a bundle that breaks it is not one this
    container should be reading at all."""
    paths = {f"0001/{name}": payload for name, payload in _members().items()}
    paths[path] = b"{}"
    with pytest.raises(CorpusRefused) as refused:
        read_bundle(_raw_bundle(paths), signature=SIGNATURE)
    assert refused.value.state == "bundle_malformed"


def test_a_bundle_missing_an_object_is_refused() -> None:
    members = _members()
    del members[TITLES_NAME]
    with pytest.raises(CorpusRefused) as refused:
        read_bundle(_bundle(members), signature=SIGNATURE)
    assert refused.value.state == "bundle_malformed"
    assert TITLES_NAME in str(refused.value)


def test_a_format_this_container_does_not_know_is_refused_and_says_what_to_do() -> None:
    """`epoch/2` is a new format, not an edit to this one. A consumer refuses it and never
    guesses — and the sentence names the fix an operator can actually take."""
    bundle, signature = _rewritten(manifest={"format": "epoch/2"})
    with pytest.raises(CorpusRefused) as refused:
        read_bundle(bundle, signature=signature)
    assert refused.value.state == "epoch_malformed"
    assert "update the container" in str(refused.value)


@pytest.mark.parametrize(
    ("overrides", "because"),
    [
        ({"ids": ["LOCAL-2026-000042"]}, "the reserved namespace nothing we ship mints"),
        ({"ids": ["GHSA-xxxx-yyyy-zzzz"]}, "a fourth namespace the wire never licensed"),
        ({"truncated": True}, "truncated with nothing dropped"),
        (
            {"counts": {"total": 1, "kev": 0, "critical": 1, "high": 0, "medium": 0, "low": 0}},
            "a band counted with no date to age it by",
        ),
        ({"oldest_published": {"total": None, "critical": None, "high": None, "medium": None, "low": None}}, "a date short"),
    ],
)
def test_a_row_the_wire_would_refuse_at_enqueue_is_refused_at_import(overrides: dict, because: str) -> None:
    """§5's requirement on this session, in a test: build the findings when the corpus is
    loaded, not per lookup. Every one of these rows would raise inside `VulnEnrichment` at
    enqueue — which is the middle of a device sync, on whichever fleet happens to install
    that app. Refused here instead, once, with the line named, and the previous epoch
    keeps answering."""
    bundle, signature = _rewritten(rows=[_row(**overrides)])
    with pytest.raises(CorpusRefused) as refused:
        read_bundle(bundle, signature=signature)
    assert refused.value.state == "epoch_malformed", because
    assert "rows line 1" in str(refused.value)


def test_a_row_count_the_manifest_disagrees_with_is_refused() -> None:
    """The manifest counts lines after decompression, so a file that unpacks to fewer rows
    than it claims is a truncation the digest alone would not name."""
    bundle, _ = _rewritten(rows=[_row()])
    members = _members(bundle)
    described = json.loads(members[MANIFEST_NAME])
    described["objects"][ROWS_NAME]["rows"] = 99
    members[MANIFEST_NAME] = json.dumps(described, indent=2).encode()
    with pytest.raises(CorpusRefused) as refused:
        read_bundle(_bundle(members), signature=hashlib.sha256(members[MANIFEST_NAME]).hexdigest())
    assert refused.value.state == "digest_mismatch"


# --- the pointer ------------------------------------------------------------------------


def test_the_pointer_is_read_tolerantly_and_a_missing_one_is_not_an_error() -> None:
    """Every field of the exchange response is optional and a V0 collector answers none of
    them. "No corpus today" has to be ordinary."""
    assert corpus_pointer(None) is None
    assert corpus_pointer({}) is None
    assert corpus_pointer({"signature": SIGNATURE}) is None
    assert corpus_pointer({"signature": SIGNATURE, "asof": "2026-09-10T20:00:00Z", "url": CORPUS_URL}) is not None
    assert corpus_pointer({"signature": "not-a-digest", "asof": "2026-09-10T20:00:00Z", "url": CORPUS_URL}) is None
    assert corpus_pointer({"signature": SIGNATURE, "asof": "the tenth", "url": CORPUS_URL}) is None


def test_a_corpus_link_this_container_will_not_dial_is_not_a_pointer(caplog) -> None:
    """The response names a destination and this container fetches it, which makes it the
    third egress sink (#131's two are `base_url` and a destination). A refusal is loud —
    the operator should be able to find "we declined the link" rather than a silence that
    looks like an epoch that never moved."""
    for url in ("http://corpus.example.com/e.tar.gz", "https://127.0.0.1/e.tar.gz", "https://169.254.169.254/e.tar.gz"):
        with caplog.at_level("WARNING"):
            assert corpus_pointer({"signature": SIGNATURE, "asof": "2026-09-10T20:00:00Z", "url": url}) is None
        assert "refuses" in caplog.text
        caplog.clear()
    assert validate_corpus_url(CORPUS_URL) == CORPUS_URL
    with pytest.raises(BlockedCorpusUrl):
        validate_corpus_url("https://user:pass@corpus.example.com/e.tar.gz")


# --- the download -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_bundle_is_fetched_over_the_exchanges_own_transport() -> None:
    """Injectable for the reason `post_exchange`'s is: the whole loader runs against the
    committed fixture with no network, which is also the only way to write down what
    happens to a download that fails."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, content=BUNDLE)

    data = await download_bundle(CORPUS_URL, transport=httpx.MockTransport(handler))
    assert data == BUNDLE
    assert seen == [CORPUS_URL]
    assert read_bundle(data, signature=SIGNATURE).epoch_id == "0001"


@pytest.mark.asyncio
async def test_a_download_that_fails_is_a_named_state_and_not_a_traceback() -> None:
    with pytest.raises(CorpusRefused) as refused:
        await download_bundle(CORPUS_URL, transport=httpx.MockTransport(lambda _: httpx.Response(403)))
    assert refused.value.state == "download_failed"


@pytest.mark.asyncio
async def test_a_redirect_is_followed_only_somewhere_this_container_would_have_dialled() -> None:
    """The hole an automatic `follow_redirects=True` leaves: the egress rules judge the
    link the exchange named, and a `302` then points the request wherever it likes. Every
    hop is validated like the first, so the metadata endpoint is refused on hop two the
    same way it is on hop one."""
    hops = {
        CORPUS_URL: httpx.Response(302, headers={"Location": "https://cdn.example.com/e.tar.gz"}),
        "https://cdn.example.com/e.tar.gz": httpx.Response(200, content=BUNDLE),
    }
    assert await download_bundle(CORPUS_URL, transport=httpx.MockTransport(lambda r: hops[str(r.url)])) == BUNDLE

    to_metadata = httpx.MockTransport(lambda _: httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/"}))
    with pytest.raises(CorpusRefused) as refused:
        await download_bundle(CORPUS_URL, transport=to_metadata)
    assert refused.value.state == "download_failed"
    assert "refuses" in str(refused.value)


@pytest.mark.asyncio
async def test_a_redirect_loop_ends_rather_than_spins() -> None:
    circular = httpx.MockTransport(lambda r: httpx.Response(302, headers={"Location": str(r.url)}))
    with pytest.raises(CorpusRefused) as refused:
        await download_bundle(CORPUS_URL, transport=circular)
    assert refused.value.state == "download_failed"
    assert "redirected more than" in str(refused.value)


def test_a_bundle_whose_directory_and_manifest_disagree_is_refused() -> None:
    """The epoch id names the directory. A bundle whose two halves disagree about which
    epoch it is has one of them wrong and no way to say which."""
    with pytest.raises(CorpusRefused) as refused:
        read_bundle(_bundle(_members(), top="0002"), signature=SIGNATURE)
    assert refused.value.state == "bundle_malformed"


# --- the seam ---------------------------------------------------------------------------


def test_the_library_corpus_satisfies_the_protocol_and_dates_itself() -> None:
    corpus = LibraryCorpus(_library())
    assert isinstance(corpus, VulnCorpus)
    assert corpus.as_of == date(2026, 9, 10)
    assert loaded_corpus() is NO_CORPUS, "nothing in this suite installs a library"


def test_a_rowless_build_of_a_known_title_is_unknown_app_and_never_a_clean_bill() -> None:
    """The trap §4f exists to name. The epoch knows this title and the pod may well be
    entitled to a clean answer for this build — but only after comparing the pod's own
    Jamf catalog stamp to the epoch's, which is a database read at judge time and #381's.
    Until then the answer is `unknown_app`: dated, never zero, and never `()`."""
    corpus = LibraryCorpus(_library())
    assert corpus.library.title_stamp(STALE_TITLE).catalog_last_modified == "2025-03-04T11:20:00Z"
    assert corpus.findings(key_title=STALE_TITLE, key_full=STALE_UNASSESSED_BUILD) is None
    assert corpus.findings(key_title=UNKNOWN_TITLE, key_full=UNKNOWN_BUILD) is None
    block = vuln_block(corpus, key_title=STALE_TITLE, key_full=STALE_UNASSESSED_BUILD, as_of=AS_OF)
    assert block.assessment == "unknown_app"
    assert block.counts is None
    assert block.corpus_as_of == date(2026, 9, 10)


def test_a_rowed_build_is_covered_with_the_epochs_own_numbers() -> None:
    corpus = LibraryCorpus(_library())
    block = vuln_block(corpus, key_title=WIRESHARK_TITLE, key_full=WIRESHARK_BUILD, as_of=AS_OF)
    assert block.assessment == "covered"
    assert block.counts.total == 17
    assert block.counts.severity.high == 9
    assert block.days_oldest_published.total == (AS_OF - date(2024, 1, 3)).days
    assert block.days_oldest_published.severity.critical is None
    assert block.vuln_ids[0] == "CVE-2025-1492"
    assert block.vuln_ids_truncated is False


def test_a_clean_row_is_covered_with_zero_which_is_a_clean_bill() -> None:
    block = vuln_block(LibraryCorpus(_library()), key_title="v1:whatever", key_full=CLEAN_BUILD, as_of=AS_OF)
    assert block.assessment == "covered"
    assert block.counts.total == 0
    assert block.vuln_ids == []
    assert block.days_oldest_published.total is None


# --- precomputed aggregates versus the finding-by-finding path --------------------------


def test_precomputed_aggregates_and_derived_findings_produce_the_same_block() -> None:
    """The widening, proved rather than asserted: for the same findings, the block built
    from a stored row is identical to the block built from the findings themselves. The
    wire does not move — only where the counting happened does."""

    findings = [
        VulnFinding(id="CVE-2026-0001", published=date(2026, 1, 5), severity="critical", kev=True),
        VulnFinding(id="CVE-2026-0002", published=date(2025, 6, 1), severity="high"),
        VulnFinding(id="CVE-2026-0003", published=date(2024, 3, 3), severity=None),
    ]

    class _Derived:
        as_of = date(2026, 9, 10)

        def findings(self, *, key_title: str, key_full: str):
            return findings

    class _Precomputed:
        as_of = date(2026, 9, 10)

        def findings(self, *, key_title: str, key_full: str):
            return AssessedBuild(
                total=3,
                kev=1,
                severity={"critical": 1, "high": 1, "medium": 0, "low": 0},
                oldest_published=date(2024, 3, 3),
                oldest_published_severity={
                    "critical": date(2026, 1, 5),
                    "high": date(2025, 6, 1),
                    "medium": None,
                    "low": None,
                },
                ids=("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"),
            )

    keys = {"key_title": "v1:t", "key_full": "v1:f"}
    derived = vuln_block(_Derived(), as_of=AS_OF, **keys)
    precomputed = vuln_block(_Precomputed(), as_of=AS_OF, **keys)
    assert precomputed.model_dump(by_alias=True) == derived.model_dump(by_alias=True)
    # And the reason the widening was needed at all: the total the row states survives a
    # capped list, where recounting the list would report the cap instead of the truth.
    assert derived.counts.total == 3


def test_a_capped_list_never_shortens_the_count_and_says_the_cap_bit() -> None:
    """`counts.total` is the uncapped truth (§4e). A row that names fewer ids than it
    counts is the normal case for a busy build, and the flag is what keeps this
    container's own cap free to move."""

    class _Corpus:
        as_of = date(2026, 9, 10)

        def findings(self, *, key_title: str, key_full: str):
            return AssessedBuild(
                total=120,
                kev=0,
                severity={"critical": 0, "high": 120, "medium": 0, "low": 0},
                oldest_published=date(2024, 1, 1),
                oldest_published_severity={"critical": None, "high": date(2024, 1, 1), "medium": None, "low": None},
                ids=tuple(f"CVE-2026-{index:04d}" for index in range(1, 51)),
                truncated=True,
            )

    block = vuln_block(_Corpus(), key_title="v1:t", key_full="v1:f", as_of=AS_OF)
    assert block.counts.total == 120
    assert len(block.vuln_ids) == 50
    assert block.vuln_ids_truncated is True
