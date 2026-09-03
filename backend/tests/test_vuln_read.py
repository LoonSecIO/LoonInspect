"""The corpus's edge on the read path — `assessment`, `corpusAsOf`, and three empty states
that never look alike (#251). Pure; no database.

The wire half is pinned by `test_vuln_block.py`. This suite pins the other half: what a
person's browser and a REST client are handed for the same three states, through the same
seam, under a fake corpus. Its whole job is #251's trap —

    `counts.total: 0` and "not assessed" must never render the same

— asserted at the layer a UI actually reads, because a component that treats a missing
block as zero has re-created the failure `assessment` was minted to prevent, in the surface
where nobody has a query to catch it.

Four things are held here:

* **the three shapes differ, by key set, not by value.** `off` carries `assessment` alone;
  `unknown_app` carries `assessment` and a date; `covered` carries every ruled key. So a
  renderer cannot confuse them even by accident, and the frontend union that mirrors these
  shapes has something to be a mirror of (`frontend/src/features/vulnerabilities/`);
* **the REST field names**, which are the wire's names — `vuln`, `corpusAsOf`,
  `daysOldestPublished`, `vulnIDs`, `vulnIDsTruncated` — so a person reading a Splunk event
  and a person reading the page use the same words;
* **the closed set**, refused rather than documented: `assessment` is a `Literal`, and an
  invented fourth state fails at construction;
* **the lookup is per row, on the row's own content keys**, once each, database untouched.

`StubCorpus` here is not a preview of #248's corpus; it is the smallest thing satisfying
the `VulnCorpus` protocol, which is all this suite is entitled to assume.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.api import devices as devices_api
from app.api.catalog import _answer, _assessed_entry_out, _entry_out
from app.api.devices import _assessed
from app.core.vuln import NO_CORPUS, VulnCorpus, VulnFinding, vuln_block
from app.core.vuln_read import assess, assess_all, corpus_as_of, today
from app.models.schema import AppCatalogEntry
from app.schemas.catalog import (
    CatalogEntryAssessedOut,
    CatalogEntryOut,
    CatalogListResponse,
    CatalogLookupOut,
    CatalogSummaryOut,
)
from app.schemas.devices import DeviceDetailOut, InstalledAppOut
from app.schemas.payload import VULN_ASSESSMENT_COVERED, VulnEnrichment

CORPUS_AS_OF = date(2026, 9, 1)
# The read path's "today" for every assertion below. Fixed rather than the wall clock: the
# day counts are arithmetic against it, and a suite that drifts with the date is a suite
# that fails on a Tuesday.
AS_OF = date(2026, 9, 3)

KNOWN_TITLE = "v1:title-known"
UNKNOWN_TITLE = "v1:title-unknown"
AFFECTED_BUILD = "v1:build-affected"
CLEAN_BUILD = "v1:build-clean"

# The keys a populated block carries and no others (docs/vulnerabilities.md §4), written
# out longhand here as they are in `test_vuln_block.py` — so the REST surface cannot grow a
# tenth key that nothing ruled, and cannot lose one either.
COVERED_KEYS = {"assessment", "corpusAsOf", "counts", "daysOldestPublished", "vulnIDs", "vulnIDsTruncated"}
UNKNOWN_KEYS = {"assessment", "corpusAsOf"}
OFF_KEYS = {"assessment"}

FINDINGS = (
    VulnFinding(id="CVE-2026-0001", published=date(2025, 8, 1), severity="critical", kev=True),
    VulnFinding(id="CVE-2026-0002", published=date(2026, 8, 20), severity="low"),
    # Unscored: in `counts.total` and in no band (§4). Present so the read path is asserted
    # against a corpus whose bands do not sum to the total.
    VulnFinding(id="LoonVD-2026-000001", published=date(2026, 7, 1)),
)


class StubCorpus:
    """Known titles, the builds this corpus positively assessed, and a record of what it
    was asked.

    §4f is obeyed rather than approximated: `()` is returned **only** for a build the
    corpus actually assessed and found clean. A known title whose build was never
    individually assessed answers `None` — `unknown_app` — because a `dict.get(key_full,
    ())` there reads exactly like a positive clean bill for a build nobody looked at.
    """

    def __init__(self, *, as_of: date | None = CORPUS_AS_OF) -> None:
        self.as_of = as_of
        self.calls: list[tuple[str, str]] = []

    def findings(self, *, key_title: str, key_full: str) -> Sequence[VulnFinding] | None:
        self.calls.append((key_title, key_full))
        if key_title != KNOWN_TITLE:
            return None
        if key_full == AFFECTED_BUILD:
            return FINDINGS
        return () if key_full == CLEAN_BUILD else None


class Row:
    """The only thing the read path asks of a row: the content keys every stored app
    already carries (`InstalledApp` and `AppCatalogEntry` both materialize them)."""

    def __init__(self, key_title: str, key_full: str, *, id: int = 1) -> None:
        self.id = id
        self.key_title = key_title
        self.key_full = key_full


OFF_ROW = Row(KNOWN_TITLE, AFFECTED_BUILD)
UNKNOWN_ROW = Row(UNKNOWN_TITLE, CLEAN_BUILD, id=2)
CLEAN_ROW = Row(KNOWN_TITLE, CLEAN_BUILD, id=3)
AFFECTED_ROW = Row(KNOWN_TITLE, AFFECTED_BUILD, id=4)
# A title the corpus knows, in a build it never assessed — §4f's common case, and the one
# a careless corpus turns into a clean bill.
UNASSESSED_BUILD_ROW = Row(KNOWN_TITLE, "v1:build-never-assessed", id=5)


@pytest.fixture
def corpus() -> StubCorpus:
    return StubCorpus()


@pytest.fixture
def loaded(corpus: StubCorpus, monkeypatch: pytest.MonkeyPatch) -> StubCorpus:
    """Make `loaded_corpus()` return the stub, for the endpoints that read it themselves.

    `_assessed` deliberately takes no corpus argument — it reads the one function that
    decides what this container has loaded, so #248 changes `loaded_corpus()` and the
    endpoint does not move. Testing it therefore means patching that function rather than
    reimplementing the two lines beside it: a test that calls its own copy of the code
    under test cannot catch the copy drifting.

    `today` is pinned at the same time so the day arithmetic is deterministic.
    """
    monkeypatch.setattr(devices_api, "loaded_corpus", lambda: corpus)
    monkeypatch.setattr(devices_api, "today", lambda: AS_OF)
    return corpus


def _rest(block: VulnEnrichment) -> dict:
    """The block as a REST client receives it: by alias, JSON types."""
    return block.model_dump(mode="json", by_alias=True)


class TestTheThreeStatesAreDistinguishable:
    """#251's trap, asserted at the shape rather than at a rendering: the three answers
    differ in which keys exist, so no reader has to know the vocabulary to tell them
    apart, and none of the three can be mistaken for another by a `?? 0`."""

    def test_off_is_the_whole_block_and_carries_no_date(self) -> None:
        block = _rest(assess(NO_CORPUS, OFF_ROW, as_of=AS_OF))
        assert block == {"assessment": "off"}
        assert set(block) == OFF_KEYS
        # The three absences that matter: no date to render, no count to read as zero, no
        # id list to render as "none found".
        assert "corpusAsOf" not in block and "counts" not in block and "vulnIDs" not in block

    def test_unknown_app_is_dated_and_never_zero(self, corpus: StubCorpus) -> None:
        block = _rest(assess(corpus, UNKNOWN_ROW, as_of=AS_OF))
        assert block == {"assessment": "unknown_app", "corpusAsOf": "2026-09-01"}
        assert set(block) == UNKNOWN_KEYS
        # The failure this whole issue exists to prevent: a surface reading a missing block
        # as zero. There is nothing here to read as zero.
        assert "counts" not in block

    def test_covered_with_nothing_found_is_a_clean_bill_and_says_when(self, corpus: StubCorpus) -> None:
        block = _rest(assess(corpus, CLEAN_ROW, as_of=AS_OF))
        assert set(block) == COVERED_KEYS
        assert block["assessment"] == "covered" and block["corpusAsOf"] == "2026-09-01"
        assert block["counts"]["total"] == 0 and block["vulnIDs"] == []
        # `-1` is the Splunk dialect's *never* and is minted at the HEC seam alone (§4c);
        # a REST client gets the canonical null and never casts it.
        assert block["daysOldestPublished"]["total"] is None
        assert set(block["daysOldestPublished"]["severity"].values()) == {None}

    def test_covered_with_findings_carries_the_ruled_summary(self, corpus: StubCorpus) -> None:
        block = _rest(assess(corpus, AFFECTED_ROW, as_of=AS_OF))
        assert set(block) == COVERED_KEYS
        assert block["counts"] == {
            "total": 3,
            "kev": 1,
            # Bands need not sum to `total`: the unscored `LoonVD-` finding is in the total
            # and in no band (§4).
            "severity": {"critical": 1, "high": 0, "medium": 0, "low": 1},
        }
        assert block["daysOldestPublished"]["total"] == (AS_OF - date(2025, 8, 1)).days
        assert block["daysOldestPublished"]["severity"] == {
            "critical": (AS_OF - date(2025, 8, 1)).days,
            "high": None,
            "medium": None,
            "low": (AS_OF - date(2026, 8, 20)).days,
        }
        # KEV first, then severity band, then recency (§4e).
        assert block["vulnIDs"] == ["CVE-2026-0001", "CVE-2026-0002", "LoonVD-2026-000001"]
        assert block["vulnIDsTruncated"] is False

    def test_a_known_title_in_an_unassessed_build_reads_unknown_app_on_the_page_too(
        self, corpus: StubCorpus
    ) -> None:
        """§4f, carried through to the surface: `()` means *positively assessed*, so a
        build the corpus never looked at reaches a person as `Outside the corpus`, dated —
        not as a green clean bill. The read path adds nothing here; it must also subtract
        nothing."""
        block = _rest(assess(corpus, UNASSESSED_BUILD_ROW, as_of=AS_OF))
        assert block == {"assessment": "unknown_app", "corpusAsOf": "2026-09-01"}

    def test_a_zero_findings_covered_app_and_an_off_app_share_no_shape(self, corpus: StubCorpus) -> None:
        """The one assertion #251 names outright. Three renderings, three key sets, and
        `covered` is the only one of the three where a number exists at all — so "we looked
        and found nothing" and "nobody looked" cannot collapse into one cell."""
        clean = _rest(assess(corpus, CLEAN_ROW, as_of=AS_OF))
        off = _rest(assess(NO_CORPUS, CLEAN_ROW, as_of=AS_OF))
        unknown = _rest(assess(corpus, UNKNOWN_ROW, as_of=AS_OF))
        assert clean != off and clean != unknown and off != unknown
        assert set(clean) != set(off) and set(clean) != set(unknown) and set(off) != set(unknown)
        assert [answer["assessment"] for answer in (clean, off, unknown)] == ["covered", "off", "unknown_app"]
        # And the date: present exactly where an answer was given, absent where none was.
        assert clean["corpusAsOf"] == unknown["corpusAsOf"] == "2026-09-01"
        assert "corpusAsOf" not in off


class TestTheVocabularyIsClosed:
    def test_a_fourth_assessment_is_refused_at_construction(self) -> None:
        """`assessment` is a `Literal`, not a string, so the OpenAPI schema is an enum of
        three and a typo cannot reach a page as a fourth state nothing renders."""
        with pytest.raises(ValidationError):
            VulnEnrichment(assessment="unknownApp")  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            VulnEnrichment(assessment="unknown")  # type: ignore[arg-type]

    def test_unknown_app_stays_snake_case(self, corpus: StubCorpus) -> None:
        """§4b: values are not governed by the camelCase law, and this one is the ruled
        spelling. A conformance sweep that "fixes" it breaks every saved search."""
        assert assess(corpus, UNKNOWN_ROW, as_of=AS_OF).assessment == "unknown_app"

    def test_zero_beside_unknown_app_cannot_be_constructed(self) -> None:
        """The trap, refused one layer below the UI as well: the model will not hold a
        count next to an assessment that did not earn one."""
        with pytest.raises(ValidationError):
            VulnEnrichment.model_validate(
                {
                    "assessment": "unknown_app",
                    "corpus_as_of": CORPUS_AS_OF,
                    "counts": {"total": 0, "kev": 0, "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}},
                }
            )


class TestTheLookup:
    def test_one_question_per_row_on_the_row_s_own_keys(self, corpus: StubCorpus) -> None:
        rows = [AFFECTED_ROW, UNKNOWN_ROW, CLEAN_ROW]
        blocks = assess_all(corpus, rows, as_of=AS_OF)
        assert [block.assessment for block in blocks] == ["covered", "unknown_app", "covered"]
        assert corpus.calls == [(row.key_title, row.key_full) for row in rows]

    def test_two_rows_of_one_title_answer_separately(self, corpus: StubCorpus) -> None:
        """A catalog page holds two versions of one app and a device can carry two builds
        of one. The corpus answers per build, so the read path must not key its work on
        anything a pair of rows can share."""
        blocks = assess_all(corpus, [AFFECTED_ROW, CLEAN_ROW], as_of=AS_OF)
        assert blocks[0].counts.total == 3 and blocks[1].counts.total == 0
        assert len(corpus.calls) == 2

    def test_no_corpus_asks_nothing_at_all(self) -> None:
        """`NO_CORPUS` short-circuits on `as_of is None`, so the container every customer
        runs today does no per-row work — which is what makes a per-request read path
        honest against "cache, don't calculate" while the corpus is empty."""
        asked = StubCorpus(as_of=None)
        assert [block.assessment for block in assess_all(asked, [AFFECTED_ROW, CLEAN_ROW], as_of=AS_OF)] == [
            "off",
            "off",
        ]
        assert asked.calls == []

    def test_the_stamp_and_the_rows_come_from_one_object(self, corpus: StubCorpus) -> None:
        """A header cannot disagree with the column under it: both read `as_of` off the
        same corpus in the same request."""
        assert corpus_as_of(corpus) == CORPUS_AS_OF
        assert assess(corpus, CLEAN_ROW, as_of=AS_OF).corpus_as_of == CORPUS_AS_OF
        assert corpus_as_of(NO_CORPUS) is None

    def test_the_read_path_s_clock_is_today(self) -> None:
        """§4d's second clock. The wire pins `as_of` to the event's `occurredAt` because an
        event is a historical record and ten retries must expand to identical bytes; a page
        answers *how old is this now*, so it counts from today."""
        assert today() == datetime.now(timezone.utc).date()

    def test_the_two_clocks_diverge_by_the_age_of_the_newest_snapshot(self, corpus: StubCorpus) -> None:
        """The consequence §4d and §4g now state, pinned so it cannot be discovered in the
        field: the same app reads a different `daysOldestPublished` on the page than in the
        event, and the gap is the age of that device's newest snapshot — **not** the sync
        gap, and unbounded once a device stops checking in.

        200 days here is a device dark for over six months: the event is still a true
        record of what was so when it was taken, and the page is still the true age today.
        Both clocks floor at zero and leave `None` for never; only the basis differs — which
        is why the gap below is read off `total`, whose oldest finding predates both dates,
        rather than off a band whose only finding is newer than the stale event and floors.
        """
        stale_event_day = AS_OF - timedelta(days=200)
        on_the_page = assess(corpus, AFFECTED_ROW, as_of=AS_OF)
        in_the_event = vuln_block(
            corpus, key_title=AFFECTED_ROW.key_title, key_full=AFFECTED_ROW.key_full, as_of=stale_event_day
        )
        assert on_the_page.days_oldest_published.total - in_the_event.days_oldest_published.total == 200
        # Everything else is the same value in both — the clock is the whole difference.
        assert on_the_page.counts == in_the_event.counts
        assert on_the_page.vuln_ids == in_the_event.vuln_ids
        assert on_the_page.assessment == in_the_event.assessment == VULN_ASSESSMENT_COVERED


class TestTheRestSurface:
    """The field names a client binds to. Additive, camelCase like the rest of the REST
    layer, and the same words the wire uses."""

    def test_an_installed_app_carries_vuln_and_defaults_to_off(self) -> None:
        app = InstalledAppOut(
            id=1,
            name="Wireshark.app",
            bundle_id="org.wireshark.Wireshark",
            version="4.2.0",
            short_version=None,
            app_hash="a" * 32,
            version_hash="b" * 32,
            is_compliant=None,
            patch_available=None,
            patch_available_since=None,
            last_patch_check_at=None,
        )
        payload = app.model_dump(mode="json", by_alias=True)
        # Present, not absent: a client that finds no `vuln` key cannot tell an old server
        # from an unassessed app, and the default is the honest answer either way.
        assert payload["vuln"] == {"assessment": "off"}

    def test_the_device_detail_stamps_every_app_and_the_header(self, loaded: StubCorpus) -> None:
        detail = DeviceDetailOut(
            id=7,
            mdm_provider="jamf",
            mdm_connection_id=1,
            external_id="7",
            serial_number="C02XX",
            hostname="mini",
            last_seen_at=None,
            last_check_in=None,
            last_inventory_at=None,
            managed=True,
            supervised=True,
            os_version="26.0",
            site=None,
            building_id=None,
            department_id=None,
            apps=[
                InstalledAppOut(
                    id=row.id,
                    name=f"app-{row.id}",
                    bundle_id=f"com.example.{row.id}",
                    version="1.0",
                    short_version=None,
                    app_hash="a" * 32,
                    version_hash="b" * 32,
                    is_compliant=None,
                    patch_available=None,
                    patch_available_since=None,
                    last_patch_check_at=None,
                )
                # Deliberately not in row order: `_assessed` pairs by id, because
                # `selectinload` promises no order and a block on the wrong app looks right.
                for row in (CLEAN_ROW, AFFECTED_ROW, UNKNOWN_ROW)
            ],
        )
        # The real `_assessed`, under a corpus that can tell the rows apart — the rows
        # handed in are in a THIRD order, so a positional pairing would mis-assign every
        # block and the assertions below would catch it.
        payload = _assessed(detail, [AFFECTED_ROW, UNKNOWN_ROW, CLEAN_ROW]).model_dump(mode="json", by_alias=True)
        assert payload["corpusAsOf"] == "2026-09-01"
        assert [app["id"] for app in payload["apps"]] == [CLEAN_ROW.id, AFFECTED_ROW.id, UNKNOWN_ROW.id]
        assert [app["vuln"]["assessment"] for app in payload["apps"]] == ["covered", "covered", "unknown_app"]
        assert payload["apps"][0]["vuln"]["counts"]["total"] == 0  # CLEAN_ROW, id 3
        assert payload["apps"][1]["vuln"]["counts"]["total"] == 3  # AFFECTED_ROW, id 4
        # Every app asked exactly once, on its own keys — no row answered twice, none skipped.
        assert sorted(loaded.calls) == sorted(
            (row.key_title, row.key_full) for row in (CLEAN_ROW, AFFECTED_ROW, UNKNOWN_ROW)
        )

    def test_the_device_detail_says_off_with_no_date_when_no_corpus_is_loaded(self) -> None:
        detail = _assessed(
            DeviceDetailOut(
                id=7,
                mdm_provider="jamf",
                mdm_connection_id=1,
                external_id="7",
                serial_number="C02XX",
                hostname="mini",
                last_seen_at=None,
                last_check_in=None,
                last_inventory_at=None,
                managed=True,
                supervised=True,
                os_version="26.0",
                site=None,
                building_id=None,
                department_id=None,
                apps=[
                    InstalledAppOut(
                        id=AFFECTED_ROW.id,
                        name="app",
                        bundle_id="com.example",
                        version="1.0",
                        short_version=None,
                        app_hash="a" * 32,
                        version_hash="b" * 32,
                        is_compliant=None,
                        patch_available=None,
                        patch_available_since=None,
                        last_patch_check_at=None,
                    )
                ],
            ),
            [AFFECTED_ROW],
        )
        payload = detail.model_dump(mode="json", by_alias=True)
        # The state every container ships with, and it is honest rather than broken: the
        # page says "not assessed — no corpus loaded" and dates it with nothing.
        assert payload["corpusAsOf"] is None
        assert payload["apps"][0]["vuln"] == {"assessment": "off"}

    def test_a_catalog_entry_carries_the_corpus_s_answer_for_that_build(self, corpus: StubCorpus) -> None:
        out = _assessed_entry_out(_catalog_row(AFFECTED_ROW), 12, {}, corpus=corpus, as_of=AS_OF)
        payload = out.model_dump(mode="json", by_alias=True)
        assert payload["deviceCount"] == 12
        assert payload["vuln"]["assessment"] == "covered"
        assert payload["vuln"]["counts"]["kev"] == 1
        assert payload["vuln"]["corpusAsOf"] == "2026-09-01"

    def test_a_catalog_entry_outside_the_corpus_is_dated_and_uncounted(self, corpus: StubCorpus) -> None:
        payload = _assessed_entry_out(_catalog_row(UNKNOWN_ROW), 1, {}, corpus=corpus, as_of=AS_OF).model_dump(
            mode="json", by_alias=True
        )
        assert payload["vuln"] == {"assessment": "unknown_app", "corpusAsOf": "2026-09-01"}

    def test_the_catalog_list_carries_the_header_stamp_and_defaults_to_none(self) -> None:
        response = CatalogListResponse(
            items=[], total=0, summary=CatalogSummaryOut(entries=0, installed=0, matched=0, unmatched=0)
        )
        payload = response.model_dump(mode="json", by_alias=True)
        assert payload["corpusAsOf"] is None
        # The summary counts rows, not assessments: counting `covered` / `unknown_app` /
        # `off` across the whole catalog is a scan per request, and those counts are
        # #250's off the join #248 stores. Asserted so nobody adds them here by reflex.
        assert set(payload["summary"]) == {"entries", "installed", "matched", "unmatched"}

    def test_openapi_documents_the_block_rather_than_an_opaque_object(self) -> None:
        """FastAPI generates the response schema in serialization mode, and a model with a
        custom serializer defaults to `{"type": "object", "additionalProperties": true}` —
        which documents nothing to a client written against the spec. `VulnEnrichment`
        overrides `__get_pydantic_json_schema__` to describe the keys it actually has, and
        this is what says the override still works after a pydantic upgrade."""
        schema = VulnEnrichment.model_json_schema(mode="serialization")
        assert set(schema["properties"]) == COVERED_KEYS
        # The closed set reaches the spec as an enum of three, not as a free string.
        assert schema["properties"]["assessment"]["enum"] == ["covered", "unknown_app", "off"]
        assert schema["properties"]["assessment"]["default"] == "off"
        assert schema.get("additionalProperties") is not True

    def test_the_lookup_never_answers_an_assessment_for_a_build_it_was_not_asked_about(
        self, corpus: StubCorpus
    ) -> None:
        """`/api/catalog/lookup` answers by `appHash` as well as by build, and under
        `appHash` the row it returns stands in for the newest version the tenant has seen —
        a different build from the caller's. Two builds of one title differ here on
        purpose: the newest is clean, the one a caller might hold is affected.

        Shipping the newest build's clean bill as the title's answer is §4a's failure one
        grain out. It is refused by the type rather than avoided by care: the lookup's
        `tenant` is the base `CatalogEntryOut`, which has no `vuln` field at all.
        """
        newest, held = _catalog_row(CLEAN_ROW), _catalog_row(AFFECTED_ROW)
        # Same title, different builds, and the corpus genuinely disagrees about them.
        assert newest.key_title == held.key_title and newest.key_full != held.key_full
        assert assess(corpus, newest, as_of=AS_OF).counts.total == 0
        assert assess(corpus, held, as_of=AS_OF).counts.total == 3

        # The stand-in as the endpoint builds it, through the real `_answer`.
        stand_in = _entry_out(newest, 3, {})
        payload = _answer("some-app-hash", stand_in, []).model_dump(mode="json", by_alias=True)
        assert "vuln" not in payload
        assert "vuln" not in payload["tenant"]
        assert "corpusAsOf" not in payload
        # And structurally, so a later edit cannot put it back by handing `_answer` a
        # different model: the type the lookup returns has no such field.
        assert "vuln" not in CatalogEntryOut.model_fields
        assert "vuln" not in CatalogLookupOut.model_fields

    def test_the_list_still_answers_per_build(self, corpus: StubCorpus) -> None:
        """The other half of the same rule: a catalog row IS its own build, so it carries
        the assessment, and two builds of one title do not share an answer."""
        rows = [_catalog_row(CLEAN_ROW), _catalog_row(AFFECTED_ROW)]
        items = [_assessed_entry_out(row, 1, {}, corpus=corpus, as_of=AS_OF) for row in rows]
        assert [item.vuln.counts.total for item in items] == [0, 3]
        assert "vuln" in CatalogEntryAssessedOut.model_fields

    def test_the_rest_block_is_the_wire_block(self, corpus: StubCorpus) -> None:
        """One model, not two. The REST field IS `VulnEnrichment`, so the page and the
        Splunk event cannot drift apart in vocabulary — there is no second place for the
        vocabulary to live."""
        entry = _assessed_entry_out(_catalog_row(AFFECTED_ROW), 1, {}, corpus=corpus, as_of=AS_OF)
        assert isinstance(entry.vuln, VulnEnrichment)
        assert entry.vuln.model_dump(mode="json", by_alias=True) == _rest(
            assess(corpus, AFFECTED_ROW, as_of=AS_OF)
        )
        assert CatalogEntryAssessedOut.model_fields["vuln"].annotation is VulnEnrichment


def _catalog_row(row: Row) -> AppCatalogEntry:
    """A transient `app_catalog` row — never added to a session, so this stays in the pure
    lane. `_entry_out` reads it through `model_validate`, exactly as the endpoint does."""
    seen = datetime(2026, 9, 1, tzinfo=timezone.utc)
    return AppCatalogEntry(
        id=row.id,
        name="Wireshark.app",
        bundle_id="org.wireshark.Wireshark",
        version="4.2.0",
        short_version=None,
        app_hash="a" * 32,
        version_hash="b" * 32,
        key_title=row.key_title,
        key_full=row.key_full,
        first_seen_at=seen,
        last_seen_at=seen,
    )


def test_the_seam_is_the_one_the_wire_uses() -> None:
    """No second lookup. The read path calls `app.core.vuln.vuln_block` through
    `app.core.vuln_read`, over the same `VulnCorpus` protocol #248 implements once."""
    assert isinstance(NO_CORPUS, VulnCorpus)
    assert isinstance(StubCorpus(), VulnCorpus)
