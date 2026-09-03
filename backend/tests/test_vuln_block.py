"""`vuln{}` on the app sub-event, over the real fixture (#249). Pure; no database.

The contract is `docs/vulnerabilities.md` §3 and §4, and this suite is the place its rules are
made unbreakable rather than described. It drives the same path `process_sync` takes —
the ledger's observation and the installed-app rows through `build_inventory_snapshot`,
then the stored payload through the Splunk fan-out — under three corpora, because the
block's whole design is that its three states are distinguishable:

* **`off`** — no corpus loaded. The block is byte-identical to what #241 and #242 shipped;
* **`unknown_app`** — a corpus that does not know the app. Dated, and **never** zero
  vulnerabilities: the counts, the days and the id list are absent, not zero (§4a);
* **`covered`** — every ruled key, `counts.total: 0` meaning a clean bill because
  `covered` says we looked.

And the four things #249 says a reviewer will check: the summary's sourcetype is
`loon:jamf:mac:app` and never the reserved compound leaf; every number is scoped to this
app on this device; absence under the two non-`covered` states; and `-1` minted at the
HEC-shaping seam rather than upstream, with the invariant
`daysOldestPublished.severity.X >= 0 <=> counts.severity.X > 0` asserted in both
directions.

The corpus itself is #248's. `StubCorpus` here is not a preview of it — it is the
smallest thing that satisfies the `VulnCorpus` protocol, which is exactly what this suite
is entitled to assume.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from copy import deepcopy
from datetime import date, timedelta

import pytest
from pydantic import ValidationError

from app.core.content_keys import app_full_key, app_title_key
from app.core.hec_fanout import fan_out
from app.core.outbox import hec_events
from app.core.vuln import (
    LOCAL_PREFIX,
    NEVER,
    NO_CORPUS,
    SEVERITY_BANDS,
    VULN_IDS_CAP,
    VulnCorpus,
    VulnFinding,
    loaded_corpus,
    mint_hec_sentinels,
    vuln_block,
)
from app.core.wire import ENVELOPE, envelope
from app.core.wire_vocabulary import enrichment_rows, registry_rows, sourcetype
from app.schemas.payload import (
    VULN_ASSESSMENT_COVERED,
    VULN_ASSESSMENT_OFF,
    VULN_ASSESSMENT_UNKNOWN_APP,
    VulnCounts,
    VulnDaysOldestPublished,
    VulnEnrichment,
    VulnSeverityCounts,
    VulnSeverityDays,
)
from tests.test_inventory_snapshot import (  # noqa: F401  (`raw` and `run` are fixtures)
    _RUN_ID,
    _WINDOW,
    _snapshot,
    raw,
    run,
)

# The corpus generation the stub stamps. A date, not a datetime: a hand-refreshed corpus
# has a generation, not an instant (§4).
CORPUS_AS_OF = date(2026, 9, 1)
# The one app of the real fixture this suite lets the corpus know. Wireshark is the
# standing fixture for the corpus itself (#248, §2) and is not on this Mac mini's 83; the
# join is keyed on a content key, so which app plays the part changes nothing here.
KNOWN_BUNDLE_ID = "com.apple.Maps"
SOURCE = "e2e.jamfcloud.com"

# The keys a populated block carries, and only these (§4). Written out rather than derived
# from the model, so the model cannot quietly grow a key that nothing ruled.
COVERED_KEYS = {"assessment", "corpusAsOf", "counts", "daysOldestPublished", "vulnIDs", "vulnIDsTruncated"}
BANDS = ("critical", "high", "medium", "low")

_CAMEL = re.compile(r"^[a-z][A-Za-z0-9]*$")
_LOWERCASE_ID_TOKEN = re.compile(r"Id(?:[A-Z]|$)")

# Measured on 2026-09-03 against the real fixture, in the two shapes a loaded corpus can
# put on the wire. `test_hec_fanout.py` pins the shipped request at 85,000 bytes measured
# under `off`; both numbers below are above it, so they are pinned HERE rather than by
# raising that ceiling — the wire that ships is still the one that ceiling guards, and
# #248 is the change that turns these on.
#
# `unknown_app` on every app: 86,957 bytes, +2,822 on `off` (54 bytes a block against 20).
# Every app `covered` at the full fifty-id cap — the worst shape v0 can take: 171,036
# bytes, 2.03x `off`, of which the blocks are 1,067 bytes each. Ceilings carry ~1%.
UNKNOWN_REQUEST_CEILING = 87_500
COVERED_REQUEST_CEILING = 173_000
COVERED_APP_SUB_EVENT_CEILING = 1_900
COVERED_BLOCK_CEILING = 1_100


class StubCorpus:
    """The smallest thing that is a `VulnCorpus`: a set of known titles and findings per
    build. #248 ships the real one; nothing here previews its format."""

    def __init__(
        self,
        *,
        as_of: date | None = CORPUS_AS_OF,
        titles: Sequence[str] = (),
        builds: dict[str, Sequence[VulnFinding]] | None = None,
    ) -> None:
        self.as_of = as_of
        self._titles = set(titles)
        self._builds = builds or {}
        self.calls: list[tuple[str, str]] = []

    def findings(self, *, key_title: str, key_full: str) -> Sequence[VulnFinding] | None:
        self.calls.append((key_title, key_full))
        if key_title not in self._titles:
            return None
        return self._builds.get(key_full, ())


def _keys(payload: dict, bundle_id: str) -> tuple[str, str]:
    """The content-key pair for one app of the fixture, computed the way the row carries
    it — the same pair `content_keys()` reads off the `installed_apps` row."""
    (app,) = [item["app"] for item in payload["app"] if item["app"].get("bundleId") == bundle_id]
    return (
        app_title_key(app["name"], app["bundleId"]),
        app_full_key(app["name"], app["bundleId"], app["version"], None),
    )


def _finding(id_: str, *, days_old: int, severity: str | None = "high", kev: bool = False) -> VulnFinding:
    return VulnFinding(id=id_, published=_WINDOW.date() - timedelta(days=days_old), severity=severity, kev=kev)


def _covered_corpus(payload: dict, findings: Sequence[VulnFinding], *, as_of: date = CORPUS_AS_OF) -> StubCorpus:
    key_title, key_full = _keys(payload, KNOWN_BUNDLE_ID)
    return StubCorpus(as_of=as_of, titles=[key_title], builds={key_full: list(findings)})


def _block(payload: dict, bundle_id: str = KNOWN_BUNDLE_ID) -> dict:
    (item,) = [item for item in payload["app"] if item["app"].get("bundleId") == bundle_id]
    return item["vuln"]


def _stored(payload: dict) -> dict:
    """The outbox row as `process_sync` stores it: the snapshot plus the envelope hints."""
    return {**payload, ENVELOPE: envelope(occurred_at=_WINDOW, host="Loon’s Mac mini", source=SOURCE)}


def _app_sub_events(payload: dict) -> list[dict]:
    return [event for event in hec_events(_stored(payload)) if "app" in event["event"]]


# --- `off`: byte-identical to what ships today ---------------------------------------


def test_with_no_corpus_every_app_reads_off_and_nothing_else(raw: dict, run) -> None:  # noqa: F811
    """The container ships `NO_CORPUS`, so the block is exactly the constant #241 and #242
    were told to emit — `{"assessment": "off"}` and nothing beside it — and the whole
    snapshot is byte-identical to the one built before this issue existed. `off` is a
    property of the pod (unlicensed, unconsented, no corpus loaded), so it is the same
    answer for all 83 apps or for none of them."""
    payload = _snapshot(raw)
    assert loaded_corpus() is NO_CORPUS
    assert NO_CORPUS.as_of is None
    assert [item["vuln"] for item in payload["app"]] == [{"assessment": VULN_ASSESSMENT_OFF}] * 83
    assert json.dumps(payload, sort_keys=True) == json.dumps(_snapshot(raw, corpus=NO_CORPUS), sort_keys=True)


def test_off_never_asks_the_corpus_anything(raw: dict, run) -> None:  # noqa: F811
    """`as_of is None` short-circuits before the lookup: a corpus that is not loaded is
    never consulted, so an unlicensed pod cannot leak a lookup either."""
    corpus = StubCorpus(as_of=None, titles=["anything"])
    payload = _snapshot(raw, corpus=corpus)
    assert corpus.calls == []
    assert {json.dumps(item["vuln"]) for item in payload["app"]} == {'{"assessment": "off"}'}


# --- `unknown_app`: dated, and never zero --------------------------------------------


def test_an_app_the_corpus_does_not_know_is_unknown_app_dated_and_never_zero(raw: dict, run) -> None:  # noqa: F811
    """§4a, the rule that was a correctness bug waiting to happen: `counts.total: 0` beside
    `assessment: unknown_app` hands a careless `stats sum(vuln.counts.total)` a clean bill
    for a fleet nobody assessed. The block carries the discriminator and the date and
    NOTHING else — and the date is what makes a small corpus honest, because its edge is
    countable and stamped."""
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-0001", days_old=10)]))
    unknown = [item["vuln"] for item in payload["app"] if item["app"].get("bundleId") != KNOWN_BUNDLE_ID]
    assert len(unknown) == 82
    for block in unknown:
        assert block == {"assessment": VULN_ASSESSMENT_UNKNOWN_APP, "corpusAsOf": "2026-09-01"}
        assert not {"counts", "daysOldestPublished", "vulnIDs", "vulnIDsTruncated"} & set(block)
    # And the zero is nowhere in the serialised event either — not as a count, not as a
    # `-1` day, not as an empty list.
    assert '"counts"' not in json.dumps(unknown)


def test_the_sum_a_careless_search_runs_counts_only_the_apps_that_were_assessed(raw: dict, run) -> None:  # noqa: F811
    """The failure §4a exists to prevent, stated as the search that would hit it:
    `stats sum(vuln.counts.total)` over one device's app sub-events sees three findings
    from the one assessed app and no contribution at all from the 82 nobody looked at."""
    payload = _snapshot(
        raw,
        corpus=_covered_corpus(
            _snapshot(raw),
            [_finding(f"CVE-2026-000{n}", days_old=n) for n in (1, 2, 3)],
        ),
    )
    totals = [item["vuln"].get("counts", {}).get("total") for item in payload["app"]]
    assert sum(total for total in totals if total is not None) == 3
    assert totals.count(None) == 82


# --- `covered`: the ruled keys, typed --------------------------------------------------


def test_a_covered_app_carries_every_contract_key_and_only_those(raw: dict, run) -> None:  # noqa: F811
    """§4's table, key for key and type for type, on the canonical payload. Every number is
    scoped to this app on this device — the corpus was asked about one build and answered
    about one build."""
    findings = [
        _finding("CVE-2026-1000", days_old=400, severity="critical", kev=True),
        _finding("CVE-2026-1001", days_old=30, severity="high"),
        _finding("CVE-2026-1002", days_old=10, severity="low"),
        _finding("LoonVD-2026-000001", days_old=5, severity=None),
    ]
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), findings))
    block = _block(payload)
    assert set(block) == COVERED_KEYS
    assert block["assessment"] == VULN_ASSESSMENT_COVERED == "covered"
    assert block["corpusAsOf"] == "2026-09-01"
    assert block["counts"] == {
        "total": 4,
        "kev": 1,
        "severity": {"critical": 1, "high": 1, "medium": 0, "low": 1},
    }
    # Bands do not sum to total: the unscored LoonVD finding is in `total` and in no band.
    assert sum(block["counts"]["severity"].values()) == 3 < block["counts"]["total"]
    assert block["daysOldestPublished"] == {
        "total": 400,
        "severity": {"critical": 400, "high": 30, "medium": None, "low": 10},
    }
    assert block["vulnIDs"] == ["CVE-2026-1000", "CVE-2026-1001", "CVE-2026-1002", "LoonVD-2026-000001"]
    assert block["vulnIDsTruncated"] is False
    for key, kind in (("total", int), ("kev", int)):
        assert isinstance(block["counts"][key], kind)
    assert all(isinstance(value, int) for value in block["counts"]["severity"].values())


def test_a_clean_bill_is_covered_with_zero_an_empty_list_and_never_everywhere(raw: dict, run) -> None:  # noqa: F811
    """§4: "A clean bill is `assessment: covered` with `counts.total: 0`, an empty
    `vulnIDs`, and `-1` in every `daysOldestPublished`. That is honest precisely because
    `covered` says we looked." Canonically the days are `None`; the `-1` is minted at the
    HEC seam below."""
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), []))
    block = _block(payload)
    assert set(block) == COVERED_KEYS
    assert block["counts"] == {"total": 0, "kev": 0, "severity": dict.fromkeys(BANDS, 0)}
    assert block["daysOldestPublished"] == {"total": None, "severity": dict.fromkeys(BANDS, None)}
    assert block["vulnIDs"] == [] and block["vulnIDsTruncated"] is False
    # And it is NOT the same event as `unknown_app`: this one says a corpus looked.
    assert block["assessment"] != _block(_snapshot(raw, corpus=StubCorpus()))["assessment"]


def test_kev_is_a_flag_and_not_a_fifth_band(raw: dict, run) -> None:  # noqa: F811
    """§4: `counts.kev` is CISA's list, "Not a severity band". A KEV finding is counted in
    `kev` AND in whatever band it carries, so the two overlap by design."""
    payload = _snapshot(
        raw,
        corpus=_covered_corpus(
            _snapshot(raw),
            [_finding("CVE-2026-2000", days_old=3, severity="critical", kev=True)],
        ),
    )
    counts = _block(payload)["counts"]
    assert counts == {"total": 1, "kev": 1, "severity": {"critical": 1, "high": 0, "medium": 0, "low": 0}}


# --- the clock -------------------------------------------------------------------------


def test_days_oldest_published_counts_from_publication_not_from_when_we_learned_of_it(raw: dict, run) -> None:  # noqa: F811
    """§4d, the ruling that is #68's clock in a second domain. Two corpora with the same
    findings and different generations answer identically — so the number cannot measure
    our refresh cadence — and moving the finding's publication date is what moves it."""
    old = _finding("CVE-2020-0001", days_old=2000, severity="high")
    fresh_corpus = _covered_corpus(_snapshot(raw), [old], as_of=date(2026, 9, 1))
    stale_corpus = _covered_corpus(_snapshot(raw), [old], as_of=date(2026, 1, 1))
    fresh = _block(_snapshot(raw, corpus=fresh_corpus))
    stale = _block(_snapshot(raw, corpus=stale_corpus))
    assert fresh["daysOldestPublished"] == stale["daysOldestPublished"] == {
        "total": 2000,
        "severity": {"critical": None, "high": 2000, "medium": None, "low": None},
    }
    assert fresh["corpusAsOf"] != stale["corpusAsOf"], "only the generation stamp moved"

    recent = _block(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-3000", days_old=7)])))
    assert recent["daysOldestPublished"]["total"] == 7


def test_the_clock_is_the_events_own_instant_not_the_wall_clock(raw: dict, run) -> None:  # noqa: F811
    """The builder is pure and clock-free, and delivery is retried against the stored row
    up to ten times — so a day boundary crossed between attempts must not change the
    bytes. `daysOldestPublished` is therefore measured from the snapshot's `occurredAt`."""
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-4000", days_old=100)]))
    assert _block(payload)["daysOldestPublished"]["total"] == 100
    assert json.loads(json.dumps(payload))["occurredAt"].startswith("2026-09-02")


def test_a_publication_date_after_the_event_reads_zero_not_a_negative(raw: dict, run) -> None:  # noqa: F811
    """A snapshot replayed out of the retention window against a corpus refreshed since.
    Zero, never a negative — `-1` already means *never* (§4c) and a negative day count
    would collide with the sentinel the moment the HEC seam mints it."""
    future = VulnFinding(id="CVE-2027-0001", published=_WINDOW.date() + timedelta(days=30), severity="high")
    block = _block(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [future])))
    assert block["daysOldestPublished"]["total"] == 0
    assert block["daysOldestPublished"]["severity"]["high"] == 0


# --- the cap ---------------------------------------------------------------------------


def test_the_cap_bites_at_fifty_in_the_ruled_priority_order(raw: dict, run) -> None:  # noqa: F811
    """§4e: ~50 ids, priority KEV -> severity -> recency, and the cap is a server-side
    number rather than a wire key — safe only because `vulnIDsTruncated` says when it bit.
    The counts do NOT cap: `counts.total` is every finding, so a truncated list never
    under-reports the number."""
    findings = [
        _finding("CVE-2026-9001", days_old=900, severity="low", kev=True),
        _finding("CVE-2026-9002", days_old=800, severity="critical"),
        *[_finding(f"CVE-2026-8{n:03d}", days_old=n, severity="medium") for n in range(60)],
    ]
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), findings))
    block = _block(payload)
    assert block["counts"]["total"] == 62
    assert len(block["vulnIDs"]) == VULN_IDS_CAP == 50
    assert block["vulnIDsTruncated"] is True
    # KEV first even though it is the lowest band and not the newest; then the critical;
    # then the mediums newest-first.
    assert block["vulnIDs"][:4] == ["CVE-2026-9001", "CVE-2026-9002", "CVE-2026-8000", "CVE-2026-8001"]


def test_exactly_the_cap_does_not_set_the_flag(raw: dict, run) -> None:  # noqa: F811
    """The flag says the cap BIT, not that the list is full."""
    at_cap = [_finding(f"CVE-2026-7{n:03d}", days_old=n) for n in range(VULN_IDS_CAP)]
    block = _block(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), at_cap)))
    assert len(block["vulnIDs"]) == VULN_IDS_CAP and block["vulnIDsTruncated"] is False

    over = [*at_cap, _finding("CVE-2026-7999", days_old=VULN_IDS_CAP)]
    over_block = _block(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), over)))
    assert len(over_block["vulnIDs"]) == VULN_IDS_CAP and over_block["vulnIDsTruncated"] is True


def test_the_order_is_deterministic_for_findings_that_tie(raw: dict, run) -> None:  # noqa: F811
    """Two findings published on one day in one band cap the same way every time: the
    fan-out has to expand one stored row to the same bytes on every retry."""
    tied = [_finding(id_, days_old=5, severity="high") for id_ in ("CVE-2026-0009", "CVE-2026-0002")]
    first = _block(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), tied)))
    second = _block(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), list(reversed(tied)))))
    assert first["vulnIDs"] == second["vulnIDs"] == ["CVE-2026-0002", "CVE-2026-0009"]


def test_an_unscored_finding_sorts_last_and_is_still_counted(raw: dict, run) -> None:  # noqa: F811
    """The labelled assumption in `app.core.vuln._band_index`: §4e does not say where a
    finding the corpus could not score goes in the cap order. Last — but never dropped,
    because §4 counts it in `total`."""
    findings = [_finding("LoonVD-2026-000002", days_old=999, severity=None), _finding("CVE-2026-5000", days_old=1)]
    block = _block(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), findings)))
    assert block["vulnIDs"] == ["CVE-2026-5000", "LoonVD-2026-000002"]
    assert block["counts"]["total"] == 2
    assert block["daysOldestPublished"]["total"] == 999, "the unscored finding still sets the overall clock"
    assert block["daysOldestPublished"]["severity"] == {"critical": None, "high": 1, "medium": None, "low": None}


# --- the id namespaces -----------------------------------------------------------------


def test_a_local_id_is_refused_where_the_finding_is_constructed(raw: dict, run) -> None:  # noqa: F811
    """§5: `LOCAL-YYYY-NNNNNN` is reserved with nothing built behind it, so an id wearing
    it is a corpus defect, not a customer finding. Refused at construction — which for a
    static corpus is load time, so #248 fails loudly on the bad record instead of failing
    every device sync on a per-lookup raise."""
    VulnFinding(id="CVE-2026-0001", published=date(2026, 1, 1))
    VulnFinding(id="LoonVD-2026-000123", published=date(2026, 1, 1))
    for reserved in ("LOCAL-2026-000042", "local-2026-000042"):
        with pytest.raises(ValueError, match="LOCAL-"):
            VulnFinding(id=reserved, published=date(2026, 1, 1))
    assert LOCAL_PREFIX == "LOCAL-"


def test_only_the_two_licensed_namespaces_construct_and_nothing_else_does() -> None:
    """§5's 'one shape … one validator', both sides of the boundary. `CVE-` and `LoonVD-`
    are the only two namespaces a finding may be constructed with; a `GHSA-`/`OSV-` id
    from a public source — or anything malformed — must not mint a fourth namespace on
    the wire, so it is refused right here rather than passed through verbatim."""
    for allowed in ("CVE-2026-0001", "CVE-2020-123456", "LoonVD-2026-000001"):
        VulnFinding(id=allowed, published=date(2026, 1, 1))
    for refused in (
        "GHSA-xxxx-yyyy-zzzz",
        "OSV-2026-1234",
        "cve-2026-0001",
        "loonvd-2026-000001",
        "CVE-2026-1",
        "LoonVD-2026-1",
        "CVE_2026_0001",
        "CVE-2026-0001x",
    ):
        with pytest.raises(ValueError, match="namespace"):
            VulnFinding(id=refused, published=date(2026, 1, 1))


def test_no_id_the_wire_carries_is_ever_a_local_id(raw: dict, run) -> None:  # noqa: F811
    """The other direction, on the emitted event: whatever the corpus holds, nothing
    LoonInspect ships puts a `LOCAL-` id on the wire."""
    findings = [_finding("CVE-2026-6000", days_old=1), _finding("LoonVD-2026-000003", days_old=2)]
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), findings))
    ids = [vuln_id for item in payload["app"] for vuln_id in item["vuln"].get("vulnIDs", [])]
    assert ids and not any(vuln_id.upper().startswith(LOCAL_PREFIX) for vuln_id in ids)
    assert LOCAL_PREFIX not in json.dumps(payload)


def test_the_mixed_prefix_list_is_why_the_key_is_not_cve_ids(raw: dict, run) -> None:  # noqa: F811
    """§4e's argument, as data: the v0 list holds CVE and `LoonVD-` ids side by side from
    day one, so `cveIDs` would have shipped as a lie."""
    findings = [_finding("CVE-2026-6001", days_old=1, kev=True), _finding("LoonVD-2026-000004", days_old=2)]
    block = _block(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), findings)))
    assert block["vulnIDs"] == ["CVE-2026-6001", "LoonVD-2026-000004"]
    assert {vuln_id.split("-")[0] for vuln_id in block["vulnIDs"]} == {"CVE", "LoonVD"}


# --- the sentinel, and the seam that mints it ------------------------------------------


def test_the_canonical_payload_keeps_none_and_the_hec_seam_mints_minus_one(raw: dict, run) -> None:  # noqa: F811
    """§4c: "The sentinel is minted in the HEC-shaping seam. The canonical layer keeps
    `None`, and other destination dialects may render it natively — SQL `NULL`." So the
    stored row carries `null` and only the Splunk sub-event carries `-1`."""
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-1100", days_old=12)]))
    stored = _block(payload)
    assert stored["daysOldestPublished"] == {
        "total": 12,
        "severity": {"critical": None, "high": 12, "medium": None, "low": None},
    }

    (sub,) = [event["event"] for event in _app_sub_events(payload) if event["event"]["app"].get("bundleId") == KNOWN_BUNDLE_ID]
    assert sub["vuln"]["daysOldestPublished"] == {
        "total": 12,
        "severity": {"critical": NEVER, "high": 12, "medium": NEVER, "low": NEVER},
    }
    assert NEVER == -1
    assert all(isinstance(value, int) for value in sub["vuln"]["daysOldestPublished"]["severity"].values())


def test_the_sentinel_never_mutates_the_stored_row_and_a_rebuild_is_identical(raw: dict, run) -> None:  # noqa: F811
    """Delivery is retried against the same row up to ten times; the seam must expand the
    same bytes each time and must not edit the row it read."""
    payload = _stored(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-1200", days_old=3)])))
    before = deepcopy(payload)
    assert hec_events(payload) == hec_events(payload)
    assert payload == before


def test_mint_hec_sentinels_is_a_no_op_for_everything_that_carries_no_populated_block() -> None:
    """The same object back, not a copy, for the thirteen other sections and for every app
    under `off` and `unknown_app` — which today is all of them."""
    for item in (
        {"cert": {"commonName": "x"}},
        {"app": {"name": "Maps.app"}, "patch": {"supported": False}, "vuln": {"assessment": "off"}},
        {"app": {"name": "Maps.app"}, "vuln": {"assessment": "unknown_app", "corpusAsOf": "2026-09-01"}},
    ):
        assert mint_hec_sentinels(item) is item


def test_a_clean_bill_is_minus_one_everywhere_on_the_wire(raw: dict, run) -> None:  # noqa: F811
    """The shape §4 names in full: `covered`, zero, an empty list, and `-1` in all five
    day slots once the seam has minted them."""
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), []))
    (sub,) = [event["event"] for event in _app_sub_events(payload) if event["event"]["app"].get("bundleId") == KNOWN_BUNDLE_ID]
    assert sub["vuln"] == {
        "assessment": "covered",
        "corpusAsOf": "2026-09-01",
        "counts": {"total": 0, "kev": 0, "severity": dict.fromkeys(BANDS, 0)},
        "daysOldestPublished": {"total": NEVER, "severity": dict.fromkeys(BANDS, NEVER)},
        "vulnIDs": [],
        "vulnIDsTruncated": False,
    }


def test_only_splunk_sees_the_sentinel(raw: dict, run) -> None:  # noqa: F811
    """A generic webhook and an Elastic document get the canonical event whole, `null`
    included — which is what makes a warehouse destination able to render SQL `NULL`."""
    from types import SimpleNamespace

    from app.core.outbox import _build_body

    payload = _stored(_snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-1300", days_old=9)])))
    body = _build_body(SimpleNamespace(type="webhook"), dict(payload))
    (item,) = [item for item in body["app"] if item["app"].get("bundleId") == KNOWN_BUNDLE_ID]
    assert item["vuln"]["daysOldestPublished"]["severity"]["low"] is None
    assert item["vuln"]["daysOldestPublished"]["total"] == 9


# --- the sourcetype the summary decides -------------------------------------------------


def test_the_summary_rides_loon_jamf_mac_app_and_never_the_reserved_compound(raw: dict, run) -> None:  # noqa: F811
    """#249's first reviewer check, and §3. The block is an inline enrichment: a populated
    `vuln{}` does not make an app a different kind of event, and `loon:jamf:mac:app:vuln`
    stays minted with no writer, reserved for the post-v0 lifecycle records. The
    alternative reading is available and wrong — the compound here would force
    `loon:jamf:mac:app:patch:vuln` on an app carrying both blocks, and a `props.conf`
    stanza takes no wildcards."""
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-1400", days_old=4, kev=True)]))
    events = hec_events(_stored(payload))
    emitted = {event["sourcetype"] for event in events}
    assert emitted == {row[3] for row in registry_rows()}
    reserved = {row[2] for row in enrichment_rows()}
    assert "loon:jamf:mac:app:vuln" in reserved and not reserved & emitted
    covered = [event for event in events if event["event"].get("vuln", {}).get("assessment") == "covered"]
    assert len(covered) == 1
    assert covered[0]["sourcetype"] == sourcetype("app") == "loon:jamf:mac:app"


def test_the_block_rides_the_app_sub_event_and_no_other(raw: dict, run) -> None:  # noqa: F811
    """One block per app, per device, per sync — and on nothing else. The anchors and the
    other six list sections carry no `vuln` key at all."""
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-1500", days_old=6)]))
    for event in hec_events(_stored(payload)):
        body = event["event"]
        assert ("vuln" in body) == ("app" in body)
    assert len(_app_sub_events(payload)) == 83


def test_every_minted_key_in_a_populated_block_obeys_the_casing_law(raw: dict, run) -> None:  # noqa: F811
    """The casing net, extended one level deeper than #242's: `test_hec_fanout.py` judges
    the block's top-level keys, and `counts.severity.*` / `daysOldestPublished.*` are the
    first nested keys LoonInspect has ever minted inside an enrichment. camelCase with `ID`
    uppercased — `vulnIDs`, not `vulnIds` — and the VALUE `unknown_app` is untouched by the
    law, which is scoped to keys (§4b)."""
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), [_finding("CVE-2026-1600", days_old=8)]))

    def walk(value) -> set[str]:
        if not isinstance(value, dict):
            return set()
        return set(value) | {key for inner in value.values() for key in walk(inner)}

    keys = {key for item in payload["app"] for key in walk(item["vuln"])}
    assert {"vulnIDs", "vulnIDsTruncated", "daysOldestPublished", "corpusAsOf"} <= keys
    assert not [key for key in keys if not _CAMEL.match(key) or _LOWERCASE_ID_TOKEN.search(key)]
    assert VULN_ASSESSMENT_UNKNOWN_APP == "unknown_app", "a value, not a key — the law does not reach it (§4b)"


# --- the shape is refused when it is wrong ---------------------------------------------


def test_the_model_refuses_a_zero_count_under_unknown_app() -> None:
    """§4a made unwritable rather than documented: the producer cannot ship the clean bill
    for a fleet nobody assessed, in either direction."""
    counts = VulnCounts(total=0, kev=0, severity=VulnSeverityCounts(critical=0, high=0, medium=0, low=0))
    days = VulnDaysOldestPublished(total=None, severity=VulnSeverityDays(critical=None, high=None, medium=None, low=None))
    with pytest.raises(ValidationError, match="counts"):
        VulnEnrichment(assessment=VULN_ASSESSMENT_UNKNOWN_APP, corpus_as_of=CORPUS_AS_OF, counts=counts)
    with pytest.raises(ValidationError, match="counts"):
        VulnEnrichment(
            assessment=VULN_ASSESSMENT_COVERED,
            corpus_as_of=CORPUS_AS_OF,
            days_oldest_published=days,
            vuln_ids=[],
            vuln_ids_truncated=False,
        )
    with pytest.raises(ValidationError, match="corpusAsOf"):
        VulnEnrichment(assessment=VULN_ASSESSMENT_UNKNOWN_APP)
    with pytest.raises(ValidationError, match="corpusAsOf"):
        VulnEnrichment(assessment=VULN_ASSESSMENT_OFF, corpus_as_of=CORPUS_AS_OF)


def test_the_model_refuses_days_that_disagree_with_counts() -> None:
    """#249's stated invariant, in both directions:
    `daysOldestPublished.severity.X >= 0 <=> counts.severity.X > 0`. A band with a count
    and no day, or a day and no count, is a producer bug refused at enqueue."""
    for critical_count, critical_days in ((1, None), (0, 5)):
        with pytest.raises(ValidationError, match="disagree"):
            VulnEnrichment(
                assessment=VULN_ASSESSMENT_COVERED,
                corpus_as_of=CORPUS_AS_OF,
                counts=VulnCounts(
                    total=max(critical_count, 1),
                    kev=0,
                    severity=VulnSeverityCounts(critical=critical_count, high=0, medium=0, low=0),
                ),
                days_oldest_published=VulnDaysOldestPublished(
                    total=1,
                    severity=VulnSeverityDays(critical=critical_days, high=None, medium=None, low=None),
                ),
                vuln_ids=[],
                vuln_ids_truncated=False,
            )


def test_the_invariant_holds_on_every_block_the_builder_produces(raw: dict, run) -> None:  # noqa: F811
    """And on the wire, after the seam: `>= 0` exactly where the count is positive."""
    findings = [
        _finding("CVE-2026-1700", days_old=50, severity="critical"),
        _finding("CVE-2026-1701", days_old=20, severity="low"),
    ]
    payload = _snapshot(raw, corpus=_covered_corpus(_snapshot(raw), findings))
    (sub,) = [event["event"] for event in _app_sub_events(payload) if event["event"]["app"].get("bundleId") == KNOWN_BUNDLE_ID]
    block = sub["vuln"]
    for band in BANDS:
        assert (block["daysOldestPublished"]["severity"][band] >= 0) == (block["counts"]["severity"][band] > 0)
    assert (block["daysOldestPublished"]["total"] >= 0) == (block["counts"]["total"] > 0)


def test_a_severity_the_corpus_invents_is_refused() -> None:
    """The four bands are a closed set; a fifth would be indexed under a name no dashboard
    knows."""
    with pytest.raises(ValueError, match="unscored"):
        VulnFinding(id="CVE-2026-1800", published=date(2026, 1, 1), severity="informational")
    assert SEVERITY_BANDS == ("critical", "high", "medium", "low")


# --- the seam #248 implements -----------------------------------------------------------


def test_the_protocol_is_the_whole_interface_248_must_implement() -> None:
    """Two members and nothing else: `as_of`, and `findings(key_title=…, key_full=…)`
    returning `None` for an app the corpus does not know, `()` for one it knows with no
    active findings, and a sequence otherwise. `NO_CORPUS` satisfies it, and so does the
    stub — which is the point: this issue consumes an interface, it does not preview a
    corpus."""
    assert isinstance(NO_CORPUS, VulnCorpus)
    assert isinstance(StubCorpus(), VulnCorpus)
    assert vuln_block(NO_CORPUS, key_title="v1:t", key_full="v1:f", as_of=date(2026, 9, 2)).assessment == "off"

    corpus = StubCorpus(titles=["v1:t"], builds={"v1:f": [_finding("CVE-2026-1900", days_old=1)]})
    assert vuln_block(corpus, key_title="v1:other", key_full="v1:f", as_of=_WINDOW.date()).assessment == "unknown_app"
    assert vuln_block(corpus, key_title="v1:t", key_full="v1:none", as_of=_WINDOW.date()).counts.total == 0
    assert vuln_block(corpus, key_title="v1:t", key_full="v1:f", as_of=_WINDOW.date()).counts.total == 1


def test_the_empty_tuple_means_positively_assessed_never_an_unassessed_build(raw: dict, run) -> None:  # noqa: F811
    """The corpus-interface hazard #279's review named, not a bug in this builder: `()`
    must mean the corpus positively assessed this exact build and found nothing active —
    never merely that it has no stored answer for it (docs/vulnerabilities.md §4f).
    `vuln_block` cannot tell the two apart — an unassessed build and a truly clean one are
    the same `()` to this module — so a hash-join corpus that knows the title but defaults
    to `()` for a build it never looked at (`StubCorpus`'s own `.get(key_full, ())`, #248's
    shape exactly) reads as a `covered` clean bill here. That is the wrong reading for an
    unassessed build, which is exactly why the distinction is the corpus's to keep, not
    this module's to infer."""
    key_title, _ = _keys(_snapshot(raw), KNOWN_BUNDLE_ID)
    corpus = StubCorpus(titles=[key_title])  # knows the title; no build was ever stored
    block = _block(_snapshot(raw, corpus=corpus))
    assert block["assessment"] == "covered"
    assert block["counts"] == {"total": 0, "kev": 0, "severity": dict.fromkeys(BANDS, 0)}


def test_an_app_with_no_row_is_still_assessed_and_never_reads_off_alone(run) -> None:  # noqa: F811
    """The alarm path in `_app_item` — an entry with no `installed_apps` row, which cannot
    happen by construction and is logged when it does. It falls back to computing the pair
    from the canonical entry body rather than shipping `off` for that one app: `off` is a
    property of the pod (unlicensed, unconsented, no corpus), so one app reading `off`
    beside eighty-two reading `covered` is not a state §4a describes.

    The fallback produces the SAME keys the row would have carried —
    `test_inventory_snapshot.py` pins that on all 83 apps of the fixture."""
    from app.mdm.jamf.contract import canonicalize_computer
    from app.mdm.snapshot import build_inventory_snapshot

    record = {
        "id": "7",
        "general": {"name": "mbp-ada"},
        "applications": [{"name": "Kept.app", "bundleId": "com.example.kept", "version": "1.0"}],
    }
    key_title = app_title_key("Kept.app", "com.example.kept")
    key_full = app_full_key("Kept.app", "com.example.kept", "1.0", None)
    corpus = StubCorpus(titles=[key_title], builds={key_full: [_finding("CVE-2026-2100", days_old=2)]})
    event = build_inventory_snapshot(
        canonicalize_computer(record, ("applications",)),
        extension_attributes=None,
        apps=[],
        occurred_at=_WINDOW,
        device_meta={},
        corpus=corpus,
    )
    (item,) = event.app or ()
    assert item.patch.supported is False, "the row is genuinely missing"
    assert item.vuln.assessment == "covered" and item.vuln.counts is not None
    assert item.vuln.counts.total == 1
    assert corpus.calls == [(key_title, key_full)]


def test_the_lookup_is_keyed_on_the_content_keys_the_container_already_computes(raw: dict, run) -> None:  # noqa: F811
    """#113's local hash-join: the corpus is asked about `key_title` and `key_full` —
    `app.core.content_keys`, stamped once in `apply_hashes` for every ingest path — and
    about nothing else. Both keys are asked for every app, once."""
    corpus = StubCorpus(titles=[])
    payload = _snapshot(raw, corpus=corpus)
    assert len(corpus.calls) == 83
    # In the observation's own (digest) order, which is the order the app items ride in.
    assert corpus.calls == [_keys(payload, item["app"]["bundleId"]) for item in payload["app"]]
    assert all(title.startswith("v1:") and full.startswith("v1:") for title, full in corpus.calls)
    assert len({full for _title, full in corpus.calls}) == 83


# --- size --------------------------------------------------------------------------------


def test_a_fully_covered_device_is_measured_and_pinned(raw: dict, run) -> None:  # noqa: F811
    """The worst shape the v0 wire can take: every app covered, every list at the cap.

    `test_hec_fanout.py` pins the request at 85,000 bytes measured with `off`, which is
    the wire that ships. This is the number #248 turns on, measured rather than estimated
    so the corpus landing is not the moment anyone discovers it."""
    findings = [_finding(f"CVE-2026-{n:04d}", days_old=n + 1, severity=BANDS[n % 4], kev=n % 7 == 0) for n in range(60)]
    key_titles = {_keys(_snapshot(raw), app["bundleId"])[0] for app in raw["applications"] if app.get("bundleId")}
    builds = {_keys(_snapshot(raw), app["bundleId"])[1]: findings for app in raw["applications"] if app.get("bundleId")}
    payload = _snapshot(raw, corpus=StubCorpus(titles=key_titles, builds=builds))

    events = _app_sub_events(payload)
    assert all(event["event"]["vuln"]["assessment"] == "covered" for event in events)
    assert all(event["event"]["vuln"]["vulnIDsTruncated"] for event in events)
    biggest = max(len(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode()) for event in events)
    assert biggest <= COVERED_APP_SUB_EVENT_CEILING, f"a covered app sub-event grew to {biggest} bytes"

    body = b"\n".join(
        json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode() for event in hec_events(_stored(payload))
    )
    assert len(body) <= COVERED_REQUEST_CEILING, f"the covered request grew to {len(body)} bytes; say why in the PR"


def test_the_three_states_cost_what_they_are_measured_to_cost(raw: dict, run) -> None:  # noqa: F811
    """What each answer costs on the most-multiplied object the product emits, per app:
    20 bytes to say `off`, 54 to say `unknown_app` with a date, 1,067 to say `covered` at
    the full cap. `off` is the shipped wire and is unchanged by this issue; the other two
    arrive with #248, which is why they are measured now rather than then.

    The 20 bytes are also the answer to *why say `off` at all*: `vuln.assessment=off`
    extracts to a Splunk field and `{}` does not, so a searchable "we did not look" costs
    a fifth of what a dated "we do not know this app" costs."""
    off = _snapshot(raw)
    unknown = _snapshot(raw, corpus=StubCorpus(titles=[]))
    covered = _snapshot(raw, corpus=_covered_corpus(off, [_finding(f"CVE-2026-{n:04d}", days_old=n + 1) for n in range(60)]))

    def size(block: dict) -> int:
        return len(json.dumps(block, separators=(",", ":"), ensure_ascii=False).encode())

    assert {size(item["vuln"]) for item in off["app"]} == {20}
    assert {size(item["vuln"]) for item in unknown["app"]} == {54}
    # A ceiling rather than an equality: a covered block's exact size moves with the digit
    # widths of its day counts, which is test data, not a wire decision. 1,067 measured.
    assert size(_block(covered)) <= COVERED_BLOCK_CEILING
    request = b"\n".join(
        json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode() for event in hec_events(_stored(unknown))
    )
    assert len(request) <= UNKNOWN_REQUEST_CEILING, f"an unknown_app fleet's request grew to {len(request)} bytes"


def test_fan_out_reads_the_seam_and_not_a_second_copy_of_it() -> None:
    """One minting site. `app.core.hec_fanout` is the only caller of the sentinel seam, so
    a second destination cannot grow its own dialect of `-1`."""
    import inspect

    source = inspect.getsource(fan_out)
    assert "mint_hec_sentinels" in source
