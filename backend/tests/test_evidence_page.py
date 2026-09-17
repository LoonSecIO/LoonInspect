"""The printable evidence page (#473): the document, its bundle, and every sentence it prints about itself.

No Postgres. `render_evidence_page` is pure over #472's object, which is what lets the failure sentences — the half
of this surface that only shows up on a bad day — be exercised rather than described in a comment.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from app.baseline.page import (
    BUNDLE_ID,
    NOT_OBSERVED_PART,
    OLD_WINDOW,
    STALE_TAIL,
    UNKNOWN_CONTRACT,
    notices,
    page_filename,
    render_evidence_page,
)
from app.baseline.report import REFUSAL

NOW = datetime(2026, 4, 11, tzinfo=UTC)
START, AS_OF, COLLECTED = "2026-03-01T00:00:00+00:00", "2026-04-10T00:00:00+00:00", "2026-04-09T01:00:00+00:00"
FORTY = {"seconds": 3456000, "days": 40}
TOTAL = {"met": FORTY, "unmet": {"seconds": 0}, "notObserved": {"seconds": 0}, "window": FORTY}
# A Mac named by whoever enrolled it, which is a machine we do not control (docs/ai-threat-model.md). Both halves on
# purpose: the tag that would close the bundle early, and the markup that would rewrite the page around it.
HOSTILE = '</script><img src=x onerror=alert(1)>Mac "quoted" & <b>bold</b>'


def _report(**over: Any) -> dict[str, Any]:
    method = {
        "statement": "What each Mac reported to one Jamf Pro connection at each inventory.",
        "source": "observation ledger",
        "connection": {"connectionID": 7, "name": HOSTILE, "provider": "jamf"},
        "catalogue": {"version": 1, "rules": 1},
        "window": {"start": START, "asOf": AS_OF},
    }
    absent = ["policy controls", "process controls", "personnel controls"]
    row = {
        "ruleID": "LI-0003",
        "deviceID": "1",
        "state": "met",
        "from": START,
        "to": AS_OF,
        "duration": "40 days",
        "collectedFrom": "2026-03-01T01:00:00+00:00",
        "collectedTo": COLLECTED,
        "sectionDigest": "v0:1f3c",
        "witnessed": {"field": "security.firewallEnabled", "value": True, "statement": "firewallEnabled = True"},
        **FORTY,
    }
    return {
        "header": {
            "method": method,
            "notVisible": {"controls": absent, "statement": "Nothing here reads a policy, a process or a person."},
            "refusal": REFUSAL,
            "contractVersions": ["v0"],
            "clock": {"interval": "device", "statement": "Device time is the interval clock."},
        },
        "rules": [{"ruleID": "LI-0003", "title": "The application firewall is on", "field": "security.firewallEnabled"}],
        "devices": [{"deviceID": "1", "name": HOSTILE, "udid": "udid-1", "serialNumber": "C02", "managementID": "m-1"}],
        "rows": [row],
        "totals": {"fleet": dict(TOTAL), "byRule": {"LI-0003": dict(TOTAL)}, "byDevice": {}},
    } | over


def _page(report: dict[str, Any] | None = None, *, heartbeat: datetime | None = NOW) -> str:
    return render_evidence_page(report or _report(), heartbeat=heartbeat, now=NOW)


def _bundle(page: str) -> dict[str, Any]:
    """The bundle as a tool would lift it: one selector, then JSON."""
    found = re.search(rf'<script type="application/json" id="{BUNDLE_ID}">(.*?)</script>', page, re.S)
    assert found, "the bundle is not liftable with one selector"
    return json.loads(found.group(1))


def _tags(page: str) -> list[str]:
    """Every tag in the document. Sound because the renderer escapes: a literal `<` in the output is markup the
    renderer wrote, and anything from the fleet is `&lt;` by the time it lands."""
    return re.findall(r"<[a-zA-Z/!][^>]*>", page)


def test_the_document_carries_its_header_its_refusal_and_its_bundle() -> None:
    """One file: the five header items, the refusal on every printed page, and the machine-readable object inside the
    document rather than beside it, where it could be separated from what it belongs to."""
    page = _page()
    for said in (REFUSAL, "policy controls, process controls, personnel controls", "the observation ledger"):
        assert said in page
    assert "Device time is the interval clock." in page and "version 1, 1 rules" in page
    # The refusal is the repeating `thead` of the one table the whole document sits in, which is the construction
    # Chrome repeats at the top of every page without printing over the content.
    assert re.search(r'<table class="sheet"><thead><tr><th class="running">[^<]*record of technical state', page)
    assert ".sheet>thead,thead{display:table-header-group}" in page.replace("\n", "").replace("  ", "")
    assert _bundle(page) == _report()


def test_the_page_is_self_contained_and_leaves_no_request() -> None:
    """It will be opened a year from now on a machine with no network. Nothing may be fetched — no CDN, no font, no
    stylesheet, no image — and the one script block is data a browser never executes."""
    page = _page()
    fetching = r"^<(?:link|img|iframe|object|embed|video|audio|source|base|use)\b"
    assert [tag for tag in _tags(page) if re.search(r"\b(?:src|srcset|href|poster)\s*=", tag)] == []
    assert [tag for tag in _tags(page) if re.match(fetching, tag)] == []
    style = re.search(r"<style>(.*?)</style>", page, re.S)
    assert style and "@import" not in style.group(1) and "url(" not in style.group(1)
    assert page.count("<script") == 1 and 'type="application/json"' in page
    assert "@page{size:A4 portrait" in style.group(1).replace("\n", "")


def test_a_device_named_after_a_closing_tag_breaks_neither_the_page_nor_the_bundle() -> None:
    """The fleet is untrusted input. A Mac called `</script>` must close nothing, and the name must still come back
    out of the bundle exactly as Jamf gave it."""
    page = _page()
    assert HOSTILE not in page, "an unescaped fleet string reached the document"
    assert page.count("<script") == 1, "a device name ended the bundle early"
    assert [tag for tag in _tags(page) if "onerror" in tag or tag.startswith("<img")] == []
    # The bundle's own defence, fired: `<` is a `\\u003c` escape, so `</script` cannot be spelled inside it.
    assert "\\u003c/script\\u003e" in page
    lifted = _bundle(page)
    assert lifted["devices"][0]["name"] == HOSTILE and lifted["header"]["method"]["connection"]["name"] == HOSTILE
    assert "&lt;/script&gt;" in page, "the name should print, escaped, where a reader can read it"


def test_the_sum_and_the_zero_that_means_seen_once() -> None:
    """A zero meaning "we saw it once" must not wear the costume of a zero meaning "it never happened" — on a page
    someone files, that is the defect docs/diagnosability.md §1 exists to forbid."""
    report = _report()
    report["totals"]["byRule"]["LI-0003"]["met"] = {"seconds": 0}
    page = _page(report)
    assert "under one reporting interval" in page and ">0 days<" not in page
    assert "Met plus unmet plus not observed is the window" in page
    assert "The application firewall is on" in page and "security.firewallEnabled" in page


def test_the_sum_says_what_its_figures_are_multiples_of() -> None:
    """The header names a 40-day window and the fleet row reads 80 days, because every bucket above the (device,
    rule) grain is the window times the rows folded into it (docs/compliance-evidence.md §4). Under a bare "= the
    window" heading that figure cannot be reconciled with the window six lines above it, and an archived document
    whose sum cannot be checked reads as evasion — the wrong answer to the question #219 R5 sends this page to ask.
    So the heading carries the multiple and the prose does the arithmetic on this report's own two numbers."""
    report = _report()
    report["devices"] = [*report["devices"], {"deviceID": "2", "name": "Mac 2"}]
    both = {"seconds": 6912000, "days": 80}
    report["totals"]["fleet"] = {"met": both, "unmet": {"seconds": 0}, "notObserved": {"seconds": 0}, "window": both}
    page = _page(report)
    assert "= the window × rows" in page and "= the window<" not in page, "the heading has to carry the multiple"
    assert "for one Mac under one rule" in page, "the grain the identity actually holds at"
    assert "the window (40 days, the one in the header) times the rows folded into it" in page
    # Counted here, not described: two Macs and one rule, so the fleet's 80 is forty days twice, and checkable.
    assert "This report holds 2 Macs and 1 rule, so a rule's row reads 40 days × 2 and the fleet's 40 days × 2 × 1." in page
    assert "Mac-days, not calendar days" in page and ">80 days<" in page


def test_a_window_that_opens_after_the_last_collection_still_says_how_old_it_is() -> None:
    """Every row not observed and not one of them carrying a collection. Read from the rows alone, the one report
    whose every day is unobserved is also the only one that never says when the last collection was; the ledger's
    own last word is the fallback that closes that."""
    report = _report()
    report["rows"] = [{k: v for k, v in report["rows"][0].items() if not k.startswith("collected")}]
    said = notices(report, heartbeat=datetime(2026, 2, 1, 12, 30, tzinfo=UTC), now=NOW)
    assert STALE_TAIL.format(collected="2026-02-01 12:30 UTC", as_of="2026-04-10 00:00 UTC") in said


def test_no_observation_in_the_window_is_said_rather_than_left_blank() -> None:
    """An empty table reads as "nothing to report", which is #150's rule: failure is not emptiness. This is also the
    shape an `asOf` earlier than the earliest observation produces."""
    report = _report(rows=[], devices=[], totals={"fleet": {}, "byRule": {}, "byDevice": {}})
    said = notices(report, heartbeat=NOW, now=NOW)
    assert said[0].startswith("No observation in this window.")
    assert "2026-03-01 00:00 UTC" in said[0] and "the run panel" in said[0]
    assert "No observation in this window." in _page(report)


def test_days_with_no_observation_behind_them_name_all_three_facts_and_a_check_that_separates_them() -> None:
    """The head before a Mac's first observation, the tail after its last and a day nobody swept are three facts
    under one label, and the page holds only the label. Naming the third alone — "the collector not running" — is
    the defect docs/diagnosability.md §2 rule 1 forbids and sends every reader to a run history with no missing run
    in it, because the ninety-day default window reaches before the first observation on any young instance and one
    quiet Mac contributes a tail. The figure says what it is counted in, too: it is a multiple of the window."""
    report = _report()
    report["totals"]["fleet"]["notObservedParts"] = {"noObservation": {"seconds": 864000, "days": 10}}
    said = notices(report, heartbeat=NOW, now=NOW)
    assert NOT_OBSERVED_PART.format(days="10 days") in said
    page = _page(report)
    assert "10 days, counted once per Mac per rule" in page
    # Apostrophe-free fragments: the box is escaped on the way in, so `Mac's` reads `Mac&#x27;s` in the document.
    for state in ("the stretch before a Mac", "enrolled mid-window", "a Mac gone quiet", "dates on which no sweep ran"):
        assert state in page, "a sentence that names one of three states hides the other two"
    assert "the collector not running" not in page
    assert "Every interval below" in page and "<h2>Every interval</h2>" in page
    # And the sum's "of which" cell names the same part in the same words, not in the wire's. The wire key stays in
    # the bundle, where a tool reads it; the cell is for the person filing the page.
    assert "<td>no observation: 10 days</td>" in page and "<td>noObservation:" not in page
    assert '"noObservation":' in page, "the object inside the page keeps the contract's key"


def test_an_as_of_past_the_last_collection_names_the_tail() -> None:
    """The days after the last read are not the last known state carried forward, and the page says which they are."""
    said = notices(_report(), heartbeat=NOW, now=NOW)
    assert STALE_TAIL.format(collected="2026-04-09 01:00 UTC", as_of="2026-04-10 00:00 UTC") in said
    assert "dated later than the last collection it could read" in _page()


def test_a_window_older_than_the_run_horizon_is_a_success_that_looks_like_a_failure() -> None:
    """An operator who cannot find the run behind an old report needs telling that this is expected and the evidence
    still sound: runs purge at thirty days, the observation ledger never does."""
    assert OLD_WINDOW.format(retention=30, start="2026-03-01 00:00 UTC") in notices(_report(), heartbeat=NOW, now=NOW)
    assert "stays answerable long after the run that collected it" in _page()
    recent = _report()
    recent["header"]["method"]["window"] = {"start": (NOW - timedelta(days=5)).isoformat(), "asOf": AS_OF}
    assert [one for one in notices(recent, heartbeat=NOW, now=NOW) if one.startswith("The runs behind")] == []


def test_observations_under_a_contract_this_build_has_no_rules_for_say_why() -> None:
    """#464 answers `not_reported` across the board for an unknown contract version. Unexplained, a page of them
    reads as a broken sweep."""
    report = _report()
    report["header"]["contractVersions"] = ["v9"]
    assert UNKNOWN_CONTRACT.format(seen="v9", known="v0") in notices(report, heartbeat=NOW, now=NOW)
    assert "left unapplied rather than guessed at" in _page(report)


def test_the_filename_carries_the_window_so_two_reports_do_not_collide() -> None:
    assert page_filename(_report()) == "evidence-7-2026-03-01-to-2026-04-10.html"
