"""The patch-policy day-walk (`app.core.patch_policy_walk`, #614): hand-derived goldens, refusals, parity,
and seeded property tests over generated documents.

Pure: no database, no network. The goldens are small documents whose whole walk is derived by hand in
each test's docstring, so a change to a counting rule shows up as a number a reader can check against
the derivation. Day numbers in the derivations count from 2026-01-01 = d0 (so d59 = 2026-03-01 and
d180 = 2026-06-30). The property tests draw documents from a seeded generator (`random.Random(seed)`,
no hypothesis dependency) and hold the plan's invariants on every one that walks.
"""

from __future__ import annotations

import ast
import copy
import datetime as dt
import functools
import itertools
import random
from typing import Any

import pytest

from app.core import patch_policy_walk as walk_module
from app.core.patch_policy_walk import (
    STOPS,
    WalkRefused,
    check_totals,
    input_id,
    invariant_failures,
    public_timeline,
    walk,
    window_for,
)

BASE = dt.date(2026, 1, 1)


def d(offset: int) -> str:
    return (BASE + dt.timedelta(days=offset)).isoformat()


def version(v: str, date: str | None, line: str = "", train: str | None = None) -> dict[str, Any]:
    return {"v": v, "keys": [v.lower()], "line": line, "train": train if train is not None else v, "date": date}


def cve(cve_id: str, *, published: str, detectable: str | None, affected: list, fixes: list, **extra: Any) -> dict[str, Any]:
    return {"cve_id": cve_id, "published": published, "detectable_at": detectable, "affected": affected, "fixes": fixes, **extra}


def fix(index: int | None, line: str = "") -> dict[str, Any]:
    return {"line": line, "index": index}


def document(tracks: list[dict[str, Any]], *, coverage: str | None = None, as_of: str = "2026-07-01T05:00:00Z") -> dict[str, Any]:
    sources: dict[str, Any] = {
        "timelines": {"vendor": {"name": "Vendor tags", "fetched_at": "2026-07-01T00:00:00Z", "clock": "tag day"}}
    }
    if coverage:
        sources["detectable"] = {"coverage_since": coverage}
    return {
        "kind": "patch_policy_reference",
        "schema": 1,
        "doc_id": "doc-golden",
        "as_of": as_of,
        "algorithm": "patch_walk/1",
        "definitions_version": "2",
        "definitions": {"ranges": "LoonVD's compiled runs."},
        "clocks": {"published": "NVD publication."},
        "sources": sources,
        "apps": [{"app": "demo", "name": "Demo", "tracks": tracks}],
    }


def timeline(observations: list, *, source: str = "public", as_of: str = "2026-07-01") -> dict[str, Any]:
    return {"source": source, "name": "Vendor tags", "as_of": as_of, "clock": "tag day", "observations": observations}


def outcome(result: dict[str, Any], cve_id: str, stop: str) -> dict[str, Any]:
    return next(row for row in result["cves"] if row["cve_id"] == cve_id)["outcomes"][stop]


# --- Golden A: one line, every stop, every class -----------------------------------------------


def golden_a() -> tuple[dict[str, Any], dict[str, Any]]:
    stable = {
        "track": "demo/stable",
        "label": "Demo",
        "path": {"kind": "latest"},
        "promotions": None,
        "timeline": "vendor",
        "versions": [
            version("0.9", d(-31)),
            version("1.0", d(0)),
            version("1.1", d(60)),
            version("1.2", d(100)),
            version("1.3", None),
        ],
        "cves": [
            cve("CVE-2026-0001", published=d(38), detectable=d(40), affected=[[0, 1]], fixes=[fix(2)]),
            cve("CVE-2026-0002", published=d(45), detectable=d(45), affected=[[0, 0]], fixes=[fix(1)]),
            cve("CVE-2026-0003", published=d(50), detectable=d(50), affected=[[3, 3]], fixes=[fix(4)]),
            cve("CVE-2026-0004", published=d(18), detectable=d(20), affected=[[2, 2]], fixes=[fix(3)]),
            cve("CVE-2026-0005", published=d(10), detectable=None, affected=[[0, 1]], fixes=[fix(2)]),
            cve("CVE-2026-0006", published=d(169), detectable=d(170), affected=[[0, 2]], fixes=[fix(3)]),
            cve("CVE-2026-0007", published=d(185), detectable=d(185), affected=[[0, 3]], fixes=[fix(4)]),
            cve("CVE-2026-0010", published=d(35), detectable=d(35), affected=[[0, 0]], fixes=[fix(1)], ambiguous_lines=[""]),
            cve("CVE-2026-0011", published=d(60), detectable=None, affected=[[4, 4]], fixes=[fix(None)], ambiguous_lines=["2.0"]),
        ],
        "exclusions": {
            "by_reason": {"rejected": 1},
            "cves": [{"cve_id": "CVE-2026-0009", "reason": "rejected", "published": d(50)}],
        },
        "not_detectable": {"count": 1, "cves": ["CVE-2026-0012"]},
    }
    beta = {
        "track": "demo/beta",
        "label": "Demo beta",
        "path": {"kind": "latest"},
        "versions": [version("2.0b1", d(90))],
        "cves": [],
    }
    observed = timeline(
        [
            {"version": "0.9", "date": d(-31)},
            {"version": "1.0", "date": d(0)},
            {"version": "1.1", "date": d(60)},
            {"version": "1.1", "date": d(63)},
            {"version": "1.2", "date": d(100)},
            {"version": "1.3", "date": None},
            {"version": "2.0B1", "date": d(90)},
        ]
    )
    return document([stable, beta], coverage="2026-01-31"), observed


def test_golden_a_window_join_and_counts() -> None:
    """The window, the join report and the counts, derived by hand.

    Join: 0.9, 1.0, 1.1, 1.2 and 1.3 are the track's (matched 5); 1.3 has no date (undated 1); 1.1 is
    dated twice, d60 and d63, and keeps the earlier (conflicts 1); `2.0B1` lowercases to the beta
    track's key (other_track 1); nothing is unmatched. first d-31, last d100.

    Window: until defaults to the day before the document's date, 2026-06-30 (d180), and nothing ends
    it earlier (the timeline was read 2026-07-01). The terms for its start: the requested 2 years
    (2024-06-30); the detectable record, which begins 2026-01-31, so 2026-02-01 (d31); 59 days after
    the first available release, d-31 + 59 = d28. So since = d31, bound by clock_coverage alone, and
    the window holds 150 days.

    Placement by clock (detectable_at, else published): before the window CVE-4 (det d20) and CVE-5
    (published d10, no det); after it CVE-7 (d185); in it CVE-1 (d40), -2 (d45), -3 (d50), -6
    (d170), -9 (published d50), -10 (d35), -11 (published d60) = 7. Every device runs line "", so
    "" is visited: CVE-10 is ambiguous on it (branch_ambiguity), CVE-3's fix is 1.3, which the
    timeline does not date (fixed_version_not_in_timeline), and CVE-9 is the document's own
    exclusion (rejected). CVE-11 is ambiguous only on 2.0, which nobody visits. So replayed 4
    (-1, -2, -6, -11), excluded 3; by clock 3 detectable_at (-1, -2, -6) and 1 published (-11).
    """
    doc, observed = golden_a()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)

    assert result["kind"] == "patch_policy_walk"
    assert result["window"]["since"] == "2026-02-01"
    assert result["window"]["until"] == "2026-06-30"
    assert result["window"]["days"] == 150
    assert [row["reason"] for row in result["window"]["shortened_by"]] == ["clock_coverage"]
    assert result["window"]["requested"] == {"years": 2, "since": "2024-06-30", "until": "2026-06-30"}

    joined = result["inputs"]["timeline"]
    assert (joined["matched"], joined["undated"], joined["conflicts"], joined["other_track"]) == (5, 1, 1, 1)
    assert joined["unmatched"] == []
    assert (joined["first"], joined["last"]) == (d(-31), d(100))

    counts = result["counts"]
    assert counts["cves_in_doc"] == 10
    assert (counts["before_window"], counts["in_window"], counts["after_window"]) == (2, 7, 1)
    assert (counts["replayed"], counts["excluded"], counts["not_detectable"]) == (4, 3, 1)
    assert counts["replayed_by_clock"] == {"detectable_at": 3, "published": 1}
    by_reason = result["exclusions"]["by_reason"]
    assert (by_reason["rejected"], by_reason["branch_ambiguity"], by_reason["fixed_version_not_in_timeline"]) == (1, 1, 1)
    assert sum(by_reason.values()) == 3
    assert {row["cve_id"]: row["reason"] for row in result["exclusions"]["cves"]} == {
        "CVE-2026-0003": "fixed_version_not_in_timeline",
        "CVE-2026-0009": "rejected",
        "CVE-2026-0010": "branch_ambiguity",
    }
    details = {row["cve_id"]: row["detail"] for row in result["exclusions"]["cves"]}
    assert details["CVE-2026-0003"] == "the fix on '' is 1.3, which this timeline does not date"
    assert details["CVE-2026-0010"] == "the range is ambiguous on '', which the path visits"
    assert result["check"]["state"] == "no_entry"
    assert invariant_failures(result) == []


def test_golden_a_devices_and_totals_per_stop() -> None:
    """Each stop's device and totals, derived by hand. Availability: 0.9 d-31, 1.0 d0, 1.1 d60, 1.2 d100.

    A D-day stop installs at availability + (D - 1) and opens on the newest release installed by d31:
      1d   installs d-31, d0, d60, d100  -> opens 1.0; 1.1 on d60, 1.2 on d100
      7d   +6                            -> opens 1.0; 1.1 on d66, 1.2 on d106
      14d  +13                           -> opens 1.0; 1.1 on d73, 1.2 on d113
      30d  +29                           -> opens 1.0; 1.1 on d89, 1.2 on d129
      60d  +59 (d28, d59, d119, d159)    -> opens 0.9; 1.0 on d59, 1.1 on d119, 1.2 on d159
      never: the newest available by d31 -> 1.0, nothing after.

    In-window CVEs (inclusive day intervals):
      CVE-1 (det d40, affected 0.9-1.0, fix 1.1): exposed until the 1.1 install.
             1d [d40,d59]=20  7d [d40,d65]=26  14d [d40,d72]=33  30d [d40,d88]=49  60d [d40,d118]=79
             never [d40,d180]=141, open at the window's end.
      CVE-2 (det d45, affected 0.9 only, fix 1.0): only the 60d device is on 0.9 then: [d45,d58]=14,
             cleared d59 by 1.0. Every other stop runs 1.0 on d45: never seen, fix installed first.
      CVE-6 (det d170, affected 0.9-1.1, fix 1.2): every day stop runs 1.2 by d170 (the 60d one from
             d159): never seen, fix first. never runs 1.0: [d170,d180]=11, open.
      CVE-11 (published d60, affected only 1.3, which nobody installs, no fix): never seen, outside the
             affected range, under every stop.
    Before the window:
      CVE-5 (published d10, affected 0.9-1.0): every device runs an affected release on d31, so it is
             carried in: 1d [d31,d59]=29  7d 35  14d 42  30d 58  60d [d31,d118]=88  never [d31,d180]=150.
      CVE-4 (det d20, affected 1.1 only): nobody runs 1.1 on d31, so every day stop enters it later:
             1d [d60,d99]  7d [d66,d105]  14d [d73,d112]  30d [d89,d128]  60d [d119,d158], 40 days each.
             never never installs 1.1: pre_window_closed.
    """
    doc, observed = golden_a()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    policies = result["policies"]

    expected = {
        # stop: (initial, installs, never_seen, outside, exposed, exposure_days, carried, entered, closed, days_carried)
        "1d": ("1.0", [(60, "1.1"), (100, "1.2")], 3, 1, 1, 20, 1, 1, 0, 29),
        "7d": ("1.0", [(66, "1.1"), (106, "1.2")], 3, 1, 1, 26, 1, 1, 0, 35),
        "14d": ("1.0", [(73, "1.1"), (113, "1.2")], 3, 1, 1, 33, 1, 1, 0, 42),
        "30d": ("1.0", [(89, "1.1"), (129, "1.2")], 3, 1, 1, 49, 1, 1, 0, 58),
        "60d": ("0.9", [(59, "1.0"), (119, "1.1"), (159, "1.2")], 2, 1, 2, 79 + 14, 1, 1, 0, 88),
        "never": ("1.0", [], 2, 1, 2, 141 + 11, 1, 0, 1, 150),
    }
    for stop, (initial, installs, never_seen, outside, exposed, days, carried, entered, closed, days_carried) in expected.items():
        policy = policies[stop]
        assert policy["initial_version"] == initial, stop
        assert [(row["date"], row["version"]) for row in policy["installs"]] == [(d(day), v) for day, v in installs], stop
        assert (policy["never_seen"], policy["never_seen_outside_affected_range"], policy["exposed"]) == (
            never_seen,
            outside,
            exposed,
        ), stop
        assert policy["exposure_days"] == days, stop
        assert (policy["carried_in"], policy["entered_after_start"], policy["pre_window_closed"]) == (carried, entered, closed), (
            stop
        )
        assert policy["exposure_days_carried_in"] == days_carried, stop
        assert policy["exposure_days_entered_after_start"] == (40 if entered else 0), stop

    assert policies["never"]["open_at_window_end"] == {"in_window": 2, "carried_in": 1, "entered_after_start": 0}
    assert policies["1d"]["open_at_window_end"] == {"in_window": 0, "carried_in": 0, "entered_after_start": 0}

    one = outcome(result, "CVE-2026-0001", "1d")
    assert one == {
        "class": "in_window",
        "outcome": "exposed",
        "exposure_days": 20,
        "open_at_window_end": False,
        "cleared_on": d(60),
        "cleared_by": "1.1",
        "intervals": [[d(40), d(59)]],
        "version_at_clock": "1.0",
    }
    assert outcome(result, "CVE-2026-0002", "7d") == {
        "class": "in_window",
        "outcome": "never_seen",
        "why": "fix_installed_first",
        "version_at_clock": "1.0",
    }
    assert outcome(result, "CVE-2026-0011", "1d")["why"] == "outside_affected_range"
    assert outcome(result, "CVE-2026-0011", "1d")["version_at_clock"] == "1.1"
    assert outcome(result, "CVE-2026-0004", "60d")["intervals"] == [[d(119), d(158)]]
    assert outcome(result, "CVE-2026-0004", "never") == {"class": "pre_window_closed", "outcome": "not_open_in_window"}
    row = next(row for row in result["cves"] if row["cve_id"] == "CVE-2026-0005")
    assert (row["class"], row["clock"], row["clock_date"]) == ("before_window", "published", d(10))


def test_golden_a_series() -> None:
    """The 1d and 60d day series, derived by hand from the intervals above.

    1d: CVE-5 is open from the first day (opening 1). CVE-1 becomes detectable while affected on d40
    (new, became_detectable). On d60 the 1.1 install closes CVE-1 and CVE-5 (resolved 2) and opens
    CVE-4 (new, entered_range). On d100 the 1.2 install closes CVE-4. So open is 1 on d31-d39, 2 on
    d40-d59, 1 on d60-d99 and 0 after; it sums to 9 + 40 + 40 = 89 = 20 + 29 + 40.

    60d: opening 1 (CVE-5); new d40 (CVE-1) and d45 (CVE-2), both became_detectable; resolved d59
    (CVE-2, by 1.0); on d119 the 1.1 install resolves CVE-1 and CVE-5 and opens CVE-4 (entered_range):
    one CVE new and two others resolved on one day, never the same CVE. Resolved d159 (CVE-4). open is
    1, 2, 3, 2, 1, 0 over d31-39, d40-44, d45-58, d59-118, d119-158, d159-180: sum 221 = 79 + 14 + 88 + 40.
    """
    doc, observed = golden_a()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)

    def nonzero(values: list[int]) -> dict[str, int]:
        return {d(31 + at): value for at, value in enumerate(values) if value}

    one = result["policies"]["1d"]["series"]
    assert one["opening"] == 1
    assert nonzero(one["new_by_reason"]["became_detectable"]) == {d(40): 1}
    assert nonzero(one["new_by_reason"]["entered_range"]) == {d(60): 1}
    assert nonzero(one["resolved"]) == {d(60): 2, d(100): 1}
    assert one["open"][:9] == [1] * 9 and one["open"][9:29] == [2] * 20 and one["open"][29:69] == [1] * 40
    assert sum(one["open"]) == 89 and one["open"][-1] == 0

    sixty = result["policies"]["60d"]["series"]
    assert sixty["opening"] == 1
    assert nonzero(sixty["new_by_reason"]["became_detectable"]) == {d(40): 1, d(45): 1}
    assert nonzero(sixty["new_by_reason"]["entered_range"]) == {d(119): 1}
    assert nonzero(sixty["resolved"]) == {d(59): 1, d(119): 2, d(159): 1}
    assert sum(sixty["open"]) == 221
    assert sixty["resolved_by_reason"]["update_installed"] == sixty["resolved"]


def test_never_is_not_a_longer_stop_than_sixty_days() -> None:
    """`never` opens on the newest release available on the window's first day (v1's steady state, kept
    by plan 4.6), which the 60-day device has not installed yet. In golden A the 60d device sees CVE-2
    (it runs 0.9 until d58) and `never` does not (it runs 1.0); `never` sees CVE-6 and the 60d device
    does not. So "a longer stop never sees fewer CVEs" holds along 1d, 7d, 14d, 30d, 60d and from 1d to
    never, and not between 60d and never: the definitions say so (`steady_state`)."""
    doc, observed = golden_a()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    exposed = {
        stop: {
            row["cve_id"]
            for row in result["cves"]
            if row["outcomes"][stop].get("outcome") == "exposed" and row["class"] == "in_window"
        }
        for stop in STOPS
    }
    assert "CVE-2026-0002" in exposed["60d"] - exposed["never"]
    assert "CVE-2026-0006" in exposed["never"] - exposed["60d"]
    assert exposed["1d"] <= exposed["never"]
    assert "59 days" in result["definitions"]["steady_state"]


# --- Golden B: a held line, line_start, ambiguity on a line nobody visits ----------------------


def golden_b() -> tuple[dict[str, Any], dict[str, Any]]:
    versions = [
        version("4.2.0", d(-92), "4.2"),
        version("4.2.1", d(-31), "4.2"),
        version("4.2.2", d(59), "4.2"),
        version("4.2.3", None, "4.2"),
        version("4.4.0", d(0), "4.4"),
        version("4.4.1", d(45), "4.4"),
        version("4.4.2", d(90), "4.4"),
        version("4.6.0", d(75), "4.6"),
    ]
    track = {
        "track": "demo/4.4",
        "label": "Demo 4.4",
        "path": {"kind": "hold", "ceiling_line": "4.4"},
        "line_components": 2,
        "timeline": "vendor",
        "versions": versions,
        "cves": [
            cve(
                "CVE-2026-0101",
                published=d(70),
                detectable=d(70),
                affected=[[0, 1], [4, 4]],
                fixes=[fix(2, "4.2"), fix(5, "4.4")],
                ambiguous_lines=["4.2"],
            ),
            cve(
                "CVE-2026-0102",
                published=d(80),
                detectable=d(80),
                affected=[[4, 4]],
                fixes=[fix(5, "4.4")],
                ambiguous_lines=["4.4"],
            ),
            cve("CVE-2026-0103", published=d(100), detectable=d(100), affected=[[4, 5]], fixes=[fix(6, "4.4")]),
            cve("CVE-2026-0105", published=d(50), detectable=d(50), affected=[[0, 2]], fixes=[fix(3, "4.2")]),
        ],
    }
    observed = timeline([{"version": v["v"], "date": v["date"]} for v in versions if v["date"]])
    return document([track]), observed


def test_golden_b_hold_path_and_line_start() -> None:
    """A held track: the device never crosses above 4.4, and the window waits for the 4.4 line.

    Start terms: the requested 2 years (2024-06-30); 59 days after the first available path release
    (4.2.0, d-92) = d-33; 59 days after the first release on the ceiling line (4.4.0, d0) = d59. The
    document has no detectable record, so no clock term. since = d59 (2026-03-01), named line_start.
    Without it a 60-day device would open on 4.2.1 and walk two lines.

    Devices on d59: 1d runs 4.4.1 (available d45) and installs 4.4.2 on d90; 4.6.0 (d75) is above
    the ceiling and never installed. 60d installs at +59: 4.4.0 d59, 4.4.1 d104, 4.2.2 d118 (ranked
    below 4.4.1, so not an event), 4.4.2 d149. never runs 4.4.1. 4.2.3 is undated, never installed.

    Visited lines: only 4.4 (every stop opens on a 4.4 release). So CVE-102 (ambiguous on 4.4) is
    excluded as branch_ambiguity, CVE-101 (ambiguous only on 4.2) is not, and CVE-105, whose fix
    4.2.3 is undated, is not excluded either: its line is never visited.

    CVE-101 (det d70; affected 4.2.0, 4.2.1, 4.4.0; fix 4.4.1 on 4.4): 1d runs 4.4.1 -> never seen,
    fix first. 60d runs 4.4.0 on d59-d103 -> [d70,d103] = 34 days, cleared d104 by 4.4.1. never runs
    4.4.1 -> never seen.
    CVE-103 (det d100; affected 4.4.0-4.4.1; fix 4.4.2): 1d runs 4.4.2 from d90 -> never seen.
    60d runs 4.4.0 on d100 -> [d100,d148] = 49, cleared d149. never runs 4.4.1 -> [d100,d180] = 81, open.
    CVE-105 (det d50, before the window; affected 4.2.x): every device runs 4.4 -> pre_window_closed
    under every stop, so it is counted (before_window 1) and not listed.
    """
    doc, observed = golden_b()
    result = walk(doc, app="demo", track="demo/4.4", timeline=observed)

    assert result["window"]["since"] == d(59)
    [shortened] = result["window"]["shortened_by"]
    assert shortened["reason"] == "line_start"
    assert "4.4.0" in shortened["sentence"] and "59 days" in shortened["sentence"]
    assert result["inputs"]["path"] == {"kind": "hold", "ceiling_line": "4.4", "waits_for_promotion": False}

    one, sixty, never = (result["policies"][stop] for stop in ("1d", "60d", "never"))
    assert (one["initial_version"], [row["version"] for row in one["installs"]]) == ("4.4.1", ["4.4.2"])
    assert (sixty["initial_version"], [(row["date"], row["version"]) for row in sixty["installs"]]) == (
        "4.4.0",
        [(d(104), "4.4.1"), (d(149), "4.4.2")],
    )
    assert never["initial_version"] == "4.4.1"

    assert {row["cve_id"]: row["reason"] for row in result["exclusions"]["cves"]} == {"CVE-2026-0102": "branch_ambiguity"}
    assert result["counts"]["before_window"] == 1
    assert [row["cve_id"] for row in result["cves"]] == ["CVE-2026-0101", "CVE-2026-0103"]
    assert all(policy["pre_window_closed"] == 1 for policy in result["policies"].values())

    assert outcome(result, "CVE-2026-0101", "1d")["why"] == "fix_installed_first"
    assert outcome(result, "CVE-2026-0101", "60d")["intervals"] == [[d(70), d(103)]]
    assert outcome(result, "CVE-2026-0101", "60d")["cleared_by"] == "4.4.1"
    assert outcome(result, "CVE-2026-0103", "60d")["exposure_days"] == 49
    assert outcome(result, "CVE-2026-0103", "never")["exposure_days"] == 81
    assert outcome(result, "CVE-2026-0103", "never")["open_at_window_end"] is True


# --- Golden C: a promotion table, rule 5, the train exception, the promotion clamp -------------


def golden_c() -> tuple[dict[str, Any], dict[str, Any]]:
    versions = [
        version("9.0.1", d(-92), train="9.0"),
        version("10.0.1", d(0), train="10.0"),
        version("10.0.2", d(19), train="10.0"),
        version("10.0.3", d(15), train="10.0"),
        version("11.0.1", d(9), train="11.0"),
        version("11.0.2", d(40), train="11.0"),
        version("12.0.1", d(59), train="12.0"),
    ]
    track = {
        "track": "demo/stable",
        "label": "Demo",
        "path": {"kind": "latest"},
        "line_components": 0,
        "timeline": "vendor",
        "promotions": [
            {"major": "10", "promoted": d(-31), "versions": [1, 3]},
            {"major": "11", "promoted": d(31), "versions": [4, 5]},
        ],
        "versions": versions,
        "cves": [
            cve("CVE-2026-0201", published=d(5), detectable=d(5), affected=[[0, 1]], fixes=[fix(2)]),
            cve("CVE-2026-0203", published=d(5), detectable=d(5), affected=[[0, 3]], fixes=[fix(4)]),
        ],
    }
    observed = timeline([{"version": v["v"], "date": v["date"]} for v in versions])
    return document([track]), observed


def test_golden_c_promotions_rule_5_and_the_clamp() -> None:
    """The waiting device, rule 5 and its train exception, and the window cut at an unpromoted major.

    Availability = max(date, the major's promotion day): 9.0.1 d-92 (below the table's oldest row,
    so its own date); 10.0.1 d0, 10.0.2 d19, 10.0.3 d15 (major 10 promoted d-31); 11.0.1 max(d9, d31)
    = d31; 11.0.2 d40 (major 11 promoted d31). 12.0.1 is above the table's newest row: never
    installed, and the timeline dates it d59, so the window ends the day before, d58 (promotion_table).
    It starts 59 days after the first available release, d-92 + 59 = d-33 (timeline_coverage).

    1d device: opens on 9.0.1; 10.0.1 on d0; 10.0.3 on d15; 10.0.2 on d19 is ranked below 10.0.3,
    so not an event; 11.0.1 on d31 (it waited for promotion: dated d9); 11.0.2 on d40.

    CVE-201 (det d5; affected 9.0.1-10.0.1; fix 10.0.2, dated d19):
      10.0.1 [d5,d14] affected by range.
      10.0.3 [d15,d30]: ranked above the fix and dated before it (d15), but of the fix's own train
             (10.0): the train exception, so clean.
      11.0.1 [d31,d39]: ranked above the fix, dated d9 before it, train 11.0: rule 5, affected.
      11.0.2 from d40: dated after the fix, clean.
      So two intervals, 10 + 9 = 19 days, cleared d40 by 11.0.2; new on d5 (became_detectable) and d31
      (entered_range), resolved d15 and d40.
    CVE-203 (det d5; affected 9.0.1-10.0.3; fix 11.0.1, dated d9): 11.0.2 is dated after it, so rule 5
      never applies: [d5,d30] = 26 days, cleared d31 by 11.0.1.
    60d device: installs at +59; 10.0.1 would be d59, past the window, so it runs 9.0.1 throughout:
      both CVEs [d5,d58] = 54 days, open at the window's end.
    """
    doc, observed = golden_c()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)

    assert (result["window"]["since"], result["window"]["until"]) == (d(-33), d(58))
    assert [row["reason"] for row in result["window"]["shortened_by"]] == ["timeline_coverage", "promotion_table"]
    assert "12.0.1" in result["window"]["shortened_by"][1]["sentence"]
    assert result["inputs"]["path"]["waits_for_promotion"] is True

    one = result["policies"]["1d"]
    assert [(row["date"], row["version"]) for row in one["installs"]] == [
        (d(0), "10.0.1"),
        (d(15), "10.0.3"),
        (d(31), "11.0.1"),
        (d(40), "11.0.2"),
    ]
    rule5 = outcome(result, "CVE-2026-0201", "1d")
    assert rule5["intervals"] == [[d(5), d(14)], [d(31), d(39)]]
    assert (rule5["exposure_days"], rule5["cleared_on"], rule5["cleared_by"]) == (19, d(40), "11.0.2")
    series = one["series"]
    offset = 33  # the window opens on d-33
    assert series["new_by_reason"]["became_detectable"][offset + 5] == 2
    assert series["new_by_reason"]["entered_range"][offset + 31] == 1
    assert series["resolved"][offset + 15] == 1 and series["resolved"][offset + 31] == 1 and series["resolved"][offset + 40] == 1

    plain = outcome(result, "CVE-2026-0203", "1d")
    assert (plain["intervals"], plain["cleared_by"]) == ([[d(5), d(30)]], "11.0.1")
    for cve_id in ("CVE-2026-0201", "CVE-2026-0203"):
        late = outcome(result, cve_id, "60d")
        assert (late["exposure_days"], late["open_at_window_end"]) == (54, True)
    assert result["policies"]["60d"]["initial_version"] == "9.0.1"
    assert result["policies"]["60d"]["installs"] == []


# --- Golden D: conformance mode (v1's rules) -------------------------------------------------


def test_golden_d_compat_v1_reproduces_the_v1_rules() -> None:
    """Conformance mode on golden A's track, derived by hand under v1's rules.

    The clock is publication for every CVE; the window is the requested 2 years, 2024-06-30 to
    2026-06-30, with no start term; a CVE is replayed only when published inside it, so CVE-4 (d18)
    and CVE-5 (d10) are replayed rather than carried in; exposure stops the day before `until`. The
    fixture's `v1_exclusion` is v1's verdict and replaces the walk's own ambiguity rules: CVE-3 and
    CVE-10 are excluded under it, and CVE-8 (published d150, affected 0.9-1.2, no fix) is replayed.

    Devices open on 2024-06-30 with nothing installed. 1d: 0.9 d-31, 1.0 d0, 1.1 d60, 1.2 d100. 60d:
    0.9 d28, 1.0 d59, 1.1 d119, 1.2 d159. never: nothing, ever, so every CVE is never seen, outside
    the affected range, with no version at publication.

      1d:  CVE-1 [d38,d59]=22; CVE-4 [d60,d99]=40; CVE-5 [d10,d59]=50; CVE-8 [d150,d180] open, 31 days
           inclusive, counted 30 (v1 stops before `until`); CVE-2 and CVE-6 fix first; CVE-11 outside.
           exposed 4, never_seen 3 (1 outside), 142 days.
      60d: CVE-1 [d38,d118]=81; CVE-2 [d45,d58]=14; CVE-4 [d119,d158]=40; CVE-5 [d28,d118]=91 (no
           release until d28); CVE-8 30 (open); CVE-6 fix first; CVE-11 outside. exposed 5, 256 days.
    The same numbers come out of LoonVD's v1 `run_policy` on the equivalent releases and ranges.
    """
    doc, observed = golden_a()
    track = doc["apps"][0]["tracks"][0]
    verdicts = {"CVE-2026-0003": "fixed_version_not_in_catalog", "CVE-2026-0010": "branch_ambiguity"}
    for row in track["cves"]:
        row["v1_exclusion"] = verdicts.get(row["cve_id"])
    track["cves"].append(
        cve("CVE-2026-0008", published=d(150), detectable=d(150), affected=[[0, 3]], fixes=[fix(None)], v1_exclusion=None)
    )
    result = walk(doc, app="demo", track="demo/stable", timeline=observed, compat_v1=True)

    assert (result["window"]["since"], result["window"]["until"], result["window"]["shortened_by"]) == (
        "2024-06-30",
        "2026-06-30",
        [],
    )
    counts = result["counts"]
    assert (counts["in_window"], counts["replayed"], counts["excluded"], counts["after_window"]) == (10, 7, 3, 1)
    assert counts["replayed_by_clock"] == {"detectable_at": 0, "published": 7}
    assert result["exclusions"]["by_reason"]["fixed_version_not_in_catalog"] == 1
    days = {stop: {row["cve_id"]: row["outcomes"][stop].get("exposure_days") for row in result["cves"]} for stop in ("1d", "60d")}
    assert days["1d"] == {
        "CVE-2026-0001": 22,
        "CVE-2026-0002": None,
        "CVE-2026-0004": 40,
        "CVE-2026-0005": 50,
        "CVE-2026-0006": None,
        "CVE-2026-0008": 30,
        "CVE-2026-0011": None,
    }
    assert days["60d"] == {
        "CVE-2026-0001": 81,
        "CVE-2026-0002": 14,
        "CVE-2026-0004": 40,
        "CVE-2026-0005": 91,
        "CVE-2026-0006": None,
        "CVE-2026-0008": 30,
        "CVE-2026-0011": None,
    }
    one, sixty, never = (result["policies"][stop] for stop in ("1d", "60d", "never"))
    assert (one["exposed"], one["never_seen"], one["never_seen_outside_affected_range"], one["exposure_days"]) == (4, 3, 1, 142)
    assert (sixty["exposed"], sixty["exposure_days"]) == (5, 256)
    assert (never["exposed"], never["never_seen"], never["never_seen_outside_affected_range"]) == (0, 7, 7)
    assert outcome(result, "CVE-2026-0008", "1d")["open_at_window_end"] is True
    assert outcome(result, "CVE-2026-0011", "never")["version_at_clock"] is None
    assert result["check"]["state"] == "not_applicable"
    assert "compat_v1" in result["definitions"]


# --- Refusals ---------------------------------------------------------------------------------


def refusal(document_: dict[str, Any], observed: dict[str, Any], **kwargs: Any) -> WalkRefused:
    with pytest.raises(WalkRefused) as caught:
        walk(document_, app=kwargs.pop("app", "demo"), track=kwargs.pop("track", "demo/stable"), timeline=observed, **kwargs)
    return caught.value


def test_a_timeline_with_no_matched_versions_is_refused_with_its_sentence() -> None:
    doc, _ = golden_a()
    refused = refusal(doc, timeline([{"version": "5.0", "date": d(1)}, {"version": "6.0", "date": d(2)}]))
    assert refused.reason == "no_matched_versions"
    assert refused.sentence == (
        "None of the 2 versions in the timeline from Vendor tags is a version LoonSec's patch-policy data lists for "
        "Demo Demo, so there is nothing to install and nothing was walked. Check that the timeline is Demo's."
    )
    assert refused.detail["unmatched"] == ["5.0", "6.0"]
    assert refusal(doc, timeline([])).reason == "no_matched_versions"


def test_above_five_percent_unmatched_is_refused_and_below_it_is_listed() -> None:
    doc, observed = golden_a()
    noisy = copy.deepcopy(observed)
    noisy["observations"].append({"version": "1.0-hotfix", "date": d(5)})
    refused = refusal(doc, noisy)
    assert refused.reason == "too_many_unmatched"
    assert refused.sentence.startswith("1 of 6 versions in the timeline from Vendor tags (16.7%) match no version")
    assert refused.detail["unmatched"] == ["1.0-hotfix"]

    # Twenty-five matched versions and one stray: 1 in 26 is 3.8%, under the line, and listed.
    many = [version(f"1.{n}", d(n * 3)) for n in range(25)]
    track = {"track": "demo/stable", "label": "Demo", "path": {"kind": "latest"}, "versions": many, "cves": []}
    stray = timeline([{"version": v["v"], "date": v["date"]} for v in many] + [{"version": "1.99-rc", "date": d(4)}])
    result = walk(document([track]), app="demo", track="demo/stable", timeline=stray)
    assert result["inputs"]["timeline"]["unmatched"] == ["1.99-rc"]


def test_an_empty_window_is_refused_with_its_reasons() -> None:
    doc, observed = golden_a()
    refused = refusal(doc, observed, until="2026-02-01")
    assert refused.reason == "window_empty"
    assert "nothing is left to walk" in refused.sentence and "2026-02-01" in refused.sentence


def test_unknown_app_track_algorithm_and_document_are_refused_in_words() -> None:
    doc, observed = golden_a()
    assert refusal(doc, observed, app="wireshark").sentence == "No reference yet for wireshark. That is not a count of zero."
    assert refusal(doc, observed, track="demo/esr").reason == "track_unknown"
    other = copy.deepcopy(doc)
    other["algorithm"] = "patch_walk/2"
    assert refusal(other, observed).sentence == (
        "This build reads patch_walk/1; the patch-policy data on this instance is 'patch_walk/2'. Update LoonInspect."
    )
    broken = copy.deepcopy(doc)
    broken["apps"][0]["tracks"][0]["cves"][0]["affected"] = [[0, 9]]
    refused = refusal(broken, observed)
    assert refused.reason == "document_invalid"
    assert "cves[0].affected[0]" in refused.sentence
    assert refusal({"kind": "something_else"}, observed).reason == "document_kind"
    unordered = copy.deepcopy(doc)
    unordered["apps"][0]["tracks"][0]["versions"][2]["line"] = "x"
    assert refusal(unordered, observed).reason == "document_invalid"


def test_bad_requests_are_refused() -> None:
    doc, observed = golden_a()
    assert refusal(doc, observed, years=5).reason == "request_invalid"
    assert refusal(doc, observed, stops=("2d",)).reason == "request_invalid"
    assert refusal(doc, {"source": "jamf", "name": "x", "as_of": None, "observations": []}).reason == "timeline_invalid"
    assert refusal(doc, timeline([{"version": "1.0", "date": "yesterday"}])).reason == "timeline_invalid"


def test_a_held_line_the_timeline_never_dates_is_refused() -> None:
    """Fleet follows only Wireshark's newest line: a 4.4 hold over a timeline with no 4.4 release."""
    doc, _ = golden_b()
    newest_only = timeline([{"version": "4.6.0", "date": d(75)}, {"version": "4.2.0", "date": d(-92)}])
    refused = refusal(doc, newest_only, track="demo/4.4")
    assert refused.reason == "ceiling_line_undated"
    assert "dates no Demo 4.4 release" in refused.sentence


def test_public_timeline_reads_the_documents_dates_and_refuses_without_them() -> None:
    doc, _ = golden_a()
    built = public_timeline(doc, app="demo", track="demo/stable")
    assert built["source"] == "public" and built["name"] == "Vendor tags"
    assert [row["version"] for row in built["observations"]] == ["0.9", "1.0", "1.1", "1.2"]
    assert walk(doc, app="demo", track="demo/stable", timeline=built)["counts"]["replayed"] == 4
    doc["apps"][0]["tracks"][0]["timeline"] = None
    with pytest.raises(WalkRefused) as caught:
        public_timeline(doc, app="demo", track="demo/stable")
    assert caught.value.sentence == (
        "LoonSec holds no public release dates for Demo yet. Jamf or Fleet may: they are read from this instance."
    )


# --- Identity and parity ----------------------------------------------------------------------


def test_the_same_input_walks_to_the_same_run_in_any_observation_order() -> None:
    doc, observed = golden_a()
    first = walk(doc, app="demo", track="demo/stable", timeline=observed)
    shuffled = copy.deepcopy(observed)
    random.Random(7).shuffle(shuffled["observations"])
    second = walk(doc, app="demo", track="demo/stable", timeline=shuffled)
    assert (first["input_id"], first["run_id"]) == (second["input_id"], second["run_id"])
    assert first["input_id"] == input_id(doc, app="demo", track="demo/stable", timeline=shuffled)
    other = walk(doc, app="demo", track="demo/stable", timeline=observed, stops=("7d",))
    assert other["input_id"] != first["input_id"] and list(other["policies"]) == ["7d"]
    assert other["policies"]["7d"] == first["policies"]["7d"]
    jamf = dict(observed, source="jamf")
    assert walk(doc, app="demo", track="demo/stable", timeline=jamf)["input_id"] != first["input_id"]


def test_parity_with_the_documents_check() -> None:
    """Plan 4.7: the public walk at the default window equals the document's `check`, or nothing is shown."""
    doc, observed = golden_a()
    first = walk(doc, app="demo", track="demo/stable", timeline=observed)
    doc["apps"][0]["tracks"][0]["check"] = {"2y": {stop: check_totals(first, stop) for stop in STOPS}}
    assert walk(doc, app="demo", track="demo/stable", timeline=observed)["check"]["state"] == "matched"
    assert walk(doc, app="demo", track="demo/stable", timeline=observed, years=3)["check"]["state"] == "no_entry"
    assert (
        walk(doc, app="demo", track="demo/stable", timeline=dict(observed, source="jamf"))["check"]["state"] == "not_applicable"
    )
    assert walk(doc, app="demo", track="demo/stable", timeline=observed, until="2026-06-01")["check"]["state"] == "not_applicable"

    doc["apps"][0]["tracks"][0]["check"]["2y"]["60d"]["exposure_days"] += 1
    refused = refusal(doc, observed)
    assert refused.reason == "parity"
    assert "60d: exposure_days is 93 here and 94 in the data" in refused.sentence


def test_window_for_names_the_window_without_walking() -> None:
    doc, observed = golden_a()
    assert window_for(doc, app="demo", track="demo/stable", timeline=observed)["since"] == "2026-02-01"
    aligned = walk(doc, app="demo", track="demo/stable", timeline=observed, common=("2026-03-01", "2026-05-31"))
    assert (aligned["window"]["since"], aligned["window"]["until"]) == ("2026-03-01", "2026-05-31")
    assert {row["reason"] for row in aligned["window"]["shortened_by"]} == {"common_window"}
    assert aligned["check"]["state"] == "not_applicable"


# --- Seeded property tests --------------------------------------------------------------------


def random_case(rng: random.Random, *, monotone: bool = False) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """A generated document, timeline and request. Dates fall in [d0, d300], the document is dated d420,
    so a 2- or 3-year request never binds the window's start (which the shift property relies on).

    `monotone`: one line, dates rising with rank, every affected set a prefix of the list, no promotion
    table. Under those, a device that waits longer always runs a release at or below a faster one's,
    so it is affected whenever the faster one is, and longer stops cannot see fewer CVEs."""
    lines = [""] if monotone else rng.choice([[""], ["1.0", "1.2"], ["2.0", "2.2", "2.4"]])
    count = rng.randint(3, 12)
    line_of = sorted(rng.choice(lines) for _ in range(count)) if len(lines) > 1 else [""] * count
    order = sorted(rng.sample(range(0, 300), count)) if monotone else [rng.randint(0, 300) for _ in range(count)]
    versions = []
    for index in range(count):
        undated = not monotone and rng.random() < 0.1
        train = f"t{index // 2}" if not monotone and rng.random() < 0.3 else f"t{index}"
        versions.append(version(f"{line_of[index] or '1'}.{index}", None if undated else d(order[index]), line_of[index], train))
    track: dict[str, Any] = {
        "track": "demo/stable",
        "label": "Demo",
        "path": {"kind": "latest"},
        "timeline": "vendor",
        "versions": versions,
        "cves": [],
        "exclusions": {"cves": []},
    }
    if not monotone and len(set(line_of)) > 1 and rng.random() < 0.5:
        track["path"] = {"kind": "hold", "ceiling_line": rng.choice(sorted(set(line_of)))}
    if not monotone and rng.random() < 0.3:
        cut = rng.randint(1, count - 1)
        track["promotions"] = [{"major": "a", "promoted": d(rng.randint(0, 200)), "versions": [0, cut - 1]}]
        if rng.random() < 0.5 and cut < count - 1:
            track["promotions"].append({"major": "b", "promoted": d(rng.randint(0, 250)), "versions": [cut, count - 2]})
    for number in range(rng.randint(0, 18)):
        cve_id = f"CVE-2026-{number:04d}"
        published = rng.randint(-60, 330)
        detectable = None if rng.random() < 0.3 else published + rng.randint(0, 20)
        if monotone:
            fix_at = rng.randint(1, count)
            affected = [[0, fix_at - 1]]
            fixes = [fix(fix_at if fix_at < count else None)]
        else:
            start = rng.randint(0, count - 1)
            end = rng.randint(start, count - 1)
            affected = [[start, end]] if rng.random() < 0.9 else []
            fixes = [fix(rng.choice([*range(count), None]), line) for line in sorted(set(line_of)) if rng.random() < 0.8]
        if not monotone and rng.random() < 0.08:
            track["exclusions"]["cves"].append({"cve_id": cve_id, "reason": "rejected", "published": d(published)})
            continue
        row = cve(
            cve_id,
            published=d(published),
            detectable=d(detectable) if detectable is not None else None,
            affected=affected,
            fixes=fixes,
        )
        if not monotone and rng.random() < 0.1:
            row["ambiguous_lines"] = [rng.choice(lines)]
        if detectable is not None and rng.random() < 0.2:
            row["detectable_not_before"] = d(detectable - rng.randint(0, 3))
        track["cves"].append(row)
    doc = document([track], coverage=d(rng.randint(-30, 60)) if rng.random() < 0.5 else None, as_of=d(420) + "T03:00:00Z")
    observations = [{"version": v["v"], "date": v["date"]} for v in versions if v["date"]]
    if observations and not monotone and rng.random() < 0.3:
        twin = rng.choice(observations)
        observations.append({"version": twin["version"].upper(), "date": d(rng.randint(0, 300))})
    observed = timeline(observations, as_of=d(rng.randint(310, 430)))
    request = {"years": rng.choice([2, 3]), "until": rng.choice([None, d(rng.randint(250, 400))])}
    return doc, observed, request


SKIPPED = {"window_empty", "nothing_to_install", "ceiling_line_undated", "no_matched_versions", "too_many_unmatched"}


@functools.cache
def generated(count: int, *, monotone: bool = False) -> tuple[tuple[int, dict, dict, dict, dict], ...]:
    """The generated cases that walked, walked once per session: the tests below only read them."""
    walked = []
    for seed in range(count):
        doc, observed, request = random_case(random.Random(seed), monotone=monotone)
        try:
            result = walk(doc, app="demo", track="demo/stable", timeline=observed, **request)
        except WalkRefused as refused:
            assert refused.reason in SKIPPED, (seed, refused.reason, refused.sentence)
            assert refused.sentence
            continue
        walked.append((seed, doc, observed, request, result))
    assert len(walked) >= count // 2, f"only {len(walked)} of {count} generated cases walked"
    return tuple(walked)


GENERATED = 400


def test_totals_always_close() -> None:
    """Every generated walk closes: never_seen + exposed = replayed per stop, replayed + excluded =
    in_window, the reasons sum to the excluded, the series steps by new - resolved, its days equal the
    listed CVEs' intervals, and the rows tally to every total (`invariant_failures`)."""
    for seed, _, _, _, result in generated(GENERATED):
        assert invariant_failures(result) == [], seed
        counts = result["counts"]
        for stop, policy in result["policies"].items():
            assert policy["never_seen"] + policy["exposed"] == counts["replayed"], (seed, stop)
        assert counts["replayed"] + counts["excluded"] == counts["in_window"], seed
        assert sum(counts["replayed_by_clock"].values()) == counts["replayed"], seed


def test_a_cve_is_never_new_and_resolved_on_the_same_day() -> None:
    """Intervals of one CVE are merged when adjacent, so the day one closes is never the day the next
    opens: no CVE is both new and resolved on one day (plan: "unless defined"; nothing defines one)."""
    for seed, _, _, _, result in generated(GENERATED):
        until = result["window"]["until"]
        for row in result["cves"]:
            for stop, found in row["outcomes"].items():
                starts = {first for first, _ in found.get("intervals", [])}
                ends = {
                    (dt.date.fromisoformat(last) + dt.timedelta(days=1)).isoformat()
                    for _, last in found.get("intervals", [])
                    if last != until
                }
                assert not starts & ends, (seed, row["cve_id"], stop)


def test_longer_stops_never_see_fewer_cves() -> None:
    """On monotone documents (see `random_case`), each day stop's exposed set contains the faster
    stop's, and `never` contains the 1-day stop's. Not asserted: 60d against never (golden A shows why)."""
    chain = ["1d", "7d", "14d", "30d", "60d"]
    for seed, _, _, _, result in generated(GENERATED, monotone=True):
        exposed = {
            stop: {
                r["cve_id"] for r in result["cves"] if r["class"] == "in_window" and r["outcomes"][stop]["outcome"] == "exposed"
            }
            for stop in STOPS
        }
        for faster, slower in itertools.pairwise(chain):
            assert exposed[faster] <= exposed[slower], (seed, faster, slower)
            assert result["policies"][faster]["exposed"] <= result["policies"][slower]["exposed"], seed
        assert exposed["1d"] <= exposed["never"], seed


def shifted(value: Any, days: int) -> Any:
    """Every date in a document, timeline or request moved by `days`; everything else as it was."""
    if isinstance(value, dict):
        return {key: shifted(item, days) for key, item in value.items()}
    if isinstance(value, list):
        return [shifted(item, days) for item in value]
    if isinstance(value, str) and len(value) >= 10 and value[4] == "-" and value[7] == "-":
        try:
            moved = dt.date.fromisoformat(value[:10]) + dt.timedelta(days=days)
        except ValueError:
            return value
        return moved.isoformat() + value[10:]
    return value


def test_shifting_every_date_shifts_the_series() -> None:
    """Moving every date in the inputs by k days moves the window by k days and leaves every count,
    every series and every outcome as it was, its dates moved by k."""
    for seed, doc, observed, request, result in generated(GENERATED)[: GENERATED // 4]:
        k = random.Random(seed).choice([-400, -37, 1, 90, 365, 1000])
        moved = walk(shifted(doc, k), app="demo", track="demo/stable", timeline=shifted(observed, k), **shifted(request, k))
        assert moved["window"]["since"] == shifted(result["window"]["since"], k), seed
        assert moved["window"]["until"] == shifted(result["window"]["until"], k), seed
        assert moved["counts"] == result["counts"], seed
        for stop, policy in result["policies"].items():
            again = moved["policies"][stop]
            assert again["series"] == policy["series"], (seed, stop)
            assert {key: again[key] for key in again if key != "installs"} == {
                key: shifted(policy[key], k) for key in policy if key != "installs"
            }, (seed, stop)
            assert again["installs"] == shifted(policy["installs"], k), (seed, stop)
        assert [row["outcomes"] for row in moved["cves"]] == shifted([row["outcomes"] for row in result["cves"]], k), seed


def test_generated_walks_are_deterministic() -> None:
    """The same input, observations in another order, is the same input_id and the same run_id."""
    for seed, doc, observed, request, result in generated(GENERATED)[: GENERATED // 8]:
        shuffled = copy.deepcopy(observed)
        random.Random(seed + 1).shuffle(shuffled["observations"])
        again = walk(doc, app="demo", track="demo/stable", timeline=shuffled, **request)
        assert (again["input_id"], again["run_id"]) == (result["input_id"], result["run_id"]), seed


def test_a_generated_timeline_with_no_matched_versions_is_refused() -> None:
    for seed in range(50):
        doc, observed, request = random_case(random.Random(seed))
        foreign = timeline([{"version": f"x{row['version']}", "date": row["date"]} for row in observed["observations"]])
        with pytest.raises(WalkRefused) as caught:
            walk(doc, app="demo", track="demo/stable", timeline=foreign, **request)
        assert caught.value.reason == "no_matched_versions", seed
        assert caught.value.sentence.startswith("None of the "), seed


def test_the_module_reads_no_clock_database_or_network() -> None:
    """Pure by construction: the module imports only the standard library, and names no wall clock."""
    with open(walk_module.__file__, encoding="utf-8") as handle:
        source = handle.read()
    imports = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imports |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".")[0])
    assert imports <= {"__future__", "datetime", "hashlib", "json", "bisect", "collections", "dataclasses", "typing"}
    for forbidden in ("today(", "now(", "utcnow(", "time.time"):
        assert forbidden not in source
