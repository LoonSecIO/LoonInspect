"""The patch-policy day-walk (`app.core.patch_policy_walk`, #614): hand-derived goldens, refusals, parity,
and seeded property tests over generated documents.

Pure: no database, no network. The goldens are small documents whose whole walk is derived by hand in
each test's docstring, so a change to a counting rule shows up as a number a reader can check against
the derivation. Day numbers in the derivations count from 2026-01-01 = d0 (so d60 = 2026-03-02 and
d180 = 2026-06-30). A stop's label is the days it waits (ruled 2026-11-27, "0 = same day"): a stop of
D days installs a release D days after the day it became available, so the 0-day stop installs it that
day and the 1-day stop the day after. The property tests draw documents from a seeded generator
(`random.Random(seed)`, no hypothesis dependency) and hold the plan's invariants on every one that
walks. The frozen check, last, holds this walk to the totals it once wrote into a document shaped like
a published one (`fixtures/patch_policy/frozen_check.<algorithm>.json`): LoonSec's published check is
held to every instance's copy of this module, so a walk that counts differently is a new algorithm,
with a file of its own. patch_walk/1's file stays as that walk wrote it; this walk is patch_walk/2.
"""

from __future__ import annotations

import ast
import copy
import datetime as dt
import functools
import itertools
import json
import random
import sys
from pathlib import Path
from typing import Any

import pytest

from app.core import patch_policy_walk as walk_module
from app.core.patch_policy_walk import (
    CHECK_KEYS,
    POLICIES,
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
        "algorithm": walk_module.ALGORITHM,
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
    (2024-06-30); the detectable record, which begins 2026-01-31, so 2026-02-01 (d31); 60 days after
    the first available release, the 60-day stop's wait, d-31 + 60 = d29. So since = d31, bound by
    clock_coverage alone, and the window holds 150 days.

    Placement by clock (detectable_at, else published): before the window CVE-4 (det d20) and CVE-5
    (published d10, no det); after it CVE-7 (d185); in it CVE-1 (d40), -2 (d45), -3 (d50), -6
    (d170), -9 (published d50), -10 (d35), -11 (published d60) = 7. Every device runs line "", so
    "" is visited: CVE-10 is ambiguous on it (branch_ambiguity), and CVE-9 is the document's own
    exclusion (rejected). CVE-11 is ambiguous only on 2.0, which nobody visits. CVE-3's fix is 1.3,
    which the timeline does not date, and nothing above it on line "" is dated either: since the
    2026-11-25 ruling that excludes nothing, and CVE-3 is walked by its affected run (fix_dated_by
    says `undated`). So replayed 5 (-1, -2, -3, -6, -11), excluded 2; by clock 4 detectable_at
    (-1, -2, -3, -6) and 1 published (-11).

    fix_dated_by, over the rows `cves` lists (the five replayed, and CVE-4 and CVE-5 from before
    the window): CVE-1, -2, -4, -5 and -6 name a fix the timeline dates (`fix`); CVE-3's 1.3 is
    dated by nothing at or above it, and CVE-11 names no fix version at all (a null index): both
    `undated`. So fix_dating is fix 5, next_dated 0, undated 2.
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
    assert (counts["replayed"], counts["excluded"], counts["not_detectable"]) == (5, 2, 1)
    assert counts["replayed_by_clock"] == {"detectable_at": 4, "published": 1}
    by_reason = result["exclusions"]["by_reason"]
    assert (by_reason["rejected"], by_reason["branch_ambiguity"]) == (1, 1)
    assert sum(by_reason.values()) == 2
    assert "fixed_version_not_in_timeline" not in by_reason
    assert {row["cve_id"]: row["reason"] for row in result["exclusions"]["cves"]} == {
        "CVE-2026-0009": "rejected",
        "CVE-2026-0010": "branch_ambiguity",
    }
    details = {row["cve_id"]: row["detail"] for row in result["exclusions"]["cves"]}
    assert details["CVE-2026-0010"] == "the range is ambiguous on '', which the path visits"
    dated_by = {row["cve_id"]: row["fix_dated_by"] for row in result["cves"]}
    assert dated_by["CVE-2026-0001"] == [{"line": "", "fix": "1.1", "named": None, "dated_as": "1.1", "on": d(60), "how": "fix"}]
    assert dated_by["CVE-2026-0003"] == [
        {"line": "", "fix": "1.3", "named": None, "dated_as": None, "on": None, "how": "undated"}
    ]
    assert dated_by["CVE-2026-0011"] == [{"line": "", "fix": None, "named": None, "dated_as": None, "on": None, "how": "undated"}]
    assert counts["fix_dating"] == {"fix": 5, "next_dated": 0, "undated": 2}
    assert result["check"]["state"] == "no_entry"
    assert invariant_failures(result) == []


def test_golden_a_devices_and_totals_per_stop() -> None:
    """Each stop's device and totals, derived by hand. Availability: 0.9 d-31, 1.0 d0, 1.1 d60, 1.2 d100.

    A D-day stop installs at availability + D (its label is the days it waits) and opens on the newest
    release installed by d31:
      0d   +0  (d-31, d0, d60, d100)    -> opens 1.0; 1.1 on d60, 1.2 on d100
      1d   +1  (d-30, d1, d61, d101)    -> opens 1.0; 1.1 on d61, 1.2 on d101
      3d   +3                           -> opens 1.0; 1.1 on d63, 1.2 on d103
      7d   +7                           -> opens 1.0; 1.1 on d67, 1.2 on d107
      14d  +14                          -> opens 1.0; 1.1 on d74, 1.2 on d114
      30d  +30 (d-1, d30, d90, d130)    -> opens 1.0, installed the day before the window; 1.1 on d90, 1.2 on d130
      60d  +60 (d29, d60, d120, d160)   -> opens 0.9; 1.0 on d60, 1.1 on d120, 1.2 on d160
      never: the newest available by d31 -> 1.0, nothing after.
    So 0d is the device the 1-day stop was before the 2026-11-27 ruling, and every other day stop
    installs each release one day later than the stop of its label did then.

    In-window CVEs (inclusive day intervals):
      CVE-3 (det d50, affected 1.2 only, fix 1.3, which nothing dates): walked by its run, so every
             day stop is exposed from its 1.2 install to the window's end, open:
             0d [d100,d180]=81  1d [d101,d180]=80  3d [d103,d180]=78  7d [d107,d180]=74
             14d [d114,d180]=67  30d [d130,d180]=51  60d [d160,d180]=21. never runs 1.0: never seen,
             outside the affected range.
      CVE-1 (det d40, affected 0.9-1.0, fix 1.1): exposed until the 1.1 install.
             0d [d40,d59]=20  1d [d40,d60]=21  3d [d40,d62]=23  7d [d40,d66]=27  14d [d40,d73]=34
             30d [d40,d89]=50  60d [d40,d119]=80 (0.9, then 1.0 from d60, both affected)
             never [d40,d180]=141, open at the window's end.
      CVE-2 (det d45, affected 0.9 only, fix 1.0): only the 60d device is on 0.9 then: [d45,d59]=15,
             cleared d60 by 1.0. Every other stop runs 1.0 on d45: never seen, fix installed first.
      CVE-6 (det d170, affected 0.9-1.1, fix 1.2): every day stop runs 1.2 by d170 (the 60d one from
             d160): never seen, fix first. never runs 1.0: [d170,d180]=11, open.
      CVE-11 (published d60, affected only 1.3, which nobody installs, no fix): never seen, outside the
             affected range, under every stop.
    So exposure days are 20 + 81 = 21 + 80 = 23 + 78 = 27 + 74 = 34 + 67 = 50 + 51 = 101 from 0d to
    30d (CVE-1 closes and CVE-3 opens on the same install day), 80 + 15 + 21 = 116 at 60d, and
    141 + 11 = 152 under never.
    Before the window:
      CVE-5 (published d10, affected 0.9-1.0): every device runs an affected release on d31, so it is
             carried in until the 1.1 install: 0d [d31,d59]=29  1d [d31,d60]=30  3d [d31,d62]=32
             7d [d31,d66]=36  14d [d31,d73]=43  30d [d31,d89]=59  60d [d31,d119]=89  never [d31,d180]=150.
      CVE-4 (det d20, affected 1.1 only): nobody runs 1.1 on d31, so every day stop enters it later,
             from its 1.1 install to its 1.2 install: 0d [d60,d99]  1d [d61,d100]  3d [d63,d102]
             7d [d67,d106]  14d [d74,d113]  30d [d90,d129]  60d [d120,d159], 40 days each. never never
             installs 1.1: pre_window_closed.
    """
    doc, observed = golden_a()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    policies = {stop: policy for stop, policy in result["policies"].items() if stop in STOPS}
    assert list(policies) == ["0d", "1d", "3d", "7d", "14d", "30d", "60d", "never"]
    # The built-in definitions follow the stops (golden G onward derives them): golden A's data names no
    # KEV source, so both KEV definitions are refused, and the critical one has no critical CVE to name.
    assert list(result["policies"])[8:] == ["critical-only"]
    assert {stop: refused["reason"] for stop, refused in result["policy_refusals"].items()} == {
        "kev-only": "kev_unknown",
        "30d-or-kev": "kev_unknown",
    }
    # Each day stop waits the days its label says.
    assert {stop: policy["install_delay_days"] for stop, policy in policies.items()} == {
        "0d": 0,
        "1d": 1,
        "3d": 3,
        "7d": 7,
        "14d": 14,
        "30d": 30,
        "60d": 60,
        "never": None,
    }

    expected = {
        # stop: (initial, installs, never_seen, outside, exposed, exposure_days, carried, entered, closed, days_carried)
        "0d": ("1.0", [(60, "1.1"), (100, "1.2")], 3, 1, 2, 20 + 81, 1, 1, 0, 29),
        "1d": ("1.0", [(61, "1.1"), (101, "1.2")], 3, 1, 2, 21 + 80, 1, 1, 0, 30),
        "3d": ("1.0", [(63, "1.1"), (103, "1.2")], 3, 1, 2, 23 + 78, 1, 1, 0, 32),
        "7d": ("1.0", [(67, "1.1"), (107, "1.2")], 3, 1, 2, 27 + 74, 1, 1, 0, 36),
        "14d": ("1.0", [(74, "1.1"), (114, "1.2")], 3, 1, 2, 34 + 67, 1, 1, 0, 43),
        "30d": ("1.0", [(90, "1.1"), (130, "1.2")], 3, 1, 2, 50 + 51, 1, 1, 0, 59),
        "60d": ("0.9", [(60, "1.0"), (120, "1.1"), (160, "1.2")], 2, 1, 3, 80 + 15 + 21, 1, 1, 0, 89),
        "never": ("1.0", [], 3, 2, 2, 141 + 11, 1, 0, 1, 150),
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
    assert policies["0d"]["open_at_window_end"] == {"in_window": 1, "carried_in": 0, "entered_after_start": 0}
    assert outcome(result, "CVE-2026-0003", "0d")["intervals"] == [[d(100), d(180)]]
    assert outcome(result, "CVE-2026-0003", "3d")["intervals"] == [[d(103), d(180)]]
    assert outcome(result, "CVE-2026-0003", "never")["why"] == "outside_affected_range"

    same_day = outcome(result, "CVE-2026-0001", "0d")
    assert same_day == {
        "class": "in_window",
        "outcome": "exposed",
        "exposure_days": 20,
        "open_at_window_end": False,
        "cleared_on": d(60),
        "cleared_by": "1.1",
        "intervals": [[d(40), d(59)]],
        "version_at_clock": "1.0",
    }
    # The 1-day stop installs 1.1 the day after it is dated, so CVE-1 is open one day more.
    assert outcome(result, "CVE-2026-0001", "1d") == {
        **same_day,
        "exposure_days": 21,
        "cleared_on": d(61),
        "intervals": [[d(40), d(60)]],
    }
    assert outcome(result, "CVE-2026-0002", "7d") == {
        "class": "in_window",
        "outcome": "never_seen",
        "why": "fix_installed_first",
        "version_at_clock": "1.0",
    }
    assert outcome(result, "CVE-2026-0011", "0d")["why"] == "outside_affected_range"
    # CVE-11's clock day is d60, the day 1.1 is dated: the 0-day device runs it that day, the 1-day
    # device does not yet.
    assert outcome(result, "CVE-2026-0011", "0d")["version_at_clock"] == "1.1"
    assert outcome(result, "CVE-2026-0011", "1d")["version_at_clock"] == "1.0"
    assert outcome(result, "CVE-2026-0004", "60d")["intervals"] == [[d(120), d(159)]]
    assert outcome(result, "CVE-2026-0004", "never") == {"class": "pre_window_closed", "outcome": "not_open_in_window"}
    row = next(row for row in result["cves"] if row["cve_id"] == "CVE-2026-0005")
    assert (row["class"], row["clock"], row["clock_date"]) == ("before_window", "published", d(10))


def test_golden_a_series() -> None:
    """The 0d, 1d and 60d day series, derived by hand from the intervals above.

    0d: CVE-5 is open from the first day (opening 1). CVE-1 becomes detectable while affected on d40
    (new, became_detectable). On d60 the 1.1 install closes CVE-1 and CVE-5 (resolved 2) and opens
    CVE-4 (new, entered_range). On d100 the 1.2 install closes CVE-4 and opens CVE-3 (new,
    entered_range), which nothing closes. So open is 1 on d31-d39, 2 on d40-d59, 1 on d60-d99 and 1
    from d100; it sums to 9 + 40 + 40 + 81 = 170 = 20 + 29 + 40 + 81.

    1d: the same, each install a day later: resolved 2 and entered 1 on d61, resolved 1 and entered 1
    on d101. open is 1 on d31-d39, 2 on d40-d60, 1 on d61-d100 and 1 from d101; it sums to
    9 + 42 + 40 + 80 = 171 = 21 + 30 + 40 + 80.

    60d: opening 1 (CVE-5); new d40 (CVE-1) and d45 (CVE-2), both became_detectable; resolved d60
    (CVE-2, by 1.0); on d120 the 1.1 install resolves CVE-1 and CVE-5 and opens CVE-4 (entered_range):
    one CVE new and two others resolved on one day, never the same CVE. On d160 the 1.2 install
    resolves CVE-4 and opens CVE-3 (entered_range). open is 1, 2, 3, 2, 1, 1 over d31-39, d40-44,
    d45-59, d60-119, d120-159, d160-180: sum 9 + 10 + 45 + 120 + 40 + 21 = 245 = 80 + 15 + 89 + 40 + 21.
    """
    doc, observed = golden_a()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)

    def nonzero(values: list[int]) -> dict[str, int]:
        return {d(31 + at): value for at, value in enumerate(values) if value}

    same_day = result["policies"]["0d"]["series"]
    assert same_day["opening"] == 1
    assert nonzero(same_day["new_by_reason"]["became_detectable"]) == {d(40): 1}
    assert nonzero(same_day["new_by_reason"]["entered_range"]) == {d(60): 1, d(100): 1}
    assert nonzero(same_day["resolved"]) == {d(60): 2, d(100): 1}
    assert same_day["open"][:9] == [1] * 9 and same_day["open"][9:29] == [2] * 20 and same_day["open"][29:69] == [1] * 40
    assert same_day["open"][69:] == [1] * 81
    assert sum(same_day["open"]) == 170 and same_day["open"][-1] == 1

    one = result["policies"]["1d"]["series"]
    assert one["opening"] == 1
    assert nonzero(one["new_by_reason"]["became_detectable"]) == {d(40): 1}
    assert nonzero(one["new_by_reason"]["entered_range"]) == {d(61): 1, d(101): 1}
    assert nonzero(one["resolved"]) == {d(61): 2, d(101): 1}
    assert one["open"][:9] == [1] * 9 and one["open"][9:30] == [2] * 21 and one["open"][30:70] == [1] * 40
    assert one["open"][70:] == [1] * 80
    assert sum(one["open"]) == 171

    sixty = result["policies"]["60d"]["series"]
    assert sixty["opening"] == 1
    assert nonzero(sixty["new_by_reason"]["became_detectable"]) == {d(40): 1, d(45): 1}
    assert nonzero(sixty["new_by_reason"]["entered_range"]) == {d(120): 1, d(160): 1}
    assert nonzero(sixty["resolved"]) == {d(60): 1, d(120): 2, d(160): 1}
    assert sum(sixty["open"]) == 245
    assert sixty["resolved_by_reason"]["update_installed"] == sixty["resolved"]


def test_never_is_not_a_longer_stop_than_sixty_days() -> None:
    """`never` opens on the newest release available on the window's first day (v1's steady state, kept
    by plan 4.6), which the 60-day device has not installed yet. In golden A the 60d device sees CVE-2
    (it runs 0.9 until d59) and `never` does not (it runs 1.0); `never` sees CVE-6 and the 60d device
    does not. So "a longer stop never sees fewer CVEs" holds along 0d, 1d, 3d, 7d, 14d, 30d, 60d and
    from 0d to never, and not between 60d and never: the definitions say so (`steady_state`). It holds
    for ranges that run from the oldest release up (the property tests' monotone documents); CVE-3, whose
    range is the newest dated release alone, is seen by every device that installs 1.2 and never by
    `never`."""
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
    assert exposed["0d"] - exposed["never"] == {"CVE-2026-0003"}
    assert "first 60 days" in result["definitions"]["steady_state"]


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

    Start terms: the requested 2 years (2024-06-30); 60 days after the first available path release
    (4.2.0, d-92) = d-32; 60 days after the first release on the ceiling line (4.4.0, d0) = d60. The
    document has no detectable record, so no clock term. since = d60 (2026-03-02), named line_start.
    Without it the window would open on d-32, and a 60-day device would open it on 4.2.0 and walk two
    lines.

    Path releases (up to the 4.4 line's last rank): 4.2.0 d-92, 4.2.1 d-31, 4.2.2 d59, 4.4.0 d0,
    4.4.1 d45, 4.4.2 d90; 4.2.3 is undated, never installed, and 4.6.0 (d75) is above the ceiling.
    Devices on d60, each installing at availability + its days:
      0d    opens 4.4.1 (d45; 4.2.2 on d59 ranks below it) and installs 4.4.2 on d90.
      14d   opens 4.4.1 (installed d59) and installs 4.4.2 on d104.
      30d   opens 4.4.0 (installed d30); 4.4.1 on d75, 4.2.2 on d89 (ranked below 4.4.1, so not an
            event), 4.4.2 on d120.
      60d   opens 4.4.0, installed d60, the window's first day itself; 4.4.1 on d105, 4.2.2 on d119
            (not an event), 4.4.2 on d150.
      never runs 4.4.1, the newest release available by d60.

    Visited lines: only 4.4 (every stop opens on a 4.4 release). So CVE-102 (ambiguous on 4.4) is
    excluded as branch_ambiguity, CVE-101 (ambiguous only on 4.2) is not, and CVE-105, whose fix
    4.2.3 is undated, is not excluded either: its line is never visited.

    CVE-101 (det d70; affected 4.2.0, 4.2.1, 4.4.0; fix 4.4.1 on 4.4): 0d to 14d run 4.4.1 -> never
    seen, fix first. 30d runs 4.4.0 on d60-d74 -> [d70,d74] = 5 days, cleared d75 by 4.4.1. 60d runs
    4.4.0 on d60-d104 -> [d70,d104] = 35 days, cleared d105 by 4.4.1. never runs 4.4.1 -> never seen.
    CVE-103 (det d100; affected 4.4.0-4.4.1; fix 4.4.2): 0d runs 4.4.2 from d90 -> never seen. 14d
    runs 4.4.1 until d103 -> [d100,d103] = 4, cleared d104. 30d -> [d100,d119] = 20, cleared d120.
    60d runs 4.4.0, then 4.4.1 from d105 -> [d100,d149] = 50, cleared d150. never runs 4.4.1 ->
    [d100,d180] = 81, open.
    CVE-105 (det d50, before the window; affected 4.2.x): every device runs 4.4 -> pre_window_closed
    under every stop, so it is counted (before_window 1) and not listed.
    """
    doc, observed = golden_b()
    result = walk(doc, app="demo", track="demo/4.4", timeline=observed)

    assert result["window"]["since"] == d(60)
    [shortened] = result["window"]["shortened_by"]
    assert shortened["reason"] == "line_start"
    assert "4.4.0" in shortened["sentence"] and "needs 60 days" in shortened["sentence"]
    assert result["inputs"]["path"] == {"kind": "hold", "ceiling_line": "4.4", "waits_for_promotion": False}

    def device(stop: str) -> tuple[str, list[tuple[str, str]]]:
        policy = result["policies"][stop]
        return policy["initial_version"], [(row["date"], row["version"]) for row in policy["installs"]]

    assert device("0d") == ("4.4.1", [(d(90), "4.4.2")])
    assert device("14d") == ("4.4.1", [(d(104), "4.4.2")])
    assert device("30d") == ("4.4.0", [(d(75), "4.4.1"), (d(120), "4.4.2")])
    assert device("60d") == ("4.4.0", [(d(105), "4.4.1"), (d(150), "4.4.2")])
    assert device("never") == ("4.4.1", [])

    assert {row["cve_id"]: row["reason"] for row in result["exclusions"]["cves"]} == {"CVE-2026-0102": "branch_ambiguity"}
    assert result["counts"]["before_window"] == 1
    assert [row["cve_id"] for row in result["cves"]] == ["CVE-2026-0101", "CVE-2026-0103"]
    assert all(policy["pre_window_closed"] == 1 for policy in result["policies"].values())

    assert outcome(result, "CVE-2026-0101", "0d")["why"] == "fix_installed_first"
    assert outcome(result, "CVE-2026-0101", "14d")["why"] == "fix_installed_first"
    assert outcome(result, "CVE-2026-0101", "30d")["intervals"] == [[d(70), d(74)]]
    assert outcome(result, "CVE-2026-0101", "60d")["intervals"] == [[d(70), d(104)]]
    assert outcome(result, "CVE-2026-0101", "60d")["cleared_by"] == "4.4.1"
    assert outcome(result, "CVE-2026-0103", "0d")["why"] == "fix_installed_first"
    assert [outcome(result, "CVE-2026-0103", stop)["exposure_days"] for stop in ("14d", "30d", "60d", "never")] == [4, 20, 50, 81]
    assert outcome(result, "CVE-2026-0103", "60d")["cleared_on"] == d(150)
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
    It starts 60 days after the first available release, d-92 + 60 = d-32 (timeline_coverage).

    0d device: opens on 9.0.1; 10.0.1 on d0; 10.0.3 on d15; 10.0.2 on d19 is ranked below 10.0.3,
    so not an event; 11.0.1 on d31 (it waited for promotion: dated d9); 11.0.2 on d40.
    1d device: each a day later, from the availability day, not from the timeline's date: 10.0.1 on
    d1, 10.0.3 on d16, 10.0.2 on d20 (not an event), 11.0.1 on d32, 11.0.2 on d41.

    CVE-201 (det d5; affected 9.0.1-10.0.1; fix 10.0.2, dated d19):
      0d: 10.0.1 [d5,d14] affected by range.
          10.0.3 [d15,d30]: ranked above the fix and dated before it (d15), but of the fix's own train
                 (10.0): the train exception, so clean.
          11.0.1 [d31,d39]: ranked above the fix, dated d9 before it, train 11.0: rule 5, affected.
          11.0.2 from d40: dated after the fix, clean.
          So two intervals, 10 + 9 = 19 days, cleared d40 by 11.0.2; new on d5 (became_detectable) and
          d31 (entered_range), resolved d15 and d40.
      1d: the same versions a day later: [d5,d15] and [d32,d40], 11 + 9 = 20 days, cleared d41 by
          11.0.2.
    CVE-203 (det d5; affected 9.0.1-10.0.3; fix 11.0.1, dated d9): 11.0.2 is dated after it, so rule 5
      never applies: 0d [d5,d30] = 26 days, cleared d31 by 11.0.1; 1d [d5,d31] = 27, cleared d32.
    60d device: installs at +60; 9.0.1 on d-32, the window's first day, and 10.0.1 would be d60, past
      the window, so it runs 9.0.1 throughout: both CVEs [d5,d58] = 54 days, open at the window's end.
    """
    doc, observed = golden_c()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)

    assert (result["window"]["since"], result["window"]["until"]) == (d(-32), d(58))
    assert [row["reason"] for row in result["window"]["shortened_by"]] == ["timeline_coverage", "promotion_table"]
    assert "12.0.1" in result["window"]["shortened_by"][1]["sentence"]
    assert result["inputs"]["path"]["waits_for_promotion"] is True

    same_day = result["policies"]["0d"]
    assert [(row["date"], row["version"]) for row in same_day["installs"]] == [
        (d(0), "10.0.1"),
        (d(15), "10.0.3"),
        (d(31), "11.0.1"),
        (d(40), "11.0.2"),
    ]
    assert [(row["date"], row["version"]) for row in result["policies"]["1d"]["installs"]] == [
        (d(1), "10.0.1"),
        (d(16), "10.0.3"),
        (d(32), "11.0.1"),
        (d(41), "11.0.2"),
    ]
    rule5 = outcome(result, "CVE-2026-0201", "0d")
    assert rule5["intervals"] == [[d(5), d(14)], [d(31), d(39)]]
    assert (rule5["exposure_days"], rule5["cleared_on"], rule5["cleared_by"]) == (19, d(40), "11.0.2")
    later = outcome(result, "CVE-2026-0201", "1d")
    assert later["intervals"] == [[d(5), d(15)], [d(32), d(40)]]
    assert (later["exposure_days"], later["cleared_on"], later["cleared_by"]) == (20, d(41), "11.0.2")
    series = same_day["series"]
    offset = 32  # the window opens on d-32
    assert series["new_by_reason"]["became_detectable"][offset + 5] == 2
    assert series["new_by_reason"]["entered_range"][offset + 31] == 1
    assert series["resolved"][offset + 15] == 1 and series["resolved"][offset + 31] == 1 and series["resolved"][offset + 40] == 1

    plain = outcome(result, "CVE-2026-0203", "0d")
    assert (plain["intervals"], plain["cleared_by"]) == ([[d(5), d(30)]], "11.0.1")
    assert outcome(result, "CVE-2026-0203", "1d")["intervals"] == [[d(5), d(31)]]
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

    Devices open on 2024-06-30 with nothing installed, and install at availability + their days, the
    count LoonVD's schema-3 replay files state. 0d: 0.9 d-31, 1.0 d0, 1.1 d60, 1.2 d100. 1d: 0.9 d-30,
    1.0 d1, 1.1 d61, 1.2 d101. 60d: 0.9 d29, 1.0 d60, 1.1 d120, 1.2 d160. never: nothing, ever, so every
    CVE is never seen, outside the affected range, with no version at publication.

      0d:  CVE-1 [d38,d59]=22; CVE-4 [d60,d99]=40; CVE-5 [d10,d59]=50; CVE-8 [d150,d180] open, 31 days
           inclusive, counted 30 (v1 stops before `until`); CVE-2 and CVE-6 fix first; CVE-11 outside.
           exposed 4, never_seen 3 (1 outside), 142 days.
      1d:  CVE-1 [d38,d60]=23; CVE-4 [d61,d100]=40; CVE-5 [d10,d60]=51; CVE-8 30 (open); CVE-2 and
           CVE-6 fix first; CVE-11 outside. exposed 4, never_seen 3 (1 outside), 144 days.
      60d: CVE-1 [d38,d119]=82; CVE-2 [d45,d59]=15; CVE-4 [d120,d159]=40; CVE-5 [d29,d119]=91 (no
           release until d29); CVE-8 30 (open); CVE-6 fix first; CVE-11 outside. exposed 5, 258 days.
    0d's numbers are the ones the 1-day stop counted before the 2026-11-27 ruling, which LoonVD's v1
    `run_policy` gave on the equivalent releases and ranges.
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
    days = {
        stop: {row["cve_id"]: row["outcomes"][stop].get("exposure_days") for row in result["cves"]}
        for stop in ("0d", "1d", "60d")
    }
    assert days["0d"] == {
        "CVE-2026-0001": 22,
        "CVE-2026-0002": None,
        "CVE-2026-0004": 40,
        "CVE-2026-0005": 50,
        "CVE-2026-0006": None,
        "CVE-2026-0008": 30,
        "CVE-2026-0011": None,
    }
    assert days["1d"] == {
        "CVE-2026-0001": 23,
        "CVE-2026-0002": None,
        "CVE-2026-0004": 40,
        "CVE-2026-0005": 51,
        "CVE-2026-0006": None,
        "CVE-2026-0008": 30,
        "CVE-2026-0011": None,
    }
    assert days["60d"] == {
        "CVE-2026-0001": 82,
        "CVE-2026-0002": 15,
        "CVE-2026-0004": 40,
        "CVE-2026-0005": 91,
        "CVE-2026-0006": None,
        "CVE-2026-0008": 30,
        "CVE-2026-0011": None,
    }
    same_day, one, sixty, never = (result["policies"][stop] for stop in ("0d", "1d", "60d", "never"))
    assert (same_day["exposed"], same_day["never_seen"], same_day["never_seen_outside_affected_range"]) == (4, 3, 1)
    assert same_day["exposure_days"] == 142
    assert (one["exposed"], one["never_seen"], one["never_seen_outside_affected_range"], one["exposure_days"]) == (4, 3, 1, 144)
    assert (sixty["exposed"], sixty["exposure_days"]) == (5, 258)
    assert (never["exposed"], never["never_seen"], never["never_seen_outside_affected_range"]) == (0, 7, 7)
    assert outcome(result, "CVE-2026-0005", "60d")["intervals"] == [[d(29), d(119)]]
    assert outcome(result, "CVE-2026-0008", "0d")["open_at_window_end"] is True
    assert outcome(result, "CVE-2026-0011", "never")["version_at_clock"] is None
    assert result["check"]["state"] == "not_applicable"
    # Conformance follows the count of LoonVD's schema-3 files: the days waited, stated per row.
    assert "A stop of D days waits D days" in result["definitions"]["compat_v1"]
    assert "install_delay_days" in result["definitions"]["compat_v1"]


# --- Refusals ---------------------------------------------------------------------------------


def refusal(document_: dict[str, Any], observed: dict[str, Any], **kwargs: Any) -> WalkRefused:
    with pytest.raises(WalkRefused) as caught:
        walk(document_, app=kwargs.pop("app", "demo"), track=kwargs.pop("track", "demo/stable"), timeline=observed, **kwargs)
    return caught.value


def test_a_timeline_with_no_matched_versions_is_refused_with_its_sentence() -> None:
    """The sentence says what to do next by source: LoonSec's own dates are reported; a timeline read on
    this instance may be the wrong title, and Public walks LoonSec's dates instead."""
    doc, _ = golden_a()
    stray = [{"version": "5.0", "date": d(1)}, {"version": "6.0", "date": d(2)}]
    refused = refusal(doc, timeline(stray))
    assert refused.reason == "no_matched_versions"
    assert refused.sentence == (
        "None of the 2 versions in the timeline from Vendor tags is a version LoonSec's patch-policy data lists for "
        "Demo, so there is nothing to install and nothing was walked. These dates are LoonSec's own and the same "
        "on every instance: report the sentence with the data's date (Settings › Support)."
    )
    assert refused.detail["unmatched"] == ["5.0", "6.0"]
    assert refusal(doc, timeline([])).reason == "no_matched_versions"
    jamf = refusal(doc, timeline(stray, source="jamf"))
    assert jamf.sentence.endswith(
        "nothing was walked. If the timeline is not Demo's, LoonInspect picked the wrong title: report the sentence "
        "(Settings › Support). These dates come from this instance's copy of Jamf's public patch catalog. Choose "
        "Public as the source to walk LoonSec's published dates for Demo instead."
    )


def test_above_five_percent_unmatched_in_reach_is_refused_and_below_it_is_listed() -> None:
    """Golden A's window is d31 to d180, so the versions in reach are those dated d-29 (d31 - 60, the
    60-day stop's wait) to d180: 1.0, 1.1 and 1.2 of the matched ones (0.9, d-31, is older; 1.3 is
    undated) and the stray 1.0-hotfix (d5). 1 of 4 is 25%: refused, with the span and the next check in
    the sentence."""
    doc, observed = golden_a()
    noisy = copy.deepcopy(observed)
    noisy["observations"].append({"version": "1.0-hotfix", "date": d(5)})
    refused = refusal(doc, noisy)
    assert refused.reason == "too_many_unmatched"
    assert refused.sentence.startswith(
        "1 of the 4 versions the timeline from Vendor tags dates from 2025-12-03 to 2026-06-30, the days a device in "
        "this view could install them, match no version LoonSec's patch-policy data lists for Demo (25.0%). "
        "Above 5% the walk is refused"
    )
    assert refused.sentence.endswith("report the sentence with the data's date (Settings › Support).")
    assert refused.detail["in_reach"] == {
        "since": "2025-12-03",
        "until": "2026-06-30",
        "matched": 3,
        "unmatched": ["1.0-hotfix"],
        "share": 0.25,
    }

    # Twenty-five matched versions and one stray, all in reach: 1 in 26 is 3.8%, under the line, and listed.
    many = [version(f"1.{n}", d(n * 3)) for n in range(25)]
    track = {"track": "demo/stable", "label": "Demo", "path": {"kind": "latest"}, "versions": many, "cves": []}
    stray = timeline([{"version": v["v"], "date": v["date"]} for v in many] + [{"version": "1.99-rc", "date": d(4)}])
    result = walk(document([track]), app="demo", track="demo/stable", timeline=stray)
    assert result["inputs"]["timeline"]["unmatched"] == ["1.99-rc"]
    assert result["inputs"]["timeline"]["in_reach"]["matched"] == 25
    assert result["inputs"]["timeline"]["in_reach"]["unmatched"] == ["1.99-rc"]


def test_the_unmatched_share_counts_only_the_versions_in_reach() -> None:
    """Plan 4.4 refuses above 5% unmatched *steps*. A hundred old matched versions cannot hide three
    misses among the window's eight releases, and two misses from years before the window cannot refuse
    a window whose every release matches."""
    old = [version(f"1.{n}", d(-2000 + n * 10)) for n in range(100)]
    new = [version(f"2.{n}", d(n * 20)) for n in range(8)]
    track = {"track": "demo/stable", "label": "Demo", "path": {"kind": "latest"}, "versions": old + new, "cves": []}
    spelled = [{"version": v["v"], "date": v["date"]} for v in old] + [
        {"version": v["v"] + ("-b1" if at in (1, 5, 7) else ""), "date": v["date"]} for at, v in enumerate(new)
    ]
    # All time: 3 unmatched of 108 (2.8%). In reach of 2024-06-30..2026-06-30: 3 of 8 (37.5%).
    refused = refusal(document([track]), timeline(spelled, source="jamf"))
    assert refused.reason == "too_many_unmatched"
    assert refused.detail["in_reach"]["unmatched"] == ["2.1-b1", "2.5-b1", "2.7-b1"]
    assert refused.detail["in_reach"]["matched"] == 5
    assert "(37.5%)" in refused.sentence
    assert refused.sentence.endswith("Choose Public as the source to walk LoonSec's published dates for Demo instead.")

    many = [version(f"1.{n}", d(n * 3)) for n in range(25)]
    track = {"track": "demo/stable", "label": "Demo", "path": {"kind": "latest"}, "versions": many, "cves": []}
    ancient = [{"version": f"0.{n}", "date": f"2019-0{n + 1}-01"} for n in range(2)]
    # All time: 2 unmatched of 27 (7.4%). In reach: none.
    result = walk(
        document([track]),
        app="demo",
        track="demo/stable",
        timeline=timeline([{"version": v["v"], "date": v["date"]} for v in many] + ancient),
    )
    assert result["inputs"]["timeline"]["unmatched"] == ["0.0", "0.1"]
    assert result["inputs"]["timeline"]["in_reach"]["unmatched"] == []


def test_exactly_five_percent_unmatched_walks_and_more_is_refused() -> None:
    """Nineteen matched versions in reach and one stray is 5.0%, at the line, and walks; drop one matched
    version from the timeline and 1 in 19 (5.3%) is refused."""
    many = [version(f"1.{n}", d(n * 3)) for n in range(19)]
    track = {"track": "demo/stable", "label": "Demo", "path": {"kind": "latest"}, "versions": many, "cves": []}
    named = [{"version": v["v"], "date": v["date"]} for v in many]
    stray = {"version": "1.99-rc", "date": d(4)}
    result = walk(document([track]), app="demo", track="demo/stable", timeline=timeline([*named, stray]))
    assert result["inputs"]["timeline"]["in_reach"]["share"] == 0.05
    refused = refusal(document([track]), timeline([*named[:-1], stray]))
    assert refused.reason == "too_many_unmatched"
    assert "(5.3%)" in refused.sentence


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
    other["algorithm"] = "patch_walk/3"
    assert refusal(other, observed).sentence == (
        "This build reads patch_walk/2; the patch-policy data on this instance is 'patch_walk/3'. Update LoonInspect."
    )
    # Data only older builds read (a copy one of them stored) is never a reason to update: it says so,
    # and never reaches parity, where the old count would read as a finding.
    other["algorithm"] = "patch_walk/1"
    older = refusal(other, observed)
    assert (older.reason, older.sentence) == (
        "algorithm_unknown",
        "This build reads patch_walk/2; the patch-policy data on this instance is 'patch_walk/1', which older builds "
        "read, so nothing was walked. Nothing on this instance needs updating: LoonSec's data for patch_walk/2 replaces "
        "it when it arrives.",
    )
    # A superscript two is a digit to `str.isdigit` and not to `int`: read as no number, never a crash.
    names = (("patch_walk/1", 1), ("patch_walk/12", 12), ("patch_walk/x", None), ("patch_walk/" + chr(0xB2), None))
    for name, number in (*names, ("other/1", None), (None, None)):
        assert walk_module.algorithm_number(name) == number, name
    assert [walk_module.is_older_algorithm(name) for name in ("patch_walk/1", "patch_walk/2", "patch_walk/3", "x")] == [
        True,
        False,
        False,
        False,
    ]
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


def _track(doc: dict[str, Any]) -> dict[str, Any]:
    return doc["apps"][0]["tracks"][0]


MALFORMED = [
    ("doc_id", lambda doc: doc.pop("doc_id")),
    ("as_of", lambda doc: doc.__setitem__("as_of", "yesterday")),
    ("apps", lambda doc: doc.__setitem__("apps", {})),
    ("apps[0]", lambda doc: doc["apps"].insert(0, "demo")),
    ("tracks", lambda doc: doc["apps"][0].__setitem__("tracks", {"demo/stable": {}})),
    ("definitions", lambda doc: doc.__setitem__("definitions", ["ranges"])),
    ("clocks", lambda doc: doc.__setitem__("clocks", "NVD")),
    ("sources", lambda doc: doc.__setitem__("sources", ["vendor"])),
    ("sources.detectable", lambda doc: doc["sources"].__setitem__("detectable", "x")),
    ("sources.timelines", lambda doc: doc["sources"].__setitem__("timelines", ["vendor"])),
    ("exclusion_reasons", lambda doc: doc.__setitem__("exclusion_reasons", ["rejected", 3])),
    ("path", lambda doc: _track(doc).__setitem__("path", "hold")),
    ("check", lambda doc: _track(doc).__setitem__("check", ["2y"])),
    ("exclusions", lambda doc: _track(doc).__setitem__("exclusions", ["CVE-2026-0009"])),
    ("not_detectable", lambda doc: _track(doc).__setitem__("not_detectable", ["CVE-2026-0012"])),
    ("not_detectable.count", lambda doc: _track(doc).__setitem__("not_detectable", {"count": "n/a"})),
    ("not_detectable.cves", lambda doc: _track(doc).__setitem__("not_detectable", {"count": 1, "cves": "CVE-2026-0012"})),
    ("not_detectable.cves", lambda doc: _track(doc).__setitem__("not_detectable", {"count": 1, "cves": ["CVE-2026-0011"]})),
    ("not_detectable.cves", lambda doc: _track(doc).__setitem__("not_detectable", {"count": 1, "cves": ["CVE-2026-0009"]})),
    ("cves[0]", lambda doc: _track(doc)["cves"][0].__setitem__("detectable_not_before", "junk")),
]


@pytest.mark.parametrize(("where", "mutate"), MALFORMED, ids=[f"{at}-{where}" for at, (where, _) in enumerate(MALFORMED)])
def test_a_malformed_document_is_refused_as_the_documents_fault_in_words(where: str, mutate: Any) -> None:
    """Every shape the walk reads is checked before it is read: a malformed document is refused as
    LoonSec's data, naming the place, never a Python exception (a 500 with no words) and never blamed
    on the request or read as absence ("No reference yet"). A CVE listed both as not detectable and as
    a row to walk or exclude is malformed: a CVE is in exactly one of the three lists."""
    doc, observed = golden_a()
    mutate(doc)
    refused = refusal(doc, observed)
    assert refused.reason == "document_invalid", refused.sentence
    assert refused.detail["where"] == where
    assert refused.sentence.startswith("LoonSec's patch-policy data")
    assert refused.sentence.endswith("report the sentence with the data's date (Settings › Support).")


def test_public_timeline_refuses_a_malformed_release_date_as_the_documents_fault() -> None:
    doc, _ = golden_a()
    _track(doc)["versions"][1]["date"] = "junk"
    with pytest.raises(WalkRefused) as caught:
        public_timeline(doc, app="demo", track="demo/stable")
    assert (caught.value.reason, caught.value.detail["where"]) == ("document_invalid", "versions[1].date")


def test_a_held_line_the_timeline_never_dates_is_refused() -> None:
    """Fleet follows only Wireshark's newest line: a 4.4 hold over a timeline with no 4.4 release."""
    doc, _ = golden_b()
    newest_only = [{"version": "4.6.0", "date": d(75)}, {"version": "4.2.0", "date": d(-92)}]
    refused = refusal(doc, timeline(newest_only), track="demo/4.4")
    assert refused.reason == "ceiling_line_undated"
    assert "dates no Demo 4.4 release" in refused.sentence
    assert refused.sentence.endswith("report the sentence with the data's date (Settings › Support).")
    fleet = refusal(doc, timeline(newest_only, source="fleet"), track="demo/4.4")
    assert fleet.sentence.endswith(
        "nothing was walked. These dates come from this instance's Fleet history. Choose Public as the source to "
        "walk LoonSec's published dates for Demo instead."
    )


def test_a_timeline_dating_only_releases_above_the_promotion_table_has_nothing_to_install() -> None:
    """Golden C's 12.0.1 is above the table's newest row. A timeline dating only it leaves the waiting
    device nothing to install: refused as such, not as an empty window."""
    doc, _ = golden_c()
    refused = refusal(doc, timeline([{"version": "12.0.1", "date": d(59)}]))
    assert refused.reason == "nothing_to_install"
    assert "above the newest major LoonSec's promotion table lists" in refused.sentence
    assert refused.detail["above_table"] == ["12.0.1"]

    held, _ = golden_b()
    above = refusal(held, timeline([{"version": "4.6.0", "date": d(75)}], source="jamf"), track="demo/4.4")
    assert above.reason == "nothing_to_install"
    assert "(every version it names that LoonSec lists is undated or above the 4.4 line)" in above.sentence
    assert above.sentence.endswith("Choose Public as the source to walk LoonSec's published dates for Demo instead.")
    plain, _ = golden_a()
    undated = refusal(plain, timeline([{"version": "1.3", "date": None}, {"version": "1.3-rc", "date": d(4)}]))
    assert undated.reason == "nothing_to_install"
    assert "(every version it names that LoonSec lists is undated), so nothing was walked. 1 of the versions" in undated.sentence
    assert undated.detail["unmatched"] == ["1.3-rc"]


def test_public_timeline_reads_the_documents_dates_and_refuses_without_them() -> None:
    doc, _ = golden_a()
    built = public_timeline(doc, app="demo", track="demo/stable")
    assert built["source"] == "public" and built["name"] == "Vendor tags"
    assert [row["version"] for row in built["observations"]] == ["0.9", "1.0", "1.1", "1.2"]
    assert walk(doc, app="demo", track="demo/stable", timeline=built)["counts"]["replayed"] == 5  # as golden A's
    doc["apps"][0]["tracks"][0]["timeline"] = None
    with pytest.raises(WalkRefused) as caught:
        public_timeline(doc, app="demo", track="demo/stable")
    assert caught.value.sentence == ("LoonSec holds no public release dates for Demo yet, so it has none of its own to walk.")


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


def test_everything_a_walk_reads_from_the_timeline_is_in_its_input_id() -> None:
    """The memo key holds every timeline field the output carries: one date moved (Jamf's hourly sync
    rewriting a date) is a new input, and so is the timeline's clock text, which the output repeats in
    `clocks.release_date`. The same input_id with a different run_id would be a defect."""
    doc, observed = golden_a()
    first = walk(doc, app="demo", track="demo/stable", timeline=observed)
    moved = copy.deepcopy(observed)
    moved["observations"][2]["date"] = d(61)
    again = walk(doc, app="demo", track="demo/stable", timeline=moved)
    assert again["input_id"] != first["input_id"]
    reclocked = dict(observed, clock="another sentence about the release date")
    clocked = walk(doc, app="demo", track="demo/stable", timeline=reclocked)
    assert clocked["clocks"]["release_date"] != first["clocks"]["release_date"]
    assert clocked["input_id"] != first["input_id"] and clocked["run_id"] != first["run_id"]


def test_parity_with_the_documents_check() -> None:
    """Plan 4.7: the public walk at the default window equals the document's `check`, or nothing is shown."""
    doc, observed = golden_a()
    first = walk(doc, app="demo", track="demo/stable", timeline=observed)
    doc["apps"][0]["tracks"][0]["check"] = {"2y": {stop: check_totals(first, stop) for stop in POLICIES}}
    # A definition the walk refused on this data is held as its refusal, as LoonVD's pinned copy writes it.
    assert doc["apps"][0]["tracks"][0]["check"]["2y"]["kev-only"] == {"refused": "kev_unknown"}
    assert walk(doc, app="demo", track="demo/stable", timeline=observed)["check"]["state"] == "matched"
    assert walk(doc, app="demo", track="demo/stable", timeline=observed, years=3)["check"]["state"] == "no_entry"
    assert (
        walk(doc, app="demo", track="demo/stable", timeline=dict(observed, source="jamf"))["check"]["state"] == "not_applicable"
    )
    assert walk(doc, app="demo", track="demo/stable", timeline=observed, until="2026-06-01")["check"]["state"] == "not_applicable"

    doc["apps"][0]["tracks"][0]["check"]["2y"]["60d"]["exposure_days"] += 1
    refused = refusal(doc, observed)
    assert refused.reason == "parity"
    assert "60d: exposure_days is 116 here and 117 in the data" in refused.sentence
    doc["apps"][0]["tracks"][0]["check"]["2y"]["60d"]["exposure_days"] -= 1

    # A check that lacks a stop's entry is refused at its first total, and so is one that lacks a
    # definition's (ruled 2026-11-28): a definition is never drawn unchecked.
    held = doc["apps"][0]["tracks"][0]["check"]["2y"]
    missing_stop = held.pop("3d")
    lacks_stop = refusal(doc, observed)
    assert lacks_stop.reason == "parity" and "(3d: since is '2026-02-01' here and None in the data)" in lacks_stop.sentence
    held["3d"] = missing_stop
    missing_definition = held.pop("critical-only")
    lacks_definition = refusal(doc, observed)
    assert lacks_definition.reason == "parity"
    assert "(critical-only: since is '2026-02-01' here and None in the data)" in lacks_definition.sentence
    assert lacks_definition.detail == {"stop": "critical-only", "key": "since", "walked": "2026-02-01", "published": None}
    held["critical-only"] = missing_definition
    # A definition walked here and published as a refusal, or the other way about, is a disagreement too.
    held["kev-only"] = check_totals(first, "never")
    swapped = refusal(doc, observed)
    assert swapped.reason == "parity" and "(kev-only: refused is 'kev_unknown' here and None in the data)" in swapped.sentence


def test_window_for_names_the_window_without_walking() -> None:
    doc, observed = golden_a()
    assert window_for(doc, app="demo", track="demo/stable", timeline=observed)["since"] == "2026-02-01"
    aligned = walk(doc, app="demo", track="demo/stable", timeline=observed, common=("2026-03-01", "2026-05-31"))
    assert (aligned["window"]["since"], aligned["window"]["until"]) == ("2026-03-01", "2026-05-31")
    assert {row["reason"] for row in aligned["window"]["shortened_by"]} == {"common_window"}
    assert aligned["check"]["state"] == "not_applicable"
    # A timeline the walk would refuse allows no window to align to either.
    noisy = copy.deepcopy(observed)
    noisy["observations"].append({"version": "1.0-hotfix", "date": d(5)})
    with pytest.raises(WalkRefused) as caught:
        window_for(doc, app="demo", track="demo/stable", timeline=noisy)
    assert caught.value.reason == "too_many_unmatched"


# --- Rules a one-line change could break unseen ---------------------------------------------


def test_exclusions_do_not_depend_on_the_stops_asked_for() -> None:
    """Exclusions are judged on the lines any of the eight stops visits, so asking for one stop excludes
    what asking for all eight does. Here only the 60-day device visits line 1, where the CVE's range is
    ambiguous: it is excluded under the 1-day stop too, or replayed + excluded could not equal in_window
    across views of one window.

    1.0 (line 1, d-100) and 2.0 (line 2, d0); the window opens d31 (clock_coverage). The 1-day device
    runs 2.0 from d1; the 60-day device runs 1.0 until 2.0's install on d60."""
    track = {
        "track": "demo/stable",
        "label": "Demo",
        "path": {"kind": "latest"},
        "versions": [version("1.0", d(-100), "1"), version("2.0", d(0), "2")],
        "cves": [
            cve("CVE-2026-0301", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1, "2")], ambiguous_lines=["1"])
        ],
    }
    doc = document([track], coverage="2026-01-31")
    observed = timeline([{"version": "1.0", "date": d(-100)}, {"version": "2.0", "date": d(0)}])
    every = walk(doc, app="demo", track="demo/stable", timeline=observed)
    assert every["policies"]["1d"]["initial_version"] == "2.0" and every["policies"]["60d"]["initial_version"] == "1.0"
    one = walk(doc, app="demo", track="demo/stable", timeline=observed, stops=("1d",))
    assert one["exclusions"] == every["exclusions"]
    assert one["exclusions"]["by_reason"]["branch_ambiguity"] == 1
    assert one["counts"] == every["counts"]


def test_a_release_dated_the_same_day_as_the_fix_is_clean_under_rule_5() -> None:
    """Rule 5 needs a release dated *before* the fix. Golden C with 11.0.1 dated d19, the day 10.0.2 (the
    fix) is dated: 11.0.1 no longer predates the fix, so under the 0-day stop CVE-201 closes on d15
    (10.0.3) for good."""
    doc, _ = golden_c()
    _track(doc)["versions"][4]["date"] = d(19)
    observed = timeline([{"version": v["v"], "date": v["date"]} for v in _track(doc)["versions"]])
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    clean = outcome(result, "CVE-2026-0201", "0d")
    assert (clean["intervals"], clean["cleared_on"], clean["cleared_by"]) == ([[d(5), d(14)]], d(15), "10.0.3")


def test_a_channel_start_binds_the_window() -> None:
    """A track that names its channel's first day starts 60 days after it, the 60-day stop's wait:
    d0 + 60 = d60, later than the detectable record's d31."""
    doc, observed = golden_a()
    _track(doc).update(channel_start=d(0), channel="stable")
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    assert result["window"]["since"] == d(60)
    [shortened] = result["window"]["shortened_by"]
    assert (shortened["reason"], shortened["date"]) == ("channel_start", d(60))
    assert shortened["sentence"] == "The stable channel begins on 2026-01-01, and the 60-day stop needs 60 days of it."


def test_a_timeline_read_before_the_documents_date_ends_the_window_the_day_before() -> None:
    doc, observed = golden_a()
    result = walk(doc, app="demo", track="demo/stable", timeline=dict(observed, as_of="2026-06-01"))
    assert result["window"]["until"] == "2026-05-31"
    assert [row["reason"] for row in result["window"]["shortened_by"]] == ["clock_coverage", "timeline_as_of"]


def test_a_fix_on_another_line_is_not_a_fix_installed_first() -> None:
    """Golden B plus CVE-106: affected 4.4.0 only, with a fix listed only on 4.2 (4.2.2, index 2). The
    1-day device runs 4.4.2 (index 6) on d100: ranked above the 4.2 fix, but on another line, so the CVE
    was never seen because 4.4.2 is outside the range, not because its fix came first."""
    doc, observed = golden_b()
    _track(doc)["cves"].append(
        cve("CVE-2026-0106", published=d(100), detectable=d(100), affected=[[4, 4]], fixes=[fix(2, "4.2")])
    )
    result = walk(doc, app="demo", track="demo/4.4", timeline=observed)
    assert outcome(result, "CVE-2026-0106", "1d")["why"] == "outside_affected_range"
    assert outcome(result, "CVE-2026-0106", "60d")["outcome"] == "exposed"


def test_uncertain_over_one_day_counts_more_than_a_day_and_not_one() -> None:
    """detectable_at one day after detectable_not_before is the day grain's own uncertainty; two days is
    counted."""
    doc, observed = golden_a()
    _track(doc)["cves"][0]["detectable_not_before"] = d(39)  # CVE-1, detectable d40: one day
    _track(doc)["cves"][1]["detectable_not_before"] = d(43)  # CVE-2, detectable d45: two days
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    assert result["counts"]["uncertain_over_1d"] == 1


# --- Golden E: a fix the timeline does not date (ruled 2026-11-25) ----------------------------
#
# "Count the next dated version at or above the fix." Each case is one line (or two) with the
# window d31 to d180 (the detectable record begins 2026-01-31; the first release, d-100, is older
# than d31 - 60), and one CVE detectable d40 whose range is the oldest release alone. The 0-day
# device installs each release the day it is dated, so its intervals read straight off the dates.


def fix_dating_walk(
    versions: list[dict[str, Any]],
    cves: list[dict[str, Any]],
    *,
    promotions: list[dict[str, Any]] | None = None,
    observed: dict[str, Any] | None = None,
    **doc_extra: Any,
) -> dict[str, Any]:
    track = {
        "track": "demo/stable",
        "label": "Demo",
        "path": {"kind": "latest"},
        "promotions": promotions,
        "timeline": "vendor",
        "versions": versions,
        "cves": cves,
    }
    doc = {**document([track], coverage="2026-01-31"), **doc_extra}
    observed = observed or timeline([{"version": v["v"], "date": v["date"]} for v in versions if v["date"]])
    return walk(doc, app="demo", track="demo/stable", timeline=observed)


def test_an_undated_fix_counts_from_the_next_dated_version_and_installing_it_clears() -> None:
    """1.0 (d-100), 1.1 (undated: the fix), 1.2 (d60). CVE-401 (det d40, range 1.0, fix 1.1, which
    NVD names 1.0.5) was excluded as fixed_version_not_in_timeline before the ruling. Now its
    effective fix is 1.2, the lowest version at or above 1.1 on line "" the timeline dates, and its
    day is d60. 1.1 is never installed (undated), so a device clears by installing 1.2:
      0d   runs 1.0, installs 1.2 on d60  -> [d40,d59]  = 20 days, cleared d60 by 1.2
      60d  1.0 installed d-40, 1.2 on d120 -> [d40,d119] = 80 days, cleared d120 by 1.2
      never runs 1.0                      -> [d40,d180] = 141 days, open.
    fix_dated_by records it: fix 1.1, named 1.0.5, dated_as 1.2 on d60, how next_dated. The document
    still lists the old reason word, so `by_reason` carries it as the document's own, counted 0."""
    result = fix_dating_walk(
        [version("1.0", d(-100)), version("1.1", None), version("1.2", d(60))],
        [
            cve(
                "CVE-2026-0401",
                published=d(40),
                detectable=d(40),
                affected=[[0, 0]],
                fixes=[{"line": "", "index": 1, "named": "1.0.5"}],
            )
        ],
        exclusion_reasons=[*walk_module.EXCLUSION_REASONS, "fixed_version_not_in_timeline"],
    )
    assert (result["counts"]["replayed"], result["counts"]["excluded"]) == (1, 0)
    assert result["exclusions"]["by_reason"]["fixed_version_not_in_timeline"] == 0
    [row] = result["cves"]
    assert row["fix_dated_by"] == [
        {"line": "", "fix": "1.1", "named": "1.0.5", "dated_as": "1.2", "on": d(60), "how": "next_dated"}
    ]
    assert result["counts"]["fix_dating"] == {"fix": 0, "next_dated": 1, "undated": 0}
    same_day, sixty, never = (row["outcomes"][stop] for stop in ("0d", "60d", "never"))
    assert (same_day["intervals"], same_day["cleared_on"], same_day["cleared_by"]) == ([[d(40), d(59)]], d(60), "1.2")
    assert (sixty["intervals"], sixty["cleared_on"], sixty["cleared_by"]) == ([[d(40), d(119)]], d(120), "1.2")
    assert (never["exposure_days"], never["open_at_window_end"]) == (141, True)
    assert "2026-11-25" in result["definitions"]["fix_dating"]
    assert invariant_failures(result) == []


def test_rule_5_reads_the_effective_fixs_day() -> None:
    """1.0 (d-100), 1.1 (undated: the fix), 1.2 (d90: the effective fix), 2.0 (d60), 2.1 (d120), each
    its own train. CVE-402: range 1.0, fix 1.1. 2.0 is ranked above the fix, on its line, dated d60,
    before the effective fix's day d90, and of neither 1.1's train nor 1.2's: rule 5, affected. 2.1
    (d120) is dated after it, so clean.
      0d device: 1.0, 2.0 on d60, 1.2 on d90 (ranked below 2.0: no event), 2.1 on d120.
           1.0 [d40,d59] by range + 2.0 [d60,d119] by rule 5 = one interval [d40,d119], 80 days,
           cleared d120 by 2.1. Were rule 5 to read the undated fix's own day, 2.0 would clear it on d60.
      60d device: 1.0, 2.0 on d120, 1.2 on d150 (no event), 2.1 on d180, the window's last day:
           [d40,d179], 140 days, cleared d180 by 2.1, so not open at the window's end."""
    result = fix_dating_walk(
        [version("1.0", d(-100)), version("1.1", None), version("1.2", d(90)), version("2.0", d(60)), version("2.1", d(120))],
        [cve("CVE-2026-0402", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)])],
    )
    [row] = result["cves"]
    assert row["fix_dated_by"] == [{"line": "", "fix": "1.1", "named": None, "dated_as": "1.2", "on": d(90), "how": "next_dated"}]
    same_day, sixty = row["outcomes"]["0d"], row["outcomes"]["60d"]
    assert (same_day["intervals"], same_day["exposure_days"], same_day["cleared_on"], same_day["cleared_by"]) == (
        [[d(40), d(119)]],
        80,
        d(120),
        "2.1",
    )
    assert (sixty["intervals"], sixty["exposure_days"], sixty["cleared_on"], sixty["cleared_by"]) == (
        [[d(40), d(179)]],
        140,
        d(180),
        "2.1",
    )
    assert sixty["open_at_window_end"] is False


def test_rule_5_spares_a_build_of_the_fixs_train() -> None:
    """The train test stays on the fix's own train. 1.0 (d-100), 1.1.0 (undated: the fix, train 1.1),
    1.1.1 (d90, train 1.1: the effective fix), 1.1.2 (d60, train 1.1). CVE-403: range 1.0, fix 1.1.0.
    1.1.2 is ranked above the fix and dated before d90, but it is a build of the fix's train: clean.
    The 0-day device installs 1.1.2 on d60 (1.1.1 on d90 is ranked below it): [d40,d59], cleared d60
    by 1.1.2. Without the train test it would stay open to the window's end.

    A second CVE shows the test reads the fix's train wherever it sits in the list: 3.0 (undated: the
    fix, train x), 3.1 (d90, train y: the effective fix), 3.2 (d60, train x). CVE-404 (range 1.0, fix
    3.0) is cleared on d60 by 3.2, a build of the fix's train, though the effective fix is of another."""
    versions = [
        version("1.0", d(-100)),
        version("1.1.0", None, train="1.1"),
        version("1.1.1", d(90), train="1.1"),
        version("1.1.2", d(60), train="1.1"),
    ]
    result = fix_dating_walk(
        versions, [cve("CVE-2026-0403", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)])]
    )
    clean = outcome(result, "CVE-2026-0403", "0d")
    assert (clean["intervals"], clean["cleared_by"]) == ([[d(40), d(59)]], "1.1.2")

    apart = [
        version("1.0", d(-100)),
        version("3.0", None, train="x"),
        version("3.1", d(90), train="y"),
        version("3.2", d(60), train="x"),
    ]
    result = fix_dating_walk(apart, [cve("CVE-2026-0404", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)])])
    clean = outcome(result, "CVE-2026-0404", "0d")
    assert (clean["intervals"], clean["cleared_by"]) == ([[d(40), d(59)]], "3.2")


def test_rule_5_spares_a_build_of_the_effective_fixs_train() -> None:
    """The version that dated the fix stands in for it, so a later build of its train carries what it
    carries. 1.0 (d-100), 1.1.0 (undated: the fix, train 1.1), 1.2.0 (d90, train 1.2: the effective
    fix), 1.2.1 (d60, train 1.2), 2.0 (d60, train 2.0).
      CVE-405, the walk over 1.0, 1.1.0, 1.2.0, 1.2.1: the 0-day device installs 1.2.1 on d60 (ranked
           above 1.2.0, dated before d90, of 1.2.0's train): clean, [d40,d59], cleared d60 by 1.2.1.
      CVE-406, the walk over 1.0, 1.1.0, 1.2.0, 2.0: 2.0 is of neither train and dated before d90:
           rule 5, affected to the window's end, [d40,d180]."""
    base = [version("1.0", d(-100)), version("1.1.0", None, train="1.1"), version("1.2.0", d(90), train="1.2")]
    row = [cve("CVE-2026-0405", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)])]
    same_train = fix_dating_walk([*base, version("1.2.1", d(60), train="1.2")], row)
    clean = outcome(same_train, "CVE-2026-0405", "0d")
    assert (clean["intervals"], clean["cleared_by"]) == ([[d(40), d(59)]], "1.2.1")

    row = [cve("CVE-2026-0406", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)])]
    other_train = fix_dating_walk([*base, version("2.0", d(60), train="2.0")], row)
    open_ = outcome(other_train, "CVE-2026-0406", "0d")
    assert (open_["intervals"], open_["open_at_window_end"]) == ([[d(40), d(180)]], True)


def test_a_fix_with_nothing_dated_at_or_above_it_on_its_line_is_walked_by_its_runs() -> None:
    """Two lines: 1.0 (line 1, d-100), 1.1 (line 1, undated: the fix), 2.0 (line 2, d60). CVE-407:
    range 1.0, fix 1.1 on line 1. 2.0 is dated and ranked above the fix, but on another line, so it
    does not date the fix: line 1 has no fix a device could install (`undated`), and the CVE is
    walked by its range. The 0-day device runs 1.0 and installs 2.0 on d60, outside the range (and
    rule 5 reads only the fix's line): [d40,d59], cleared d60 by 2.0. Both lines are visited, and the
    row has a fix on line 1 only, so one entry."""
    result = fix_dating_walk(
        [version("1.0", d(-100), "1"), version("1.1", None, "1"), version("2.0", d(60), "2")],
        [cve("CVE-2026-0407", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1, "1")])],
    )
    [row] = result["cves"]
    assert row["fix_dated_by"] == [{"line": "1", "fix": "1.1", "named": None, "dated_as": None, "on": None, "how": "undated"}]
    assert result["counts"]["fix_dating"] == {"fix": 0, "next_dated": 0, "undated": 1}
    same_day = row["outcomes"]["0d"]
    assert (same_day["intervals"], same_day["cleared_by"]) == ([[d(40), d(59)]], "2.0")


def test_fix_dated_by_lists_only_the_lines_the_path_visits() -> None:
    """Golden B's CVE-101 names a fix on 4.2 (4.2.2) and on 4.4 (4.4.1). Every device runs 4.4, so only
    4.4's is listed; the timeline dates 4.4.1 on d45."""
    doc, observed = golden_b()
    result = walk(doc, app="demo", track="demo/4.4", timeline=observed)
    row = next(row for row in result["cves"] if row["cve_id"] == "CVE-2026-0101")
    assert row["fix_dated_by"] == [{"line": "4.4", "fix": "4.4.1", "named": None, "dated_as": "4.4.1", "on": d(45), "how": "fix"}]


def test_a_named_fix_that_is_not_a_version_is_refused_as_the_documents_fault() -> None:
    for bad in (5, "", None, ["1.0.5"]):
        doc, observed = golden_a()
        _track(doc)["cves"][0]["fixes"][0]["named"] = bad
        refused = refusal(doc, observed)
        assert refused.reason == "document_invalid", bad
        assert refused.detail["where"] == "cves[0].fixes[0].named", bad


def test_the_fix_dating_count_must_tally_the_rows() -> None:
    doc, observed = golden_a()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    assert set(result["counts"]["fix_dating"]) == {"fix", "next_dated", "undated"}
    for row in result["cves"]:
        for entry in row["fix_dated_by"]:
            assert set(entry) == {"line", "fix", "named", "dated_as", "on", "how"}
    result["counts"]["fix_dating"]["fix"] += 1
    assert "counts.fix_dating does not tally the rows' fix_dated_by" in invariant_failures(result)


def test_fix_dated_by_lists_every_visited_line_in_the_documents_order() -> None:
    """Two lines, both visited. 4.2.0 (d-100), 4.2.1 (undated: the fix on 4.2), 4.2.2 (d70), 4.4.0 (d50),
    4.4.1 (d80: the fix on 4.4). CVE-411: det d40, range 4.2.0 and 4.4.0. Every device runs 4.2.0 on d31
    and the day stops move to 4.4.0, so both lines are visited and both fixes are listed, in `fixes[]`
    order: 4.2.1 dated by 4.2.2 on d70 (`next_dated`), 4.4.1 by itself on d80 (`fix`).
      0d: 4.2.0 to d49, 4.4.0 on d50 (in range), 4.2.2 on d70 (ranked below 4.4.0: no event), 4.4.1 on
          d80 -> [d40,d79] = 40 days, cleared by 4.4.1.
      never: runs 4.2.0 -> [d40,d180] = 141 days, open."""
    versions = [
        version("4.2.0", d(-100), "4.2"),
        version("4.2.1", None, "4.2"),
        version("4.2.2", d(70), "4.2"),
        version("4.4.0", d(50), "4.4"),
        version("4.4.1", d(80), "4.4"),
    ]
    row = cve("CVE-2026-0411", published=d(40), detectable=d(40), affected=[[0, 0], [3, 3]], fixes=[fix(1, "4.2"), fix(4, "4.4")])
    result = fix_dating_walk(versions, [row])
    [listed] = result["cves"]
    assert listed["fix_dated_by"] == [
        {"line": "4.2", "fix": "4.2.1", "named": None, "dated_as": "4.2.2", "on": d(70), "how": "next_dated"},
        {"line": "4.4", "fix": "4.4.1", "named": None, "dated_as": "4.4.1", "on": d(80), "how": "fix"},
    ]
    assert result["counts"]["fix_dating"] == {"fix": 1, "next_dated": 1, "undated": 0}
    same_day, never = listed["outcomes"]["0d"], listed["outcomes"]["never"]
    assert (same_day["intervals"], same_day["cleared_by"]) == ([[d(40), d(79)]], "4.4.1")
    assert (never["exposure_days"], never["open_at_window_end"]) == (141, True)
    assert invariant_failures(result) == []


def test_a_version_the_cve_still_affects_never_dates_its_fix_and_installing_a_fix_in_range_clears_nothing() -> None:
    """A fix never stands in for itself inside its own CVE's range. One line: 1.0 (d-100), 2.0 (a fix: as
    where an unmarked ESR bound sat inside a release run on a single-line track, before LoonSec's data
    stopped pointing a fix inside its own CVE's range; such a document is still walked as given), 3.0
    (d60), 4.0 (d90: the other fix). CVE-412: det d40, one run 1.0..3.0, fixes 2.0 and 4.0.

    A timeline that does not date 2.0: 3.0 is dated and at or above it, but inside the run, so it cannot
    stand in for the fix; 2.0 is dated by 4.0 on d90, the first dated version above the run.
      0d: 1.0, 3.0 on d60 (still in range), 4.0 on d90 -> [d40,d89] = 50 days, cleared by 4.0.

    A timeline that dates 2.0 itself (d55): it is its own fix (`how: fix`) though the run covers it,
    because LoonSec's data names it; dating it is not clearing it. The 0-day device installs 2.0 on d55
    and 3.0 on d60, both in range, and clears on 4.0 the same way."""
    rows = [cve("CVE-2026-0412", published=d(40), detectable=d(40), affected=[[0, 2]], fixes=[fix(1), fix(3)])]
    undated = fix_dating_walk([version("1.0", d(-100)), version("2.0", None), version("3.0", d(60)), version("4.0", d(90))], rows)
    [row] = undated["cves"]
    assert row["fix_dated_by"] == [
        {"line": "", "fix": "2.0", "named": None, "dated_as": "4.0", "on": d(90), "how": "next_dated"},
        {"line": "", "fix": "4.0", "named": None, "dated_as": "4.0", "on": d(90), "how": "fix"},
    ]
    same_day = row["outcomes"]["0d"]
    assert (same_day["intervals"], same_day["exposure_days"], same_day["cleared_by"]) == ([[d(40), d(89)]], 50, "4.0")
    assert "Dating a fix is not clearing it" in undated["definitions"]["fix_dating"]

    dated = fix_dating_walk([version("1.0", d(-100)), version("2.0", d(55)), version("3.0", d(60)), version("4.0", d(90))], rows)
    [row] = dated["cves"]
    assert row["fix_dated_by"][0] == {"line": "", "fix": "2.0", "named": None, "dated_as": "2.0", "on": d(55), "how": "fix"}
    same_day = row["outcomes"]["0d"]
    assert (same_day["intervals"], same_day["cleared_by"]) == ([[d(40), d(89)]], "4.0")


def test_passing_over_a_version_in_range_moves_the_day_rule_5_reads() -> None:
    """A fix's only stand-in must be outside the CVE's range, and its day is the one rule 5 reads. One
    line, each version its own train: 1.0 (d-100), 2.0 (undated: the fix, which NVD names 1.5), 2.1 (d50),
    3.0 (d90), 4.0 (d70). CVE-416: det d40, run 1.0..2.1, one fix, 2.0. 2.1 is dated and above the fix but
    inside the run, so the fix is dated by 3.0 on d90. 4.0, ranked above the fix, of neither 2.0's train
    nor 3.0's and dated d70, before d90: rule 5, affected.
      0d: 1.0, 2.1 on d50 (in range), 4.0 on d70 (rule 5), 3.0 on d90 (ranked below 4.0: no event)
          -> [d40,d180] = 141 days, open. Were 2.1 to stand in (d50), 4.0 would be clean, cleared d70.

    With nothing dated above the run, the line has no fix to install: 1.0 (d-100), 2.0 (undated), 2.1
    (d50), run 1.0..2.1. 2.1 cannot stand in, so the fix is `undated` and the CVE is walked by its run."""
    result = fix_dating_walk(
        [version("1.0", d(-100)), version("2.0", None), version("2.1", d(50)), version("3.0", d(90)), version("4.0", d(70))],
        [
            cve(
                "CVE-2026-0416",
                published=d(40),
                detectable=d(40),
                affected=[[0, 2]],
                fixes=[{"line": "", "index": 1, "named": "1.5"}],
            )
        ],
    )
    [row] = result["cves"]
    assert row["fix_dated_by"] == [
        {"line": "", "fix": "2.0", "named": "1.5", "dated_as": "3.0", "on": d(90), "how": "next_dated"}
    ]
    same_day = row["outcomes"]["0d"]
    assert (same_day["intervals"], same_day["exposure_days"], same_day["open_at_window_end"]) == ([[d(40), d(180)]], 141, True)
    assert invariant_failures(result) == []

    nothing = fix_dating_walk(
        [version("1.0", d(-100)), version("2.0", None), version("2.1", d(50))],
        [cve("CVE-2026-0417", published=d(40), detectable=d(40), affected=[[0, 2]], fixes=[fix(1)])],
    )
    [row] = nothing["cves"]
    assert row["fix_dated_by"] == [{"line": "", "fix": "2.0", "named": None, "dated_as": None, "on": None, "how": "undated"}]
    assert nothing["counts"]["fix_dating"] == {"fix": 0, "next_dated": 0, "undated": 1}
    assert row["outcomes"]["0d"]["open_at_window_end"] is True

    # Every run is passed over, not only the first: 1.0 (d-100), 2.0 (undated: the fix), 2.1 (d50),
    # 2.2 (undated), 2.3 (d60), 3.0 (d90), runs 1.0, 2.1 and 2.3. The first dated version above 2.1's
    # run is 2.3, inside the next run, so 3.0 dates the fix.
    gaps = fix_dating_walk(
        [
            version("1.0", d(-100)),
            version("2.0", None),
            version("2.1", d(50)),
            version("2.2", None),
            version("2.3", d(60)),
            version("3.0", d(90)),
        ],
        [cve("CVE-2026-0422", published=d(40), detectable=d(40), affected=[[0, 0], [2, 2], [4, 4]], fixes=[fix(1)])],
    )
    [row] = gaps["cves"]
    assert row["fix_dated_by"] == [{"line": "", "fix": "2.0", "named": None, "dated_as": "3.0", "on": d(90), "how": "next_dated"}]


def test_two_cves_with_one_fix_and_different_ranges_find_their_own_stand_ins() -> None:
    """The stand-in is the CVE's own, not the fix's: 1.0 (d-100), 2.0 (undated: the fix of both), 2.1
    (d50), 3.0 (d90). CVE-420's run is 1.0..2.1, so 2.1 cannot stand in and 3.0 dates its fix; CVE-421's
    is 1.0 alone, so 2.1 dates its fix. Each clears on its own stand-in."""
    result = fix_dating_walk(
        [version("1.0", d(-100)), version("2.0", None), version("2.1", d(50)), version("3.0", d(90))],
        [
            cve("CVE-2026-0420", published=d(40), detectable=d(40), affected=[[0, 2]], fixes=[fix(1)]),
            cve("CVE-2026-0421", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)]),
        ],
    )
    wide, narrow = result["cves"]
    assert (wide["fix_dated_by"][0]["dated_as"], narrow["fix_dated_by"][0]["dated_as"]) == ("3.0", "2.1")
    assert (wide["outcomes"]["1d"]["cleared_by"], narrow["outcomes"]["1d"]["cleared_by"]) == ("3.0", "2.1")


def test_a_stand_in_rule_5_holds_affected_under_another_fix_still_stands_in() -> None:
    """Only versions the CVE's runs cover are passed over, not those rule 5 holds affected. 1.0 (d-100,
    train 1), 1.2 (d100, train 1.2: a fix the timeline dates), 1.5 (undated, train 1.5: a fix), 2.0 (d50,
    train 2), 3.0 (d120, train 3). CVE-418: det d40, run 1.0, fixes 1.2 and 1.5. 2.0 is the first dated
    version at or above 1.5 outside the run, so it dates 1.5, though rule 5 holds it affected under 1.2
    (above it, dated d50 before d100, of another train).
      0d: 1.0, 2.0 on d50 (rule 5 under 1.2), 1.2 on d100 (ranked below 2.0: no event), 3.0 on d120
          -> [d40,d119] = 80 days, cleared by 3.0."""
    result = fix_dating_walk(
        [
            version("1.0", d(-100), train="1"),
            version("1.2", d(100), train="1.2"),
            version("1.5", None, train="1.5"),
            version("2.0", d(50), train="2"),
            version("3.0", d(120), train="3"),
        ],
        [cve("CVE-2026-0418", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1), fix(2)])],
    )
    [row] = result["cves"]
    assert row["fix_dated_by"] == [
        {"line": "", "fix": "1.2", "named": None, "dated_as": "1.2", "on": d(100), "how": "fix"},
        {"line": "", "fix": "1.5", "named": None, "dated_as": "2.0", "on": d(50), "how": "next_dated"},
    ]
    same_day = row["outcomes"]["0d"]
    assert (same_day["intervals"], same_day["exposure_days"], same_day["cleared_by"]) == ([[d(40), d(119)]], 80, "3.0")


def test_fixes_the_document_points_at_one_version_are_one_entry_each_in_its_order() -> None:
    """The document's own shape (Chrome's CVE-2011-3022, Firefox's CVE-2024-9399): several `fixes[]`
    entries point at one version, first the fix LoonSec lists itself with no `named`, then each NVD
    bound listed at that version with its `named`. `fix_dated_by` keeps one entry per document entry, in
    its order, and `counts.fix_dating` counts each. 1.0 (d-100), 2.0 (d60), 3.0 (d90). CVE-419: det d40,
    run 1.0, three fixes at 2.0 (none, named 1.7.5, named 1.9).
      Public dates 2.0: three `fix` entries on d60; the 0-day device clears on 2.0, [d40,d59].
      A timeline without 2.0: three `next_dated` entries, each dated by 3.0 on d90; it clears on 3.0,
          [d40,d89]. Three entries, not one: the walk does not merge fixes the document lists apart."""
    versions = [version("1.0", d(-100)), version("2.0", d(60)), version("3.0", d(90))]
    fixes = [{"line": "", "index": 1}, {"line": "", "index": 1, "named": "1.7.5"}, {"line": "", "index": 1, "named": "1.9"}]
    rows = [cve("CVE-2026-0419", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=fixes)]

    public = fix_dating_walk(versions, rows)
    [row] = public["cves"]
    assert row["fix_dated_by"] == [
        {"line": "", "fix": "2.0", "named": named, "dated_as": "2.0", "on": d(60), "how": "fix"}
        for named in (None, "1.7.5", "1.9")
    ]
    assert public["counts"]["fix_dating"] == {"fix": 3, "next_dated": 0, "undated": 0}
    assert row["outcomes"]["0d"]["intervals"] == [[d(40), d(59)]]

    gap = timeline([{"version": "1.0", "date": d(-100)}, {"version": "3.0", "date": d(90)}], source="fleet")
    fleet = fix_dating_walk(versions, rows, observed=gap)
    [row] = fleet["cves"]
    assert row["fix_dated_by"] == [
        {"line": "", "fix": "2.0", "named": named, "dated_as": "3.0", "on": d(90), "how": "next_dated"}
        for named in (None, "1.7.5", "1.9")
    ]
    assert fleet["counts"]["fix_dating"] == {"fix": 0, "next_dated": 3, "undated": 0}
    assert (row["outcomes"]["0d"]["intervals"], row["outcomes"]["0d"]["cleared_by"]) == ([[d(40), d(89)]], "3.0")
    assert invariant_failures(public) == [] and invariant_failures(fleet) == []


def test_fix_dated_by_follows_the_documents_order_where_it_is_not_sorted() -> None:
    """The order is the document's, not one the walk sorts into: a higher fix first, then, at one
    version, `named` 1.9 before 1.7.5 before the entry with none. LoonSec's data writes its own order
    (the entry without `named` first, then by `named`); the walk keeps whichever it is given, so a sort
    of the walk's own would show here. 1.0 (d-100), 2.0 (d60), 3.0 (d90). CVE-423: det d40, run 1.0,
    four fixes, each dated by itself and each counted."""
    versions = [version("1.0", d(-100)), version("2.0", d(60)), version("3.0", d(90))]
    fixes = [
        {"line": "", "index": 2},
        {"line": "", "index": 1, "named": "1.9"},
        {"line": "", "index": 1, "named": "1.7.5"},
        {"line": "", "index": 1},
    ]
    result = fix_dating_walk(versions, [cve("CVE-2026-0423", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=fixes)])
    [row] = result["cves"]
    assert [(entry["fix"], entry["named"], entry["how"]) for entry in row["fix_dated_by"]] == [
        ("3.0", None, "fix"),
        ("2.0", "1.9", "fix"),
        ("2.0", "1.7.5", "fix"),
        ("2.0", None, "fix"),
    ]
    assert result["counts"]["fix_dating"] == {"fix": 4, "next_dated": 0, "undated": 0}
    assert row["outcomes"]["1d"]["cleared_by"] == "2.0"
    assert invariant_failures(result) == []


def test_a_document_with_or_without_the_retired_reason_word_walks_the_same() -> None:
    """Since 2026-11-25 `fixed_version_not_in_timeline` is no reason of the walk's, and LoonSec's data
    drops it from `exclusion_reasons`. A document that still lists it, and one that does not, walk to the
    same numbers; the one that lists it keeps it in `by_reason` as its own word, counted 0."""
    doc, observed = golden_a()
    without = {**doc, "exclusion_reasons": list(walk_module.EXCLUSION_REASONS)}
    with_word = {**doc, "exclusion_reasons": [*walk_module.EXCLUSION_REASONS, "fixed_version_not_in_timeline"]}
    assert "fixed_version_not_in_timeline" not in walk_module.EXCLUSION_REASONS
    a = walk(without, app="demo", track="demo/stable", timeline=observed)
    b = walk(with_word, app="demo", track="demo/stable", timeline=observed)
    assert "fixed_version_not_in_timeline" not in a["exclusions"]["by_reason"]
    assert b["exclusions"]["by_reason"]["fixed_version_not_in_timeline"] == 0
    for result in (a, b):
        assert invariant_failures(result) == []
        result["exclusions"]["by_reason"].pop("fixed_version_not_in_timeline", None)
        result.pop("run_id")
    assert a == b


def test_the_fix_is_dated_by_the_timelines_day_not_by_when_a_device_may_install_it() -> None:
    """The next dated version is found among every version the timeline dates, and its day is the
    timeline's, whatever the promotion table says about installing it.

    Promotion-delayed: 1.0 (d-100), 1.1 (undated: the fix), 1.2 (d60, its major promoted d100, so
    available d100: the effective fix), 2.0 (d70, available d70). CVE-413: det d40, range 1.0, fix 1.1.
    The fix's day is d60, so 2.0 (dated d70) is clean under rule 5 and the 0-day device clears on d70:
    [d40,d69] = 30 days. Were the fix's day 1.2's availability, d100, rule 5 would hold 2.0 affected
    to the window's end.

    Above the table: 1.0 (d-100), 1.1 (undated: the fix), 2.0 (d150, above the table's newest row, so
    never installed, and the window ends d149). The timeline dates 2.0, so it dates the fix
    (`next_dated`) though no device can install it, and CVE-414 stays open on 1.0: [d40,d149]."""
    delayed = fix_dating_walk(
        [version("1.0", d(-100)), version("1.1", None), version("1.2", d(60)), version("2.0", d(70))],
        [cve("CVE-2026-0413", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)])],
        promotions=[
            {"major": "1.0", "promoted": d(-200), "versions": [0, 0]},
            {"major": "1.1", "promoted": d(100), "versions": [1, 2]},
            {"major": "2", "promoted": d(-200), "versions": [3, 3]},
        ],
    )
    [row] = delayed["cves"]
    assert row["fix_dated_by"] == [{"line": "", "fix": "1.1", "named": None, "dated_as": "1.2", "on": d(60), "how": "next_dated"}]
    same_day = row["outcomes"]["0d"]
    assert (same_day["intervals"], same_day["cleared_on"], same_day["cleared_by"]) == ([[d(40), d(69)]], d(70), "2.0")

    above = fix_dating_walk(
        [version("1.0", d(-100)), version("1.1", None), version("2.0", d(150))],
        [cve("CVE-2026-0414", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)])],
        promotions=[{"major": "1", "promoted": d(-200), "versions": [0, 1]}],
    )
    assert above["window"]["until"] == d(149)
    [row] = above["cves"]
    assert row["fix_dated_by"] == [
        {"line": "", "fix": "1.1", "named": None, "dated_as": "2.0", "on": d(150), "how": "next_dated"}
    ]
    same_day = row["outcomes"]["0d"]
    assert (same_day["intervals"], same_day["open_at_window_end"]) == ([[d(40), d(149)]], True)


def test_a_later_train_build_shipped_before_the_fix_stands_in_for_it() -> None:
    """On a line that holds several trains, the next dated version can be a build of a later train
    that the vendor shipped before the fix. 1.0 (d-100, train 1), 1.5 (d100, train 1: the fix), 2.0
    (d50, train 2), 2.1 (d120, train 2). CVE-415: det d40, range 1.0, fix 1.5.
      Public dates 1.5: rule 5 holds 2.0 (d50, before d100, of another train) affected, so the 0-day
          device runs 1.0, then 2.0 from d50, and clears on 2.1 (d120): [d40,d119] = 80 days.
      A timeline without 1.5 dates the fix by 2.0 on d50 (before the fix's own day). 2.0 stands in
          for the fix and is spared: [d40,d49] = 10 days, cleared by 2.0."""
    versions = [
        version("1.0", d(-100), train="1"),
        version("1.5", d(100), train="1"),
        version("2.0", d(50), train="2"),
        version("2.1", d(120), train="2"),
    ]
    rows = [cve("CVE-2026-0415", published=d(40), detectable=d(40), affected=[[0, 0]], fixes=[fix(1)])]
    public = outcome(fix_dating_walk(versions, rows), "CVE-2026-0415", "0d")
    assert (public["intervals"], public["cleared_by"]) == ([[d(40), d(119)]], "2.1")
    gap = timeline([{"version": v["v"], "date": v["date"]} for v in versions if v["v"] != "1.5"], source="fleet")
    result = fix_dating_walk(versions, rows, observed=gap)
    [row] = result["cves"]
    assert row["fix_dated_by"] == [{"line": "", "fix": "1.5", "named": None, "dated_as": "2.0", "on": d(50), "how": "next_dated"}]
    same_day = row["outcomes"]["0d"]
    assert (same_day["intervals"], same_day["cleared_by"]) == ([[d(40), d(49)]], "2.0")


def test_a_v1_verdict_the_document_does_not_list_is_refused_as_the_documents_fault() -> None:
    """In conformance mode a row's `v1_exclusion` is its reason. Since 2026-11-25 the walk no longer adds
    `fixed_version_not_in_timeline` to every reason list, so a document that uses that word as a v1
    verdict without listing it is refused naming the row (`document_invalid`), as an unlisted
    `exclusions.cves[].reason` is, rather than walked into a `by_reason` that cannot count it
    (`invariant`, which would blame LoonInspect). Listed, it walks and counts. Outside conformance mode
    the verdict is not read."""
    doc, observed = golden_a()
    for row in _track(doc)["cves"]:
        row["v1_exclusion"] = "fixed_version_not_in_timeline" if row["cve_id"] == "CVE-2026-0003" else None
    with pytest.raises(WalkRefused) as caught:
        walk(doc, app="demo", track="demo/stable", timeline=observed, compat_v1=True)
    assert caught.value.reason == "document_invalid"
    assert caught.value.detail["where"] == "cves[2].v1_exclusion"
    assert "'fixed_version_not_in_timeline' is not a reason this build knows" in caught.value.sentence
    assert walk(doc, app="demo", track="demo/stable", timeline=observed)["counts"]["replayed"] == 5

    doc["exclusion_reasons"] = [*walk_module.EXCLUSION_REASONS, "fixed_version_not_in_timeline"]
    result = walk(doc, app="demo", track="demo/stable", timeline=observed, compat_v1=True)
    assert result["exclusions"]["by_reason"]["fixed_version_not_in_timeline"] == 1
    assert invariant_failures(result) == []


# --- Golden F: the days waited, from the window's first day ------------------------------------


def golden_f() -> tuple[dict[str, Any], dict[str, Any]]:
    """One line, each version its own train: 1.0 (d-100), 1.1 dated d31, the window's first day, and
    1.2 and 1.3 both dated d90."""
    versions = [version("1.0", d(-100)), version("1.1", d(31)), version("1.2", d(90)), version("1.3", d(90))]
    track = {
        "track": "demo/stable",
        "label": "Demo",
        "path": {"kind": "latest"},
        "timeline": "vendor",
        "versions": versions,
        "cves": [
            cve("CVE-2026-0501", published=d(20), detectable=d(20), affected=[[0, 0]], fixes=[fix(1)]),
            cve("CVE-2026-0502", published=d(60), detectable=d(60), affected=[[0, 1]], fixes=[fix(2)]),
            cve("CVE-2026-0503", published=d(100), detectable=d(100), affected=[[2, 2]], fixes=[fix(3)]),
        ],
    }
    observed = timeline([{"version": v["v"], "date": v["date"]} for v in versions])
    return document([track], coverage="2026-01-31"), observed


def test_golden_f_a_stop_waits_its_label_from_a_release_dated_on_the_windows_first_day() -> None:
    """A release dated on the window's first day, and two releases due on one day, under every stop.

    Window: the detectable record begins 2026-01-31, so d31 to d180; 60 days after the first release,
    d-100 + 60 = d-40, does not bind. Rule 5 never applies: no version is dated before a fix it ranks
    above (1.3 is dated the day of 1.2, not before it).

    Devices, installing at availability + D, and opening on the newest release installed by d31:
      0d    1.1 is due d31, the first day itself, so it opens on 1.1; 1.2 and 1.3 are both due d90, and
            the higher, 1.3, is installed: installs (d90, 1.3).
      1d    opens 1.0; 1.1 on d32, 1.3 on d91.     3d   1.0; 1.1 on d34, 1.3 on d93.
      7d    opens 1.0; 1.1 on d38, 1.3 on d97.     14d  1.0; 1.1 on d45, 1.3 on d104.
      30d   opens 1.0; 1.1 on d61, 1.3 on d120.    60d  1.0 (due d-40); 1.1 on d91, 1.3 on d150.
      never runs 1.1, dated by d31, and installs nothing after it.
    1.2 is installed under no stop: on the day it is due, 1.3 is due too.

    CVE-501 (det d20, before the window; affected 1.0; fix 1.1): the 0-day device runs 1.1 from the
      window's first day, so it is never open in the window (pre_window_closed), and so under never.
      Every other day stop runs 1.0 from d31 until its 1.1 install, D days after d31: carried in for
      exactly D days, [d31, d(30 + D)]: 1, 3, 7, 14, 30 and 60 days. The label is the days waited.
    CVE-502 (det d60; affected 1.0-1.1; fix 1.2): open from d60 until the 1.3 install, 1.2 never being
      installed: 0d [d60,d89] = 30, 1d [d60,d90] = 31, 3d [d60,d92] = 33, 7d [d60,d96] = 37,
      14d [d60,d103] = 44, 30d [d60,d119] = 60 (1.0, then 1.1 from d61), 60d [d60,d149] = 90;
      each cleared by 1.3. never runs 1.1: [d60,d180] = 121, open.
    CVE-503 (det d100; affected 1.2 alone; fix 1.3): no device ever runs 1.2, so it is never seen. By
      d100 the 0d, 1d, 3d and 7d devices run 1.3 (fix installed first); the 14d, 30d and 60d devices
      still run 1.1 and never runs 1.1 (outside the affected range).
    So every stop counts 1 exposed and 1 never seen of the 2 replayed, with CVE-502's days as its
    exposure days.
    """
    doc, observed = golden_f()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    assert (result["window"]["since"], result["window"]["until"]) == (d(31), d(180))
    assert [row["reason"] for row in result["window"]["shortened_by"]] == ["clock_coverage"]
    policies = result["policies"]
    expected = {
        # stop: (initial, installs, CVE-501's carried-in days or None when it is never open, CVE-502's days, CVE-503's why)
        "0d": ("1.1", [(90, "1.3")], None, 30, "fix_installed_first"),
        "1d": ("1.0", [(32, "1.1"), (91, "1.3")], 1, 31, "fix_installed_first"),
        "3d": ("1.0", [(34, "1.1"), (93, "1.3")], 3, 33, "fix_installed_first"),
        "7d": ("1.0", [(38, "1.1"), (97, "1.3")], 7, 37, "fix_installed_first"),
        "14d": ("1.0", [(45, "1.1"), (104, "1.3")], 14, 44, "outside_affected_range"),
        "30d": ("1.0", [(61, "1.1"), (120, "1.3")], 30, 60, "outside_affected_range"),
        "60d": ("1.0", [(91, "1.1"), (150, "1.3")], 60, 90, "outside_affected_range"),
        "never": ("1.1", [], None, 121, "outside_affected_range"),
    }
    for stop, (initial, installs, carried, days, why) in expected.items():
        policy = policies[stop]
        assert (policy["initial_version"], [(row["date"], row["version"]) for row in policy["installs"]]) == (
            initial,
            [(d(day), v) for day, v in installs],
        ), stop
        first = outcome(result, "CVE-2026-0501", stop)
        if carried is None:
            assert first == {"class": "pre_window_closed", "outcome": "not_open_in_window"}, stop
            assert (policy["carried_in"], policy["pre_window_closed"]) == (0, 1), stop
        else:
            assert (first["class"], first["intervals"], first["cleared_by"]) == (
                "carried_in",
                [[d(31), d(30 + carried)]],
                "1.1",
            ), stop
            assert (policy["carried_in"], policy["exposure_days_carried_in"]) == (1, carried), stop
        second = outcome(result, "CVE-2026-0502", stop)
        assert (second["exposure_days"], second["cleared_by"]) == (days, None if stop == "never" else "1.3"), stop
        assert outcome(result, "CVE-2026-0503", stop)["why"] == why, stop
        assert (policy["exposed"], policy["never_seen"], policy["exposure_days"]) == (1, 1, days), stop
    assert outcome(result, "CVE-2026-0502", "never")["open_at_window_end"] is True
    assert not any(row["version"] == "1.2" for policy in policies.values() for row in policy["installs"])
    assert invariant_failures(result) == []


# --- Golden G onward: the built-in policy definitions (#954, ruled 2026-11-28) -----------------
#
# Each golden is one line of releases, each its own train and dated in rank order, so rule 5 never
# applies, under a document that names a KEV source (`sources.kev`), so a null `kev_date_added` says
# "not listed". The window is d31 to d180 throughout (the detectable record begins 2026-01-31).


def kev_document(tracks: list[dict[str, Any]]) -> dict[str, Any]:
    doc = document(tracks, coverage="2026-01-31")
    doc["sources"]["kev"] = {"via": "NVD cisaExploitAdd"}
    return doc


def definition_case(versions: list[dict[str, Any]], cves: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    track = {
        "track": "demo/stable",
        "label": "Demo",
        "path": {"kind": "latest"},
        "timeline": "vendor",
        "versions": versions,
        "cves": cves,
    }
    return kev_document([track]), timeline([{"version": v["v"], "date": v["date"]} for v in versions])


def by(rule: str, cve_id: str | None = None, on: int | None = None, basis: str | None = None) -> dict[str, Any]:
    """What installed a release (`installs[].by`, `opening_by`), as the walk writes it."""
    return {"rule": rule, "cve_id": cve_id, "on": d(on) if on is not None else None, "basis": basis}


def installs_of(result: dict[str, Any], policy: str) -> list[tuple[str, str, dict[str, Any]]]:
    return [(row["date"], row["version"], row["by"]) for row in result["policies"][policy]["installs"]]


def golden_g() -> tuple[dict[str, Any], dict[str, Any]]:
    """1.0 (d-100), 1.1 (d40), 1.2 (d70), 1.3 (d100), 1.4 (d130). CVE-601 is listed on KEV on d80,
    after its fix 1.1 and the newer 1.2 are out; CVE-602 on d90, before its fix 1.3 is; CVE-603 never."""
    versions = [
        version("1.0", d(-100)),
        version("1.1", d(40)),
        version("1.2", d(70)),
        version("1.3", d(100)),
        version("1.4", d(130)),
    ]
    cves = [
        cve(
            "CVE-2026-0601",
            published=d(34),
            detectable=d(35),
            affected=[[0, 0]],
            fixes=[fix(1)],
            severity="high",
            kev_date_added=d(80),
        ),
        cve(
            "CVE-2026-0602",
            published=d(44),
            detectable=d(45),
            affected=[[0, 2]],
            fixes=[fix(3)],
            severity="medium",
            kev_date_added=d(90),
        ),
        cve(
            "CVE-2026-0603",
            published=d(110),
            detectable=d(110),
            affected=[[3, 3]],
            fixes=[fix(4)],
            severity="critical",
            kev_date_added=None,
        ),
    ]
    return definition_case(versions, cves)


def test_golden_g_a_kev_trigger_waits_for_the_later_of_its_release_and_its_listing() -> None:
    """Patch on a KEV (`kev-only`: otherwise never; kev_listed within 0), derived by hand.

    It opens as `never` does, on the newest release available by d31: 1.0 (1.1 is d40), said
    `otherwise`. Each KEV CVE names its fix, which the timeline dates itself, on its trigger day, the
    later of the day the release is available and the day the CVE was listed:
      CVE-601, listed d80, after its fix 1.1 (d40) is out: due d80 (the listing).
      CVE-602, listed d90, before its fix 1.3 (d100) is out: due d100 (the release).
      CVE-603 is never listed, so its fix 1.4 is named by nothing, and installed by nothing.
    So 1.1 on d80 and 1.3 on d100, each naming its CVE. On d80 the newer 1.2 (d70) is out too, and the
    device installs the fixing release it names, 1.1, not the newest (`fixing_release`); 1.2 is never
    installed, because no trigger names it and otherwise never.
      CVE-601 (affected 1.0; det d35): [d35, d79] = 45 days, cleared d80 by 1.1.
      CVE-602 (affected 1.0 to 1.2; det d45): 1.0, then 1.1 from d80, both affected: [d45, d99] = 55,
              cleared d100 by 1.3.
      CVE-603 (affected 1.3 alone; det d110): the device runs 1.3 from d100 to the end: [d110, d180] =
              71, open at the window's end.
    Totals: 3 exposed, 0 never seen, 45 + 55 + 71 = 171 exposure days, 2 update events, 1.0 to 1.3.
    """
    doc, observed = golden_g()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    assert (result["window"]["since"], result["window"]["until"]) == (d(31), d(180))
    assert result["policy_refusals"] == {}
    assert list(result["policies"]) == list(POLICIES)
    kev = result["policies"]["kev-only"]
    assert (kev["stop"], kev["install_delay_days"], kev["initial_version"], kev["final_version"]) == (
        "kev-only",
        None,
        "1.0",
        "1.3",
    )
    assert kev["opening_by"] == by("otherwise")
    assert installs_of(result, "kev-only") == [
        (d(80), "1.1", by("kev_listed", "CVE-2026-0601", 80, "kev_date_added")),
        (d(100), "1.3", by("kev_listed", "CVE-2026-0602", 90, "kev_date_added")),
    ]
    assert (kev["exposed"], kev["never_seen"], kev["exposure_days"], kev["update_events"]) == (3, 0, 171, 2)
    assert kev["open_at_window_end"] == {"in_window": 1, "carried_in": 0, "entered_after_start": 0}
    assert outcome(result, "CVE-2026-0601", "kev-only") == {
        "class": "in_window",
        "outcome": "exposed",
        "exposure_days": 45,
        "open_at_window_end": False,
        "cleared_on": d(80),
        "cleared_by": "1.1",
        "intervals": [[d(35), d(79)]],
        "version_at_clock": "1.0",
    }
    assert outcome(result, "CVE-2026-0602", "kev-only")["intervals"] == [[d(45), d(99)]]
    assert outcome(result, "CVE-2026-0603", "kev-only")["intervals"] == [[d(110), d(180)]]
    assert not any(row["version"] == "1.2" for row in kev["installs"])
    # Each CVE row says the day each trigger's fact was knowable, and its basis.
    knowable = {row["cve_id"]: row["knowable"] for row in result["cves"]}
    assert knowable["CVE-2026-0601"] == {
        "kev_listed": {"on": d(80), "basis": "kev_date_added"},
        "critical": None,
        "critical_or_high": {"on": d(35), "basis": "clock_day"},
    }
    assert knowable["CVE-2026-0603"]["kev_listed"] is None
    assert result["counts"]["knowable"] == {
        "kev_listed": {"kev_date_added": 2},
        "critical": {"first_scored": 0, "clock_day": 1},
        "critical_or_high": {"first_scored": 0, "clock_day": 2},
    }
    # The definitions ride as data, and each is printed in the walk's own words under its id.
    assert result["policy_definitions"] == [
        {"id": "kev-only", "name": "Patch on a KEV", "otherwise": "never", "when": [{"fixes": "kev_listed", "within_days": 0}]},
        {
            "id": "critical-only",
            "name": "Patch only on a critical",
            "otherwise": "never",
            "when": [{"fixes": "critical", "within_days": 0}],
        },
        {
            "id": "30d-or-kev",
            "name": "30 days, same day on a KEV",
            "otherwise": 30,
            "when": [{"fixes": "kev_listed", "within_days": 0}],
        },
    ]
    assert result["definitions"]["kev-only"].startswith(
        "Patch on a KEV, a built-in policy definition (`kev-only`): otherwise never"
    )
    assert "installs the fixing release it names, not the newest release" in result["definitions"]["fixing_release"]
    assert invariant_failures(result) == []


def test_golden_g_the_mixed_definition_where_otherwise_and_a_trigger_compete() -> None:
    """30 days, same day on a KEV (`30d-or-kev`: otherwise 30; kev_listed within 0), derived by hand.

    Otherwise, each release 30 days after it is dated: 1.0 d-70, 1.1 d70, 1.2 d100, 1.3 d130, 1.4
    d160. The KEV triggers compete with those days, and the earlier wins:
      1.1: otherwise d70, CVE-601's trigger d80: otherwise, d70.
      1.3: otherwise d130, CVE-602's trigger d100 (its release day): the trigger, d100.
    It opens on 1.0, installed d-70 by otherwise. On d100, 1.2 (otherwise) and 1.3 (the trigger) are
    both due, and only the higher, 1.3, is installed; 1.4 on d160 by otherwise.
      CVE-601: [d35, d69] = 35, cleared d70 by 1.1.
      CVE-602: 1.0, then 1.1: [d45, d99] = 55, cleared d100 by 1.3.
      CVE-603: on 1.3 from d100 to d159: [d110, d159] = 50, cleared d160 by 1.4.
    Totals: 3 exposed, 35 + 55 + 50 = 140 exposure days, 3 update events. The 30-day stop, by hand
    for the comparison: 1.1 d70, 1.2 d100, 1.3 d130, 1.4 d160, so CVE-602 stays open on 1.2 until
    d130 ([d45, d129] = 85) and CVE-603 opens on d130 ([d130, d159] = 30): 35 + 85 + 30 = 150, in 4
    update events.
    """
    doc, observed = golden_g()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    mixed, thirty = result["policies"]["30d-or-kev"], result["policies"]["30d"]
    assert (mixed["initial_version"], mixed["opening_by"]) == ("1.0", by("otherwise"))
    assert installs_of(result, "30d-or-kev") == [
        (d(70), "1.1", by("otherwise")),
        (d(100), "1.3", by("kev_listed", "CVE-2026-0602", 90, "kev_date_added")),
        (d(160), "1.4", by("otherwise")),
    ]
    assert [
        outcome(result, cve_id, "30d-or-kev")["exposure_days"] for cve_id in ("CVE-2026-0601", "CVE-2026-0602", "CVE-2026-0603")
    ] == [
        35,
        55,
        50,
    ]
    assert (mixed["exposed"], mixed["exposure_days"], mixed["update_events"], mixed["final_version"]) == (3, 140, 3, "1.4")
    assert [(row["date"], row["version"]) for row in thirty["installs"]] == [
        (d(70), "1.1"),
        (d(100), "1.2"),
        (d(130), "1.3"),
        (d(160), "1.4"),
    ]
    assert (thirty["exposure_days"], thirty["update_events"]) == (150, 4)
    assert invariant_failures(result) == []


def test_golden_g_a_severity_trigger_on_the_clock_day_with_todays_severity() -> None:
    """Patch only on a critical (`critical-only`: otherwise never; critical within 0), by hand.

    Only CVE-603 is critical today, and the data states no first-scored day for it, so its clock day,
    d110 (first detectable), stands in (ruled 2026-11-28), and its fix 1.4 (d130) is due d130, the
    later of the two. It opens on 1.0 and installs 1.4 on d130, never 1.1 to 1.3.
      CVE-601 (1.0): [d35, d129] = 95, cleared d130 by 1.4.
      CVE-602 (1.0 to 1.2): on 1.0 throughout: [d45, d129] = 85, cleared d130 by 1.4.
      CVE-603 (1.3 alone): the device never runs 1.3, and on d110 it runs 1.0, below the fix: never
              seen, outside the affected range.
    Totals: 2 exposed, 1 never seen (1 outside), 95 + 85 = 180 exposure days, 1 update event.
    """
    doc, observed = golden_g()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    critical = result["policies"]["critical-only"]
    assert installs_of(result, "critical-only") == [(d(130), "1.4", by("critical", "CVE-2026-0603", 110, "clock_day"))]
    assert (critical["exposed"], critical["never_seen"], critical["never_seen_outside_affected_range"]) == (2, 1, 1)
    assert (critical["exposure_days"], critical["update_events"]) == (180, 1)
    assert outcome(result, "CVE-2026-0603", "critical-only") == {
        "class": "in_window",
        "outcome": "never_seen",
        "why": "outside_affected_range",
        "version_at_clock": "1.0",
    }
    row = next(row for row in result["cves"] if row["cve_id"] == "CVE-2026-0603")
    assert row["knowable"]["critical"] == {"on": d(110), "basis": "clock_day"}


def golden_h() -> tuple[dict[str, Any], dict[str, Any]]:
    """1.0 (d-100), 1.1 (d40), 1.2 (d120); nothing on KEV. CVE-701 is critical, and LoonSec's data
    states the day it first scored critical (d90) and high or critical (d45); CVE-702 is critical with
    no first-scored day; both are fixed by 1.1. CVE-703 is high, fixed by 1.2."""
    versions = [version("1.0", d(-100)), version("1.1", d(40)), version("1.2", d(120))]
    cves = [
        cve(
            "CVE-2026-0701",
            published=d(44),
            detectable=d(45),
            affected=[[0, 0]],
            fixes=[fix(1)],
            severity="critical",
            kev_date_added=None,
            first_scored={"critical": d(90), "critical_or_high": d(45)},
        ),
        cve(
            "CVE-2026-0702",
            published=d(74),
            detectable=d(75),
            affected=[[0, 0]],
            fixes=[fix(1)],
            severity="critical",
            kev_date_added=None,
        ),
        cve(
            "CVE-2026-0703",
            published=d(59),
            detectable=d(60),
            affected=[[0, 1]],
            fixes=[fix(2)],
            severity="high",
            kev_date_added=None,
        ),
    ]
    return definition_case(versions, cves)


def test_golden_h_severity_on_both_bases_and_two_triggers_naming_one_release() -> None:
    """Patch only on a critical, by hand: the ruled day under both bases, and the earlier of two
    triggers naming one release.

    CVE-701's critical day is the one LoonSec's data states, d90 (`first_scored`); CVE-702's is its
    clock day, d75 (first detectable), with today's severity standing in (`clock_day`). Both name 1.1
    (d40): CVE-701 on max(d40, d90) = d90, CVE-702 on max(d40, d75) = d75. The earliest due day wins,
    so 1.1 is installed on d75 by CVE-702, though CVE-701's trigger is offered first. CVE-703 is high,
    so nothing names 1.2.
      CVE-701 (1.0; det d45): [d45, d74] = 30, cleared d75 by 1.1.
      CVE-702 (1.0; det d75): 1.1 is installed that day, so the device never runs an affected version
              from its clock day: never seen, the fix installed first.
      CVE-703 (1.0 to 1.1; det d60): [d60, d180] = 121, open.
    Totals: 2 exposed, 1 never seen (0 outside), 30 + 121 = 151 exposure days, 1 update event.
    """
    doc, observed = golden_h()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    critical = result["policies"]["critical-only"]
    assert installs_of(result, "critical-only") == [(d(75), "1.1", by("critical", "CVE-2026-0702", 75, "clock_day"))]
    assert outcome(result, "CVE-2026-0701", "critical-only")["intervals"] == [[d(45), d(74)]]
    assert outcome(result, "CVE-2026-0702", "critical-only") == {
        "class": "in_window",
        "outcome": "never_seen",
        "why": "fix_installed_first",
        "version_at_clock": "1.1",
    }
    assert outcome(result, "CVE-2026-0703", "critical-only")["exposure_days"] == 121
    assert (critical["exposed"], critical["never_seen"], critical["never_seen_outside_affected_range"]) == (2, 1, 0)
    assert (critical["exposure_days"], critical["update_events"]) == (151, 1)
    knowable = {row["cve_id"]: row["knowable"] for row in result["cves"]}
    assert knowable["CVE-2026-0701"]["critical"] == {"on": d(90), "basis": "first_scored"}
    assert knowable["CVE-2026-0702"]["critical"] == {"on": d(75), "basis": "clock_day"}
    assert knowable["CVE-2026-0703"]["critical"] is None
    assert result["counts"]["knowable"]["critical"] == {"first_scored": 1, "clock_day": 1}


def test_golden_h_within_days_and_critical_or_high_on_a_test_definition(monkeypatch) -> None:
    """A definition no build ships, put beside the built-in ones for this test only: otherwise never;
    critical_or_high within 3 days. By hand:

    high or critical: CVE-701's stated day is d45 (`first_scored.critical_or_high`); CVE-702 is
    critical today with no stated day, so its clock day d75; CVE-703 is high today, so its clock day
    d60. Due 3 days after each trigger day: CVE-701 names 1.1 on max(d40, d45) + 3 = d48; CVE-702
    names 1.1 on max(d40, d75) + 3 = d78 (later, so it loses); CVE-703 names 1.2 on max(d120, d60) + 3
    = d123. So 1.1 on d48 and 1.2 on d123.
      CVE-701: [d45, d47] = 3, cleared d48. CVE-702: on 1.1 by d75, never seen, the fix first.
      CVE-703: [d60, d122] = 63, cleared d123 by 1.2.
    Totals: 2 exposed, 1 never seen, 66 exposure days, 2 update events.
    """
    test_definition = {
        "id": "high-3d",
        "name": "High or critical within 3 days",
        "otherwise": "never",
        "when": [{"fixes": "critical_or_high", "within_days": 3}],
    }
    monkeypatch.setattr(walk_module, "POLICY_DEFINITIONS", (*walk_module.POLICY_DEFINITIONS, test_definition))
    monkeypatch.setattr(walk_module, "POLICIES", (*POLICIES, "high-3d"))
    doc, observed = golden_h()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed, stops=("0d", "high-3d"))
    assert list(result["policies"]) == ["0d", "high-3d"]
    assert installs_of(result, "high-3d") == [
        (d(48), "1.1", by("critical_or_high", "CVE-2026-0701", 45, "first_scored")),
        (d(123), "1.2", by("critical_or_high", "CVE-2026-0703", 60, "clock_day")),
    ]
    run = result["policies"]["high-3d"]
    assert (run["exposed"], run["never_seen"], run["exposure_days"], run["update_events"]) == (2, 1, 66, 2)
    assert outcome(result, "CVE-2026-0701", "high-3d")["intervals"] == [[d(45), d(47)]]
    assert outcome(result, "CVE-2026-0703", "high-3d")["intervals"] == [[d(60), d(122)]]
    assert result["definitions"]["high-3d"].endswith(
        "a release that fixes a high or critical CVE is installed 3 days after its trigger day, the later of the day it "
        "is available and the day `severity_day` gives for high or critical."
    )


def golden_i() -> tuple[dict[str, Any], dict[str, Any]]:
    """1.0 (d-200), 1.1 (d10), 1.2 (d100). CVE-801, from before the window, is listed on KEV on d20,
    after its fix 1.1 is out; CVE-802 is never listed."""
    versions = [version("1.0", d(-200)), version("1.1", d(10)), version("1.2", d(100))]
    cves = [
        cve(
            "CVE-2026-0801",
            published=d(4),
            detectable=d(5),
            affected=[[0, 0]],
            fixes=[fix(1)],
            severity="high",
            kev_date_added=d(20),
        ),
        cve(
            "CVE-2026-0802",
            published=d(49),
            detectable=d(50),
            affected=[[0, 1]],
            fixes=[fix(2)],
            severity="medium",
            kev_date_added=None,
        ),
    ]
    return definition_case(versions, cves)


def test_golden_i_a_trigger_due_before_the_windows_first_day_raises_the_opening() -> None:
    """The opening (`definition_opening`), by hand. The 30-day stop's install days are 1.0 d-170, 1.1
    d40 and 1.2 d130, so it opens on d31 on 1.0. Under `30d-or-kev`, CVE-801's trigger names 1.1 on
    max(d10, d20) = d20, before the window's first day and before its otherwise day d40, so 1.1's
    install day is d20 and the window opens on 1.1, installed by the listing (`opening_by`).
      30d:        CVE-801 is carried in on 1.0, [d31, d39] = 9 days, cleared d40 by 1.1; CVE-802
                  [d50, d129] = 80, cleared d130 by 1.2.
      30d-or-kev: CVE-801 is never open in the window (pre_window_closed); CVE-802 [d50, d129] = 80.
    Patch on a KEV opens as `never` does, on the newest release available by d31, 1.1 (d10): CVE-801's
    trigger names that release too, and no trigger due by then can rank above it, so `otherwise` opened
    it. Nothing names 1.2, so CVE-802 is open from d50 to the end, [d50, d180] = 131.
    """
    doc, observed = golden_i()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    thirty, mixed, kev = (result["policies"][policy] for policy in ("30d", "30d-or-kev", "kev-only"))
    assert (thirty["initial_version"], thirty["carried_in"], thirty["exposure_days_carried_in"]) == ("1.0", 1, 9)
    assert (mixed["initial_version"], mixed["opening_by"]) == ("1.1", by("kev_listed", "CVE-2026-0801", 20, "kev_date_added"))
    assert installs_of(result, "30d-or-kev") == [(d(130), "1.2", by("otherwise"))]
    assert (mixed["carried_in"], mixed["pre_window_closed"], mixed["exposed"], mixed["exposure_days"]) == (0, 1, 1, 80)
    assert outcome(result, "CVE-2026-0801", "30d-or-kev") == {"class": "pre_window_closed", "outcome": "not_open_in_window"}
    assert outcome(result, "CVE-2026-0802", "30d-or-kev")["intervals"] == [[d(50), d(129)]]
    assert (kev["initial_version"], kev["opening_by"], kev["installs"]) == ("1.1", by("otherwise"), [])
    assert outcome(result, "CVE-2026-0802", "kev-only")["intervals"] == [[d(50), d(180)]]
    assert "raised by any trigger already due by the window's first day" in result["definitions"]["definition_opening"]
    assert invariant_failures(result) == []


def test_the_stops_walk_the_same_with_the_definitions_beside_them() -> None:
    """The definitions change no stop: every stop's run, and every CVE's outcome under it, is the
    same asked alone as beside every definition, and the exclusions and counts are the same."""
    for doc, observed in (golden_g(), golden_h(), golden_i(), golden_a()):
        every = walk(doc, app="demo", track="demo/stable", timeline=observed)
        alone = walk(doc, app="demo", track="demo/stable", timeline=observed, stops=STOPS)
        assert {stop: every["policies"][stop] for stop in STOPS} == alone["policies"]
        assert every["exclusions"] == alone["exclusions"]
        rows = {row["cve_id"]: row["outcomes"] for row in alone["cves"]}
        for row in every["cves"]:
            assert {stop: row["outcomes"][stop] for stop in STOPS} == rows[row["cve_id"]]
        assert alone["policy_definitions"] == [] and alone["policy_refusals"] == {}


def test_a_definition_the_data_cannot_run_is_refused_in_words_and_every_stop_still_walks() -> None:
    """`kev_unknown`: a document that names no KEV source, or a row that does not say, or says it with
    something that is not a date. `severity_unknown`: a severity, or a first-scored day, the walk does
    not read. Each refuses only the definitions that read it, with a sentence; the stops, and the
    definitions that do not read it, walk as before."""
    doc, observed = golden_g()
    plain = copy.deepcopy(doc)
    del plain["sources"]["kev"]
    result = walk(plain, app="demo", track="demo/stable", timeline=observed)
    assert set(result["policy_refusals"]) == {"kev-only", "30d-or-kev"}
    assert result["policy_refusals"]["kev-only"] == {
        "reason": "kev_unknown",
        "sentence": "LoonSec's patch-policy data for Demo cannot say whether a CVE is on CISA's KEV list (it names no source "
        "of KEV dates, sources.kev), so the policy definition Patch on a KEV (kev-only) was not walked; every stop was. "
        "The data is the same for every instance and none of yours is read: report the sentence with the data's date "
        "(Settings › Support).",
    }
    assert list(result["policies"]) == [*STOPS, "critical-only"]
    assert check_totals(result, "kev-only") == {"refused": "kev_unknown"}
    # Every CVE row says nothing about KEV then, rather than "not listed".
    assert all(row["knowable"]["kev_listed"] is None for row in result["cves"])
    assert result["counts"]["knowable"]["kev_listed"] == {"kev_date_added": 0}
    # Its definition is still carried as data, so the page can name what it refused.
    assert [each["id"] for each in result["policy_definitions"]] == ["kev-only", "critical-only", "30d-or-kev"]

    unsaid = copy.deepcopy(doc)
    del unsaid["apps"][0]["tracks"][0]["cves"][2]["kev_date_added"]
    assert (
        "(CVE-2026-0603 has no kev_date_added)"
        in walk(unsaid, app="demo", track="demo/stable", timeline=observed)["policy_refusals"]["kev-only"]["sentence"]
    )
    garbled = copy.deepcopy(doc)
    garbled["apps"][0]["tracks"][0]["cves"][0]["kev_date_added"] = "soon"
    assert (
        "(CVE-2026-0601's kev_date_added 'soon' is not a date)"
        in walk(garbled, app="demo", track="demo/stable", timeline=observed)["policy_refusals"]["30d-or-kev"]["sentence"]
    )

    full = walk(doc, app="demo", track="demo/stable", timeline=observed)
    for mutate, what in (
        (lambda row: row.__setitem__("severity", "severe"), "CVE-2026-0601's severity 'severe' is not one this walk reads"),
        (lambda row: row.__setitem__("first_scored", ["2026-03-01"]), "CVE-2026-0601's first_scored is not an object of days"),
        (
            lambda row: row.__setitem__("first_scored", {"critical": "later"}),
            "CVE-2026-0601's first_scored.critical 'later' is not a date",
        ),
    ):
        odd = copy.deepcopy(doc)
        mutate(odd["apps"][0]["tracks"][0]["cves"][0])
        refused = walk(odd, app="demo", track="demo/stable", timeline=observed)
        assert set(refused["policy_refusals"]) == {"critical-only"}, what
        assert refused["policy_refusals"]["critical-only"]["reason"] == "severity_unknown"
        assert refused["policy_refusals"]["critical-only"]["sentence"] == (
            f"LoonSec's patch-policy data for Demo cannot say which CVEs are critical ({what}), so the policy definition "
            "Patch only on a critical (critical-only) was not walked; every stop was. The data is the same for every "
            "instance and none of yours is read: report the sentence with the data's date (Settings › Support)."
        )
        # The KEV definitions read no severity, so they walk as before, and so does every stop.
        assert refused["policies"]["kev-only"] == full["policies"]["kev-only"]
        assert {stop: refused["policies"][stop] for stop in STOPS} == {stop: full["policies"][stop] for stop in STOPS}


@pytest.mark.parametrize(
    ("broken", "problem"),
    [
        (
            {"when": [{"fixes": "epss_over_half", "within_days": 0}]},
            "when[0] fixes 'epss_over_half', which is not one of the triggers",
        ),
        (
            {"when": [{"fixes": "kev_listed", "within_days": 2}]},
            "when[0].within_days is 2, not one of the slider's day counts (0, 1, 3, 7, 14, 30, 60)",
        ),
        ({"otherwise": 90}, "otherwise is 90, neither never nor one of the slider's day counts (0, 1, 3, 7, 14, 30, 60)"),
        ({"when": "kev_listed"}, "when is not a list of triggers"),
    ],
)
def test_a_definition_whose_trigger_the_walk_cannot_run_is_refused_as_a_defect(monkeypatch, broken: dict, problem: str) -> None:
    """A built-in definition that names a trigger outside the closed set, or a day count the slider
    does not have, is LoonInspect's own defect: it is refused in words, and nothing else is."""
    odd = {"id": "odd", "name": "An odd one", "otherwise": "never", "when": [], **broken}
    monkeypatch.setattr(walk_module, "POLICY_DEFINITIONS", (*walk_module.POLICY_DEFINITIONS, odd))
    monkeypatch.setattr(walk_module, "POLICIES", (*POLICIES, "odd"))
    doc, observed = golden_g()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    refused = result["policy_refusals"]["odd"]
    assert refused["reason"] == "definition_invalid"
    assert refused["sentence"].startswith(f"The built-in policy definition An odd one (odd) cannot be walked ({problem}")
    assert refused["sentence"].endswith(
        "so it was not walked; every stop was. This is a defect in LoonInspect, not in this instance's data: report the "
        "sentence (Settings › Support)."
    )
    assert "odd" not in result["policies"] and "odd" not in result["definitions"]
    assert list(result["policy_refusals"]) == ["odd"]


def test_a_definition_is_asked_for_by_its_id_and_conformance_mode_walks_the_stops_only() -> None:
    doc, observed = golden_g()
    one = walk(doc, app="demo", track="demo/stable", timeline=observed, stops=("kev-only",))
    assert list(one["policies"]) == ["kev-only"] and one["inputs"]["stops"] == ["kev-only"]
    assert one["policies"]["kev-only"] == walk(doc, app="demo", track="demo/stable", timeline=observed)["policies"]["kev-only"]
    unknown = refusal(doc, observed, stops=("kev-maybe",))
    assert unknown.reason == "request_invalid"
    assert unknown.sentence.startswith("The stops and policy definitions asked for are ['kev-maybe']; each is one of 0d, 1d")
    assert unknown.sentence.endswith("never, kev-only, critical-only, 30d-or-kev, once.")
    conformance = refusal(doc, observed, stops=("kev-only",), compat_v1=True)
    assert conformance.sentence.endswith("never, once (conformance mode walks the stops only).")
    v1 = walk(doc, app="demo", track="demo/stable", timeline=observed, compat_v1=True)
    assert list(v1["policies"]) == list(STOPS) and v1["policy_definitions"] == [] and "knowable" not in v1["counts"]
    assert all("knowable" not in row for row in v1["cves"])


def test_no_definition_is_named_for_a_framework_or_says_a_policy_is_met() -> None:
    """The 2026-08-31 scope ruling: "Patch on a KEV" is a rule about a public list. No built-in
    definition, and none of the walk's words about them, names a framework or says meets, passes or
    complies."""
    doc, observed = golden_g()
    result = walk(doc, app="demo", track="demo/stable", timeline=observed)
    said = [definition["name"] for definition in walk_module.POLICY_DEFINITIONS]
    said += [result["definitions"][key] for key in ("policy_definition", "trigger_day", "fixing_release", "severity_day")]
    said += [result["definitions"][definition["id"]] for definition in walk_module.POLICY_DEFINITIONS]
    for text in said:
        lowered = text.lower()
        for word in (
            "meets",
            "passes",
            "complies",
            "compliant",
            "compliance",
            "nist",
            "cis ",
            "pci",
            "hipaa",
            "soc 2",
            "iso ",
            "fedramp",
            "essentials",
            "bod ",
        ):
            assert word not in lowered, (word, text)
    ids = [definition["id"] for definition in walk_module.POLICY_DEFINITIONS]
    assert not set(ids) & set(STOPS) and all(each == each.lower() and " " not in each for each in ids)
    assert (*STOPS, *ids) == POLICIES


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
    # What the built-in definitions read (#954), drawn last, so that every draw above is the one it
    # always was: a named KEV source, each row's listing day or none, today's severity, and now and
    # then the first-scored days LoonSec's data may state.
    doc["sources"]["kev"] = {"via": "generated"}
    for row in track["cves"]:
        row["kev_date_added"] = d(rng.randint(-60, 330)) if rng.random() < 0.35 else None
        row["severity"] = rng.choice(["critical", "high", "medium", "low", None])
        if rng.random() < 0.25:
            row["first_scored"] = {
                kind: d(rng.randint(-60, 330)) if rng.random() < 0.6 else None for kind in ("critical", "critical_or_high")
            }
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
    """Intervals of one CVE are merged when adjacent, so the day an interval closes is never the day the next
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
    stop's, and `never` contains the 0-day stop's, which opens the window on the release `never`
    keeps and only rises from it. Not asserted: a slower stop against never, which can open the window
    on an older release (golden A's 60d shows why)."""
    chain = ["0d", "1d", "3d", "7d", "14d", "30d", "60d"]
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
        assert exposed["0d"] <= exposed["never"], seed


def test_a_definition_runs_between_its_otherwise_stop_and_the_0_day_stop() -> None:
    """On monotone documents, a definition's device never runs a release below its `otherwise` stop's
    (each release is installed no later, and the window opens no lower), nor above the 0-day stop's
    (no release is installed before it is available), so the CVEs it is exposed to contain the 0-day
    stop's and are contained in its otherwise stop's: `never` for `kev-only` and `critical-only`, 30
    days for `30d-or-kev`. And no trigger installs a release before its date or its fact."""
    otherwise = {"kev-only": "never", "critical-only": "never", "30d-or-kev": "30d"}
    triggered = 0
    for seed, _, observed, _, result in generated(GENERATED, monotone=True):
        assert result["policy_refusals"] == {}, seed
        dated = {row["version"].lower(): row["date"] for row in observed["observations"]}
        exposed = {
            policy: {
                r["cve_id"] for r in result["cves"] if r["class"] == "in_window" and r["outcomes"][policy]["outcome"] == "exposed"
            }
            for policy in POLICIES
        }
        for policy, slower in otherwise.items():
            assert exposed["0d"] <= exposed[policy] <= exposed[slower], (seed, policy)
            for install in result["policies"][policy]["installs"]:
                assert install["date"] >= dated[install["version"].lower()], (seed, policy, install)
                if install["by"]["rule"] != "otherwise":
                    triggered += 1
                    assert install["date"] >= install["by"]["on"], (seed, policy, install)
    assert triggered > 50, "the generated documents give the definitions too few triggers to test"


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


# --- The frozen check: what this walk counted, held --------------------------------------------

# A `patch_policy_reference` of invented apps whose every track's `check` this walk wrote once
# (`write_frozen`), one file per algorithm. An instance holds a published document's check to its
# own copy of this module (plan 4.7), so this is the cross-version test the hand goldens above are
# not: a walk that counts differently is a new algorithm, with its own file beside the old ones.
FROZEN_DIR = Path(__file__).parent / "fixtures" / "patch_policy"
FROZEN_WRITE = "cd backend && uv run --frozen python -m tests.test_patch_policy_walk --write"


def frozen_path(algorithm: str, directory: Path = FROZEN_DIR) -> Path:
    """The frozen check one algorithm wrote: `frozen_check.patch_walk-1.json` for patch_walk/1."""
    return directory / f"frozen_check.{algorithm.replace('/', '-')}.json"


FROZEN = frozen_path(walk_module.ALGORITHM)


class FrozenRefused(Exception):
    """`write_frozen` would change a check the walk under the same algorithm already wrote."""


def frozen_checks(doc: dict[str, Any], module: Any = walk_module) -> dict[tuple[str, str], dict[str, dict[str, Any]]]:
    """Each track's `check` as `module`'s walk writes it, by (app, track): every window length the
    walk offers, every stop's and built-in definition's `check_totals` (`POLICIES`), over the track's
    public timeline. The shape LoonVD publishes. Walked on a copy without the checks it holds, so a
    walk that disagrees is compared here, in words, rather than refused as parity. A window the walk
    refuses is a broken fixture, and raises."""
    doc = copy.deepcopy(doc)
    doc["doc_id"] = doc.get("doc_id") or "frozen-check"  # a walk names its inputs by it; totals never read it
    for app in doc["apps"]:
        for track in app["tracks"]:
            track["check"] = {}
    written = {}
    for app in doc["apps"]:
        for track in app["tracks"]:
            timeline = module.public_timeline(doc, app=app["app"], track=track["track"])
            check = {}
            for years in module.WINDOW_YEARS:
                result = module.walk(doc, app=app["app"], track=track["track"], timeline=timeline, years=years)
                check[f"{years}y"] = {stop: module.check_totals(result, stop) for stop in module.POLICIES}
            written[(app["app"], track["track"])] = check
    return written


def first_difference(held: dict[str, Any], walked: dict[str, Any]) -> tuple[str, str, str, Any, Any] | None:
    """The first (window, stop, key, walked, held) where a held check and a walked one differ, in
    the walk's order of windows, stops and keys; None when they are the same. A window or stop
    either side lacks differs at its first key."""
    for window in sorted(set(held) | set(walked), key=lambda name: (name not in walked, name)):
        stops_held, stops_walked = held.get(window) or {}, walked.get(window) or {}
        for stop in [*POLICIES, *sorted(set(stops_held) - set(POLICIES))]:
            now, then = stops_walked.get(stop) or {}, stops_held.get(stop) or {}
            for key in [*CHECK_KEYS, *sorted(set(then) - set(CHECK_KEYS))]:
                if now.get(key) != then.get(key):
                    return window, stop, key, now.get(key), then.get(key)
    return None


def _counts_differently(path: Path, where: str, key: str, walked: Any, frozen: Any) -> str:
    """The words for a walk that no longer counts the check it wrote: the change is a new
    algorithm, and nothing rewrites the old algorithm's check."""
    return (
        f"patch_policy_walk now counts differently from the check it wrote in tests/fixtures/patch_policy/{path.name} "
        f"({where}: {key} is {walked!r} here and {frozen!r} in the check). A counting change is a new algorithm "
        "(LoonVD's contract: \"A walk that counts differently is a new algorithm\"): LoonSec publishes each track's "
        f"check from its pinned copy of this walk, so every instance still on {walk_module.ALGORITHM} would refuse the "
        "app as parity. Revert the counting change. A ruled one ships as a new algorithm with the N-1 plan (the old "
        "one kept published for at least 90 days, ruled R11): bump ALGORITHM, and --write then writes the new "
        f"algorithm's frozen check in a file of its own beside {path.name}, which stays as it is. --write never "
        "rewrites a check under the algorithm that wrote it."
    )


def _algorithm_number(path: Path, directory: Path = FROZEN_DIR) -> int:
    """N of the patch_walk/N whose frozen check `path` is, read from the document and held to its name."""
    algorithm = json.loads(path.read_text())["algorithm"]
    assert frozen_path(algorithm, directory) == path, f"{path.name} holds {algorithm}: a frozen check is named by its algorithm"
    family, _, number = algorithm.partition("/")
    assert family == "patch_walk" and number.isdigit(), f"{path.name}: {algorithm!r} is not patch_walk/N"
    return int(number)


def write_frozen(directory: Path = FROZEN_DIR, module: Any = walk_module) -> tuple[Path, list[str]]:
    """Write the frozen check of `module`'s algorithm, and say which tracks it wrote.

    With that algorithm's file present it fills only what a check lacks: a track whose `check` is
    empty (a new case, or one whose case was changed on purpose and its check emptied in the same
    change), and the entries of a policy a check does not hold yet (the built-in definitions, added
    to patch_walk/2 before it was published; ruled 2026-11-28). It refuses, writing nothing, when any
    entry already there differs from this walk: a counting change under the same algorithm is the
    change the frozen check exists to stop. With no file for it (a new algorithm) it writes one
    beside the others from the newest one's body, every track's check walked afresh, and leaves the
    older files as they are. The `doc_id` is recomputed whenever it writes; a file with nothing to
    fill is left alone."""
    from app.core import patch_policy_feed as feed

    path = frozen_path(module.ALGORITHM, directory)
    filled: list[str] = []
    if path.exists():
        doc = json.loads(path.read_text())
        if doc["algorithm"] != module.ALGORITHM:
            raise FrozenRefused(f"{path.name} holds {doc['algorithm']!r}, not {module.ALGORITHM}: name it by its algorithm.")
        written = frozen_checks(doc, module)
        for app in doc["apps"]:
            for track in app["tracks"]:
                walked = written[(app["app"], track["track"])]
                if not track.get("check"):
                    track["check"] = walked
                    filled.append(track["track"])
                    continue
                held = track["check"]
                # Every entry the check holds is compared; one it lacks is not a difference but a new case.
                compared = {
                    window: {stop: (walked.get(window) or {}).get(stop) for stop in stops} for window, stops in held.items()
                }
                differs = first_difference(held, compared)
                if differs:
                    window, stop, key, now, then = differs
                    raise FrozenRefused(
                        "Nothing written. "
                        + _counts_differently(path, f"{track['track']}, {window}, {stop}", key, now, then)
                        + ' To change a case on purpose, empty that track\'s check ("check": {}) in the same change; '
                        "--write fills only an empty check, or an entry a check lacks."
                    )
                lacked = [
                    (window, stop) for window, stops in walked.items() for stop in stops if stop not in held.get(window, {})
                ]
                for window, stop in lacked:
                    held.setdefault(window, {})[stop] = walked[window][stop]
                if lacked:
                    filled.append(track["track"])
        if not filled:
            return path, []
    else:
        older = sorted(directory.glob("frozen_check.*.json"), key=lambda found: _algorithm_number(found, directory))
        if not older:
            raise FrozenRefused(f"No frozen check in {directory} to start {module.ALGORITHM}'s from.")
        doc = json.loads(older[-1].read_text())
        doc["algorithm"] = module.ALGORITHM
        written = frozen_checks(doc, module)
        for app in doc["apps"]:
            for track in app["tracks"]:
                track["check"] = written[(app["app"], track["track"])]
                filled.append(track["track"])
    doc["doc_id"] = feed.canonical_doc_id(doc)
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    return path, filled


def test_the_walk_still_counts_the_check_it_wrote() -> None:
    """Every stop of every window of every track of this algorithm's frozen check walks to exactly
    the check this walk wrote for it. The document holds what a real one does in small: one line
    with a train per major and a backport shipped two days after the next major (rule 5 keeps 116.0
    affected until 115.0.2's day), three lines with a track held to one of them and fixes on several,
    a CVE NVD names no fix for, a fix only an undated build carries, a fix NVD names by a build the
    track does not list, a CVE on the ESR edition set aside (`other_edition_only`) beside the ESR
    channel the app names under `other_channels` and does not walk, the day boundaries the hand
    goldens pin (Example Editor, whose dates met patch_walk/1's stops, and Example Notes, added
    with patch_walk/2: a release dated on the two-year window's first day, which the 0-day stop runs
    that day and the 1-day stop installs the next, and a fix the 3-day stop installs on the window's
    last day), and a Chrome-style promotion table (Example Viewer: early builds dated before their
    major's promotion day, a respin dated after the next major's early build, and a release above the
    table's newest row that cuts the window). `COUNTING_MUTANTS` names each rule. Its versions,
    dates and CVE ids are invented."""
    from app.core import patch_policy_feed as feed

    assert FROZEN.exists(), (
        f"This walk is {walk_module.ALGORITHM} and no frozen check is written for it: {FROZEN_WRITE} writes "
        f"{FROZEN.name} beside the older algorithms' files, which stay."
    )
    raw = FROZEN.read_bytes()
    doc = json.loads(raw)
    assert doc["algorithm"] == walk_module.ALGORITHM, f"{FROZEN.name} holds {doc['algorithm']}: name it by its algorithm"
    # A document an instance would store: checked whole, its doc_id its contents.
    feed.read_document(raw, expected_doc_id=doc["doc_id"])

    written = frozen_checks(doc)
    for app in doc["apps"]:
        for track in app["tracks"]:
            frozen = track["check"]
            assert set(frozen) == {f"{years}y" for years in walk_module.WINDOW_YEARS}, (
                f"{track['track']} has no frozen check for every window; {FROZEN_WRITE} fills an empty one"
            )
            for window, stops in frozen.items():
                assert set(stops) == set(POLICIES), (
                    f"{track['track']} {window} lacks a stop or a definition; {FROZEN_WRITE} fills it"
                )
            differs = first_difference(frozen, written[(app["app"], track["track"])])
            if differs:
                window, stop, key, walked, held = differs
                pytest.fail(_counts_differently(FROZEN, f"{track['track']}, {window}, {stop}", key, walked, held))
            for window in frozen:
                # As an instance runs it: the public walk at each window matches.
                result = walk(
                    doc,
                    app=app["app"],
                    track=track["track"],
                    timeline=public_timeline(doc, app=app["app"], track=track["track"]),
                    years=int(window[:-1]),
                )
                assert result["check"]["state"] == "matched"


def test_every_algorithm_keeps_its_own_frozen_check() -> None:
    """One file per algorithm, named by it, from patch_walk/1 to this walk's: a new algorithm's check
    is written beside the old ones, never in their place. A file of an algorithm this build no
    longer reads is kept as the record of what that walk counted."""
    numbers = sorted(_algorithm_number(path) for path in FROZEN_DIR.glob("frozen_check.*.json"))
    current = int(walk_module.ALGORITHM.rpartition("/")[2])
    assert numbers == list(range(1, current + 1)), (
        f"frozen checks held for patch_walk/{numbers}; every algorithm from patch_walk/1 to {walk_module.ALGORITHM} "
        "keeps its own file"
    )
    assert not (FROZEN_DIR / "frozen_check.json").exists(), "frozen_check.json is named by no algorithm"


# What patch_walk/1's 1-day stop installed and totalled over the frozen check's own document, per
# track and window, before the 2026-11-27 ruling: printed from origin/main's walk at 8c42d569 and held
# here as that walk printed them, so that no edit to this walk can rewrite them. Each value is the
# installs, "day version" in order, then `check_totals`. That stop installed each release on the day it
# was dated, which is the 0-day stop now: "0 computes what the 1-day stop computes today" (#953).
PATCH_WALK_1_ONE_DAY: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {
    ("browser/release", "2y"): (
        "2024-12-17 114.0 2024-12-31 114.0.1 2025-01-28 115.0 2025-02-11 115.0.1 2025-03-11 116.0 "
        "2025-03-25 116.0.1 2025-04-22 117.0 2025-05-06 117.0.1 2025-06-03 118.0 2025-06-17 118.0.1 "
        "2025-07-15 119.0 2025-07-29 119.0.1 2025-08-26 120.0 2025-09-09 120.0.1 2025-10-07 121.0 "
        "2025-10-21 121.0.1 2025-11-18 122.0 2025-12-02 122.0.1 2025-12-15 122.0.2.1 2025-12-30 123.0 "
        "2026-01-13 123.0.1 2026-02-10 124.0 2026-02-24 124.0.1 2026-03-24 125.0 2026-04-07 125.0.1 "
        "2026-05-05 126.0 2026-05-19 126.0.1 2026-06-16 127.0 2026-07-28 128.0 2026-08-11 128.0.1 "
        "2026-09-08 129.0 2026-09-22 129.0.1 2026-10-20 130.0 2026-11-03 130.0.1",
        {"since": "2024-11-22", "until": "2026-11-22", "in_window": 9, "replayed": 7, "excluded": 2, "never_seen": 0,
         "never_seen_outside_affected_range": 0, "exposed": 7, "exposure_days": 221,
         "open_at_window_end": {"in_window": 1, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 2, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 34, "initial_version": "113.0.1",
         "final_version": "130.0.1"},
    ),
    ("browser/release", "3y"): (
        "2024-06-04 109.0.1 2024-07-02 110.0 2024-07-16 110.0.1 2024-08-13 111.0 2024-08-27 111.0.1 "
        "2024-09-24 112.0 2024-10-08 112.0.1 2024-11-05 113.0 2024-11-19 113.0.1 2024-12-17 114.0 "
        "2024-12-31 114.0.1 2025-01-28 115.0 2025-02-11 115.0.1 2025-03-11 116.0 2025-03-25 116.0.1 "
        "2025-04-22 117.0 2025-05-06 117.0.1 2025-06-03 118.0 2025-06-17 118.0.1 2025-07-15 119.0 "
        "2025-07-29 119.0.1 2025-08-26 120.0 2025-09-09 120.0.1 2025-10-07 121.0 2025-10-21 121.0.1 "
        "2025-11-18 122.0 2025-12-02 122.0.1 2025-12-15 122.0.2.1 2025-12-30 123.0 2026-01-13 123.0.1 "
        "2026-02-10 124.0 2026-02-24 124.0.1 2026-03-24 125.0 2026-04-07 125.0.1 2026-05-05 126.0 "
        "2026-05-19 126.0.1 2026-06-16 127.0 2026-07-28 128.0 2026-08-11 128.0.1 2026-09-08 129.0 "
        "2026-09-22 129.0.1 2026-10-20 130.0 2026-11-03 130.0.1",
        {"since": "2024-05-22", "until": "2026-11-22", "in_window": 10, "replayed": 8, "excluded": 2, "never_seen": 0,
         "never_seen_outside_affected_range": 0, "exposed": 8, "exposure_days": 228,
         "open_at_window_end": {"in_window": 1, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 1, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 43, "initial_version": "109.0",
         "final_version": "130.0.1"},
    ),
    ("analyzer/4.2", "2y"): (
        "2025-01-15 4.2.6 2025-05-14 4.2.7 2025-09-10 4.2.8 2026-01-14 4.2.9 2026-05-13 4.2.10",
        {"since": "2024-11-22", "until": "2026-11-22", "in_window": 5, "replayed": 5, "excluded": 0, "never_seen": 1,
         "never_seen_outside_affected_range": 1, "exposed": 4, "exposure_days": 283,
         "open_at_window_end": {"in_window": 1, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 1, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 5, "initial_version": "4.2.5",
         "final_version": "4.2.10"},
    ),
    ("analyzer/4.2", "3y"): (
        "2024-07-10 4.2.4 2024-10-09 4.2.5 2025-01-15 4.2.6 2025-05-14 4.2.7 2025-09-10 4.2.8 2026-01-14 4.2.9 "
        "2026-05-13 4.2.10",
        {"since": "2024-05-22", "until": "2026-11-22", "in_window": 6, "replayed": 6, "excluded": 0, "never_seen": 1,
         "never_seen_outside_affected_range": 1, "exposed": 5, "exposure_days": 331,
         "open_at_window_end": {"in_window": 1, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 0, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 7, "initial_version": "4.2.3",
         "final_version": "4.2.10"},
    ),
    ("analyzer/newest", "2y"): (
        "2025-01-15 4.4.2 2025-04-09 4.4.3 2025-07-09 4.4.4 2025-10-08 4.4.5 2026-01-14 4.4.6 2026-04-08 4.4.7 "
        "2026-07-08 4.4.8 2026-10-07 4.4.9",
        {"since": "2024-11-22", "until": "2026-11-22", "in_window": 5, "replayed": 5, "excluded": 0, "never_seen": 1,
         "never_seen_outside_affected_range": 1, "exposed": 4, "exposure_days": 173,
         "open_at_window_end": {"in_window": 0, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 1, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 8, "initial_version": "4.4.1", "final_version": "4.4.9"},
    ),
    ("analyzer/newest", "3y"): (
        "2024-07-10 4.2.4 2024-08-28 4.4.0 2024-11-22 4.4.1 2025-01-15 4.4.2 2025-04-09 4.4.3 2025-07-09 4.4.4 "
        "2025-10-08 4.4.5 2026-01-14 4.4.6 2026-04-08 4.4.7 2026-07-08 4.4.8 2026-10-07 4.4.9",
        {"since": "2024-05-22", "until": "2026-11-22", "in_window": 6, "replayed": 6, "excluded": 0, "never_seen": 1,
         "never_seen_outside_affected_range": 1, "exposed": 5, "exposure_days": 221,
         "open_at_window_end": {"in_window": 0, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 0, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 11, "initial_version": "4.2.3",
         "final_version": "4.4.9"},
    ),
    ("editor/release", "2y"): (
        "2024-12-02 3.0.2 2025-02-03 4.0 2025-03-03 4.0.1 2025-05-05 5.0 2025-06-02 6.0 2025-06-28 7.0.1 "
        "2025-08-11 8.0 2025-09-08 8.0.1 2025-09-22 9.0 2025-10-06 9.0.1 2025-11-03 10.0 2025-11-17 10.0.1 "
        "2025-12-15 11.0 2026-02-09 12.0 2026-05-04 13.0 2026-08-03 14.0 2026-09-14 14.0.1 2026-10-26 15.0 "
        "2026-11-16 15.0.1",
        {"since": "2024-11-22", "until": "2026-11-22", "in_window": 5, "replayed": 5, "excluded": 0, "never_seen": 1,
         "never_seen_outside_affected_range": 0, "exposed": 4, "exposure_days": 95,
         "open_at_window_end": {"in_window": 0, "carried_in": 0, "entered_after_start": 0}, "carried_in": 1,
         "entered_after_start": 0, "pre_window_closed": 0, "exposure_days_carried_in": 10,
         "exposure_days_entered_after_start": 0, "update_events": 19, "initial_version": "3.0.1",
         "final_version": "15.0.1"},
    ),
    ("editor/release", "3y"): (
        "2024-06-10 2.0.1 2024-09-16 3.0 2024-11-10 3.0.1 2024-12-02 3.0.2 2025-02-03 4.0 2025-03-03 4.0.1 "
        "2025-05-05 5.0 2025-06-02 6.0 2025-06-28 7.0.1 2025-08-11 8.0 2025-09-08 8.0.1 2025-09-22 9.0 "
        "2025-10-06 9.0.1 2025-11-03 10.0 2025-11-17 10.0.1 2025-12-15 11.0 2026-02-09 12.0 2026-05-04 13.0 "
        "2026-08-03 14.0 2026-09-14 14.0.1 2026-10-26 15.0 2026-11-16 15.0.1",
        {"since": "2024-05-22", "until": "2026-11-22", "in_window": 6, "replayed": 6, "excluded": 0, "never_seen": 1,
         "never_seen_outside_affected_range": 0, "exposed": 5, "exposure_days": 115,
         "open_at_window_end": {"in_window": 0, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 0, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 22, "initial_version": "2.0", "final_version": "15.0.1"},
    ),
    ("viewer/stable", "2y"): (
        "2025-01-14 104.0.5400.55 2025-02-18 104.0.5400.80 2025-04-15 105.0.5500.45 2025-05-20 105.0.5500.70 "
        "2025-07-15 106.0.5600.45 2025-08-19 106.0.5600.70 2025-10-14 107.0.5700.45 2025-11-18 107.0.5700.70 "
        "2026-01-13 108.0.5800.45 2026-02-17 108.0.5800.70 2026-04-07 108.0.5800.90 2026-04-14 109.0.5900.45 "
        "2026-05-19 109.0.5900.70 2026-07-14 110.0.6000.45 2026-08-18 110.0.6000.70 2026-10-13 111.0.6100.45 "
        "2026-11-03 111.0.6100.70",
        {"since": "2024-11-22", "until": "2026-11-09", "in_window": 5, "replayed": 5, "excluded": 0, "never_seen": 0,
         "never_seen_outside_affected_range": 0, "exposed": 5, "exposure_days": 59,
         "open_at_window_end": {"in_window": 1, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 1, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 17, "initial_version": "103.0.5300.70",
         "final_version": "111.0.6100.70"},
    ),
    ("viewer/stable", "3y"): (
        "2024-07-16 102.0.5200.50 2024-08-20 102.0.5200.75 2024-10-15 103.0.5300.45 2024-11-19 103.0.5300.70 "
        "2025-01-14 104.0.5400.55 2025-02-18 104.0.5400.80 2025-04-15 105.0.5500.45 2025-05-20 105.0.5500.70 "
        "2025-07-15 106.0.5600.45 2025-08-19 106.0.5600.70 2025-10-14 107.0.5700.45 2025-11-18 107.0.5700.70 "
        "2026-01-13 108.0.5800.45 2026-02-17 108.0.5800.70 2026-04-07 108.0.5800.90 2026-04-14 109.0.5900.45 "
        "2026-05-19 109.0.5900.70 2026-07-14 110.0.6000.45 2026-08-18 110.0.6000.70 2026-10-13 111.0.6100.45 "
        "2026-11-03 111.0.6100.70",
        {"since": "2024-05-22", "until": "2026-11-09", "in_window": 6, "replayed": 6, "excluded": 0, "never_seen": 0,
         "never_seen_outside_affected_range": 0, "exposed": 6, "exposure_days": 66,
         "open_at_window_end": {"in_window": 1, "carried_in": 0, "entered_after_start": 0}, "carried_in": 0,
         "entered_after_start": 0, "pre_window_closed": 0, "exposure_days_carried_in": 0,
         "exposure_days_entered_after_start": 0, "update_events": 21, "initial_version": "101.0.5100.70",
         "final_version": "111.0.6100.70"},
    ),
}  # fmt: skip


def test_the_0_day_stop_installs_and_totals_what_the_1_day_stop_of_patch_walk_1_did() -> None:
    """On the frozen check's document, every track patch_walk/1's file holds (their bodies are the same
    in both algorithms' files) and every window: the 0-day stop installs and totals exactly what
    patch_walk/1's 1-day stop did, held above as that walk printed them. The totals are also the `1d`
    entries of patch_walk/1's own frozen check (frozen_check.patch_walk-1.json, which stays as it is),
    so the literals and that file read against each other, and neither is this walk's to rewrite."""
    doc = json.loads(FROZEN.read_text())
    older = json.loads(frozen_path("patch_walk/1").read_text())
    assert older["algorithm"] == "patch_walk/1"
    held = {
        (track["track"], window): stops["1d"]
        for app in older["apps"]
        for track in app["tracks"]
        for window, stops in track["check"].items()
    }
    assert set(PATCH_WALK_1_ONE_DAY) == set(held)
    bodies = {track["track"]: (app, track) for app in doc["apps"] for track in app["tracks"]}
    for track_id, window in PATCH_WALK_1_ONE_DAY:
        app, track = bodies[track_id]
        older_track = next(each for each in (t for a in older["apps"] for t in a["tracks"]) if each["track"] == track_id)
        assert {**track, "check": None} == {**older_track, "check": None}, f"{track_id}'s body is not patch_walk/1's"
        installs, totals = PATCH_WALK_1_ONE_DAY[(track_id, window)]
        timeline = public_timeline(doc, app=app["app"], track=track_id)
        result = walk(doc, app=app["app"], track=track_id, timeline=timeline, years=int(window[:-1]))
        same_day = result["policies"]["0d"]
        assert " ".join(f"{row['date']} {row['version']}" for row in same_day["installs"]) == installs, (track_id, window)
        assert check_totals(result, "0d") == totals, (track_id, window)
        assert totals == held[(track_id, window)], (track_id, window)


def _frozen_copy(tmp_path: Path) -> Path:
    copied = tmp_path / FROZEN.name
    copied.write_bytes(FROZEN.read_bytes())
    return copied


def test_write_refuses_to_rewrite_a_check_under_the_algorithm_that_wrote_it(tmp_path: Path, monkeypatch) -> None:
    """The forbidden path stays shut: a counting change with ALGORITHM unchanged (every day stop
    waiting a day longer than its label, here) makes `--write` refuse, say where it differs, and write
    nothing. So does a check edited by hand."""
    copied = _frozen_copy(tmp_path)
    before = copied.read_bytes()
    with monkeypatch.context() as patched:
        patched.setattr(walk_module, "DAY_STOPS", {stop: days + 1 for stop, days in walk_module.DAY_STOPS.items()})
        with pytest.raises(FrozenRefused) as counted:
            write_frozen(tmp_path)
    words = str(counted.value)
    assert words.startswith("Nothing written. patch_policy_walk now counts differently from the check it wrote")
    # The 0-day stop waiting one day counts what the 1-day stop does, and its check holds 221, the
    # exposure days the 1-day stop of patch_walk/1 counted (`PATCH_WALK_1_ONE_DAY`).
    assert f"in tests/fixtures/patch_policy/{FROZEN.name} (browser/release, 2y, 0d: exposure_days is 227 here and 221 in" in words
    assert "--write never rewrites a check under the algorithm that wrote it" in words
    assert copied.read_bytes() == before

    edited = json.loads(before)
    edited["apps"][1]["tracks"][0]["check"]["3y"]["30d"]["exposure_days"] += 1
    copied.write_text(json.dumps(edited, indent=1, ensure_ascii=False) + "\n")
    tampered = copied.read_bytes()
    with pytest.raises(FrozenRefused, match=r"\(analyzer/4\.2, 3y, 30d: exposure_days is \d+ here and \d+ in the check\)"):
        write_frozen(tmp_path)
    assert copied.read_bytes() == tampered


def test_write_fills_only_a_track_whose_check_is_empty(tmp_path: Path) -> None:
    """A new case is a track with no check: `--write` fills it and leaves every other one as it was,
    and the same walk fills it with exactly what it wrote before. With nothing to fill it writes
    nothing."""
    copied = _frozen_copy(tmp_path)
    before = copied.read_bytes()
    assert write_frozen(tmp_path) == (copied, [])
    assert copied.read_bytes() == before
    emptied = json.loads(before)
    emptied["apps"][0]["tracks"][0]["check"] = {}
    copied.write_text(json.dumps(emptied, indent=1, ensure_ascii=False) + "\n")
    assert write_frozen(tmp_path) == (copied, ["browser/release"])
    assert copied.read_bytes() == before


def test_write_fills_a_definitions_entries_a_check_lacks_and_moves_no_stop(tmp_path: Path) -> None:
    """How the built-in definitions joined patch_walk/2's frozen check (ruled 2026-11-28, before it was
    published): `--write` fills each entry a check lacks and compares every entry it holds, so a
    definition is added beside the stops without a stop's number moving, and a stop that moved still
    refuses."""
    copied = _frozen_copy(tmp_path)
    before = copied.read_bytes()
    lacking = json.loads(before)
    for app in lacking["apps"]:
        for track in app["tracks"]:
            for stops in track["check"].values():
                for definition in ("kev-only", "critical-only", "30d-or-kev"):
                    del stops[definition]
    copied.write_text(json.dumps(lacking, indent=1, ensure_ascii=False) + "\n")
    _, filled = write_frozen(tmp_path)
    assert filled == [track["track"] for app in lacking["apps"] for track in app["tracks"]]
    assert copied.read_bytes() == before
    lacking["apps"][0]["tracks"][0]["check"]["2y"]["7d"]["exposure_days"] += 1
    copied.write_text(json.dumps(lacking, indent=1, ensure_ascii=False) + "\n")
    with pytest.raises(FrozenRefused, match=r"\(browser/release, 2y, 7d: exposure_days is \d+ here and \d+ in the check\)"):
        write_frozen(tmp_path)


def test_a_new_algorithm_writes_its_own_check_beside_the_old_one(tmp_path: Path, monkeypatch) -> None:
    """The documented path works: with ALGORITHM bumped, `--write` writes the new algorithm's file
    from the old one's body and leaves the old file as it was. (The same walk under a new name
    writes the same totals; a ruled change would move them in the new file only.)"""
    copied = _frozen_copy(tmp_path)
    before = copied.read_bytes()
    monkeypatch.setattr(walk_module, "ALGORITHM", "patch_walk/3")
    path, filled = write_frozen(tmp_path)
    assert path == tmp_path / "frozen_check.patch_walk-3.json"
    assert copied.read_bytes() == before
    old, new = json.loads(before), json.loads(path.read_text())
    assert new["algorithm"] == "patch_walk/3" and new["doc_id"] != old["doc_id"]
    assert filled == [track["track"] for app in old["apps"] for track in app["tracks"]]
    assert {k: v for k, v in new.items() if k not in ("algorithm", "doc_id")} == {
        k: v for k, v in old.items() if k not in ("algorithm", "doc_id")
    }


# Single-line counting changes the frozen check must catch: each is a rule the hand goldens above
# pin, so each moves some total of the frozen document (`test_the_frozen_check_moves_on_every_
# counting_change_it_pins`). An edit to the walk that moves one of these lines fails that test by
# name; re-point the entry at the line that now does it.
COUNTING_MUTANTS = {
    "rule 5 off": (
        "            if own < self.dates[dated_as]:\n                return True",
        "            if False:\n                return True",
    ),
    "rule 5 exempts no train": (
        "if dated_as is None or version.train in (self.versions[fix].train, self.versions[dated_as].train):",
        "if dated_as is None:",
    ),
    "rule 5 exempts the fix's train only": (
        "version.train in (self.versions[fix].train, self.versions[dated_as].train)",
        "version.train == self.versions[fix].train",
    ),
    "rule 5 counts a build dated the fix's day": ("if own < self.dates[dated_as]:", "if own <= self.dates[dated_as]:"),
    "no next dated version stands in for a fix": (
        "prepared.effective_fixes[key] = (found, NEXT_DATED) if found is not None else (None, FIX_UNDATED)",
        "prepared.effective_fixes[key] = (None, FIX_UNDATED)",
    ),
    "a version in the run stands in for its fix": ("if run < 0 or row.runs[run][1] < dated[at]:", "if True:"),
    # The count ruled 2026-11-27 ("0 = same day"): a stop's label is the days it waits. This mutant is
    # the count it replaced, under which a D-day stop waited D - 1 days.
    "a stop waits a day less than its label": (
        "delay = dt.timedelta(days=DAY_STOPS[stop])",
        "delay = dt.timedelta(days=DAY_STOPS[stop] - 1)",
    ),
    "never keeps the version before the window's first day": (
        "return [(since, max((index for index, day in available if day <= since), default=None))]",
        "return [(since, max((index for index, day in available if day < since), default=None))]",
    ),
    "a stop installs a version due on the window's first day late": (
        "current = max((index for index, day in installs if day <= since), default=None)",
        "current = max((index for index, day in installs if day < since), default=None)",
    ),
    "two versions due the same day install the first": ("(day not in due or index > due[day])", "(day not in due)"),
    "a CVE clocked on the window's first day is before it": (
        "in_window = clock_day >= since",
        "in_window = clock_day > since",
    ),
    "exposure counts from the window's first day, not the CVE's clock": (
        "found = _intervals(row, steps, max(clock_day, since), until, judge)",
        "found = _intervals(row, steps, since, until, judge)",
    ),
    "carried in reaches the window's second day": (
        "elif found and found[0][0] == since:",
        "elif found and found[0][0] <= since + _DAY:",
    ),
    "open at the window's end reaches its last day but one": (
        "open_at_window_end = bool(found) and found[-1][1] == until",
        "open_at_window_end = bool(found) and found[-1][1] >= until - _DAY",
    ),
    "the fix itself installed is outside the range": (
        "line == versions[at].line and at >= fix for line, fix in row.fixes",
        "line == versions[at].line and at > fix for line, fix in row.fixes",
    ),
    # The promotion table (Example Viewer): a release of a promoted major waits for the later of its
    # own date and the major's promotion day, one above the table's newest row is never installed,
    # and the window ends the day before the timeline dates such a release.
    "a promoted major's release is available on its own date": (
        "released = max(released, runs[at][2])",
        "released = released",
    ),
    "a promoted major's release waits a day past the promotion": (
        "released = max(released, runs[at][2])",
        "released = max(released, runs[at][2] + _DAY)",
    ),
    # Killed through the window's end, as the next mutant is: the window always ends the day before
    # such a release, so its first difference is `until`. Kept so that the guard stays pinned.
    "a release above the promotion table's newest row is installed": (
        "if newest is not None and index > newest:",
        "if False:",
    ),
    "the window runs past the first release above the promotion table": ("if prepared.above_table:", "if False:"),
    # The built-in definitions (ruled 2026-11-28; Example Mail holds each case). A trigger's day is the
    # later of its release's day and the day its fact was knowable; the earliest due day wins; a
    # severity trigger reads the first-scored day the data states, else the CVE's clock day; a fix the
    # timeline does not date is named by its stand-in; and a trigger due by the window's first day
    # raises the opening.
    "a trigger fires before the fact was knowable": (
        "named.append((dated_as, max(available[dated_as], on), row.cve_id, basis, on))",
        "named.append((dated_as, available[dated_as], row.cve_id, basis, on))",
    ),
    "a trigger fires before its release is available": (
        "named.append((dated_as, max(available[dated_as], on), row.cve_id, basis, on))",
        "named.append((dated_as, on, row.cve_id, basis, on))",
    ),
    "the first trigger offered wins, not the earliest due": (
        "if held is None or (due, rank) < (held[0], held[1]):",
        "if held is None:",
    ),
    "a severity trigger reads no first-scored day": (
        "            if first is not None:\n                known[kind] = (first, BASIS_FIRST_SCORED)",
        "            if False:\n                known[kind] = (first, BASIS_FIRST_SCORED)",
    ),
    "a severity trigger's clock day is NVD publication": (
        "known[kind] = (row.clock_day, BASIS_CLOCK)",
        "known[kind] = (row.published, BASIS_CLOCK)",
    ),
    "a trigger names only a fix the timeline dates itself": (
        "dated_as, _ = _effective_fix(prepared, row, line, fix)",
        "dated_as = fix if fix in prepared.join.dates else None",
    ),
    "a definition's opening ignores a trigger due by the window's first day": (
        "steps = _stepped([(index, due) for index, (due, _, _) in sorted(best.items())], since, until, floor)",
        "steps = _stepped([(i, due) for i, (due, rank, _) in sorted(best.items()) if due > since or not rank[0]], "
        "since, until, floor)",
    ),
}


@pytest.mark.parametrize("mutant", list(COUNTING_MUTANTS))
def test_the_frozen_check_moves_on_every_counting_change_it_pins(mutant: str, monkeypatch) -> None:
    """Each of `COUNTING_MUTANTS`, applied to a copy of the walk, moves some total of the frozen
    check (or makes its walk refuse): an edit to the fixture that drops the case one of them needs
    fails here, by name, rather than leaving that rule unwatched across versions."""
    import importlib.util

    old, new = COUNTING_MUTANTS[mutant]
    source = Path(walk_module.__file__).read_text()
    assert source.count(old) == 1, (
        f"{mutant!r}: its line is not in patch_policy_walk.py exactly once; re-point it at the line that now does this"
    )
    name = f"tests._patch_policy_walk_mutant_{list(COUNTING_MUTANTS).index(mutant)}"
    mutated = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    monkeypatch.setitem(sys.modules, name, mutated)  # a dataclass reads its module while the class is built
    exec(compile(source.replace(old, new), walk_module.__file__, "exec"), mutated.__dict__)

    doc = json.loads(FROZEN.read_text())
    held = {(app["app"], track["track"]): track["check"] for app in doc["apps"] for track in app["tracks"]}
    try:
        walked = frozen_checks(doc, mutated)
    except mutated.WalkRefused:
        return  # the frozen test fails on the refusal too
    assert any(first_difference(held[key], walked[key]) for key in held), (
        f"{mutant!r} counts differently, and no total of {FROZEN.name} moves: the fixture lacks the case it needs"
    )


def test_the_frozen_document_holds_what_its_check_is_meant_to_pin() -> None:
    """The cases the frozen check exists for, read from the document itself, so an edit to the
    fixture cannot drop one in silence."""
    doc = json.loads(FROZEN.read_text())
    tracks = [(app, track) for app in doc["apps"] for track in app["tracks"]]
    lines = {track["track"]: {v["line"] for v in track["versions"]} for _, track in tracks}
    assert any(len(found) >= 3 for found in lines.values()), "no track spans several lines"
    assert any(track["path"].get("kind") == "hold" for _, track in tracks), "no track holds a line"
    trains_on_a_line = {
        (track["track"], v["line"], v["train"]) for _, track in tracks for v in track["versions"] if v["line"] == ""
    }
    assert len(trains_on_a_line) >= 10, "no line holds several trains"
    rows = [row for _, track in tracks for row in track["cves"]]
    assert any(fix["index"] is None for row in rows for fix in row["fixes"]), "no CVE without a fix"
    assert any(len({fix["line"] for fix in row["fixes"]}) >= 2 for row in rows), "no CVE fixed on several lines"
    assert any("named" in fix for row in rows for fix in row["fixes"]), "no fix NVD names by an unlisted build"
    assert any(v["date"] is None for _, track in tracks for v in track["versions"]), "no undated version"
    set_aside = [
        (app, row) for app, track in tracks for row in track["exclusions"]["cves"] if row["reason"] == "other_edition_only"
    ]
    assert set_aside and all(app.get("other_channels") for app, _ in set_aside), "no ESR set-aside"

    # Rule 5's case: a fix dated after a version of another train that ranks above it on its line.
    def backported(track: dict[str, Any]) -> bool:
        versions = track["versions"]
        for row in track["cves"]:
            for fix in row["fixes"]:
                if fix["index"] is None or versions[fix["index"]]["date"] is None:
                    continue
                fixed = versions[fix["index"]]
                if any(
                    v["line"] == fixed["line"] and v["train"] != fixed["train"] and v["date"] and v["date"] < fixed["date"]
                    for v in versions[fix["index"] + 1 :]
                ):
                    return True
        return False

    assert any(backported(track) for _, track in tracks), "no backport for rule 5"

    # The promotion table's cases (a Chrome-style track): a fix dated before its major's promotion
    # day, a release dated on that day, and a release above the table's newest row that the
    # timeline dates inside the requested window, so the window is cut the day before it.
    last_day = (dt.date.fromisoformat(doc["as_of"][:10]) - dt.timedelta(days=1)).isoformat()
    promoted = [track for _, track in tracks if track.get("promotions")]
    assert promoted, "no promotion table"

    def waits(track: dict[str, Any]) -> dict[int, str]:
        return {
            index: row["promoted"] for row in track["promotions"] for index in range(row["versions"][0], row["versions"][1] + 1)
        }

    assert any(
        track["versions"][fix["index"]]["date"] < waits(track)[fix["index"]]
        for track in promoted
        for row in track["cves"]
        for fix in row["fixes"]
        if fix["index"] in waits(track) and track["versions"][fix["index"]]["date"]
    ), "no fix dated before its major's promotion day"
    assert any(track["versions"][index]["date"] == day for track in promoted for index, day in waits(track).items()), (
        "no release dated on its major's promotion day"
    )
    assert any(
        version["date"] and version["date"] <= last_day
        for track in promoted
        for version in track["versions"][track["promotions"][-1]["versions"][1] + 1 :]
    ), "no release above the promotion table's newest row inside the window"

    # The built-in definitions' cases (Example Mail, ruled 2026-11-28), read from the document: a named KEV
    # source; a CVE listed after its fix and a newer release are dated, and one listed before its fix is;
    # a critical CVE whose stated first-scored day is after its clock day and its fix's date; a critical
    # one with none, detectable after it was published and after its fix; two critical CVEs naming one
    # fix, the later id due first; a listed CVE whose fix is undated; and a listing due before the
    # two-year window's first day, of a fix dated within 30 days of it.
    assert doc["sources"].get("kev"), "no KEV source, so a null kev_date_added would say nothing"

    def dated(track: dict[str, Any], index: int | None) -> str | None:
        return track["versions"][index]["date"] if index is not None else None

    listed = [
        (track, row, row["fixes"][0]["index"])
        for _, track in tracks
        for row in track["cves"]
        if row.get("kev_date_added") and row["fixes"]
    ]
    assert any(
        dated(track, at)
        and dated(track, at) < row["kev_date_added"]
        and any(v["date"] and dated(track, at) < v["date"] < row["kev_date_added"] for v in track["versions"])
        for track, row, at in listed
    ), "no CVE listed after its fix and a newer release are dated"
    assert any(dated(track, at) and row["kev_date_added"] < dated(track, at) for track, row, at in listed), (
        "no CVE listed before its fix"
    )
    assert any(dated(track, at) is None for track, row, at in listed), "no listed CVE whose fix the timeline does not date"
    two_year_since = "2024-11-22"
    assert any(
        dated(track, at) and row["kev_date_added"] <= two_year_since and dated(track, at) > "2024-10-23"
        for track, row, at in listed
    ), "no listing due before the two-year window opens, of a fix dated within 30 days of it"
    critical = [(track, row) for _, track in tracks for row in track["cves"] if row.get("severity") == "critical"]
    assert any(
        (row.get("first_scored") or {}).get("critical", "")
        > max(row["detectable_at"], dated(track, row["fixes"][0]["index"]) or "")
        for track, row in critical
    ), "no stated first-scored day after both the clock day and the fix's date"
    assert any(
        not row.get("first_scored")
        and row["published"] < row["detectable_at"]
        and (dated(track, row["fixes"][0]["index"]) or "9") < row["detectable_at"]
        for track, row in critical
    ), "no critical CVE without a first-scored day, detectable after its publication and its fix"
    by_fix: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for track, row in critical:
        if not row.get("first_scored"):
            by_fix.setdefault((track["track"], row["fixes"][0]["index"]), []).append(row)
    assert any(
        len(rows) > 1
        and sorted(rows, key=lambda r: r["cve_id"])[-1]["detectable_at"]
        < sorted(rows, key=lambda r: r["cve_id"])[0]["detectable_at"]
        for rows in by_fix.values()
    ), "no two critical CVEs naming one fix with the later id due first"


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        raise SystemExit(
            f"usage: {FROZEN_WRITE}\nFills each empty check in {FROZEN.name} from today's walk, or writes a new "
            "algorithm's file beside the old ones; it never rewrites a check that is there."
        )
    try:
        written_to, tracks = write_frozen()
    except FrozenRefused as refused:
        raise SystemExit(str(refused)) from None
    print(f"wrote {', '.join(tracks)} in {written_to}" if tracks else f"nothing to write: every check in {written_to} is there")
