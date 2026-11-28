"""Check every recorded result set against counts computed from the fixture's own rules.

Runs in the runner container (cwd=/work). The spike's scopes go through the spike's own bench.check_result, unmodified;
the alternate scopes go through the same arithmetic with a different membership test.
"""
import json
import sys
from collections import Counter

sys.path.insert(0, "/work/docs/spikes/attribute-breakdown-at-40k")
sys.path.insert(0, "/work/backend")
import bench
from ledger import membership_ids

N = 40000


def observed(i):
    return i % 25 != 1


def ea13(i):
    return None if i % 50 == 1 else f"value-{i % 13}"


SCOPES = {
    # group is 5, EA 13 is_not value-3 (an unanswered EA is not "is_not"), site North
    "grp_ea_site": lambda i: observed(i) and 5 in membership_ids(i) and ea13(i) not in (None, "value-3") and i % 3 != 0,
    "grp_managed_site": lambda i: observed(i) and 5 in membership_ids(i) and i % 5 != 0 and i % 3 != 0,
    # group is_not 7 needs a membership section that was read
    "notgrp_managed_site": lambda i: observed(i) and 7 not in membership_ids(i) and i % 5 != 0 and i % 3 != 0,
    "three-column-myrenderer": lambda i: i % 5 != 0 and i % 7 != 0 and i % 3 != 0,
}


def expect(label, in_scope):
    expected = Counter()
    members = Counter({str(g): 0 for g in range(1, 301)})
    membership = [0, 0, 0]
    total = 0
    for i in range(1, N + 1):
        if not in_scope(i):
            continue
        total += 1
        if label == "built-in":
            expected[f"FixtureModel{i % 24}"] += 1
        elif label == "ea":
            expected["" if i % 50 == 1 else f"value-{i % 13}"] += 1
        elif not observed(i):
            membership[2] += 1
        else:
            groups = membership_ids(i)
            members.update(map(str, groups))
            membership[0 if 7 in groups else 1] += 1
    return expected, members, membership, total


def main():
    data = json.loads(open(sys.argv[1]).read())
    bad = 0
    for case in data["cases"]:
        name, scope, result = case["query"], case["scope"], case["result"]
        try:
            if scope in ("whole-fleet", "three-column"):
                bench.check_result(N, scope == "three-column", name, result)
                note = ""
            else:
                expected, members, membership, total = expect(name, SCOPES[scope])
                if name == "one-group":
                    assert result == ["|".join(map(str, membership))], (result, membership)
                else:
                    tallies = {k: int(v) for k, v in (row.split("|") for row in result)}
                    assert tallies == dict(members if name == "all-groups" else expected), "tallies differ"
                note = f" (scope holds {total} Macs)"
            print(f"ok   {data['stage']} {name} {scope}{note}")
        except AssertionError as exc:
            bad += 1
            print(f"FAIL {data['stage']} {name} {scope}: {str(exc)[:300]}")
    print("all result sets correct" if not bad else f"{bad} result sets WRONG")
    sys.exit(1 if bad else 0)


main()
