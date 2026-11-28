import json, statistics, sys, glob, os
HERE = os.path.dirname(os.path.abspath(__file__))
stages = sys.argv[1:] or sorted(os.path.basename(p)[8:-5] for p in glob.glob(HERE + "/results-*.json"))
scopes = ["whole-fleet", "three-column", "grp_managed_site", "grp_ea_site", "notgrp_managed_site"]
queries = ["built-in", "ea", "all-groups", "one-group"]
def walk(n):
    yield n
    for c in n.get("Plans", []): yield from walk(c)
for st in stages:
    r = json.load(open(f"{HERE}/results-{st}.json"))
    s = r["setup"]
    print(f"\n== {st}: closed computer spans {s['closed_computer_spans']} ({s['closed_computer_spans']/40000:.1f}/Mac), sections {s['sections']} (group lists {s['group_sections']}), entries {s['entries']}, spans heap {s['spans_heap']}, sections heap {s['sections_heap']}, db {s['db']}")
    gucs = sorted({c.get("guc", "") for c in r["cases"]})
    for g in gucs:
        if g: print("   with", g)
        print(f"   {'warm ms (cold)':16s}" + "".join(f"{q:>22s}" for q in queries))
        for sc in scopes:
            row = []
            for q in queries:
                c = [c for c in r["cases"] if c["query"] == q and c["scope"] == sc and c.get("guc", "") == g]
                if not c: row.append(""); continue
                ex = [p["Execution Time"] for p in c[0]["plans"]]
                row.append(f"{statistics.median(ex[1:]):.0f} ({ex[0]:.0f})")
            if any(row): print(f"   {sc:16s}" + "".join(f"{x:>22s}" for x in row))
