#!/usr/bin/env python3
"""Time queries with the spike's protocol: restart PostgreSQL per case, one cold run, three warm, then fetch the rows.

usage: measure.py <stage-label> <set>[,<set>...] [--guc "SET x=y;"] [--only name,name]
sets: spike (the 8 recorded statements), alt:<scope label>, renderer
Only the container verify1002-pg is restarted.
"""
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PG = "verify1002-pg"
Q = json.loads((HERE.parent / "work/harness/queries.json").read_text())
BINDING = f"SET looninspect.tenant_id='{Q['tenant']}';"


def psql(sql, timeout=1800):
    return subprocess.run(
        ["docker", "exec", "-i", PG, "psql", "-XqAt", "-U", "bench_app", "-d", "bench", "-v", "ON_ERROR_STOP=1"],
        input=sql, text=True, check=True, stdout=subprocess.PIPE, timeout=timeout,
    ).stdout.strip()


def ready():
    for _ in range(240):
        if subprocess.run(["docker", "exec", PG, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], capture_output=True).returncode == 0:
            return
        time.sleep(0.25)
    raise RuntimeError("PostgreSQL readiness timeout")


def restart():
    subprocess.run(["docker", "restart", PG], check=True, stdout=subprocess.DEVNULL)
    ready()


def walk(node):
    yield node
    for child in node.get("Plans", []):
        yield from walk(child)


def signature(plan):
    """How each ledger table was reached, and whether workers ran."""
    bits = []
    for node in walk(plan):
        rel = node.get("Relation Name")
        if rel in {"observation_spans", "observation_sections", "observation_entries", "device_extension_attributes", "devices", "subject_departures"}:
            how = node["Node Type"].replace(" Scan", "")
            if node.get("Index Name"):
                how += f"({node['Index Name']})"
            bits.append(f"{rel.replace('observation_', 'o_').replace('device_extension_attributes', 'dea')}:{how}x{node.get('Actual Loops')}")
    workers = max((n.get("Workers Launched", 0) for n in walk(plan)), default=0)
    return f"workers={workers} " + " ".join(bits)


def main():
    stage, sets = sys.argv[1], sys.argv[2].split(",")
    guc = ""
    only = None
    if "--guc" in sys.argv:
        guc = sys.argv[sys.argv.index("--guc") + 1]
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))
    cases = []
    for s in sets:
        if s == "spike":
            for scoped in (0, 1):
                for name in ("built-in", "ea", "all-groups", "one-group"):
                    cases.append((name, "three-column" if scoped else "whole-fleet", Q["spike"][f"{name}|{scoped}"]))
        elif s == "spike-scoped":
            for name in ("built-in", "ea", "all-groups", "one-group"):
                cases.append((name, "three-column", Q["spike"][f"{name}|1"]))
        elif s.startswith("alt:"):
            label = s[4:]
            for name in ("built-in", "ea", "all-groups", "one-group"):
                cases.append((name, label, Q["alt"][f"{name}|{label}"]))
        elif s.startswith("altfix:"):
            label = s[7:]
            for name in ("built-in", "ea", "all-groups", "one-group"):
                cases.append((name, label + "+plain-is_current", Q["altfix"][f"{name}|{label}"]))
        elif s == "renderer":
            for name in ("built-in", "ea", "all-groups", "one-group"):
                cases.append((name, "three-column-myrenderer", Q["renderer_check"][name]))
    if only:
        cases = [c for c in cases if c[0] in only]
    out_path = HERE / f"results-{stage}.json"
    output = json.loads(out_path.read_text()) if out_path.exists() else {"stage": stage, "cases": []}
    output["setup"] = json.loads(psql(BINDING + """SELECT json_build_object(
      'devices',(SELECT count(*) FROM devices),'ea_rows',(SELECT count(*) FROM device_extension_attributes),
      'entries',(SELECT count(*) FROM observation_entries),'spans',(SELECT count(*) FROM observation_spans),
      'current_computer_spans',(SELECT count(*) FROM observation_spans WHERE is_current AND subject_kind='computer'),
      'closed_computer_spans',(SELECT count(*) FROM observation_spans WHERE NOT is_current AND subject_kind='computer'),
      'sections',(SELECT count(*) FROM observation_sections),
      'hardware_sections',(SELECT count(*) FROM observation_sections WHERE section='hardware'),
      'group_sections',(SELECT count(*) FROM observation_sections WHERE section='group_memberships'),
      'departure_rows',(SELECT count(*) FROM subject_departures),
      'spans_heap',pg_size_pretty(pg_relation_size('observation_spans')),'spans_total',pg_size_pretty(pg_total_relation_size('observation_spans')),
      'sections_heap',pg_size_pretty(pg_relation_size('observation_sections')),'sections_total',pg_size_pretty(pg_total_relation_size('observation_sections')),
      'entries_heap',pg_size_pretty(pg_relation_size('observation_entries')),
      'ea_heap',pg_size_pretty(pg_relation_size('device_extension_attributes')),'db',pg_size_pretty(pg_database_size(current_database())),
      'shared_buffers',current_setting('shared_buffers'),'work_mem',current_setting('work_mem'),
      'max_parallel_workers_per_gather',current_setting('max_parallel_workers_per_gather'))"""))
    print("setup", json.dumps(output["setup"]), flush=True)
    for name, scope, sql in cases:
        restart()
        plans = [json.loads(psql(BINDING + guc + "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql))[0] for _ in range(4)]
        result = psql(BINDING + guc + sql).splitlines()
        ex = [p["Execution Time"] for p in plans]
        warm = statistics.median(ex[1:])
        mid = 1 + sorted(range(3), key=lambda i: ex[1 + i])[1]
        root = plans[mid]["Plan"]
        record = {"query": name, "scope": scope, "guc": guc, "sql": sql, "plans": plans, "result": result}
        output["cases"] = [c for c in output["cases"] if not (c["query"] == name and c["scope"] == scope and c.get("guc", "") == guc)] + [record]
        out_path.write_text(json.dumps(output, separators=(",", ":")) + "\n")
        print(
            f"{stage:14s} {name:10s} {scope:22s} cold={ex[0]:9.1f} warm={warm:9.1f} (warm runs {ex[1]:.1f} {ex[2]:.1f} {ex[3]:.1f}) "
            f"plan_ms={statistics.median(p['Planning Time'] for p in plans):.1f} rows={len(result)} "
            f"buf hit={root.get('Shared Hit Blocks')} read={root.get('Shared Read Blocks')} tread={root.get('Temp Read Blocks')} twrite={root.get('Temp Written Blocks')}\n"
            f"      {signature(root)}",
            flush=True,
        )


if __name__ == "__main__":
    main()
