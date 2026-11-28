"""Measure four device reads on disposable migrated PG17; run with backend's Python, from repository root."""

import asyncio
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects import postgresql

ROOT = Path.cwd()
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))
from app.core.device_scope import scoped_devices
from app.schemas.patch_plans import DeviceScope
from app.core.tenancy import OPERATIONAL_TENANT_ID
from ledger import membership_ids, seed_ledger

TENANT = str(OPERATIONAL_TENANT_ID)
RULES = [
    {"field": "managed", "value": "true"},
    {"field": "supervised", "value": "true"},
    {"field": "site", "value": "North"},
]
SPAN = """ JOIN observation_spans s ON s.subject_kind='computer' AND s.is_current AND s.subject_id=d.external_id
             AND s.mdm_connection_id=d.mdm_connection_id """
MEMBERS = " LEFT JOIN observation_sections m ON m.section='group_memberships' AND m.digest=s.section_digests->>'group_memberships' "
QUERIES = {
    "built-in": "SELECT h.body->>'modelIdentifier',count(*) FROM scoped d"
    + SPAN
    + " JOIN observation_sections h ON h.section='hardware' AND h.digest=s.section_digests->>'hardware' GROUP BY 1",
    "ea": "SELECT v.value,count(*) FROM scoped d LEFT JOIN device_extension_attributes ea ON ea.device_id=d.id AND ea.definition_id='13' LEFT JOIN LATERAL jsonb_array_elements_text(ea.\"values\") v(value) ON true GROUP BY 1",
    "all-groups": """, counts AS (SELECT e.body->>'groupId' gid,count(*) n FROM scoped d """
    + SPAN
    + MEMBERS
    + """ CROSS JOIN LATERAL jsonb_array_elements_text(m.entry_digests) v(digest)
 JOIN observation_entries e ON e.kind='group_membership' AND e.digest=v.digest GROUP BY 1)
 SELECT gid,coalesce(n,0) FROM (SELECT DISTINCT body->>'groupId' gid FROM observation_entries WHERE kind='group_membership') known LEFT JOIN counts USING(gid)""",
    "one-group": """, target AS (SELECT array_agg(digest::text) ids FROM observation_entries WHERE kind='group_membership' AND body->>'groupId'='7')
 SELECT count(*) FILTER (WHERE m.entry_digests ?| target.ids),count(*) FILTER (WHERE NOT(m.entry_digests ?| target.ids)),
 count(*) FILTER (WHERE m.id IS NULL) FROM scoped d CROSS JOIN target LEFT JOIN observation_spans s ON s.subject_kind='computer' AND s.is_current
 AND s.subject_id=d.external_id AND s.mdm_connection_id=d.mdm_connection_id """
    + MEMBERS,
}


def sql_query(name, scoped):
    scope = DeviceScope.model_validate({"rules": RULES if scoped else []})
    selected = select(scoped_devices(scope, datetime(2026, 11, 28, tzinfo=UTC))).compile(
        dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
    )
    return f"WITH scoped AS ({selected}) " + QUERIES[name]


def check_result(n, scoped, label, result):
    from collections import Counter

    expected = Counter()
    members = Counter({str(g): 0 for g in range(1, 301)})
    membership = [0, 0, 0]
    for i in range(1, n + 1):
        if scoped and (i % 5 == 0 or i % 7 == 0 or i % 3 == 0):
            continue
        if label == "built-in":
            expected[f"FixtureModel{i % 24}"] += 1
        elif label == "ea":
            expected["" if i % 50 == 1 else f"value-{(i + 13) % 13}"] += 1
        elif i % 25 == 1:
            membership[2] += 1
        else:
            groups = membership_ids(i)
            members.update(map(str, groups))
            membership[0 if 7 in groups else 1] += 1
    if label == "one-group":
        assert result == ["|".join(map(str, membership))], (label, result, membership)
    else:
        tallies = {k: int(v) for k, v in (row.split("|") for row in result)}
        assert tallies == dict(members if label == "all-groups" else expected), label


def run(n):
    name = "li966-" + secrets.token_hex(5)
    pw = secrets.token_hex(20)
    app_pw = secrets.token_hex(20)
    env = dict(os.environ, POSTGRES_PASSWORD=pw)

    def docker(*args, **kwargs):
        return subprocess.run(["docker", *args], check=True, env=env, **kwargs)

    def sql(s, app=True, opts=()):
        role = "bench_app" if app else "postgres"
        db = "bench" if app else "postgres"
        return docker(
            "exec",
            "-i",
            name,
            "psql",
            "-XqAt",
            "-U",
            role,
            "-d",
            db,
            "-v",
            "ON_ERROR_STOP=1",
            *opts,
            input=s,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def ready():
        for _ in range(120):
            if (
                subprocess.run(
                    ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                    capture_output=True,
                ).returncode
                == 0
            ):
                return
            time.sleep(0.25)
        raise RuntimeError("PostgreSQL readiness timeout")

    docker(
        "run",
        "--rm",
        "-d",
        "--name",
        name,
        "--shm-size",
        "256m",
        "-p",
        "127.0.0.1::5432",
        "-e",
        "POSTGRES_PASSWORD",
        "postgres:17-alpine",
        stdout=subprocess.DEVNULL,
    )
    try:
        ready()
        port = docker("port", name, "5432/tcp", capture_output=True, text=True).stdout.strip().split(":")[-1]
        sql(
            f"CREATE ROLE bench_app LOGIN PASSWORD '{app_pw}' NOSUPERUSER NOBYPASSRLS;CREATE DATABASE bench OWNER bench_app;",
            False,
        )
        migration = dict(
            env,
            DATABASE_URL=f"postgresql+asyncpg://bench_app:{app_pw}@127.0.0.1:{port}/bench",
            PYTHONPATH=str(ROOT / "backend"),
            UPDATE_CHECK="false",
            ENCRYPTION_KEY=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        )
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=ROOT / "backend",
            env=migration,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        print("seeding", n, flush=True)
        sql((HERE / "seed.sql").read_text(), opts=("-v", f"n={n}", "-v", f"tenant={TENANT}"))
        asyncio.run(
            seed_ledger(
                n,
                OPERATIONAL_TENANT_ID,
                migration["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://"),
            )
        )
        sql("VACUUM (ANALYZE);")
        binding = f"SET looninspect.tenant_id='{TENANT}';"
        metadata = sql(
            binding
            + "SELECT json_build_object('postgres',version(),'shared_buffers',current_setting('shared_buffers'),'work_mem',current_setting('work_mem'),'devices',(SELECT count(*) FROM devices),'ea_rows',(SELECT count(*) FROM device_extension_attributes),'groups',(SELECT count(*) FROM observation_entries WHERE kind='group_membership'),'current_spans',(SELECT count(*) FROM observation_spans WHERE is_current),'sections',(SELECT count(*) FROM observation_sections),'group_sections',(SELECT count(*) FROM observation_sections WHERE section='group_memberships'),'can_bypass',(SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user));"
        )
        output = {"setup": json.loads(metadata), "cases": []}
        assert not output["setup"]["can_bypass"] and output["setup"]["ea_rows"] == 150 * n
        assert output["setup"]["groups"] == 300 and output["setup"]["current_spans"] == n
        for scoped in (False, True):
            for label in QUERIES:
                query = sql_query(label, scoped)
                docker("restart", name, stdout=subprocess.DEVNULL)
                ready()
                record = {"query": label, "scoped": scoped, "sql": query, "plans": []}
                for run_id in range(4):
                    record["plans"].append(
                        json.loads(sql(binding + "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query))[0]
                    )
                record["result"] = sql(binding + query).splitlines()
                check_result(n, scoped, label, record["result"])
                output["cases"].append(record)
                (HERE / f"results-{n}.json").write_text(json.dumps(output, separators=(",", ":")) + "\n")
                print(n, scoped, label, [p["Execution Time"] for p in record["plans"]], flush=True)
    finally:
        docker("stop", "-t", "2", name, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    for count in map(int, sys.argv[1:] or [5000, 40000]):
        run(count)
