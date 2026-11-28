"""Emit the spike's exact SQL (from its own bench.py) plus alternate-scope variants. Runs in the runner container, cwd=/work."""
import json, sys
from datetime import UTC, datetime
from pathlib import Path
sys.path.insert(0, "/work/docs/spikes/attribute-breakdown-at-40k")
sys.path.insert(0, "/work/backend")
import bench  # the spike's module, unmodified; importing does not run it
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from app.core.device_scope import scoped_devices
from app.schemas.patch_plans import DeviceScope

def lit(v):
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, datetime):
        return "'" + v.isoformat() + "'::timestamptz"
    if isinstance(v, (list, dict)):
        return "'" + json.dumps(v).replace("'", "''") + "'::jsonb"
    return "'" + str(v).replace("'", "''") + "'"


def scope_sql(rules, match="all"):
    """Same statement the spike compiles, with binds rendered by hand: SQLAlchemy's literal_binds
    cannot render the JSONB literal an `ea` rule compares against, so the spike's own renderer fails on it."""
    scope = DeviceScope.model_validate({"rules": rules, "match": match})
    compiled = select(scoped_devices(scope, datetime(2026, 11, 28, tzinfo=UTC))).compile(dialect=postgresql.dialect())
    return str(compiled) % {k: lit(v) for k, v in compiled.params.items()}


def with_rules(name, rules, match="all"):
    return f"WITH scoped AS ({scope_sql(rules, match)}) " + bench.QUERIES[name]


ALT = {
    # three rules, AND: one group rule, one EA rule, one column rule
    "grp_ea_site": [{"field": "group", "key": "1", "value": "5"}, {"field": "ea", "key": "13", "operator": "is_not", "value": "value-3"}, {"field": "site", "value": "North"}],
    # three rules, AND: group membership only on one, the others columns
    "grp_managed_site": [{"field": "group", "key": "1", "value": "5"}, {"field": "managed", "value": "true"}, {"field": "site", "value": "North"}],
    # three rules, AND: a negative group rule
    "notgrp_managed_site": [{"field": "group", "key": "1", "operator": "is_not", "value": "7"}, {"field": "managed", "value": "true"}, {"field": "site", "value": "North"}],
}
out = {"tenant": bench.TENANT, "spike": {}, "alt": {}}
for scoped in (False, True):
    for name in bench.QUERIES:
        out["spike"][f"{name}|{int(scoped)}"] = bench.sql_query(name, scoped)
for label, rules in ALT.items():
    for name in bench.QUERIES:
        out["alt"][f"{name}|{label}"] = with_rules(name, rules)
out["scope_only"] = {label: "WITH scoped AS (" + scope_sql(rules) + ") SELECT count(*) FROM scoped" for label, rules in ALT.items()}
# my renderer applied to the spike's own three-rule scope, to prove the renderer equivalent
out["renderer_check"] = {name: with_rules(name, bench.RULES) for name in bench.QUERIES}
Path("/work/harness/queries.json").write_text(json.dumps(out, indent=1))
print("tenant", bench.TENANT, "queries", len(out["spike"]), len(out["alt"]))
