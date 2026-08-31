"""Departments and buildings: the names behind the two ids a Jamf device carries.

A computer record names its department and its building by id — `departmentId: "7"` —
and Jamf keeps the names in two catalogs of their own. The device row stores the id,
because that is what the device actually says and because a name is a label an admin
can change without anything about the Mac changing (docs/jamf-observations.md §2.2).
The resolution happens here, and only here:

* **Write** — `record_org_units` caches the two catalogs per connection, once per sweep
  and once per catalog refresh. Tens of rows, two API reads.
* **Read** — `load_names` returns the whole tenant's lookup as one dict, joined in
  Python against a page of devices. `ids_for_name` runs the filter's direction of
  travel: a name the operator typed, back to the ids the device rows hold.

Cache, don't calculate — and cache the small thing. Resolving per device row would put
a join on the hot path of a 40,000-row table to answer a question about forty rows.

The ids are scoped to their connection: department 7 in one Jamf Pro instance has
nothing to do with department 7 in another, so every key here is
`(connection, kind, id)` and the filter matches the pair, never the id alone.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.schema import JamfOrgUnit

DEPARTMENT = "department"
BUILDING = "building"
KINDS = (DEPARTMENT, BUILDING)

# (mdm_connection_id, kind, external_id) -> name
OrgUnitNames = dict[tuple[int, str, str], str]


async def record_org_units(
    db: AsyncSession, *, connection_id: int, kind: str, units: list[dict]
) -> int:
    """Cache one catalog. Returns how many objects it held.

    Upsert, never replace: a rename lands on the existing row, and a catalog read that
    came back empty because the API client lost a privilege leaves the last known names
    standing rather than blanking every device's department. Objects deleted in Jamf
    keep a stale row whose `last_seen_at` stops moving — departure is #181's subject,
    and a label nobody references any more costs one row.
    """
    if not units:
        return 0

    now = datetime.now(timezone.utc)
    statement = pg_insert(JamfOrgUnit).values(
        [
            {
                "mdm_connection_id": connection_id,
                "kind": kind,
                "external_id": unit["id"],
                "name": unit.get("name") or "",
                "first_seen_at": now,
                "last_seen_at": now,
            }
            for unit in units
        ]
    )
    await db.execute(
        statement.on_conflict_do_update(
            constraint="uq_jamf_org_unit",
            set_={"name": statement.excluded.name, "last_seen_at": now},
        )
    )
    return len(units)


async def load_names(db: AsyncSession) -> OrgUnitNames:
    """The tenant's whole lookup, one query. Tens of rows per connection."""
    rows = await db.execute(
        select(JamfOrgUnit.mdm_connection_id, JamfOrgUnit.kind, JamfOrgUnit.external_id, JamfOrgUnit.name)
    )
    return {(connection_id, kind, external_id): name for connection_id, kind, external_id, name in rows}


def name_for(names: OrgUnitNames, *, connection_id: int | None, kind: str, external_id: str | None) -> str | None:
    """The name for one id, or None while the catalog has not been read since the id
    first appeared — a device webhooked in between sweeps, or an API client without the
    privilege. None rather than the bare id: the id is served in its own field, and a
    number in a column headed "Department" is not a department."""
    if connection_id is None or external_id is None:
        return None
    return names.get((connection_id, kind, external_id))


async def ids_for_name(db: AsyncSession, *, kind: str, name: str) -> list[tuple[int, str]]:
    """The `(connection, id)` pairs whose name is this one, case-insensitively.

    Case-insensitive because this is a filter box an operator types into by hand, and
    "engineering" meaning nothing while "Engineering" means something is a bug report
    waiting to happen.
    """
    rows = await db.execute(
        select(JamfOrgUnit.mdm_connection_id, JamfOrgUnit.external_id).where(
            JamfOrgUnit.kind == kind,
            func.lower(JamfOrgUnit.name) == name.strip().lower(),
        )
    )
    return [(connection_id, external_id) for connection_id, external_id in rows]
