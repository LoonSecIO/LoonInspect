"""Rotating ENCRYPTION_KEY (#144): the rewrite that moves every stored value to the new key.

A rotation is two environment variables and a restart. `ENCRYPTION_KEY` becomes the new key and
`ENCRYPTION_KEY_PREVIOUS` the one the database was written under; from then on every stored value
opens under either (`app.core.crypto`), and this runs at each start to rewrite, under the new key,
every value still carrying the old one. When it reports none left, the operator removes
`ENCRYPTION_KEY_PREVIOUS` and the old key is out of the system. The key id in the envelope stays
`k1` across a rotation on purpose: an older image that knows one key reads a rewritten row under
the new key as it would any other, so the one-step-back rollback (operations.md §5) still holds
once the rewrite has finished — which is why the log line says to finish it first.

Every column of the type is found from the models, not from a list kept here: a column added
later is rotated the day it exists. Values are read and written as the raw text in the column,
never through the type decorator, so a value under the old key is opened once with the right key
and written once with the new one, and a value under neither is counted and named by its
column, never printed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import Column, Table, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import (
    EncryptedString,
    StoredValueUnknownKeyId,
    StoredValueUnreadable,
    encrypt_value,
    open_stored,
)
from app.core.database import Base, unscoped_session
from app.core.tenant_jobs import tenant_job
from app.models.schema import Tenant


@dataclass
class RekeySummary:
    """What one pass over every tenant found and did."""

    rewritten: int = 0  # opened under the previous key, written again under the current one
    current: int = 0  # already under the current key; left as they were
    unreadable: int = 0  # under neither key: written under a third key, or not a token at all
    unreadable_in: list[str] = field(default_factory=list)  # `table.column` for each of those, once

    @property
    def complete(self) -> bool:
        return self.unreadable == 0


def encrypted_columns() -> list[tuple[Table, Column]]:
    """Every column stored through `EncryptedString`, from the models themselves."""
    found: list[tuple[Table, Column]] = []
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if isinstance(column.type, EncryptedString):
                found.append((table, column))
    return found


def _quoted(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


async def rekey_session(db: AsyncSession, summary: RekeySummary) -> None:
    """Rewrite, in the rows this session can see, every stored value not under the current key."""
    for table, column in encrypted_columns():
        keys = [c.name for c in table.primary_key.columns]
        if not keys:
            continue
        key_list = ", ".join(_quoted(k) for k in keys)
        held = _quoted(column.name)
        rows = await db.execute(text(f"SELECT {key_list}, {held} AS stored FROM {_quoted(table.name)} WHERE {held} IS NOT NULL"))
        where = " AND ".join(f"{_quoted(k)} = :{k}" for k in keys)
        rewrite = text(f"UPDATE {_quoted(table.name)} SET {_quoted(column.name)} = :value WHERE {where}")
        for row in rows.mappings():
            try:
                plaintext, opened_with = open_stored(row["stored"])
            except (StoredValueUnknownKeyId, StoredValueUnreadable):
                summary.unreadable += 1
                place = f"{table.name}.{column.name}"
                if place not in summary.unreadable_in:
                    summary.unreadable_in.append(place)
                continue
            if opened_with == "current":
                summary.current += 1
                continue
            await db.execute(rewrite, {"value": encrypt_value(plaintext), **{k: row[k] for k in keys}})
            summary.rewritten += 1
        await db.commit()


async def rekey_stored_values() -> RekeySummary:
    """One pass over every tenant, each in a session scoped to it, since every table holding an
    encrypted column is tenant-scoped by row-level security and a job sees one tenant at a time."""
    async with unscoped_session() as db:
        tenant_ids: list[uuid.UUID] = list((await db.execute(select(Tenant.id).order_by(Tenant.slug))).scalars().all())
    summary = RekeySummary()
    for tenant_id in tenant_ids:
        async with tenant_job(tenant_id) as db:
            await rekey_session(db, summary)
    return summary
