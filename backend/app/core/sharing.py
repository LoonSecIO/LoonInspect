"""Snapshot assembly for community data sharing (docs/data-sharing.md).

Builds the exact request body the v1 exchange sends — which is also what the
Settings page's "show exactly what would be sent now" button renders. One code
path for both is the point: the preview cannot drift from the wire.

The exchange job itself (scheduling, transport, the share log) is INSPECT-0048;
until it lands this module has exactly one caller, the preview endpoint.
"""

from __future__ import annotations

from fnmatch import fnmatch

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.content_keys import os_key
from app.core.version import get_app_version
from app.models.schema import DataSharingSettings, Device, InstalledApp

CONTRACT_VERSION = "v1"


async def get_or_create_settings(db: AsyncSession) -> DataSharingSettings:
    """The tenant's consent row, created with the defaults on first access.

    Lazy creation mirrors FeatureFlag: an absent row and the defaults are the same
    state, and materializing it on first touch gives the submission UUID a single
    stable birth rather than a special case in every reader.
    """
    row = (await db.execute(select(DataSharingSettings))).scalar_one_or_none()
    if row is None:
        row = DataSharingSettings()
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


def _excluded(bundle_id: str, globs: list[str]) -> bool:
    return any(fnmatch(bundle_id, pattern) for pattern in globs)


async def build_exchange_request(db: AsyncSession, settings_row: DataSharingSettings) -> dict:
    """The v1 exchange request body, aggregated in SQL: distinct tuples with counts,
    never per-device rows. `reveals` is always empty here — answers to reveal
    requests are assembled by the exchange job (INSPECT-0048), because they depend
    on the previous response, which a preview does not have."""
    globs = list(settings_row.exclude_globs or [])

    app_rows = (
        await db.execute(
            select(
                InstalledApp.key_title,
                InstalledApp.key_full,
                func.max(InstalledApp.bundle_id).label("bundle_id"),
                func.count(distinct(InstalledApp.device_id)).label("count"),
            ).group_by(InstalledApp.key_title, InstalledApp.key_full)
        )
    ).all()

    apps = [
        {"title": row.key_title, "full": row.key_full, "count": row.count}
        for row in app_rows
        if not _excluded(row.bundle_id, globs)
    ]

    # Devices carry os_version today but no build, model, or arch — those columns
    # don't exist yet. The os key hashes what we have (missing fields are the empty
    # string, per the canonicalization contract) and hardware stays an empty list
    # until the inventory grows the fields; the contract's shape doesn't change.
    os_rows = (
        await db.execute(
            select(Device.os_version, func.count(Device.id).label("count"))
            .where(Device.os_version.is_not(None))
            .group_by(Device.os_version)
        )
    ).all()
    os_tuples = [
        {"key": os_key("macos", row.os_version, None), "count": row.count} for row in os_rows
    ]

    return {
        "contract": CONTRACT_VERSION,
        "submission": str(settings_row.submission_uuid),
        "tier": settings_row.tier,
        "build": get_app_version(),
        "snapshot": {"apps": apps, "os": os_tuples, "hardware": []},
        "reveals": [],
    }
