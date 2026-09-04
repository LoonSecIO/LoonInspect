"""The alerts machinery and its first kind — the NEW-app latch (#101, docs/alerts.md).

Kyle ruled the shape of this on 2026-09-04: **the latch closes itself.** A row is open
while the app is present on the device and was absent from that device's previous
inventory, and it closes the moment the app is gone. No dismiss button, no
`acknowledged_at`, no audit action, no human state — #101 rules out a dedicated alerts
page in v0, so a manual acknowledge would have nowhere to be clicked and would
accumulate forever. That is why `alerts.open` may be read as "true of the fleet right
now" rather than "not yet dealt with".

Three properties fall out of *how* the delta is computed rather than from a gate that
has to be maintained:

* **The baseline primes silently.** A device with no previous inventory of applications
  opens nothing, so the first sweep of a 40k fleet writes zero rows instead of a latch
  per app per device. The guard is the device's own state, deliberately not
  `Run.comparison`: runs are purged at 30 days and `comparison` partitions by lock
  class, so a webhook run's first pass on a connection that has swept for a year still
  reports `full` — the 2026-08-29 verify pass found exactly that.
* **A version bump is silent.** The identity key is `app_hash` (md5(name:bundle_id)),
  never `version_hash`. `process_sync`'s existing `previous_hashes` map is keyed by
  version, and reusing it here would make every update a NEW-app alert — the loudest
  possible violation of the silent-new-version ruling.
* **A quiet pull costs nothing.** Nothing is written when no app arrived and *nothing is
  queried* when no app left, so the latch adds zero round-trips per device to a sweep
  designed to move 40k devices in ten minutes (cache, don't calculate).

The kind vocabulary is CLOSED. A later kind is an entry in `KINDS`, an entry in
`KIND_LEVELS`, and a row in docs/alerts.md — never a reshape of this module or the
table. `tests/test_alerts.py` holds the doc and the tuple to each other in both
directions.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.changes.policy import HIGH
from app.models.schema import Alert, InstalledApp

logger = logging.getLogger(__name__)

# --- The closed vocabulary -------------------------------------------------------------

# An app the device did not have at its previous inventory. Founder-ruled 2026-08-29:
# previous-inventory semantics, keyed on the app field, silent new version, level high.
NEW_APP = "new_app"

KINDS: tuple[str, ...] = (NEW_APP,)

# `level`, reusing `app.changes.policy.LEVELS` — never a minted `severity` (#229). The
# product already has one word for how much a thing matters, and a second vocabulary
# would have to be mapped onto the first forever.
KIND_LEVELS: dict[str, str] = {NEW_APP: HIGH}


# --- The pure half ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LatchDelta:
    """What one device's app read means for its latches. Both sets are `app_hash`es."""

    to_open: frozenset[str]
    departed: frozenset[str]


def latch_delta(
    previous_app_hashes: Iterable[str],
    current_app_hashes: Iterable[str],
    *,
    device_is_new: bool,
) -> LatchDelta:
    """The NEW-app latch's whole decision, with no session in sight.

    `previous_app_hashes` is the device's inventory as the last read left it;
    `current_app_hashes` is what this read found. Both are app identities, not builds.

    Two ways a pass is a **priming** pass, and both open nothing:

    * `device_is_new` — the `Device` row did not exist before this pass. Captured by the
      caller *before* the row is created, because after the insert there is no way to
      ask the question.
    * an empty `previous_app_hashes` — the row existed but has never had an application
      read against it. This happens for real: a device first seen through a collection
      whose aperture excludes `applications` (or through a narrowly-scoped webhook)
      has a row and no app rows, and without this half its first full sweep would open
      one latch per installed app. The cost of the conservative reading is a single
      missed alert on the vanishing case of a Mac that genuinely reported zero
      applications and then installed one — a silence, never a flood.

    `departed` is computed on every pass, priming included, and is empty there by
    construction. It is what the caller closes on, and the caller must not query
    anything when it is empty.
    """
    previous = frozenset(previous_app_hashes)
    current = frozenset(current_app_hashes)
    # There is no previous inventory to be absent from, so nothing here is *new* — it is
    # simply the first thing we know about this device.
    priming = device_is_new or not previous
    return LatchDelta(
        to_open=frozenset() if priming else current - previous,
        departed=previous - current,
    )


# --- The database half ------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def sync_new_app_latches(
    db: AsyncSession,
    *,
    device_id: int,
    previous_app_hashes: Iterable[str],
    current_rows: Sequence[InstalledApp],
    device_is_new: bool,
    run_id: uuid.UUID | None,
) -> LatchDelta:
    """Open and close this device's `new_app` latches for the read that just landed.

    Called from `process_sync` immediately after `record_device_apps`, inside the
    caller's transaction: the latch rows commit with the ledger rows, the device state
    and both events, so "the app is on the device" and "we opened an alert about it" can
    never drift apart from a partial failure. Returns the delta it acted on, for the
    caller's logs and for tests.

    Never called when `device.apps is None` — a section outside the read's aperture
    observed no applications, so it can neither open nor close a latch. That is the same
    guard `record_device_apps` sits behind, and it is the caller's to apply.
    """
    # First row wins per identity: two builds of one app on one device (two paths) are
    # one app, and the latch is keyed on the app.
    current_by_hash: dict[str, InstalledApp] = {}
    for row in current_rows:
        if row.app_hash and row.app_hash not in current_by_hash:
            current_by_hash[row.app_hash] = row

    delta = latch_delta(previous_app_hashes, current_by_hash.keys(), device_is_new=device_is_new)
    now = _utcnow()

    if delta.to_open:
        # Core insert with ON CONFLICT DO NOTHING against `uq_alerts_open`, deliberately
        # not `db.add()`. Webhook runs never take the sweep lock, so two ingests of one
        # device can be in flight at once; an ORM add would silently bypass the partial
        # unique index and raise on flush instead of losing the race quietly. `tenant_id`
        # is omitted so the column default reads the transaction's GUC — the same rule
        # every other table follows.
        await db.execute(
            pg_insert(Alert.__table__)
            .values(
                [
                    {
                        "kind": NEW_APP,
                        "level": KIND_LEVELS[NEW_APP],
                        "device_id": device_id,
                        "app_hash": app_hash,
                        "app_name": current_by_hash[app_hash].name,
                        "bundle_id": current_by_hash[app_hash].bundle_id,
                        "opened_at": now,
                        "opened_run_id": run_id,
                    }
                    for app_hash in sorted(delta.to_open)
                ]
            )
            .on_conflict_do_nothing(
                index_elements=["tenant_id", "kind", "device_id", "app_hash"],
                index_where=Alert.__table__.c.closed_at.is_(None),
            )
        )

    if delta.departed:
        # One UPDATE, not a SELECT and then an UPDATE: the rows are found by the same
        # index the open path conflicts on, and the caller never needs to see them. Rows
        # are stamped closed and kept — deleting here would silently redefine
        # `alerts.opened_24h` as "…that are still open" (docs/posture-snapshot.md).
        await db.execute(
            sa_update(Alert)
            .where(
                Alert.device_id == device_id,
                Alert.kind == NEW_APP,
                Alert.closed_at.is_(None),
                Alert.app_hash.in_(delta.departed),
            )
            .values(closed_at=now, closed_run_id=run_id)
        )

    return delta


async def purge_closed_alerts(db: AsyncSession, retention_days: int) -> int:
    """Drop closed latches past retention. Commits; returns rows deleted.

    Closed rows cannot be deleted at close — `alerts.opened_24h` is frozen as "alerts
    opened in the trailing 24h", and a delete-on-close would quietly turn it into "…that
    are still open", which is a different number with the same name. So they age out
    here instead, on `run_retention_days` (30) rather than a setting of their own: a
    closed alert is run history in the same sense a finished run is, and one more knob
    on the pod is a knob an operator has to have an opinion about.
    """
    cutoff = _utcnow() - timedelta(days=retention_days)
    result = await db.execute(sa_delete(Alert).where(Alert.closed_at.is_not(None), Alert.closed_at < cutoff))
    await db.commit()
    return result.rowcount or 0
