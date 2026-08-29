"""The AI gate (INSPECT-0112): the socket every future AI feature plugs into.

No AI feature exists yet — this module ships before any does, so that the first one
arrives into plumbing that already refuses correctly. Two independent switches, both
default OFF:

- the master feature flag (``ai_features``, app.core.feature_flags): turns the AI
  feature area on at all;
- the AI-inference consent (``ai_inference`` on the data-sharing settings row): the
  same consent surface as community data sharing, governing whether any byte may
  leave the pod for inference.

The flag without consent still permits on-device work; consent without the flag
permits nothing. Every permitted off-pod call writes one row to the share log —
the same log the community exchange writes — carrying the feature name, the
destination, and the field-level disclosure of what left. Field names only, never
payload contents: the log answers "what kind of thing left, and where to", and the
row is committed before the first byte moves, so a crash mid-call can lose the
answer but never the question.

Standing doctrine for every implementer who calls this gate (founder-ruled; the
v-never list restated):

- **No model-sourced numbers anywhere.** Counts, versions, CVE data, dates — every
  number in the product comes from a real data path. A model may explain numbers;
  it may never be the source of one.
- **Fleet-identifying payloads run BYO-key or on-device only, never a hosted
  default.** Run logs, hostnames, serials — and typed search strings are ruled
  fleet data. If it can identify a fleet, it does not go to a vendor endpoint the
  product configured on its own.
- **Everything defaults off.** The flag, the consent, and any feature behind them.
  Enabling an AI feature must show field-level disclosure of exactly what leaves
  the pod and to where.
- **No silent egress.** If the gate did not log it, the call was not permitted to
  happen. Call ``require_ai`` before the request is made, not after.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.feature_flags import AI_FEATURES_FLAG
from app.core.sharing import get_or_create_settings
from app.models.schema import FeatureFlag, ShareLog

# The tier value AI rows carry in the share log. Community-exchange rows carry the
# sharing tier (off | keys | reveal); "ai" marks the other consent lane, and is what
# the exchange's due-ness and last-exchange readers filter out (app.core.sharing,
# app.api.system).
AI_SHARE_TIER = "ai"

_LOG_RETENTION = timedelta(days=90)


class AIRefused(Exception):
    """The gate said no. Callers treat this as "the feature is not available",
    never as an error to retry: the operator's switches are the reason."""


class AIFeaturesDisabled(AIRefused):
    """The master flag is off — no AI feature may run at all."""


class AIConsentMissing(AIRefused):
    """The flag is on but AI-inference consent is not granted — nothing may leave
    the pod, though on-device work may proceed."""


async def ai_features_enabled(db: AsyncSession) -> bool:
    """The master flag, read the way the flags API reads it: an absent row and
    False are the same state."""
    flag = (
        await db.execute(select(FeatureFlag).where(FeatureFlag.key == AI_FEATURES_FLAG))
    ).scalar_one_or_none()
    return flag is not None and flag.enabled


async def require_ai(
    db: AsyncSession,
    *,
    feature: str,
    destination: str | None = None,
    fields: Sequence[str] = (),
) -> None:
    """The one call every AI feature makes before doing anything.

    ``destination=None`` declares on-pod/no-egress work: only the master flag is
    checked, and nothing is logged because nothing leaves. A destination declares
    an off-pod inference call: the flag AND the consent must both be on, ``fields``
    must name every field that will leave (an off-pod call disclosing nothing is a
    programming error, not a consent question), and one share-log row is committed
    — feature, destination, field names — before this returns. Make the network
    call after, never before.
    """
    if not await ai_features_enabled(db):
        raise AIFeaturesDisabled(f"AI features are off; {feature} may not run")

    if destination is None:
        return

    if not fields:
        raise ValueError(
            f"off-pod inference for {feature} must disclose the fields it sends"
        )

    settings_row = await get_or_create_settings(db)
    if not settings_row.ai_inference:
        raise AIConsentMissing(
            f"AI-inference consent is off; {feature} may not send bytes to {destination}"
        )

    now = datetime.now(timezone.utc)
    db.add(
        ShareLog(
            occurred_at=now,
            tier=AI_SHARE_TIER,
            endpoint=destination,
            outcome="sent",
            # Field names and destination only, never payload contents: the log's
            # job is disclosure, and contents would make it a second copy of the
            # very data whose leaving it records.
            payload={"feature": feature, "fields": sorted(set(fields))},
        )
    )
    # The same 90-day retention the exchange enforces, applied here too so a tenant
    # with community sharing off but AI on still keeps the log's pruning promise.
    await db.execute(delete(ShareLog).where(ShareLog.occurred_at < now - _LOG_RETENTION))
    await db.commit()
