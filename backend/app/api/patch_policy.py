"""Posture > Patch policy's data: LoonSec's patch-policy reference document as this organization reads it (#614).

One route today. It reads the copy the container holds (`app.core.patch_policy_feed`) and the
organization's data-sharing tier, and nothing else: no inventory, no catalog, and nothing is
asked of anyone. The walk over a timeline, and the Jamf and Fleet positions, are later slices.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import patch_policy_feed
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.schemas.patch_policy import PatchPolicyAppOut, PatchPolicyAppsOut, PatchPolicyFeedOut

router = APIRouter(prefix="/api/patch-policy", tags=["patch-policy"])


@router.get("/apps", response_model=PatchPolicyAppsOut, dependencies=[Depends(require(Permission.APP_READ))])
async def patch_policy_apps(db: AsyncSession = Depends(get_db)) -> PatchPolicyAppsOut:
    """The feed's state, with its sentence, and every app the held copy references.

    **The tier gate first.** An organization whose data-sharing tier is `off` reads `tier_off`
    and no document, even while the container holds one, because the document is received in
    exchange for sharing (docs/data-sharing.md, "The corpus channel"). Then: `never` before any
    copy arrived, the last attempt's failure when it failed (`not_published`,
    `algorithm_unknown`, `download_failed`, `invalid`, each still naming the copy that answers),
    `stale` for a copy more than three days old, and `current`. Every state's sentence says what
    it means and what to check (docs/troubleshooting.md §32).

    `apps` is null, never empty, when no copy answers for this organization. Each app carries its
    tracks with the counts the document states, and which sources can date its versions: the
    public timeline when the document holds one; the Jamf and Fleet positions answer
    `available: false` until they are built.
    """
    view = await patch_policy_feed.feed_view(db)
    feed = PatchPolicyFeedOut(
        state=view.state,
        sentence=view.sentence,
        algorithm=patch_policy_feed.ALGORITHM,
        doc_id=view.doc_id,
        as_of=view.as_of,
        fetched_at=view.fetched_at,
        coverage_since=view.coverage_since,
        until=view.until,
        attempted_at=view.attempted_at,
        source=view.source,
        outcome=view.outcome,
        host=view.host,
        http_status=view.http_status,
        detail=view.detail,
        from_file=view.from_file,
    )
    if view.document is None:
        return PatchPolicyAppsOut(feed=feed, apps=None)
    apps = [PatchPolicyAppOut.model_validate(app) for app in patch_policy_feed.app_summaries(view.document)]
    return PatchPolicyAppsOut(feed=feed, apps=apps)
