"""Posture > Patch policy's data: LoonSec's patch-policy reference document as this organization reads it (#614).

Two routes. `GET /api/patch-policy/apps` reads the copy the container holds
(`app.core.patch_policy_feed`), the organization's data-sharing tier, and which of three timelines
can date each app's tracks: LoonSec's published dates, this instance's copy of Jamf's public patch
catalog, and this instance's copy of Fleet's history while the Fleet catalog flag is on
(`app.core.patch_policy_timelines`). `GET /api/patch-policy/walk` walks one track over one of them
(`app.core.patch_policy_views`). Neither reads a device, and nothing is asked of anyone: the
catalogs are the ones the instance already syncs.
"""

from __future__ import annotations

from typing import Literal, get_args

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import patch_policy_feed, patch_policy_views
from app.core.auth import require
from app.core.database import get_db
from app.core.patch_policy_walk import STOPS
from app.core.permissions import Permission
from app.schemas.patch_policy import (
    PatchPolicyAppOut,
    PatchPolicyAppsOut,
    PatchPolicyFeedOut,
    PatchPolicyRefusalOut,
    PatchPolicyWalkOut,
)

router = APIRouter(prefix="/api/patch-policy", tags=["patch-policy"])

Stop = Literal["1d", "7d", "14d", "30d", "60d", "never"]
assert set(get_args(Stop)) == set(STOPS)  # the query's words are the walk's stops


@router.get("/apps", response_model=PatchPolicyAppsOut, dependencies=[Depends(require(Permission.APP_READ))])
async def patch_policy_apps(db: AsyncSession = Depends(get_db)) -> PatchPolicyAppsOut:
    """The feed's state, with its sentence, and every app the held copy references.

    **The tier gate first.** An organization whose data-sharing tier is `off` reads `tier_off`
    and no document, even while the container holds one, because the document is received in
    exchange for sharing (docs/data-sharing.md, "The corpus channel"). Then: `never` before any
    copy arrived, the last attempt's failure when it failed (`not_published`,
    `algorithm_unknown`, `download_failed`, `invalid`, each still naming the copy that answers),
    `stale` for a copy dated (`asOf`) more than three days ago, whatever LoonSec's last build
    (`builtAt`) says, which names only the cause (`publisherRunning`, judged by this instance's
    clock), and `current`. Every state's sentence says what it means and what to check
    (docs/troubleshooting.md §32).

    `apps` is null, never empty, when no copy answers for this organization. Each app carries its
    tracks with the counts the document states, and `sources`: for `public`, `jamf` and `fleet`,
    whether a walk of it can be shown, each track's answer with the default two-year window it
    would cover, and otherwise the state word and sentence that say why not
    (docs/troubleshooting.md §33). Jamf and Fleet are read from this instance's own copies.
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
        built_at=view.built_at,
        publisher_running=view.publisher_running,
    )
    if view.document is None:
        return PatchPolicyAppsOut(feed=feed, apps=None)
    sources = await patch_policy_views.app_sources(db, view.document)
    apps = [
        PatchPolicyAppOut.model_validate({**app, "sources": sources[app["app"]]})
        for app in patch_policy_feed.app_summaries(view.document)
    ]
    return PatchPolicyAppsOut(feed=feed, apps=apps)


@router.get(
    "/walk",
    response_model=PatchPolicyWalkOut,
    responses={409: {"model": PatchPolicyRefusalOut, "description": "The walk is not shown; `detail` says why."}},
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def patch_policy_walk(
    db: AsyncSession = Depends(get_db),
    app: str = Query(min_length=1, max_length=128, description="The app's id in LoonSec's data, as `/apps` lists it."),
    track: str | None = Query(default=None, max_length=128, description="One of the app's tracks; its default when absent."),
    source: Literal["public", "jamf", "fleet"] = Query(default="public"),
    years: int = Query(
        default=2, ge=2, le=3, description="The window asked for, in years ending the day before the data's date."
    ),
    align: Literal["common"] | None = Query(
        default=None, description="`common` cuts the window to the days every source that can date the track covers."
    ),
    stop: Stop | None = Query(default=None, description="The stop whose day intervals each CVE row carries; none when absent."),
    page: int = Query(default=1, ge=1, le=10_000, description=f"The page of `cves`, {patch_policy_views.PAGE_SIZE} rows each."),
):
    """One app track walked day by day over one timeline, under every stop of the patch-policy
    slider, for a window of two or three years: what a Mac that installed each release that many
    days after it was dated would have run, and which CVEs it ran affected, from the first day
    each was detectable. A reference analysis: it reads no device, and its result is neither stored
    nor sent anywhere.

    `source` picks the dates releases install on: `public` (LoonSec's published release dates),
    `jamf` (this instance's copy of Jamf's public patch catalog) or `fleet` (this instance's copy of
    Fleet's history, while this organization's Fleet catalog flag is on). The walk is held to
    LoonSec's published totals for the app: a window whose own walk disagrees refuses every source
    of the app, and a window LoonSec published no totals for is shown as `check.state:
    unchecked_window` only when another window of the app matched.

    Memoised by the walk's `input_id`, so the slider and the toggle re-ask cheaply. The answer
    keeps every total and every stop's per-day series whole, pages `cves` (`cves_page`), and keeps
    each CVE's day intervals only under `stop`. Anything that cannot be walked is a 409 whose
    `detail` is the sentence that says why (docs/troubleshooting.md §33), with `reason`, `source`
    and `facts` beside it; the feed's own states (§32) come back the same way.
    """
    try:
        return await patch_policy_views.walk_view(
            db, app=app, track=track, source=source, years=years, align=align, stop=stop, page=page
        )
    except patch_policy_views.Refused as refused:
        body = PatchPolicyRefusalOut(detail=refused.sentence, reason=refused.reason, source=refused.source, facts=refused.facts)
        return JSONResponse(status_code=409, content=body.model_dump(mode="json"))
