"""The nightly tape has a reader (#470, docs/posture-snapshot.md "The reader").

**Absent is not zero**, so the response is the table's own grain — one row per metric per capture
per population — and a key that recorded nothing has no row and no cell for a client to fill.
**Every read names one population**, and **the registry is the key list**, never a copy."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.posture import ACTIVE_KEYS, CAPTURE_PLATFORM, KEY_DEFINITIONS, PLATFORM_ROLLUP, PLATFORMS, RESERVED_KEYS
from app.models.schema import PostureSnapshot
from app.schemas.posture import PostureKeyOut, PostureListResponse, PostureRegistryOut, PostureRowOut

router = APIRouter(prefix="/api/posture", tags=["posture"])

# The sentence a reader needs before drawing anything, served with the keys.
ABSENCE = (
    "A key with no row for a capture did not apply that night and is never zero: `outbox.oldest_pending_age_s` writes no row "
    "when nothing was pending, and the four `vuln.*` keys write none at all until the corpus has judged this tenant."
)
REGISTRY = "GET /api/posture/registry lists every key this tape carries"
# A key the recorder writes that nothing here defines: the drift test refuses it in CI, and a
# reader who meets one anyway is sent to the document rather than handed a 500 with no words.
UNDEFINED = "No definition: this registry has drifted from docs/posture-snapshot.md, which holds them — please report it."
NO_ROLLUP = f"{PLATFORM_ROLLUP} is the reserved cross-platform roll-up and nothing writes it: ask for one population"
RESERVED = "{key} is reserved: its definition is ruled and nothing writes it yet, so the tape has no rows for it"


def _population(platform: str) -> str:
    """The population to read, refused by name — an empty page would read as "never captured".
    `all` above all: ruled, written by nothing, so it could only ever answer that page, and being
    the English word for the fold this design forbids, the reader likeliest to type it is the
    likeliest to believe it. Its own sentence, and no other refusal offers it as a thing to try."""
    if platform == PLATFORM_ROLLUP:
        raise HTTPException(status_code=422, detail=NO_ROLLUP)
    if platform not in PLATFORMS:
        raise HTTPException(status_code=422, detail=f"platform must be one of {', '.join(PLATFORMS)}")
    return platform


def _wanted(raw: str | None) -> list[str]:
    """The `keys` filter, narrowed to the registry and refused by name: an empty page would read
    as "that number was never captured". Omitted is every key; sent with no key in it is a typo."""
    if raw is None:
        return []
    wanted = [key.strip() for key in raw.split(",") if key.strip()]
    if not wanted:
        raise HTTPException(status_code=422, detail=f"keys was sent with no key in it; omit it for every key. {REGISTRY}")
    for key in wanted:
        if key in RESERVED_KEYS:
            raise HTTPException(status_code=422, detail=RESERVED.format(key=key))
        if key not in ACTIVE_KEYS:
            raise HTTPException(status_code=422, detail=f"unknown posture key {key}; {REGISTRY}")
    return wanted


@router.get("", response_model=PostureListResponse, dependencies=[Depends(require(Permission.AUDIT_READ))])
async def list_posture(
    keys: str | None = Query(default=None, description="Comma-separated registry keys; every key the capture wrote when omitted"),
    platform: str = Query(default=CAPTURE_PLATFORM, description="The population to read; never collapsed across two"),
    days: int | None = Query(default=None, ge=1, le=400, description="Trailing window in days, instead of since"),
    since: datetime | None = Query(default=None, description="Captures at or after this instant, instead of days; naive is UTC"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
    db: AsyncSession = Depends(get_db),
) -> PostureListResponse:
    """The tape, newest capture first: one row is one metric, one capture, one population.

    **The default capture is chosen by the tape and never by `keys`** — the newest `captured_at`
    for the population, then the key filter over its rows; picking the newest capture that
    *carries* the key would report an empty queue as yesterday's pending age. The rest is
    docs/posture-snapshot.md, "The reader"."""
    platform = _population(platform)
    if days is not None and since is not None:
        raise HTTPException(status_code=422, detail="ask for a window with days, or with since, never both")

    conditions = [PostureSnapshot.platform == platform]
    if wanted := _wanted(keys):
        conditions.append(PostureSnapshot.metric_key.in_(wanted))
    if days is not None:
        since = datetime.now(UTC) - timedelta(days=days)
    if since is not None:
        # A bound sent without an offset is UTC: `captured_at` is timezone-aware, and comparing
        # it against a naive datetime raises inside the driver instead of answering.
        conditions.append(PostureSnapshot.captured_at >= (since if since.tzinfo else since.replace(tzinfo=UTC)))
    else:
        # Deliberately not key-filtered: this is "the last capture", full stop. A tenant with no
        # capture yet has no maximum, the comparison is never true, and the page is honestly empty.
        latest = select(func.max(PostureSnapshot.captured_at)).where(PostureSnapshot.platform == platform).scalar_subquery()
        conditions.append(PostureSnapshot.captured_at == latest)

    total = (await db.execute(select(func.count()).select_from(PostureSnapshot).where(*conditions))).scalar_one()
    page_of = (
        select(PostureSnapshot)
        .where(*conditions)
        .order_by(PostureSnapshot.captured_at.desc(), PostureSnapshot.metric_key.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return PostureListResponse(
        items=[
            PostureRowOut(
                key=row.metric_key,
                # NUMERIC out of Postgres is a Decimal; these values are counts and seconds.
                value=float(row.value),
                captured_at=row.captured_at,
                platform=row.platform,
                full_sweep_run_id=str(row.full_sweep_run_id) if row.full_sweep_run_id else None,
            )
            for row in (await db.execute(page_of)).scalars().all()
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/registry", response_model=PostureRegistryOut, dependencies=[Depends(require(Permission.AUDIT_READ))])
async def posture_registry() -> PostureRegistryOut:
    """Every key the tape can carry and what it means, so a value can be read without
    docs/posture-snapshot.md and a gap can be read as the statement it is (`absence`). Grows with
    `ACTIVE_KEYS`; a reserved name is listed and is not readable, its tape not started."""
    return PostureRegistryOut(
        keys=[PostureKeyOut(key=key, status="active", definition=KEY_DEFINITIONS.get(key, UNDEFINED)) for key in ACTIVE_KEYS]
        + [PostureKeyOut(key=key, status="reserved", definition=KEY_DEFINITIONS.get(key, UNDEFINED)) for key in RESERVED_KEYS],
        absence=ABSENCE,
        capture_platform=CAPTURE_PLATFORM,
    )
