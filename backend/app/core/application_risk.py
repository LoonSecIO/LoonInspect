"""Scoped application counts from stored, current-epoch answers; never capped CVE IDs."""

from sqlalchemy import BigInteger, and_, case, cast, distinct, func, literal, or_, select

from app.core.device_scope import scoped_devices
from app.core.vuln_answer import served
from app.models.schema import InstalledApp
from app.schemas.applications import ApplicationRisk, ApplicationScope
from app.schemas.payload import VULN_SEVERITY_BANDS

BANDS = VULN_SEVERITY_BANDS
COUNTS = ("total", "kev", *BANDS)


def _count(band):
    # A restored/hand-edited answer must not turn one malformed number into a failed
    # list. Only nonnegative integers fitting the wire's safe numeric range are read.
    value = InstalledApp.vuln_counts[band]
    return case(
        (and_(func.jsonb_typeof(value) == "number", value.astext.op("~")(r"^[0-9]{1,15}$")), cast(value.astext, BigInteger))
    )


def stored_answer(epoch: str | None):
    """`(known, counts)` over an `installed_apps` row's stored answer, in SQL. `known` holds only for an answer
    served under `epoch` whose every count parses. With nothing answering it is `literal(False)`, never
    `served(..., epoch=None)`: that compiles to `vuln_signature IS NULL` and would serve an unsigned row."""
    app = InstalledApp
    counts = {band: _count(band) for band in COUNTS}
    if epoch is None:
        return literal(False), counts
    return and_(served(app.vuln_assessment, app.vuln_signature, epoch=epoch), *(v.is_not(None) for v in counts.values())), counts


def application_rows(scope, app_scope: ApplicationScope, epoch: str | None, *, app_hashes=None, now=None):
    """One row per app, counting a repeated path only once per device/build."""
    app = InstalledApp
    known, counts = stored_answer(epoch)
    builds = select(
        app.app_hash,
        app.device_id,
        app.version_hash,
        func.min(app.name).label("name"),
        func.min(app.bundle_id).label("bundle_id"),
        func.bool_or(app.jamf_title_ids.is_not(None)).label("matched"),
        func.bool_or(app.patch_available.is_(True)).label("patch_available"),
        func.bool_and(func.coalesce(known, False)).label("assessed"),
        *(func.max(case((known, value))).label(band) for band, value in counts.items()),
    ).group_by(app.app_hash, app.device_id, app.version_hash)
    if scope is not None:
        population = scoped_devices(scope, now)
        builds = builds.join(population, population.c.id == app.device_id)
    if app_scope.q:
        builds = builds.where(
            or_(app.name.icontains(app_scope.q, autoescape=True), app.bundle_id.icontains(app_scope.q, autoescape=True))
        )
    if app_hashes is not None:
        builds = builds.where(app.app_hash.in_(app_hashes))
    b = builds.subquery()
    grouped = select(
        b.c.app_hash,
        func.min(b.c.name).label("name"),
        func.min(b.c.bundle_id).label("bundle_id"),
        func.count(distinct(b.c.device_id)).label("device_count"),
        func.count(distinct(b.c.version_hash)).label("version_count"),
        func.count(distinct(b.c.device_id)).filter(b.c.matched).label("matched_device_count"),
        func.count(distinct(b.c.device_id)).filter(b.c.patch_available).label("patch_available_device_count"),
        func.count(distinct(b.c.device_id)).filter(b.c.assessed).label("assessed_device_count"),
        func.count(distinct(b.c.device_id)).filter(~b.c.assessed).label("devices_with_unknown_builds"),
        func.count().filter(b.c.assessed).label("assessed_build_count"),
        func.count().filter(~b.c.assessed).label("unknown_build_count"),
        *(func.sum(b.c[band]).filter(b.c.assessed).label(band) for band in COUNTS),
    ).group_by(b.c.app_hash)
    if app_scope.severities:
        grouped = grouped.having(or_(*(func.sum(b.c[band]).filter(b.c.assessed) > 0 for band in set(app_scope.severities))))
    if app_scope.has_kev:
        grouped = grouped.having(func.sum(b.c.kev).filter(b.c.assessed) > 0)
    return grouped


def risk_output(row, *, available: bool) -> ApplicationRisk:
    if not available:
        return ApplicationRisk(
            assessment="off", devices_with_unknown_builds=row.device_count, unknown_build_count=row.unknown_build_count
        )
    assessed = row.assessed_device_count
    counts = {band: int(row._mapping[band] or 0) for band in COUNTS} if assessed else None
    return ApplicationRisk(
        assessment="unknown_app" if not assessed else "partial" if row.unknown_build_count else "covered",
        counts=counts,
        assessed_device_count=assessed,
        devices_with_unknown_builds=row.devices_with_unknown_builds,
        assessed_build_count=row.assessed_build_count,
        unknown_build_count=row.unknown_build_count,
        average_per_assessed_device=counts["total"] / assessed if counts is not None else None,
    )


def application_scope_description(scope: ApplicationScope) -> list[str]:
    result = [f"Application name or bundle contains: {scope.q}"] if scope.q else []
    if scope.severities:
        result.append("Has any selected severity: " + ", ".join(dict.fromkeys(scope.severities)))
    if scope.has_kev:
        result.append("Has a known exploited vulnerability (KEV).")
    return result or ["All application risk levels."]
