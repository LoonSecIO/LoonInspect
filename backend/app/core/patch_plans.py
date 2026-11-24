"""Build a patch proposal from a single scoped inventory snapshot, without executing updates."""

import hashlib
import json
import re
from collections import defaultdict
from copy import deepcopy
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import distinct, func, select

from app.core import fleet_catalog
from app.core.application_risk import application_rows, application_scope_description, risk_output
from app.core.config import settings
from app.core.device_scope import scope_description, scoped_devices
from app.core.device_scope_queries import prepare_scope
from app.core.provenance import source_options, source_url
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_read import NO_ANSWER, corpus_as_of
from app.mdm.patch.requirements import compare_versions, version_tuple
from app.models.schema import Device, FleetCatalogState, FleetMaintainedApp, InstalledApp, JamfPatchTitle, MdmConnection

_NUMERIC_RELEASE = re.compile(r"[vV]?([0-9]+(?:\.[0-9]+)*)")


def release_order(installed: str, target: str) -> int | None:
    """Compare dotted marketing versions. Qualifiers need product-specific ordering."""
    if installed == target and version_tuple(installed):
        return 0
    left, right = _NUMERIC_RELEASE.fullmatch(installed.strip()), _NUMERIC_RELEASE.fullmatch(target.strip())
    if not left or not right:
        return None
    return compare_versions(left[1], right[1])


def iso(value):
    return value.isoformat() if value else None


def checksum(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def plan_output(plan):
    body = {
        "id": str(plan.id),
        "title": plan.title,
        "createdAt": iso(plan.created_at),
        "createdBy": plan.created_by,
        "revision": plan.revision,
        "snapshot": plan.snapshot,
        "researchStatus": plan.research_status,
        "researchStartedAt": iso(plan.research_started_at),
        "research": plan.research,
    }
    return report_presentation(body)


def report_presentation(report):
    """Hash the displayed report after withholding sensitive source-URL components.

    Historical snapshots stay stored unchanged. Their displayed hash changes only if
    redaction changes the body; the revision remains the saved evidence's revision.
    """
    body = deepcopy(report)
    body.pop("sha256", None)
    for app in body["snapshot"]["applications"]:
        app["options"] = source_options(app["options"])
    research = body.get("research") or {}
    for app in research.get("applications", []):
        if "url" in app:
            app["url"] = source_url(app["url"])
    return {**body, "sha256": checksum(body)}


def rollout_steps(name, target):
    version = target or "a vendor-supported target version after validating the application identity"
    return [
        f"Confirm {name}'s bundle identifier, signing team, CPU architecture, minimum macOS version and release channel.",
        f"Validate {version} against vendor release notes and your organization's patch policy; record the approved target.",
        "In the selected Jamf Pro instance, verify the patch title and package association, or "
        "create a policy for a verified installer.",
        "Select a representative pilot from this device scope. Set an owner, maintenance window "
        "and user deferral/relaunch behavior.",
        "Test installation, application launch and user data on the pilot. Document recovery "
        "using a vendor-supported previous package or backup.",
        "Review pilot results, then expand the Jamf scope in stages. Hold failures and devices "
        "that have not checked in for follow-up.",
        "Collect fresh inventory and verify the target version, application health and policy "
        "results. Record exceptions and completion evidence.",
    ]


async def build_snapshot(db, payload, organization):
    await prepare_scope(db, payload.scope)
    now = datetime.now(UTC)
    devices = scoped_devices(payload.scope, now)
    app = InstalledApp
    selected = select(app).join(devices, devices.c.id == app.device_id).where(app.app_hash.in_(payload.app_hashes))
    # Aggregate before materializing: a large fleet yields one row per installed version, not one per Mac.
    query = (
        select(
            app.app_hash,
            app.name,
            app.bundle_id,
            app.version,
            app.short_version,
            func.count(distinct(app.device_id)).label("macs"),
            func.jsonb_agg(distinct(app.jamf_title_ids)).filter(app.jamf_title_ids.is_not(None)).label("titles"),
            func.bool_or(app.ea_assumed).label("assumed"),
            func.bool_and(app.jamf_title_ids.is_not(None) & (app.jamf_title_ids != [])).label("all_matched"),
            func.min(app.last_patch_check_at).label("checked"),
            func.bool_and(app.last_patch_check_at.is_not(None)).label("evaluated"),
        )
        .join(devices, devices.c.id == app.device_id)
        .where(app.app_hash.in_(payload.app_hashes))
        .group_by(
            app.app_hash,
            app.name,
            app.bundle_id,
            app.version,
            app.short_version,
        )
        .order_by(app.name, app.version)
    )
    rows = (await db.execute(query)).all()
    grouped = defaultdict(list)
    for row in rows:
        grouped[row.app_hash].append(row)
    if set(payload.app_hashes) != set(grouped):
        raise HTTPException(
            409, "Some selected applications are no longer installed in this device scope. Refresh the list and rebuild."
        )
    corpus = await earned_corpus(db)
    stamp = corpus_as_of(corpus)
    epoch = loaded_epoch_signature() if stamp is not None else None
    if (payload.application_scope.severities or payload.application_scope.has_kev) and epoch is None:
        raise HTTPException(409, NO_ANSWER)
    risk_rows = (
        await db.execute(
            application_rows(payload.scope, payload.application_scope, epoch, app_hashes=payload.app_hashes, now=now)
        )
    ).all()
    if {row.app_hash for row in risk_rows} != set(payload.app_hashes):
        raise HTTPException(409, "Some selected apps no longer match the application filters. Refresh the list and rebuild.")
    risks = {row.app_hash: risk_output(row, available=epoch is not None).model_dump(by_alias=True) for row in risk_rows}
    jamf_ids = {key for row in rows for group in row.titles or [] for key in group}
    jamf = {t.id: t for t in await db.scalars(select(JamfPatchTitle).where(JamfPatchTitle.id.in_(jamf_ids)))}
    fleet_on = await fleet_catalog.enabled(db)
    fleet_state = await db.get(FleetCatalogState, 1) if fleet_on else None
    fleet = defaultdict(list)
    if fleet_on:
        for title in await db.scalars(
            select(FleetMaintainedApp).where(FleetMaintainedApp.bundle_id.in_({r.bundle_id for r in rows}))
        ):
            fleet[title.bundle_id].append(title)
    app_counts = dict(
        (
            await db.execute(
                select(app.app_hash, func.count(distinct(app.device_id)))
                .join(devices, devices.c.id == app.device_id)
                .where(app.app_hash.in_(payload.app_hashes))
                .group_by(app.app_hash)
            )
        ).all()
    )
    source_rows = (
        await db.execute(
            select(
                MdmConnection.id,
                MdmConnection.name,
                func.count(distinct(Device.id)),
                func.min(Device.last_inventory_at),
                func.max(Device.last_inventory_at),
                func.count().filter(Device.last_inventory_at.is_(None)),
            )
            .select_from(Device)
            .join(devices, devices.c.id == Device.id)
            .join(MdmConnection, MdmConnection.id == Device.mdm_connection_id)
            .group_by(MdmConnection.id, MdmConnection.name)
        )
    ).all()
    sources = [
        {
            "connectionId": row[0],
            "name": row[1],
            "mdm": "Jamf Pro",
            "devices": row[2],
            "oldestInventoryAt": iso(row[3]),
            "newestInventoryAt": iso(row[4]),
            "unknownInventoryDates": row[5],
        }
        for row in source_rows
    ]
    applications = []
    for app_hash, builds in grouped.items():
        first = builds[0]
        ids = sorted({key for row in builds for group in row.titles or [] for key in group})
        options, gaps = [], []
        target = None
        for title_id in ids:
            title = jamf.get(title_id)
            if title is None:
                gaps.append(f"Jamf title {title_id} is missing from the current public cache. Refresh Jamf Patch data.")
                continue
            conditional = (
                any(b.assumed for b in builds)
                or any(not b.all_matched for b in builds)
                or len(ids) > 1
                or any(title_id not in {key for group in b.titles or [] for key in group} for b in builds)
            )
            options.append(
                {
                    "source": "Jamf Patch",
                    "status": "identity_review" if conditional else "catalog_match",
                    "title": title.name,
                    "reference": title.id,
                    "targetVersion": title.current_version,
                    "url": source_url(f"{source_url(settings.jamf_patch_base_url).rstrip('/')}/patch/{title.id}"),
                    "observedAt": iso(title.synced_at),
                    "sourceRevision": title.last_modified,
                    "detail": "Public title match. Jamf package association, deployment policy and entitlement need "
                    "verification.",
                }
            )
            if not conditional:
                target = title.current_version
        jamf_identity_review = any(option["status"] == "identity_review" for option in options)
        if jamf_identity_review:
            gaps.append(
                "Jamf title matching is conditional or differs across devices or builds. "
                "Verify application identity before selecting a target."
            )
        if not ids:
            gaps.append(
                "No Jamf Patch match was recorded for these builds."
                if all(b.evaluated for b in builds)
                else "Jamf Patch matching has not been completed for every installed build."
            )
        candidates = fleet.get(first.bundle_id, []) if first.bundle_id and first.bundle_id != first.name else []
        complete = bool(fleet_state and fleet_state.snapshot_status == "complete")
        for title in candidates:
            options.append(
                {
                    "source": "Fleet",
                    "status": "catalog_match" if complete and len(candidates) == 1 else "identity_review",
                    "title": title.name,
                    "reference": title.slug,
                    "targetVersion": title.latest_version,
                    "url": f"https://github.com/fleetdm/fleet/blob/main/ee/maintained-apps/outputs/{title.slug}/darwin.json",
                    "observedAt": iso(title.updated_at),
                    "sourceRevision": title.manifest_sha,
                    "detail": "Public maintained-app metadata. This inventory is managed by Jamf; Fleet deployment "
                    "availability is unverified.",
                }
            )
        if not fleet_on:
            gaps.append("Fleet catalog evidence is disabled for this organization.")
        elif not complete:
            gaps.append("Fleet catalog is unread or incomplete; absence cannot establish lack of coverage.")
        elif not candidates:
            gaps.append("No matching Fleet title in the completed cached catalog.")
        if (
            target is None
            and not jamf_identity_review
            and complete
            and len(candidates) == 1
            and not any(b.assumed for b in builds)
            and len(ids) <= 1
        ):
            target = candidates[0].latest_version
        gaps.extend(
            [
                "Installomator has not been investigated for this plan.",
                "Configured Jamf deployment, package signing, owner, pilot and rollout window require operator review.",
            ]
        )
        applications.append(
            {
                "appHash": app_hash,
                "name": first.name,
                "bundleId": first.bundle_id,
                "devices": app_counts[app_hash],
                "vulnerabilities": risks[app_hash],
                "status": "draft" if options else "investigation_required",
                "targetVersion": target,
                "versions": [
                    {
                        "version": b.version,
                        "shortVersion": b.short_version,
                        "devices": b.macs,
                        "relation": (
                            {-1: "older", 0: "at_target", 1: "newer"}.get(
                                release_order(b.short_version or b.version, target), "unknown"
                            )
                            if target
                            else "unknown"
                        ),
                        "patchEvaluatedAt": iso(b.checked),
                    }
                    for b in builds
                ],
                "options": options,
                "gaps": gaps,
                "steps": rollout_steps(first.name, target),
            }
        )
    return {
        "organization": organization,
        "asOf": now.isoformat(),
        "scope": payload.scope.model_dump(by_alias=True),
        "scopeDescription": scope_description(payload.scope),
        "applicationScope": payload.application_scope.model_dump(by_alias=True),
        "applicationScopeDescription": application_scope_description(payload.application_scope),
        "vulnerabilitySource": {"asOf": iso(stamp), "release": epoch},
        "scopedDevices": await db.scalar(select(func.count()).select_from(devices)),
        "applicationDevices": await db.scalar(select(func.count(distinct(selected.subquery().c.device_id)))),
        "sources": sources,
        "applications": applications,
        "status": "Draft - operator review required",
        "limitations": [
            "This report documents proposed patch work. It does not attest that deployment or remediation has occurred.",
            "Inventory and catalog dates describe held evidence, not a live device check.",
            "Known findings are uncapped counts once per assessed device/build, not unique CVEs across builds. "
            "Average = known findings / distinct assessed devices. Unknown or stale builds contribute no zeroes.",
            "Public catalog coverage does not prove a deployment policy is configured in Jamf.",
        ],
    }
