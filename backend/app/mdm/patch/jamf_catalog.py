from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.user_agent import build_user_agent
from app.models.schema import JamfPatchTitle

JAMF_PATCH_BASE_URL = "https://jamf-patch.jamfcloud.com/v1"

_STRIP_PATCH_KEYS = ("standalone", "minimumOperatingSystem", "reboot", "killApps", "components", "capabilities")


def _remove_embedded_cert(body: str) -> dict:
    """Jamf's public patch server wraps each patch definition's JSON body in an
    embedded certificate blob; trim down to the outermost {...} before parsing."""
    s = body
    while s and not s.startswith('{"'):
        s = s[1:]
    while s and not s.endswith("]}"):
        s = s[:-1]
    if not s:
        return {}
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return {}


async def _fetch_current_titles(client: httpx.AsyncClient) -> list[dict]:
    response = await client.get(f"{JAMF_PATCH_BASE_URL}/software")
    response.raise_for_status()
    return response.json()


async def _fetch_title_detail(client: httpx.AsyncClient, title_id: str) -> dict:
    response = await client.get(f"{JAMF_PATCH_BASE_URL}/patch/{title_id}")
    response.raise_for_status()
    return _remove_embedded_cert(response.text)


def _strip_patch_entry(patch: dict) -> dict:
    return {key: value for key, value in patch.items() if key not in _STRIP_PATCH_KEYS}


def _convert_requirements(requirements: list[dict]) -> list[dict]:
    """Collapse Jamf's flat, `and`-linked requirement list into OR'd groups of
    AND'd criteria (a requirement starts a new group when it isn't and-linked
    to the previous one)."""
    if not requirements:
        return []

    groups: list[dict] = []
    current: dict = {"operator": "and", "tests": []}

    for requirement in requirements:
        test = {
            "name": requirement.get("name"),
            "operator": requirement.get("operator"),
            "value": requirement.get("value"),
            "type": requirement.get("type"),
        }
        if current["tests"] and not requirement.get("and", True):
            groups.append(current)
            current = {"operator": "and", "tests": []}
        current["tests"].append(test)

    groups.append(current)
    return groups


def _needs_refresh(existing: JamfPatchTitle | None, title_summary: dict) -> bool:
    if existing is None:
        return True
    return (
        existing.last_modified != title_summary.get("lastModified")
        or existing.current_version != title_summary.get("currentVersion")
    )


async def sync_catalog(db: AsyncSession) -> int:
    """Refresh the jamf_patch_titles cache from Jamf's public patch definition
    catalog. Only titles whose lastModified/currentVersion changed (or are new)
    are re-fetched in full. Returns the number of titles synced."""

    headers = {"User-Agent": build_user_agent("jamf-patch-sync")}

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        summaries = await _fetch_current_titles(client)

        result = await db.execute(select(JamfPatchTitle))
        existing_rows = {row.id: row for row in result.scalars().all()}

        to_refresh = [
            summary for summary in summaries if _needs_refresh(existing_rows.get(summary.get("id")), summary)
        ]

        details = await asyncio.gather(
            *(_fetch_title_detail(client, summary["id"]) for summary in to_refresh),
            return_exceptions=True,
        )

    now = datetime.now(timezone.utc)
    synced = 0

    for summary, detail in zip(to_refresh, details):
        if isinstance(detail, BaseException) or not detail:
            continue

        title_id = summary["id"]
        row = existing_rows.get(title_id)
        if row is None:
            row = JamfPatchTitle(id=title_id)
            db.add(row)

        row.name = detail.get("name", "")
        row.publisher = detail.get("publisher")
        row.app_name = detail.get("appName")
        row.bundle_id = detail.get("bundleId")
        row.current_version = detail.get("currentVersion", "")
        row.last_modified = detail.get("lastModified", "")
        row.patches = [_strip_patch_entry(patch) for patch in detail.get("patches", [])]
        row.requirements = _convert_requirements(detail.get("requirements", []))
        row.synced_at = now
        synced += 1

    await db.commit()
    return synced
