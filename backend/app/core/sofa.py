"""Dated SOFA compatibility evidence for macOS posture (#849)."""

import asyncio
import json
import logging
import re
from datetime import UTC, date, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

import httpx

from app.core.config import settings

FEED = "https://sofafeed.macadmins.io/v2/macos_data_feed.json"
BUNDLED = Path(__file__).with_name("sofa_macos.json")


def compact_feed(feed: dict) -> dict:
    branches = {}
    releases = set()
    for os in feed["OSVersions"]:
        latest = os["Latest"]
        version = latest["ProductVersion"]
        major = str(int(version.split(".")[0]))
        for release in [latest, *os.get("SecurityReleases", [])]:
            if release.get("ProductVersion") and release.get("ReleaseDate"):
                releases.add((release["ReleaseDate"][:10], release["ProductVersion"]))
        branches[major] = {
            "version": version,
            "builds": sorted({latest["Build"], *latest.get("AllBuilds", [])}),
            "released": latest["ReleaseDate"][:10],
        }
    models = {
        name: sorted({int(n) for n in model["OSVersions"]}) for name, model in feed["Models"].items() if model.get("OSVersions")
    }
    if not branches or not models:
        raise ValueError("empty compatibility catalog")
    stamp = datetime.fromisoformat(feed["LastCheck"]).astimezone(UTC)
    return {
        "asOf": stamp.isoformat(),
        "source": FEED,
        "branches": branches,
        "models": models,
        "releases": [{"released": day, "version": v} for day, v in sorted(releases)],
    }


def catalog_for(day: date) -> dict | None:
    cache = Path(settings.sofa_cache_dir)
    candidates = [p for p in cache.glob("????-??-??.json") if p.stem <= day.isoformat()]
    bundled = json.loads(BUNDLED.read_text())
    newest = bundled if date.fromisoformat(bundled["asOf"][:10]) <= day else None
    for path in sorted(candidates, reverse=True):
        if newest and newest["asOf"][:10] > path.stem:
            break
        try:
            data = json.loads(path.read_text())
            if data.get("asOf", "")[:10] != path.stem or not data.get("branches") or not data.get("models"):
                raise ValueError("invalid dated catalog")
            if not newest or data["asOf"] > newest["asOf"]:
                newest = data
            break
        except (ValueError, OSError, AttributeError):
            logging.getLogger(__name__).warning("Unreadable SOFA cache entry %s. Refresh the catalog in Posture.", path.name)
    return newest


async def refresh_catalog() -> dict:
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        response = await client.get(FEED)
        response.raise_for_status()
    data = compact_feed(response.json())
    await asyncio.to_thread(save_catalog, data)
    return data


def save_catalog(data: dict) -> None:
    cache = Path(settings.sofa_cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (data["asOf"][:10] + ".json")
    with NamedTemporaryFile(mode="w", dir=cache, delete=False) as temp:
        json.dump(data, temp)
    Path(temp.name).replace(target)


def assessment(version, build, model, target, catalog):
    if not catalog or not version or not build or not re.fullmatch(r"\d+(?:\.\d+)*", version):
        return "unknown", None, "unknown"
    major = version.split(".")[0]
    branch = catalog["branches"].get(major)
    patch = "unknown"
    if branch:
        if version == branch["version"] and build in branch["builds"]:
            patch = "current"
        elif tuple(map(int, version.split("."))) < tuple(map(int, branch["version"].split("."))):
            patch = "available"
    supported = catalog["models"].get(model)
    eligible = "unknown"
    if supported and target in catalog["branches"]:
        eligible = "compatible" if int(target) in supported else "incompatible"
    return patch, branch["version"] if branch else None, eligible
