"""Generate the scored ledger columns with the Jamf observation contract from this checkout."""

import json
import random
from datetime import UTC, datetime
from functools import cache
from uuid import uuid4

import asyncpg

from app.mdm.jamf.contract import build_aperture, canonicalize_computer, compute_head_digest

SCALARS = ("general", "hardware", "operating_system")
OBSERVED = (*SCALARS, "extension_attributes", "group_memberships")


@cache
def extension_attributes(pattern):
    rows = [
        {
            "definitionId": str(j),
            "name": f"Attribute {j}",
            "values": [] if pattern < 0 else [f"value-{(pattern + j) % 13}"],
        }
        for j in range(1, 151)
    ]
    return canonicalize_computer({"id": "a", "extensionAttributes": rows}, ["extension_attributes"]).sections[
        "extension_attributes"
    ]


def membership_ids(i):
    degree = 5 + i % 36
    common = [1, *(gid for gid in range(2, 10) if i % gid < 2)][:degree]
    return common + random.Random(i).sample(range(10, 301), degree - len(common))


def fixture(n, tenant):
    at = datetime.now(UTC)
    full = build_aperture(
        host="mdm.example.invalid", jamf_version=None, sections=OBSERVED, inventory_collection=None
    )
    partial = build_aperture(
        host="mdm.example.invalid", jamf_version=None, sections=OBSERVED[:-1], inventory_collection=None
    )
    apertures = [(tenant, 1, a.digest, "v0", json.dumps(a.document), at, at) for a in (full, partial)]
    sections, entries, spans = {}, {}, []
    for i in range(1, n + 1):
        raw = {
            "id": str(i),
            "general": {"name": f"mac-{i}", "managed": i % 5 != 0, "supervised": i % 7 != 0},
            "operatingSystem": {"name": "macOS", "version": f"26.{i % 5}", "build": f"fixture-{i % 8}"},
            "hardware": {
                "modelIdentifier": f"FixtureModel{i % 24}",
                "serialNumber": f"FIXTURE-{i}",
                "processorArchitecture": "arm64",
                "totalRamMegabytes": (16 + 16 * (i % 3)) * 1024,
                "processorType": "Fixture CPU",
                "model": "Synthetic Mac",
                "coreCount": 8 + i % 4,
                "appleSilicon": True,
            },
        }
        included = list(SCALARS)
        aperture = partial
        if i % 25 != 1:
            aperture = full
            included.append("group_memberships")
            raw["groupMemberships"] = [
                {"groupId": str(g), "groupName": f"Group {g}", "smartGroup": g % 2 == 0}
                for g in membership_ids(i)
            ]
        contents = canonicalize_computer(raw, included).sections
        contents["extension_attributes"] = extension_attributes(-1 if i % 50 == 1 else i % 13)
        digests = {key: section.digest for key, section in contents.items()}
        head = compute_head_digest("computer", str(i), aperture.digest, digests)
        spans.append(
            (
                uuid4(),
                tenant,
                1,
                "computer",
                str(i),
                "v0",
                aperture.digest,
                head,
                json.dumps(digests),
                at,
                at,
                at,
                at,
                1,
                "manual",
                True,
            )
        )
        for section in contents.values():
            if section.digest in sections:
                continue
            sections[section.digest] = (
                tenant,
                section.digest,
                section.name,
                None if section.is_list else json.dumps(section.body),
                json.dumps(section.entry_digests) if section.is_list else None,
                len(section.entries),
                at,
            )
            for e in section.entries:
                if e.digest not in entries:
                    entries[e.digest] = (tenant, e.digest, e.kind, json.dumps(e.body), e.label, at)
    return [
        (
            "observation_apertures",
            "tenant_id mdm_connection_id digest contract_version document first_seen_at last_seen_at",
            apertures,
        ),
        ("observation_entries", "tenant_id digest kind body label first_seen_at", entries.values()),
        (
            "observation_sections",
            "tenant_id digest section body entry_digests entry_count first_seen_at",
            sections.values(),
        ),
        (
            "observation_spans",
            "id tenant_id mdm_connection_id subject_kind subject_id contract_version aperture_digest head_digest "
            "section_digests first_observed_at last_observed_at first_collected_at last_collected_at observation_count last_trigger is_current",
            spans,
        ),
    ]


async def seed_ledger(n, tenant, url):
    conn = await asyncpg.connect(url)
    try:
        async with conn.transaction():
            await conn.fetchval("SELECT set_config('looninspect.tenant_id',$1,true)", str(tenant))
            for table, columns, records in fixture(n, tenant):
                # COPY is disallowed into forced-RLS tables; the INSERT enforces the app's policy.
                names = ", ".join(columns.split())
                staging = f"incoming_{table}"
                await conn.execute(f"CREATE TEMP TABLE {staging} ON COMMIT DROP AS SELECT {names} FROM {table} WITH NO DATA")
                await conn.copy_records_to_table(staging, records=records)
                await conn.execute(f"INSERT INTO {table} ({names}) SELECT {names} FROM {staging}")
    finally:
        await conn.close()
