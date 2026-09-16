"""Excluded bundle IDs: the candidate query and the glob counts (#483).

Two properties, both SQL and so both against a real Postgres. **Unknown is the whole claim
the surface makes**, so a Jamf Patch match or a vulnerability-library title has to be
enough to keep an app off the list — otherwise the page invites an operator to exclude
Chrome. And **a glob's app count is asserted against what `build_exchange_request` actually
drops**, not against a hand count: the page and the exchange would otherwise be two
implementations of one filter, and the day they disagree would be a support ticket rather
than a failing test. The case near-miss rides along, because `com.acme.*` silently missing
`com.Acme.Portal` is the trap this whole surface exists for.

The fleet is cleared first: `installed_apps` rows outlive the suites that write them (see
conftest) and the group list is capped at a screenful, so another file's leftovers could
push this file's group off the end of it.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import delete

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# Unique per run, so a re-run against a persistent database cannot meet its own leftovers
# and no other suite's bundle ID can land in this file's prefix group.
SUFFIX = uuidlib.uuid4().hex[:6]
ACME = f"com.acme{SUFFIX}"
PORTAL = f"com.Acme{SUFFIX}.portal"
TITLE_ID = f"loon-{SUFFIX}"


@pytest_asyncio.fixture(loop_scope="session")
async def fleet(db):
    """Three Macs and five titles: three unknown under one prefix (one of them spelled with
    a capital A), one matched by Jamf Patch, one named by the vulnerability library. Payroll
    is installed at two versions, so the snapshot carries more rows than titles."""
    from app.core.content_keys import app_full_key, app_title_key
    from app.models.schema import (
        AppCatalogEntry,
        AppCatalogTitleMatch,
        Device,
        InstalledApp,
        JamfPatchTitle,
        VulnLibraryTitle,
    )

    await db.rollback()
    await db.execute(delete(InstalledApp))
    await db.commit()
    macs = [
        Device(mdm_provider="jamf", external_id=f"x{SUFFIX}{n}", serial_number=f"S{SUFFIX}{n}", hostname=f"h{SUFFIX}{n}")
        for n in range(3)
    ]
    db.add_all(macs)
    await db.commit()
    # Read now, not in teardown: the rollback there expires every instance, and reaching
    # for `.id` afterwards is a lazy load in a place that cannot await one.
    mac_ids = [mac.id for mac in macs]
    chrome_hash = uuidlib.uuid4().hex
    chrome_id, firefox_id = f"com.google{SUFFIX}.Chrome", f"org.mozilla{SUFFIX}.firefox"

    def app(mac, name, bundle_id, version, version_hash=None):
        return InstalledApp(
            device_id=mac.id,
            name=name,
            bundle_id=bundle_id,
            version=version,
            app_hash=uuidlib.uuid4().hex,
            version_hash=version_hash or uuidlib.uuid4().hex,
            key_title=app_title_key(name, bundle_id),
            key_full=app_full_key(name, bundle_id, version, None),
        )

    now = datetime.now(UTC)
    entry = AppCatalogEntry(
        name="Google Chrome",
        bundle_id=chrome_id,
        version="120",
        app_hash=uuidlib.uuid4().hex,
        version_hash=chrome_hash,
        key_title=app_title_key("Google Chrome", chrome_id),
        key_full=app_full_key("Google Chrome", chrome_id, "120", None),
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add_all(
        [
            app(macs[0], "Acme Payroll", f"{ACME}.payroll", "1.0"),
            app(macs[1], "Acme Payroll", f"{ACME}.payroll", "2.0"),
            app(macs[0], "Acme Deploy", f"{ACME}.deploy", "1.0"),
            app(macs[1], "Acme Portal", PORTAL, "1.0"),
            app(macs[0], "Google Chrome", chrome_id, "120", chrome_hash),
            app(macs[2], "Mozilla Firefox", firefox_id, "130"),
            entry,
            JamfPatchTitle(id=TITLE_ID, name="Google Chrome", current_version="120", last_modified="x"),
            VulnLibraryTitle(
                title_id=TITLE_ID, key_title=app_title_key("Mozilla Firefox", firefox_id), catalog_last_modified="x"
            ),
        ]
    )
    await db.commit()
    db.add(
        AppCatalogTitleMatch(
            app_catalog_id=entry.id,
            title_id=TITLE_ID,
            basis="requirements",
            state="latest",
            version_known=True,
            on_latest=True,
            latest_version="120",
        )
    )
    await db.commit()

    yield chrome_id, firefox_id

    await db.rollback()
    await db.execute(delete(InstalledApp))
    await db.execute(delete(AppCatalogTitleMatch).where(AppCatalogTitleMatch.title_id == TITLE_ID))
    await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash == chrome_hash))
    await db.execute(delete(VulnLibraryTitle).where(VulnLibraryTitle.title_id == TITLE_ID))
    await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == TITLE_ID))
    await db.execute(delete(Device).where(Device.id.in_(mac_ids)))
    await db.commit()


async def test_unknown_titles_are_candidates_and_known_ones_are_not(db, fleet) -> None:
    """Neither source knows it → candidate; either source knows it → not.

    The two knowns are deliberately different kinds — Chrome because a Jamf Patch title
    matched its build through `app_catalog`, Firefox because the loaded epoch names its
    title key — since only one of those paths existing leaves the other free to drift.
    """
    from app.core.exclusion_candidates import REASON_UNKNOWN, build_candidates

    answer = await build_candidates(db, [])
    group = next(g for g in answer.groups if g.prefix.lower() == ACME.lower())

    assert {a.bundle_id for a in group.apps} == {f"{ACME}.payroll", f"{ACME}.deploy", PORTAL}
    assert {a.reason for a in group.apps} == {REASON_UNKNOWN}
    # Payroll is on two Macs at two versions: counted once per Mac, never once per build.
    assert next(a.device_count for a in group.apps if a.bundle_id == f"{ACME}.payroll") == 2
    # Two of the three Macs carry something here; the third carries only Firefox.
    assert (group.app_count, group.device_count, group.excluded) == (3, 2, False)
    # Several unknown titles under a prefix no known title uses earns a suggestion,
    # spelled the way most of the group spells it.
    assert group.suggestion == f"{ACME}.*"
    assert set(fleet) & {a.bundle_id for g in answer.groups for a in g.apps} == set()
    assert (answer.catalog_titles, answer.library_titles) >= (1, 1)


async def test_a_glob_counts_exactly_what_the_snapshot_loses(db, fleet) -> None:
    """The page's count and the exchange's filter are one answer, asserted as one.

    `build_exchange_request` emits a row per (title key, build key, platform), so Payroll
    at two versions is two rows and one title. Titles are what the page counts, and this
    is what keeps the two from drifting apart while both look right in isolation.
    """
    from app.core.exclusion_candidates import build_candidates
    from app.core.sharing import build_exchange_request, get_or_create_settings

    glob = f"{ACME}.*"
    row = await get_or_create_settings(db)
    before = row.exclude_globs
    try:
        row.exclude_globs = []
        await db.commit()
        full = await build_exchange_request(db, row)
        row.exclude_globs = [glob]
        await db.commit()
        filtered = await build_exchange_request(db, row)
    finally:
        row.exclude_globs = before
        await db.commit()

    gone = {a["title"] for a in full["snapshot"]["apps"]} - {a["title"] for a in filtered["snapshot"]["apps"]}
    counted = {g.glob: g for g in (await build_candidates(db, [glob, "com.nobody.*"])).globs}

    assert counted[glob].app_count == len(gone) == 2
    assert (counted[glob].source, counted[glob].device_count) == ("typed", 2)
    # The trap, in the response the page renders: the capital A is not matched, and this
    # says so rather than leaving the app quietly out of the count. A glob that matches
    # nothing is legible too — in the preview a typo looks exactly like a working pattern.
    assert counted[glob].case_misses == [PORTAL]
    assert (counted["com.nobody.*"].app_count, counted["com.nobody.*"].case_misses) == (0, [])
    # With the capital spelling excluded too, the group has nothing left to offer.
    covered = await build_candidates(db, [glob, f"com.Acme{SUFFIX}.*"])
    assert next(g for g in covered.groups if g.prefix.lower() == ACME.lower()).excluded is True


async def test_the_matcher_is_the_exchange_s_own(db) -> None:
    """Not a behaviour test but an identity one: the counts are trustworthy only because
    this module calls the exchange's `_excluded` rather than a second `fnmatch` of its own,
    and an innocent-looking local helper would pass every assertion above."""
    from app.core import exclusion_candidates, sharing

    assert exclusion_candidates._excluded is sharing._excluded


async def test_a_prefix_needs_three_labels() -> None:
    """`com.acme` has no prefix worth proposing — `com.acme.*` does not even match it."""
    from app.core.exclusion_candidates import prefix_of

    assert (prefix_of("com.acme.payroll"), prefix_of("com.acme"), prefix_of("Acme")) == ("com.acme", None, None)
