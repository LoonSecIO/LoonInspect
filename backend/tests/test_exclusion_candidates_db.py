"""Excluded bundle IDs: the candidate query and the glob counts (#483).

Three properties, against a real Postgres because all three are SQL:

1. A title no public source on this container knows is a candidate — and a title either
   source knows is not, whichever source it is. "Unknown" is the whole claim the surface
   makes, so a Jamf Patch match or a vulnerability-library title has to be enough to keep
   an app off the list; otherwise the page invites an operator to exclude Chrome.
2. A glob's app count equals the titles the snapshot loses when that glob is applied.
   The page and the exchange would otherwise be two implementations of one filter, and
   the day they disagree is a support ticket rather than a failing test — so the count is
   asserted against `build_exchange_request`'s own output, not against a hand count.
3. A near-miss on case is named. `fnmatch` is case-sensitive in the Linux container, and
   `com.acme.*` silently missing `com.Acme.Portal` is the trap the whole session is for.

The fleet is cleared first: `installed_apps` rows outlive the suites that wrote them
(see conftest), and the group list is capped at a screenful, so leftovers from a file
that already ran could push this file's group off the end of it.
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

# Unique per run so a re-run against a persistent database cannot collide with its own
# leftovers, and so no other suite's bundle ID can land in this file's prefix group.
SUFFIX = uuidlib.uuid4().hex[:6]
ACME = f"com.acme{SUFFIX}"
TITLE_ID = f"loon-{SUFFIX}"


@pytest_asyncio.fixture(loop_scope="session")
async def fleet(db):
    """Three Macs, five titles: three unknown under one prefix, one matched by Jamf Patch,
    one named by the vulnerability library. Payroll is installed at two versions so the
    snapshot carries more rows than titles — the count under test is titles."""
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

    devices = [
        Device(mdm_provider="jamf", external_id=f"x{SUFFIX}{n}", serial_number=f"S{SUFFIX}{n}", hostname=f"h{SUFFIX}{n}")
        for n in range(3)
    ]
    db.add_all(devices)
    await db.commit()
    # Read now, not in teardown: the rollback there expires every instance, and reaching
    # for `.id` afterwards is a lazy load in a place that cannot await one.
    device_ids = [device.id for device in devices]

    catalog_hash = uuidlib.uuid4().hex

    def app(device, name, bundle_id, version, version_hash=None):
        return InstalledApp(
            device_id=device.id,
            name=name,
            bundle_id=bundle_id,
            version=version,
            app_hash=uuidlib.uuid4().hex,
            version_hash=version_hash or uuidlib.uuid4().hex,
            key_title=app_title_key(name, bundle_id),
            key_full=app_full_key(name, bundle_id, version, None),
        )

    db.add_all(
        [
            app(devices[0], "Acme Payroll", f"{ACME}.payroll", "1.0"),
            app(devices[1], "Acme Payroll", f"{ACME}.payroll", "2.0"),
            app(devices[0], "Acme Deploy", f"{ACME}.deploy", "1.0"),
            # The near-miss: same organization, capital A, so `com.acme….*` does not match it.
            app(devices[1], "Acme Portal", f"com.Acme{SUFFIX}.portal", "1.0"),
            app(devices[0], "Google Chrome", f"com.google{SUFFIX}.Chrome", "120", catalog_hash),
            app(devices[2], "Mozilla Firefox", f"org.mozilla{SUFFIX}.firefox", "130"),
        ]
    )
    now = datetime.now(UTC)
    entry = AppCatalogEntry(
        name="Google Chrome",
        bundle_id=f"com.google{SUFFIX}.Chrome",
        version="120",
        app_hash=uuidlib.uuid4().hex,
        version_hash=catalog_hash,
        key_title=app_title_key("Google Chrome", f"com.google{SUFFIX}.Chrome"),
        key_full=app_full_key("Google Chrome", f"com.google{SUFFIX}.Chrome", "120", None),
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add_all(
        [
            entry,
            JamfPatchTitle(id=TITLE_ID, name="Google Chrome", current_version="120", last_modified="x"),
            VulnLibraryTitle(
                title_id=TITLE_ID,
                key_title=app_title_key("Mozilla Firefox", f"org.mozilla{SUFFIX}.firefox"),
                catalog_last_modified="x",
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

    yield devices

    await db.rollback()
    await db.execute(delete(InstalledApp))
    await db.execute(delete(AppCatalogTitleMatch).where(AppCatalogTitleMatch.title_id == TITLE_ID))
    await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash == catalog_hash))
    await db.execute(delete(VulnLibraryTitle).where(VulnLibraryTitle.title_id == TITLE_ID))
    await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == TITLE_ID))
    await db.execute(delete(Device).where(Device.id.in_(device_ids)))
    await db.commit()


async def test_unknown_titles_are_candidates_and_known_ones_are_not(db, fleet) -> None:
    """Neither source knows it → candidate. Either source knows it → not.

    The two knowns are deliberately different kinds: Chrome is known because a Jamf Patch
    title matched its build through `app_catalog`, Firefox because the loaded epoch names
    its title key. Only one of those paths existing would leave the other free to drift.
    """
    from app.core.exclusion_candidates import REASON_UNKNOWN, build_candidates
    from app.schemas.system import ExclusionCandidatesOut

    answer = await build_candidates(db, [])
    group = next(g for g in answer.groups if g.prefix.lower() == ACME.lower())

    assert {a.bundle_id for a in group.apps} == {
        f"{ACME}.payroll",
        f"{ACME}.deploy",
        f"com.Acme{SUFFIX}.portal",
    }
    assert {a.reason for a in group.apps} == {REASON_UNKNOWN}
    # Payroll is on two Macs at two versions and counted once per Mac, not once per build.
    assert next(a.device_count for a in group.apps if a.bundle_id == f"{ACME}.payroll") == 2
    # Two of the three Macs carry something in this group; the third carries only Firefox.
    assert group.device_count == 2
    assert group.app_count == 3
    # Several unknown titles under a prefix no known title uses: that earns a suggestion,
    # spelled the way most of the group spells it.
    assert group.suggestion == f"{ACME}.*"
    assert group.excluded is False

    known = {f"com.google{SUFFIX}.Chrome", f"org.mozilla{SUFFIX}.firefox"}
    assert known & {a.bundle_id for g in answer.groups for a in g.apps} == set()
    assert answer.catalog_titles >= 1
    assert answer.library_titles >= 1
    # The route's own conversion, so a dataclass field the response model does not name
    # fails here rather than as a 500 on the settings page.
    assert ExclusionCandidatesOut.model_validate(answer).groups


async def test_a_glob_counts_exactly_what_the_snapshot_loses(db, fleet) -> None:
    """The page's count and the exchange's filter are one answer, asserted as one.

    `build_exchange_request` emits a row per (title key, build key, platform), so Payroll
    at two versions is two rows and one title. The count the page shows is titles, and
    this is the assertion that keeps the two from drifting apart in production while both
    look right in isolation.
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
    counted = next(g for g in (await build_candidates(db, [glob])).globs if g.glob == glob)

    assert counted.app_count == len(gone) == 2
    assert counted.source == "typed"
    assert counted.device_count == 2
    # The trap, in the response the page renders: the capital A is not matched, and the
    # page says so rather than leaving the app quietly out of the count.
    assert counted.case_misses == [f"com.Acme{SUFFIX}.portal"]


async def test_a_glob_that_matches_nothing_says_nothing(db, fleet) -> None:
    """Zero is a legible answer. A typo that matches no app looks identical to a working
    pattern in the preview — the payload simply has all its rows — so the count has to be
    allowed to be zero and be shown."""
    from app.core.exclusion_candidates import build_candidates

    counted = next(g for g in (await build_candidates(db, ["com.nobody.*"])).globs if g.glob == "com.nobody.*")
    assert (counted.app_count, counted.device_count, counted.case_misses) == (0, 0, [])


async def test_an_accepted_suggestion_reads_back_as_covered(db, fleet) -> None:
    """Accepting a suggestion changes what the group says about itself.

    The write is the audited `PUT`'s, and this is the read after it: the same group comes
    back marked covered, so the page can stop offering a glob the box already holds
    instead of listing it forever beside an Add button that does nothing.
    """
    from app.core.exclusion_candidates import build_candidates

    answer = await build_candidates(db, [f"{ACME}.*", f"com.Acme{SUFFIX}.*"])
    group = next(g for g in answer.groups if g.prefix.lower() == ACME.lower())
    assert group.excluded is True
    assert [g.source for g in answer.globs] == ["typed", "typed"]


async def test_the_query_survives_a_fleet_with_no_inventory(db, fleet) -> None:
    """An empty fleet answers an empty list, not an error — the state a pod is in before
    its first sweep, and the one the page has to say something legible about."""
    from app.core.exclusion_candidates import build_candidates
    from app.models.schema import InstalledApp

    await db.execute(delete(InstalledApp))
    await db.commit()

    answer = await build_candidates(db, ["com.acme.*"])
    assert (answer.groups, answer.more_groups) == ([], 0)
    assert [(g.app_count, g.device_count) for g in answer.globs] == [(0, 0)]


async def test_the_matcher_is_the_exchange_s_own(db) -> None:
    """Not a behaviour test — an identity one. The counts are only trustworthy because
    this module calls the exchange's `_excluded` rather than a second `fnmatch` of its
    own, and an innocent-looking local helper would pass every test above."""
    from app.core import exclusion_candidates, sharing

    assert exclusion_candidates._excluded is sharing._excluded


async def test_a_prefix_needs_three_labels() -> None:
    """`com.acme` has no prefix worth proposing: `com.acme.*` does not match it."""
    from app.core.exclusion_candidates import prefix_of

    assert prefix_of("com.acme.payroll") == "com.acme"
    assert prefix_of("com.acme") is None
    assert prefix_of("Acme") is None
