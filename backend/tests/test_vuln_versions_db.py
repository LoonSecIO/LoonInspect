"""A Jamf title's listed versions, each answered as its own build (`app.core.vuln_versions`).

The Jamf Patch title page's Vulnerability column reads the library rather than the tenant's
catalog, because most of a title's versions are on no Mac. What that must not change:

* **a row is the verdict, and the only verdict** (ruling R-D) — the fixture epoch's
  Wireshark 4.2.0 reads `covered` with the row's own aggregates, and 4.2.1, which the epoch
  holds no row for, reads `unknown_app`, dated, on the same title;
* **the gate is the tenant** — a tier of `off` answers nothing at all, with no statement;
* **one statement per title**, however many versions it lists.

Gated on RUN_DB_TESTS, on `test_vuln_answer_db.py`'s fixtures and its teardown.
"""

from __future__ import annotations

import os
import uuid as uuidlib

import pytest
from sqlalchemy import delete

from app.core.content_keys import app_full_key
from app.core.vuln_library import earned_corpus, load_epoch_if_new
from app.core.vuln_versions import title_version_vulns
from app.models.schema import AppCatalogVersion, JamfPatchTitle, VulnLibraryRow
from tests.test_vuln_answer_db import (  # noqa: F401
    TODAY,
    _filtering,
    _pointer,
    _set_tier,
    _statements,
    acting_tenant,
    fleet,
    tenant_selection,
)
from tests.test_vuln_library import BUNDLE, WIRESHARK_BUILD, WIRESHARK_TITLE, _rewritten, _row
from tests.test_vuln_library_db import _serving, foreign_tenant  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

NAME, BUNDLE_ID = "Wireshark.app", "org.wireshark.Wireshark"
VERSIONS = ["4.2.1", "4.2.0"]


async def _title(db, *, bundles: tuple[str, ...] = (BUNDLE_ID,)) -> str:
    """A Jamf title listing two Wireshark versions, with the index rows the catalog sync
    would have built for it — one per (bundle ID, version), keyed by `content_keys`."""
    title_id = f"versions-{uuidlib.uuid4().hex[:8]}"
    db.add(
        JamfPatchTitle(
            id=title_id,
            name="Wireshark",
            app_name=NAME,
            app_name_source="jamf",
            bundle_id=bundles[0],
            current_version=VERSIONS[0],
            last_modified="2026-09-10",
            patches=[{"version": version} for version in VERSIONS],
        )
    )
    await db.flush()
    for bundle in bundles:
        for version in VERSIONS:
            db.add(
                AppCatalogVersion(
                    title_id=title_id,
                    title_name="Wireshark",
                    app_name=NAME,
                    bundle_id=bundle,
                    version=version,
                    key_title=WIRESHARK_TITLE,
                    key_full=app_full_key(NAME, bundle, version, None),
                )
            )
    await db.commit()
    return title_id


async def _forget(db, title_id: str) -> None:
    # `jamf_patch_titles` is global, so no rollback takes it away; its index rows cascade.
    await db.rollback()
    await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == title_id))
    await db.commit()


async def test_each_listed_version_reads_its_own_row_and_only_its_own(db, fleet) -> None:  # noqa: F811
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    title_id = await _title(db)
    try:
        corpus = await earned_corpus(db)
        with _statements() as seen:
            blocks = await title_version_vulns(db, title_id, VERSIONS, corpus=corpus, as_of=TODAY)
        assert len(seen) == 1, seen

        row = await db.get(VulnLibraryRow, WIRESHARK_BUILD)
        covered = blocks["4.2.0"]
        assert covered.assessment == "covered"
        assert covered.counts.total == row.counts["total"] > 0
        assert covered.vuln_ids == row.ids[: len(covered.vuln_ids)]
        assert covered.corpus_as_of == corpus.as_of

        # The same title, one release on, and no row: outside the corpus, dated, no count.
        unknown = blocks["4.2.1"]
        assert unknown.assessment == "unknown_app"
        assert unknown.corpus_as_of == corpus.as_of
        assert unknown.counts is None
    finally:
        await _forget(db, title_id)


async def test_a_second_bundle_id_answers_where_the_first_has_no_row(db, fleet) -> None:  # noqa: F811
    """A title speaking for two bundle IDs has two keys a version; a version is outside the
    corpus only when neither has a row."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    title_id = await _title(db, bundles=("org.wireshark.Elsewhere", BUNDLE_ID))
    try:
        blocks = await title_version_vulns(db, title_id, VERSIONS, corpus=await earned_corpus(db), as_of=TODAY)
        assert blocks["4.2.0"].assessment == "covered"
        assert blocks["4.2.1"].assessment == "unknown_app"
    finally:
        await _forget(db, title_id)


async def test_nothing_answers_for_a_tenant_that_does_not_share(db, fleet) -> None:  # noqa: F811
    """The epoch is loaded and the tier is `off`: no block, no date, and no statement."""
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    title_id = await _title(db)
    try:
        await _set_tier(db, "off")
        corpus = await earned_corpus(db)
        assert corpus.as_of is None
        with _statements() as seen:
            assert await title_version_vulns(db, title_id, VERSIONS, corpus=corpus, as_of=TODAY) == {}
        assert seen == []
    finally:
        await _set_tier(db, "keys")
        await _forget(db, title_id)


async def test_the_answer_is_the_release_this_tenant_was_judged_by_in_both_modes(
    db,
    fleet,  # noqa: F811
    foreign_tenant,  # noqa: F811
    tenant_selection,  # noqa: F811
) -> None:
    """The gate does not move for this reader. Under `VULN_TENANT_SELECTION` the rows are the
    tenant's **selected** release and no other: a newer epoch the container holds and this
    tenant never acquired has a row for 4.2.1, and 4.2.1 still reads outside the corpus. On
    the legacy path the container's one loaded epoch answers, so the same import moves both."""
    _, device = fleet
    await _filtering(db, device, acquire=tenant_selection)
    title_id = await _title(db)
    try:
        newer_build = app_full_key(NAME, BUNDLE_ID, "4.2.1", None)
        newer, digest = _rewritten(rows=[_row(key_full=newer_build)])
        assert await load_epoch_if_new(db, _pointer(digest), transport=_serving(newer)) is not None

        blocks = await title_version_vulns(db, title_id, VERSIONS, corpus=await earned_corpus(db), as_of=TODAY)
        answered = {version: block.assessment for version, block in blocks.items()}
        if tenant_selection:
            assert answered == {"4.2.0": "covered", "4.2.1": "unknown_app"}
            assert blocks["4.2.0"].vuln_ids == ["CVE-2026-0001", "CVE-2026-0002"]
        else:
            assert answered == {"4.2.0": "unknown_app", "4.2.1": "covered"}
    finally:
        await _forget(db, title_id)
