"""`patch.jamfPatch{}` on the wire (#311), end to end on the real record and no database.

`patch{}` shipped one bit — `supported` — from #241 until #311, while the whole Jamf Patch
answer sat on the `installed_apps` rows the producer already held. This suite runs the actual
chain that produces the block, with nothing stubbed between the ends:

    the captured Mac mini record
      -> normalize_computer          (the rows process_sync would write)
      -> match_app / summarize       (app.mdm.patch.matching, against the real catalog slice)
      -> _apply_summary / copy_answer (app.catalog.service — the columns, on the same objects)
      -> build_inventory_snapshot     (the producer)
      -> to_payload                   (the bytes)

so a change to any link in it fails here rather than in production. The two service functions
are pure over ORM instances, which is what lets the whole path run with no session.

What it pins: the ruled key set and its casing, `supported` as a discriminator that leaves
`false` one key wide, the index-aligned title arrays and their all-or-nothing rule, `eaAssumed`
reaching the wire at all, #68's two-key sentence appearing only when a patch is available, and
the measured byte cost of the whole thing on a real device.

The matcher's own answers are `tests/test_patch_matching.py`'s business; this file asserts they
arrive intact, not that they are right.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.catalog.service import _apply_summary, copy_answer
from app.core.vuln import NO_CORPUS
from app.mdm.jamf.client import normalize_computer
from app.mdm.jamf.contract import canonicalize_computer
from app.mdm.patch import matching
from app.mdm.patch.matching import (
    STATE_AHEAD,
    STATE_BEHIND,
    STATE_LATEST,
    STATE_UNKNOWN,
    Catalog,
    cached_title_names,
    match_app,
    reset_catalog_cache,
)
from app.mdm.patch.requirements import Facts
from app.mdm.service import apply_hashes
from app.mdm.snapshot import build_inventory_snapshot, patch_answer
from app.models.schema import AppCatalogEntry, InstalledApp
from app.schemas.payload import JamfPatchAnswer, PatchEnrichment

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"
_NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
_WINDOW = datetime(2026, 9, 4, 2, 0, tzinfo=timezone.utc)

# The block's keys, in the order the model declares them, under their wire spellings. Restated
# here rather than read off the model: this is the ruled list (#311), and a key added to the
# model without a ruling has to fail something.
RULED_KEYS = (
    "titleIDs",
    "titleNames",
    "state",
    "onLatest",
    "versionKnown",
    "eaAssumed",
    "latestVersion",
    "latestReleasedAt",
    "referenceTitleID",
    "patchAvailableSince",
    "releasesMissed",
    "sentenceTitleID",
)


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return Catalog.from_records(json.loads((FIXTURES / "patch_titles_subset.json").read_text()))


@pytest.fixture(scope="module")
def title_names(catalog: Catalog) -> dict[str, str]:
    return {title.id: title.name for title in catalog.titles}


@pytest.fixture(scope="module")
def raw() -> dict:
    return json.loads((FIXTURES / "computer_inventory_detail_real.json").read_text())


@pytest.fixture(scope="module")
def rows(raw: dict, catalog: Catalog) -> list[InstalledApp]:
    """The device's 83 `installed_apps` rows with the Jamf Patch answer copied on, produced by
    the real matcher and the real `copy_answer` rather than by hand."""
    device = normalize_computer(raw)
    attributes = {ea.name: (ea.values[0] if ea.values else None) for ea in device.extension_attributes if ea.name}
    built = []
    for app in device.apps:
        apply_hashes(app)
        row = InstalledApp(
            name=app.name,
            bundle_id=app.bundle_id,
            version=app.version,
            short_version=app.short_version,
            app_hash=app.app_hash,
            version_hash=app.version_hash,
            key_title=app.key_title,
            key_full=app.key_full,
        )
        matches = match_app(
            Facts(
                app_name=app.name,
                bundle_id=app.bundle_id,
                versions=tuple(v for v in (app.version, app.short_version) if v),
                os_version=device.os_version,
                extension_attributes=attributes,
            ),
            catalog,
        )
        entry = AppCatalogEntry()
        _apply_summary(entry, matches, now=_NOW, signature="test")
        copy_answer(entry, row, now=_NOW)
        built.append(row)
    assert len(built) == 83
    return built


@pytest.fixture(scope="module")
def blocks(rows: list[InstalledApp], raw: dict, title_names: dict[str, str]) -> dict[str, dict]:
    """App name -> the serialised `patch{}` block, off the real producer and the real payload."""
    event = build_inventory_snapshot(
        canonicalize_computer(raw, ("applications",)),
        extension_attributes=None,
        apps=rows,
        occurred_at=_WINDOW,
        device_meta={},
        corpus=NO_CORPUS,
        title_names=title_names,
    )
    payload = event.to_payload()
    return {item["app"]["name"]: item["patch"] for item in payload["app"]}


# --- the shape ------------------------------------------------------------------------


def test_the_state_vocabulary_is_the_matchers(catalog: Catalog) -> None:
    """`PATCH_STATES` is restated in `app.schemas.payload` rather than imported, because
    `app.schemas` sits below `app.mdm` and importing upwards to read four strings inverts the
    dependency. Restating is only safe with a guard, so this is the guard — the same one the
    wire registry and `ADDITIVE_ONLY_CLAUSES` already run against their own docs."""
    declared = set(JamfPatchAnswer.model_fields["state"].annotation.__args__)  # type: ignore[union-attr]
    assert declared == {STATE_LATEST, STATE_BEHIND, STATE_AHEAD, STATE_UNKNOWN}


def test_an_unmatched_app_is_one_key_wide(blocks: dict[str, dict]) -> None:
    """`supported: false` ships NOTHING else, which is what makes the block affordable at one
    per app per device per sync: 72 of this device's 83 apps match no title, so a `false`
    padded with nine nulls would be ~87% of the object's bytes saying nothing."""
    unmatched = {name: block for name, block in blocks.items() if not block["supported"]}
    assert len(unmatched) == 72
    assert {tuple(block) for block in unmatched.values()} == {("supported",)}
    assert blocks["Mail.app"] == {"supported": False}


def test_every_matched_app_carries_a_jamf_patch_block_and_only_ruled_keys(blocks: dict[str, dict]) -> None:
    matched = {name: block for name, block in blocks.items() if block["supported"]}
    assert len(matched) == 11
    for name, block in matched.items():
        assert set(block) == {"supported", "jamfPatch"}, name
        assert set(block["jamfPatch"]) <= set(RULED_KEYS), name
        # The five keys that are never absent on an answer: without them the block cannot say
        # what it found, and `patch_answer` degrades to `supported: false` rather than ship a
        # partial one.
        assert {"titleIDs", "titleNames", "state", "onLatest", "versionKnown"} <= set(block["jamfPatch"]), name


def test_the_keys_are_camel_case_with_the_token_id_uppercased(blocks: dict[str, dict]) -> None:
    """The narrow casing rule (docs/splunk-wire-vocabulary.md §4): camelCase, `ID` uppercase
    wherever it appears, every other initialism following camelCase. SPL field names are
    case-sensitive and a wrong one returns zero rows with no error."""
    seen = {key for block in blocks.values() for key in block.get("jamfPatch", {})}
    assert seen  # the fixture really does produce blocks
    for key in seen:
        assert key[0].islower(), key
        assert "_" not in key, key
        assert "Id" not in key, f"{key}: the token is ID, not Id"
    assert "titleIDs" in seen


# --- the values, on the real device ---------------------------------------------------


def test_xcode_on_the_latest_says_so_and_carries_no_sentence(blocks: dict[str, dict]) -> None:
    """#68's two keys are absent, not null and not zero, when no patch is available. A
    consumer's `stats sum(...releasesMissed)` must not count compliant builds as zero-missed
    rows; the absence is unambiguous because `state` is present and says `latest`."""
    answer = blocks["Xcode.app"]["jamfPatch"]
    assert answer["titleIDs"] == ["0C3"] and answer["titleNames"] == ["Apple Xcode"]
    assert answer["state"] == STATE_LATEST and answer["onLatest"] is True and answer["versionKnown"] is True
    assert answer["latestVersion"] == "26.6"
    assert answer["latestReleasedAt"] == "2026-06-25T23:45:58Z"
    assert "patchAvailableSince" not in answer and "releasesMissed" not in answer


def test_wireshark_carries_both_halves_of_the_sentence_from_one_title(blocks: dict[str, dict]) -> None:
    """"Behind since 2024-01-03 · 14 releases missed" — #68's ruled sentence, and both halves
    come from the 4.2 line (whose 4.2.1 is the earliest miss), never from a fold across the two
    matched titles. The rolling title says 25. The wire carries the raw date and the raw
    integer; no day count is minted here, because a day computed at enqueue is wrong the moment
    the event is read and because buckets are a renderer's business."""
    answer = blocks["Wireshark.app"]["jamfPatch"]
    assert answer["titleIDs"] == ["612", "5F6"]
    assert answer["titleNames"] == ["Wireshark", "Wireshark 4.2"]
    assert answer["state"] == STATE_BEHIND and answer["onLatest"] is False and answer["versionKnown"] is True
    assert answer["latestVersion"] == "4.6.8"
    assert answer["patchAvailableSince"].startswith("2024-01-03")
    assert answer["releasesMissed"] == 14
    assert not any(key.lower().startswith("days") for key in answer)
    # THE TWO SCALARS ARE ABOUT DIFFERENT TITLES, and the block says so (#311, Kyle
    # 2026-09-04). 4.6.8 is the rolling "Wireshark" (612); 14 is the "Wireshark 4.2" line
    # (5F6), whose own latest is 4.2.14 and whose rolling sibling has missed 25. Without the
    # subjects the two keys read as "14 releases behind 4.6.8", which is true of neither.
    assert answer["referenceTitleID"] == "612"
    assert answer["sentenceTitleID"] == "5F6"


def test_camtasia_is_latest_on_its_line_and_says_so_with_both_titles_named(blocks: dict[str, dict]) -> None:
    """Kyle's #65 rule reaching the wire: at least one matched title says the installed version
    is its current one, so the app is latest — and BOTH titles are named, so a reader can see
    that the rolling title disagrees rather than being told only the flattering half."""
    answer = blocks["Camtasia 2022.app"]["jamfPatch"]
    assert answer["titleIDs"] == ["608", "514"]
    assert answer["titleNames"] == ["TechSmith Camtasia", "TechSmith Camtasia 2022"]
    assert answer["state"] == STATE_LATEST and answer["onLatest"] is True
    assert answer["latestVersion"] == "2022.6.10"
    assert "patchAvailableSince" not in answer
    # 2022.6.10 is the 2022 line's (514). The rolling title (608) is in `titleIDs` saying the
    # vendor ships 2026.2.0, so naming the subject is what stops `latestVersion` reading as
    # "the newest Camtasia there is". No sentence, so no `sentenceTitleID` to go with it.
    assert answer["referenceTitleID"] == "514"
    assert "sentenceTitleID" not in answer


def test_safari_ahead_of_the_catalog_is_neither_compliant_nor_behind(blocks: dict[str, dict]) -> None:
    """`ahead` and `unknown` are the two states no pair of booleans can express, which is the
    whole argument for `state` riding beside `onLatest`. Safari on the macOS 27 beta is newer
    than anything Jamf lists: not on latest, no patch available, and `versionKnown: false`
    saying Jamf never published this build."""
    answer = blocks["Safari.app"]["jamfPatch"]
    assert answer["state"] == STATE_AHEAD
    assert answer["onLatest"] is False and answer["versionKnown"] is False
    assert "patchAvailableSince" not in answer and "releasesMissed" not in answer


def test_the_title_arrays_are_index_aligned_everywhere(blocks: dict[str, dict]) -> None:
    """The contract a consumer's `mvzip(titleIDs, titleNames)` depends on."""
    for name, block in blocks.items():
        answer = block.get("jamfPatch")
        if answer is None:
            continue
        assert len(answer["titleIDs"]) == len(answer["titleNames"]), name
        assert all(isinstance(value, str) and value for value in answer["titleNames"]), name


# --- eaAssumed ------------------------------------------------------------------------


def _row(**answer) -> InstalledApp:
    return InstalledApp(
        name="Mixed.app", bundle_id="com.example.mixed", version="14.2",
        app_hash="a", version_hash="v", key_title="v1:t", key_full="v1:f",
        **{"jamf_title_ids": ["M1"], "patch_state": STATE_LATEST, **answer},
    )


def test_ea_assumed_folds_onto_the_row_and_reaches_the_wire(catalog: Catalog) -> None:
    """The 2026-08-22 ruling resolved an absent extension attribute TRUE and recorded
    `basis = ea_assumed` "so the assumption stays visible". Until #311 it was visible only in
    `app_catalog_title_matches` — a Splunk reader could not tell a fully-evaluated match from
    an assumed one, which is the outcome `basis` was minted to prevent. The whole fold runs
    here: matcher -> summarize -> `_apply_summary` -> `copy_answer` -> the block."""
    title = {
        "id": "M1", "name": "Mixed", "bundleId": "com.example.mixed", "currentVersion": "14.2",
        "patches": [{"version": "14.2", "releaseDate": "2026-01-01T00:00:00Z"}],
        "requirements": [{"operator": "and", "tests": [
            {"name": "Application Bundle ID", "type": "recon", "value": "com.example.mixed", "operator": "is"},
            {"name": "jamf-patch-mixed", "type": "extensionAttribute", "value": "14.", "operator": "like"},
        ]}],
        "extensionAttributes": [{"key": "jamf-patch-mixed", "displayName": "Mixed Version"}],
    }
    one = Catalog.from_records([title])
    facts = Facts(app_name="Mixed.app", bundle_id="com.example.mixed", versions=("14.2",))

    def block(carried: dict) -> dict:
        row = InstalledApp(
            name="Mixed.app", bundle_id="com.example.mixed", version="14.2",
            app_hash="a", version_hash="v", key_title="v1:t", key_full="v1:f",
        )
        entry = AppCatalogEntry()
        matches = match_app(Facts(**{**facts.__dict__, "extension_attributes": carried}), one)
        _apply_summary(entry, matches, now=_NOW, signature="t")
        copy_answer(entry, row, now=_NOW)
        answers = patch_answer([row], {"M1": "Mixed"})
        return answers[("Mixed.app", "com.example.mixed", "14.2")].model_dump(by_alias=True)["jamfPatch"]

    # The device does not carry the attribute: Jamf's scoping device resolves TRUE, and the
    # wire says the answer rests on that assumption.
    assert block({})["eaAssumed"] is True
    # It does carry it, and it passes: the same match, evaluated for real.
    assert block({"Mixed Version": "14.2"})["eaAssumed"] is False


def test_ea_assumed_is_absent_rather_than_false_on_a_row_judged_before_311() -> None:
    """Additive-only clause 4, exactly: absence means the event predates the key. The column is
    nullable with no backfill (migration c2f7b9e41d83), so a row nobody has re-judged says
    nothing rather than asserting that nothing was assumed."""
    answers = patch_answer([_row(ea_assumed=None)], None)
    answer = answers[("Mixed.app", "com.example.mixed", "14.2")].model_dump(by_alias=True)["jamfPatch"]
    assert "eaAssumed" not in answer
    assert patch_answer([_row(ea_assumed=False)], None)[
        ("Mixed.app", "com.example.mixed", "14.2")
    ].model_dump(by_alias=True)["jamfPatch"]["eaAssumed"] is False


# --- titleNames, and the paths where there are none -----------------------------------


def test_a_name_missing_for_any_title_drops_the_whole_list(caplog) -> None:
    """All or nothing, because the alignment is the contract: one missing name would silently
    re-label every title after it under `mvzip`. The ids are still true and still ship, and an
    id is never passed off as a name — the same rule `DeviceOut.building` follows."""
    row = _row(jamf_title_ids=["M1", "GONE"], reference_title_id="M1")
    with caplog.at_level("WARNING", logger="app.mdm.snapshot"):
        answer = patch_answer([row], {"M1": "Mixed"})[("Mixed.app", "com.example.mixed", "14.2")]
    dumped = answer.model_dump(by_alias=True)["jamfPatch"]
    assert dumped["titleIDs"] == ["M1", "GONE"]
    assert "titleNames" not in dumped
    assert any("no name in the loaded catalog" in record.message for record in caplog.records)


def test_no_catalog_means_no_names_and_no_alarm(caplog) -> None:
    """The scoped-read path: `record_device_apps` is skipped, so `process_sync` passes `None`
    and the rows carry an older answer. Names read off a catalog that was never consulted for
    these rows would be a guess, so there are none — and this is normal, not an alarm."""
    with caplog.at_level("WARNING", logger="app.mdm.snapshot"):
        answer = patch_answer([_row()], None)[("Mixed.app", "com.example.mixed", "14.2")]
    assert "titleNames" not in answer.model_dump(by_alias=True)["jamfPatch"]
    assert not caplog.records


def test_cached_title_names_reads_the_process_cache_and_never_the_database(catalog: Catalog) -> None:
    """It takes no session on purpose: `record_device_apps` loads the catalog a few statements
    before the snapshot is built, so re-loading it per device would be forty thousand queries a
    sweep to re-fetch an object that has not moved. `None` before anything has loaded one."""
    reset_catalog_cache()
    try:
        assert cached_title_names() is None
        matching._cache = catalog
        names = cached_title_names()
        assert names is not None and names["0C3"] == "Apple Xcode"
        assert len(names) == len(catalog.titles)
    finally:
        reset_catalog_cache()


# --- the refusals ---------------------------------------------------------------------


def test_supported_and_the_block_must_agree() -> None:
    """`supported` is the discriminator and the shape is a function of it — refused at enqueue
    rather than papered over by the fan-out, the same posture `VulnEnrichment` takes with
    `assessment`."""
    answer = JamfPatchAnswer(title_ids=["M1"], state=STATE_LATEST, on_latest=True, version_known=True)
    with pytest.raises(ValidationError, match="no source block"):
        PatchEnrichment(supported=True)
    with pytest.raises(ValidationError, match="no title matched"):
        PatchEnrichment(supported=False, jamf_patch=answer)
    assert PatchEnrichment(supported=True, jamf_patch=answer).supported is True


def test_an_answer_with_no_title_and_a_misaligned_name_list_are_both_refused() -> None:
    with pytest.raises(ValidationError, match="names no title"):
        JamfPatchAnswer(title_ids=[], state=STATE_LATEST, on_latest=True, version_known=True)
    with pytest.raises(ValidationError, match="index-aligned"):
        JamfPatchAnswer(
            title_ids=["M1", "M2"], title_names=["Mixed"], state=STATE_LATEST, on_latest=True, version_known=True
        )


def test_a_row_naming_titles_with_no_state_degrades_rather_than_raising(caplog) -> None:
    """Both columns are written by one statement in `_apply_summary` and copied by one in
    `copy_answer`, so this cannot happen — which makes it an alarm, not a case with a right
    answer. One corrupt row must not fail a whole device's sync, and half an answer on the wire
    is worse than none."""
    with caplog.at_level("WARNING", logger="app.mdm.snapshot"):
        answers = patch_answer([_row(patch_state=None)], None)
    assert answers[("Mixed.app", "com.example.mixed", "14.2")] == PatchEnrichment(supported=False)
    assert any("carries no patch state" in record.message for record in caplog.records)


# --- the subjects ---------------------------------------------------------------------


def test_a_single_title_answer_carries_no_subject_keys(blocks: dict[str, dict]) -> None:
    """With one matched title every scalar is about that title by construction, and `titleIDs`
    already names it. Shipping the subjects anyway would repeat a value already on the event on
    the nine-in-eleven apps that match one title — and `mvcount(titleIDs) == 1` is the test a
    consumer writes, so the absence needs no discriminator of its own."""
    single = {
        name: block["jamfPatch"]
        for name, block in blocks.items()
        if block["supported"] and len(block["jamfPatch"]["titleIDs"]) == 1
    }
    assert len(single) == 9
    for name, answer in single.items():
        assert "referenceTitleID" not in answer and "sentenceTitleID" not in answer, name


def test_only_the_multi_title_apps_carry_them(blocks: dict[str, dict]) -> None:
    """Two of the device's eleven matched apps belong to more than one title — Jamf keeps
    versioned lines beside rolling ones — and they are exactly the two that need a subject."""
    with_subject = {name for name, block in blocks.items() if "referenceTitleID" in block.get("jamfPatch", {})}
    assert with_subject == {"Wireshark.app", "Camtasia 2022.app"}


def test_the_subject_must_be_a_title_this_answer_matched() -> None:
    """A subject naming a title outside `titleIDs` is not a subject, it is a dangling
    reference — refused at enqueue rather than joined against nothing in a dashboard."""
    with pytest.raises(ValidationError, match="did not match"):
        JamfPatchAnswer(
            title_ids=["M1", "M2"], state=STATE_BEHIND, on_latest=False, version_known=True,
            reference_title_id="ELSEWHERE",
        )


def test_a_multi_title_answer_must_name_its_reference() -> None:
    with pytest.raises(ValidationError, match="required when more than one title"):
        JamfPatchAnswer(title_ids=["M1", "M2"], state=STATE_BEHIND, on_latest=False, version_known=True)


def test_a_single_title_answer_refuses_them() -> None:
    """Both directions, so the producer's rule and the model's cannot drift apart."""
    with pytest.raises(ValidationError, match="needs no subject keys"):
        JamfPatchAnswer(
            title_ids=["M1"], state=STATE_LATEST, on_latest=True, version_known=True, reference_title_id="M1"
        )


def test_the_sentence_subject_rides_only_with_the_sentence() -> None:
    """Naming the line a missed-release count came from, on an event carrying no count, answers
    a question nobody asked — and the other direction leaves #68's sentence unattributed on
    exactly the apps where it is ambiguous."""
    with pytest.raises(ValidationError, match="rides only with"):
        JamfPatchAnswer(
            title_ids=["M1", "M2"], state=STATE_BEHIND, on_latest=False, version_known=True,
            reference_title_id="M1", sentence_title_id="M2",
        )
    with pytest.raises(ValidationError, match="must name it when several matched"):
        JamfPatchAnswer(
            title_ids=["M1", "M2"], state=STATE_BEHIND, on_latest=False, version_known=True,
            reference_title_id="M1", releases_missed=3,
        )


# --- what it costs --------------------------------------------------------------------


def test_the_block_costs_what_311_measured(blocks: dict[str, dict]) -> None:
    """The number #311 was ruled on, pinned so the next key added to this block is loud.

    Measured on the real Mac mini: 72 unmatched apps unchanged at 19 bytes, 11 matched apps
    carrying the full answer. `deviceMeta` alone costs ~32.6 KB per device per sync (13 keys
    across 107 sub-events), so the whole enrichment is under a tenth of what the block that
    was capped at thirteen keys already spends.
    """
    compact = lambda value: len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())  # noqa: E731
    floor = compact({"supported": False})
    added = sum(compact(block) - floor for block in blocks.values())
    assert floor == 19
    assert 2_000 <= added <= 4_000, f"patch block now adds {added} B per device per sync"
