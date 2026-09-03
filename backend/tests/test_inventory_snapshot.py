"""The per-device snapshot event against the real fixture (#241). Pure; no database.

`device.inventory` is the first of the two highest-volume objects the product will ever
emit, and the fan-out (#242) reads its shape verbatim — every decision about it is
permanent the moment a customer indexes one. So this suite holds the built event to the
rulings, on a captured Jamf Pro 11.31 record rather than on a hand-written payload:

* the head is `event`, `jobID`, `occurredAt`, `deviceMeta`, and the section keys are
  exactly the frozen registry's — `SECTION_WRAPPERS`, never a spelling of this file's;
* every `app` item is Jamf's object under Jamf's v4 names, restricted to the ledger's
  allowlist, beside `patch{}` and `vuln{}` and nothing else — no minted identity field,
  no telemetry, no `alert`;
* `deviceMeta` is #189's ruled set, copied verbatim, with `jobID` at the root too (#220);
* `patch.supported` reads the installed-app row and survives canonicalisation;
* the aperture rule holds per section: absent means unread, `[]` means read-empty;
* the serialised size of the fixture's snapshot is pinned as a ceiling, so the next
  volume change is loud (the spirit of #154).

The database lane — one row per device per pass, the delta beside it, the counts — is
`tests/test_outbox_passes_db.py`, `tests/test_jamf_sync_e2e.py` and `tests/test_runs.py`.
"""

from __future__ import annotations

import json
import logging
import unicodedata
import uuid as uuidlib
from collections.abc import Iterator
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.content_keys import app_full_key, app_title_key
from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, RunContext, reset_run
from app.core.runs import set_run as _set_run
from app.core.vuln import NO_CORPUS, VulnCorpus
from app.core.wire_vocabulary import ENRICHMENTS, SECTION_WRAPPERS, SUB_EVENT_KEYS
from app.mdm.jamf.client import normalize_computer
from app.mdm.jamf.contract import SECTIONS, V0_SECTIONS, Observation, SectionContent, canonicalize_computer
from app.mdm.service import _device_meta, apply_hashes
from app.mdm.snapshot import app_identity, build_inventory_snapshot, content_keys
from app.models.schema import Device, InstalledApp
from app.schemas.payload import (
    INVENTORY_EVENT_TYPE,
    SNAPSHOT_HEAD_KEYS,
    VULN_ASSESSMENT_OFF,
    InventoryAppItem,
    InventorySnapshotEvent,
    NormalizedDevice,
    NormalizedExtensionAttribute,
    PatchEnrichment,
    VulnEnrichment,
)
from tests.test_device_meta import RESERVED, SHIPPED_ELEVEN

FIXTURE = Path(__file__).parent / "fixtures" / "jamf" / "computer_inventory_detail_real.json"

# The ledger's allowlist for an application (`contract._APPLICATION`), which is the field
# set the app object carries — the labelled assumption on #81's 2026-09-02 ruling comment.
ALLOWED_APP_KEYS = frozenset(
    {"name", "path", "version", "cfBundleShortVersionString", "cfBundleVersion", "bundleId", "macAppStore"}
)
# Off the wire, and asserted absent: the three telemetry fields the allowlist excludes,
# and the four identity fields LoonInspect mints (Kyle, 2026-09-02: "leave them out for
# now we can add them in the future").
TELEMETRY_KEYS = frozenset({"sizeMegabytes", "updateAvailable", "externalVersionId"})
MINTED_KEYS = frozenset({"appHash", "versionHash", "keyTitle", "keyFull"})

# The number measured on 2026-09-03 for the fixture below, under the full aperture, with
# the eleven-key meta block, as compact JSON: 28,783 bytes. #241 measured 28,234 on the
# same record before #197 ruled the extension-attribute wire object (nine Jamf keys plus
# `source`, three items rather than two) and before #220 hoisted `jobID` to the root.
# The ceiling is deliberately close: a key added to every app item is ~83 bytes times
# 83 apps and must trip this.
SIZE_CEILING = 29_000

_RUN_ID = uuidlib.UUID("0199a5c4-7b2e-7c3a-9f1e-3c2b1a0d9e8f")
_WINDOW = datetime(2026, 9, 2, 2, 0, tzinfo=timezone.utc)


@pytest.fixture
def run() -> Iterator[RunContext]:
    context = RunContext(
        id=_RUN_ID,
        connection_id=1,
        collection_id=4,
        trigger=TRIGGER_SWEEP,
        comparison="delta",
        lock_class=LOCK_DEVICE_SWEEP,
        window_start=_WINDOW,
    )
    token = _set_run(context)
    try:
        yield context
    finally:
        reset_run(token)


@pytest.fixture
def raw() -> dict:
    return json.loads(FIXTURE.read_text())


def _rows(view: NormalizedDevice, titles: dict[str, list[str]] | None = None) -> list[InstalledApp]:
    """`installed_apps` rows exactly as process_sync would create them from the normalized
    view: raw strings, hashed by apply_hashes, the Jamf Patch answer copied on."""
    rows = []
    for app in view.apps or ():
        apply_hashes(app)
        rows.append(
            InstalledApp(
                name=app.name,
                bundle_id=app.bundle_id,
                version=app.version,
                short_version=app.short_version,
                app_hash=app.app_hash,
                version_hash=app.version_hash,
                key_title=app.key_title,
                key_full=app.key_full,
                jamf_title_ids=(titles or {}).get(app.bundle_id),
            )
        )
    return rows


def _device(raw: dict) -> Device:
    return Device(
        external_id=str(raw["id"]),
        serial_number=raw["hardware"]["serialNumber"],
        hostname=raw["general"]["name"],
        last_inventory_at=datetime(2026, 8, 22, 1, 44, 27, tzinfo=timezone.utc),
        managed=True,
    )


def _snapshot(
    raw: dict,
    sections=V0_SECTIONS,
    *,
    titles: dict[str, list[str]] | None = None,
    corpus: VulnCorpus = NO_CORPUS,
) -> dict:
    """The fixture through the two views `ingest_computer` builds and the builder, to the
    stored payload — the same path process_sync takes, minus the session.

    `corpus` defaults to the one the container ships (`NO_CORPUS`), so every existing
    assertion in this suite and in `test_hec_fanout.py` describes the shipped wire."""
    observation = canonicalize_computer(raw, sections)
    view = normalize_computer(raw, sections)
    event = build_inventory_snapshot(
        observation,
        extension_attributes=view.extension_attributes,
        apps=_rows(view, titles),
        occurred_at=_WINDOW,
        device_meta=_device_meta(_device(raw)),
        corpus=corpus,
    )
    return event.to_payload()


@pytest.fixture
def payload(raw: dict, run: RunContext) -> dict:
    return _snapshot(raw)


def _compact(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --- the head, and the fourteen wrappers -------------------------------------------


def test_the_head_is_the_four_keys_and_the_type_is_the_snapshots_own(payload: dict, run: RunContext) -> None:
    """`event` is the one discriminator on every family (docs/runs.md §4); the snapshot's
    is `device.inventory` — the state — beside the delta's `device.inventory.changed`.
    `jobID` rides at the root and inside `deviceMeta`, read off one block (#220), and the
    three keys every fan-out sub-event must carry (SUB_EVENT_KEYS) are all here, or they
    would be unreachable by the time `_build_body` splits the event."""
    assert payload["event"] == INVENTORY_EVENT_TYPE == "device.inventory"
    assert set(SNAPSHOT_HEAD_KEYS) <= set(payload)
    assert set(SUB_EVENT_KEYS) <= set(payload)
    assert payload["jobID"] == str(run.id) == payload["deviceMeta"]["jobID"]
    assert datetime.fromisoformat(payload["occurredAt"]) == _WINDOW


def test_under_the_full_aperture_the_section_keys_are_the_registrys_fourteen(payload: dict) -> None:
    """Exactly `SECTION_WRAPPERS.values()`, in both directions, and the cardinality of each
    comes from the contract's own `SectionSpec.is_list` — the seven scalar sections are
    objects, the seven list sections are lists (`localUserAccount` included: the registry's
    "one per device — long" comment is the naming rule, and the contract's list wins)."""
    wrappers = set(payload) - set(SNAPSHOT_HEAD_KEYS)
    assert wrappers == set(SECTION_WRAPPERS.values())
    assert len(wrappers) == 14
    for section, spec in SECTIONS.items():
        value = payload[SECTION_WRAPPERS[section]]
        assert isinstance(value, list if spec.is_list else dict), f"{section} has the wrong cardinality"


def test_the_model_pins_its_wrapper_fields_to_the_registry_in_both_directions() -> None:
    """The producer spells no wrapper by hand, and the model cannot drift from the
    registry either: adding a section to SECTIONS needs a name in SECTION_WRAPPERS (pinned
    in test_wire_vocabulary.py) AND a field here, or this fails."""
    wire = {info.alias or name for name, info in InventorySnapshotEvent.model_fields.items()}
    assert wire - set(SNAPSHOT_HEAD_KEYS) == set(SECTION_WRAPPERS.values())
    assert set(SNAPSHOT_HEAD_KEYS) <= wire


def test_the_scalar_sections_are_jamfs_objects_under_jamfs_keys(payload: dict, raw: dict) -> None:
    """Jamf's v4 names verbatim (Kyle, 2026-09-02), the allowlist's fields: a key in a
    section object is a key Jamf sent under that name, and telemetry stays off."""
    assert payload["hardware"]["serialNumber"] == raw["hardware"]["serialNumber"]
    assert payload["operatingSystem"]["version"] == raw["operatingSystem"]["version"]
    assert payload["general"]["name"] == raw["general"]["name"]
    assert payload["general"]["remoteManagement"] == {"managed": raw["general"]["remoteManagement"]["managed"]}
    # Not listed by the allowlist, so not on the wire — additive later under clause 1.
    for telemetry in ("lastIpAddress", "reportDate", "lastContactTime", "lastContact"):
        assert telemetry not in payload["general"]
    # The real record's user fields are all null: read, and genuinely empty, is `{}`.
    assert payload["userAndLocation"] == {}


# --- the app item ------------------------------------------------------------------


def test_every_app_item_is_jamfs_object_beside_patch_and_vuln_and_nothing_else(payload: dict, raw: dict) -> None:
    """The fan-out sub-event's body minus SUB_EVENT_KEYS, 83 times.

    Every item: `app` under at most the seven allowlisted keys — absent where Jamf sent
    nothing (82 of 83 carry all seven; BambuStudio.app reports `cfBundleVersion: null`
    and carries six) — `patch` at its bool floor, `vuln` at its `off` floor. Never a
    telemetry field, never a minted identity field, and never `alert`: ruled name-only
    on #229, nothing writes it in v0, even though it is in ENRICHMENTS beside the two.
    """
    items = payload["app"]
    assert len(items) == len(raw["applications"]) == 83
    for item in items:
        assert set(item) == {"app", "patch", "vuln"}
        assert set(item["app"]) <= ALLOWED_APP_KEYS
        assert not set(item["app"]) & TELEMETRY_KEYS
        assert not set(item["app"]) & MINTED_KEYS
        assert item["patch"] == {"supported": False}
        assert item["vuln"] == {"assessment": VULN_ASSESSMENT_OFF}
    assert sum(1 for item in items if set(item["app"]) == ALLOWED_APP_KEYS) == 82
    (short,) = [item["app"] for item in items if set(item["app"]) != ALLOWED_APP_KEYS]
    assert short["name"] == "BambuStudio.app" and "cfBundleVersion" not in short
    # `alert` is the registry's third enrichment and rides nothing here.
    assert "alert" in ENRICHMENTS["app"]
    assert set(ENRICHMENTS["app"]) - {"alert"} == {"patch", "vuln"}


def test_the_app_values_are_jamfs_verbatim(payload: dict, raw: dict) -> None:
    """The first `applications[]` entry of the fixture, as #241's body sketch shows it:
    Jamf's seven under Jamf's spelling — `bundleId`, not `bundleID`, because a vendor's
    native key keeps the vendor's spelling."""
    maps = next(item for item in payload["app"] if item["app"].get("bundleId") == "com.apple.Maps")
    first = raw["applications"][0]
    assert first["name"] == "Maps.app"
    assert maps["app"] == {
        "name": "Maps.app",
        "path": "/System/Applications/Maps.app",
        "version": "3.0",
        "cfBundleShortVersionString": "3.0",
        "cfBundleVersion": "2972.20.6.12.13",
        "bundleId": "com.apple.Maps",
        "macAppStore": False,
    }
    assert maps["app"] == {key: first[key] for key in ALLOWED_APP_KEYS}


def test_patch_supported_reads_the_row_and_survives_canonicalisation(run: RunContext) -> None:
    """`supported` is `true` iff the row's `jamf_title_ids` names a title — read off the
    `installed_apps` row already in the transaction, never computed here.

    The trap #241 named: the row hashed Jamf's RAW strings and the entry body is the
    canonical form, so a join on `version_hash` silently reports `false` for any app whose
    name canonicalises differently from its raw string. The fixture cannot catch that (all
    83 names canonicalise to themselves), so this record carries one name with trailing
    whitespace and a decomposed accent, and asserts the title-matched build reads `true`.
    """
    accented = unicodedata.normalize("NFD", "Café.app") + "  "
    raw = {
        "id": "7",
        "general": {"name": "mbp-ada"},
        "applications": [
            {"name": accented, "bundleId": "com.example.cafe", "version": " 1.0", "path": "/Applications/Café.app"},
            {"name": "Plain.app", "bundleId": "com.example.plain", "version": "2.0", "path": "/Applications/Plain.app"},
            {"name": "Nameless.app", "bundleId": "", "version": "3.0", "path": "/Applications/Nameless.app"},
        ],
    }
    view = normalize_computer(raw, ("applications",))
    rows = _rows(view)
    rows[0].jamf_title_ids = ["42"]
    rows[1].jamf_title_ids = []
    rows[2].jamf_title_ids = ["7", "9"]
    # The two sides really do hash different strings — this is why the join is not on it.
    assert rows[0].name == accented and rows[0].name != unicodedata.normalize("NFC", accented).strip()

    event = build_inventory_snapshot(
        canonicalize_computer(raw, ("applications",)),
        extension_attributes=None,
        apps=rows,
        occurred_at=_WINDOW,
        device_meta={},
        corpus=NO_CORPUS,
    )
    by_name = {item.app["name"]: item for item in event.app or ()}
    assert set(by_name) == {"Café.app", "Plain.app", "Nameless.app"}
    assert by_name["Café.app"].patch.supported is True
    assert by_name["Café.app"].app["version"] == "1.0"
    assert by_name["Plain.app"].patch.supported is False
    # A missing bundleId falls back to the name on the row (client.normalize_computer) and
    # is dropped from the canonical entry; the identity agrees on both sides regardless.
    assert by_name["Nameless.app"].patch.supported is True
    assert app_identity(accented, "", " 1.0") == ("Café.app", "Café.app", "1.0")


def test_the_row_and_the_canonical_entry_agree_on_the_content_keys(payload: dict, raw: dict) -> None:
    """The join #249's `vuln{}` is looked up on, pinned on all 83 apps of the fixture.

    `content_keys()` reads `key_title` / `key_full` off the `installed_apps` row, which
    hashed Jamf's RAW strings in `apply_hashes`; the fallback for an app with no row
    computes them from the CANONICAL entry body. The two are the same string because
    `content_keys.canonical_key` NFC-normalises and strips every field before hashing and
    the entry body is already in that form — the property that lets the corpus be keyed on
    one hash whichever side computes it. Unlike `version_hash`, which really does differ
    between the two sides (see the `patch.supported` test below) and is why the patch join
    is on the canonical identity triple instead.
    """
    view = normalize_computer(raw, V0_SECTIONS)
    from_rows = content_keys(_rows(view))
    assert len(from_rows) == 83
    for item in payload["app"]:
        app = item["app"]
        identity = app_identity(app.get("name"), app.get("bundleId"), app.get("version"))
        name, bundle, version = identity
        assert from_rows[identity] == (app_title_key(name, bundle), app_full_key(name, bundle, version, None))


def test_the_rowless_fallbacks_key_full_agrees_with_the_row_only_because_short_version_is_pinned_none(
    raw: dict,
) -> None:
    """The dependency `_fallback_content_keys` (`app.mdm.snapshot`) actually relies on for
    `key_full`, which canonicalisation does not explain: `normalize_computer` pins
    `short_version` to `None` for every app Jamf's `applications` section reports — the
    fourth field `apply_hashes` hashes into the row's `key_full`, and the exact value the
    fallback hardcodes in its place. If an ingest path ever started populating it, this is
    the assertion that would break before the fallback silently diverged from the row."""
    view = normalize_computer(raw, V0_SECTIONS)
    assert all(app.short_version is None for app in view.apps or ())


def test_a_removed_app_is_absent_and_a_rowless_app_is_unsupported_and_logged(run: RunContext, caplog) -> None:
    """The snapshot is the observation's list: a row for an app Jamf no longer reports (a
    removed app still sitting in a loaded collection) never appears. The other direction —
    an entry with no row — cannot happen by construction; when it does it is
    `supported: false` plus a log line, never an exception in the ingest path."""
    raw = {
        "id": "7",
        "general": {"name": "mbp-ada"},
        "applications": [{"name": "Kept.app", "bundleId": "com.example.kept", "version": "1.0"}],
    }
    removed = InstalledApp(
        name="Gone.app", bundle_id="com.example.gone", version="9.9", app_hash="x", version_hash="y",
        key_title="v1:t", key_full="v1:f", jamf_title_ids=["1"],
    )
    with caplog.at_level(logging.WARNING, logger="app.mdm.snapshot"):
        event = build_inventory_snapshot(
            canonicalize_computer(raw, ("applications",)),
            extension_attributes=None,
            apps=[removed],
            occurred_at=_WINDOW,
            device_meta={},
            corpus=NO_CORPUS,
        )
    assert [item.app["name"] for item in event.app or ()] == ["Kept.app"]
    assert event.app is not None and event.app[0].patch.supported is False
    assert any("no row to read patch support" in record.message for record in caplog.records)


# --- the other list sections ---------------------------------------------------------


def test_the_ea_items_are_jamfs_object_verbatim_plus_source(payload: dict, raw: dict) -> None:
    """#197's ruled wire object (docs/splunk-wire-vocabulary.md §4, jamf-observations.md
    §7): Jamf's extension-attribute object verbatim — nine keys under Jamf's spelling,
    nulls included — plus `source`, the one key LoonInspect mints inside a Jamf object
    anywhere on the wire. Three items, not two: the EA the fixture displays under General
    is merged since the hoist, and its `source` says so."""
    wire_keys = {info.serialization_alias or name for name, info in NormalizedExtensionAttribute.model_fields.items()}
    items = payload["ea"]
    assert len(items) == 3
    for item in items:
        assert set(item) == {"ea"}
        assert set(item["ea"]) == wire_keys
    by_id = {item["ea"]["definitionId"]: item["ea"] for item in items}
    top_level = {str(ea["definitionId"]) for ea in raw["extensionAttributes"]}
    nested = {str(ea["definitionId"]) for ea in raw["general"]["extensionAttributes"]}
    assert {definition_id for definition_id, ea in by_id.items() if ea["source"] == "extensionAttributes"} == top_level
    assert {definition_id for definition_id, ea in by_id.items() if ea["source"] == "general"} == nested
    # Verbatim means Jamf's values as sent, whole lists included.
    first = raw["extensionAttributes"][0]
    assert by_id[str(first["definitionId"])]["values"] == first["values"]
    assert by_id[str(first["definitionId"])]["name"] == first["name"]


def test_labelled_entries_carry_their_label_under_jamfs_key(payload: dict, raw: dict) -> None:
    """The contract keeps names out of the hash and carries them beside the body as the
    entry's label; the wire wants the name under the key Jamf spells it with —
    `group.groupName`, `profile.displayName` — because that is what an analyst types."""
    (group,) = payload["group"]
    assert set(group) == {"group"}
    assert group["group"] == {
        "groupId": str(raw["groupMemberships"][0]["groupId"]),
        "smartGroup": raw["groupMemberships"][0]["smartGroup"],
        "groupName": raw["groupMemberships"][0]["groupName"],
    }
    names = {item["profile"]["displayName"] for item in payload["profile"]}
    assert names == {profile["displayName"] for profile in raw["configurationProfiles"]}
    assert all(set(item) == {"profile"} for item in payload["profile"])
    # And the label never leaks a key the allowlist did not admit.
    assert all("groupDescription" not in item["group"] for item in payload["group"])
    assert all("lastInstalled" not in item["profile"] for item in payload["profile"])


def test_every_list_item_is_wrapped_under_its_own_section_key(payload: dict) -> None:
    for section, spec in SECTIONS.items():
        if not spec.is_list or section == "applications":
            continue
        wrapper = SECTION_WRAPPERS[section]
        assert payload[wrapper], f"the fixture carries {section}; the section must not be empty here"
        for item in payload[wrapper]:
            assert set(item) == {wrapper}
            assert isinstance(item[wrapper], dict) and item[wrapper]


# --- deviceMeta, jobID, occurredAt -------------------------------------------------


def test_device_meta_is_the_ruled_eleven_copied_verbatim(payload: dict, raw: dict, run: RunContext) -> None:
    """#189's block, whole and untouched: the same set `tests/test_device_meta.py` holds the
    inventory family to, with nothing added and nothing dropped, and `eventID` on the same
    grain the delta uses — one per device per sync, `uuid5(jobID, jamfProID)`."""
    meta = payload["deviceMeta"]
    assert set(meta) == set(SHIPPED_ELEVEN)
    assert RESERVED not in meta
    assert meta == _device_meta(_device(raw))
    assert meta["eventID"] == str(uuidlib.uuid5(run.id, str(raw["id"])))
    assert meta["jamfProID"] == str(raw["id"])
    assert all(value is not None for value in meta.values())


def test_outside_a_run_job_id_is_absent_not_null(raw: dict) -> None:
    """No run fixture. The block drops `jobID` and `eventID` under its null rule, and the
    root copy follows it — absent rather than null, so a run-less enqueue never pays bytes
    to say nothing and never leaves one copy null beside an absent one."""
    payload = _snapshot(raw)
    assert "jobID" not in payload
    assert "jobID" not in payload["deviceMeta"] and "eventID" not in payload["deviceMeta"]
    assert payload["event"] == INVENTORY_EVENT_TYPE


# --- the aperture ------------------------------------------------------------------


def test_a_scoped_read_emits_only_the_wrappers_it_read(raw: dict, run: RunContext) -> None:
    """The 2026-08-29 ruling applied per section: `None` means outside the read, and the
    snapshot never asserts an absence the read did not observe. A webhook collection
    scoped to three scalar sections — the case `test_narrow_webhook_scope_never_wipes_apps`
    builds — produces three wrappers and NO `app` key, rather than an empty one."""
    payload = _snapshot(raw, ("general", "hardware", "operating_system"))
    assert set(payload) - set(SNAPSHOT_HEAD_KEYS) == {"general", "hardware", "operatingSystem"}
    assert "app" not in payload and "ea" not in payload
    assert payload["hardware"]["serialNumber"] == raw["hardware"]["serialNumber"]
    # The head survives any aperture: this is still the join key.
    assert payload["jobID"] == str(run.id) and set(SUB_EVENT_KEYS) <= set(payload)


def test_a_read_and_empty_list_section_is_an_empty_list(raw: dict, run: RunContext) -> None:
    """The other half of the ruling: `[]` is a real read of a device with no apps."""
    raw["applications"] = []
    payload = _snapshot(raw)
    assert payload["app"] == []
    assert set(payload) - set(SNAPSHOT_HEAD_KEYS) == set(SECTION_WRAPPERS.values())


def test_a_read_that_disagrees_with_itself_about_the_ea_aperture_raises(raw: dict, run: RunContext) -> None:
    """Both views of one read are built from the same `sections`, so the ledger holding the
    EA section while the normalized view says it was not read is a programming error —
    it fails the device loudly rather than shipping `"ea": []` for a section nobody read."""
    observation = canonicalize_computer(raw, ("extension_attributes",))
    with pytest.raises(ValueError, match="must agree on the aperture"):
        build_inventory_snapshot(
            observation, extension_attributes=None, apps=(), occurred_at=_WINDOW, device_meta={}, corpus=NO_CORPUS
        )


# --- refusals at enqueue -------------------------------------------------------------


def test_a_missing_enrichment_block_is_refused_at_enqueue() -> None:
    """#242 relies on both blocks being present on every app item — it copies them through
    and stamps nothing — so a producer that forgets one must fail here, not at delivery."""
    app = {"name": "Maps.app", "bundleId": "com.apple.Maps", "version": "3.0"}
    InventoryAppItem(app=app, patch=PatchEnrichment(supported=False), vuln=VulnEnrichment())
    with pytest.raises(ValidationError):
        InventoryAppItem(app=app, vuln=VulnEnrichment())  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        InventoryAppItem(app=app, patch=PatchEnrichment(supported=False))  # type: ignore[call-arg]
    # `assessment` is the ruled closed set, `unknown_app` spelled the founder's way —
    # and it carries `corpusAsOf`, because a dated edge is what makes it honest (§4a).
    VulnEnrichment(assessment="unknown_app", corpus_as_of=date(2026, 9, 1))
    with pytest.raises(ValidationError):
        VulnEnrichment(assessment="unknownApp", corpus_as_of=date(2026, 9, 1))


def test_a_bare_jamf_object_in_a_list_section_is_refused() -> None:
    """Every list item is the sub-event body minus SUB_EVENT_KEYS — `{"cert": {…}}` — so
    the fan-out iterates rather than reshapes. A bare object, or an item carrying a second
    key, is refused at enqueue."""
    InventorySnapshotEvent(occurredAt=_WINDOW, cert=[{"cert": {"commonName": "x"}}])
    with pytest.raises(ValidationError, match="cert"):
        InventorySnapshotEvent(occurredAt=_WINDOW, cert=[{"commonName": "x"}])
    with pytest.raises(ValidationError, match="cert"):
        InventorySnapshotEvent(occurredAt=_WINDOW, cert=[{"cert": {"commonName": "x"}, "patch": {}}])


def test_a_wrapper_the_model_has_no_field_for_is_refused_at_enqueue() -> None:
    """`extra="forbid"` (PR #273's verify pass, should-fix 1). Pydantic's default is
    `ignore`, under which a fifteenth section added to the registry without a field here
    would be silently dropped from every snapshot in production while only the pure tests
    went red. Refused at enqueue instead — the posture the app item already had — and the
    alias and the Python name both still populate."""
    InventorySnapshotEvent(occurredAt=_WINDOW, operatingSystem={"version": "27.0"})
    InventorySnapshotEvent(occurredAt=_WINDOW, operating_system={"version": "27.0"})
    with pytest.raises(ValidationError, match="fonts"):
        InventorySnapshotEvent(occurredAt=_WINDOW, fonts=[{"fonts": {"name": "Menlo"}}])
    with pytest.raises(ValidationError, match="storage"):
        InventorySnapshotEvent(occurredAt=_WINDOW, storage={"disks": []})


def test_to_payload_drops_only_the_unread_wrappers_and_a_run_less_job_id() -> None:
    """Absent-not-null on exactly two kinds of key, and nothing inside a Jamf object is
    touched: the extension-attribute item keeps Jamf's nulls verbatim (#197)."""
    ea = {"definitionId": "3", "name": None, "description": None, "values": [], "source": "extensionAttributes"}
    event = InventorySnapshotEvent(occurredAt=_WINDOW, deviceMeta={"jamfProID": "1"}, ea=[{"ea": ea}], update=[])
    payload = event.to_payload()
    assert set(payload) == {"event", "occurredAt", "deviceMeta", "ea", "update"}
    assert payload["ea"] == [{"ea": ea}]
    assert payload["update"] == []


# --- size ------------------------------------------------------------------------------


def test_the_fixture_snapshots_size_is_pinned_as_a_ceiling(payload: dict) -> None:
    """One Mac mini with 83 apps, as compact JSON: the number #241 asked to be measured
    rather than estimated, pinned so the next change to the most-multiplied object on the
    wire is loud. The `app` list is the bulk of it — ~268 bytes an item, ~204 for Jamf's
    seven fields and the rest for the two enrichment blocks and the wrapper."""
    total = len(_compact(payload))
    assert total <= SIZE_CEILING, f"the fixture snapshot grew to {total} bytes; say why in the PR"
    app_bytes = len(_compact(payload["app"]))
    assert app_bytes / len(payload["app"]) < 300
    # And it is most of the event: the other thirteen sections plus the head are small.
    assert app_bytes > total * 0.7


def test_the_observation_is_the_only_source_for_thirteen_sections(raw: dict, run: RunContext) -> None:
    """Why the builder reads the canonical observation rather than the row tables: no row
    holds `path`, `cfBundleShortVersionString`, `cfBundleVersion` or `macAppStore`, and
    thirteen sections have no row table at all. The snapshot must therefore agree with
    the ledger's canonical bodies byte for byte, which is what lets a `device.inventory`
    sub-event and a `device.change` derived from the same span join on equal strings."""
    observation = canonicalize_computer(raw)
    payload = _snapshot(raw)
    for section, content in observation.sections.items():
        if content.is_list or section == "extension_attributes":
            continue
        assert payload[SECTION_WRAPPERS[section]] == content.body
    certs = [item["cert"] for item in payload["cert"]]
    assert certs == [entry.body for entry in observation.sections["certificates"].entries]
    assert isinstance(observation, Observation) and isinstance(observation.sections["general"], SectionContent)
