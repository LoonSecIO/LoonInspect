"""Extension attributes reach every path from all six of Jamf's arrays (#197).

Jamf reports a computer's extension attributes in six places: a top-level array and one
nested inside each of the five sections an admin can pick as an EA's inventory display.
The observation contract merged all six; the current-state normalizer read one, so every
EA displayed on a section tab — a Crowdstrike sensor version among them — was invisible
to the product and to the wire while the ledger recorded it changing. One hoist helper
now serves both, and these tests pin what it promises: every source with its `source`,
no stray array left behind, every value of a multi-value EA, an identity a rename cannot
move, a quarantine that holds on every path, and the aperture closure that stops the
section picker being a hidden EA picker. Pure; no database.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.mdm.jamf import contract as c
from app.mdm.jamf.client import normalize_computer
from app.schemas.payload import NormalizedDevice, NormalizedExtensionAttribute

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"


@pytest.fixture
def raw() -> dict:
    return json.loads((FIXTURES / "computer_inventory_detail.json").read_text())


@pytest.fixture
def real() -> dict:
    return json.loads((FIXTURES / "computer_inventory_detail_real.json").read_text())


# The five display sections by Jamf's response key, and the EA the synthetic fixture
# nests under each — the table from #197.
NESTED = {
    "general": ("12", "Crowdstrike Sensor Version", ["7.18.18805.0"]),
    "hardware": ("9", "Uptime Days", ["13"]),
    "operatingSystem": ("22", "Last OS Update Check", ["2026-08-20"]),
    "userAndLocation": ("18", "Manager", ["charles@example.com"]),
    "purchasing": ("31", "Cost Center", ["CC-4410"]),
}


def _by_id(device: NormalizedDevice) -> dict[str, NormalizedExtensionAttribute]:
    assert device.extension_attributes is not None
    return {ea.definition_id: ea for ea in device.extension_attributes}


# --- the hoist: six sources, one list, each item stamped ----------------------------


def test_an_ea_nested_under_each_of_the_five_sections_reaches_the_normalized_view(raw: dict) -> None:
    eas = _by_id(normalize_computer(raw))
    for source, (definition_id, name, values) in NESTED.items():
        ea = eas[definition_id]
        assert (ea.name, ea.values, ea.source) == (name, values, source)
    # The top-level array is a source like any other, named by its own key.
    assert eas["5"].source == "extensionAttributes" and eas["27"].source == "extensionAttributes"
    assert len(eas) == 7


def test_the_crowdstrike_sensor_version_is_no_longer_dropped(raw: dict) -> None:
    """The worst case #197 names: a security product silently losing the EDR sensor
    version because the admin displayed it under General."""
    device = normalize_computer(raw)
    assert device.extension_attributes is not None
    assert any(ea.name == "Crowdstrike Sensor Version" for ea in device.extension_attributes)


def test_the_hoist_leaves_no_section_carrying_an_extension_attributes_array(raw: dict) -> None:
    hoist = c.hoist_extension_attributes(raw, sections=c.V0_SECTIONS)
    assert "extensionAttributes" not in hoist.computer
    for key, value in hoist.computer.items():
        if isinstance(value, dict):
            assert "extensionAttributes" not in value, key
    # The caller's record is untouched: the contract reads the same object afterwards.
    assert "extensionAttributes" in raw and "extensionAttributes" in raw["hardware"]


def test_the_hoist_is_discovery_driven_not_a_list_of_five(raw: dict) -> None:
    """A display section Jamf adds later is found and named, not silently dropped — and
    not merged either: a sweep cannot request a section the contract cannot name, so
    admitting it would make a detail fetch disagree with a sweep page."""
    raw["licensing"] = {"extensionAttributes": [{"definitionId": "99", "name": "Seat", "values": ["1"]}]}
    hoist = c.hoist_extension_attributes(raw, sections=c.V0_SECTIONS)
    assert "99" not in {hoisted.item["definitionId"] for hoisted in hoist.items}
    assert hoist.unadmitted == ("licensing",)
    assert "extensionAttributes" not in hoist.computer["licensing"]


def test_nothing_is_admitted_or_reported_when_extension_attributes_were_not_requested(raw: dict) -> None:
    hoist = c.hoist_extension_attributes(raw, sections=("general", "applications"))
    assert hoist.items == () and hoist.unadmitted == ()
    assert "extensionAttributes" not in hoist.computer and "extensionAttributes" not in hoist.computer["general"]
    assert normalize_computer(raw, ("general", "applications")).extension_attributes is None


def test_the_wire_object_is_jamfs_verbatim_plus_source(raw: dict) -> None:
    """Jamf's keys under Jamf's spellings, and exactly one minted key (#188: a vendor's
    native key keeps the vendor's casing; `source` is LoonInspect's)."""
    ea = _by_id(normalize_computer(raw))["12"]
    assert ea.model_dump(by_alias=True) == {
        "definitionId": "12",
        "name": "Crowdstrike Sensor Version",
        "description": "Falcon sensor version from falconctl",
        "enabled": True,
        "multiValue": False,
        "values": ["7.18.18805.0"],
        "dataType": "STRING",
        "options": [],
        "inputType": "SCRIPT",
        "source": "general",
    }


# --- the three defects fixed alongside ----------------------------------------------


def test_a_multi_value_ea_survives_with_all_its_values(raw: dict) -> None:
    ea = _by_id(normalize_computer(raw))["27"]
    assert ea.multi_value is True and ea.values == ["Research", "Engineering"]


def test_renaming_an_ea_does_not_change_its_key(raw: dict) -> None:
    before = _by_id(normalize_computer(raw))["12"]
    raw["general"]["extensionAttributes"][0]["name"] = "Falcon Sensor (renamed)"
    after = _by_id(normalize_computer(raw))["12"]
    assert after.definition_id == before.definition_id
    assert after.name == "Falcon Sensor (renamed)" and after.values == before.values


def test_a_disabled_definition_still_reports_and_says_so(raw: dict) -> None:
    """Ruled with #197: a definition the admin disabled still holds a value on the
    device, and hiding it would be the silent drop this work ends. The flag rides so a
    consumer can tell a live value from a frozen one."""
    raw["hardware"]["extensionAttributes"][0]["enabled"] = False
    ea = _by_id(normalize_computer(raw))["9"]
    assert ea.enabled is False and ea.values == ["13"]


def test_an_unanswered_ea_is_still_an_item(real: dict) -> None:
    """Defined on the server, no value on the device: present with an empty list, so a
    first value later is a change and not an appearance — the ledger's rule, kept."""
    eas = _by_id(normalize_computer(real))
    assert set(eas) == {"1", "2", "3"}
    assert eas["1"].values == [] and eas["1"].source == "general"
    assert eas["2"].options == ["True", "False"] and eas["2"].input_type == "POPUP"


def test_an_item_without_a_definition_id_is_not_an_extension_attribute(raw: dict) -> None:
    raw["extensionAttributes"].append({"name": "orphan", "values": ["x"]})
    raw["extensionAttributes"].append("not even an object")
    assert set(_by_id(normalize_computer(raw))) == {"5", "27", "12", "9", "22", "18", "31"}


# --- quarantine: absent from every path ---------------------------------------------


def test_a_quarantined_ea_is_absent_from_every_path(raw: dict) -> None:
    quarantined = ["9"]
    ledger = c.canonicalize_computer(raw, quarantined_extension_attributes=quarantined)
    assert "Uptime Days" not in {e.label for e in ledger.sections["extension_attributes"].entries}
    view = normalize_computer(raw, quarantined_extension_attributes=quarantined)
    assert view.extension_attributes is not None
    assert "9" not in _by_id(view)
    assert "Uptime Days" not in {ea.name for ea in view.extension_attributes}
    # Without the quarantine the same record carries it on both.
    assert "9" in _by_id(normalize_computer(raw))


# --- one helper, both paths ---------------------------------------------------------


def test_the_contract_and_the_normalizer_agree_on_the_set_of_eas(raw: dict, real: dict) -> None:
    for record in (raw, real):
        ledger = {
            entry.body["definitionId"]
            for entry in c.canonicalize_computer(record).sections["extension_attributes"].entries
        }
        assert set(_by_id(normalize_computer(record))) == ledger


def test_source_is_carried_by_the_view_and_discarded_by_the_contract(raw: dict) -> None:
    """The deliberate tension, written down so nobody reconciles it: moving an EA between
    display sections changes the wire event and no span."""
    before = c.canonicalize_computer(raw).section_digests
    moved = raw["hardware"]["extensionAttributes"].pop()
    raw["extensionAttributes"].append(moved)
    assert c.canonicalize_computer(raw).section_digests == before
    assert _by_id(normalize_computer(raw))["9"].source == "extensionAttributes"


# --- the aperture: asking for EAs reads their carriers ------------------------------


def test_the_carriers_are_the_five_display_sections() -> None:
    assert c.EXTENSION_ATTRIBUTE_CARRIERS == (
        "general", "hardware", "operating_system", "user_and_location", "purchasing",
    )
    assert all(name in c.SECTIONS for name in c.EXTENSION_ATTRIBUTE_CARRIERS)


def test_requesting_extension_attributes_pulls_in_their_carriers() -> None:
    closed = c.with_extension_attribute_carriers(["applications", "extension_attributes"])
    assert closed == ("applications", "extension_attributes", *c.EXTENSION_ATTRIBUTE_CARRIERS)
    # Idempotent, order-preserving, a no-op without EAs, and it drops nothing it does
    # not know — canonicalize_computer is where an unknown section is refused.
    assert c.with_extension_attribute_carriers(closed) == closed
    assert c.with_extension_attribute_carriers(["security", "applications"]) == ("security", "applications")
    assert c.with_extension_attribute_carriers(c.V0_SECTIONS) == tuple(c.V0_SECTIONS)
    assert c.with_extension_attribute_carriers(["fonts", "extension_attributes"])[0] == "fonts"


def test_a_collection_saved_with_eas_reads_their_carriers() -> None:
    """The save-time half: the row the editor shows is the set that is fetched."""
    from app.api.collections import _validate_scope
    from app.models.schema import Collection

    collection = Collection(
        kind="device_sweep", sections=["extension_attributes", "applications"], quarantined_extension_attributes=[]
    )
    _validate_scope(collection)
    assert collection.sections == ["extension_attributes", "applications", *c.EXTENSION_ATTRIBUTE_CARRIERS]
    narrow = Collection(kind="webhook", sections=["applications"], quarantined_extension_attributes=[])
    _validate_scope(narrow)
    assert narrow.sections == ["applications"]


def test_the_view_under_a_closed_aperture_carries_every_nested_ea(raw: dict) -> None:
    """What the closure buys: a collection that asked for applications and EAs — and
    nothing else — still sees the purchasing-displayed Cost Center."""
    sections = c.with_extension_attribute_carriers(["applications", "extension_attributes"])
    assert "31" in _by_id(normalize_computer(raw, sections))
    # Without it the same request silently lost five of seven — the bug. The sections
    # that carried them are named rather than merged.
    hoist = c.hoist_extension_attributes(raw, sections=("applications", "extension_attributes"))
    assert {hoisted.item["definitionId"] for hoisted in hoist.items} == {"5", "27"}
    assert set(hoist.unadmitted) == {"general", "hardware", "operatingSystem", "userAndLocation", "purchasing"}
