"""`app.changes.diff`: two observations in, changes out — pure, on the real record.

The engine knows nothing about policy; it must see everything and pair entries by
identity so a version bump is one `updated`, not a removal plus an addition.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from app.changes.diff import Entry, diff_entries, diff_scalar, flatten
from app.mdm.jamf import contract as c

REAL = Path(__file__).parent / "fixtures" / "jamf" / "computer_inventory_detail_real.json"


@pytest.fixture
def real() -> dict:
    return json.loads(REAL.read_text())


def _entries(observation: c.Observation, section: str) -> list[Entry]:
    return [Entry(digest=e.digest, body=e.body, label=e.label) for e in observation.sections[section].entries]


def test_flatten_dotted_paths_and_lists_as_leaves() -> None:
    assert flatten({"a": {"b": 1, "c": {"d": "x"}}, "e": [1, 2]}) == {"a.b": 1, "a.c.d": "x", "e": [1, 2]}
    assert flatten(None) == {}


def test_scalar_diff_reports_each_leaf_once(real: dict) -> None:
    before = c.canonicalize_computer(real)
    real["security"]["firewallEnabled"] = True
    real["security"]["remoteDesktopEnabled"] = True
    real["general"]["name"] = "renamed"
    after = c.canonicalize_computer(real)

    security = diff_scalar("security", before.sections["security"].body, after.sections["security"].body)
    assert {(d.field, d.old, d.new) for d in security} == {
        ("firewallEnabled", False, True),
        ("remoteDesktopEnabled", False, True),
    }
    general = diff_scalar("general", before.sections["general"].body, after.sections["general"].body)
    assert [(d.field, d.old, d.new) for d in general] == [("name", "Loon’s Mac mini", "renamed")]


def test_scalar_diff_sees_absence_both_ways(real: dict) -> None:
    before = c.canonicalize_computer(real)
    real["general"]["assetTag"] = "LOON-7"  # was null → absent
    after = c.canonicalize_computer(real)
    changes = diff_scalar("general", before.sections["general"].body, after.sections["general"].body)
    assert [(d.field, d.old, d.new) for d in changes] == [("assetTag", None, "LOON-7")]


def test_an_app_version_bump_is_one_update(real: dict) -> None:
    before = c.canonicalize_computer(real)
    slack = next(a for a in real["applications"] if a["bundleId"] == "com.tinyspeck.slackmacgap")
    slack["version"] = slack["cfBundleShortVersionString"] = "4.51.0"
    slack["cfBundleVersion"] = "451000000"
    after = c.canonicalize_computer(real)

    changes = diff_entries(
        "applications", "application", ("name", "bundleId", "path"),
        _entries(before, "applications"), _entries(after, "applications"),
    )
    assert len(changes) == 1
    change = changes[0]
    assert change.change == "updated"
    assert change.identity == {"name": "Slack.app", "bundleId": "com.tinyspeck.slackmacgap", "path": "/Applications/Slack.app"}
    assert change.changed_fields == ("cfBundleShortVersionString", "cfBundleVersion", "version")
    assert change.old["version"] == "4.50.143" and change.new["version"] == "4.51.0"


def test_added_and_removed_apps(real: dict) -> None:
    before = c.canonicalize_computer(real)
    real["applications"] = [a for a in real["applications"] if a["bundleId"] != "org.wireshark.Wireshark"]
    real["applications"].append(
        {
            "name": "Ghostty.app", "path": "/Applications/Ghostty.app", "version": "1.1",
            "bundleId": "com.mitchellh.ghostty", "macAppStore": False,
        }
    )
    after = c.canonicalize_computer(real)
    changes = diff_entries(
        "applications", "application", ("name", "bundleId", "path"),
        _entries(before, "applications"), _entries(after, "applications"),
    )
    assert [(ch.change, ch.identity["bundleId"]) for ch in changes] == [
        ("removed", "org.wireshark.Wireshark"),
        ("added", "com.mitchellh.ghostty"),
    ]


def test_account_admin_flip_is_an_update_with_the_field_named(real: dict) -> None:
    before = c.canonicalize_computer(real)
    account = next(a for a in real["localUserAccounts"] if a["username"] == "loonuser")
    account["admin"] = False
    after = c.canonicalize_computer(real)
    changes = diff_entries(
        "local_user_accounts", "local_user_account", ("uid", "username"),
        _entries(before, "local_user_accounts"), _entries(after, "local_user_accounts"),
    )
    assert len(changes) == 1 and changes[0].change == "updated"
    assert changes[0].changed_fields == ("admin",)
    assert changes[0].identity == {"uid": "501", "username": "loonuser"}


def test_group_membership_uses_group_id_and_keeps_the_label(real: dict) -> None:
    before = c.canonicalize_computer(real)
    real["groupMemberships"].append({"groupId": "12", "groupName": "Devices out of Checkin Compliance", "smartGroup": True})
    after = c.canonicalize_computer(real)
    changes = diff_entries(
        "group_memberships", "group_membership", ("groupId",),
        _entries(before, "group_memberships"), _entries(after, "group_memberships"),
    )
    assert [(ch.change, ch.identity, ch.label) for ch in changes] == [
        ("added", {"groupId": "12"}, "Devices out of Checkin Compliance")
    ]


def test_extension_attribute_value_change_is_an_update(real: dict) -> None:
    before = c.canonicalize_computer(real)
    ea = next(e for e in real["extensionAttributes"] if e["definitionId"] == "2")
    ea["values"] = ["True"]
    after = c.canonicalize_computer(real)
    changes = diff_entries(
        "extension_attributes", "extension_attribute", ("definitionId",),
        _entries(before, "extension_attributes"), _entries(after, "extension_attributes"),
    )
    assert len(changes) == 1
    assert changes[0].change == "updated" and changes[0].changed_fields == ("values",)
    assert changes[0].old == {"definitionId": "2"} and changes[0].new == {"definitionId": "2", "values": ["True"]}


def test_identical_observations_produce_no_changes(real: dict) -> None:
    before = c.canonicalize_computer(real)
    after = c.canonicalize_computer(copy.deepcopy(real))
    for name, content in before.sections.items():
        if content.is_list:
            kind = c.SECTIONS[name].entry_kind or name
            assert diff_entries(name, kind, ("name",), _entries(before, name), _entries(after, name)) == []
        else:
            assert diff_scalar(name, content.body, after.sections[name].body) == []
