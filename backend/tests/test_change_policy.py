"""`app.changes.policy`: the defaults an admin inherits and the overrides they can make.

The level decides the default (high + normal on, low off); overrides are sparse. These
tests pin the defaults that were reasoned from the real record, the override
precedence, and the describe() document the UI renders.
"""

from __future__ import annotations

from app.changes import policy as p
from app.mdm.jamf.contract import SECTIONS


def test_every_scalar_rule_names_a_contract_section() -> None:
    sections = set(SECTIONS) | {"definition"}
    for rule in p.FIELD_RULES:
        assert rule.section in sections, rule.key
    for rule in p.ENTRY_RULES:
        assert rule.section in SECTIONS and SECTIONS[rule.section].entry_kind == rule.kind


def test_defaults_follow_the_level() -> None:
    policy = p.EffectivePolicy()
    assert policy.field_enabled("security", "firewallEnabled") is True  # high
    assert policy.field_enabled("general", "name") is True  # normal
    assert policy.field_enabled("purchasing", "poNumber") is False  # low
    assert policy.field_enabled("hardware", "altMacAddress") is False  # low: docks
    assert policy.field_enabled("security", "xprotectVersion") is False  # low: fleet-wide weekly
    assert policy.entry_enabled("application", "added") is True
    assert policy.entry_enabled("application", "updated", "version") is True
    assert policy.entry_enabled("application", "updated", "macAppStore") is False
    assert policy.entry_enabled("local_user_account", "updated", "admin") is True
    assert policy.entry_enabled("local_user_account", "updated", "fullName") is False
    assert policy.entry_enabled("software_update", "added") is False
    assert policy.system_apps_individually is False


def test_the_security_posture_is_all_high() -> None:
    for rule in p.FIELD_RULES:
        if rule.section == "security" and rule.field != "xprotectVersion":
            assert rule.level == p.HIGH, rule.key
        if rule.section == "disk_encryption" and rule.field not in (
            "bootPartitionEncryptionDetails.partitionName",
            "diskEncryptionConfigurationName",
            "fileVault2EligibilityMessage",
        ):
            assert rule.level == p.HIGH, rule.key


def test_minimum_level_is_the_preset() -> None:
    high_only = p.EffectivePolicy(p.Overrides(minimum_level="high"))
    assert high_only.field_enabled("security", "firewallEnabled") is True
    assert high_only.field_enabled("general", "name") is False
    assert high_only.entry_enabled("application", "added") is False
    assert high_only.entry_enabled("local_user_account", "added") is True

    everything = p.EffectivePolicy(p.Overrides(minimum_level="low"))
    assert everything.field_enabled("purchasing", "poNumber") is True
    assert everything.entry_enabled("software_update", "added") is True


def test_overrides_win_over_the_level() -> None:
    policy = p.EffectivePolicy(
        p.Overrides(
            fields={"purchasing.poNumber": True, "security.firewallEnabled": False},
            entries={"application.added": False, "local_user_account.fullName": True, "certificate": False},
        )
    )
    assert policy.field_enabled("purchasing", "poNumber") is True
    assert policy.field_enabled("security", "firewallEnabled") is False
    assert policy.entry_enabled("application", "added") is False
    assert policy.entry_enabled("application", "removed") is True
    assert policy.entry_enabled("local_user_account", "updated", "fullName") is True
    assert policy.entry_enabled("certificate", "added") is False  # whole kind off
    assert policy.entry_enabled("certificate", "removed") is False


def test_unknown_field_defaults_to_normal() -> None:
    """A contract field the policy does not name yet must not drop on the floor."""
    policy = p.EffectivePolicy()
    assert policy.field_enabled("general", "someNewContractField") is True
    assert p.EffectivePolicy(p.Overrides(minimum_level="high")).field_enabled("general", "someNewContractField") is False


def test_overrides_document_round_trips_and_ignores_garbage() -> None:
    document = {
        "minimumLevel": "high",
        "fields": {"general.name": True},
        "entries": {"application": False},
        "systemAppsIndividually": True,
        "mutedGroups": ["12", 13],
        "mutedExtensionAttributes": ["9"],
    }
    overrides = p.Overrides.from_document(document)
    assert overrides.minimum_level == "high"
    assert overrides.muted_groups == ("12", "13")
    assert overrides.to_document()["mutedGroups"] == ["12", "13"]
    assert p.Overrides.from_document({"minimumLevel": "bogus"}).minimum_level == p.DEFAULT_MINIMUM_LEVEL
    assert p.Overrides.from_document(None).to_document()["fields"] == {}


def test_describe_lists_every_rule_with_default_and_override_state() -> None:
    policy = p.EffectivePolicy(p.Overrides(fields={"purchasing.poNumber": True}))
    document = policy.describe()
    assert document["version"] == p.CHANGE_POLICY_VERSION
    by_key = {f["key"]: f for s in document["sections"] for f in s["fields"]}
    assert by_key["purchasing.poNumber"] == {
        "key": "purchasing.poNumber", "field": "poNumber", "label": "PO number", "level": "low",
        "why": "Procurement metadata.", "default": False, "enabled": True, "overridden": True,
    }
    assert by_key["security.firewallEnabled"]["enabled"] is True and by_key["security.firewallEnabled"]["overridden"] is False
    apps = next(e for e in document["entries"] if e["kind"] == "application")
    assert apps["added"] is True and any(f["name"] == "macAppStore" and f["enabled"] is False for f in apps["fields"])


def test_system_app_detection() -> None:
    assert p.is_system_app({"path": "/System/Applications/Mail.app"}) is True
    assert p.is_system_app({"path": "/Applications/Slack.app"}) is False
    assert p.is_system_app({}) is False
