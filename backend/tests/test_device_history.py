"""Truthful history values and policy eligibility independent of the database (#605)."""

from app.api.device_history import choices_for, value_for
from app.changes.policy import EffectivePolicy, Overrides
from app.observations.history_capture import assessment_totals


def test_counts_are_uncapped_build_finding_pairs_and_unknown_is_not_zero():
    def app(version, total, critical):
        return {
            "app": {"name": "Browser", "bundleId": "org.browser", "version": version},
            "vuln": {
                "assessment": "covered",
                "corpusAsOf": "2026-09-20",
                "vulnIDs": ["CVE-1"],
                "vulnIDsTruncated": True,
                "counts": {"total": total, "severity": {"critical": critical}},
            },
        }

    first = app("1", 50, 4)
    result = assessment_totals({"app": [first, first, app("2", 2, 1), {"app": {"name": "Unknown"}}]})
    assert result == {"total": 52, "critical": 5, "covered": 2, "outside": 1, "corpus": ["2026-09-20"]}
    assert assessment_totals({})["total"] is None
    assert assessment_totals({"app": [{"app": {}, "vuln": {"assessment": "off"}}]})["critical"] is None
    assert assessment_totals({"app": [app("3", 0, 0)]})["total"] == 0


def test_policy_limits_scalar_and_entry_choices_and_metrics():
    policy = EffectivePolicy(
        Overrides(
            fields={"security.firewallEnabled": False}, entries={"application.version": False}, muted_extension_attributes=("7",)
        )
    )
    docs = {
        "applications": [
            {"name": "Browser", "bundleId": "org.browser", "path": "/Applications/Browser.app"},
            {"name": "System", "path": "/System/Applications/System.app"},
        ],
        "extension_attributes": [{"definitionId": "7", "values": ["secret"]}],
    }
    choices = choices_for(docs, policy, 1)
    assert not choices["security.firewallEnabled"]["enabled"]
    assert all(not c["enabled"] for c in choices.values() if c.get("field") == "version" and c.get("kind"))
    assert all(not c["enabled"] for c in choices.values() if c.get("kind") == "extension_attribute")
    policy = EffectivePolicy(Overrides(entries={"application.removed": False}))
    assert not choices_for({}, policy, 1)["applications.count"]["enabled"]


def test_absence_zero_false_and_multiversion_remain_distinct():
    choices = choices_for({}, EffectivePolicy(), 1)
    firewall = choices["security.firewallEnabled"]
    assert value_for(firewall, {"security": {"firewallEnabled": False}}, [], None, 1) == {"state": "present", "value": False}
    assert value_for(firewall, {}, ["security"], None, 1)["state"] == "not_observed"
    assert value_for(firewall, {}, [], None, 1)["state"] == "outside_aperture"
    assert value_for(choices["applications.count"], {"applications": []}, [], None, 1)["value"] == 0
    assert value_for(choices["findings.total"], {"applications": []}, [], None, 1)["state"] == "not_recorded"
    docs = {"applications": [{"name": "B", "version": "1"}, {"name": "B", "version": "2"}]}
    choice = next(
        c for c in choices_for(docs, EffectivePolicy(), 1).values() if c.get("kind") == "application" and c["field"] == "version"
    )
    assert value_for(choice, docs, [], None, 1)["value"] == ["1", "2"]


def test_extension_attribute_selection_survives_rename_and_shows_first_value():
    policy = EffectivePolicy()
    docs = {"extension_attributes": [{"definitionId": "42", "_label": "Old name", "values": ["first", "second"]}]}
    choice = next(c for c in choices_for(docs, policy, 7).values() if c.get("kind") == "extension_attribute")
    docs["extension_attributes"][0]["_label"] = "New name"
    renamed = choices_for(docs, policy, 7)[choice["key"]]
    assert renamed["name"] == "New name" and renamed["identity"] == {"definitionId": "42"}
    assert value_for(renamed, docs, [], None, 7)["value"] == "first"
    other = next(c for c in choices_for(docs, policy, 8).values() if c.get("kind") == "extension_attribute")
    assert other["key"] != choice["key"]


def test_last_check_in_uses_only_the_recorded_clock():
    choice = choices_for({}, EffectivePolicy(), 1)["observation.lastCheckIn"]
    assert choice["enabled"]
    assert value_for(choice, {}, [], None, 1)["state"] == "not_recorded"
    assert value_for(choice, {}, [], {"lastCheckIn": "2026-09-20T12:00:00Z"}, 1)["value"] == "2026-09-20T12:00:00Z"
