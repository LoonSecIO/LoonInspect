"""Jamf Patch matching against the real device record and a real slice of the catalog.

`tests/fixtures/jamf/patch_titles_subset.json` is 51 titles copied from the catalog as synced on
2026-08-22 — every title that names a bundle ID the real Mac mini carries, the sixteen Wireshark
titles among them, plus the 1Password line, Ableton, Firefox, PyCharm, two device-level
"Apple macOS" titles and a few more — with each title's patch list trimmed to its first 25
entries plus any version the device has installed. The expectations below are the dry run the
matcher was designed from: 12 of the device's 83 apps resolve, 14 app-title rows.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.mdm.jamf.client import normalize_computer
from app.mdm.patch.matching import (
    BASIS_EA_ASSUMED,
    BASIS_REQUIREMENTS,
    STATE_AHEAD,
    STATE_BEHIND,
    STATE_LATEST,
    Catalog,
    TitleMatch,
    match_app,
    summarize,
)
from app.mdm.patch.requirements import Facts

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return Catalog.from_records(json.loads((FIXTURES / "patch_titles_subset.json").read_text()))


@pytest.fixture(scope="module")
def device_matches(catalog: Catalog) -> dict[str, list[TitleMatch]]:
    """app name -> matches, built exactly as process_sync builds the facts: the normalized
    app's version (Jamf's marketing version; short_version is null for Jamf) and the device's
    OS version and extension attributes."""
    raw = json.loads((FIXTURES / "computer_inventory_detail_real.json").read_text())
    device = normalize_computer(raw)
    extension_attributes = {ea.key: ea.value for ea in device.extension_attributes}
    result: dict[str, list[TitleMatch]] = {}
    for app in device.apps:
        facts = Facts(
            app_name=app.name,
            bundle_id=app.bundle_id,
            versions=tuple(v for v in (app.version, app.short_version) if v),
            os_version=device.os_version,
            extension_attributes=extension_attributes,
        )
        result[app.name] = match_app(facts, catalog)
    assert len(result) == 83
    return result


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class TestCatalogIndex:
    def test_device_level_titles_are_left_out(self, catalog: Catalog) -> None:
        names = {title.name for title in catalog.titles}
        assert "Apple macOS" not in names and "Apple macOS Catalina" not in names
        assert "Apple Xcode" in names

    def test_narrow_titles_are_reached_through_the_bundle_index(self, catalog: Catalog) -> None:
        wireshark = [title.name for title in catalog.candidates("org.wireshark.Wireshark")]
        assert "Wireshark 4.2" in wireshark and "Wireshark" in wireshark
        # The rolling TechSmith title tests `like com.techsmith.camtasia` and is broad; the
        # 2022 title pins its own bundle ID.
        broad = {title.name for title in catalog.broad}
        assert "TechSmith Camtasia" in broad and "TechSmith Camtasia 2022" not in broad
        # Attribute-only titles hang off their bundleId column, not the broad list.
        assert "Mozilla Firefox" not in broad
        assert "Mozilla Firefox" in [title.name for title in catalog.candidates("org.mozilla.firefox")]


class TestRealDevice:
    def test_twelve_apps_resolve_to_fourteen_rows(self, device_matches) -> None:
        matched = {name: matches for name, matches in device_matches.items() if matches}
        assert sorted(matched) == [
            "BambuStudio.app", "Camtasia 2022.app", "Codex.app", "Docker.app", "Postman.app", "PyCharm.app",
            "Safari.app", "Self Service.app", "Slack.app", "Wireshark.app", "Xcode.app", "zoom.us.app",
        ]
        assert sum(len(matches) for matches in matched.values()) == 14

    def test_xcode_is_on_the_latest(self, device_matches) -> None:
        (match,) = device_matches["Xcode.app"]
        assert match.title.name == "Apple Xcode" and match.basis == BASIS_REQUIREMENTS
        assert match.state == STATE_LATEST and match.on_latest and match.version_known
        assert match.latest_version == "26.6" and match.latest_released_at == _ts("2026-06-25T23:45:58Z")
        summary = summarize(device_matches["Xcode.app"])
        assert summary.is_compliant is True and summary.patch_available is False
        assert summary.title_ids == ["0C3"] and summary.state == STATE_LATEST

    def test_slack_is_behind_with_both_dates_from_jamf(self, device_matches) -> None:
        (match,) = device_matches["Slack.app"]
        assert match.title.name == "Slack" and match.state == STATE_BEHIND and match.version_known
        assert match.installed_version == "4.50.143" and match.installed_released_at == _ts("2026-06-24T20:00:15Z")
        assert match.latest_version == "4.51.191" and match.latest_released_at == _ts("2026-08-17T19:10:13Z")
        assert match.first_newer_released_at is not None
        assert match.installed_released_at < match.first_newer_released_at <= match.latest_released_at
        summary = summarize(device_matches["Slack.app"])
        assert summary.patch_available is True and summary.is_compliant is False
        assert summary.patch_available_since == match.first_newer_released_at

    def test_wireshark_resolves_to_its_line_and_the_rolling_title_only(self, device_matches) -> None:
        """Sixteen titles share org.wireshark.Wireshark; `Application Version like "4.2."`
        picks the line, and the rolling "Wireshark" title matches on the bundle ID alone."""
        matches = device_matches["Wireshark.app"]
        assert {m.title.id for m in matches} == {"5F6", "612"}
        assert all(m.basis == BASIS_REQUIREMENTS and m.state == STATE_BEHIND and m.version_known for m in matches)
        summary = summarize(matches)
        assert summary.title_ids == ["612", "5F6"]  # by name: "Wireshark" sorts before "Wireshark 4.2"
        assert summary.latest_version == "4.6.8" and summary.state == STATE_BEHIND

    def test_camtasia_2022_is_latest_on_its_line_and_behind_the_rolling_title(self, device_matches) -> None:
        """Both answers are kept; the summary follows Kyle's rule — at least one title says
        latest, so the app is latest (on its line), and no patch is "available"."""
        by_id = {m.title.id: m for m in device_matches["Camtasia 2022.app"]}
        assert set(by_id) == {"514", "608"}
        assert by_id["514"].state == STATE_LATEST and by_id["514"].latest_version == "2022.6.10"
        assert by_id["608"].state == STATE_BEHIND and by_id["608"].latest_version == "2026.2.0"
        summary = summarize(list(by_id.values()))
        assert summary.state == STATE_LATEST and summary.latest_version == "2022.6.10"
        assert summary.is_compliant is True and summary.patch_available is False and summary.this_version_seen is True
        assert summary.patch_available_since is None and summary.title_ids == ["608", "514"]

    def test_safari_on_the_beta_is_ahead_of_the_catalog(self, device_matches) -> None:
        (match,) = device_matches["Safari.app"]
        assert match.title.name == "Apple Safari" and match.state == STATE_AHEAD
        assert match.version_known is False and match.latest_version == "26.6.2"
        summary = summarize([match])
        assert summary.this_version_seen is False and summary.is_compliant is False and summary.patch_available is False

    def test_pycharm_resolves_its_scoping_attribute_as_true(self, device_matches) -> None:
        """JetBrains PyCharm Unified's only requirement is an extension attribute (Jamf's way
        of telling Professional from Community). The device does not carry it: resolved TRUE,
        the title identified by its bundleId column, the assumption recorded in the basis."""
        (match,) = device_matches["PyCharm.app"]
        assert match.title.name == "JetBrains PyCharm Unified" and match.basis == BASIS_EA_ASSUMED
        assert match.state == STATE_BEHIND and match.version_known

    def test_self_service_matches_through_a_like_test_the_column_would_miss(self, device_matches) -> None:
        """The title's bundleId column is `com.jamfsoftware.selfservice`; the app's is
        `com.jamfsoftware.selfservice.mac`. A join on the column misses it; the requirement is
        `Application Bundle ID like com.jamfsoftware.selfservice` and finds it."""
        (match,) = device_matches["Self Service.app"]
        assert match.title.name == "Jamf Self Service for macOS"
        assert match.title.bundle_id == "com.jamfsoftware.selfservice" and match.title.required_bundle_ids is None
        assert match.basis == BASIS_REQUIREMENTS and match.state == STATE_BEHIND

    def test_zoom_with_a_parenthesised_build_is_seen(self, device_matches) -> None:
        (match,) = device_matches["zoom.us.app"]
        assert match.installed_version == "7.0.5 (81138)" and match.version_known and match.state == STATE_BEHIND
        assert match.latest_version == "7.1.5 (84650)"

    def test_system_apps_match_nothing(self, device_matches) -> None:
        assert device_matches["Safari.app"]  # the one Apple app with a title
        for name in ("Calculator.app", "Mail.app", "Finder.app"):
            if name in device_matches:
                assert device_matches[name] == []


class TestExtensionAttributes:
    def test_firefox_assumed_read_or_ruled_out(self, catalog: Catalog) -> None:
        firefox = Facts(app_name="Firefox.app", bundle_id="org.mozilla.firefox", versions=("154.0",))
        # No attribute on the device: resolved TRUE, identified by the bundleId column.
        (match,) = match_app(firefox, catalog)
        assert match.title.name == "Mozilla Firefox" and match.basis == BASIS_EA_ASSUMED and match.state == STATE_LATEST
        # The attribute under Jamf Pro's display name: the requirement names the key, the
        # definition maps one to the other — read for real.
        named = Facts(**{**firefox.__dict__, "extension_attributes": {"Mozilla Firefox Version": "154.0"}})
        (match,) = match_app(named, catalog)
        assert match.basis == BASIS_REQUIREMENTS and match.state == STATE_LATEST
        # The attribute present and empty: Jamf's "not installed" — read for real, no match.
        empty = Facts(**{**firefox.__dict__, "extension_attributes": {"jamf-patch-mozilla-firefox": ""}})
        assert match_app(empty, catalog) == []
        # A different app never reaches an attribute-only title: its bundleId column is the test.
        chrome = Facts(app_name="Google Chrome.app", bundle_id="com.google.Chrome", versions=("151.0.7922.174",))
        assert [m.title.name for m in match_app(chrome, catalog)] == ["Google Chrome"]

    def test_an_attribute_only_group_never_identifies_an_app_by_itself(self, catalog: Catalog, device_matches) -> None:
        """JetBrains PyCharm Community is `[attribute is not ""] OR [Bundle ID is
        com.jetbrains.pycharm.ce]`. The attribute group is device scoping: it must not make the
        title match Xcode (or anything else) — the bundle group decides."""
        assert [m.title.name for m in device_matches["Xcode.app"]] == ["Apple Xcode"]
        community = Facts(app_name="PyCharm CE.app", bundle_id="com.jetbrains.pycharm.ce", versions=("2025.2.6.1",))
        (match,) = match_app(community, catalog)
        assert match.title.name == "JetBrains PyCharm Community" and match.basis == BASIS_REQUIREMENTS
        assert match.state == STATE_LATEST

    def test_attribute_only_titles_without_a_bundle_id_are_the_agents(self, catalog: Catalog) -> None:
        names = {title.name for title in catalog.titles}
        assert "Node.js 14" not in names and "Eclipse Temurin (JRE) 19" not in names
        firefox = next(title for title in catalog.titles if title.name == "Mozilla Firefox")
        assert firefox.attribute_only and firefox.attribute_names == {"jamf-patch-mozilla-firefox", "mozilla firefox version"}
        slack = next(title for title in catalog.titles if title.name == "Slack")
        assert not slack.attribute_only and slack.attribute_names == frozenset()


class TestSummary:
    def test_no_matches_means_no_summary(self) -> None:
        assert summarize([]) is None
