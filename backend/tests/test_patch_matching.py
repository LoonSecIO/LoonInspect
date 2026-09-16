"""Jamf Patch matching against the real device record and a real slice of the catalog.

`tests/fixtures/jamf/patch_titles_subset.json` is 51 titles copied from the catalog as synced on
2026-08-22 — every title that names a bundle ID the real Mac mini carries, the sixteen Wireshark
titles among them, plus the 1Password line, Ableton, Firefox, PyCharm, two device-level
"Apple macOS" titles and a few more — with each title's patch list trimmed to its first 25
entries plus any version the device has installed. The expectations below are the dry run the
matcher was designed from: 12 of the device's 83 apps resolve, 14 app-title rows — 11 and 13
before #386 admitted the attribute-only titles that carry a `bundleId`, which is what brings
PyCharm (and, on a Mac that runs it, Firefox) an answer at all.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.catalog.index import build_rows
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
from app.mdm.patch.requirements import (
    DETECTION_EXTENSION_ATTRIBUTE,
    DETECTION_INVENTORY,
    PLATFORM_MAC,
    Facts,
    jamf_platform_name,
)

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return Catalog.from_records(json.loads((FIXTURES / "patch_titles_subset.json").read_text()))


def _device_facts() -> dict[str, Facts]:
    """app name -> the facts, built exactly as process_sync builds them: the normalized app's
    version (Jamf's marketing version; short_version is null for Jamf) and the device's OS
    version and extension attributes."""
    raw = json.loads((FIXTURES / "computer_inventory_detail_real.json").read_text())
    device = normalize_computer(raw)
    # Requirements name an attribute by its display name and compare one value; the
    # normalized item carries every value and the definition id beside it (#197).
    extension_attributes = {ea.name: (ea.values[0] if ea.values else None) for ea in device.extension_attributes if ea.name}
    return {
        app.name: Facts(
            app_name=app.name,
            bundle_id=app.bundle_id,
            versions=tuple(v for v in (app.version, app.short_version) if v),
            os_version=device.os_version,
            # Said, not defaulted (#236): the device is a Mac because the computer client
            # read it, and the evaluator no longer assumes so.
            platform=jamf_platform_name(device.platform),
            extension_attributes=extension_attributes,
        )
        for app in device.apps
    }


@pytest.fixture(scope="module")
def device_matches(catalog: Catalog) -> dict[str, list[TitleMatch]]:
    """app name -> matches, against the real slice of the catalog."""
    result = {name: match_app(facts, catalog) for name, facts in _device_facts().items()}
    assert len(result) == 83
    return result


class TestPlatform:
    """#236: the platform is a fact the caller states, and a known non-Mac one is unmatchable."""

    def test_the_default_is_unknown_and_the_computer_client_is_a_mac(self) -> None:
        assert Facts().platform is None
        assert jamf_platform_name("macos") == PLATFORM_MAC == "Mac"
        assert jamf_platform_name("ios") == "iOS" and jamf_platform_name(None) is None
        assert jamf_platform_name("android") is None, "an unknown spelling is unknown, not a Mac"

    def test_a_known_non_mac_platform_considers_no_titles(self, catalog: Catalog, device_matches) -> None:
        # Xcode matches title 0C3 on a Mac; the same name, bundle id and version on an iPad
        # matches nothing, because Jamf Patch has no iPad titles to consider.
        assert device_matches["Xcode.app"], "the Mac's own answer, unchanged"
        mac = Facts(app_name="Xcode.app", bundle_id="com.apple.dt.Xcode", versions=("16.4",), platform=PLATFORM_MAC)
        ipad = Facts(app_name="Xcode.app", bundle_id="com.apple.dt.Xcode", versions=("16.4",), platform="iPadOS")
        assert match_app(mac, catalog)
        assert match_app(ipad, catalog) == []

    def test_an_unknown_platform_is_still_judged(self, catalog: Catalog) -> None:
        # Unknown is not "not Mac": titles without a Platform criterion may still match, and
        # one with it reads NOT_APPLICABLE rather than passing on an assumption.
        unknown = Facts(app_name="Xcode.app", bundle_id="com.apple.dt.Xcode", versions=("16.4",))
        assert unknown.platform is None
        assert isinstance(match_app(unknown, catalog), list)


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


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

    def test_an_admitted_attribute_only_title_is_indexed_on_its_column(self, catalog: Catalog) -> None:
        """#386: an attribute test pins nothing, so `required_bundle_ids` is None for all 182 and
        they would land in `broad` — evaluated against every app on every Mac. Their identity IS
        the column, so they are reached through the bundle index like any pinned title."""
        assert "Mozilla Firefox" in {title.name for title in catalog.candidates("org.mozilla.firefox")}
        assert "Mozilla Firefox" not in {title.name for title in catalog.broad}


class TestRealDevice:
    def test_twelve_apps_resolve_to_fourteen_rows(self, device_matches) -> None:
        """Eleven and thirteen before #386; PyCharm is the twelfth and the fourteenth."""
        matched = {name: matches for name, matches in device_matches.items() if matches}
        assert sorted(matched) == [
            "BambuStudio.app",
            "Camtasia 2022.app",
            "Codex.app",
            "Docker.app",
            "Postman.app",
            "PyCharm.app",
            "Safari.app",
            "Self Service.app",
            "Slack.app",
            "Wireshark.app",
            "Xcode.app",
            "zoom.us.app",
        ]
        assert sum(len(matches) for matches in matched.values()) == 14

    def test_xcode_is_on_the_latest(self, device_matches) -> None:
        (match,) = device_matches["Xcode.app"]
        assert match.title.name == "Apple Xcode" and match.basis == BASIS_REQUIREMENTS
        assert match.state == STATE_LATEST and match.on_latest and match.version_known
        assert match.releases_missed == 0
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
        assert match.releases_missed and summary.releases_missed == match.releases_missed

    def test_wireshark_resolves_to_its_line_and_the_rolling_title_only(self, device_matches) -> None:
        """Sixteen titles share org.wireshark.Wireshark; `Application Version like "4.2."`
        picks the line, and the rolling "Wireshark" title matches on the bundle ID alone."""
        matches = device_matches["Wireshark.app"]
        assert {m.title.id for m in matches} == {"5F6", "612"}
        assert all(m.basis == BASIS_REQUIREMENTS and m.state == STATE_BEHIND and m.version_known for m in matches)
        summary = summarize(matches)
        assert summary.title_ids == ["612", "5F6"]  # by name: "Wireshark" sorts before "Wireshark 4.2"
        assert summary.latest_version == "4.6.8" and summary.state == STATE_BEHIND
        # #68's sentence: the date and the count come from one title — the 4.2 line, whose
        # 4.2.1 is the earliest miss — never from a fold across the two.
        by_id = {m.title.id: m for m in matches}
        assert by_id["5F6"].releases_missed == 14 and by_id["612"].releases_missed == 25
        assert summary.patch_available_since == by_id["5F6"].first_newer_released_at
        assert summary.releases_missed == 14

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
        assert summary.patch_available_since is None and summary.releases_missed is None
        assert summary.title_ids == ["608", "514"]

    def test_safari_on_the_beta_is_ahead_of_the_catalog(self, device_matches) -> None:
        (match,) = device_matches["Safari.app"]
        assert match.title.name == "Apple Safari" and match.state == STATE_AHEAD
        assert match.version_known is False and match.latest_version == "26.6.2"
        summary = summarize([match])
        assert summary.this_version_seen is False and summary.is_compliant is False and summary.patch_available is False

    def test_pycharm_is_admitted_on_its_bundle_id_and_flagged(self, device_matches, catalog: Catalog) -> None:
        """JetBrains PyCharm Unified's only requirement is an extension attribute (Jamf's way of
        telling Professional from Community). It has no identifying recon test, so before #386 it
        was not considered and this Mac's PyCharm had no answer at all. Admitted on the strength
        of its `bundleId` column, with the attribute assumed TRUE and `detection` saying the
        title is one Jamf detects on the device rather than in the inventory walk."""
        (match,) = device_matches["PyCharm.app"]
        assert match.title.name == "JetBrains PyCharm Unified"
        assert match.title.detection == DETECTION_EXTENSION_ATTRIBUTE
        assert match.basis == BASIS_EA_ASSUMED and match.installed_version == "2026.1.2"
        assert "JetBrains PyCharm Unified" in {title.name for title in catalog.titles}

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
    def test_firefox_matches_on_the_column_and_reads_the_attribute_when_carried(self, catalog: Catalog) -> None:
        """#386, the ruling's own example. Firefox's one requirement is
        `jamf-patch-mozilla-firefox is not ""`, so nothing in it identifies an app and the title
        had no rows and no answer. Admitted, it matches an installed Firefox by Jamf's `bundleId`
        column; the attribute goes on doing what #65 said it does — scoping — so an absent one
        resolves TRUE (`ea_assumed`) and a carried one is read for real."""
        firefox = Facts(app_name="Firefox.app", bundle_id="org.mozilla.firefox", versions=("154.0",))
        (match,) = match_app(firefox, catalog)
        assert match.title.name == "Mozilla Firefox" and match.basis == BASIS_EA_ASSUMED
        assert match.title.detection == DETECTION_EXTENSION_ATTRIBUTE and match.state == STATE_LATEST
        carried = Facts(**{**firefox.__dict__, "extension_attributes": {"Mozilla Firefox Version": "154.0"}})
        (match,) = match_app(carried, catalog)
        assert match.basis == BASIS_REQUIREMENTS  # the attribute is not empty: the test passes for real
        # The column is compared exactly, never as a prefix: nothing else narrows these titles.
        assert match_app(Facts(**{**firefox.__dict__, "bundle_id": "org.mozilla.firefox.nightly"}), catalog) == []
        chrome = Facts(app_name="Google Chrome.app", bundle_id="com.google.Chrome", versions=("151.0.7922.174",))
        assert [m.title.name for m in match_app(chrome, catalog)] == ["Google Chrome"]
        assert next(t for t in catalog.titles if t.name == "Google Chrome").detection == DETECTION_INVENTORY

    def test_an_ea_detected_title_reads_absent_until_the_attribute_is_read(self, device_matches) -> None:
        """Kyle's second half (#386): admission reaches Firefox, not Python. The real Mac runs
        Python 3.14 — `Python Launcher.app`, bundle ID `org.python.PythonLauncher` — and Jamf's
        "Python 3" title names `org.python.python`, a bundle ID no `.app` on any Mac reports,
        because a command-line Python is not something recon walks. So the title is admitted,
        enumerates its versions, and still matches nothing: the Mac reads *absent* with
        `detection: extension_attribute` until the EA value itself is read as the presence
        witness (docs/troubleshooting.md §6 step 5)."""
        title = {
            "id": "11A",
            "name": "Python 3",
            "bundleId": "org.python.python",
            "currentVersion": "3.14.0",
            "patches": [{"version": "3.14.0", "releaseDate": "2026-08-07T00:00:00Z"}],
            "requirements": [
                {
                    "operator": "and",
                    "tests": [{"name": "jamf-patch-python-3", "type": "extensionAttribute", "value": "|3.", "operator": "like"}],
                }
            ],
            "extensionAttributes": [{"key": "jamf-patch-python-3", "displayName": "Python 3 Bundle Version"}],
        }
        python = Catalog.from_records([title])
        (admitted,) = python.titles
        assert admitted.detection == DETECTION_EXTENSION_ATTRIBUTE and admitted.admitted
        assert [row["version"] for row in build_rows(python)] == ["3.14.0"]
        assert all(match_app(facts, python) == [] for facts in _device_facts().values()), "no .app reports org.python.python"
        assert device_matches["Python Launcher.app"] == []

    def test_a_mixed_group_assumes_an_absent_attribute_and_reads_a_carried_one(self) -> None:
        """A title with `Bundle ID is X AND attribute like "v14."` — the attribute is scoping."""
        title = {
            "id": "T1",
            "name": "Mixed",
            "bundleId": "com.example.mixed",
            "currentVersion": "14.2",
            "patches": [{"version": "14.2", "releaseDate": "2026-01-01T00:00:00Z"}],
            "requirements": [
                {
                    "operator": "and",
                    "tests": [
                        {"name": "Application Bundle ID", "type": "recon", "value": "com.example.mixed", "operator": "is"},
                        {"name": "jamf-patch-mixed", "type": "extensionAttribute", "value": "v14.", "operator": "like"},
                    ],
                }
            ],
            "extensionAttributes": [{"key": "jamf-patch-mixed", "displayName": "Mixed Version"}],
        }
        catalog = Catalog.from_records([title])
        app = Facts(app_name="Mixed.app", bundle_id="com.example.mixed", versions=("14.2",))
        (match,) = match_app(app, catalog)
        assert match.basis == BASIS_EA_ASSUMED and match.state == STATE_LATEST
        (match,) = match_app(Facts(**{**app.__dict__, "extension_attributes": {"Mixed Version": "v14.2"}}), catalog)
        assert match.basis == BASIS_REQUIREMENTS
        assert match_app(Facts(**{**app.__dict__, "extension_attributes": {"jamf-patch-mixed": "v13.9"}}), catalog) == []

    def test_an_attribute_only_group_never_identifies_an_app_by_itself(self, catalog: Catalog, device_matches) -> None:
        """JetBrains PyCharm Community is `[attribute is not ""] OR [Bundle ID is
        com.jetbrains.pycharm.ce]`. The attribute group is device scoping: it must not make the
        title match Xcode (or anything else) — the bundle group decides."""
        assert [m.title.name for m in device_matches["Xcode.app"]] == ["Apple Xcode"]
        community = Facts(app_name="PyCharm CE.app", bundle_id="com.jetbrains.pycharm.ce", versions=("2025.2.6.1",))
        (match,) = match_app(community, catalog)
        assert match.title.name == "JetBrains PyCharm Community" and match.basis == BASIS_REQUIREMENTS
        assert match.state == STATE_LATEST

    def test_what_is_not_considered(self, catalog: Catalog) -> None:
        names = {title.name for title in catalog.titles}
        # Node.js 14 and Temurin JRE 19 are attribute-only and Jamf publishes no `bundleId` for
        # either, so #386's admission cannot reach them — nothing names the software. "Apple
        # macOS" is device-level: `detection_for` answers None rather than either constant.
        for absent in ("Node.js 14", "Eclipse Temurin (JRE) 19", "Apple macOS"):
            assert absent not in names
        community = next(title for title in catalog.titles if title.name == "JetBrains PyCharm Community")
        assert community.attribute_names == {"jamf-patch-jetbrains-pycharm-community", "pycharm community version"}
        slack = next(title for title in catalog.titles if title.name == "Slack")
        assert slack.attribute_names == frozenset()


class TestSummary:
    def test_no_matches_means_no_summary(self) -> None:
        assert summarize([]) is None
