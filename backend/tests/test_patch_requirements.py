"""The pure evaluator behind Jamf Patch matching (`app.mdm.patch.requirements`).

Literal expectations taken from the real catalog (synced 2026-08-22): 1Password 4's group with
the `not like "5.4."` guard, Ableton Live Lite's `Application Title has`, Mozilla Firefox's
extension-attribute-only requirement, and an "Apple macOS" title that is about the device, not
an app. The semantics mirror `frontend/src/features/jamfPatch/requirementsEvaluator.ts`.
"""

from __future__ import annotations

import pytest

from app.mdm.patch.requirements import (
    Facts,
    Outcome,
    Verdict,
    compare,
    compare_versions,
    evaluate,
    evaluate_group,
    evaluate_test,
    is_app_level,
    required_bundle_ids,
    version_tuple,
)

ONEPASSWORD_4 = [
    {
        "operator": "and",
        "tests": [
            {"name": "Application Bundle ID", "type": "recon", "value": "com.agilebits.onepassword4", "operator": "is"},
            {"name": "Application Version", "type": "recon", "value": "4.", "operator": "like"},
            {"name": "Application Bundle ID", "type": "recon", "value": "com.agilebits.onepassword4", "operator": "is"},
            {"name": "Application Version", "type": "recon", "value": "5.4.", "operator": "not like"},
        ],
    }
]
ONEPASSWORD_6 = [
    {
        "operator": "and",
        "tests": [
            {"name": "Application Bundle ID", "type": "recon", "value": "com.agilebits.onepassword4", "operator": "is"},
            {"name": "Application Version", "type": "recon", "value": "6.", "operator": "like"},
        ],
    }
]
ABLETON_LIVE_LITE = [
    {
        "operator": "and",
        "tests": [
            {"name": "Application Bundle ID", "type": "recon", "value": "com.ableton.live", "operator": "is"},
            {"name": "Application Title", "type": "recon", "value": "Ableton Live 10 Lite.app", "operator": "has"},
        ],
    },
    {
        "operator": "and",
        "tests": [{"name": "Application Title", "type": "recon", "value": "Ableton Live 11 Lite.app", "operator": "has"}],
    },
    {
        "operator": "and",
        "tests": [{"name": "Application Title", "type": "recon", "value": "Ableton Live 12 Lite.app", "operator": "has"}],
    },
]
FIREFOX = [
    {
        "operator": "and",
        "tests": [{"name": "jamf-patch-mozilla-firefox", "type": "extensionAttribute", "value": "", "operator": "is not"}],
    }
]
MACOS_CATALINA = [
    {
        "operator": "and",
        "tests": [
            {"name": "Operating System Version", "type": "recon", "value": "10.15", "operator": "greater than or equal"},
            {"name": "Operating System Version", "type": "recon", "value": "10.16", "operator": "less than"},
        ],
    }
]


def onepassword(version: str) -> Facts:
    return Facts(app_name="1Password.app", bundle_id="com.agilebits.onepassword4", versions=(version,))


class TestVersions:
    def test_digit_runs_are_the_tuple(self) -> None:
        assert version_tuple("7.0.5 (81138)") == (7, 0, 5, 81138)
        assert version_tuple("02.05.00.66") == (2, 5, 0, 66)
        assert version_tuple("") == ()

    @pytest.mark.parametrize(
        ("a", "b", "sign"),
        [
            ("4.2", "4.2.0", 0),
            ("7.0.5 (81138)", "7.1.5 (84650)", -1),
            ("02.05.00.66", "02.08.02.61", -1),
            ("27.0", "26.6.2", 1),
            ("2022.6.10", "2026.2.0", -1),
            ("11.30.2", "11.31.1", -1),
        ],
    )
    def test_compare_versions(self, a: str, b: str, sign: int) -> None:
        result = compare_versions(a, b)
        assert (result > 0) - (result < 0) == sign


class TestCompare:
    def test_is_and_is_not_are_case_insensitive_equality(self) -> None:
        assert compare("is", "com.Apple.Safari", "com.apple.safari") is True
        assert compare("is not", "com.apple.safari", "com.apple.safari") is False

    def test_like_is_substring_which_the_catalog_relies_on(self) -> None:
        """"5.4.3" is like "4." — the reason 1Password 4 also says not like "5.4."."""
        assert compare("like", "5.4.3", "4.") is True
        assert compare("not like", "5.4.3", "5.4.") is False
        assert compare("has", "Ableton Live 11 Lite.app", "Ableton Live 11 Lite.app") is True

    def test_regex_operators(self) -> None:
        assert compare("matches regex", "4.2.0", r"^4\.2\.") is True
        assert compare("does not match regex", "4.2.0", r"^4\.2\.") is False
        # An invalid pattern can never match, so "matches" fails and "does not match" passes.
        assert compare("matches regex", "anything", "[") is False
        assert compare("does not match regex", "anything", "[") is True

    def test_ordered_operators_compare_versions(self) -> None:
        assert compare("greater than or equal", "10.15.7", "10.15") is True
        assert compare("less than", "10.15.7", "10.16") is True
        assert compare("greater than", "26.0", "26.0") is False
        assert compare("less than or equal", "26.0", "26.0") is True

    def test_an_unknown_operator_is_none_not_false(self) -> None:
        assert compare("is within", "a", "a") is None


class TestEvaluateTest:
    def test_bundle_id(self) -> None:
        test = ONEPASSWORD_4[0]["tests"][0]
        assert evaluate_test(test, onepassword("4.4.3")) is Outcome.PASS
        assert evaluate_test(test, Facts(bundle_id="com.agilebits.onepassword7")) is Outcome.FAIL
        assert evaluate_test(test, Facts(bundle_id=None)) is Outcome.NOT_APPLICABLE

    def test_version_passes_if_any_version_string_does(self) -> None:
        """SimpleMDM carries build and marketing versions; Jamf carries one. The evaluator does
        not care which slot a connector used."""
        test = {"name": "Application Version", "type": "recon", "value": "126.0.", "operator": "like"}
        assert evaluate_test(test, Facts(versions=("6478.127", "126.0.6478.127"))) is Outcome.PASS
        assert evaluate_test(test, Facts(versions=("6478.127",))) is Outcome.FAIL
        assert evaluate_test(test, Facts(versions=())) is Outcome.NOT_APPLICABLE

    def test_extension_attribute_absent_is_not_applicable_but_empty_is_a_value(self) -> None:
        test = FIREFOX[0]["tests"][0]
        assert evaluate_test(test, Facts(extension_attributes={})) is Outcome.NOT_APPLICABLE
        # Jamf's scoping attributes: the matcher asks for absent ones to resolve TRUE.
        assert evaluate_test(test, Facts(extension_attributes={}, assume_missing_attributes=True)) is Outcome.PASS
        empty = Facts(extension_attributes={"jamf-patch-mozilla-firefox": ""}, assume_missing_attributes=True)
        assert evaluate_test(test, empty) is Outcome.FAIL
        assert evaluate_test(test, Facts(extension_attributes={"jamf-patch-mozilla-firefox": ""})) is Outcome.FAIL
        assert evaluate_test(test, Facts(extension_attributes={"JAMF-PATCH-MOZILLA-FIREFOX": "154.0"})) is Outcome.PASS
        assert evaluate_test(test, Facts(extension_attributes={"jamf-patch-mozilla-firefox": None})) is Outcome.FAIL

    def test_os_and_platform(self) -> None:
        ge, lt = MACOS_CATALINA[0]["tests"]
        assert evaluate_test(ge, Facts(os_version="10.15.7")) is Outcome.PASS
        assert evaluate_test(lt, Facts(os_version="10.15.7")) is Outcome.PASS
        assert evaluate_test(lt, Facts(os_version="27.0")) is Outcome.FAIL
        assert evaluate_test(ge, Facts(os_version=None)) is Outcome.NOT_APPLICABLE
        platform = {"name": "Platform", "type": "recon", "value": "Mac", "operator": "is"}
        assert evaluate_test(platform, Facts()) is Outcome.PASS
        assert evaluate_test(platform, Facts(platform=None)) is Outcome.NOT_APPLICABLE

    def test_unknown_test_or_operator_is_not_applicable(self) -> None:
        unknown = {"name": "Computer Name", "type": "recon", "value": "x", "operator": "is"}
        assert evaluate_test(unknown, Facts()) is Outcome.NOT_APPLICABLE
        odd = {"name": "Application Bundle ID", "type": "recon", "value": "x", "operator": "is within"}
        assert evaluate_test(odd, Facts(bundle_id="x")) is Outcome.NOT_APPLICABLE


class TestGroupsAndVerdicts:
    def test_a_group_matches_only_when_every_test_passes(self) -> None:
        group = {
            "operator": "and",
            "tests": [
                {"name": "Application Bundle ID", "type": "recon", "value": "org.mozilla.firefox", "operator": "is"},
                FIREFOX[0]["tests"][0],
            ],
        }
        facts = Facts(bundle_id="org.mozilla.firefox")
        assert evaluate_group(group, facts) is Verdict.INCONCLUSIVE  # pass + not applicable
        carried = Facts(bundle_id="org.mozilla.firefox", extension_attributes={"jamf-patch-mozilla-firefox": "154.0"})
        assert evaluate_group(group, carried) is Verdict.MATCHED
        assert evaluate_group(group, Facts(bundle_id="com.google.Chrome", extension_attributes={})) is Verdict.NOT_MATCHED
        assert evaluate_group({"operator": "and", "tests": []}, facts) is Verdict.NOT_MATCHED

    def test_any_matched_group_matches_the_title(self) -> None:
        lite = Facts(app_name="Ableton Live 12 Lite.app", bundle_id="com.ableton.live", versions=("12.1",))
        suite = Facts(app_name="Ableton Live 11 Suite.app", bundle_id="com.ableton.live", versions=("11.3",))
        assert evaluate(ABLETON_LIVE_LITE, lite) is Verdict.MATCHED
        assert evaluate(ABLETON_LIVE_LITE, suite) is Verdict.NOT_MATCHED

    def test_inconclusive_only_when_nothing_matched_and_something_could_not_be_judged(self) -> None:
        assert evaluate(FIREFOX, Facts(bundle_id="org.mozilla.firefox")) is Verdict.INCONCLUSIVE
        assert evaluate([], Facts()) is Verdict.NOT_MATCHED

    def test_1password_4_versus_5_the_substring_leak(self) -> None:
        assert evaluate(ONEPASSWORD_4, onepassword("4.4.3")) is Verdict.MATCHED
        assert evaluate(ONEPASSWORD_4, onepassword("5.4.3")) is Verdict.NOT_MATCHED  # like "4." but not like "5.4."
        assert evaluate(ONEPASSWORD_6, onepassword("6.8.9")) is Verdict.MATCHED
        assert evaluate(ONEPASSWORD_6, onepassword("4.4.3")) is Verdict.NOT_MATCHED


class TestTitleShape:
    def test_only_titles_with_an_identifying_recon_test_are_considered(self) -> None:
        """Kyle's rule: at least one recon test on the bundle ID or the application title."""
        assert is_app_level(ONEPASSWORD_4) is True
        assert is_app_level(ABLETON_LIVE_LITE) is True  # Application Title
        assert is_app_level(MACOS_CATALINA) is False  # device-level
        assert is_app_level(FIREFOX) is False  # attribute-only: the patching agent's
        version_test = {"name": "Application Version", "type": "recon", "value": "4.", "operator": "like"}
        assert is_app_level([{"operator": "and", "tests": [version_test]}]) is False

    def test_required_bundle_ids(self) -> None:
        assert required_bundle_ids(ONEPASSWORD_4) == frozenset({"com.agilebits.onepassword4"})
        # Group two has no bundle-ID test: the title can match any app and cannot be narrowed.
        assert required_bundle_ids(ABLETON_LIVE_LITE) is None
        assert required_bundle_ids(FIREFOX) is None
        like_test = {"name": "Application Bundle ID", "type": "recon", "value": "com.techsmith.camtasia", "operator": "like"}
        assert required_bundle_ids([{"operator": "and", "tests": [like_test]}]) is None
