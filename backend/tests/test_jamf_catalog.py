"""Pure helpers behind the Jamf patch catalog sync.

`sync_catalog` itself needs a session and the network and is not covered here. Its
three pure helpers are, because each one fails quietly rather than loudly: a title that
does not parse is skipped with `continue`, a requirement group collapsed wrongly still
produces well-formed JSON, and `_needs_refresh` returning the wrong answer either
re-fetches the entire catalog every hour or never refreshes it again. None of the three
raises.
"""

from __future__ import annotations

from app.mdm.patch.jamf_catalog import (
    _convert_requirements,
    _needs_refresh,
    _remove_embedded_cert,
    _strip_patch_entry,
)
from app.models.schema import JamfPatchTitle


def _requirement(name: str, *, and_linked: bool | None = True) -> dict:
    requirement = {"name": name, "operator": "is", "value": "1", "type": "recon"}
    if and_linked is not None:
        requirement["and"] = and_linked
    return requirement


class TestRemoveEmbeddedCert:
    def test_strips_the_certificate_envelope(self) -> None:
        body = '\x30\x82CERT{"name":"Slack","patches":[{"version":"4.0.1"}]}\n-----END-----'
        assert _remove_embedded_cert(body) == {"name": "Slack", "patches": [{"version": "4.0.1"}]}

    def test_passes_an_unwrapped_body_through(self) -> None:
        assert _remove_embedded_cert('{"name":"Slack","patches":[]}') == {"name": "Slack", "patches": []}

    def test_returns_empty_for_a_body_with_no_json(self) -> None:
        assert _remove_embedded_cert("no json here at all") == {}

    def test_returns_empty_for_an_empty_body(self) -> None:
        assert _remove_embedded_cert("") == {}

    def test_returns_empty_for_malformed_json(self) -> None:
        assert _remove_embedded_cert('{"a":[1,,2]}') == {}

    def test_discards_valid_json_not_ending_in_a_closing_array(self) -> None:
        """Documents current behaviour, which is sharper than it looks.

        The right-hand trim walks back to `]}`, so a detail payload whose final key is
        not an array is discarded whole — here a syntactically valid document returns
        `{}`. `sync_catalog` then skips it via `or not detail`, so the title silently
        never syncs. Safe only while Jamf keeps `patches` last in the response; nothing
        in JSON guarantees key order, and nothing here would report it if that changed.
        """
        assert _remove_embedded_cert('{"name":"Slack","patches":{}}') == {}


class TestConvertRequirements:
    def test_empty_requirements_produce_no_groups(self) -> None:
        assert _convert_requirements([]) == []

    def test_and_linked_requirements_share_one_group(self) -> None:
        groups = _convert_requirements([_requirement("a"), _requirement("b")])

        assert len(groups) == 1
        assert [test["name"] for test in groups[0]["tests"]] == ["a", "b"]
        assert groups[0]["operator"] == "and"

    def test_a_non_and_linked_requirement_opens_a_new_group(self) -> None:
        """The OR seam. Flattening these into one group would turn "matches A or B"
        into "matches A and B" and stop the title matching anything."""
        groups = _convert_requirements([_requirement("a"), _requirement("b", and_linked=False)])

        assert [[test["name"] for test in group["tests"]] for group in groups] == [["a"], ["b"]]

    def test_a_missing_and_key_defaults_to_and_linked(self) -> None:
        groups = _convert_requirements([_requirement("a"), _requirement("b", and_linked=None)])

        assert len(groups) == 1

    def test_the_first_requirements_and_flag_is_ignored(self) -> None:
        """There is no preceding group to close, so a leading `and: false` must not
        open an empty one — an empty leading group would AND against nothing and match
        every title."""
        groups = _convert_requirements([_requirement("a", and_linked=False)])

        assert len(groups) == 1
        assert [test["name"] for test in groups[0]["tests"]] == ["a"]

    def test_each_test_keeps_the_four_matching_fields(self) -> None:
        """`bundle_id` is only a prefilter — these criteria are what actually decides a
        match, because duplicate bundle_ids appear across major-version titles."""
        groups = _convert_requirements([_requirement("Application Bundle ID")])

        assert groups[0]["tests"][0] == {
            "name": "Application Bundle ID",
            "operator": "is",
            "value": "1",
            "type": "recon",
        }


class TestStripPatchEntry:
    def test_drops_the_bulky_keys(self) -> None:
        patch = {
            "version": "4.0.1",
            "releaseDate": "2024-01-01",
            "standalone": True,
            "minimumOperatingSystem": "12.0",
            "reboot": False,
            "killApps": [],
            "components": [],
            "capabilities": [],
        }

        assert _strip_patch_entry(patch) == {"version": "4.0.1", "releaseDate": "2024-01-01"}

    def test_keeps_an_entry_with_nothing_to_strip(self) -> None:
        assert _strip_patch_entry({"version": "4.0.1"}) == {"version": "4.0.1"}


class TestNeedsRefresh:
    def test_an_unseen_title_needs_refreshing(self) -> None:
        assert _needs_refresh(None, {"id": "slack", "lastModified": "1", "currentVersion": "4.0.1"}) is True

    def test_an_unchanged_title_does_not(self) -> None:
        """The whole point of the check: without it every hourly tick re-fetches the
        full detail payload for every title in the catalog."""
        existing = JamfPatchTitle(id="slack", last_modified="1", current_version="4.0.1")

        assert _needs_refresh(existing, {"id": "slack", "lastModified": "1", "currentVersion": "4.0.1"}) is False

    def test_a_changed_last_modified_triggers_a_refresh(self) -> None:
        existing = JamfPatchTitle(id="slack", last_modified="1", current_version="4.0.1")

        assert _needs_refresh(existing, {"id": "slack", "lastModified": "2", "currentVersion": "4.0.1"}) is True

    def test_a_changed_current_version_triggers_a_refresh(self) -> None:
        existing = JamfPatchTitle(id="slack", last_modified="1", current_version="4.0.1")

        assert _needs_refresh(existing, {"id": "slack", "lastModified": "1", "currentVersion": "4.1.0"}) is True
