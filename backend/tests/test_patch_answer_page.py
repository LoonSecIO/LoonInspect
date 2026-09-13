"""The patch answer as the pages read it (#313), in the pure lane.

#311 put the whole Jamf Patch answer on the Splunk wire and left the REST surfaces carrying the
pre-#65 columns, so a Splunk user could read `eaAssumed` and the two subject ids and the
operator on the page could not. These pin the additive REST shape the pages now consume and
the one rule the device read applies when it names titles: an id the catalog cannot name is
left out of the named list and stays on the id list, never shipped as its id in disguise.
"""

from __future__ import annotations

from app.api.devices import _titled
from app.schemas.applications import ApplicationOut
from app.schemas.catalog import CatalogEntryOut
from app.schemas.devices import DeviceDetailOut, InstalledAppOut

WIRESHARK = {
    "id": 1,
    "name": "Wireshark.app",
    "bundle_id": "org.wireshark.Wireshark",
    "version": "4.2.0",
    "short_version": None,
    "app_hash": "a" * 32,
    "version_hash": "b" * 32,
    "is_compliant": False,
    "patch_available": True,
    "patch_available_since": "2024-01-03T18:00:00Z",
    "last_patch_check_at": None,
    "jamf_title_ids": ["612", "5F6"],
    "patch_state": "behind",
    "this_version_seen": True,
    "latest_version": "4.6.8",
    "releases_missed": 14,
    "ea_assumed": False,
    "reference_title_id": "612",
    "sentence_title_id": "5F6",
}


def _detail(*apps: InstalledAppOut) -> DeviceDetailOut:
    return DeviceDetailOut(
        id=7,
        mdm_provider="jamf",
        platform="macos",
        mdm_connection_id=1,
        external_id="7",
        serial_number="C02XX",
        hostname="mini",
        last_seen_at=None,
        last_check_in=None,
        last_inventory_at=None,
        managed=True,
        supervised=True,
        os_version="26.0",
        site=None,
        building_id=None,
        department_id=None,
        apps=list(apps),
    )


class TestTheRestShape:
    def test_an_installed_app_carries_the_subjects_and_the_assumption_by_the_wire_s_names(self) -> None:
        payload = InstalledAppOut(**WIRESHARK).model_dump(mode="json", by_alias=True)
        # The same facts a Splunk event carries under `patch.jamfPatch`, camelCased like the
        # rest of REST; `jamfTitles` is the names a person can read, resolved by the route.
        assert payload["eaAssumed"] is False
        assert (payload["referenceTitleId"], payload["sentenceTitleId"]) == ("612", "5F6")
        assert payload["jamfTitles"] == []

    def test_a_row_judged_before_311_says_nothing_rather_than_false(self) -> None:
        old = {**WIRESHARK, "ea_assumed": None, "reference_title_id": None, "sentence_title_id": None}
        payload = InstalledAppOut(**old).model_dump(mode="json", by_alias=True)
        # Never defaulted: `false` would assert that nothing was assumed on a row nobody has
        # re-judged, and a page that trusted it would drop the marker on exactly the rows
        # whose basis is unknown.
        assert payload["eaAssumed"] is None and payload["referenceTitleId"] is None and payload["sentenceTitleId"] is None

    def test_a_catalog_row_carries_the_same_three_keys(self) -> None:
        assert {"ea_assumed", "reference_title_id", "sentence_title_id", "jamf_titles"} <= set(CatalogEntryOut.model_fields)

    def test_the_applications_row_carries_the_answer_at_its_own_grain(self) -> None:
        """Two counts beside `deviceCount`, and still no per-version breakdown (#299)."""
        row = ApplicationOut(
            app_hash="a" * 32, name="Wireshark.app", bundle_id="org.wireshark.Wireshark", device_count=12, version_count=3
        )
        payload = row.model_dump(mode="json", by_alias=True)
        assert (payload["matchedDeviceCount"], payload["patchAvailableDeviceCount"]) == (0, 0)
        assert "versions" not in payload


class TestNamingTheTitles:
    def test_names_ride_in_id_order_and_an_unnamed_title_is_left_out_not_disguised(self) -> None:
        detail = _titled(_detail(InstalledAppOut(**WIRESHARK)), {"5F6": "Wireshark 4.2", "612": "Wireshark"})
        (app,) = detail.apps
        assert [(ref.id, ref.name) for ref in app.jamf_titles] == [("612", "Wireshark"), ("5F6", "Wireshark 4.2")]

        # A title the catalog holds no name for: the id list is whole, the named list is
        # shorter, and no entry says "612" where a name should be.
        partial = _titled(_detail(InstalledAppOut(**WIRESHARK)), {"5F6": "Wireshark 4.2"})
        (app,) = partial.apps
        assert app.jamf_title_ids == ["612", "5F6"]
        assert [(ref.id, ref.name) for ref in app.jamf_titles] == [("5F6", "Wireshark 4.2")]

    def test_an_unmatched_app_names_nothing_and_the_others_are_untouched(self) -> None:
        unmatched = InstalledAppOut(**{**WIRESHARK, "id": 2, "jamf_title_ids": None, "patch_state": None, "ea_assumed": None})
        detail = _titled(_detail(InstalledAppOut(**WIRESHARK), unmatched), {"612": "Wireshark", "5F6": "Wireshark 4.2"})
        assert [len(app.jamf_titles) for app in detail.apps] == [2, 0]
        # `model_copy` keeps everything else: the block the corpus stamped, the columns, the id.
        assert [app.id for app in detail.apps] == [1, 2] and detail.apps[1].vuln.assessment == "off"


class _Rows:
    def __init__(self, rows: list[tuple[str, str]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str, str]]:
        return self._rows


class _OneRead:
    """Just enough session for `title_names`: one execute, and a count of how many ran."""

    def __init__(self, rows: list[tuple[str, str]]) -> None:
        self.rows = rows
        self.reads = 0

    async def execute(self, _statement):
        self.reads += 1
        return _Rows(self.rows)


class TestTheNameRead:
    async def test_an_empty_name_is_no_name(self) -> None:
        """Jamf can serve a title whose `name` is empty (`sync_catalog` stores `""`), and a
        page that trusted it would print a blank link. An empty name is left out, exactly as
        a missing row is, so the page shows the id with its hint instead."""
        from app.catalog.service import title_names

        db = _OneRead([("612", "Wireshark"), ("5F6", "")])
        assert await title_names(db, ["612", "5F6"]) == {"612": "Wireshark"}

    async def test_one_read_for_a_page_and_none_for_no_titles(self) -> None:
        from app.catalog.service import title_names

        db = _OneRead([("612", "Wireshark")])
        await title_names(db, ["612", "612", "5F6", ""])
        assert db.reads == 1
        empty = _OneRead([])
        assert await title_names(empty, []) == {} and empty.reads == 0
