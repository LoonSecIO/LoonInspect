"""The Jamf side of the app catalog as a local lookup (`app.catalog.index`), built from the real
catalog slice: which titles make rows, which rows carry the hashes, and that the hashes are the
ones every installed app carries (`app.core.hashing`, `app.core.content_keys`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.catalog.index import build_rows, title_bundle_ids
from app.catalog.service import catalog_signature
from app.core.content_keys import app_full_key, app_title_key
from app.core.hashing import compute_app_hash, compute_version_hash
from app.mdm.patch.matching import Catalog

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return Catalog.from_records(json.loads((FIXTURES / "patch_titles_subset.json").read_text()), signature=(51, None))


@pytest.fixture(scope="module")
def rows(catalog: Catalog) -> list[dict]:
    return build_rows(catalog)


def _rows(rows, **where):
    return [row for row in rows if all(row[key] == value for key, value in where.items())]


class TestBundleIds:
    def test_column_and_is_values(self, catalog: Catalog) -> None:
        titles = {title.name: title for title in catalog.titles}
        assert title_bundle_ids(titles["1Password 4"]) == ["com.agilebits.onepassword4"]
        # The rolling 1Password title has no column; its two groups name two bundle IDs.
        assert title_bundle_ids(titles["1Password"]) == ["com.1password.1password"]
        # Self Service: the column is a prefix, the test is `like` — only the column makes rows.
        assert title_bundle_ids(titles["Jamf Self Service for macOS"]) == ["com.jamfsoftware.selfservice"]


class TestRows:
    def test_xcode_rows_carry_the_hashes_an_installed_app_would(self, rows) -> None:
        (row,) = _rows(rows, title_id="0C3", version="26.6")
        assert row["app_name"] == "Xcode.app" and row["bundle_id"] == "com.apple.dt.Xcode" and row["is_latest"] is True
        assert row["app_hash"] == compute_app_hash("Xcode.app", "com.apple.dt.Xcode")
        assert row["version_hash"] == compute_version_hash("Xcode.app", "com.apple.dt.Xcode", "26.6")
        assert row["key_title"] == app_title_key("Xcode.app", "com.apple.dt.Xcode")
        assert row["key_full"] == app_full_key("Xcode.app", "com.apple.dt.Xcode", "26.6", None)
        assert row["released_at"] is not None and row["publisher"] == "Apple"

    def test_1password_4_and_5_differ_on_the_same_bundle_id(self, rows) -> None:
        four = _rows(rows, title_id="0F5")
        five = _rows(rows, title_id="0F6")
        assert four and five
        assert {r["bundle_id"] for r in four} == {r["bundle_id"] for r in five} == {"com.agilebits.onepassword4"}
        assert {r["app_name"] for r in four} == {"1Password 4.app"} and {r["app_name"] for r in five} == {"1Password 5.app"}
        assert {r["version_hash"] for r in four}.isdisjoint({r["version_hash"] for r in five})

    def test_titles_without_an_app_name_make_pair_rows_only(self, rows) -> None:
        wireshark = _rows(rows, title_id="5F6")
        assert wireshark and all(r["app_name"] is None and r["version_hash"] is None and r["key_full"] is None for r in wireshark)
        assert any(r["version"] == "4.2.0" for r in wireshark) and sum(r["is_latest"] for r in wireshark) == 1

    def test_not_considered_titles_make_no_rows(self, rows) -> None:
        names = {row["title_name"] for row in rows}
        for absent in ("Apple macOS", "Apple macOS Catalina", "Node.js 14", "Mozilla Firefox", "JetBrains PyCharm Unified"):
            assert absent not in names
        assert "JetBrains PyCharm Community" in names  # it has a bundle-ID group

    def test_versions_are_not_duplicated_per_bundle(self, rows) -> None:
        seen = {(row["title_id"], row["bundle_id"], row["version"].casefold()) for row in rows}
        assert len(seen) == len(rows)


class TestSignature:
    def test_signature_names_count_and_newest_sync(self) -> None:
        from datetime import datetime, timezone

        assert catalog_signature(Catalog([], signature=(0, None))) == "0:"
        stamp = datetime(2026, 8, 22, 17, 0, tzinfo=timezone.utc)
        assert catalog_signature(Catalog([], signature=(1549, stamp))) == "1549:2026-08-22T17:00:00+00:00"
