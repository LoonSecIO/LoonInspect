"""Bundle identity is additive and cannot turn a backend stamp into a guessed app version."""

import json

import pytest

from app.api import system
from app.core import version


@pytest.fixture
def stamp(tmp_path, monkeypatch):
    path = tmp_path / "build_info.json"
    monkeypatch.setattr(version, "_BUILD_INFO_PATH", path)
    version.get_app_version.cache_clear()
    yield path
    version.get_app_version.cache_clear()


async def test_mac_identity_and_legacy_backend_stamp_share_one_response(stamp, monkeypatch):
    stamp.write_text(json.dumps({"version": "2026.11.21+1234567", "app_version": "1.2.0", "app_build": "42"}))
    monkeypatch.setattr(system.settings, "instance_kind", "mac-app")
    assert (await system.version()).model_dump(by_alias=True) == {
        "version": "2026.11.21+1234567",
        "kind": "mac-app",
        "appVersion": "1.2.0",
        "appBuild": "42",
    }


async def test_container_never_claims_a_mac_identity(stamp, monkeypatch):
    stamp.write_text(json.dumps({"version": "2026.11.21+1234567", "app_version": "1.2.0", "app_build": "42"}))
    monkeypatch.setattr(system.settings, "instance_kind", "container")
    assert (await system.version()).model_dump(by_alias=True) == {
        "version": "2026.11.21+1234567",
        "kind": "container",
        "appVersion": None,
        "appBuild": None,
    }


@pytest.mark.parametrize(
    "content", [None, "broken JSON", "[]", '{"version":"2026.11.21+1234567"}', '{"app_version":42,"app_build":" "}']
)
def test_missing_or_invalid_bundle_identity_stays_unknown(stamp, content):
    if content is not None:
        stamp.write_text(content)
    assert version.get_mac_app_identity() == (None, None)


def test_partial_identity_retains_only_what_was_recorded(stamp):
    stamp.write_text('{"app_version":" 1.2.0 ","app_build":null}')
    assert version.get_mac_app_identity() == ("1.2.0", None)
