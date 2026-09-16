"""The dimensions stamped on a change row (#447): `app.changes.derive.device_dimensions`.

The change feed could only be filtered by what its table shows. These are the Mac's own
dimensions — model, OS, org, management, assigned user — written onto every row of one
boundary so a filter needs no join, and so it reads the value the Mac carried *at that
observation* rather than today's (ruling H1).

The wire's `deviceMeta` block is the same move for the same reason, and the two are kept apart
here on purpose: that block is correlation (jobID, eventID, shortDate) and is frozen at eleven
ruled names (#189, `test_device_meta.py`), while this stamp is attributes and lives only in
this database. A test below holds the boundary, because a key that leaked from here into the
event body would be an addition to a frozen vocabulary that nobody ruled.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.changes.derive import (
    _DEVICE_META_SOURCES,
    DEVICE_META_KEYS,
    DEVICE_META_MAX_KEYS,
    device_dimensions,
)
from app.changes.policy import FIELD_RULES
from app.mdm.jamf.contract import SUBJECT_COMPUTER, Observation, SectionContent

# One full aperture, with the values the demo pod actually holds for Kyle's minis.
_BODIES: dict[str, dict] = {
    "hardware": {
        "make": "Apple",
        "model": "Mac mini (2024) M4",
        "modelIdentifier": "Mac16,10",
        "appleSilicon": True,
        "serialNumber": "KY4QVD7430",
    },
    "operating_system": {
        "name": "macOS",
        "version": "26.6.2",
        "build": "25G83",
        "fileVault2Status": "NOT_ENCRYPTED",
    },
    "user_and_location": {
        "username": "kyle",
        "realname": "Kyle Pazandak",
        "email": "kyle@example.com",
        "position": "Founder",
        "buildingId": "2",
        "departmentId": "5",
    },
    "general": {
        "name": "Kyle’s Mac mini",
        "supervised": True,
        "remoteManagement": {"managed": True},
        "site": {"id": "-1", "name": "None"},
        "lastEnrolledDate": "2026-08-23T23:47:59Z",
    },
}


def _observation(subject_kind: str = SUBJECT_COMPUTER, **bodies: dict | None) -> Observation:
    """A pull as the ledger saw it. A section named with None is outside the aperture."""
    sections = {**_BODIES, **bodies}
    return Observation(
        subject_kind=subject_kind,
        subject_id="4",
        sections={
            name: SectionContent(name=name, digest=f"v1:{name}", body=body) for name, body in sections.items() if body is not None
        },
        observed_at=datetime(2026, 9, 14, 16, 57, 26, tzinfo=UTC),
        serial_number="KY4QVD7430",
        label="Kyle’s Mac mini",
    )


def test_a_full_aperture_stamps_every_key() -> None:
    assert device_dimensions(_observation()) == {
        "model": "Mac mini (2024) M4",
        "modelIdentifier": "Mac16,10",
        "appleSilicon": True,
        "osVersion": "26.6.2",
        "osBuild": "25G83",
        "fileVault": "NOT_ENCRYPTED",
        "siteId": "-1",
        "buildingId": "2",
        "departmentId": "5",
        "managed": True,
        "supervised": True,
        "enrolledAt": "2026-08-23T23:47:59Z",
        "username": "kyle",
        "realName": "Kyle Pazandak",
        "email": "kyle@example.com",
        "position": "Founder",
    }


def test_the_keys_are_the_named_ones_and_the_cap_holds() -> None:
    """Sixteen of eighteen, two held open as #189 held its thirteenth slot: a later key is a
    parameter, not a migration, and the cap is what keeps "one more" from becoming a document."""
    assert tuple(key for key, _, _ in _DEVICE_META_SOURCES) == DEVICE_META_KEYS
    assert len(DEVICE_META_KEYS) == 16
    assert len(DEVICE_META_KEYS) <= DEVICE_META_MAX_KEYS
    assert len(set(DEVICE_META_KEYS)) == len(DEVICE_META_KEYS)


def test_every_source_is_a_field_the_policy_tracks() -> None:
    """The paths are the policy's own field names. A section that renames one would otherwise
    stamp nulls for ever, and nothing would fail."""
    tracked = {(rule.section, rule.field) for rule in FIELD_RULES}
    for key, section, path in _DEVICE_META_SOURCES:
        assert (section, path) in tracked, (key, section, path)


def test_nulls_and_empty_strings_are_dropped_not_stored() -> None:
    """Jamf sends "" for an unassigned user. Stored, it would match a filter for the empty
    string and read as a value on the page; the wire's block already drops nulls this way."""
    stamp = device_dimensions(
        _observation(
            user_and_location={"username": "", "realname": None, "email": "", "departmentId": "5"},
            general={"remoteManagement": {}, "supervised": False},
        )
    )
    assert stamp is not None
    assert "username" not in stamp and "realName" not in stamp and "email" not in stamp
    assert stamp["departmentId"] == "5"
    assert "managed" not in stamp
    # False is a value, not an absence: an unsupervised Mac is a thing to filter for.
    assert stamp["supervised"] is False


def test_a_section_outside_the_aperture_drops_its_keys_together() -> None:
    """Absence of observation, not absence of the fact (#98). A webhook's narrow read can
    leave a row with a model and no department, and that is the honest stamp."""
    stamp = device_dimensions(_observation(user_and_location=None, general=None))
    assert stamp is not None
    assert set(stamp) == {"model", "modelIdentifier", "appleSilicon", "osVersion", "osBuild", "fileVault"}


def test_a_dotted_path_reads_jamfs_nested_objects() -> None:
    stamp = device_dimensions(_observation(general={"remoteManagement": {"managed": False}, "site": {"id": "7"}}))
    assert stamp is not None
    assert (stamp["managed"], stamp["siteId"]) == (False, "7")
    assert "supervised" not in stamp and "enrolledAt" not in stamp


def test_a_subject_that_is_not_a_device_is_stamped_with_nothing() -> None:
    """A smart group has no model and no department. An invented dimension is worse than none."""
    assert device_dimensions(_observation("computer_group")) is None


def test_an_aperture_that_read_none_of_the_sections_stamps_nothing() -> None:
    assert device_dimensions(_observation(hardware=None, operating_system=None, user_and_location=None, general=None)) is None


def test_nothing_crosses_from_the_stamp_into_the_wire() -> None:
    """The event body is an explicit dict (`_event_payload`) and the block inside it is frozen at
    #189's names, so a stamped key that crossed into it would be an addition to a frozen
    vocabulary nobody ruled (#188 clause 3).

    `managed` is the one name the two surfaces share, and that is the point rather than a leak:
    #189 ruled it onto the wire, this stamp reads the same field out of the same GENERAL body,
    and one word means one thing in both places. Every other dimension stays in this database.
    """
    from app.changes.derive import _change_device_meta

    meta = _change_device_meta(_observation())
    assert set(DEVICE_META_KEYS) & set(meta) == {"managed"}
    assert meta["managed"] is device_dimensions(_observation())["managed"]
