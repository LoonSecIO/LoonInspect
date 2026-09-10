"""The observation read's pure facts (#368): the four states partition the cases, the
vocabulary is closed, and the sections come in registry order."""

from __future__ import annotations

from app.core.wire_vocabulary import SECTION_WRAPPERS
from app.observations.read import EMPTY, NOT_OBSERVED, OUTSIDE_APERTURE, PRESENT, classify


def test_the_four_states_partition_the_cases() -> None:
    assert classify(digested=True, populated=True, in_sweep=True) == PRESENT
    assert classify(digested=True, populated=True, in_sweep=False) == PRESENT, "a digest outranks the sweep's current list"
    assert classify(digested=True, populated=False, in_sweep=True) == EMPTY
    assert classify(digested=False, populated=False, in_sweep=True) == NOT_OBSERVED
    assert classify(digested=False, populated=False, in_sweep=False) == OUTSIDE_APERTURE
    assert {PRESENT, EMPTY, NOT_OBSERVED, OUTSIDE_APERTURE} == {"present", "empty", "not_observed", "outside_aperture"}


def test_the_schema_state_is_the_closed_set_and_the_sections_are_the_registry() -> None:
    from typing import get_args

    from app.schemas.devices import SectionObservationOut, SectionState

    assert set(get_args(SectionState)) == {PRESENT, EMPTY, NOT_OBSERVED, OUTSIDE_APERTURE}
    assert "state" in SectionObservationOut.model_fields and SectionObservationOut.model_fields["state"].is_required()
    assert list(SECTION_WRAPPERS) == [
        "general",
        "hardware",
        "operating_system",
        "user_and_location",
        "purchasing",
        "security",
        "disk_encryption",
        "local_user_accounts",
        "applications",
        "extension_attributes",
        "group_memberships",
        "configuration_profiles",
        "certificates",
        "software_updates",
    ]
