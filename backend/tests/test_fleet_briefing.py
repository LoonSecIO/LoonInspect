"""The migration briefing's pure half (#910): which counts may leave, and which replies are a choice. No database."""

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.api import fleet_briefing as briefing
from app.schemas.fleet_assessment import FleetAssessmentOut
from app.schemas.fleet_migration import LocalApp, MigrationReport, MigrationScope


def example() -> MigrationReport:
    app = LocalApp(app_hash="private-app-id", name="Secret.app", bundle_id="private.bundle", macs=2, version_count=1,
                   match="exact", has_jamf_match=True, jamf_evaluated=True, fleet_candidates=[])  # fmt: skip
    row = FleetAssessmentOut(target_version="3.0", out_of_policy_builds=1, kev_builds=1, unknown_builds=1, management="recurring")
    scope = MigrationScope(eligible_macs=4, selected_macs=2)
    return MigrationReport(as_of=datetime.now(UTC), scope=scope, items=[app], app_assessments={app.app_hash: row})


FACTS = briefing._facts(example())


def test_facts_are_the_reports_non_zero_counts_then_its_macs_and_never_a_name() -> None:
    assert [(fact.code, fact.count) for fact in FACTS] == [
        ("apps_overdue", 1), ("apps_with_kev", 1), ("incomplete_comparisons", 1), ("recurring_review", 1),
        ("exact_candidates", 1), ("scoped_macs", 2),
    ]  # fmt: skip
    assert not [word for word in ("private", "Secret", "3.0", "4") if word in json.dumps([f.model_dump() for f in FACTS])]
    empty = briefing._facts(MigrationReport(as_of=datetime.now(UTC), scope=MigrationScope()))
    assert [(fact.code, fact.count) for fact in empty] == [("scoped_macs", 0)]


NO_CHOICE = [
    *('["CVE-2026-9999"]', '{"command":"run"}', '["scoped_macs","scoped_macs"]', '["apps_with_kev",{}]'),  # #857's corpus
    '["ambiguous_apps"]',  # a code, but not one the report counted
    *("[]", '["apps_overdue","apps_with_kev","exact_candidates","scoped_macs"]', "[1]", '"apps_overdue"', "", "no"),
    *('Here they are:\n```json\n["apps_overdue"]\n```', '```json\n["apps_overdue"]\n```\nThe overdue apps matter most.'),
    '```json\n["apps_overdue"]\n```\n```json\n["apps_with_kev"]\n```',
    '["apps_overdue"' + " " * 500 + "]",
]


@pytest.mark.parametrize(
    ("raw", "codes"),
    [
        ('["apps_with_kev","apps_overdue"]', ["apps_with_kev", "apps_overdue"]),  # the model's order
        ('```json\n["apps_overdue"]\n```', ["apps_overdue"]),
        ('\n```\n["scoped_macs","exact_candidates","apps_overdue"]\n```\n', ["scoped_macs", "exact_candidates", "apps_overdue"]),
        *((bad, []) for bad in NO_CHOICE),
    ],
)
def test_one_to_three_codes_the_request_carried_are_a_choice_and_nothing_else_is(raw: str, codes: list[str]) -> None:
    assert [fact.code for fact in briefing._pick(raw, FACTS)] == codes


def test_request_cannot_supply_prompt_or_report_data() -> None:
    with pytest.raises(ValidationError):
        briefing.BriefingIn.model_validate({"prompt": "private facts", "apps_overdue": 999})
