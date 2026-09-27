"""The submission text rule (#623): Support's "text" as Kyle ruled Support #17's decision 6 on 2026-09-27, checked
here before anything leaves. The cases are frontend/src/features/submissions/textRule.cases.json, which the dialog's
own check answers alike (submissions.test.tsx). Pure: no database."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.submissions import SubmissionIn, text_refusal

TABLE = Path(__file__).resolve().parents[2] / "frontend" / "src" / "features" / "submissions" / "textRule.cases.json"
CASES = json.loads(TABLE.read_text())["cases"]
APP = {"appName": "Wireshark", "bundleId": "org.wireshark.Wireshark", "platform": "macos", "versions": ["3.6.2"]}
BODY = {"kind": "coverage"} | APP
ALIAS = {"app_name": "appName", "bundle_id": "bundleId", "text": "text", "contact": "contact"}
BLANK = "{} is blank: it holds only spaces, tabs, line breaks or the joiners U+200C and U+200D, and a case takes no blank text."


def _refusals(field: str, value: str) -> list[tuple]:
    try:
        SubmissionIn.model_validate(BODY | {ALIAS[field]: value})
    except ValidationError as refused:
        return [(error["type"], error["loc"], error["msg"]) for error in refused.errors()]
    return []


@pytest.mark.parametrize("case", CASES, ids=[case["why"] for case in CASES])
def test_each_case_is_answered_as_the_dialog_answers_it(case):
    """A refusal names the field, the code point and the place; it is pydantic's only error for the body, so an
    unpaired surrogate never reaches the length check's "unable to parse raw data", which names no field."""
    field, said = case["field"], text_refusal(case["field"], case["value"])
    if case["refused"] is None:
        assert said is None and _refusals(field, case["value"]) == []
        return
    if case["refused"] == "blank":  # Support #27: nothing left once whitespace and the two joiners go
        assert said == BLANK.format(field)
    else:
        assert said.startswith(f"{field} has {case['refused']}, which a case cannot carry: ")
    assert said == case.get("said", said)
    assert _refusals(field, case["value"]) == [("text_rule", (ALIAS[field],), said)]


def test_the_table_covers_every_text_field_and_both_verdicts():
    assert {case["field"] for case in CASES} == set(ALIAS)
    assert {case["field"] for case in CASES if "said" in case} == set(ALIAS), "one whole sentence per field"
    assert {case["field"] for case in CASES if case["refused"] == "blank"} == set(ALIAS), "joiners alone are blank anywhere"
    assert {case["refused"] is None for case in CASES} == {True, False}


@pytest.mark.parametrize(("field", "value"), [("text", " \n\t "), ("text", ""), ("contact", " "), ("app_name", "\u3000")])
def test_a_blank_field_is_refused_by_name(field, value):
    """Not blank, as Support's "text" says; the dialog leaves a blank field out, so only another client meets this.
    The table's `blank` cases are the joiners alone and with whitespace."""
    said = BLANK.format(field)
    assert text_refusal(field, value) == said and _refusals(field, value) == [("text_rule", (ALIAS[field],), said)]
