"""The Prompt bar's model half (`app.ai.changes_prompt`): the vocabulary, the parser, the
whitelist, the guards, which way each repair moves the answer, and the sanitiser. Pure;
no database, no network, no model.

The five replies at the top are the handoff's own self-test, now asserting the level as
well as the section and the filter (the handoff never checked the level). The guard
questions are the eval set's, scored against Apple FM through `fm serve` on 2026-09-14;
`tests/test_changes_prompt_live.py` asks the real model.

The vocabulary is three copies of one fact (the model's display names, the page's
`SECTION_ORDER`, the Jamf contract's sections), so the drift tests read the other two
rather than restating them. The change kinds and the list sections are the same kind of
fact: the page's `CHANGE_KINDS` and the change policy's two rule tables are read too.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import time
from pathlib import Path

import pytest

from app.ai.changes_prompt import (
    CALL_TIMEOUT_SECONDS,
    CHANGES,
    DISCLOSED_FIELDS,
    ENTRY_SECTIONS,
    FEATURE,
    LEVELS,
    MAX_QUESTION_CHARS,
    MAX_REPLY_CHARS,
    MAX_REPLY_TOKENS,
    SECTIONS,
    SYSTEM_INSTRUCTION,
    Interpretation,
    Repair,
    coerce,
    guard,
    interpret,
    parse_reply,
    sanitize_question,
)

_ROOT = Path(__file__).resolve().parents[2]
RENDER_TS = _ROOT / "frontend" / "src" / "features" / "changes" / "render.ts"
MODULE = _ROOT / "backend" / "app" / "ai" / "changes_prompt.py"

NO_FILTERS = {"q": None, "artifact": None, "level": None, "section": None, "change": None}
NOT_PARSED = Interpretation(filters=NO_FILTERS, unsupported=None, repairs=[], parsed=False)


def _coerced(reply: str):
    obj = parse_reply(reply)
    assert obj is not None, reply
    return coerce(obj)


def _widening(repairs) -> list[str]:
    """The repairs that widen, as `Interpretation.widening` reads them."""
    return Interpretation(filters=NO_FILTERS, unsupported=None, repairs=list(repairs), parsed=True).widening


# --- the handoff's self-test ---------------------------------------------------------------

# (reply, section, artifact, level): section and level in the page's vocabulary, None = any.
SELFTEST = [
    (
        '{"search":null,"filter":"Wireshark","level":"any","section":"Applications","unsupported":null}',
        "applications",
        "Wireshark",
        None,
    ),
    ('```json\n{"search":"KY4QVD7430","filter":null,"level":"HIGH","section":"Hardware"}\n```', "hardware", None, "high"),
    ('{"search":null,"filter":"Chrome","level":"any","section":"apps"}', None, "Chrome", None),
    ('{"filter":"Robert\'); DROP TABLE devices;--","section":"Applications"}', "applications", None, None),
    ('Sure! Here is the filter: {"filter":"Docker","section":"Applications","level":"any"}', "applications", "Docker", None),
]


@pytest.mark.parametrize(("reply", "section", "artifact", "level"), SELFTEST)
def test_the_handoff_selftest_lands_on_the_right_section_artifact_and_level(reply, section, artifact, level):
    filters, _, _ = _coerced(reply)
    assert (filters["section"], filters["artifact"], filters["level"]) == (section, artifact, level)


def test_a_fenced_reply_keeps_its_search_and_an_upper_case_level():
    filters, unsupported, repairs = _coerced(SELFTEST[1][0])
    assert filters == {**NO_FILTERS, "q": "KY4QVD7430", "level": "high", "section": "hardware"}
    assert unsupported is None
    assert repairs == []


def test_a_near_miss_section_is_reported_not_guessed():
    _, _, repairs = _coerced(SELFTEST[2][0])
    assert repairs == ["The model named a section this page does not have, so it was read as any section."]
    # Any section is more than the model named: a widening repair, so the answer is proposed.
    assert _widening(repairs) == repairs


def test_a_section_named_by_its_key_is_accepted_too():
    filters, _, repairs = coerce({"section": "disk_encryption"})
    assert filters["section"] == "disk_encryption"
    assert repairs == []


def test_an_unknown_level_is_any_and_says_so():
    filters, _, repairs = coerce({"level": "critical"})
    assert filters["level"] is None
    assert repairs == ["The model named a level that is not any, low, normal or high, so it was read as any level."]
    assert _widening(repairs) == repairs


# --- the change ------------------------------------------------------------------------------


@pytest.mark.parametrize("change", ["added", "removed", "updated", "changed", "ADDED", " updated "])
def test_a_change_kind_is_kept(change):
    filters, _, repairs = coerce({"change": change})
    assert filters["change"] == change.strip().lower()
    assert repairs == []


@pytest.mark.parametrize("change", ["any", "ANY", None, ""])
def test_change_any_or_left_out_is_unset(change):
    filters, _, repairs = coerce({"change": change})
    assert filters["change"] is None
    assert repairs == []


def test_an_unknown_change_is_any_and_says_so_without_quoting_it():
    filters, _, repairs = coerce({"change": "installed"})
    assert filters["change"] is None
    assert repairs == [
        "The model named a change that is not any, added, removed, updated or changed, so it was read as any change."
    ]
    assert _widening(repairs) == repairs


# --- the whitelist -------------------------------------------------------------------------


# The refusal, as the page shows it: what a name may hold, never what this one held.
REFUSED_FILTER = (
    "Dropped the model's value for Filter to one thing: a name here takes only letters and digits in any script, "
    "spaces, and . _ @ ' \u2019 ( ) + / - & # ! , : \u2014 it held another character."
)


def test_the_injection_value_is_dropped_and_never_quoted_back():
    filters, _, repairs = _coerced(SELFTEST[3][0])
    assert filters["artifact"] is None
    assert repairs == [REFUSED_FILTER]
    assert "DROP" not in " ".join(repairs)
    assert "Robert" not in " ".join(repairs)
    # The name filter left empty matches every application: wider than the model's answer.
    assert _widening(repairs) == [REFUSED_FILTER]


def test_the_refusal_is_true_of_the_whitelist_it_describes():
    """#436: the first sentence said the value "carried characters no name here has", and
    Café Manager has them. This one lists what is kept, so every character it names must be."""
    listed = REFUSED_FILTER.split("spaces, and ", 1)[1].split(" \u2014 ", 1)[0].split(" ")
    assert len(listed) == 15
    for mark in listed:
        filters, _, repairs = coerce({"filter": f"Wire{mark}shark"})
        assert (filters["artifact"], repairs) == (f"Wire{mark}shark", []), mark


# Kept: letters and digits in any script, and the punctuation real names carry.
KEPT_NAMES = [
    "Caf\u00e9 Manager",  # Café Manager: the issue's own example (#436)
    "AT&T Global Network Client",
    "C#",
    "Pok\u00e9mon GO",  # Pokémon GO
    "\u5fae\u4fe1",  # WeChat, in Chinese
    "\u30ab\u30ab\u30aa\u30c8\u30fc\u30af",  # KakaoTalk in katakana; the long-vowel mark is a letter (Lm)
    "\u0939\u093f\u0928\u094d\u0926\u0940",  # Hindi, written with vowel signs and a virama (Mc, Mn)
    "Yahoo!",
    "Hello, World: Notes",
    "Kyle\u2019s Mac mini",
    "google_chrome-2 (beta) +v1/x @home",
]


@pytest.mark.parametrize("name", KEPT_NAMES)
def test_a_real_name_in_any_script_is_kept(name):
    filters, _, repairs = coerce({"search": name, "filter": name})
    assert (filters["q"], filters["artifact"]) == (name, name)
    assert repairs == []


# Refused: every character an injection is made of, and the invisible ones.
REFUSED_NAMES = [
    "Robert'); DROP TABLE devices;--",
    "%",
    "Wire%shark",
    '"Wireshark"',
    "<b>Wireshark</b>",
    "Wire\\shark",
    "name=Wireshark",
    *(f"Wire{mark}shark" for mark in ";*?`${}[]|~^"),
    "Wire\u200bshark",  # zero-width space
    "Wire\u202eshark",  # right-to-left override
    "Wire\tshark",
    "Wire\x00shark",
    "Wireshark \u2122",  # a symbol, not a letter
]


@pytest.mark.parametrize("name", REFUSED_NAMES)
def test_an_injection_shaped_value_is_still_dropped_and_widens(name):
    filters, _, repairs = coerce({"filter": name})
    assert filters["artifact"] is None
    assert repairs == [REFUSED_FILTER]
    assert _widening(repairs) == repairs


def test_sixty_four_characters_is_a_name_and_sixty_five_is_not():
    filters, _, repairs = coerce({"filter": "a" * 64})
    assert filters["artifact"] == "a" * 64
    assert repairs == []
    filters, _, repairs = coerce({"filter": "a" * 65})
    assert filters["artifact"] is None
    assert any("longer than 64" in repair for repair in repairs)
    assert _widening(repairs) == repairs


def test_the_typographic_apostrophe_macos_names_a_mac_with_is_kept():
    filters, _, repairs = coerce({"search": "Kyle\u2019s Mac mini"})
    assert filters["q"] == "Kyle\u2019s Mac mini"
    assert repairs == []


def test_a_jamf_id_sent_as_a_number_is_a_search_and_a_boolean_is_not():
    filters, _, repairs = coerce({"search": 42, "filter": True})
    assert filters["q"] == "42"
    assert filters["artifact"] is None
    assert repairs == ["Dropped the model's value for Filter to one thing: it was not text."]
    assert _widening(repairs) == repairs


def test_no_repair_quotes_a_value_or_a_key_the_page_refused():
    """Every refusal at once, each carrying the same marker; none of the repairs does."""
    hostile = "<b>zq9</b>"
    obj = {
        "search": hostile,
        "filter": hostile,
        "level": hostile,
        "section": hostile,
        "change": hostile,
        "unsupported": [hostile],
        hostile: hostile,
    }
    filters, unsupported, repairs = coerce(obj)
    assert filters == NO_FILTERS
    assert unsupported is None
    assert len(repairs) == 7
    assert "zq9" not in " ".join(repairs)
    # The five controls emptied widen the answer, and so does the ignored key, which held
    # a value; only the note does not.
    assert len(_widening(repairs)) == 6
    assert [r for r in repairs if r not in _widening(repairs)] == [
        "Dropped the model's note on what the filters cannot express: it was not text.",
    ]


# --- what the reply may carry ----------------------------------------------------------------


IGNORED_ONE = "Ignored 1 field the Prompt bar does not use, holding a value that may have been meant as a filter."
IGNORED_EMPTY = "Ignored 1 field the Prompt bar does not use, holding nothing."


def test_unknown_keys_are_ignored_and_counted_never_named():
    filters, _, repairs = coerce({"filter": "Docker", "sort": "desc", "limit": 5, "why": None, "notes": []})
    assert filters == {**NO_FILTERS, "artifact": "Docker"}
    assert repairs == [
        "Ignored 2 fields the Prompt bar does not use, holding values that may have been meant as filters.",
        "Ignored 2 fields the Prompt bar does not use, holding nothing.",
    ]


@pytest.mark.parametrize("key", ["sort", "<img src=x onerror=alert(1)>"])
def test_one_unknown_key_is_counted_whatever_its_shape(key):
    _, _, repairs = coerce({key: 1})
    assert repairs == [IGNORED_ONE]


@pytest.mark.parametrize(
    "reply",
    [
        "I cannot help with that.",
        "",
        "{not json}",
        "[1, 2, 3]",
        '"just a string"',
        "42",
        "null",
        '```json\n["Wireshark"]\n```',
        "[" * 4_000 + "]" * 4_000,
        "[" * 100_000 + "]" * 100_000,
    ],
)
def test_a_reply_without_a_filter_object_is_not_parsed_and_sets_nothing(reply):
    assert parse_reply(reply) is None
    assert interpret("which computers installed wireshark", reply) == NOT_PARSED


@pytest.mark.parametrize("reply", ["{}", '{"foo": 1}', '{"sort":"desc","limit":5}'])
def test_an_object_with_none_of_the_fields_asked_for_is_not_an_answer(reply):
    """Coerced, it is every control unset: applied, the whole feed under a readback that
    says the question was understood."""
    assert parse_reply(reply) is not None
    assert interpret("anything high severity on KY4QVD7430", reply) == NOT_PARSED


def test_one_field_asked_for_is_an_answer_even_when_it_is_null():
    result = interpret("show me everything", '{"search": null, "foo": 1}')
    assert result.parsed is True
    assert result.filters == NO_FILTERS
    assert result.repairs == [IGNORED_ONE]


def test_a_megabyte_of_braces_is_refused_at_once():
    """The first parser's brace-to-brace pattern backtracked over this for 161.8 s, and the
    route runs it on the event loop."""
    started = time.perf_counter()
    result = interpret("which computers installed wireshark", "{" * 1_000_000)
    elapsed = time.perf_counter() - started
    assert result == NOT_PARSED
    assert elapsed < 0.5, f"{elapsed:.3f} s"


@pytest.mark.parametrize(
    "reply",
    [
        "{" * MAX_REPLY_CHARS,
        "}" * MAX_REPLY_CHARS,
        "{" * (MAX_REPLY_CHARS // 2) + "}" * (MAX_REPLY_CHARS // 2),
        '{"a":' * (MAX_REPLY_CHARS // 5),
        "```" * (MAX_REPLY_CHARS // 3),
    ],
)
def test_the_worst_reply_the_parser_does_read_is_read_quickly(reply):
    assert len(reply) <= MAX_REPLY_CHARS
    started = time.perf_counter()
    assert parse_reply(reply) is None
    assert time.perf_counter() - started < 0.5


def test_a_reply_at_the_cap_is_read_and_one_character_more_is_not():
    obj = '{"filter":"Docker","section":"Applications"}'
    at_cap = obj + " " * (MAX_REPLY_CHARS - len(obj))
    assert parse_reply(at_cap) == {"filter": "Docker", "section": "Applications"}
    assert parse_reply(at_cap + " ") is None


@pytest.mark.parametrize(
    "reply",
    [
        '{"filter":"Docker","section":"Applications"}',
        'Sure! Here is the filter: {"filter":"Docker","section":"Applications"} Let me know if it helps.',
        '```json\n{"filter":"Docker","section":"Applications"}\n```',
        '```\n{"filter":"Docker","section":"Applications"}\n```',
        'Here you go:\n```json\n{"filter":"Docker","section":"Applications"}\n```\nThat should do it.',
    ],
)
def test_an_object_wrapped_in_prose_or_a_fence_is_still_read(reply):
    assert parse_reply(reply) == {"filter": "Docker", "section": "Applications"}


@pytest.mark.parametrize("value", [["Cannot express OR"], 42, {"why": "no"}, True])
def test_an_unsupported_that_is_not_text_is_dropped(value):
    _, unsupported, repairs = coerce({"unsupported": value})
    assert unsupported is None
    assert any("not text" in repair for repair in repairs)


def test_unsupported_is_one_plain_line_capped_at_three_hundred():
    _, unsupported, _ = coerce({"unsupported": "  Cannot\u202e express\nOR \u200b" + "x" * 400})
    assert unsupported.startswith("Cannot express OR x")
    assert "\u202e" not in unsupported and "\u200b" not in unsupported and "\n" not in unsupported
    assert len(unsupported) == 300


@pytest.mark.parametrize("value", ["", "   ", "null", "None"])
def test_an_empty_unsupported_is_none(value):
    _, unsupported, repairs = coerce({"unsupported": value})
    assert unsupported is None
    assert repairs == []


# --- the guards ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "artifact",
    ["Disk encryption", "Application", "Local accounts", "Configuration profiles", "Operating system", "Security", "any"],
)
def test_a_section_or_a_kind_is_not_one_thing(artifact):
    filters, _, repairs = guard("show me changes", {**NO_FILTERS, "artifact": artifact}, None, [])
    assert filters["artifact"] is None
    assert any("names a section or a kind" in repair for repair in repairs)


def test_one_named_thing_stands():
    filters, _, repairs = guard("who added zoom", {**NO_FILTERS, "artifact": "Zoom"}, None, [])
    assert filters["artifact"] == "Zoom"
    assert repairs == []


def test_a_search_that_repeats_the_name_filter_is_cleared_without_quoting_it():
    filters, _, repairs = guard(
        "machines that moved to chrome 153",
        {**NO_FILTERS, "q": "Chrome", "artifact": "Google Chrome", "section": "applications"},
        None,
        [],
    )
    assert filters["q"] is None
    assert filters["artifact"] == "Google Chrome"
    assert repairs == ["Cleared Search: it repeated the Filter to one thing name instead of naming a device."]


@pytest.mark.parametrize(
    ("q", "artifact"), [("Chrome", "Google Chrome"), ("google", "Google Chrome"), ("WIRESHARK", "Wireshark")]
)
def test_a_search_that_is_the_name_or_a_piece_of_it_is_a_repeat(q, artifact):
    filters, _, _ = guard("show me changes", {**NO_FILTERS, "q": q, "artifact": artifact}, None, [])
    assert filters["q"] is None
    assert filters["artifact"] == artifact


@pytest.mark.parametrize(
    ("question", "q", "artifact"),
    [
        # A Mac named after an app: the name is a piece of the Search, not the other way round.
        ("zoom changes on Zoom Room Conf A", "Zoom Room Conf A", "Zoom"),
        # A Jamf ID or a serial names only a device, whatever it happens to sit inside.
        ("Office 365 changes on Jamf ID 3", "3", "Office 365"),
        ("changes on C02XL0ABJG5H", "C02XL0ABJG5H", "C02XL0ABJG5H Tools"),
    ],
)
def test_a_device_whose_name_holds_the_app_name_stands(question, q, artifact):
    filters, _, repairs = guard(question, {**NO_FILTERS, "q": q, "artifact": artifact}, None, [])
    assert (filters["q"], filters["artifact"]) == (q, artifact)
    assert repairs == []


def test_a_device_beside_a_name_stands():
    filters, _, repairs = guard("wireshark on KY4QVD7430", {**NO_FILTERS, "q": "KY4QVD7430", "artifact": "Wireshark"}, None, [])
    assert (filters["q"], filters["artifact"]) == ("KY4QVD7430", "Wireshark")
    assert repairs == []


def test_a_cleared_search_is_filled_from_the_one_serial_in_the_question():
    filters, _, repairs = guard("wireshark on VKM73DMG47", {**NO_FILTERS, "q": "Wireshark", "artifact": "Wireshark"}, None, [])
    assert (filters["q"], filters["artifact"]) == ("VKM73DMG47", "Wireshark")
    assert len(repairs) == 2


def test_the_one_serial_in_the_question_fills_an_empty_search():
    filters, _, repairs = guard("local account changes on VKM73DMG47", NO_FILTERS, None, [])
    assert filters["q"] == "VKM73DMG47"
    assert any("serial" in repair for repair in repairs)


@pytest.mark.parametrize(
    "question",
    [
        "did anyone install 1password",
        "compare KY4QVD7430 and VKM73DMG47",
    ],
)
def test_no_serial_or_two_serials_fill_nothing(question):
    filters, _, repairs = guard(question, NO_FILTERS, None, [])
    assert filters["q"] is None
    assert repairs == []


def test_the_serial_rule_never_overrides_the_models_search():
    filters, _, _ = guard("changes on VKM73DMG47", {**NO_FILTERS, "q": "Kyle\u2019s Mac mini"}, None, [])
    assert filters["q"] == "Kyle\u2019s Mac mini"


@pytest.mark.parametrize(
    "question",
    [
        "devices with wireshark but not docker",
        "machines that moved to chrome 153",
        "firefox or chrome installs",
        "changes in the last 24 hours",
        "computers missing the FileVault profile",
        "computers without crowdstrike",
        "Wireshark installs in the past week",
        "Which Macs installed Wireshark but not CrowdStrike?",
    ],
)
def test_unsupported_stands_when_the_question_asks_for_what_the_controls_cannot(question):
    _, unsupported, repairs = guard(question, NO_FILTERS, "Cannot express that.", [])
    assert unsupported == "Cannot express that."
    assert repairs == []


@pytest.mark.parametrize(
    "question",
    [
        "What serial numbers of computers have installed wireshark",
        "who added zoom",
        "list serial numbers with docker installed",
        "did anyone install 1password",
        "List new application installs",
    ],
)
def test_unsupported_is_dropped_when_the_question_asks_for_nothing_the_controls_cannot(question):
    _, unsupported, repairs = guard(question, NO_FILTERS, "Cannot express 'but not'.", [])
    assert unsupported is None
    assert any("no or, not, date, version or comparison word" in repair for repair in repairs)


@pytest.mark.parametrize("section", sorted(ENTRY_SECTIONS))
def test_changed_in_a_list_section_is_any_change(section):
    filters, _, repairs = guard("show me changes", {**NO_FILTERS, "section": section, "change": "changed"}, None, [])
    assert filters["change"] is None
    assert len(repairs) == 1
    assert "added, removed or updated, never changed" in repairs[0]


@pytest.mark.parametrize("section", sorted(set(SECTIONS.values()) - ENTRY_SECTIONS))
@pytest.mark.parametrize("change", ["added", "removed", "updated"])
def test_an_entry_change_in_a_field_section_is_any_change(section, change):
    filters, _, repairs = guard("show me changes", {**NO_FILTERS, "section": section, "change": change}, None, [])
    assert filters["change"] is None
    assert len(repairs) == 1
    assert "only records changed values" in repairs[0]


@pytest.mark.parametrize(
    ("section", "change"),
    [
        ("applications", "added"),
        ("applications", "removed"),
        ("local_user_accounts", "updated"),
        ("hardware", "changed"),
        ("definition", "changed"),
        *((None, change) for change in ("added", "removed", "updated", "changed")),
    ],
)
def test_a_change_the_section_records_or_with_no_section_stands(section, change):
    filters, _, repairs = guard("show me changes", {**NO_FILTERS, "section": section, "change": change}, None, [])
    assert filters["change"] == change
    assert repairs == []


def test_guard_works_on_copies():
    filters = {**NO_FILTERS, "artifact": "Application"}
    repairs: list[str] = []
    guard("local account changes on VKM73DMG47", filters, None, repairs)
    assert filters == {**NO_FILTERS, "artifact": "Application"}
    assert repairs == []


# --- which way a repair moves the answer (ruled 1C, #436) -------------------------------------


def test_a_repair_is_the_sentence_it_says_and_carries_its_direction():
    widening = Repair("Dropped it.", widens=True)
    assert widening == "Dropped it." and isinstance(widening, str) and widening.widens is True
    assert Repair("Fixed it.").widens is False
    # A plain string handed in, as a caller of `guard` may, is a repair that does not widen.
    assert _widening(["Fixed it.", widening]) == ["Dropped it."]
    assert all(type(sentence) is str for sentence in _widening([widening]))


@pytest.mark.parametrize(
    ("question", "filters", "unsupported"),
    [
        ("show me changes", {**NO_FILTERS, "artifact": "Application"}, None),
        ("machines that moved to chrome 153", {**NO_FILTERS, "q": "Chrome", "artifact": "Google Chrome"}, None),
        ("local account changes on VKM73DMG47", NO_FILTERS, None),
        ("who added zoom", NO_FILTERS, "Cannot express 'but not'."),
        ("show me changes", {**NO_FILTERS, "section": "local_user_accounts", "change": "changed"}, None),
        ("show me changes", {**NO_FILTERS, "section": "hardware", "change": "added"}, None),
    ],
    ids=[
        "a kind as the name",
        "a Search that repeats it",
        "the serial filled",
        "a false caveat",
        "changed in a list",
        "added in a field section",
    ],
)
def test_every_guard_fixes_or_narrows_and_never_widens(question, filters, unsupported):
    _, _, repairs = guard(question, filters, unsupported, [])
    assert len(repairs) == 1
    assert _widening(repairs) == []


def test_an_empty_unknown_key_and_a_note_that_is_not_text_do_not_widen():
    _, _, repairs = coerce({"filter": "Docker", "sort": None, "unsupported": 42})
    assert len(repairs) == 2
    assert _widening(repairs) == []


def test_an_unknown_key_that_held_a_name_is_proposed():
    """The name the controls never got: run, this was every added app."""
    reply = '{"search":null,"app":"Wireshark","level":"any","section":"Applications","change":"added"}'
    result = interpret("which macs installed wireshark", reply)
    assert result.filters == {**NO_FILTERS, "section": "applications", "change": "added"}
    assert result.widening == [IGNORED_ONE]


def test_a_widening_repair_survives_the_guards_and_marks_the_answer_widened():
    reply = '{"search":null,"filter":"Caf\u00e9 Manager;","level":"any","section":"Applications","change":"added"}'
    result = interpret("which macs installed caf\u00e9 manager", reply)
    assert result.parsed is True
    assert result.filters == {**NO_FILTERS, "section": "applications", "change": "added"}
    assert result.widened is True
    assert result.widening == [REFUSED_FILTER]


def test_a_name_in_any_script_is_applied_not_proposed():
    """The issue's question: with the ASCII whitelist its name was dropped and every added
    app was run; now the name is kept and nothing widens."""
    reply = '{"search":null,"filter":"Caf\u00e9 Manager","level":"any","section":"Applications","change":"added"}'
    result = interpret("which macs installed Caf\u00e9 Manager", reply)
    assert result.filters == {**NO_FILTERS, "artifact": "Caf\u00e9 Manager", "section": "applications", "change": "added"}
    assert result.repairs == []
    assert result.widened is False


@pytest.mark.parametrize(
    "field",
    [{"section": "Apps"}, {"level": "critical"}, {"change": "installed"}, {"search": ["KY4QVD7430"]}, {"filter": "a" * 65}],
    ids=["section", "level", "change", "search not text", "name too long"],
)
def test_each_widening_kind_marks_the_answer_widened(field):
    reply = json.dumps({"search": None, "filter": None, "level": "any", "section": "any", "change": "any", **field})
    result = interpret("show me changes", reply)
    assert result.parsed is True
    assert result.widened is True
    assert result.widening == result.repairs and len(result.repairs) == 1


def test_a_serial_filled_by_the_guard_is_applied_not_proposed():
    reply = '{"search":null,"filter":null,"level":"any","section":"any","change":"any","unsupported":null}'
    result = interpret("what happened on VKM73DMG47", reply)
    assert result.filters == {**NO_FILTERS, "q": "VKM73DMG47"}
    assert result.repairs == ["Filled Search with the one serial-number-shaped word in the question."]
    assert result.widened is False
    assert result.widening == []


@pytest.mark.parametrize("search", ["KY4QVD7430?", ["KY4QVD7430"]], ids=["refused", "not text"])
def test_a_search_dropped_then_filled_with_the_serial_is_applied_not_proposed(search):
    """The filters come out as a clean reply's, so the drop is said but does not widen."""
    reply = json.dumps({"search": search, "filter": None, "level": "any", "section": "any", "change": "any"})
    result = interpret("what happened on KY4QVD7430?", reply)
    assert result.filters == {**NO_FILTERS, "q": "KY4QVD7430"}
    assert len(result.repairs) == 2 and result.repairs[0].startswith("Dropped the model's value for Search")
    assert result.widened is False


def test_the_serial_undoes_only_the_search_drop():
    reply = '{"search":"KY4QVD7430?","filter":"Wireshark;","level":"any","section":"any","change":"any"}'
    result = interpret("did KY4QVD7430 install wireshark", reply)
    assert result.filters == {**NO_FILTERS, "q": "KY4QVD7430"}
    assert result.widening == [REFUSED_FILTER]


@pytest.mark.parametrize("word", ["all", "ALL", "null", "none", ""])
def test_a_word_for_no_filter_is_any_without_a_repair(word):
    reply = json.dumps({"search": None, "filter": None, "level": word, "section": word, "change": word})
    result = interpret("show me changes", reply)
    assert result == Interpretation(filters=NO_FILTERS, unsupported=None, repairs=[], parsed=True)


@pytest.mark.parametrize(
    "name",
    ["Wire\u3164shark", "Wire\u115fshark", "Wire\ufe0fshark", "Wire\u034fshark", "Wire\u180bshark", "Wire\U000e0100shark"],
    ids=["hangul filler", "choseong filler", "variation selector 16", "grapheme joiner", "mongolian selector", "VS17"],
)
def test_a_name_holding_a_character_that_draws_nothing_is_refused(name):
    """It reads back as "Wire shark" or "Wireshark" and matches no row: refused, and proposed."""
    filters, _, repairs = coerce({"filter": name})
    assert filters["artifact"] is None
    assert repairs == [REFUSED_FILTER]
    assert _widening(repairs) == repairs


@pytest.mark.parametrize(
    "name",
    [
        "\u0939\u093f\u0902\u0926\u0940",
        "\u0e20\u0e32\u0e29\u0e32\u0e44\u0e17\u0e22",
        "\u05e9\u05b8\u05c1\u05dc\u05d5\u05b9\u05dd",
    ],
    ids=["Devanagari", "Thai", "Hebrew with points"],
)
def test_a_name_written_with_combining_marks_is_kept(name):
    """Marks that draw are part of the name: these scripts write letters with them."""
    filters, _, repairs = coerce({"filter": name})
    assert (filters["artifact"], repairs) == (name, [])


# --- whole replies ---------------------------------------------------------------------------


def test_the_demo_question_end_to_end_filters_without_a_banner():
    reply = (
        '{"search":null,"filter":"Wireshark","level":"any","section":"Applications",'
        '"unsupported":"Cannot express \'but not\' - run the second filter separately."}'
    )
    result = interpret("What serial numbers of computers have installed wireshark", reply)
    assert result.parsed is True
    assert result.filters == {**NO_FILTERS, "artifact": "Wireshark", "section": "applications"}
    assert result.unsupported is None


def test_local_account_changes_are_any_change_not_changed_values():
    reply = '{"search":"VKM73DMG47","filter":null,"level":"any","section":"Local accounts","change":"changed","unsupported":null}'
    result = interpret("local account changes on VKM73DMG47", reply)
    assert result.parsed is True
    assert result.filters == {**NO_FILTERS, "q": "VKM73DMG47", "section": "local_user_accounts"}
    assert result.repairs == ["Entries in Local accounts are added, removed or updated, never changed; showing any change."]


def test_moved_to_chrome_keeps_the_name_and_drops_the_search_that_repeats_it():
    reply = (
        '{"search":"Chrome","filter":"Google Chrome","level":"any","section":"Applications",'
        '"change":"updated","unsupported":"Cannot match a specific version."}'
    )
    result = interpret("machines that moved to chrome 153", reply)
    assert result.parsed is True
    assert result.filters == {**NO_FILTERS, "artifact": "Google Chrome", "section": "applications", "change": "updated"}
    assert result.unsupported == "Cannot match a specific version."
    assert result.repairs == ["Cleared Search: it repeated the Filter to one thing name instead of naming a device."]


# Kyle's three demo questions (2026-09-14), each with the answer the live lane expects of
# the model, and what the page is then set to. Only the third keeps its banner.
DEMO = [
    (
        "List new application installs",
        '{"search":null,"filter":null,"level":"any","section":"Applications","change":"added","unsupported":null}',
        {**NO_FILTERS, "section": "applications", "change": "added"},
        None,
    ),
    (
        "Changes made to VKM73DMG47",
        '{"search":"VKM73DMG47","filter":null,"level":"any","section":"any","change":"any","unsupported":null}',
        {**NO_FILTERS, "q": "VKM73DMG47"},
        None,
    ),
    (
        "Which Macs installed Wireshark but not CrowdStrike?",
        '{"search":null,"filter":"Wireshark","level":"any","section":"Applications","change":"added",'
        '"unsupported":"Cannot express \'but not\' - run the second filter separately."}',
        {**NO_FILTERS, "artifact": "Wireshark", "section": "applications", "change": "added"},
        "Cannot express 'but not' - run the second filter separately.",
    ),
]


@pytest.mark.parametrize(("question", "reply", "filters", "unsupported"), DEMO, ids=[d[0] for d in DEMO])
def test_the_demo_questions_set_the_page_as_ruled(question, reply, filters, unsupported):
    result = interpret(question, reply)
    assert result == Interpretation(filters=filters, unsupported=unsupported, repairs=[], parsed=True)
    # Applied on Enter, never held back as a proposal (1C).
    assert result.widened is False


# --- the way in ------------------------------------------------------------------------------


def test_the_question_leaves_as_one_plain_line():
    raw = "  which\u202e computers\u200b\ninstalled\x00 wire\tshark\r\n  "
    assert sanitize_question(raw) == "which computers installed wire shark"


def test_the_question_is_normalised_and_capped():
    assert sanitize_question("cafe\u0301") == "caf\u00e9"
    long = sanitize_question("wireshark " * 200)
    assert len(long) <= MAX_QUESTION_CHARS
    assert not long.endswith(" ")
    assert sanitize_question(long) == long


@pytest.mark.parametrize("raw", ["", "   ", "\n\t", "\u200b\u202e\x00"])
def test_a_question_of_nothing_visible_is_empty(raw):
    assert sanitize_question(raw) == ""


# --- the constants the route leans on --------------------------------------------------------


def test_the_gate_is_told_one_field_and_the_bounds_are_the_ruled_ones():
    assert FEATURE == "changes_prompt"
    assert DISCLOSED_FIELDS == ("query_text",)
    assert (MAX_QUESTION_CHARS, MAX_REPLY_TOKENS, CALL_TIMEOUT_SECONDS) == (500, 200, 30.0)
    assert MAX_REPLY_CHARS == 8_000


def test_the_module_is_stdlib_only():
    """S1 names three modules this one must not import; the contract is stricter —
    nothing outside the standard library, so it stays testable and pure."""
    tree = ast.parse(MODULE.read_text())
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    roots = {name.split(".")[0] for name in imported}
    assert roots <= set(sys.stdlib_module_names) | {"__future__"}, roots - set(sys.stdlib_module_names)


# --- drift: one vocabulary, three copies -----------------------------------------------------


def _section_order() -> list[str]:
    match = re.search(r"export const SECTION_ORDER = \[(.*?)\] as const;", RENDER_TS.read_text(), re.S)
    assert match, "frontend/src/features/changes/render.ts no longer declares SECTION_ORDER"
    return re.findall(r'"([^"]+)"', match.group(1))


def _change_kinds() -> list[str]:
    match = re.search(r"export const CHANGE_KINDS\b[^=]*=\s*\[(.*?)\]", RENDER_TS.read_text(), re.S)
    assert match, "frontend/src/features/changes/render.ts does not declare CHANGE_KINDS"
    return re.findall(r"[\"']([^\"']+)[\"']", match.group(1))


def test_the_section_keys_are_the_pages_section_order():
    assert list(SECTIONS.values()) == _section_order(), (
        "the Prompt bar would set a section the page's dropdown does not have, or miss one it does"
    )


def test_the_section_keys_are_the_jamf_contracts_sections_plus_the_group_definition():
    from app.mdm.jamf.contract import GROUP_DEFINITION_SECTION
    from app.mdm.jamf.contract import SECTIONS as JAMF_SECTIONS

    assert set(SECTIONS.values()) == set(JAMF_SECTIONS) | {GROUP_DEFINITION_SECTION}


def test_the_levels_are_the_change_policys_plus_any():
    from app.changes.policy import LEVELS as POLICY_LEVELS

    assert set(LEVELS) - {"any"} == set(POLICY_LEVELS)


def test_the_change_kinds_are_the_pages_change_control_plus_any():
    kinds = _change_kinds()
    assert CHANGES[0] == "any"
    assert sorted(kinds) == sorted(CHANGES[1:]), (
        "the Prompt bar would set a change the page's Change control does not offer, or miss one it does"
    )


def test_the_change_kinds_are_what_the_changes_api_accepts():
    """The third copy: GET /api/changes refuses a change outside its own tuple, and the
    prompt's summary is built with it — a kind the prompt allows but the API does not
    would 422 after the model was already asked."""
    from app.api.changes import CHANGE_KINDS as API_CHANGE_KINDS

    assert sorted(API_CHANGE_KINDS) == sorted(CHANGES[1:])


def test_the_list_sections_are_the_change_policys_entry_rule_sections():
    """The guard's premise: a list section's rows are added, removed or updated."""
    from app.changes.policy import ENTRY_RULES

    assert set(ENTRY_SECTIONS) == {rule.section for rule in ENTRY_RULES}
    assert set(ENTRY_SECTIONS) <= set(SECTIONS.values())


def test_every_other_section_is_a_field_rule_section():
    """And the other half: every section that is not a list is scalar fields, whose rows
    are only ever changed."""
    from app.changes.policy import FIELD_RULES

    assert set(SECTIONS.values()) - ENTRY_SECTIONS == {rule.section for rule in FIELD_RULES}


# --- the instructions ------------------------------------------------------------------------

# The first prompt's four examples, as the measured prompt carries them. The Change control
# came after that prompt, so each of its answers gained a "change" key ("updated" for the
# Chrome move: a new version of an app that was already there) and nothing else in them
# moved. The second prompt's lines are pinned, with the first prompt's beside them so the
# key is provably the only difference. Copied here, not read from anywhere, so a reword of
# any copy fails. (question, the answer as measured, the answer as first handed over)
ORIGINAL_EXAMPLES = [
    (
        "Q: find devices that installed wireshark",
        '{"search":null,"filter":"Wireshark","level":"any","section":"Applications","change":"added","unsupported":null}',
        '{"search":null,"filter":"Wireshark","level":"any","section":"Applications","unsupported":null}',
    ),
    (
        "Q: anything high severity on KY4QVD7430",
        '{"search":"KY4QVD7430","filter":null,"level":"high","section":"any","change":"any","unsupported":null}',
        '{"search":"KY4QVD7430","filter":null,"level":"high","section":"any","unsupported":null}',
    ),
    (
        "Q: machines that moved to chrome 153",
        '{"search":null,"filter":"Google Chrome","level":"any","section":"Applications","change":"updated",'
        '"unsupported":"Cannot match a specific version — filters match names, not values."}',
        '{"search":null,"filter":"Google Chrome","level":"any","section":"Applications",'
        '"unsupported":"Cannot match a specific version — filters match names, not values."}',
    ),
    (
        "Q: devices with wireshark but not docker",
        '{"search":null,"filter":"Wireshark","level":"any","section":"Applications","change":"any",'
        '"unsupported":"Cannot express \'but not\' — run the second filter separately."}',
        '{"search":null,"filter":"Wireshark","level":"any","section":"Applications",'
        '"unsupported":"Cannot express \'but not\' — run the second filter separately."}',
    ),
]


def _examples() -> list[tuple[str, str]]:
    lines = SYSTEM_INSTRUCTION.split("Examples:\n", 1)[1].splitlines()
    return [(q.removeprefix("Q: "), a) for q, a in zip(lines[::2], lines[1::2], strict=True)]


def test_the_instructions_name_every_section_level_and_change_in_order():
    for name in SECTIONS:
        assert name in SYSTEM_INSTRUCTION, name
    assert ", ".join(SECTIONS) in SYSTEM_INSTRUCTION
    for level in LEVELS:
        assert level in SYSTEM_INSTRUCTION, level
    assert f"one of: {', '.join(LEVELS)}\n" in SYSTEM_INSTRUCTION
    assert f"one of: {', '.join(CHANGES)}. " in SYSTEM_INSTRUCTION


@pytest.mark.parametrize(("question", "answer", "first"), ORIGINAL_EXAMPLES)
def test_the_original_examples_are_kept_word_for_word_but_for_the_change(question, answer, first):
    assert f"{question}\n{answer}\n" in SYSTEM_INSTRUCTION
    assert re.sub(r'"change":"[a-z]+",', "", answer, count=1) == first


def test_every_example_survives_the_parser_and_the_guards_untouched():
    """An example the page would repair teaches the model a shape the page changes."""
    examples = _examples()
    assert len(examples) == 8
    for question, answer in examples:
        assert question and answer.startswith("{"), (question, answer)
        result = interpret(question, answer)
        assert result.parsed and result.repairs == [], (question, result.repairs)


def test_the_instructions_are_the_measured_text():
    """The eval score in the module's comment belongs to these exact bytes. Changing them
    is allowed; doing it without re-running the eval and updating the comment, and this
    digest, is what this refuses."""
    digest = hashlib.sha256(SYSTEM_INSTRUCTION.encode()).hexdigest()
    assert digest == "9ddf259a96bdfe612f1e222cbfca4f9551551de7b0059ddbe190d48992df9272"
