"""The Changes page's Prompt bar, the model's half: a question in, the page's own filter
state out. Sentence-to-filter, the first slot of ``docs/ai-threat-model.md`` §7.

The model never sees device rows. It only fills in the five controls the page already
has, chosen from closed vocabularies, and Postgres does the filtering. That keeps the
cost of a question fixed no matter how large the fleet is, and makes it structurally
impossible for the model to invent a row or reach the database. (It can put a serial it
made up in Search; guard rule 3 drops one the question never named.)

What leaves is the static instructions below and the operator's question, nothing else.
What comes back is forced into the page's vocabulary before the page sees it:

1. ``parse_reply`` finds the one JSON object in the reply, or says there is none; a
   reply longer than any filter object is refused unread;
2. ``coerce`` keeps a value only if it is a known level, section or change, or a name the
   character whitelist accepts, and ignores keys it does not know;
3. ``guard`` applies six deterministic rules for what the model gets wrong on its own.

One filter is not the model's at all: ``resolve_since`` reads a start out of the question's
own words, against the server's clock and the viewer's zone (Kyle, 2026-09-16, #444). The
instructions never mention it, so their measurement holds.

Every change a step makes is written down as a repair, in the page's words. A repair
never quotes a value the whitelist refused, nor a key the page does not know: the only
free text of the model's that reaches the page is ``unsupported``, and the page renders
it as text.

A repair also carries which way it moved the answer (``Repair``). Most fix it or narrow
it, and the page runs the answer at once. A dropped name, a serial the question never
named, an unknown section, level or change read as any, or an unknown key that held a
value widens it: the page then gets the filters as a proposal, and a person applies them
(Kyle, 2026-09-15, ruling 1C on #436).

Some text is not a question the filters can answer: a greeting, a question about the
model, general knowledge, a request to write something, an order to do something to a
device. Asked "What model are you?", the model used to answer every control "any", which
is the whole log, and the page listed every device (Kyle, 2026-09-15). The instructions
now tell it to reply ``{"invalid": true}`` to such text, and ``interpret`` reads that as
``Interpretation.invalid``: the page runs nothing and says why in its own words. The
refusal is the model's judgement, not a word list over the question: a list refused real
questions ("Install macOS Sequoia" is an app; "Was hat sich getan?" asks what changed)
wherever it was tried.

Pure and stdlib-only on purpose: no database, no network, and none of ``app.models``,
``app.core.outbox`` or ``app.core.sharing`` (threat-model S1, ``tests/test_ai_structure.py``).
The route, ``app.api.changes_prompt``, does the gating and the talking.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

FEATURE = "changes_prompt"
# A typed search string is fleet data (``app.core.ai``), so the gate is told it leaves and
# the share log names it. It is the only thing that does.
DISCLOSED_FIELDS = ("query_text",)
MAX_QUESTION_CHARS = 500
# A filter object is a few dozen tokens; the rest is room for a model that wraps it in a
# fence or a sentence anyway.
MAX_REPLY_TOKENS = 200
# What the parser reads at most. A 200-token answer is well under a thousand characters,
# so anything longer is not a filter object, whatever an endpoint that ignored
# ``max_tokens`` sent; it is refused before any of it is scanned.
MAX_REPLY_CHARS = 8_000
# The page waits on this, so it is far shorter than the test box's wall clock.
CALL_TIMEOUT_SECONDS = 30.0

# ---------------------------------------------------------------------------------------
# The vocabulary. These are the ONLY values the model may produce; anything else is
# rejected before it reaches the query layer. The model speaks the display names, which
# are what an operator says; the page speaks the keys. `tests/test_changes_prompt.py`
# pins the keys to the page's `SECTION_ORDER` and to the Jamf contract's sections.
# ---------------------------------------------------------------------------------------

SECTIONS: dict[str, str] = {
    "General": "general",
    "Hardware": "hardware",
    "Operating system": "operating_system",
    "User and location": "user_and_location",
    "Purchasing": "purchasing",
    "Security": "security",
    "Disk encryption": "disk_encryption",
    "Smart group definition": "definition",
    "Applications": "applications",
    "Extension attributes": "extension_attributes",
    "Smart group memberships": "group_memberships",
    "Configuration profiles": "configuration_profiles",
    "Local accounts": "local_user_accounts",
    "Certificates": "certificates",
    "Pending updates": "software_updates",
}
# "any" is the model's word for leaving the control unset; the rest are
# `app.changes.policy.LEVELS`.
LEVELS: tuple[str, ...] = ("any", "low", "normal", "high")
# The same "any", then the values `device_changes.change` holds: an entry in a list
# section is added, removed or updated; a field in any other section is changed. The
# page's Change control offers the four (`CHANGE_KINDS` in the SPA's `render.ts`).
CHANGES: tuple[str, ...] = ("any", "added", "removed", "updated", "changed")
# The list sections, the ones `app.changes.policy.ENTRY_RULES` covers. The rest are
# `FIELD_RULES`' and only ever record `changed`. A constant because this module imports
# nothing of the app's; `tests/test_changes_prompt.py` pins it to both tables.
ENTRY_SECTIONS: frozenset[str] = frozenset(
    {
        "applications",
        "extension_attributes",
        "group_memberships",
        "configuration_profiles",
        "local_user_accounts",
        "certificates",
        "software_updates",
    }
)

# Free-text fields are capped and character-restricted. They reach the query layer as
# bound parameters, never interpolated, but a tight whitelist here means a malformed
# generation fails loudly instead of quietly matching nothing. A name keeps letters and
# digits in any script (Café Manager, Pokémon GO, a name in Japanese), with the marks
# some scripts write a letter with (a Devanagari vowel sign is one; NFC composes Latin
# accents, not those), and the punctuation real names carry: "AT&T Global Network
# Client", "C#". U+2019 is in it because macOS names a Mac with the typographic apostrophe.
# Anything else is refused: the characters an injection is made of first among them
# (; % " < > \ = * ? ` $ { } [ ] | ~ ^), and every symbol, control and format character.
# The first whitelist was ASCII, and dropped Café Manager's name (#436).
_NAME_CATEGORIES = frozenset({"Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Mc", "Nd"})
_NAME_PUNCTUATION = " ._@'\u2019()+/-&#!,:"
# Refused though their categories are a letter's or a mark's, because they draw nothing:
# the Hangul fillers (Lo), the combining grapheme joiner, the Khmer inherent vowels, and
# the Mongolian and Unicode variation selectors (Mn). "Wire", a Hangul filler, "shark"
# reads back as "Wire shark" and matches no row: the quiet failure the whitelist is for.
_INVISIBLE = (
    frozenset("\u115f\u1160\u3164\uffa0\u034f\u17b4\u17b5\u180b\u180c\u180d\u180f")
    | frozenset(map(chr, range(0xFE00, 0xFE10)))
    | frozenset(map(chr, range(0xE0100, 0xE01F0)))
)
_NAME_MAX_CHARS = 64
_UNSUPPORTED_MAX_CHARS = 300

# What the instructions below ask for. Anything else in a reply is ignored and said so,
# and a reply carrying none of these is not an answer at all.
_REPLY_KEYS = ("search", "filter", "level", "section", "change", "unsupported")
# The model's refusal: `{"invalid": true}` for text that is not a question about device
# changes. Read before the keys above, and never counted as a key the page does not use.
_REFUSAL_KEY = "invalid"
# Why a question is not one the filters can answer, as `Interpretation.invalid` carries it:
# a closed word, which the route turns into the page's own sentence. The model's refusal
# is the only one today.
NOT_ABOUT_CHANGES = "not_about_changes"

# The page's own names for its controls (`changes.search`, `changes.artifact` in the
# SPA's copy), so a repair reads in the words the operator sees above the table.
_SEARCH = "Search"
_ARTIFACT = "Filter to one thing"

# The instructions, static and versioned here (threat-model P2). Byte for byte the text
# measured against Apple FM through `fm serve` on 2026-09-14. The first version scored 29
# of 29 on a 29-question set with 10 held out, where the prompt as first handed over
# scored 5 of 19. This second one adds the `change` field, an eighth example and a
# "change" key in every example answer; it scored 35 of 35 on those 29 plus Kyle's three
# demo questions and three change probes, each through this module's parser and guards
# (`tests/test_changes_prompt_live.py`; median 1.1 s a question). The first four examples
# are the handed-over prompt's, word for word but for that key; the rest of the difference
# is the paragraph before them, the `low` level and four examples.
#
# The third (2026-09-15) adds the paragraph asking for `{"invalid":true}`, and nothing
# else. A 286-question set was written for it and split in two. Four panel designs were
# scored on the whole set (one, with two refusal examples, moved all three demo answers),
# then six wordings on one half; of the three that kept the 35 exact, this one refused the
# fewest real questions. Scored once on the other half: of 56 questions not about device
# changes, the second version ran 43 and this one runs 17 (5 of them as the whole log) and
# holds 1 as a proposal; of 81 real ones it refuses 5, each asking a device's current state
# or a share of the fleet ("how much memory does VKM73DMG47 have"). The 35 are still 35 of
# 35, and the live lane adds 20 texts it must refuse. Edit it and the measurement is gone.
SYSTEM_INSTRUCTION = """You convert a question about a device change log into filter settings.

You do NOT answer the question and you do NOT see any device data. You only choose filter values. Reply with JSON only, no prose, no markdown.

Fields:
  search    device name, serial number, or Jamf ID. null if not mentioned.
  filter    the NAME of an app, account, group, or profile. Names only, never version numbers or values. null if not mentioned.
  level     one of: any, low, normal, high
  section   one of: General, Hardware, Operating system, User and location, Purchasing, Security, Disk encryption, Smart group definition, Applications, Extension attributes, Smart group memberships, Configuration profiles, Local accounts, Certificates, Pending updates — or "any"
  change    one of: any, added, removed, updated, changed. added = installed or new; removed = uninstalled or deleted; updated = an app, profile or account that was already there changed; changed = a setting's value changed. The word "changes" alone means any.
  unsupported  null, OR a short sentence naming what these controls cannot express.

The controls CANNOT express: OR between two things, negation ("not", "without", "missing"), date or time ranges, matching a version or other value, or comparing two rows. If the question needs any of those, set unsupported and still fill in the closest values you can.

Everything else is supported, so unsupported is null. Every result row shows the device name and serial number, so asking which devices, which serial numbers, or who did something is supported. filter is null unless the question names one specific app, account, group, profile, or certificate; never put a section name or a generic word such as "application" or "profile" in filter. "Severity" means level.

Some text is not a question about device changes, and then you reply exactly {"invalid":true} and nothing else: a greeting or thanks; a question about you; general knowledge, or how to do something; math; a request to write text or code; a request to do something to a device or to this app, such as install, remove, lock, restart, push, create, alert or export; a question about vulnerabilities, compliance, risk or device health. Anything asking which devices had a change, or what changed, is a question about device changes, even when the controls only partly express it. A name alone, such as an app, a device, a serial number or a section, is a search. Asking for all changes is valid, with every field any.

Examples:
Q: find devices that installed wireshark
{"search":null,"filter":"Wireshark","level":"any","section":"Applications","change":"added","unsupported":null}
Q: anything high severity on KY4QVD7430
{"search":"KY4QVD7430","filter":null,"level":"high","section":"any","change":"any","unsupported":null}
Q: machines that moved to chrome 153
{"search":null,"filter":"Google Chrome","level":"any","section":"Applications","change":"updated","unsupported":"Cannot match a specific version — filters match names, not values."}
Q: devices with wireshark but not docker
{"search":null,"filter":"Wireshark","level":"any","section":"Applications","change":"any","unsupported":"Cannot express 'but not' — run the second filter separately."}
Q: which serial numbers have slack
{"search":null,"filter":"Slack","level":"any","section":"Applications","change":"any","unsupported":null}
Q: hardware changes
{"search":null,"filter":null,"level":"any","section":"Hardware","change":"any","unsupported":null}
Q: low level changes on C02XL0ABJG5H
{"search":"C02XL0ABJG5H","filter":null,"level":"low","section":"any","change":"any","unsupported":null}
Q: apps uninstalled from C02XL0ABJG5H
{"search":"C02XL0ABJG5H","filter":null,"level":"any","section":"Applications","change":"removed","unsupported":null}
"""  # noqa: E501


Filters = dict[str, str | None]


class Repair(str):
    """One repair's sentence, and which way it moved the answer (ruled 1C, #436).

    Most repairs fix the answer or narrow it: a caveat the question gives no ground for, a
    section name in the name filter, a Search that repeated it, the serial the model
    missed, a change the section never records, empty keys the page does not use. Four
    kinds widen it: a Search or Filter-to-one-thing value dropped (the whitelist refused
    it, or it was not text), a serial in Search the question never named (guard rule 3),
    an unknown section, level or change read as any, and a key the page does not use that
    held a value, which may have been meant as a filter (``{"app": "Wireshark"}``). Run
    as it stood, a widened answer searched for more than
    the question asked ("which macs installed Café Manager", its name dropped, ran every
    added app), so the page is handed it as a proposal to apply rather than running it.

    ``control`` names the control a drop emptied, so a guard that fills that control
    again from the question can say the drop no longer widens.

    A str, so a list of them joins, compares and reaches the page as the sentences they
    are; a plain str is a repair that does not widen."""

    widens: bool
    control: str | None

    def __new__(cls, sentence: str, widens: bool = False, control: str | None = None) -> Repair:
        repair = super().__new__(cls, sentence)
        repair.widens = widens
        repair.control = control
        return repair


def _widens(sentence: str, control: str | None = None) -> Repair:
    return Repair(sentence, widens=True, control=control)


def _fixes(sentence: str) -> Repair:
    return Repair(sentence, widens=False)


@dataclass(frozen=True)
class Interpretation:
    """What a reply meant, in the page's vocabulary. ``filters`` carries the page's URL
    keys (``q``, ``artifact``, ``level``, ``section``, ``change``, ``since``; None is
    "any" or unset). ``parsed`` is False when the reply held neither a filter object nor
    the model's refusal, and then nothing else is said.

    ``since`` is the one the model never wrote: it is read from the question's own words
    (#444), and ``since_asked`` carries the same start as an instant, to count rows with."""

    filters: Filters
    unsupported: str | None
    repairs: list[str]
    parsed: bool
    # Why the question is not one the filters can answer (``NOT_ABOUT_CHANGES``), or None.
    # When set, the filters are all unset and nothing is to run: the page says why instead.
    invalid: str | None = None
    # The start the question's words asked for, as ``resolve_since`` read it, or None.
    since_asked: Since | None = None

    @property
    def widening(self) -> list[str]:
        """The repairs that widened the answer, in the order they were made, as sentences."""
        return [str(repair) for repair in self.repairs if isinstance(repair, Repair) and repair.widens]

    @property
    def widened(self) -> bool:
        """Whether a repair widened the answer. Then it is proposed, never applied (1C)."""
        return bool(self.widening)


def _no_filters() -> Filters:
    return {"q": None, "artifact": None, "level": None, "section": None, "change": None, "since": None}


# --- the way in ------------------------------------------------------------------------

# Control, format and surrogate characters. Format (`Cf`) is the bidi overrides and the
# zero-width family: they render as nothing and reorder or hide what is around them. A
# lone surrogate is not text at all and would fail to encode on the wire.
_DROPPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


def _plain(text: str) -> str:
    """One line of visible text: any whitespace (tab, newline, U+2028…) as a single
    space, the characters above dropped, NFC, trimmed. Dropped before normalising so a
    combining mark that followed a hidden character composes with what it now follows."""
    kept: list[str] = []
    for ch in text:
        if ch.isspace():
            kept.append(" ")
        elif unicodedata.category(ch) not in _DROPPED_CATEGORIES:
            kept.append(ch)
    return " ".join(unicodedata.normalize("NFC", "".join(kept)).split())


# Model control tokens (docs/ai-threat-model.md P3): the strings a chat template is built
# from, which a tokenizer reads as a turn, a system block, the end of the text or a
# reasoning block rather than as words. Slot 1's question is written by the person who
# asks it, but a question pasted from a chat log or from a model's own output can carry
# them. The first slot that sends fleet data to a model needs this pattern for every value
# it sends — and more than this function: P3's per-field cap with a visible truncation
# marker, which a question's silent 500-character cap is not.
#
# The families, case-insensitive: `<|...|>` (ChatML's <|im_start|> and <|im_end|>,
# <|endoftext|>, Llama 3's <|eot_id|> and <|start_header_id|>), and DeepSeek's spelling of
# it with full-width bars; [INST] and [/INST]; <<SYS>> and <</SYS>>; <s> and </s>; <think>
# and </think>; Gemma's <start_of_turn> and <end_of_turn>. None of them holds whitespace,
# and a tokenizer matches one only character for character, so a token broken by a space or
# a newline is plain text already. That is also why one pass is enough: each token becomes
# a space, and no pattern matches across a space, so taking one out never joins the pieces
# around it into another.
_CONTROL_TOKENS = re.compile(
    r"<[|\uff5c][^\s<>|\uff5c]*[|\uff5c]>|\[/?INST\]|<</?SYS>>|</?s>|</?think>|<(?:start|end)_of_turn>",
    re.IGNORECASE,
)


def sanitize_question(text: str) -> str:
    """The question as it may leave: plain, without a model's control tokens, and at most
    ``MAX_QUESTION_CHARS``. Empty means there was nothing to ask.

    The tokens come out after ``_plain`` and before the cap. After, because a zero-width or
    control character inside a token hides it from the pattern, and ``_plain`` then drops
    the character and puts the token back together. Before, so the cap counts what leaves
    rather than what was taken out."""
    plain = " ".join(_CONTROL_TOKENS.sub(" ", _plain(text)).split())
    return plain[:MAX_QUESTION_CHARS].rstrip()


# --- the way back ----------------------------------------------------------------------

# Models wrap JSON in fences even when told not to. Each match is a fixed few characters
# at a line's edge, so the strip is one pass.
_FENCE = re.compile(r"^```(?:json)?|```$", re.M)


def parse_reply(text: str) -> dict[str, Any] | None:
    """The JSON object in a reply, or None when there is none: a reply longer than
    ``MAX_REPLY_CHARS`` refused unread, fences stripped, then everything from the first
    ``{`` to the last ``}`` parsed. Anything but an object is None too.

    The object is cut out with ``find`` and ``rfind``, not a pattern: a brace-to-brace
    regex tries every ``{`` against the rest of the reply, and a megabyte of ``{`` held
    the event loop for minutes. This is two scans of at most ``MAX_REPLY_CHARS``.

    A reply that is not JSON as written is not repaired. Apple's model writes a bare
    ``"level":any`` now and then: on 2026-09-15 it did so for 27 of 321 questions. Given
    their quotes, 24 of those replies parse, 22 of them to questions not about device
    changes ("who made you", "what's the capital of France"), and 20 are every control
    unset — the whole log, run. Left as they are, the page says it could not interpret the
    answer, and runs nothing."""
    if len(text) > MAX_REPLY_CHARS:
        return None
    cleaned = _FENCE.sub("", text.strip()).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    try:
        obj = json.loads(cleaned[start : end + 1] if 0 <= start < end else cleaned)
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


def _refused(obj: Mapping[str, Any]) -> bool:
    """The model's ``{"invalid": true}``. True, or the word true in quotes; nothing else,
    so a model that writes ``"invalid": false`` beside real filters has its filters read."""
    value = obj.get(_REFUSAL_KEY)
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _not_refused(value: Any) -> bool:
    """A refusal key that plainly says no: false, null, 0, "false", or empty."""
    if isinstance(value, str):
        return value.strip().lower() in ("", "false")
    return value is None or value is False or (isinstance(value, int) and value == 0) or value in ([], {})


def _fields(count: int) -> str:
    return f"{count} field{'' if count == 1 else 's'}"


def _ignored_keys(obj: Mapping[str, Any]) -> list[Repair]:
    """Counted, never named: a key is the model's own text, and the page has no use for it.

    An ignored key that held a value widens the answer: ``{"app": "Wireshark"}`` is a name
    the controls never got. One that held nothing (null, an empty string, list or object)
    moves nothing.

    The refusal key is the page's when it plainly says "not refused" (false, null, 0, "false"
    or empty) and is then passed over. Any other value that is not the refusal — a reason in
    words, 1, "yes" — is counted here like any key holding a value, so the answer widens and
    waits for Apply. Passed over silently, such a reply beside every control any was the
    whole log, run: the defect the refusal exists for."""
    unknown = [
        value for key, value in obj.items() if key not in _REPLY_KEYS and not (key == _REFUSAL_KEY and _not_refused(value))
    ]
    held = sum(1 for value in unknown if value not in (None, "", [], {}))
    empty = len(unknown) - held
    repairs: list[Repair] = []
    if held:
        what = "a value that may have been meant as a filter" if held == 1 else "values that may have been meant as filters"
        repairs.append(_widens(f"Ignored {_fields(held)} the Prompt bar does not use, holding {what}."))
    if empty:
        repairs.append(_fixes(f"Ignored {_fields(empty)} the Prompt bar does not use, holding nothing."))
    return repairs


def _is_name(text: str) -> bool:
    return all(ch not in _INVISIBLE and (ch in _NAME_PUNCTUATION or unicodedata.category(ch) in _NAME_CATEGORIES) for ch in text)


# The whitelist's punctuation as the refusal lists it: one space between each.
_NAME_PUNCTUATION_LISTED = " ".join(_NAME_PUNCTUATION.strip())


# Every drop here widens: the control the model filled is left empty, so the answer then
# matches more than the model's did.
def _name(value: Any, control: str, repairs: list[str]) -> str | None:
    if value is None:
        return None
    # A Jamf ID may arrive as a number; nothing else that is not a string is a name.
    if isinstance(value, bool) or not isinstance(value, str | int):
        repairs.append(_widens(f"Dropped the model's value for {control}: it was not text.", control))
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > _NAME_MAX_CHARS:
        repairs.append(
            _widens(
                f"Dropped the model's value for {control}: longer than {_NAME_MAX_CHARS} characters, so not a name.",
                control,
            )
        )
        return None
    if not _is_name(text):
        # True of the value without quoting it: says what a name may hold, not what this held.
        repairs.append(
            _widens(
                f"Dropped the model's value for {control}: a name here takes only letters and digits in any script, "
                f"spaces, and {_NAME_PUNCTUATION_LISTED} — it held another character.",
                control,
            )
        )
        return None
    return text


_SECTION_BY_WORD: dict[str, str] = {name.lower(): key for name, key in SECTIONS.items()} | {key: key for key in SECTIONS.values()}


# The words a model writes for "no filter" besides the "any" it is asked for. Each is read
# as any with no repair: the answer is no wider than the one the model meant.
_ANY = frozenset({"any", "all", "null", "none"})


# An unknown section, level or change is read as any, which widens the answer. Said as
# what was done to it rather than as "showing", since a widened answer is not shown until
# a person applies it.
def _section(value: Any, repairs: list[str]) -> str | None:
    word = str(value or "any").strip().lower()
    if word in _ANY:
        return None
    key = _SECTION_BY_WORD.get(word)
    if key is None:
        # A near miss is more useful reported than silently coerced.
        repairs.append(_widens("The model named a section this page does not have, so it was read as any section."))
    return key


def _level(value: Any, repairs: list[str]) -> str | None:
    level = str(value or "any").strip().lower()
    if level in _ANY:
        return None
    if level not in LEVELS:
        repairs.append(_widens("The model named a level that is not any, low, normal or high, so it was read as any level."))
        return None
    return None if level == "any" else level


def _change(value: Any, repairs: list[str]) -> str | None:
    change = str(value or "any").strip().lower()
    if change in _ANY:
        return None
    if change not in CHANGES:
        repairs.append(
            _widens("The model named a change that is not any, added, removed, updated or changed, so it was read as any change.")
        )
        return None
    return None if change == "any" else change


def _unsupported(value: Any, repairs: list[str]) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        repairs.append(_fixes("Dropped the model's note on what the filters cannot express: it was not text."))
        return None
    text = _plain(value)[:_UNSUPPORTED_MAX_CHARS].rstrip()
    # "null" written as a string is still null; a banner reading it would be noise.
    return None if text.lower() in {"", "null", "none"} else text


def coerce(obj: Mapping[str, Any]) -> tuple[Filters, str | None, list[str]]:
    """Force a reply object into the page's vocabulary. Anything that does not match a
    known value is dropped, not passed through, and every drop is a repair."""
    repairs: list[str] = [*_ignored_keys(obj)]
    filters: Filters = {
        "q": _name(obj.get("search"), _SEARCH, repairs),
        "artifact": _name(obj.get("filter"), _ARTIFACT, repairs),
        "level": _level(obj.get("level"), repairs),
        "section": _section(obj.get("section"), repairs),
        "change": _change(obj.get("change"), repairs),
        # Never the model's: `interpret` fills it from the question (#444), and one the model
        # invented is an unknown key like any other — counted, ignored, and widening.
        "since": None,
    }
    return filters, _unsupported(obj.get("unsupported"), repairs), repairs


# --- the time bound ---------------------------------------------------------------------
# Kyle ruled it on #444 (2026-09-16): the start comes from the question's own words, read here.
# Ruling 11 (`docs/ai-layer.md`) measured a sixth reply field at 2 to 6 wrong answers of 68, the
# injection refusal broken in every arrangement, so the instructions stay as measured and this
# costs them nothing. A word list was ruled out for *refusing* a question (#442); one that only
# sets a start refuses nothing, and a phrase it does not know sets no window at all.


@dataclass(frozen=True)
class Since:
    """A start the question asked for: the instant in UTC, and the words that set it. ``closed``
    marks a phrase that named an end as well — the answer runs past that end, so the question's
    date words are still beyond the controls and a caveat on them stands (guard rule 5)."""

    at: datetime
    phrase: str
    closed: bool = False


# A length of time back from now: "in the last 24 hours", "past 7 days", "3 days ago". A month is
# 30 days and a year 365 — an approximation, and the chip states the instant it resolved to.
_SINCE_UNITS: dict[str, timedelta] = {
    "minute": timedelta(minutes=1), "hour": timedelta(hours=1), "h": timedelta(hours=1),
    "day": timedelta(days=1), "d": timedelta(days=1), "week": timedelta(weeks=1), "w": timedelta(weeks=1),
    "month": timedelta(days=30), "year": timedelta(days=365),
}  # fmt: skip
_UNIT_WORDS = "|".join(sorted(_SINCE_UNITS, key=len, reverse=True))
_BACK = re.compile(
    r"\b(?:(?:in|over|within|during|from)\s+)?(?:the\s+)?(?:last|past|previous)\s+"
    rf"(?:(\d{{1,4}})\s*)?({_UNIT_WORDS})s?\b"
    rf"|\b(\d{{1,4}})\s*({_UNIT_WORDS})s?\s+ago\b",
    re.I,
)
_WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
_SINCE_WEEKDAY = re.compile(rf"\bsince\s+({'|'.join(_WEEKDAYS)})\b", re.I)
# From its first day; a week starts on Monday (ISO), which the chip's own date settles.
_THIS = re.compile(r"\bthis\s+(week|month|year)\b", re.I)
# "yesterday" named an end there is none to set (`closed`); "since yesterday" did not.
_DAY = re.compile(r"\b(since\s+)?(today|yesterday)\b", re.I)
# A zone as `Intl.DateTimeFormat().resolvedOptions().timeZone` writes one, checked before
# `ZoneInfo` is handed browser-supplied text.
_ZONE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_+/-]{0,63}")


def _viewer_zone(name: str | None) -> tzinfo:
    """The viewer's IANA zone, or UTC. Anything that is not a plain zone name, and any name this
    build's tzdb does not hold, is UTC: a start an hour or two off is a window the chip still
    states honestly, and a refusal would cost the answer."""
    if not name or not _ZONE_NAME.fullmatch(name):
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return UTC


def _since(at: datetime, phrase: str, closed: bool = False) -> Since:
    return Since(at=at.astimezone(UTC), phrase=" ".join(phrase.split()), closed=closed)


def resolve_since(question: str, now: datetime, zone: str | None = None) -> Since | None:
    """The start the question's own words ask for, resolved against ``now`` and the viewer's
    zone — or None, when they ask for none or ask for one this list does not hold.

    ``now`` is the server's clock, because the model does not know today's date and one it invented
    would narrow an answer silently (ruling 11); the zone is the browser's, so "today" is the
    operator's day. Midnight is taken there — on the one day a year a zone has none, it lands an
    hour to one side, inside the day either way."""
    text = sanitize_question(question)
    local = now.astimezone(_viewer_zone(zone))
    midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
    back = _BACK.search(text)
    if back:
        count, unit = (back[1], back[2]) if back[2] else (back[3], back[4])
        try:
            return _since(now - int(count or 1) * _SINCE_UNITS[unit.lower()], back[0])
        except OverflowError:
            return None  # "the last 9999 years" predates the year datetime counts from
    weekday = _SINCE_WEEKDAY.search(text)
    if weekday:
        back_days = (local.weekday() - _WEEKDAYS.index(weekday[1].lower())) % 7
        return _since(midnight - timedelta(days=back_days), weekday[0])
    period = _THIS.search(text)
    if period:
        word = period[1].lower()
        if word == "week":
            return _since(midnight - timedelta(days=local.weekday()), period[0])
        return _since(midnight.replace(day=1) if word == "month" else midnight.replace(month=1, day=1), period[0])
    day = _DAY.search(text)
    if day:
        if day[2].lower() == "today":
            return _since(midnight, day[0])
        return _since(midnight - timedelta(days=1), day[0], closed=not day[1])
    return None


def wire_time(at: datetime) -> str:
    """A start as the `since` URL key already carries one: UTC, ISO 8601, `Z` — the Overview
    link's format (`sinceAnchor.ts`), so both arrive at the page the same way."""
    return at.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


# --- the guards ------------------------------------------------------------------------
# Deterministic, after `coerce`: what a closed vocabulary cannot enforce on its own.

_GENERIC = {
    "any", "all", "none", "null", "everything", "anything",
    "app", "application", "software", "profile", "configuration profile",
    "account", "local account", "user", "group", "smart group", "certificate",
    "device", "computer", "mac", "machine", "change", "update", "software update",
    "extension attribute", "setting", "policy", "item", "thing",
}  # fmt: skip


def _singular(word: str) -> str:
    word = word.strip().lower()
    return word[:-1] if word.endswith("s") and not word.endswith("ss") else word


# Every section, by display name and by key, singular or plural.
_SECTION_WORDS = {form for word in _SECTION_BY_WORD for form in (word, _singular(word))}


def _names_a_kind(value: str) -> bool:
    word = _singular(value)
    return word in _GENERIC or word in _SECTION_WORDS


# A claim that the controls cannot express the question may stand only when the
# question carries a word of the kind the controls cannot express. Two groups, because one
# kind of range the controls now do express: with a start set, a question's date words are
# expressed after all, and only a word of the other kind keeps the caveat (rule 5).
_TIME_UNITS = r"minute|minutes|hour|hours|day|days|week|weeks|month|months|year|years"
# Dates and times. Deliberately NOT here: "last", "past", "recent", "recently", "latest",
# "most recent". Those ask for an order, not a range, and the feed is ordered by observed
# time, newest first, with that time in the answer box (ruling R3 on #443) — asked "when was
# the last time someone installed wireshark", the model's "Cannot express 'when' — filters
# match names, not timestamps" stood over an answer whose first row was the answer. A unit
# still makes a range: "last week" matches `week`, "past 3 days" matches `days`, "overnight"
# and "last night" match a word of their own.
_RANGE_MARKERS = re.compile(
    r"\b(today|yesterday|tonight|night|nights|overnight|weekend|weekends|"
    r"since|before|after|between|until|till|ago|" + _TIME_UNITS + "|"
    r"january|february|march|april|june|july|august|september|october|november|december|"
    r"monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b"
    # A number that is a length of time — "3 days", "24h" — which "chrome 153" is not.
    r"|(?<![a-z0-9])\d+\s*(?:" + _TIME_UNITS + r"|h|d|w|m)\b",
    re.I,
)
# Everything else the controls cannot do: or, negation, a value, a comparison between rows.
_OTHER_MARKERS = re.compile(
    r"\b(or|either|nor|not|no|without|missing|except|excluding|lacking|never|none|"
    r"version|versions|older|newer|below|above|under|over|less|greater|least|"
    r"compare|compared|comparing|than|versus|vs|differ|different|difference|same|both|and|also|"
    r"more|fewer|top|every|each)\b|n't\b|\bmost\b(?!\s+recent)"
    # A bare number: a version, a count, a threshold. Not a length of time, which is a range.
    r"|(?<![a-z0-9])\d+(?:\.\d+)*(?![a-z0-9])(?!\s*(?:" + _TIME_UNITS + r")\b)",
    re.I,
)

# Serial-number shaped: 8 to 14 capitals and digits, at least two of each.
_SERIALISH = re.compile(r"\b(?=[A-Z0-9]*\d[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z][A-Z0-9]*[A-Z])[A-Z0-9]{8,14}\b")


def _one_serial(question: str) -> str | None:
    found = _SERIALISH.findall(question)
    return found[0] if len(found) == 1 else None


def _compact(text: str) -> str:
    """Letters and digits only, compatibility-folded and casefolded: a serial typed as
    "KY4Q-VD74-30", "ky4q vd74 30" or in full-width letters is still KY4QVD7430."""
    return "".join(ch for ch in unicodedata.normalize("NFKC", text).casefold() if ch.isalnum())


def _repeats(search: str, name: str) -> bool:
    """Search is the Filter-to-one-thing name or a piece of it ("Chrome" beside "Google
    Chrome"). Not the other way round: a Mac can be named after an app ("Zoom Room Conf A"
    beside "Zoom"). And never a Jamf ID or a serial, which only ever name a device."""
    if search.isdigit() or _SERIALISH.fullmatch(search):
        return False
    return search.lower() in name.lower()


_SECTION_NAME: dict[str, str] = {key: name for name, key in SECTIONS.items()}
# What a list section's entries can be (`app.changes.diff`); a field is only `changed`.
_ENTRY_CHANGES = frozenset({"added", "removed", "updated"})


def guard(
    question: str, filters: Mapping[str, str | None], unsupported: str | None, repairs: Iterable[str], since_set: bool = False
) -> tuple[Filters, str | None, list[str]]:
    """The six rules, on copies, in the order they run:

    1. a Filter-to-one-thing value that names a section or a kind of thing ("Disk
       encryption", "Application") is dropped: it would match no one thing;
    2. a Search that is the Filter-to-one-thing name, or a piece of it, is dropped: asked
       about "machines that moved to chrome 153" the model can put "Chrome" in Search beside
       "Google Chrome", and Search names a device, so it matches none;
    3. a serial-shaped Search that is not in the question, letters and digits compared, is
       dropped: it is the model's, not the operator's. Asked "and the other mac?", the model
       searched for KY4QVD7430, a serial from its own examples;
    4. with Search empty and exactly one serial-shaped word in the question, Search is it;
    5. ``unsupported`` stands only if the question has an or / not / date / value /
       comparison word — and, with ``since_set``, only a word of the other kinds, because the
       date words are then expressed. The first prompt claimed "Cannot express 'but not'" for
       "which computers installed wireshark", a banner that would have been noise on the
       question the page is demonstrated with; "last", "recent" and "latest" ask for an order,
       not a range, so they are no longer date words (#443);
    6. a change a section never records is any: a list section's entries are added,
       removed or updated, and every other section's fields are only ever changed. With
       no section, the change stands as the model gave it.

    Rule 3 widens and says so (``Repair``): what it drops is a device the question never
    named. The rest are taken as fixing the answer or narrowing it: rule 4 narrows, rule 5
    moves no filter, the pair rule 6 undoes matches no row at all, and what rule 2 drops
    names no device. Rule 1 can widen without saying so, and runs anyway: a thing named for
    its section (a profile called "Security") loses its name, and the answer shows the
    whole section. Held back, every answer in which the model copied a section name into
    the filter, as the first prompt did, would be a proposal.

    Rule 4 also undoes a widening. A Search value the whitelist refused ("KY4QVD7430?"), or
    that rule 3 dropped, left Search empty; filled again with the question's one serial,
    the answer is no wider than a clean reply's, so the drop is kept as said but no longer
    widens.
    """
    filters = dict(filters)
    repairs = list(repairs)
    artifact = filters.get("artifact")
    if artifact and _names_a_kind(artifact):
        repairs.append(_fixes(f"Dropped “{artifact}” from {_ARTIFACT}: it names a section or a kind of thing, not one thing."))
        filters["artifact"] = None
    search, artifact = filters.get("q"), filters.get("artifact")
    if search and artifact and _repeats(search, artifact):
        repairs.append(_fixes(f"Cleared {_SEARCH}: it repeated the {_ARTIFACT} name instead of naming a device."))
        filters["q"] = None
    search = filters.get("q")
    if search and _SERIALISH.fullmatch(search.upper()) and _compact(search) not in _compact(question):
        repairs.append(_widens(f"Dropped the model's value for {_SEARCH}: that serial number is not in the question.", _SEARCH))
        filters["q"] = None
    if filters.get("q") is None:
        serial = _one_serial(question)
        if serial:
            repairs = [
                _fixes(repair) if isinstance(repair, Repair) and repair.widens and repair.control == _SEARCH else repair
                for repair in repairs
            ]
            repairs.append(_fixes(f"Filled {_SEARCH} with the one serial-number-shaped word in the question."))
            filters["q"] = serial
    if unsupported:
        # With a start set, the question's date words are expressed after all, so only a word
        # of the other kind is still grounds for the caveat. A phrase that named an end too
        # ("yesterday") does not set it: the answer runs past that end (``Since.closed``).
        dates_stand = not since_set and bool(_RANGE_MARKERS.search(question))
        if not (_OTHER_MARKERS.search(question) or dates_stand):
            repairs.append(
                _fixes(
                    "Dropped the model's note that the filters cannot express this: the time it asked for is set "
                    "in Since, and nothing else in it is beyond the filters."
                    if since_set
                    else "Dropped the model's note that the filters cannot express this: the question has no or, not, "
                    "date, version or comparison word."
                )
            )
            unsupported = None
    section, change = filters.get("section"), filters.get("change")
    if section and change:
        name = _SECTION_NAME.get(section, section)
        if section in ENTRY_SECTIONS and change == "changed":
            repairs.append(_fixes(f"Entries in {name} are added, removed or updated, never changed; showing any change."))
            filters["change"] = None
        elif section not in ENTRY_SECTIONS and change in _ENTRY_CHANGES:
            repairs.append(
                _fixes(f"{name} only records changed values, never added, removed or updated ones; showing any change.")
            )
            filters["change"] = None
    return filters, unsupported, repairs


def interpret(question: str, reply_text: str, now: datetime | None = None, zone: str | None = None) -> Interpretation:
    """A model's reply to ``question``, parsed, forced into the vocabulary and guarded.
    The question is sanitised here too, so a caller passing the raw text gets the same
    answer as one passing what was sent.

    ``now`` and ``zone`` are the server's clock and the viewer's IANA zone; with them the
    question's own words may set ``since`` (``resolve_since``, #444), and without ``now`` no
    window is set — what every caller before #444 got.

    An object with none of the fields the instructions ask for is no answer either:
    ``{"foo": 1}`` coerces to every control unset, and applied, that is the whole feed
    under a banner saying the question was understood.

    The model's refusal wins over anything beside it: ``{"invalid": true}`` is
    ``invalid``, every control unset, whatever filters came with it. It is read first
    because it is not a filter answer at all, and it is never a key the page ignores."""
    obj = parse_reply(reply_text)
    if obj is not None and _refused(obj):
        return Interpretation(filters=_no_filters(), unsupported=None, repairs=[], parsed=True, invalid=NOT_ABOUT_CHANGES)
    if obj is None or not any(key in obj for key in _REPLY_KEYS):
        return Interpretation(filters=_no_filters(), unsupported=None, repairs=[], parsed=False)
    asked = sanitize_question(question)
    since = resolve_since(asked, now, zone) if now is not None else None
    filters, unsupported, repairs = coerce(obj)
    filters["since"] = wire_time(since.at) if since else None
    # No repair is recorded: the corrections list is what the page changed in the model's answer,
    # and this filter is not the model's. The chip and the readback state the start.
    filters, unsupported, repairs = guard(asked, filters, unsupported, repairs, since_set=since is not None and not since.closed)
    return Interpretation(filters=filters, unsupported=unsupported, repairs=repairs, parsed=True, since_asked=since)
