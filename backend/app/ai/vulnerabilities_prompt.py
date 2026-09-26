"""Posture > Vulnerabilities, the AI lever's model half (#534): a question in, that page's own
filter state out. Slot 2 of ``docs/ai-threat-model.md`` §7, on slot 1's mechanism and under
slot 1's rulings, none of which is re-argued here.

The model never sees a build, a finding id, a count or a date. It fills in the four controls
the page already has, from closed vocabularies, and Postgres filters and counts: the number
the box states is `GET /api/catalog`'s own, for the very filters the list then runs. So a
question costs the same whatever the catalog holds, and no number in the answer can be the
model's (``docs/v-never.md``, *no model-sourced numbers anywhere*).

What leaves the pod is the instructions below and the operator's question, nothing else. What
comes back is forced into this page's vocabulary by the half this shares with slot 1 —
``sanitize_question`` with its control-token strip (#435), ``parse_reply``, ``refused``,
``ignored_keys``, ``whitelisted_name``, ``unsupported_note``, ``Repair`` and
``Interpretation``, imported rather than copied. ``unsupported`` is the only model-written
text that reaches the page, and the page renders it as text. An id is not the model's either:
a question that IS one routes to that id's page (#533) with no model call at all.

Not measured against a live endpoint — #534 asks for no live-provider test. What holds the
instructions is the labelled held-out set in ``tests/test_vulnerabilities_prompt.py``, which
is where a wording change is answered for. Pure and stdlib-only, like slot 1 (S1).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from app.ai.changes_prompt import (
    Filters,
    Interpretation,
    Repair,
    ignored_keys,
    parse_reply,
    refused,
    unsupported_note,
    whitelisted_name,
)

FEATURE = "vulnerabilities_prompt"
# The typed question, and nothing else. Ruled fleet data (``app.core.ai``), so the gate is
# told it leaves and the share log names it — the same one field slot 1 discloses.
DISCLOSED_FIELDS = ("query_text",)

# --------------------------------------------------------------------------------------
# The vocabulary: the page's four filter keys, and the ONLY values the model may produce.
# `tests/test_vulnerabilities_prompt.py` pins each tuple to `GET /api/catalog`'s own
# Literal and to the page's own const, so a filter added to one without the other fails.
# --------------------------------------------------------------------------------------

# The page's `vuln`. There is no "all" on this page: with nothing chosen it shows `findings`,
# so that is what "any" means here, and what an unknown state is read as.
STATES: tuple[str, ...] = ("findings", "kev", "unknown_app", "clean", "patchable")
DEFAULT_STATE = "findings"
BANDS: tuple[str, ...] = ("critical", "high", "medium", "low")
ORDERS: tuple[str, ...] = ("exposure", "age", "payoff")
DEFAULT_ORDER = "exposure"
# `payoff` ranks what an update would close, and the filter and the ranking are ONE state: the
# page reads the ranking off the filter alone (`payoffList`), so *Easily patchable* is always
# ranked that way and no other list ever is. The pairing therefore binds in BOTH directions —
# `payoff` only with `patchable`, and `patchable` only with `payoff`.
PAYOFF_STATE = "patchable"
PAYOFF_ORDER = "payoff"
# A band counts findings, so beside a state that has none it matches no row at all.
NO_BANDS = ("clean", "unknown_app")

REPLY_KEYS = ("app", "state", "band", "order", "unsupported")

# Why a question is not one these filters can answer. One reason and one sentence (the
# route's), and that sentence names the device list: "which Macs have Chrome" is a real
# question about a real page, and a bare refusal would read as a refusal of the fact.
NOT_ABOUT_VULNERABILITIES = "not_about_vulnerabilities"

# The page's own word for the box a repair emptied.
_SEARCH = "Search"
# The noun the page uses for the thing that asked, in a repair the reader can act on (#534).
_LEVER = "the AI lever"
# The words a model writes for "no filter", read with no repair: the answer is no wider than
# the one it meant. Slot 1's set, and its reason.
_ANY = frozenset({"any", "all", "null", "none", "everything"})
# Near misses taken as written rather than reported: the page's own chips say *Outside the
# corpus* and *No findings*, and a model answering in those words has not got it wrong.
_STATE_WORDS: dict[str, str] = {
    "unknown": "unknown_app", "unknown app": "unknown_app", "outside": "unknown_app",
    "outside the corpus": "unknown_app", "no findings": "clean", "cisa kev": "kev",
    "on cisa kev": "kev", "easily patchable": "patchable",
}  # fmt: skip
# A value naming a filter, a band or a kind of thing rather than one app: it matches no
# build's name, bundle id or version, so the list would read as *nothing found* for a
# question the page can answer.
_GENERIC = frozenset(
    {"any", "all", "app", "apps", "application", "applications", "software", "build", "builds", "package",
     "vulnerability", "vulnerabilities", "finding", "findings", "cve", "kev", "critical", "high", "medium",
     "low", "severity", "patch", "update", "mac", "macs", "device", "devices", "corpus"}
)  # fmt: skip
# A value that IS a finding id. The two namespaces §5 mints, mirroring `_ALLOWED_ID`
# (`app.core.vuln`) term for term, `re.ASCII` and `fullmatch` included, as the page's own
# `FINDING_ID` does — written out rather than imported so this module stays stdlib-only (S1),
# and pinned to that regex by a test so a widened namespace, or a digit from another script
# (#684), cannot drift away from it.
_FINDING_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|LoonVD-\d{4}-\d{6})$", re.ASCII)


def is_finding_id(value: str) -> bool:
    """Whether a Search value is a finding id rather than an app. The page never searches one
    (`findingIdIn`): an id routes to its own page and the lists run unfiltered."""
    return _FINDING_ID.fullmatch(value.strip()) is not None


# The instructions, static and versioned here (threat-model P2). Slot 1's measured shape — the
# field block, the "CANNOT express" paragraph, the refusal paragraph, then examples — carrying
# this page's five fields. Its refusal paragraph gains the one clause this page needs and slot
# 1 has no use for: a question about Macs, people, departments or sites is the device list's.
SYSTEM_INSTRUCTION = """You convert a question about a list of vulnerable app builds into filter settings.

You do NOT answer the question and you do NOT see any app, device or vulnerability data. You only choose filter values. Reply with JSON only, no prose, no markdown.

The page lists every app BUILD a fleet of Macs carries: one row per build, with how many findings a vulnerability corpus has against it, how many of those are on CISA KEV, how many Macs carry it, and how long the oldest finding has been published.

Fields:
  app    the name of ONE app, or its bundle id, or a version. null if the question does not name one.
  state  one of: any, findings, kev, unknown_app, clean, patchable. findings = builds the corpus has findings against; kev = builds with a finding on CISA KEV; unknown_app = builds the corpus does not know; clean = builds it knows and has no findings against; patchable = builds whose update closes more findings than it opens. any means findings.
  band   one of: any, critical, high, medium, low — the severity of the findings.
  order  one of: exposure, age, payoff. exposure = CISA KEV first, then the most Macs; age = the oldest publication date first; payoff = what an update would close, times the Macs it reaches. payoff and state patchable always go together: use payoff with patchable and with nothing else.
  unsupported  null, OR a short sentence naming what these controls cannot express.

The controls CANNOT express: OR between two things, negation ("not", "without"), date or time ranges, matching a version number, counting or comparing rows, one finding id, or anything about one Mac or one person. If the question needs any of those, set unsupported and still fill in the closest values you can.

Some text is not a question about this list, and then you reply exactly {"invalid":true} and nothing else: a greeting or thanks; a question about you; general knowledge, or how to do something; math; a request to write text or code; a request to do something, such as patch, update, push, install, remove, lock, export or alert; a question about which MACS, people, departments or sites are affected, which another page answers; a question about what changed on devices. Anything asking which apps or builds carry findings, which are on CISA KEV, which the corpus does not know, which are clean, which are worth patching first, or how exposed one app is, is a question about this list, even when the controls only partly express it. A name alone is an app.

Examples:
Q: which apps are on cisa kev
{"app":null,"state":"kev","band":"any","order":"exposure","unsupported":null}
Q: what should we patch first
{"app":null,"state":"patchable","band":"any","order":"payoff","unsupported":null}
Q: anything critical
{"app":null,"state":"findings","band":"critical","order":"exposure","unsupported":null}
Q: has wireshark got anything against it
{"app":"Wireshark","state":"findings","band":"any","order":"exposure","unsupported":null}
Q: what have we been carrying the longest
{"app":null,"state":"findings","band":"any","order":"age","unsupported":null}
Q: apps the corpus does not know
{"app":null,"state":"unknown_app","band":"any","order":"exposure","unsupported":null}
Q: which macs have google chrome
{"invalid":true}
Q: critical or high findings
{"app":null,"state":"findings","band":"critical","order":"exposure","unsupported":"Cannot express 'or' between two bands — run the second band separately."}
"""  # noqa: E501


def _widens(sentence: str) -> Repair:
    return Repair(sentence, widens=True)


def _fixes(sentence: str) -> Repair:
    return Repair(sentence, widens=False)


def no_filters() -> Filters:
    """The page with nothing chosen: builds with findings, every band, most exposed first."""
    return {"q": None, "vuln": DEFAULT_STATE, "band": None, "order": DEFAULT_ORDER}


def _state(value: Any, repairs: list[str]) -> str:
    word = str(value if value is not None else "any").strip().lower()
    if word in _ANY:
        return DEFAULT_STATE
    key = _STATE_WORDS.get(word, word)
    if key not in STATES:
        # Read as the page's default, which is a different set of builds from the one the
        # model named and in general a larger one: the answer waits for Apply, never runs.
        repairs.append(_widens("The model named a state this page does not have, so it was read as builds with findings."))
        return DEFAULT_STATE
    return key


def _band(value: Any, repairs: list[str]) -> str | None:
    word = str(value if value is not None else "any").strip().lower()
    if word in _ANY:
        return None
    if word not in BANDS:
        repairs.append(_widens("The model named a severity that is not critical, high, medium or low, so it was read as any."))
        return None
    return word


def default_order(state: str) -> str:
    """The order the page WILL rank this state by with nothing else said — `payoff` for the
    easily-patchable list, which is ranked that way whatever the URL holds (`payoffList`), and
    `exposure` for every other. A default read off the state rather than a constant, so a reply
    that named a state and no order is not answered with an order the page then ignores."""
    return PAYOFF_ORDER if state == PAYOFF_STATE else DEFAULT_ORDER


def _order(value: Any, state: str, repairs: list[str]) -> str:
    fallback = default_order(state)
    word = str(value if value is not None else fallback).strip().lower()
    if word in ORDERS:
        return word
    # A model that answers every other field "any" answers this one "any" too. The page's
    # default is what that means, and saying so as a correction would be noise on a reply
    # that got nothing wrong.
    if word in _ANY:
        return fallback
    # An order decides which rows come first, never which rows match, so this neither widens
    # nor narrows the answer: it is a fix.
    repairs.append(_fixes(f"The model named an order this page does not have, so the list is ordered by {fallback}."))
    return fallback


def coerce(obj: Mapping[str, Any]) -> tuple[Filters, str | None, list[str]]:
    """Force a reply object into this page's vocabulary. Anything that is not a known value is
    dropped rather than passed through, and every drop is a repair."""
    repairs: list[str] = [*ignored_keys(obj, REPLY_KEYS, control=_LEVER)]
    # In the order the repairs read, and `state` before `order` because the order a missing
    # field means is the state's (`default_order`), not one constant for the whole page.
    search = whitelisted_name(obj.get("app"), _SEARCH, repairs)
    state = _state(obj.get("state"), repairs)
    filters: Filters = {
        "q": search,
        "vuln": state,
        "band": _band(obj.get("band"), repairs),
        "order": _order(obj.get("order"), state, repairs),
    }
    return filters, unsupported_note(obj.get("unsupported"), repairs), repairs


def guard(filters: Mapping[str, str | None], repairs: list[str]) -> tuple[Filters, list[str]]:
    """The four rules a closed vocabulary cannot enforce on its own, on copies:

    1. a Search naming a filter, a band or a kind of thing ("critical", "apps") is dropped: it
       matches no build's name, bundle id or version, so the list would read as *nothing found*
       for a question the page can answer;
    2. a Search that IS a finding id is dropped: the page never searches an id (`findingIdIn`
       sends one to its own page and lists unfiltered), so an id left here would be counted by
       `list_catalog` and then not used by the list — the box's number and the rows below it
       disagreeing, which is the one thing this route exists to prevent;
    3. a band beside *No findings* or *Outside the corpus* is dropped: a band counts findings
       and neither state has any, so the pair matches no row at all;
    4. the order and the list are made one, in both directions. *Easily patchable* takes
       `payoff`, because the page ranks that filter that way whatever the order says
       (`payoffList` reads the filter ALONE); `payoff` elsewhere, and `age` beside anything but
       the plain list of builds with findings, are read as *Most exposed* (`agedList`). Left as
       given, either way round, the readback would name a list nobody is looking at — and an
       applied answer whose order the page then overrode had its whole card judged stale.

    None widens, so an answer carrying only these still runs on Enter (ruling 2): 1 and 2 drop a
    value that matched nothing or was never searched, and 3 and 4 undo a pair matching nothing
    and an order that changes no row's membership.
    """
    kept = dict(filters)
    search = kept.get("q")
    if search and is_finding_id(search):
        repairs.append(
            _fixes(
                f"Dropped “{search}” from {_SEARCH}: it is a finding id, and this list searches names, bundle ids "
                "and versions. Type an id into the box on its own to open it."
            )
        )
        kept["q"] = None
    elif search and search.strip().lower() in _GENERIC:
        repairs.append(_fixes(f"Dropped “{search}” from {_SEARCH}: it names a filter or a kind of thing, not one app."))
        kept["q"] = None
    if kept.get("band") and kept.get("vuln") in NO_BANDS:
        repairs.append(_fixes("A severity counts findings, and this state has none; showing every severity."))
        kept["band"] = None
    if kept.get("vuln") == PAYOFF_STATE:
        if kept.get("order") != PAYOFF_ORDER:
            repairs.append(_fixes("The easily-patchable list is always ranked by what an update closes; ordering by payoff."))
            kept["order"] = PAYOFF_ORDER
    elif kept.get("order") == PAYOFF_ORDER:
        repairs.append(_fixes("Only the easily-patchable list is ranked by what an update closes; ordering by exposure."))
        kept["order"] = DEFAULT_ORDER
    elif kept.get("order") == "age" and (kept.get("vuln") != DEFAULT_STATE or kept.get("band")):
        repairs.append(_fixes("Only the full list of builds with findings is ordered by publication date; ordering by exposure."))
        kept["order"] = DEFAULT_ORDER
    return kept, repairs


def interpret(reply_text: str) -> Interpretation:
    """A model's reply, parsed, forced into this page's vocabulary and guarded.

    The refusal wins over anything beside it and is read first: ``{"invalid": true}`` is
    ``invalid`` with the page's filters untouched, whatever came with it. An object with none of
    the fields the instructions ask for is no answer either — ``{"foo": 1}`` would coerce to the
    page's default and read, applied, as a question that had been understood. No question is
    passed in: no filter here is read from its words (slot 1's ``since``, #444, has no
    counterpart), and the route sanitises before sending.
    """
    obj = parse_reply(reply_text)
    if obj is not None and refused(obj):
        return Interpretation(filters=no_filters(), unsupported=None, repairs=[], parsed=True, invalid=NOT_ABOUT_VULNERABILITIES)
    if obj is None or not any(key in obj for key in REPLY_KEYS):
        return Interpretation(filters=no_filters(), unsupported=None, repairs=[], parsed=False)
    filters, unsupported, repairs = coerce(obj)
    filters, repairs = guard(filters, repairs)
    return Interpretation(filters=filters, unsupported=unsupported, repairs=repairs, parsed=True)
