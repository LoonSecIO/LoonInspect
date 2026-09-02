"""The frozen v0 Splunk wire vocabulary — the sourcetype tree and its wrapper keys (#188).

The vocabulary had been ruled three times, differently, and no artifact held the answer.
This module is that artifact: every sourcetype string and every body wrapper key the
product will ever mint is derived here, and `docs/splunk-wire-vocabulary.md` is generated
from it. `props.conf [<sourcetype>]` stanzas accept no wildcards, so each string minted
is a hand-written stanza in a customer's Splunk forever, and SPL field names are
case-sensitive — a wrong one returns zero rows with no error.

Amendments are additive and owned by the issue that rules them — #229 added the `alert`
enrichment on 2026-09-02 — and #188 stays closed: the ruling issue edits this module,
regenerates the doc, pins the refused spelling in `tests/test_wire_vocabulary.py`, and
leaves one pointer on #188.

Where the rest of the contract lives: the casing law and the `deviceMeta` block are in
`docs/runs.md` (#189); the envelope — `time` / `host` / `source` — is `app.core.wire`;
the read aperture that decides which sections are fetched at all is
`app.mdm.jamf.contract.SECTIONS`, which this module reads rather than restates, so a
section cannot be collected without a name to travel under.

`sourcetype` is not yet stamped on delivered events (`app.core.outbox`): the tree names
fan-out sub-events that are not built. This module is the ruling; stamping it is #222.
"""

from __future__ import annotations

from app.mdm.jamf.contract import SECTIONS

# The producer token leads because `loon:*` is then the one search that finds everything
# this product wrote, in an index it shares with EDR, DHCP and identity logs. The vendor
# segment is insurance for Addigy / Fleet / SimpleMDM, whose raw records genuinely differ
# in shape: `loon:*:mac:app` covers them all in one dashboard. `pro` is dropped — Jamf
# School, if it ever happens, is `loon:jamfschool:*`.
PRODUCER = "loon"

# LoonInspect's own assertions carry no vendor segment: they are statements about a run,
# not about a fleet. This is also the answer to open question 4 of
# docs/splunk-event-shaping.md — augmentations are namespaced, not flattened into Jamf's
# native fields.
ASSERTION_SOURCETYPE = f"{PRODUCER}:run"

# Ruling 4 (#188): short where the fan-out is high, long where the section is one-per-
# device or low fan-out. Ambiguity overrides brevity — `user` / `account` was rejected
# because `userAndLocation` and `localUserAccounts` become indistinguishable, the same
# failure the contract's "readable English, no abbreviations" rule exists to prevent.
#
# Keyed by the contract's section name. Every entry in SECTIONS must appear here and
# nothing else may: tests/test_wire_vocabulary.py refuses the drift in both directions,
# so a section cannot be added to the read aperture without being given a name on the
# wire, and a name cannot outlive the section it travels for.
SECTION_WRAPPERS: dict[str, str] = {
    # one per device — long
    "general": "general",
    "hardware": "hardware",
    "operating_system": "operatingSystem",
    "user_and_location": "userAndLocation",
    "purchasing": "purchasing",
    "security": "security",
    "disk_encryption": "diskEncryption",
    "local_user_accounts": "localUserAccount",
    # many per device — short
    "applications": "app",
    "extension_attributes": "ea",
    "group_memberships": "group",
    "configuration_profiles": "profile",
    "certificates": "cert",
    "software_updates": "update",
}

# Enrichment sections: LoonInspect's own answers about a Jamf object, carried on the
# object's sub-event rather than as sub-events of their own. All three are short by the
# same rule — they ride the highest fan-out object the product emits, one per app per
# device.
#
# `vuln` and `patch` were ruled 2026-09-01 against the competing `vulnerabilities{}` /
# `patching{}` spellings carried by #81 ruling 5 and the #113 CVE scope; those records
# were corrected rather than honoured, because the brevity rule applies cleanly where
# nothing is ambiguous.
#
# `alert` was ruled 2026-09-02 (#229) against the plural `alerts{}` that #81 ruling 5
# parked and #101 carries: singular, like every other wrapper. It is LoonInspect's own
# latch on the app — the NEW-app latch first (#101) — and never the customer's Splunk
# saved-search alert, which is the thing a LoonInspect `alert` is fired *on*. The latch
# is a fact about the app on this pull, so it rides inline; a lifecycle fan-out of what
# happened, if one is ever built, takes the reserved `loon:jamf:mac:app:alert` string
# the way #113's vulnerability design pairs an inline summary with lifecycle records.
# Nothing writes it in v0 — #101 ships the alerts table and the Needs Attention rows
# with nothing on the wire, and emitting the block later is additive under clause 1.
# The field that grades an alert is `level`, reusing `app.changes.policy.LEVELS`, never
# `severity`. `app` is the only carrier: a device-scoped alert kind, if #101's close-out
# ever names one, is a carrier decision on the structure #243 rules for `change`, not a
# naming one — the leaf and its sense are fixed here, and moving the declaration between
# dicts changes nothing a customer can see.
ENRICHMENTS: dict[str, tuple[str, ...]] = {
    "app": ("patch", "vuln", "alert"),
}


def sourcetype(wrapper: str, *, vendor: str = "jamf", platform: str = "mac", leaf: str | None = None) -> str:
    """`loon:<vendor>:<platform>:<entity>`, with an optional trailing compound leaf.

    Ruling 5 (#188): the leaf equals the body's wrapper key, so `sourcetype=loon:jamf:mac:app`
    implies `app.*` and there is one vocabulary rather than two. Ruling 2: the trailing
    compound survives — `loon:jamf:mac:app:vuln` — so `*:vuln` still pulls every
    vulnerability across every subject and every vendor.
    """
    parts = [PRODUCER, vendor, platform, wrapper]
    if leaf is not None:
        parts.append(leaf)
    return ":".join(parts)


def registry_rows(*, vendor: str = "jamf", platform: str = "mac") -> list[tuple[str, str, str, str]]:
    """The registry, generated from the read aperture: one row per collected section.

    `(section, jamf response key, wrapper key, sourcetype)`, ordered as SECTIONS is —
    which is the order the contract itself declares them, not alphabetical, so the doc
    reads in the same order as the code.
    """
    rows: list[tuple[str, str, str, str]] = []
    for name, spec in SECTIONS.items():
        wrapper = SECTION_WRAPPERS[name]
        rows.append((name, spec.response_key, wrapper, sourcetype(wrapper, vendor=vendor, platform=platform)))
    return rows


def enrichment_rows(*, vendor: str = "jamf", platform: str = "mac") -> list[tuple[str, str, str]]:
    """`(carrier wrapper, enrichment wrapper, sourcetype)` for every enrichment section."""
    rows: list[tuple[str, str, str]] = []
    for carrier, leaves in ENRICHMENTS.items():
        for leaf in leaves:
            rows.append((carrier, leaf, sourcetype(carrier, vendor=vendor, platform=platform, leaf=leaf)))
    return rows


# The additive-only policy, in testable clauses. Clause one is verbatim from #188's
# acceptance list and is what licenses shipping `patch{}` and `vuln{}` after v0 at all:
# without it in writing, adding a key later is a breaking change by default.
ADDITIVE_ONLY_CLAUSES: tuple[str, ...] = (
    "New keys may appear; consumers must ignore unknown keys.",
    "A key's name, type and meaning never change once shipped. A different meaning is a "
    "different key.",
    "A key that ships is never removed. A key that stops being computed ships its "
    "null-equivalent, or is absent under the null-dropping rule that already governs "
    "deviceMeta.",
    "Absence of a key means the event predates it, never that its value is 'none'. A "
    "vocabulary needing to say 'never' says so with a sentinel, which is why days_oldest "
    "uses -1.",
    "A sourcetype string, once minted, is permanent. New shapes get new sourcetypes; "
    "existing ones are not repurposed.",
    "schemaVersion rides the deviceMeta block and never the sourcetype. A version in the "
    "sourcetype breaks every dashboard on every bump, so it never gets bumped, so it is "
    "a lie.",
)
