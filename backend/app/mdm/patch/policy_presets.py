"""Published requirements a patching rule can be started from (#736). Pure; no database.

An organization's patch timeline is often not its own sentence but a clause of a scheme it is
assessed against. Each entry here is one such clause, mapped onto the rule vocabulary of
`app.mdm.patch.policy`, so the rule editor can open on it instead of on empty boxes.

**An entry is a starting rule, never a verdict.** The 2026-08-31 scope ruling stands: this
product evidences what Jamf can observe and attests to no framework. Choosing an entry fills
the editor; confirming it makes it the organization's own rule; and a rule confirmed unchanged
records the entry as its *basis* — where the rule came from. Nothing reads a basis as *meets*,
*passes* or *complies*, and nothing may.

**An entry ships only when its numbers were read from the publisher's own text.** `document`,
`published`, `section` and `url` say which text, `verified_on` says when it was read, and the
record of what was read — and of the requirements that were NOT admitted, with why — is #736.
A number from memory, or from somebody's summary of a standard, is how a product ends up
enforcing a clause the standard dropped a revision ago: PCI DSS's one-month deadline covered
critical and high in v4.0 and, by two secondary accounts, critical only in v4.0.1, and the
standard itself could not be read here. It is not in the catalogue.

The words that explain an entry — what the text requires, how the rule maps it, where the two
part ways — are the page's (`en.ts`/`de.ts`, keyed by `id`), so they are translated with the
rest of the page; `tests/test_patch_policy_presets.py` holds the two together. What is here is
what code needs: the identity, the source, and the rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from app.mdm.patch.policy import Rule


@dataclass(frozen=True)
class Preset:
    # Stable, and versioned with the document: a revised document is a new entry, so a basis
    # recorded against the old one keeps saying which text the rule was drawn from.
    id: str
    framework: str
    document: str
    published: str
    section: str
    url: str
    # The day the publisher's text was read and these numbers taken from it.
    verified_on: date
    rule: Rule


# Cyber Essentials: Requirements for IT Infrastructure v3.3 (NCSC, April 2026), control 3,
# Security update management. Read 2026-10-03 from NCSC's PDF. The text requires updates to be
# applied within 14 days of release where they fix vulnerabilities the vendor describes as
# critical or high risk, that have a CVSS v3 base score of 7 or above, or whose severity the
# vendor gives no details of; and recommends, without requiring, 14 days for every update.
#
# Mapped to 14 days for every update, NOT to the severe limit. The third condition is the
# reason: an update of unstated severity is in scope, and a rule cannot tell that from a minor
# update — `max_days_behind_severe` reads the corpus's findings for the installed build, and a
# build the corpus has not assessed is judged by the ordinary limit. A 14-day severe limit
# alone would leave exactly the builds the text sweeps in unjudged.
CYBER_ESSENTIALS_3_3 = Preset(
    id="cyber-essentials-3.3",
    framework="Cyber Essentials",
    document="Requirements for IT Infrastructure v3.3",
    published="April 2026",
    section="Security update management",
    url="https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf",
    verified_on=date(2026, 10, 3),
    rule=Rule(max_days_behind=14),
)

PRESETS: tuple[Preset, ...] = (CYBER_ESSENTIALS_3_3,)
_BY_ID = {preset.id: preset for preset in PRESETS}


def preset(preset_id: object) -> Preset | None:
    """The entry with this id, or None — for an id this build does not hold, which is what a
    basis recorded by a newer build reads as here."""
    return _BY_ID.get(preset_id) if isinstance(preset_id, str) else None


def is_basis_of(preset_id: object, rule: Rule | None) -> bool:
    """Whether a rule may record this entry as its basis: only while it IS the entry's rule,
    limit for limit. A rule somebody changed is their own, and saying it was drawn from a
    clause it no longer matches would be the product vouching for a mapping nobody made."""
    entry = preset(preset_id)
    return entry is not None and rule is not None and rule == entry.rule
