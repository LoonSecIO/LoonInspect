"""The per-device snapshot — one `device.inventory` per device per pass, fattened at
enqueue (#241).

Everything here is pure: the canonical observation the ledger just wrote, the device's
installed-app rows, the meta block and the occurrence time in; the event out. No I/O, no
session, no clock. `app.mdm.service.process_sync` is the one caller, and it enqueues the
result in the same transaction as the ledger write and the row updates.

Why the observation is the source, and not the raw record or the row tables (the choice
#241 put to this session, taken here and recorded in the PR):

* The `Observation` is, section for section, the allowlisted view of the record the
  ledger just wrote — Jamf's v4 keys, the contract's field set, nested extension
  attributes already merged and the quarantine already applied. It is the only object in
  hand that serves all fourteen sections: `installed_apps` holds no `path`,
  `cfBundleShortVersionString`, `cfBundleVersion` or `macAppStore`, and thirteen other
  sections have no row table at all, so a column route would have been app-only and would
  still have needed this for everything else.
* Its values are the ledger's canonical form rather than Jamf's raw bytes — NFC-normalised
  and stripped strings, timestamps at UTC whole seconds, every spelling of absence
  dropped, byte-identical entries collapsed, digest order rather than Jamf's. Against the
  83 apps of the real fixture none of that changes a single string. The trade is worth
  it: a `device.inventory` sub-event and a `device.change` derived from the same span
  (#223) agree byte for byte, which is what makes them join on equal strings.

The one section that does NOT come from the observation is `ea`. #197 ruled the wire's
extension-attribute object separately — Jamf's object verbatim plus `source`, the one key
LoonInspect mints inside a Jamf object anywhere on the wire (docs/splunk-wire-vocabulary.md
§4, docs/jamf-observations.md §7) — and the contract discards `source` by design. So the
`ea` items are the normalized view's `NormalizedExtensionAttribute`s, which carry exactly
that object, and the observation decides only whether the section was in the aperture.

Wrapper keys come from `SECTION_WRAPPERS` and are never spelled by hand; the cardinality
of a section comes from the contract's `SectionSpec`, never from a table here.

Both enrichment blocks on an app item are decided HERE, at enqueue, from rows already in
the transaction — the fan-out (#242) copies them through and stamps nothing. `patch{}`
reads the row's Jamf Patch answer; `vuln{}` is `app.core.vuln.vuln_block` over the corpus
the caller passed and the two content keys the row already carries (#249,
docs/vulnerabilities.md §4). Neither costs a query, which is the whole point: the
enrichments are lookups on hashes the container computed once, not work done per device.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime
from typing import TYPE_CHECKING

from app.core.content_keys import app_full_key, app_title_key
from app.core.vuln import VulnCorpus, vuln_block
from app.core.wire_vocabulary import SECTION_WRAPPERS
from app.mdm.jamf.contract import SECTIONS, Entry, Observation, canonical_string
from app.schemas.payload import (
    InventoryAppItem,
    InventorySnapshotEvent,
    NormalizedExtensionAttribute,
    PatchEnrichment,
)

if TYPE_CHECKING:
    from app.models.schema import InstalledApp

logger = logging.getLogger(__name__)

_APPLICATIONS = "applications"
_EXTENSION_ATTRIBUTES = "extension_attributes"


def app_identity(name: str | None, bundle_id: str | None, version: str | None) -> tuple[str, str, str]:
    """The key on which an observation entry and an `installed_apps` row are the same app.

    The two sides hash DIFFERENT strings, so the row's `version_hash` cannot be the join:
    `normalize_computer` hands `process_sync` Jamf's raw `name` / `bundleId` / `version`
    and `apply_hashes` md5s them untouched, while the entry body is the canonical form —
    NFC-normalised and stripped. An app whose name carries trailing whitespace or a
    decomposed accent would then be a silent `supported: false` on every device, and the
    real fixture could not catch it (all 83 names canonicalise to themselves). So both
    sides are keyed on the canonicalised triple instead, with the row's own fallback
    reproduced: a missing `bundleId` is the app's name (`client.normalize_computer`), and
    the canonical entry drops an empty `bundleId` the same way.
    """
    canonical_name = canonical_string(name or "")
    canonical_bundle = canonical_string(bundle_id or "") or canonical_name
    return canonical_name, canonical_bundle, canonical_string(version or "")


def patch_support(apps: Iterable[InstalledApp]) -> dict[tuple[str, str, str], bool]:
    """`patch.supported` per app identity, read off rows already in the transaction.

    `true` iff the row's `jamf_title_ids` names at least one title — `None` is "no titles"
    (`schema.InstalledApp`), and `summarize()` in app.mdm.patch.matching returns a
    non-empty list or nothing. Two rows collapsing onto one canonical identity (a name that
    differs only in whitespace) answer `true` if either does.
    """
    support: dict[tuple[str, str, str], bool] = {}
    for row in apps:
        key = app_identity(row.name, row.bundle_id, row.version)
        support[key] = support.get(key, False) or bool(row.jamf_title_ids)
    return support


def content_keys(apps: Iterable[InstalledApp]) -> dict[tuple[str, str, str], tuple[str, str]]:
    """`(key_title, key_full)` per app identity — the corpus lookup key (#249).

    Read off the same rows `patch_support` reads and never recomputed here: the pair is
    stamped once, in `app.mdm.service.apply_hashes`, for every ingest path there is, so a
    second computation is a second definition waiting to drift. Cache, don't calculate —
    the enrichment is a lookup keyed on a hash the container already holds, not a hash
    recomputed per app per device per sweep.

    `key_title` identifies the application and answers *does the corpus know this app at
    all*; `key_full` identifies the build and answers *which findings are active against
    it* (`app.core.content_keys`). Rows collapsing onto one canonical identity keep the
    first pair seen, which is the same rule `patch_support` uses in bool form.
    """
    keys: dict[tuple[str, str, str], tuple[str, str]] = {}
    for row in apps:
        key = app_identity(row.name, row.bundle_id, row.version)
        if key not in keys and row.key_title and row.key_full:
            keys[key] = (row.key_title, row.key_full)
    return keys


def _fallback_content_keys(body: Mapping[str, object]) -> tuple[str, str]:
    """The pair computed from the canonical entry body, for the app that has no row.

    Reached only from the "no row" alarm below, and it produces the SAME strings the row
    would have carried: `content_keys.canonical_key` NFC-normalises and strips every field
    before hashing, the entry body is already in that form, and `app_identity`'s
    empty-`bundleId`-falls-back-to-the-name rule is Jamf's own (`normalize_computer`), so
    both sides hash one string. Pinned against all 83 rows of the real fixture in
    tests/test_inventory_snapshot.py.

    Computing rather than shipping `off` for the odd app: a device where one app reads
    `off` and eighty-two read `covered` is not a state §4a describes — `off` is a property
    of the pod, not of an app.
    """
    name, bundle, version = app_identity(
        str(body.get("name") or ""), str(body.get("bundleId") or ""), str(body.get("version") or "")
    )
    return app_title_key(name, bundle), app_full_key(name, bundle, version, None)


def _app_item(
    entry: Entry,
    support: Mapping[tuple[str, str, str], bool],
    keys: Mapping[tuple[str, str, str], tuple[str, str]],
    *,
    subject_id: str,
    corpus: VulnCorpus,
    as_of: date,
) -> InventoryAppItem:
    body = entry.body
    key = app_identity(body.get("name"), body.get("bundleId"), body.get("version"))
    supported = support.get(key)
    if supported is None:
        # A genuine miss is `supported: false` plus a log line, never an exception: every
        # entry has a row by construction (both views are built from the same raw list),
        # so this is the alarm for that construction breaking, not a per-device failure.
        # `app_name`, not `name`: `name` is a reserved LogRecord attribute and `extra`
        # refuses to overwrite it — this line ran once with `name` and raised in a test.
        logger.warning(
            "installed app has no row to read patch support from; shipping supported=false",
            extra={"subject_id": subject_id, "app_name": body.get("name"), "bundle_id": body.get("bundleId")},
        )
        supported = False
    key_title, key_full = keys.get(key) or _fallback_content_keys(body)
    return InventoryAppItem(
        app=dict(body),
        patch=PatchEnrichment(supported=supported),
        vuln=vuln_block(corpus, key_title=key_title, key_full=key_full, as_of=as_of),
    )


def _labelled(entry: Entry, label_key: str | None) -> dict:
    """The entry body plus its label under the key Jamf spells it with.

    The contract keeps names out of the hash — "names of Jamf objects are labels, not
    content" — and carries them beside the body as `Entry.label`. The wire wants the name:
    `group.groupName` and `profile.displayName` are what an analyst types. Jamf's field
    under Jamf's name, so inside "names verbatim"; absent when Jamf sent none.
    """
    if label_key is None or entry.label is None:
        return dict(entry.body)
    return {**entry.body, label_key: entry.label}


def build_inventory_snapshot(
    observation: Observation,
    *,
    extension_attributes: Sequence[NormalizedExtensionAttribute] | None,
    apps: Iterable[InstalledApp],
    occurred_at: datetime,
    device_meta: Mapping[str, object],
    corpus: VulnCorpus,
) -> InventorySnapshotEvent:
    """The snapshot for one pull.

    A section rides iff it is in `observation.sections`, which is built from the read's
    `sections` and nothing else — so the aperture carve-out (Kyle, 2026-08-29: `None` is
    outside the read, `[]` is read-empty) is free and applies per section. A scoped read
    produces a snapshot with only the wrappers it read; a section-less snapshot cannot
    exist, because `webhook_scope` falls back to the whole contract.

    `extension_attributes` is the normalized view's list — `None` outside the aperture,
    which must agree with the observation because both are built from the same
    `sections`. A disagreement is a programming error and raises, loudly, rather than
    asserting zero extension attributes for a section that was not read.

    `apps` are the device's CURRENT installed-app rows — after the removed rows were
    deleted and the added ones flushed, and after `record_device_apps` copied the Jamf
    Patch answer onto them. Not `existing.apps`: SQLAlchemy does not prune a loaded
    collection on delete, so that collection can still hold the removed rows. They carry
    both enrichments' inputs: the Jamf Patch answer and the two content keys the corpus is
    looked up on.

    `corpus` is required and has no default (#249). `app.core.vuln.NO_CORPUS` is what the
    container ships until #248 lands, and passing it explicitly is the point: a default
    here would make a forgotten wiring look exactly like a fleet nobody assessed, which is
    the one failure the `assessment` vocabulary exists to prevent.

    `occurredAt` is the clock the block's day arithmetic uses — the event's own instant,
    never the wall clock. This function stays pure and clock-free, and a delivery retried
    across a day boundary re-expands the stored row to the same bytes.
    """
    apps = list(apps)
    support = patch_support(apps)
    keys = content_keys(apps)
    sections: dict[str, dict | list] = {}
    for name, content in observation.sections.items():
        spec = SECTIONS[name]
        wrapper = SECTION_WRAPPERS[name]
        if name == _EXTENSION_ATTRIBUTES:
            if extension_attributes is None:
                raise ValueError(
                    "extension_attributes was read by the ledger but is None on the normalized "
                    "view; the two views of one read must agree on the aperture"
                )
            sections[wrapper] = [
                {wrapper: ea.model_dump(mode="json", by_alias=True)} for ea in extension_attributes
            ]
        elif name == _APPLICATIONS:
            sections[wrapper] = [
                _app_item(
                    entry,
                    support,
                    keys,
                    subject_id=observation.subject_id,
                    corpus=corpus,
                    as_of=occurred_at.date(),
                )
                for entry in content.entries
            ]
        elif spec.is_list:
            sections[wrapper] = [{wrapper: _labelled(entry, spec.entry_label)} for entry in content.entries]
        else:
            sections[wrapper] = dict(content.body or {})

    return InventorySnapshotEvent(
        # `.get`, not `[...]`: the block drops its nulls, so a run-less enqueue leaves both
        # copies absent rather than one absent and one null.
        jobID=device_meta.get("jobID"),
        occurredAt=occurred_at,
        deviceMeta=dict(device_meta),
        **sections,
    )
