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
    JamfPatchAnswer,
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


def patch_answer(
    apps: Iterable[InstalledApp], title_names: Mapping[str, str] | None = None
) -> dict[tuple[str, str, str], PatchEnrichment]:
    """`patch{}` per app identity, read off rows already in the transaction (#311).

    `supported` is `true` iff the row carries a COMPLETE answer: `jamf_title_ids` names at
    least one title and `patch_state` says what it found. `None` is "no titles"
    (`schema.InstalledApp`), and `summarize()` in app.mdm.patch.matching returns a non-empty
    list or nothing. Under #311 `supported` no longer means "a title matched" but "a source
    answered", and a block is the answer — so a row that names titles and cannot state its
    verdict is not a `true` with a hole in it, it is the alarm below. Two rows collapsing onto
    one canonical identity (a name that differs only in whitespace) answer `true` if either
    does, and the answering row is the one whose block rides: the first row seen with a
    complete answer wins, which is the same "first one seen" rule `content_keys` below uses
    for its pair.

    **Nine column reads and no query.** `copy_answer` (`app.catalog.service`) has already
    written the whole Jamf Patch answer onto these very instances — `process_sync` hands the
    producer the same objects the session's identity map gave `record_device_apps` — so
    every value here is in memory before this function is called. Until #311 this read the
    same rows and returned `bool(row.jamf_title_ids)`, throwing nine populated columns away.

    `title_names` is the loaded catalog's id -> name map (`matching.cached_title_names`),
    or `None` on a path where no catalog was consulted. A name missing for ANY matched title
    drops the whole `titleNames` list rather than shipping a hole: the two arrays are
    index-aligned by contract, and an id in disguise would be indistinguishable from a title
    genuinely named "612".
    """
    answers: dict[tuple[str, str, str], PatchEnrichment] = {}
    unsupported = PatchEnrichment(supported=False)
    for row in apps:
        key = app_identity(row.name, row.bundle_id, row.version)
        existing = answers.get(key)
        if existing is not None and existing.supported:
            continue
        title_ids = list(row.jamf_title_ids or ())
        if not title_ids or not row.patch_state:
            if title_ids:
                # Both columns are written by one statement in `_apply_summary` and copied by
                # one statement in `copy_answer`, so they cannot diverge — this is the alarm
                # for that construction breaking, not a case with a right answer. Degrade the
                # way the rowless app below degrades (warn, `supported: false`) rather than
                # raising: one corrupt row must not fail a whole device's sync, and half an
                # answer on the wire is worse than none.
                logger.warning(
                    "installed app names Jamf Patch titles but carries no patch state; shipping supported=false",
                    extra={"app_name": row.name, "bundle_id": row.bundle_id, "title_ids": title_ids},
                )
            answers.setdefault(key, unsupported)
            continue
        answers[key] = PatchEnrichment(
            supported=True,
            jamf_patch=JamfPatchAnswer(
                title_ids=title_ids,
                title_names=_title_names(title_ids, title_names),
                state=row.patch_state,
                on_latest=bool(row.is_compliant),
                version_known=bool(row.this_version_seen),
                ea_assumed=row.ea_assumed,
                latest_version=row.latest_version,
                latest_released_at=row.latest_released_at,
                patch_available_since=row.patch_available_since,
                releases_missed=row.releases_missed,
                # The subjects, and only where there is something to disambiguate — the model
                # refuses them on a single-title answer, where `titleIDs` already names the one
                # title every scalar is about. A row judged before the columns existed carries
                # None and simply says less, which is what clause 4's absence means.
                **_subjects(row),
            ),
        )
    return answers


def _subjects(row: InstalledApp) -> dict[str, str | None]:
    """`referenceTitleID` / `sentenceTitleID`, dropped on a single-title answer.

    The producer applies the presence rule and `JamfPatchAnswer` refuses a violation of it, so
    the two agree by construction rather than by comment. `sentence_title_id` is already null
    on a row with no #68 sentence — `_apply_summary` writes it from `summarize`'s `sentence`,
    which is None unless a patch is available — so there is nothing to guard here beyond the
    count.
    """
    if len(row.jamf_title_ids or ()) < 2:
        return {}
    return {"reference_title_id": row.reference_title_id, "sentence_title_id": row.sentence_title_id}


def _title_names(title_ids: Sequence[str], names: Mapping[str, str] | None) -> list[str] | None:
    """The names for these ids, index-aligned — or `None` if any one of them is unresolvable.

    All or nothing, because the alignment is the contract: a consumer pairs the two arrays by
    position (`mvzip`), so one missing name would silently re-label every title after it.
    Unresolvable happens legitimately — a scoped read consults no catalog, and a title Jamf
    dropped between the judge and this pull is gone from the loaded one — so it is a WARNING
    with the ids on it, not an exception: the ids themselves are still true and still ship.
    """
    if not names:
        return None
    resolved = [names.get(title_id) for title_id in title_ids]
    if any(name is None for name in resolved):
        logger.warning(
            "jamf patch title has no name in the loaded catalog; shipping titleIDs without titleNames",
            extra={"title_ids": list(title_ids)},
        )
        return None
    return [name for name in resolved if name is not None]


def content_keys(apps: Iterable[InstalledApp]) -> dict[tuple[str, str, str], tuple[str, str]]:
    """`(key_title, key_full)` per app identity — the corpus lookup key (#249).

    Read off the same rows `patch_answer` reads and never recomputed here: the pair is
    stamped once, in `app.mdm.service.apply_hashes`, for every ingest path there is, so a
    second computation is a second definition waiting to drift. Cache, don't calculate —
    the enrichment is a lookup keyed on a hash the container already holds, not a hash
    recomputed per app per device per sweep.

    `key_title` identifies the application and answers *does the corpus know this app at
    all*; `key_full` identifies the build and answers *which findings are active against
    it* (`app.core.content_keys`). Rows collapsing onto one canonical identity keep the
    first pair seen, which is the same rule `patch_answer` uses to pick the answering row.
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
    would have carried — but canonicalisation is only half the reason, and `key_title` is
    the half it actually explains: `content_keys.canonical_key` NFC-normalises and strips
    every field before hashing, the entry body is already in that form, and
    `app_identity`'s empty-`bundleId`-falls-back-to-the-name rule is Jamf's own
    (`normalize_computer`), so both sides hash one string for `key_title`.

    `key_full` hashes a fourth field that canonicalisation says nothing about:
    `apply_hashes` (`app.mdm.service`) hashes `app.short_version` into the row's
    `key_full`, and this function hardcodes `None` in its place below. The two agree only
    because `app.mdm.jamf.client.normalize_computer` pins `short_version=None` on every
    `NormalizedApp` it builds from Jamf's `applications` section — that endpoint exposes
    one `version` field and no separate short version, so there is nothing else to put
    there. That pin is internal, not wire (Jamf's own object is untouched), but it is
    exactly what this function depends on: if an ingest path ever started populating
    `short_version`, the row's `key_full` would move and this fallback's would not, and
    the two sides would silently diverge. Pinned against all 83 rows of the real fixture,
    and against the dependency itself, in tests/test_inventory_snapshot.py.

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
    answers: Mapping[tuple[str, str, str], PatchEnrichment],
    keys: Mapping[tuple[str, str, str], tuple[str, str]],
    *,
    subject_id: str,
    corpus: VulnCorpus,
    as_of: date,
) -> InventoryAppItem:
    body = entry.body
    key = app_identity(body.get("name"), body.get("bundleId"), body.get("version"))
    patch = answers.get(key)
    if patch is None:
        # A genuine miss is `supported: false` plus a log line, never an exception: every
        # entry has a row by construction (both views are built from the same raw list),
        # so this is the alarm for that construction breaking, not a per-device failure.
        # `app_name`, not `name`: `name` is a reserved LogRecord attribute and `extra`
        # refuses to overwrite it — this line ran once with `name` and raised in a test.
        logger.warning(
            "installed app has no row to read patch support from; shipping supported=false",
            extra={"subject_id": subject_id, "app_name": body.get("name"), "bundle_id": body.get("bundleId")},
        )
        patch = PatchEnrichment(supported=False)
    key_title, key_full = keys.get(key) or _fallback_content_keys(body)
    return InventoryAppItem(
        app=dict(body),
        patch=patch,
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
    title_names: Mapping[str, str] | None = None,
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

    `title_names` is the loaded patch catalog's id -> name map, for `patch.jamfPatch.titleNames`
    (#311). A plain mapping rather than the `Catalog` itself, so this function stays a pure
    function of plain data and needs no patch-matching import to be tested. `None` is the honest
    default: on a scoped read no catalog is consulted, and names read off a catalog that was
    never asked about these rows would be a guess.

    `occurredAt` is the clock the block's day arithmetic uses — the event's own instant,
    never the wall clock. This function stays pure and clock-free, and a delivery retried
    across a day boundary re-expands the stored row to the same bytes.
    """
    apps = list(apps)
    answers = patch_answer(apps, title_names)
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
                    answers,
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
