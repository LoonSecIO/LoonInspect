"""The stored per-build answer: the columns it lives in, and the seam that reads it (#381).

#248 loads an epoch. This is where its answer for one build is **kept**, and how the wire
and the page read it back.

**The join runs once per distinct build, never per device.** `app.catalog.service` joins a
tenant's `app_catalog` rows to `vuln_library_rows` on `key_full` at judge time — one
`UPDATE … FROM` per epoch per tenant — and copies the answer onto every `installed_apps`
row carrying that build, exactly as it already copies the Jamf Patch answer. A device page
with 250 apps then reads 250 columns rather than asking a corpus 250 questions, and a
40k-device sweep fans out ~3M app items off answers that were computed once. That is
"cache, don't calculate" in its usual shape: the answer is a property of the *build*, and
nothing about it differs between two Macs carrying it.

**A row is the only thing that means "clean" — here too** (ruling R-D, 2026-09-11;
docs/vulnerabilities.md §4f). `vuln_assessment` is `covered` or NULL, and NULL is
`unknown_app`: the epoch held no row for this build, which is *not* a clean bill and never
renders as one. Nothing upgrades a missing row — not a title in the coverage metadata, not
a stamp, not an absence of findings.

**Which epoch answered travels with the answer.** `vuln_signature` is the signature of the
epoch that produced the counts, compared for equality against the epoch this process has
loaded and never ordered. An answer from an epoch that is no longer answering reads
`unknown_app` until the next judge pass rewrites it, because `corpusAsOf` on the block
names the *loaded* epoch — counts from one epoch under another's date is the silent
staleness §4 exists to prevent, and "dated, never zero" is the conservative direction the
contract rules in every other place the question comes up. The window is bounded by the
hourly catalog refresh — which copies for the whole tenant on **every** pass, not only when
it re-judged something — and by that device's own next sync. Not by the next sync of *any*
device carrying the build: the Mac that judges is the one whose rows get the copy, so the
tenant-wide pass is the only thing that reaches the rest of them.

**`off` is decided here and now, never stored.** A tenant whose data-sharing tier is `off`
and a container with no epoch both read `off` through `loaded_corpus()`'s own gate, which
is one `is None` and no per-row work at all — `stored_corpus` hands the caller the corpus
it was given, unchanged, so the `off` block stays byte-identical to the day #241 emitted
it. The judge path writes nothing under that gate either: a tenant that has not consented
carries no corpus-derived columns, and flipping the tier back re-judges with no download
(§8).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, date, datetime
from typing import Protocol

from app.core.vuln import AssessedBuild, VulnCorpus, VulnFinding
from app.core.vuln_library import loaded_epoch_signature
from app.schemas.payload import VULN_ASSESSMENT_COVERED, VULN_SEVERITY_BANDS

logger = logging.getLogger(__name__)

# What "the vulnerability answer" IS, in column terms — the one definition, for the same
# reason `app.catalog.service.answer_columns` exists for the Jamf Patch answer: there are
# two paths that copy it onto `installed_apps` (per row at device process, and a set-based
# UPDATE after an epoch moves), and a second hand-written list is how one of them silently
# stops carrying a column (#311's `ea_assumed`, found in a container rather than by a test).
#
# Ordered as the judge-time statement writes them. `vuln_evaluated_at` is deliberately NOT
# here: it is the catalog row's own judge clock, the pair of `evaluated_at`, and a device
# row's clock is `last_patch_check_at`.
VULN_ANSWER_COLUMNS: tuple[str, ...] = (
    "vuln_assessment",
    "vuln_counts",
    "vuln_oldest_published",
    "vuln_ids",
    "vuln_ids_truncated",
    "vuln_signature",
)


class HasStoredAnswer(Protocol):
    """Anything carrying the stored answer — `AppCatalogEntry` and `InstalledApp`, which
    carry identical copies of it. A protocol rather than a union of the two models so this
    module imports no ORM and stays as cheap to test as `app.core.vuln_read`."""

    key_full: str
    vuln_assessment: str | None
    vuln_counts: dict | None
    vuln_oldest_published: dict | None
    vuln_ids: list | None
    vuln_ids_truncated: bool | None
    vuln_signature: str | None


def stored_build(row: HasStoredAnswer) -> AssessedBuild | None:
    """One row's stored answer as the seam's `AssessedBuild`, or `None` for *not assessed*.

    The aggregates are passed through, never recomputed — `counts.total` is the uncapped
    truth the epoch stated and `vuln_ids` is a capped list, so recounting the list would
    under-report (§4a, §4e). The day arithmetic and the id cap stay `vuln_block`'s, because
    both depend on something a stored row cannot know: the event's own clock, and this
    container's `VULN_IDS_CAP`.

    Raises if the stored JSON is not the shape the library publishes. That is deliberate
    and it is caught by the one caller that reads rows it did not just write
    (`stored_corpus`): `AssessedBuild`'s own invariants are what make a malformed answer a
    named, logged `unknown_app` instead of a plausible wrong number.
    """
    if row.vuln_assessment != VULN_ASSESSMENT_COVERED:
        return None
    counts: Mapping[str, object] = row.vuln_counts or {}
    oldest: Mapping[str, object] = row.vuln_oldest_published or {}
    return AssessedBuild(
        total=int(counts["total"]),  # type: ignore[arg-type]
        kev=int(counts["kev"]),  # type: ignore[arg-type]
        severity={band: int(counts[band]) for band in VULN_SEVERITY_BANDS},  # type: ignore[arg-type]
        oldest_published=_published(oldest.get("total")),
        oldest_published_severity={band: _published(oldest.get(band)) for band in VULN_SEVERITY_BANDS},
        ids=tuple(row.vuln_ids or ()),
        truncated=bool(row.vuln_ids_truncated),
    )


def _published(value: object) -> date | None:
    """A stored publication stamp back as a date — the shape
    `app.core.vuln_library._stamp` writes, which is the format's own
    `YYYY-MM-DDTHH:MM:SSZ`. `None` is "no finding in this band", not a parse failure;
    anything else that is not that shape is one, and the caller names it."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{value!r} is not a publication timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).date()


class StoredAnswers:
    """`VulnCorpus` over the answers already on the rows in hand — no lookup, no database.

    The seam does not move: `vuln_block` and `assess` ask the same two-member protocol the
    same question, and only *where the answer comes from* changed. `findings()` is a
    dictionary read over rows the caller already loaded, so a response or an event costs
    nothing per app beyond the block it was always building.

    Keyed on `key_full` alone, which is what ruling R-D makes it: the verdict comes from the
    build's row, never from its title. Collapsing two rows onto one key is therefore not a
    hazard here the way it would be for `key_title` — `key_full` hashes `(name, bundleId,
    version)` and `key_title` hashes the first two of those, so one determines the other and
    two rows sharing a `key_full` are the same application at the same version. Two catalog
    rows can share it across platforms; they carry the same answer, because the library is
    keyed on the build and knows nothing about platforms.
    """

    __slots__ = ("_answers", "_as_of")

    def __init__(self, as_of: date, answers: Mapping[str, AssessedBuild]) -> None:
        self._as_of = as_of
        self._answers = answers

    @property
    def as_of(self) -> date | None:
        return self._as_of

    def findings(self, *, key_title: str, key_full: str) -> AssessedBuild | Sequence[VulnFinding] | None:
        return self._answers.get(key_full)


def stored_corpus(corpus: VulnCorpus, rows: Iterable[HasStoredAnswer]) -> VulnCorpus:
    """The corpus a caller should hand `vuln_block` for THESE rows.

    `corpus` is what the gate answered (`loaded_corpus()` / `earned_corpus`), and it is
    returned untouched when nothing is answering — `off`, one `is None`, no per-row work,
    byte-identical. Otherwise the stamp is the loaded epoch's and every answer is one that
    was judged against that same epoch; anything else is left out, which reads
    `unknown_app`.

    Nothing here reads the database. The rows are ones the caller already has: the device's
    own app rows, the catalog page's own entries, the snapshot's `current_rows`.
    """
    if corpus.as_of is None:
        return corpus
    signature = loaded_epoch_signature()
    answers: dict[str, AssessedBuild] = {}
    for row in rows:
        if row.vuln_assessment != VULN_ASSESSMENT_COVERED or row.vuln_signature != signature:
            continue
        try:
            build = stored_build(row)
        except (KeyError, TypeError, ValueError) as exc:
            _unreadable(row, exc)
            continue
        if build is not None:
            answers[row.key_full] = build
    return StoredAnswers(corpus.as_of, answers)


def _unreadable(row: HasStoredAnswer, exc: Exception) -> None:
    """One stored answer that is not the shape the library writes, named rather than raised.

    Every one of these was written by a column-to-column copy out of a row the epoch import
    already validated, so this line firing means the stored answer moved underneath us —
    a hand-edited row, a restored backup from a different build. The app it describes reads
    `unknown_app` (dated, never zero) and the next judge pass rewrites it; a traceback out
    of a device page would be the wrong answer to a row this container can simply decline
    to trust.
    """
    logger.warning(
        "the stored vulnerability answer for %s could not be read: %s. That app reads assessment: unknown_app until the "
        "next judge pass rewrites it (docs/troubleshooting.md §5)",
        row.key_full,
        exc,
        extra={"state": "answer_unreadable", "key_full": row.key_full},
    )
