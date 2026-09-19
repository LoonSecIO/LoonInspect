"""Whether a corpus is answering for the acting tenant (#529), and which builds one finding
id is on (#533).

The Posture section's Vulnerabilities entry is listed when the corpus answers for this
organization — the data decides, not a switch nobody knows to flip — and the sidebar needs
that answer before any page is open, so it cannot come off `/api/catalog`'s `corpusAsOf` the
way the banner's does. `VULN_READ` because every role holds it, and this says nothing a role
could be refused for: a date, or `null`.

Deliberately not a second gate: `corpus_as_of(await earned_corpus(db))` is the same answer
`app.api.catalog` gives its rows, so the nav and the banner cannot disagree.
"""

from __future__ import annotations

from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.catalog import NO_ANSWER, _assessed_entry_out, _device_counts, _title_refs
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.vuln import validate_finding_id
from app.core.vuln_answer import served, stored_corpus
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_read import corpus_as_of, detection, today
from app.models.schema import AppCatalogEntry
from app.schemas.catalog import CatalogEntryAssessedOut

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


class VulnStatusOut(BaseModel):
    """`null` is the honest answer under both of §8's causes — no epoch loaded here, or an
    epoch loaded and this organization's sharing off — and the caller may not tell them
    apart, exactly as the `off` block may not (§4a)."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    corpus_as_of: date | None = None


@router.get("/status", response_model=VulnStatusOut, dependencies=[Depends(require(Permission.VULN_READ))])
async def vulnerability_status(db: AsyncSession = Depends(get_db)) -> VulnStatusOut:
    return VulnStatusOut(corpus_as_of=corpus_as_of(await earned_corpus(db)))


class FindingDetectedOut(BaseModel):
    """When this pod first and last saw the id on a Mac, and on how many (#591, over #590's ledger).
    One object rather than four loose keys, so its absence is **one** absence. `lastDetectedAt` is
    *as of last observation*, never as of now — an open row only says the finding was there when
    that Mac was last seen (§6), so a dark Mac's finding ages with the Mac, and the page says so."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)

    first_detected_at: datetime
    last_detected_at: datetime | None
    devices_open: int
    devices_ever: int


class VulnLookupOut(BaseModel):
    """What one id answers with — and what it cannot answer for.

    The builds are the Catalog list's own rows, `CatalogEntryAssessedOut` — **one per build,
    never per Mac**, since each row IS the build being answered about (§4a) — with that row's
    `vuln` block, #482's `vulnUpdate` line, the device count and the hashes a page links with.

    `truncatedBuilds` is the caveat carried rather than implied: a capped id list (§4e) leaves an
    id counted in `counts.total` and named nowhere, where no lookup can see it. It counts every
    served row a Mac carries whose list was cut — not only the rows below, because those are
    exactly the ones that could not appear — and a surface prints it beside an empty answer too,
    so *nothing found* is never read as *not on your fleet* (§4a).
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    corpus_as_of: date
    builds: list[CatalogEntryAssessedOut]
    truncated_builds: int
    # `null` while the ledger holds no row for this id — **absent, never four zeros** (§4a). Null
    # beside a non-empty `builds` is legible, not broken: the corpus says which builds carry the id
    # now and the ledger since when this pod saw it, and a Mac unswept since #590 answers only the
    # first.
    detected: FindingDetectedOut | None = None


# After `/status` on purpose: FastAPI matches in declaration order, and a dynamic segment above
# it would swallow "status" as an id — and then refuse it as a shape.
@router.get("/{vuln_id}", response_model=VulnLookupOut, dependencies=[Depends(require(Permission.VULN_READ))])
async def lookup_vulnerability(vuln_id: str, db: AsyncSession = Depends(get_db)) -> VulnLookupOut:
    """The tenant's builds whose SERVED answer names this id (#533) — §4e's list asked the other
    way round, so *is CVE-X on my fleet* is answerable in the product and not only in Splunk.
    Served is `vuln_answer.served` and nothing else: a row judged by an epoch that has moved reads
    `unknown_app` whatever ids it stores, and `unknown_app` and `off` rows carry no ids at all
    (§4a, §4f). Installed, too — see `carried` below. Two refusals come first, in this order: the
    shape, by §5's one validator, which refuses `LOCAL-` in its own words and names the two
    licensed namespaces for anything else; then the tier, since an empty answer for an
    organization nothing answers for reads as *nothing found*, so it meets the refusal a
    vulnerability filter meets, in its words."""
    try:
        finding = validate_finding_id(vuln_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    corpus = await earned_corpus(db)
    if corpus.as_of is None:
        raise HTTPException(status_code=409, detail=NO_ANSWER)
    covered = served(AppCatalogEntry.vuln_assessment, AppCatalogEntry.vuln_signature, epoch=loaded_epoch_signature())
    counts = _device_counts()
    devices = counts.c.devices
    # A build a Mac carries NOW, the Catalog list's own `installedOnly` default: the table keeps a
    # build after the last Mac drops it, and a row no Mac has is neither an answer to *is this on
    # my fleet* nor something the caveat below should count. Then `@>` — the containment
    # `ix_app_catalog_vuln_ids` serves, so this is an index probe and not a walk of every build.
    carried = AppCatalogEntry.version_hash == counts.c.version_hash
    carrying = (
        select(AppCatalogEntry, devices.label("devices"))
        .join(counts, carried)
        .where(covered, AppCatalogEntry.vuln_ids.contains([finding]))
        .order_by(devices.desc(), AppCatalogEntry.name, AppCatalogEntry.version)
    )
    cut = (
        select(func.count())
        .select_from(AppCatalogEntry)
        .join(counts, carried)
        .where(covered, AppCatalogEntry.vuln_ids_truncated.is_(True))
    )
    rows, truncated = (await db.execute(carrying)).all(), (await db.execute(cut)).scalar_one()
    entries = [row[0] for row in rows]
    refs, stored, as_of = await _title_refs(db, entries), stored_corpus(corpus, entries), today()
    builds = [_assessed_entry_out(entry, count, refs, corpus=stored, as_of=as_of) for entry, count in rows]
    # One ledger statement for the whole response: this id's own interval. The builds below carry
    # no *Seen here* — that column is the list's, and nothing on this page draws it yet (#591).
    found = await detection(db, finding)
    detected = FindingDetectedOut.model_validate(found) if found is not None else None
    return VulnLookupOut(corpus_as_of=corpus.as_of, builds=builds, truncated_builds=int(truncated), detected=detected)
