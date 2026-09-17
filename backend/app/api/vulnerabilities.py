"""Whether a corpus is answering for the acting tenant, for a surface that must decide
before it draws anything (#529).

The Posture section's Vulnerabilities entry is listed when the corpus answers for this
organization — the data decides, not a switch nobody knows to flip — and the sidebar needs
that answer before any page is open, so it cannot come off `/api/catalog`'s `corpusAsOf` the
way the banner's does. `VULN_READ` because every role holds it, and this says nothing a role
could be refused for: a date, or `null`.

Deliberately not a second gate: `corpus_as_of(await earned_corpus(db))` is the same answer
`app.api.catalog` gives its rows, so the nav and the banner cannot disagree.
"""

from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.vuln_library import earned_corpus
from app.core.vuln_read import corpus_as_of

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
