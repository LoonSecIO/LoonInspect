"""Smart groups, read from the observation ledger.

One endpoint so far: the tenant's smart groups ranked by likely recalculation cost.
The ranking itself, and everything it deliberately refuses to claim, is
`app.mdm.jamf.group_cost` — read that module's docstring before changing anything here.

Where the criteria actually live, since the answer is not obvious: the catalog
collection observes each smart group as its own subject (`computer_group`), and the
criteria are inside the content-addressed `definition` section. So a group's *current*
definition is the current span for that subject joined to the section row whose digest
the span names. That join is this whole feature's substance and it is one query.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends
from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.mdm.jamf.contract import GROUP_DEFINITION_SECTION, SUBJECT_COMPUTER_GROUP
from app.mdm.jamf.group_cost import RANKING_VERSION, assess_criteria, rank_key
from app.models.schema import ObservationEntry, ObservationSection, ObservationSpan
from app.schemas.smart_groups import SmartGroupCostOut, SmartGroupCostResponse, SmartGroupCriterionOut

router = APIRouter(prefix="/api/smart-groups", tags=["smart-groups"])

ADVISORY = (
    "Advisory. Ranked from the criteria Jamf reports, by what each operator has to do to "
    "one device's value — not a measurement of your Jamf server."
)


@router.get(
    "/cost",
    response_model=SmartGroupCostResponse,
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="Smart groups ranked by likely recalculation cost (advisory)",
)
async def smart_group_cost(db: AsyncSession = Depends(get_db)) -> SmartGroupCostResponse:
    """Every smart group whose definition the ledger currently holds, most expensive
    first. Read-only, and local: nothing here contacts Jamf.

    Unpaginated on purpose. A Jamf tenant has tens to hundreds of smart groups, the
    criteria of all of them are a few hundred kilobytes at worst, and the ordering is
    over the whole set — a page-at-a-time API would have to rank server-side anyway and
    would still hand the caller a list it could not re-sort honestly.

    A tenant that has never run a catalog collection gets `{items: [], total: 0}` and a
    200. Nothing has gone wrong in that case: there is simply nothing observed yet, and
    a 404 would be indistinguishable from a broken route.
    """
    # No tenant predicate anywhere below, and that is the design: row-level security on
    # observation_spans / observation_sections / observation_entries is the boundary,
    # and a hand-written `tenant_id ==` beside it is a second boundary that can drift
    # out of agreement with the first. `tests/test_smart_group_cost_db.py` is what
    # proves the one boundary holds, under a non-superuser role, for this join.
    rows = (
        await db.execute(
            select(ObservationSpan, ObservationSection.body)
            .join(
                ObservationSection,
                ObservationSection.digest == ObservationSpan.section_digests[GROUP_DEFINITION_SECTION].astext,
            )
            .where(
                ObservationSpan.subject_kind == SUBJECT_COMPUTER_GROUP,
                ObservationSpan.is_current.is_(True),
                ObservationSection.section == GROUP_DEFINITION_SECTION,
            )
        )
    ).all()

    ea_names = (
        await db.execute(
            select(distinct(ObservationEntry.label)).where(
                ObservationEntry.kind == "extension_attribute", ObservationEntry.label.is_not(None)
            )
        )
    ).scalars().all()

    items: list[tuple[tuple, SmartGroupCostOut]] = []
    for span, body in rows:
        cost = assess_criteria((body or {}).get("criteria"), extension_attributes=ea_names)
        out = SmartGroupCostOut(
            id=span.subject_id,
            # The span's label first. For a group both carry the name — the contract
            # treats a group's own name as part of its definition — but the label is
            # refreshed on every observation, and the body is whatever was hashed.
            name=span.label or (body or {}).get("name"),
            mdm_connection_id=span.mdm_connection_id,
            band=cost.band,
            class_counts=dict(cost.class_counts),
            criteria_count=cost.criteria_count,
            dependent_count=cost.dependent_count,
            max_depth=cost.max_depth,
            criteria=[SmartGroupCriterionOut(**asdict(criterion)) for criterion in cost.criteria],
            first_observed_at=span.first_observed_at,
            last_observed_at=span.last_observed_at,
        )
        # The stable tail the ranking deliberately leaves to the caller, so two groups
        # that cost the same come back in the same order on every request.
        items.append(((*rank_key(cost), out.name or "", out.mdm_connection_id, out.id), out))

    items.sort(key=lambda pair: pair[0])
    ordered = [out for _, out in items]
    return SmartGroupCostResponse(items=ordered, total=len(ordered), ranking=RANKING_VERSION, advisory=ADVISORY)
