"""Tenant settings served as text (#116), and the rules an organization confirms beside them.

The **statement** is display and evidence context, never a threshold: docs/v-never.md refuses
invented compliance regimes, and a sentence cannot be evaluated. The **rules** are the
legitimization #116 left as its own ruling — limits from a closed vocabulary
(`app.mdm.patch.policy`) that someone holding `system:write` confirms, for the organization
and per title. Only a confirmed rule judges a build. One more setting is enforced rather than
displayed: who must sign in with a second factor (#653), read by app.core.auth."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db
from app.core.permissions import Permission
from app.mdm.patch.policy import Rule, Rules
from app.mdm.patch.policy_presets import PRESETS, Preset, is_basis_of, preset
from app.models.schema import JamfPatchTitle, PatchingPolicy, Tenant
from app.schemas.settings import (
    MfaPolicy,
    PatchingPolicyOut,
    PatchingPolicyUpdate,
    PatchingRulesOut,
    PatchRule,
    PatchRuleConfirm,
    PatchRuleOverride,
    PatchRuleOverrideOut,
    PresetOut,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


async def patching_rules(db: AsyncSession) -> Rules:
    """The acting tenant's confirmed rules — empty when none is, which judges nothing."""
    stored = (await db.execute(select(PatchingPolicy.rules))).scalar_one_or_none()
    return Rules.from_stored(stored)


def _rule_out(rule: Rule) -> PatchRule:
    return PatchRule(
        max_days_behind=rule.max_days_behind,
        max_releases_behind=rule.max_releases_behind,
        max_days_behind_severe=rule.max_days_behind_severe,
    )


def _preset_out(entry: Preset) -> PresetOut:
    return PresetOut(
        id=entry.id,
        framework=entry.framework,
        document=entry.document,
        published=entry.published,
        section=entry.section,
        url=entry.url,
        verified_on=entry.verified_on,
        rule=_rule_out(entry.rule),
    )


async def _policy_out(db: AsyncSession, row: PatchingPolicy | None) -> PatchingPolicyOut:
    if row is None:
        return PatchingPolicyOut()
    rules = Rules.from_stored(row.rules)
    names = {}
    if rules.overrides:
        found = await db.execute(select(JamfPatchTitle.id, JamfPatchTitle.name).where(JamfPatchTitle.id.in_(rules.overrides)))
        names = dict(found.all())
    overrides = [
        PatchRuleOverrideOut(
            title_id=title_id,
            title_name=names.get(title_id),
            max_days_behind=rule.max_days_behind,
            max_releases_behind=rule.max_releases_behind,
            max_days_behind_severe=rule.max_days_behind_severe,
            exempt=rule.exempt,
        )
        for title_id, rule in rules.overrides.items()
    ]
    overrides.sort(key=lambda override: ((override.title_name or override.title_id).casefold(), override.title_id))
    default = rules.default
    stamp = row.rules or {}
    updated_at = stamp.get("updated_at")
    return PatchingPolicyOut(
        statement=row.statement,
        updated_at=row.updated_at,
        updated_by=row.updated_by,
        rules=PatchingRulesOut(
            default=None if default is None else _rule_out(default),
            # Shown only while it still holds: an entry this build does not have, or a rule
            # that no longer equals the entry's, has no basis to show.
            basis=_preset_out(basis) if (basis := preset(rules.default_basis)) and is_basis_of(basis.id, default) else None,
            overrides=overrides,
            updated_at=datetime.fromisoformat(updated_at) if isinstance(updated_at, str) else None,
            updated_by=stamp.get("updated_by") if isinstance(stamp.get("updated_by"), str) else None,
        ),
    )


async def _row_for_write(db: AsyncSession) -> PatchingPolicy:
    row = (await db.execute(select(PatchingPolicy))).scalar_one_or_none()
    if row is None:
        row = PatchingPolicy()
        db.add(row)
    return row


def _store_rules(row: PatchingPolicy, rules: Rules, principal: Principal) -> None:
    """The whole document, replaced — a JSONB column mutated in place is a write SQLAlchemy
    does not see."""
    row.rules = {
        "default": rules.default.stored() if rules.default is not None else None,
        "default_basis": rules.default_basis,
        "overrides": {title_id: rule.stored() for title_id, rule in rules.overrides.items()},
        "updated_at": datetime.now(UTC).isoformat(),
        "updated_by": principal.account.email,
    }


@router.get(
    "/patching-policy",
    response_model=PatchingPolicyOut,
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def get_patching_policy(db: AsyncSession = Depends(get_db)) -> PatchingPolicyOut:
    """The org's stated patching policy and its confirmed rules — an empty statement and no
    rules when nothing has been stated.

    Gated like the Jamf Patch page it is read beside (`app:read`), so the auditor who
    reads the numbers reads the sentence. Reading creates nothing: an unstated policy is
    an absent row, and the page says "no patching policy stated" in words.
    """
    return await _policy_out(db, (await db.execute(select(PatchingPolicy))).scalar_one_or_none())


@router.put(
    "/patching-policy",
    response_model=PatchingPolicyOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def put_patching_policy(
    payload: PatchingPolicyUpdate,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> PatchingPolicyOut:
    """State the policy, or clear it with an empty statement. Audited: who stated what an
    auditor will read is exactly what the audit trail exists for. The rules are untouched:
    rewording the sentence does not move what the page judges against."""
    row = await _row_for_write(db)
    row.statement = payload.statement.strip()
    row.updated_at = datetime.now(UTC)
    row.updated_by = principal.account.email
    await db.commit()
    await db.refresh(row)
    audit(
        AuditAction.PATCHING_POLICY_UPDATED,
        target_type="patching_policy",
        statement_length=len(row.statement),
        cleared=row.statement == "",
    )
    return await _policy_out(db, row)


@router.get(
    "/patching-policy/presets",
    response_model=list[PresetOut],
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def list_patching_presets() -> list[PresetOut]:
    """The published requirements a rule can be started from, each with its source and the
    rule it maps to. Static, the same for every organization, and read by anyone who reads
    the page: an auditor following a rule's basis reads the same entry the admin chose."""
    return [_preset_out(entry) for entry in PRESETS]


@router.put(
    "/patching-policy/rule",
    response_model=PatchingPolicyOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def put_patching_rule(
    payload: PatchRuleConfirm,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> PatchingPolicyOut:
    """Confirm the organization's rule, or clear it with both limits null. This is the act
    that makes a threshold the organization's own rather than the product's; audited with
    the limits themselves, because what was confirmed is what an auditor will ask."""
    row = await _row_for_write(db)
    current = Rules.from_stored(row.rules)
    rule = Rule(
        max_days_behind=payload.max_days_behind,
        max_releases_behind=payload.max_releases_behind,
        max_days_behind_severe=payload.max_days_behind_severe,
    )
    if payload.basis is not None and not is_basis_of(payload.basis, rule):
        known = preset(payload.basis)
        if known is None:
            detail = (
                f"This build has no published requirement with the id {payload.basis}, so the rule cannot be recorded as "
                "drawn from it. Confirm the limits without a basis."
            )
        else:
            detail = (
                f"The limits sent are not the ones {known.framework} ({known.document}, {known.section}) maps to, so the "
                "rule cannot be recorded as drawn from it. Confirm the limits without a basis, or start again from that "
                "requirement."
            )
        raise HTTPException(status_code=422, detail=detail)
    confirmed = Rules(default=rule if rule.judges else None, overrides=current.overrides, default_basis=payload.basis)
    _store_rules(row, confirmed, principal)
    await db.commit()
    await db.refresh(row)
    audit(
        AuditAction.PATCHING_POLICY_UPDATED,
        target_type="patching_policy_rule",
        basis=payload.basis,
        max_days_behind=rule.max_days_behind,
        max_releases_behind=rule.max_releases_behind,
        max_days_behind_severe=rule.max_days_behind_severe,
        cleared=not rule.judges,
    )
    return await _policy_out(db, row)


@router.put(
    "/patching-policy/overrides/{title_id}",
    response_model=PatchingPolicyOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def put_patching_override(
    title_id: str,
    payload: PatchRuleOverride,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> PatchingPolicyOut:
    """Give one Jamf Patch title its own rule, which replaces the organization's for that
    title: different limits, or `exempt`. Refused for a title the catalog does not list — an
    override nothing can be judged by is a typo, and it would sit unseen."""
    if await db.get(JamfPatchTitle, title_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"No Jamf Patch title has the id {title_id}, so there is nothing for this override to judge. "
            "Check the id against Devices › Applications › Jamf Patch; if the catalog is empty, press Sync now there first.",
        )
    row = await _row_for_write(db)
    current = Rules.from_stored(row.rules)
    rule = Rule(
        max_days_behind=payload.max_days_behind,
        max_releases_behind=payload.max_releases_behind,
        max_days_behind_severe=payload.max_days_behind_severe,
        exempt=payload.exempt,
    )
    # `replace`, so the organization's rule and its basis ride through a title's change untouched.
    _store_rules(row, replace(current, overrides={**current.overrides, title_id: rule}), principal)
    await db.commit()
    await db.refresh(row)
    audit(
        AuditAction.PATCHING_POLICY_UPDATED,
        target_type="patching_policy_override",
        target_id=title_id,
        max_days_behind=rule.max_days_behind,
        max_releases_behind=rule.max_releases_behind,
        max_days_behind_severe=rule.max_days_behind_severe,
        exempt=rule.exempt,
    )
    return await _policy_out(db, row)


@router.delete(
    "/patching-policy/overrides/{title_id}",
    response_model=PatchingPolicyOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def delete_patching_override(
    title_id: str,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> PatchingPolicyOut:
    """Remove a title's own rule, so the organization's judges it again. Removing one that is
    not there answers the current policy: the state asked for is the state that holds."""
    row = (await db.execute(select(PatchingPolicy))).scalar_one_or_none()
    current = Rules.from_stored(row.rules) if row is not None else Rules()
    if row is None or title_id not in current.overrides:
        return await _policy_out(db, row)
    kept = {other: rule for other, rule in current.overrides.items() if other != title_id}
    _store_rules(row, replace(current, overrides=kept), principal)
    await db.commit()
    await db.refresh(row)
    audit(AuditAction.PATCHING_POLICY_UPDATED, target_type="patching_policy_override", target_id=title_id, removed=True)
    return await _policy_out(db, row)


@router.get("/mfa-policy", response_model=MfaPolicy, dependencies=[Depends(require(Permission.ACCOUNT_READ))])
async def get_mfa_policy(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> MfaPolicy:
    """Who must sign in with a second factor where this session acts; read by whoever reads Accounts."""
    tenant = await db.get(Tenant, principal.tenant_id)
    return MfaPolicy(mfa_required=tenant.mfa_required)


@router.put("/mfa-policy", response_model=MfaPolicy, dependencies=[Depends(require(Permission.ACCOUNT_WRITE))])
async def put_mfa_policy(
    payload: MfaPolicy,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> MfaPolicy:
    """Administrators only. It applies from each account's next request; nobody is signed out."""
    tenant = await db.get(Tenant, principal.tenant_id)
    before = tenant.mfa_required
    tenant.mfa_required = payload.mfa_required
    await db.commit()
    audit(AuditAction.MFA_POLICY_CHANGED, target_type="tenant", target_id=tenant.id, before=before, after=tenant.mfa_required)
    return MfaPolicy(mfa_required=tenant.mfa_required)
