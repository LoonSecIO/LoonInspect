from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import (
    Principal,
    current_principal,
    require,
    revoke_all_sessions,
    revoke_all_tokens,
)
from app.core.bootstrap import create_account
from app.core.database import get_db
from app.core.permissions import Permission, Role
from app.core.security import hash_password
from app.models.schema import Account, AccountRole, AuthIdentity
from app.schemas.accounts import (
    AccountCreateRequest,
    AccountSummaryOut,
    AccountUpdateRequest,
    PasswordResetRequest,
)

router = APIRouter(prefix="/api/accounts", tags=["accounts"])
logger = logging.getLogger(__name__)

_VALID_ROLES = {role.value for role in Role}
_VALID_STATUSES = {"active", "disabled"}

# Role grants this API owns. Rows from any other source belong to the system that
# created them — a future IdP group sync reconciles its own and must not have them
# deleted out from under it by a human edit here.
_MANUAL = "manual"


def _to_out(account: Account) -> AccountSummaryOut:
    return AccountSummaryOut(
        id=account.id,
        email=account.email,
        display_name=account.display_name,
        status=account.status,
        roles=sorted({row.role for row in account.roles}),
        is_break_glass=account.is_break_glass,
        is_service_account=account.is_service_account,
        external_source=account.external_source,
        created_at=account.created_at,
        last_login_at=account.last_login_at,
    )


async def _get_or_404(db: AsyncSession, account_id: str) -> Account:
    account = await db.get(Account, account_id)
    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    return account


def _validate_roles(roles: list[str]) -> list[str]:
    unknown = sorted(set(roles) - _VALID_ROLES)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown role(s): {', '.join(unknown)}")
    return sorted(set(roles))


async def _active_admin_ids(db: AsyncSession, exclude: str | None = None) -> set[str]:
    """Accounts that can still administer the system. The guard rails below are all
    expressed in terms of this set."""
    query = (
        select(Account.id)
        .join(AccountRole, AccountRole.account_id == Account.id)
        .where(Account.status == "active", AccountRole.role == Role.admin.value)
    )
    if exclude is not None:
        query = query.where(Account.id != exclude)
    result = await db.execute(query)
    return set(result.scalars().all())


async def _assert_not_last_admin(db: AsyncSession, account: Account) -> None:
    """Refuse a change that would leave nobody able to administer the system.

    There is no password-reset-by-email and no console. Losing the last admin means
    exec'ing into the container with a Python shell to repair it, so this is worth
    blocking rather than warning about.
    """
    if not await _active_admin_ids(db, exclude=account.id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This is the only remaining administrator. Grant admin to another "
            "active account first.",
        )


async def _replace_manual_roles(db: AsyncSession, account: Account, roles: list[str], granted_by: str) -> None:
    await db.execute(
        delete(AccountRole).where(
            AccountRole.account_id == account.id, AccountRole.source == _MANUAL
        )
    )
    for role in roles:
        db.add(
            AccountRole(
                account_id=account.id, role=role, source=_MANUAL, granted_by=granted_by
            )
        )
    await db.flush()


@router.get("", response_model=list[AccountSummaryOut], dependencies=[Depends(require(Permission.ACCOUNT_READ))])
async def list_accounts(db: AsyncSession = Depends(get_db)) -> list[AccountSummaryOut]:
    result = await db.execute(select(Account).order_by(Account.created_at))
    return [_to_out(account) for account in result.scalars().all()]


@router.post(
    "",
    response_model=AccountSummaryOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.ACCOUNT_WRITE))],
)
async def create(
    payload: AccountCreateRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> AccountSummaryOut:
    email = payload.email.strip().lower()

    existing = await db.execute(select(Account.id).where(Account.email == email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with that email already exists")

    roles = _validate_roles(payload.roles) or [Role.viewer.value]

    account, _ = await create_account(
        db,
        email=email,
        display_name=payload.display_name,
        password=payload.password,
        roles=roles,
    )
    # granted_by isn't set by create_account, which has no notion of a caller.
    await _replace_manual_roles(db, account, roles, granted_by=principal.account.id)
    await db.commit()
    await db.refresh(account, ["roles"])

    audit(
        AuditAction.ACCOUNT_CREATED,
        target_type="account",
        target_id=account.id,
        email=account.email,
        roles=roles,
    )
    logger.info("account created", extra={"account_id": account.id, "email": account.email})
    return _to_out(account)


@router.get(
    "/{account_id}",
    response_model=AccountSummaryOut,
    dependencies=[Depends(require(Permission.ACCOUNT_READ))],
)
async def get_account(account_id: str, db: AsyncSession = Depends(get_db)) -> AccountSummaryOut:
    return _to_out(await _get_or_404(db, account_id))


@router.patch(
    "/{account_id}",
    response_model=AccountSummaryOut,
    dependencies=[Depends(require(Permission.ACCOUNT_WRITE))],
)
async def update_account(
    account_id: str,
    payload: AccountUpdateRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> AccountSummaryOut:
    account = await _get_or_404(db, account_id)
    is_self = account.id == principal.account.id
    events: list[tuple[AuditAction, dict]] = []

    if payload.display_name is not None:
        account.display_name = payload.display_name.strip()

    if payload.roles is not None:
        roles = _validate_roles(payload.roles)
        previous = sorted({row.role for row in account.roles})

        if roles != previous:
            # Self-demotion is blocked outright rather than guarded by the last-admin
            # check: an admin removing their own admin role in a two-admin system
            # passes that check and still locks themselves out of this page.
            if is_self and Role.admin.value in previous and Role.admin.value not in roles:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="You cannot remove your own administrator role. Ask another "
                    "administrator to do it.",
                )
            if Role.admin.value in previous and Role.admin.value not in roles:
                await _assert_not_last_admin(db, account)

            await _replace_manual_roles(db, account, roles, granted_by=principal.account.id)
            events.append(
                (AuditAction.ACCOUNT_ROLES_CHANGED, {"before": previous, "after": roles})
            )

    if payload.status is not None and payload.status != account.status:
        if payload.status not in _VALID_STATUSES:
            raise HTTPException(status_code=422, detail=f"Unknown status: {payload.status}")

        if payload.status == "disabled":
            if is_self:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="You cannot disable your own account.",
                )
            await _assert_not_last_admin(db, account)

            account.status = "disabled"
            # Synchronous and complete. A disabled operator still holding a valid
            # session cookie or API token is precisely what disabling exists to stop;
            # letting those expire on their own is not an answer anyone accepts.
            await revoke_all_sessions(db, account.id)
            await revoke_all_tokens(db, account.id)
            events.append((AuditAction.ACCOUNT_DISABLED, {"email": account.email}))
        else:
            account.status = "active"
            events.append((AuditAction.ACCOUNT_ENABLED, {"email": account.email}))

    await db.commit()
    await db.refresh(account, ["roles"])

    if payload.display_name is not None and not events:
        events.append((AuditAction.ACCOUNT_UPDATED, {"changed": ["display_name"]}))

    for action, metadata in events:
        audit(action, target_type="account", target_id=account.id, **metadata)

    return _to_out(account)


@router.post(
    "/{account_id}/reset-password",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.ACCOUNT_WRITE))],
)
async def reset_password(
    account_id: str,
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Administrative password reset — the only account recovery path, since there is
    no mail transport to send a reset link through."""
    account = await _get_or_404(db, account_id)

    result = await db.execute(
        select(AuthIdentity).where(
            AuthIdentity.account_id == account.id, AuthIdentity.provider == "local"
        )
    )
    identity = result.scalar_one_or_none()
    if identity is None:
        raise HTTPException(status_code=422, detail="That account has no password identity to reset")

    identity.secret_hash = hash_password(payload.new_password)
    identity.password_changed_at = datetime.now(timezone.utc)

    # Everything that authenticated with the old password dies with it. An attacker
    # who prompted the reset by locking someone out shouldn't keep their foothold.
    await revoke_all_sessions(db, account.id)
    await revoke_all_tokens(db, account.id)
    await db.commit()

    audit(
        AuditAction.PASSWORD_RESET,
        target_type="account",
        target_id=account.id,
        email=account.email,
    )
    logger.warning("password reset by administrator", extra={"account_id": account.id})
