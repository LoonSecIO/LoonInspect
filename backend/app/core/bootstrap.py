from __future__ import annotations

import logging
import secrets
from collections.abc import Iterable
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.core.tenancy import (
    OPERATIONAL_TENANT_ID,
    OPERATIONAL_TENANT_SLUG,
    ROOT_TENANT_ID,
    ROOT_TENANT_SLUG,
)
from app.models.schema import Account, AccountRole, AuthIdentity, Destination, Tenant

logger = logging.getLogger(__name__)

# Regenerated on every boot and never persisted. A restart mid-setup invalidates the
# old token, which is the correct behaviour: the claim window should be tied to the
# running process, not left recoverable from disk.
_claim_token: str | None = None


def get_claim_token() -> str | None:
    return _claim_token


# (id, slug, name, kind) for the two tenants every install starts with. Root is
# management-only and owns no operational data; the child is what a single-tenant
# deployment's devices, connections, accounts, and events all belong to.
_BOOTSTRAP_TENANTS = (
    (ROOT_TENANT_ID, ROOT_TENANT_SLUG, "Root", "root"),
    (OPERATIONAL_TENANT_ID, OPERATIONAL_TENANT_SLUG, "Default", "operational"),
)


async def bootstrap_tenants(db: AsyncSession) -> None:
    """Create the root and operational tenants if they are not already there.

    Runs before anything else at startup and takes an *unscoped* session: every other
    table's row-level security reads a tenant that does not exist yet at this point,
    so this has to happen first, and `tenants` is deliberately outside that policy set
    for exactly this reason.

    Idempotent by id rather than by count, so adding a third tenant later can never
    make this decide the install is unbootstrapped.
    """
    existing = set(
        (await db.execute(select(Tenant.id).where(Tenant.id.in_([row[0] for row in _BOOTSTRAP_TENANTS]))))
        .scalars()
        .all()
    )

    created = [row for row in _BOOTSTRAP_TENANTS if row[0] not in existing]
    for tenant_id, slug, name, kind in created:
        db.add(Tenant(id=tenant_id, slug=slug, name=name, kind=kind))

    if created:
        await db.commit()
        logger.info("tenants bootstrapped", extra={"slugs": [row[1] for row in created]})


async def account_count(db: AsyncSession) -> int:
    result = await db.execute(select(func.count()).select_from(Account))
    return int(result.scalar_one())


async def create_account(
    db: AsyncSession,
    *,
    email: str,
    display_name: str,
    password: str,
    roles: Iterable[str] = ("admin",),
) -> tuple[Account, AuthIdentity]:
    now = datetime.now(timezone.utc)
    account = Account(
        email=email.strip().lower(),
        display_name=display_name.strip(),
        status="active",
        created_at=now,
        updated_at=now,
    )
    db.add(account)
    await db.flush()

    # subject is the account id for local identities: there's no external issuer to
    # take it from, and it must stay stable if the email changes.
    identity = AuthIdentity(
        account_id=account.id,
        provider="local",
        subject=account.id,
        secret_hash=hash_password(password),
        password_changed_at=now,
    )
    db.add(identity)
    for role in dict.fromkeys(roles):  # de-duplicated, order preserved
        db.add(AccountRole(account_id=account.id, role=role, source="manual"))
    await db.flush()
    return account, identity


async def bootstrap_accounts(db: AsyncSession) -> None:
    """Decide how the first admin gets created, once per boot.

    Three outcomes: accounts already exist and nothing happens; env vars provision an
    admin non-interactively; or a claim token is minted and logged for the first-run
    wizard.
    """
    global _claim_token

    if await account_count(db) > 0:
        _claim_token = None
        return

    if settings.initial_admin_email and settings.initial_admin_password:
        account, _ = await create_account(
            db,
            email=settings.initial_admin_email,
            display_name=settings.initial_admin_email.split("@")[0],
            password=settings.initial_admin_password,
        )
        await db.commit()
        _claim_token = None
        # This path returns before the claim token below is ever minted, so the setup
        # wizard — the only place community data sharing is offered — never renders on
        # it. Nothing here writes a consent row on purpose: the absent row already
        # means "off" (models.schema.DataSharingSettings.tier), and an install that
        # nobody asked must not share. Said out loud in the log because this is the
        # documented path for pods, scripts and MSP fleets, and the operator reading
        # this line is the one who would otherwise never learn sharing exists.
        logger.info(
            "initial admin created from environment; community data sharing is off "
            "until an administrator opts in under Settings → Data Sharing",
            extra={"account_id": account.id, "email": account.email},
        )
        return

    _claim_token = secrets.token_urlsafe(24)
    # Logged, not returned over HTTP: whoever can read the container logs is the
    # person entitled to claim the instance. Without this gate, the first stranger to
    # reach the port during a deploy becomes the administrator.
    logger.warning(
        "no accounts exist — first-run setup required. Open the app and enter this "
        "claim token to create the first administrator: %s",
        _claim_token,
    )


async def migrate_legacy_siem_webhook(db: AsyncSession) -> None:
    """One-time migration for anyone with SIEM_WEBHOOK_URL already configured before
    the destinations model existed.

    Runs every boot but is a no-op the moment any destination exists — including one
    a user creates or deletes by hand afterward — so it can never fight with, resurrect,
    or duplicate something the operator has since changed.
    """
    if not settings.siem_webhook_url:
        return

    existing = await db.scalar(select(func.count()).select_from(Destination))
    if existing:
        return

    db.add(
        Destination(
            name="Legacy SIEM webhook",
            type="generic_webhook",
            url=settings.siem_webhook_url,
            auth_type="none",
            enabled=True,
            subscribed_events=None,
        )
    )
    await db.commit()
    logger.info("migrated SIEM_WEBHOOK_URL into a destination row")


def consume_claim_token() -> None:
    """Called after a successful claim so the token can't be replayed."""
    global _claim_token
    _claim_token = None
