from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.models.schema import Account, AccountRole, AuthIdentity

logger = logging.getLogger(__name__)

# Regenerated on every boot and never persisted. A restart mid-setup invalidates the
# old token, which is the correct behaviour: the claim window should be tied to the
# running process, not left recoverable from disk.
_claim_token: str | None = None


def get_claim_token() -> str | None:
    return _claim_token


async def account_count(db: AsyncSession) -> int:
    result = await db.execute(select(func.count()).select_from(Account))
    return int(result.scalar_one())


async def create_account(
    db: AsyncSession,
    *,
    email: str,
    display_name: str,
    password: str,
    role: str = "admin",
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
        logger.info(
            "initial admin created from environment",
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


def consume_claim_token() -> None:
    """Called after a successful claim so the token can't be replayed."""
    global _claim_token
    _claim_token = None
