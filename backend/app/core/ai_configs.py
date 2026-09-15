"""Saved AI provider configs: what Save on a Settings > AI card keeps (ruled by Kyle,
2026-09-14), so a feature a viewer can use — the Changes Prompt bar first — can call the
endpoint without the admin's browser in the loop.

One row per provider per tenant. The key is encrypted at rest like a Jamf client secret
(``EncryptedString``) and is write-only above this module. Listing and saving never
decrypt it: whether a key is stored is a NULL test in SQL, and a save writes a new key or
leaves the stored one where it is. Only a caller about to send the key loads the whole
row (``get_config``, ``first_config``). So a wrong ENCRYPTION_KEY breaks only the call
that needs the key, and re-entering the key on the card is still a way out.

Nothing here judges a URL or asks the AI gate; the routes do both, in the order
``app.api.ai`` sets out. This module only reads and writes the rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import case, delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.providers import Provider
from app.models.schema import AIProviderConfig

# The order the cards are shown in, and the order a feature falls back through when it
# is not told which provider to use: the on-device model first.
PROVIDER_ORDER: tuple[Provider, ...] = (Provider.apple_fm, Provider.openai_compatible, Provider.anthropic)

_ORDERED = case(
    {provider.value: rank for rank, provider in enumerate(PROVIDER_ORDER)},
    value=AIProviderConfig.provider,
    else_=len(PROVIDER_ORDER),
)


@dataclass(frozen=True)
class SavedConfig:
    """A saved config as any page may see it: everything but the key, and whether one is
    stored."""

    provider: str
    host_reach: str | None
    base_url: str
    model: str
    reasoning_effort: str | None
    has_key: bool
    updated_at: datetime | None
    updated_by: str | None


# The columns of a `SavedConfig`, in its field order. The key is tested, never selected.
_SAVED_COLUMNS = (
    AIProviderConfig.provider,
    AIProviderConfig.host_reach,
    AIProviderConfig.base_url,
    AIProviderConfig.model,
    AIProviderConfig.reasoning_effort,
    AIProviderConfig.api_key_encrypted.is_not(None),
    AIProviderConfig.updated_at,
    AIProviderConfig.updated_by,
)


async def list_configs(db: AsyncSession) -> list[SavedConfig]:
    """Every saved config, in ``PROVIDER_ORDER``."""
    rows = (await db.execute(select(*_SAVED_COLUMNS).order_by(_ORDERED))).all()
    return [SavedConfig(*row) for row in rows]


async def saved_config(db: AsyncSession, provider: Provider) -> SavedConfig | None:
    row = (await db.execute(select(*_SAVED_COLUMNS).where(AIProviderConfig.provider == provider.value))).one_or_none()
    return SavedConfig(*row) if row is not None else None


async def get_config(db: AsyncSession, provider: Provider) -> AIProviderConfig | None:
    """The whole row, key decrypted — for a caller about to send it."""
    return (await db.execute(select(AIProviderConfig).where(AIProviderConfig.provider == provider.value))).scalar_one_or_none()


async def first_config(db: AsyncSession) -> AIProviderConfig | None:
    """The saved config a feature uses when it is not told which: the first in
    ``PROVIDER_ORDER``, key decrypted."""
    return (await db.execute(select(AIProviderConfig).order_by(_ORDERED).limit(1))).scalar_one_or_none()


def keeps_key(stored: bool, api_key: str | None, clear_key: bool) -> bool:
    """Whether the row holds a key after a save. A new key replaces whatever was stored;
    with none sent, ``clear_key`` removes the stored one and its absence keeps it. The
    browser never holds the stored key, so "no key sent" has to mean "no change"."""
    return bool(api_key) or (stored and not clear_key)


async def save_config(
    db: AsyncSession,
    provider: Provider,
    *,
    host_reach: str | None,
    base_url: str,
    model: str,
    reasoning_effort: str | None,
    api_key: str | None,
    clear_key: bool,
    updated_by: str | None,
) -> SavedConfig:
    """Create or replace the provider's row, in one statement. The key follows
    ``keeps_key``: written when sent, NULLed when cleared, and otherwise not in the
    statement at all — so the stored one is neither read nor rewritten."""
    values: dict[str, object] = {
        "provider": provider.value,
        "host_reach": host_reach,
        "base_url": base_url,
        "model": model,
        "reasoning_effort": reasoning_effort,
        # Stamped on every Save, changed or not: the card says when an admin last stood
        # behind these settings, which a no-op save still is.
        "updated_at": datetime.now(UTC),
        "updated_by": updated_by,
    }
    if api_key:
        values["api_key_encrypted"] = api_key
    elif clear_key:
        values["api_key_encrypted"] = None
    statement = pg_insert(AIProviderConfig).values(**values)
    statement = statement.on_conflict_do_update(
        constraint="uq_ai_provider_configs_tenant_provider",
        set_={name: statement.excluded[name] for name in values if name != "provider"},
    ).returning(*_SAVED_COLUMNS)
    row = (await db.execute(statement)).one()
    await db.commit()
    return SavedConfig(*row)


async def delete_config(db: AsyncSession, provider: Provider) -> bool:
    """Remove the provider's row. False when there was none."""
    result = await db.execute(delete(AIProviderConfig).where(AIProviderConfig.provider == provider.value))
    await db.commit()
    return bool(result.rowcount)
