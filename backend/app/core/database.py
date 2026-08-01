from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session_factory = async_sessionmaker(engine, expire_on_commit=False)

_BACKEND_DIR = Path(__file__).resolve().parents[2]


def _run_migrations() -> None:
    # Alembic's command API is sync and internally does its own asyncio.run() for the
    # async engine, so this must run off the main event loop thread (see init_db()).
    config = Config(str(_BACKEND_DIR / "alembic.ini"))
    command.upgrade(config, "head")


async def init_db() -> None:
    await asyncio.to_thread(_run_migrations)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session
