from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mdm_provider: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    serial_number: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str] = mapped_column(String(255))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    apps: Mapped[list["InstalledApp"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class InstalledApp(Base):
    __tablename__ = "installed_apps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(255))
    bundle_id: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(64))
    full_hash: Mapped[str] = mapped_column(String(32), index=True)

    device: Mapped[Device] = relationship(back_populates="apps")


class MdmSyncState(Base):
    __tablename__ = "mdm_sync_state"

    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="idle")
    device_count: Mapped[int] = mapped_column(Integer, default=0)
