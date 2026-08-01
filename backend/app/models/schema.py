from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.crypto import EncryptedString
from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MdmConnection(Base):
    __tablename__ = "mdm_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    base_url: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_secret_encrypted: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    api_key_encrypted: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    webhook_secret_encrypted: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)

    patch_management_provider: Mapped[str] = mapped_column(String(16), default="none")
    loonsecio_license_key_encrypted: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    loonsecio_data_sharing_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    devices: Mapped[list["Device"]] = relationship(back_populates="connection")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("mdm_connection_id", "external_id", name="uq_device_connection_external_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mdm_connection_id: Mapped[int | None] = mapped_column(ForeignKey("mdm_connections.id"), index=True)
    mdm_provider: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(255), index=True)
    serial_number: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str] = mapped_column(String(255))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    last_check_in: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_inventory_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    managed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    supervised: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    site: Mapped[str | None] = mapped_column(String(255), nullable=True)
    building: Mapped[str | None] = mapped_column(String(255), nullable=True)
    department: Mapped[str | None] = mapped_column(String(255), nullable=True)

    connection: Mapped[MdmConnection | None] = relationship(back_populates="devices")
    apps: Mapped[list["InstalledApp"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    extension_attributes: Mapped[list["DeviceExtensionAttribute"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class DeviceExtensionAttribute(Base):
    __tablename__ = "device_extension_attributes"
    __table_args__ = (UniqueConstraint("device_id", "key", name="uq_device_extension_attribute_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    key: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)

    device: Mapped[Device] = relationship(back_populates="extension_attributes")


class InstalledApp(Base):
    __tablename__ = "installed_apps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(255))
    bundle_id: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(64))
    full_hash: Mapped[str] = mapped_column(String(32), index=True)

    is_compliant: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_available: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_available_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_patch_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    device: Mapped[Device] = relationship(back_populates="apps")


class MdmSyncState(Base):
    __tablename__ = "mdm_sync_state"

    mdm_connection_id: Mapped[int] = mapped_column(ForeignKey("mdm_connections.id"), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="idle")
    device_count: Mapped[int] = mapped_column(Integer, default=0)
