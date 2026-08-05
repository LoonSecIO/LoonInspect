from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.crypto import EncryptedString
from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class MdmConnection(Base):
    __tablename__ = "mdm_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    base_url: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Provider-specific auth (Jamf's client_id/client_secret, SimpleMDM's api_key, etc.) —
    # shape is defined per-provider in app.mdm.credentials, stored as one JSON blob so
    # adding a new provider's auth fields never requires a schema migration.
    credentials_encrypted: Mapped[str | None] = mapped_column(EncryptedString(2048), nullable=True)
    webhook_secret_encrypted: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)

    patch_management_provider: Mapped[str] = mapped_column(String(16), default="none")
    loonsecio_license_key_encrypted: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    loonsecio_data_sharing_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    user_agent_override: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # What LoonInspect uses this connection for. Devices/Users are CRUD (LoonInspect
    # creates/updates/deletes its own records from the synced data); callback Webhooks
    # and Jamf Pro (patch reporting) are read-only. Devices defaults on since that's the
    # common case; everything else is opt-in.
    capability_devices: Mapped[bool] = mapped_column(Boolean, default=True)
    capability_users: Mapped[bool] = mapped_column(Boolean, default=False)
    capability_webhooks: Mapped[bool] = mapped_column(Boolean, default=False)
    capability_jamf_pro: Mapped[bool] = mapped_column(Boolean, default=False)

    last_successful_auth_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    credentials_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    credentials_fingerprint: Mapped[str | None] = mapped_column(String(3), nullable=True)

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
    short_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # md5(name:bundle_id) — the application, independent of version. Indexed because
    # it's the grouping key behind the Applications page's per-app device counts.
    app_hash: Mapped[str] = mapped_column(String(32), index=True)

    # md5(name:bundle_id:version[:short_version]) — a specific build, and the lookup
    # key sent to the LoonSec Global API. Also what inventory deltas are computed on:
    # a version change is a change.
    version_hash: Mapped[str] = mapped_column(String(32), index=True)

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


class JamfPatchTitle(Base):
    """A cached title from Jamf's public patch definition catalog (jamf-patch.jamfcloud.com),
    refreshed hourly. Global — not tied to any one MdmConnection since the catalog itself
    carries no tenant credentials or scoping."""

    __tablename__ = "jamf_patch_titles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    publisher: Mapped[str | None] = mapped_column(String(255), nullable=True)
    app_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    bundle_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    current_version: Mapped[str] = mapped_column(String(64))
    last_modified: Mapped[str] = mapped_column(String(64))
    patches: Mapped[list] = mapped_column(JSON, default=list)
    requirements: Mapped[list] = mapped_column(JSON, default=list)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class FeatureFlag(Base):
    """Admin overrides for features that are otherwise gated behind normal business
    conditions (e.g. a connection's capability flags). A flag being on here forces
    the feature visible regardless of that underlying condition."""

    __tablename__ = "feature_flags"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class Account(Base):
    """A LoonInspect operator — someone who signs into this application.

    Deliberately separate from the MDM-synced people on the Users page: those are
    device owners pulled from Jamf, these are the humans administering LoonInspect.
    Conflating the two would mean an MDM sync could create login accounts.

    Carries no credential columns. Authentication material lives in AuthIdentity so
    that an account can hold a password *and* an SSO identity at once — which is
    exactly what a break-glass account needs once SSO enforcement is on.
    """

    __tablename__ = "accounts"
    __table_args__ = (
        UniqueConstraint("external_source", "external_id", name="uq_account_external_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)

    # SCIM's required unique login identifier. Usually the email, but an IdP can map it
    # to samAccountName or a UPN, so it can't be assumed equal. Unused until SCIM lands;
    # carried now because backfilling it after duplicate accounts appear is far worse.
    username: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True, index=True)

    # Keeps local password login even under SSO enforcement. Every authentication by
    # one of these is logged at WARNING so the exemption can't be used quietly.
    is_break_glass: Mapped[bool] = mapped_column(Boolean, default=False)

    # Non-human principals — the future SCIM bearer token's owner, CI, the macOS app.
    # Never authenticate interactively and are never IdP-managed, so an IdP can't
    # deprovision the credential it uses to talk to us.
    is_service_account: Mapped[bool] = mapped_column(Boolean, default=False)

    # Set when an external system owns this record's lifecycle, plus that system's own
    # identifier for the user (SCIM `externalId`) — which is not the OIDC `sub`.
    external_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    identities: Mapped[list["AuthIdentity"]] = relationship(
        back_populates="account", cascade="all, delete-orphan", lazy="selectin"
    )
    roles: Mapped[list["AccountRole"]] = relationship(
        back_populates="account", cascade="all, delete-orphan", lazy="selectin"
    )


class AuthIdentity(Base):
    """One way an account can authenticate.

    Only `local` rows exist today. An OIDC row joins the same account later with no
    change to Account itself — keyed on (provider, subject) rather than email, because
    IdPs rewrite emails and matching on one is an account-takeover path.
    """

    __tablename__ = "auth_identities"
    __table_args__ = (UniqueConstraint("provider", "subject", name="uq_auth_identity_provider_subject"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)

    provider: Mapped[str] = mapped_column(String(64), default="local")
    subject: Mapped[str] = mapped_column(String(255))

    # argon2id. Null for non-password providers, which is the whole reason this lives
    # here rather than as a column on Account.
    secret_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    account: Mapped[Account] = relationship(back_populates="identities")


class AccountRole(Base):
    """A role grant, carrying where it came from.

    `source` is what lets a future IdP group sync reconcile only the rows it owns,
    instead of clobbering a manually granted role — including the break-glass admin's.
    Enforcement arrives with RBAC; this phase only records the grant.
    """

    __tablename__ = "account_roles"

    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), primary_key=True, default="manual")

    granted_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    account: Mapped[Account] = relationship(back_populates="roles")


class UserSession(Base):
    """A browser session. Named UserSession to stay clearly distinct from a SQLAlchemy
    session in a codebase where `session` already means the database.

    Opaque and server-side rather than a JWT: revocation has to be immediate (account
    disabled, password changed, admin action), and a JWT denylist is this table with
    extra steps.
    """

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # sha256 of the cookie value. The raw token is never stored, so a database leak
    # doesn't hand over live sessions.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    identity_id: Mapped[str | None] = mapped_column(ForeignKey("auth_identities.id"), nullable=True)
    auth_method: Mapped[str] = mapped_column(String(32), default="password")

    csrf_token: Mapped[str] = mapped_column(String(64))

    # Reserved for OIDC backchannel logout: the IdP reports its own session id, and
    # ending it has to end ours.
    idp_session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Null means the session never idles out — the operator chose an unlimited lifetime.
    # Revocation still applies; only the passive timer is gone.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ApiToken(Base):
    """A personal access token — the non-browser authentication path, for the macOS
    client, CI, and scripts.

    May belong to a service account rather than a person, which is how an automation
    credential avoids dying when its creator leaves.
    """

    __tablename__ = "api_tokens"

    # Doubles as the lookup key embedded in the token string, so verifying a request
    # is a primary-key hit rather than a scan over every token's hash.
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))

    # sha256 of the secret half. Fast on purpose, unlike a password: the secret is 256
    # bits of CSPRNG output with nothing to brute-force, and it's verified on every
    # single request — argon2 here would be a self-inflicted denial of service.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # Empty means "inherit whatever the owner currently has". A non-empty list narrows
    # that set — it can never widen it, since the two are intersected at auth time.
    scopes: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LoginAttempt(Base):
    """Failed-login counter backing the lockout in the login route.

    In the database rather than in process memory so it survives a restart — otherwise
    `docker compose restart` is a lockout bypass.
    """

    __tablename__ = "login_attempts"
    __table_args__ = (UniqueConstraint("identifier", "ip", name="uq_login_attempt_identifier_ip"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identifier: Mapped[str] = mapped_column(String(320), index=True)  # lowercased email
    ip: Mapped[str] = mapped_column(String(64))

    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    last_failure_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
