from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.crypto import EncryptedString
from app.core.database import Base
from app.core.tenancy import TENANT_GUC


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


def tenant_id_column(**kwargs) -> Mapped[uuid.UUID]:
    """The owning tenant, on every table that holds customer data.

    Never written by application code, and deliberately given no Python-side default:
    the column default reads the per-transaction `looninspect.tenant_id` GUC that
    app.core.database binds from the request or job context, and each table's RLS
    policy re-checks the result on write. A tenant the database stamps from the
    session it was bound to cannot be forgotten at a call site, cannot be overridden
    by a request body, and does not need threading through a service signature — which
    is what makes "injected via context object, never inferred" hold all the way down
    to storage rather than only at the API edge.
    """
    return mapped_column(
        Uuid,
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        server_default=text(f"current_setting('{TENANT_GUC}')::uuid"),
        **kwargs,
    )


class Tenant(Base):
    """An isolation boundary. Two exist from install time — a management-only root and
    one operational child — and everything else in this file belongs to one of them.

    Outside its own tenancy: this is the table that says which tenants exist, so
    scoping it to the tenant asking would make it unreadable. Nothing here is customer
    data; the rows are created at bootstrap and read to resolve a name.
    """

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))

    # root | operational. Kept as data rather than inferred from the id so a second
    # operational tenant is a row insert, not a code change.
    kind: Mapped[str] = mapped_column(String(16), default="operational", index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class MdmConnection(Base):
    __tablename__ = "mdm_connections"
    # Per-tenant rather than global: two tenants both calling their connection
    # "Production" is the normal case, not a conflict.
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_mdm_connection_tenant_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    base_url: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Provider-specific auth (Jamf's client_id/client_secret, SimpleMDM's api_key, etc.) —
    # shape is defined per-provider in app.mdm.credentials, stored as one JSON blob so
    # adding a new provider's auth fields never requires a schema migration.
    credentials_encrypted: Mapped[str | None] = mapped_column(EncryptedString(), nullable=True)
    webhook_secret_encrypted: Mapped[str | None] = mapped_column(EncryptedString(), nullable=True)

    patch_management_provider: Mapped[str] = mapped_column(String(16), default="none")
    loonsecio_license_key_encrypted: Mapped[str | None] = mapped_column(EncryptedString(), nullable=True)
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

    devices: Mapped[list[Device]] = relationship(back_populates="connection")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("mdm_connection_id", "external_id", name="uq_device_connection_external_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
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
    apps: Mapped[list[InstalledApp]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    extension_attributes: Mapped[list[DeviceExtensionAttribute]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class DeviceExtensionAttribute(Base):
    __tablename__ = "device_extension_attributes"
    __table_args__ = (UniqueConstraint("device_id", "key", name="uq_device_extension_attribute_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    key: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)

    device: Mapped[Device] = relationship(back_populates="extension_attributes")


class InstalledApp(Base):
    __tablename__ = "installed_apps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(255))
    bundle_id: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(64))
    short_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # md5(name:bundle_id) — the application, independent of version. Indexed because
    # it's the grouping key behind the Applications page's per-app device counts.
    app_hash: Mapped[str] = mapped_column(String(32), index=True)

    # md5(name:bundle_id:version[:short_version]) — a specific build. Internal only:
    # inventory deltas are computed on it (a version change is a change). Its former
    # wire role belongs to key_full below.
    version_hash: Mapped[str] = mapped_column(String(32), index=True)

    # v1 canonical content keys (app.core.content_keys) — the wire vocabulary for
    # community data sharing and feed lookups (docs/data-sharing.md). Materialized
    # because they are recomputed never and joined on daily: "v1:" + 64 hex chars.
    key_title: Mapped[str] = mapped_column(String(67), index=True)
    key_full: Mapped[str] = mapped_column(String(67), index=True)

    is_compliant: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_available: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_available_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_patch_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    device: Mapped[Device] = relationship(back_populates="apps")


class MdmSyncState(Base):
    __tablename__ = "mdm_sync_state"

    mdm_connection_id: Mapped[int] = mapped_column(ForeignKey("mdm_connections.id"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
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
    # JSONB, not JSON. `requirements` carries the Jamf Patch matching criteria and
    # matching against it is a query — bundle_id above only narrows the candidates.
    # JSON would store the raw text and force every row to be parsed per predicate;
    # JSONB is parsed once on write and is the only one of the two that can be
    # indexed. `patches` follows it because nothing here depends on key order or
    # whitespace being preserved, which is the sole reason to prefer JSON.
    patches: Mapped[list] = mapped_column(JSONB, default=list)
    requirements: Mapped[list] = mapped_column(JSONB, default=list)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class DataSharingSettings(Base):
    """One row per tenant: the community data-sharing consent state
    (docs/data-sharing.md). Created lazily on first access; an absent row means the
    defaults — tier "reveal", no exclusions — which is also what the first-run
    wizard's pre-checked choice writes.
    """

    __tablename__ = "data_sharing_settings"

    tenant_id: Mapped[uuid.UUID] = tenant_id_column(primary_key=True)

    # off | keys | reveal — app.schemas.system.SharingTier is the source of truth.
    tier: Mapped[str] = mapped_column(String(16), default="reveal")

    # The pseudonymous dedup identity on the wire. Per tenant, not per instance, so
    # the server cannot tell which tenants co-reside on one box; resettable because
    # the disclosure page promises it is.
    submission_uuid: Mapped[uuid.UUID] = mapped_column(Uuid, default=uuid.uuid4)

    # Operator's own filter, ahead of any server-side rule: bundle_id globs whose
    # tuples never enter a snapshot at all (e.g. "com.acme.*").
    exclude_globs: Mapped[list] = mapped_column(JSONB, default=list)

    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Title keys the server asked to have revealed, carried to the NEXT exchange —
    # the reveal-lag the contract specifies. Only ever populated on the reveal tier.
    pending_reveal_keys: Mapped[list] = mapped_column(JSONB, default=list)


class ShareLog(Base):
    """One row per exchange attempt: exactly what left the box, verbatim
    (docs/data-sharing.md). Plain JSONB and not EncryptedString on purpose — the
    payload has already left; the log's whole value is that it is inspectable, and
    pretending it is secret would be theater. Pruned past 90 days on write."""

    __tablename__ = "share_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    tier: Mapped[str] = mapped_column(String(16))
    endpoint: Mapped[str] = mapped_column(String(255))
    # sent | failed | skipped_env
    outcome: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    reveal_requests: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class FeatureFlag(Base):
    """Admin overrides for features that are otherwise gated behind normal business
    conditions (e.g. a connection's capability flags). A flag being on here forces
    the feature visible regardless of that underlying condition."""

    __tablename__ = "feature_flags"

    # Part of the primary key rather than a plain column: a flag is a per-tenant
    # override, so the same key has to be able to hold a different value in each.
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(primary_key=True)
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
    # Identity is scoped to the tenant, not global to the deployment. #30 leaves this
    # open; per-tenant is the answer that does not create a cross-tenant oracle — a
    # global unique index rejects a signup with an email already used in *another*
    # tenant, and that rejection is itself a disclosure no RLS policy can take back.
    # The cost is that one human administering two tenants holds two accounts, which
    # is the correct shape anyway while roles are granted per tenant.
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_account_tenant_email"),
        UniqueConstraint("tenant_id", "username", name="uq_account_tenant_username"),
        UniqueConstraint(
            "tenant_id", "external_source", "external_id", name="uq_account_external_identity"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)

    # SCIM's required unique login identifier. Usually the email, but an IdP can map it
    # to samAccountName or a UPN, so it can't be assumed equal. Unused until SCIM lands;
    # carried now because backfilling it after duplicate accounts appear is far worse.
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

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

    identities: Mapped[list[AuthIdentity]] = relationship(
        back_populates="account", cascade="all, delete-orphan", lazy="selectin"
    )
    roles: Mapped[list[AccountRole]] = relationship(
        back_populates="account", cascade="all, delete-orphan", lazy="selectin"
    )


class AuthIdentity(Base):
    """One way an account can authenticate.

    Only `local` rows exist today. An OIDC row joins the same account later with no
    change to Account itself — keyed on (provider, subject) rather than email, because
    IdPs rewrite emails and matching on one is an account-takeover path.
    """

    __tablename__ = "auth_identities"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "provider", "subject", name="uq_auth_identity_provider_subject"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
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
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
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
    # Which tenant this session acts for. #30 resolves it at authentication from the
    # account; until then it is the deployment's single operational tenant, and it is
    # already stored here so that change is a write at login rather than a migration.
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    # sha256 of the cookie value. The raw token is never stored, so a database leak
    # doesn't hand over live sessions. Unique across the deployment rather than per
    # tenant: a collision between two tenants' tokens is a collision, not a namespace.
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
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))

    # sha256 of the secret half. Fast on purpose, unlike a password: the secret is 256
    # bits of CSPRNG output with nothing to brute-force, and it's verified on every
    # single request — argon2 here would be a self-inflicted denial of service.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # Empty means "inherit whatever the owner currently has". A non-empty list narrows
    # that set — it can never widen it, since the two are intersected at auth time.
    scopes: Mapped[list] = mapped_column(JSONB, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Destination(Base):
    """Where processed events get delivered — a SIEM, a customer-run webhook receiver,
    or an ingestion endpoint in front of a warehouse like Snowflake. Deliberately one
    flexible type rather than a menu of named vendor integrations: from here it is
    always an HTTPS POST, and vendor differences live almost entirely in the auth
    header, which `auth_type` covers. Splunk gets its own `type` because HEC has a
    fixed envelope shape, not because its transport is actually different.
    """

    __tablename__ = "destinations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    name: Mapped[str] = mapped_column(String(255))
    # "generic_webhook" | "splunk_hec"
    type: Mapped[str] = mapped_column(String(32), default="generic_webhook")
    url: Mapped[str] = mapped_column(String(1024))

    # none | bearer | header | splunk_hec. "header" covers anything behind an API
    # gateway or a vendor's own REST ingestion (e.g. Snowpipe) that expects its own
    # named header rather than a standard Authorization convention.
    auth_type: Mapped[str] = mapped_column(String(16), default="none")
    auth_header_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_secret_encrypted: Mapped[str | None] = mapped_column(EncryptedString(), nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Event types this destination receives. Null/empty means all — the default, and
    # what makes the legacy SIEM_WEBHOOK_URL migration behave identically to today
    # (that env var currently receives every event, unfiltered).
    subscribed_events: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class EventOutbox(Base):
    """One row per event produced anywhere in the app — inventory deltas today, group
    membership changes and enrichment results later. Written in the same transaction
    as the state change that produced it, so 'we updated the database' and 'we queued
    the event' can never drift apart from a partial failure mid-request.

    Destination-agnostic by design. Producers (process_sync, and later group sync and
    the inbound webhook handler) only record that something happened; they don't need
    to know which destinations exist or care if that set changes later. Fan-out to
    specific destinations happens in the delivery worker, on its own schedule — which
    is what lets a slow or down destination be handled without ever blocking whatever
    produced the event.
    """

    __tablename__ = "event_outbox"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    # Ties a delivery back to the request or job that produced it, for tracing through
    # the application log.
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Set once OutboxDelivery rows exist for this event. Lets the worker find only new
    # events instead of re-scanning ones it has already fanned out.
    fanned_out: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class OutboxDelivery(Base):
    """Delivery state of one event to one destination.

    Split from EventOutbox because one event fanning out to three destinations needs
    three independent retry histories — a dead destination must never block or get
    conflated with a healthy one's delivery.
    """

    __tablename__ = "outbox_deliveries"
    __table_args__ = (
        UniqueConstraint("outbox_event_id", "destination_id", name="uq_outbox_delivery_event_destination"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    outbox_event_id: Mapped[int] = mapped_column(ForeignKey("event_outbox.id"), index=True)
    destination_id: Mapped[int] = mapped_column(ForeignKey("destinations.id"), index=True)

    # pending | delivered | failed (failed = exhausted retries, dead-lettered)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    last_attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class LoginAttempt(Base):
    """Failed-login counter backing the lockout in the login route.

    In the database rather than in process memory so it survives a restart — otherwise
    `docker compose restart` is a lockout bypass.
    """

    __tablename__ = "login_attempts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "identifier", "ip", name="uq_login_attempt_identifier_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    identifier: Mapped[str] = mapped_column(String(320), index=True)  # lowercased email
    ip: Mapped[str] = mapped_column(String(64))

    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    last_failure_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --- The observation ledger ---------------------------------------------------------
#
# What the Jamf connector writes beneath `devices` / `installed_apps`: a versioned,
# content-addressed record of what each subject looked like each time it was observed.
# Shape and rules are in docs/jamf-observations.md; the normalization that produces the
# digests is app.mdm.jamf.contract. Four tables, top to bottom:
#
#   observation_spans      one row per run of identical observations of one subject
#   observation_sections   one row per distinct section content (by digest)
#   observation_entries    one row per distinct entry (by digest), shared fleet-wide
#   observation_apertures  one row per distinct "how we looked" (by digest)
#
# Content rows are immutable and never deleted in v0 — a span references them by digest,
# and the digest is the contract, so a compaction job later must keep anything a span
# still names. Everything is tenant-scoped and under RLS like the rest of the schema.


class ObservationSpan(Base):
    """A run of consecutive observations of one subject with identical content.

    A new row is written only when the head digest changes — a section's content, or
    the aperture it was taken through. An observation that matches the current span
    bumps its `last_observed_at` and `observation_count` instead. That makes storage
    proportional to change rate rather than sweep count, and makes "sustained for k
    observations" a column rather than a query.

    The subject is (connection, kind, id): for computers the Jamf computer id, which is
    also `devices.external_id` on the same connection — the join the UI uses — and for
    smart groups the group id. udid / serial / management id are carried because lineage
    is the triple (collector, UDID, serial): a logic-board repair keeps the serial and
    changes the UDID, so neither hardware key alone identifies a Mac over its life.

    Time is kept twice on purpose. `observed_at` is the device's own inventory time
    (Jamf's reportDate) and is what the monotonic guard compares, so a sweep reading a
    stale copy after a webhook wrote a fresh one cannot roll the record back.
    `collected_at` is our clock. Groups carry no device time, so both are ours.
    """

    __tablename__ = "observation_spans"
    __table_args__ = (
        Index(
            "ix_observation_spans_subject",
            "tenant_id", "mdm_connection_id", "subject_kind", "subject_id",
        ),
        # The "current" pointer, enforced: at most one open span per subject. Acquisition
        # is the insert, so two writers racing on one subject cannot both win.
        Index(
            "uq_observation_spans_current_subject",
            "mdm_connection_id", "subject_kind", "subject_id",
            unique=True,
            postgresql_where=text("is_current"),
        ),
        # Lineage walks (docs/jamf-observations.md §3): the same Mac across re-enrollment,
        # collectors, or a logic-board repair is found by serial and by UDID.
        Index("ix_observation_spans_serial", "tenant_id", "serial_number", postgresql_where=text("serial_number IS NOT NULL")),
        Index("ix_observation_spans_udid", "tenant_id", "udid", postgresql_where=text("udid IS NOT NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    mdm_connection_id: Mapped[int] = mapped_column(
        ForeignKey("mdm_connections.id", ondelete="CASCADE"), index=True
    )
    subject_kind: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str] = mapped_column(String(255))
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)

    udid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    management_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    contract_version: Mapped[str] = mapped_column(String(8))
    aperture_digest: Mapped[str] = mapped_column(String(67))
    head_digest: Mapped[str] = mapped_column(String(67), index=True)
    # {section name: section digest}. GIN-indexed so "every subject whose applications
    # section is X" is an index lookup — the second hop of the inverted index.
    section_digests: Mapped[dict] = mapped_column(JSONB)

    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    last_trigger: Mapped[str] = mapped_column(String(16))

    previous_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("observation_spans.id", ondelete="SET NULL"), nullable=True
    )
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)


class ObservationSection(Base):
    """The content behind one section digest. Scalar sections store the canonical
    document; list sections store the sorted array of entry digests, which is exactly
    what was hashed, so the digest can be re-verified from the row alone."""

    __tablename__ = "observation_sections"
    __table_args__ = (UniqueConstraint("tenant_id", "digest", name="uq_observation_section_digest"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    digest: Mapped[str] = mapped_column(String(67), index=True)
    section: Mapped[str] = mapped_column(String(32))
    body: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # GIN-indexed: "every section content that contains entry X" is the first hop of
    # Discover, from one entry digest to the spans that carry it.
    entry_digests: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ObservationEntry(Base):
    """One content-addressed item — an application, a certificate, a group membership —
    stored once per tenant however many devices carry it. `label` is the one mutable
    column: a display name the contract deliberately keeps out of the hash (a group or
    EA can be renamed without the device changing), refreshed when a newer one is seen."""

    __tablename__ = "observation_entries"
    __table_args__ = (UniqueConstraint("tenant_id", "digest", name="uq_observation_entry_digest"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    digest: Mapped[str] = mapped_column(String(67), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    body: Mapped[dict] = mapped_column(JSONB)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ObservationAperture(Base):
    """How an observation was taken: collector identity and version, the sections
    requested, Jamf's inventory-collection settings, the EA quarantine. Part of every
    head digest, so a change here opens a new span explicitly rather than surfacing as
    per-section noise across the fleet."""

    __tablename__ = "observation_apertures"
    __table_args__ = (UniqueConstraint("tenant_id", "digest", name="uq_observation_aperture_digest"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    mdm_connection_id: Mapped[int] = mapped_column(
        ForeignKey("mdm_connections.id", ondelete="CASCADE"), index=True
    )
    digest: Mapped[str] = mapped_column(String(67), index=True)
    contract_version: Mapped[str] = mapped_column(String(8))
    document: Mapped[dict] = mapped_column(JSONB)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Collection(Base):
    """What to collect from a connection, and when — docs/ingest-scheduling.md §3, #27.

    A connection carries credentials and capabilities and nothing else; every pull is
    described by a collection that references it: the Splunk modular-input shape (one
    account, N inputs). Three kinds:

      device_sweep  computers-inventory with `sections` and an optional RSQL `selector`
                    pushed into Jamf's query; always ends with a catalog refresh so the
                    group definitions are never older than the memberships that
                    reference them
      catalog       smart-group definitions (with criteria) on their own cadence, so a
                    criteria edit is timestamped finer than the device sweep
      webhook       event-driven: no schedule; its sections and quarantine govern the
                    fetch-by-jssID the webhook endpoint performs

    The schedule is time-of-day + IANA zone + coarse frequency, interpreted by
    app.core.scheduling; `next_due_at` is materialised so the minute tick's due query is
    an index scan rather than timezone arithmetic across every row. The claim is an
    atomic conditional UPDATE of that column, which is what keeps two processes from
    running the same collection twice.
    """

    __tablename__ = "collections"
    __table_args__ = (
        UniqueConstraint("mdm_connection_id", "name", name="uq_collection_connection_name"),
        Index("ix_collections_due", "enabled", "next_due_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    mdm_connection_id: Mapped[int] = mapped_column(
        ForeignKey("mdm_connections.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(16), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # What. Section names are the contract's (app.mdm.jamf.contract.SECTIONS); the
    # aperture records them, so narrowing a collection is an explicit boundary.
    sections: Mapped[list] = mapped_column(JSONB, default=list)
    selector: Mapped[str | None] = mapped_column(Text, nullable=True)
    quarantined_extension_attributes: Mapped[list] = mapped_column(JSONB, default=list)

    # When. Null frequency means event-driven (webhook).
    frequency: Mapped[str | None] = mapped_column(String(16), nullable=True)
    interval_n: Mapped[int | None] = mapped_column(Integer, nullable=True)
    at_hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    at_minute: Mapped[int | None] = mapped_column(Integer, nullable=True)
    weekday: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    next_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Outcome of the last run, per collection — MdmSyncState is per connection and
    # cannot say which collection failed.
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_run_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
