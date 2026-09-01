from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, Numeric, String, Text, UniqueConstraint, Uuid, text
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

    # Devices per computers-inventory page, defined as the page size *at full
    # sections* — the worst case this connection's collections can ask for, since
    # sections are per collection (#27). Null means the default
    # (app.mdm.jamf.client.DEFAULT_SWEEP_PAGE_SIZE); the limiter is sections, not the
    # API, so an admin fetching many sections turns this down and a narrow collection
    # may override upward (#73).
    sweep_page_size: Mapped[int | None] = mapped_column(Integer, nullable=True)

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
    # Jamf hands the device the department and the building as opaque ids and keeps the
    # names in two catalogs of its own, so the ids are what a device carries. Storing
    # them rather than names is also the rule the ledger follows (docs/jamf-observations.md
    # §2.2): a rename is not a change to any Mac. `jamf_org_units` turns them into names
    # at read time.
    building_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    department_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

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
    # device_id is the primary access path to this table — `process_sync` reads one
    # device's apps twice per device — and it is the largest table in the schema at
    # ~100 rows per device. Without the index that read is a parallel seq scan over
    # every row in the tenant.
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
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

    # The Jamf Patch answer for this build, derived at device process from the catalog
    # (app.mdm.patch.matching): the titles it belongs to, the rolling title's state and latest
    # version, and whether Jamf has listed this version. One row per (app, title) in
    # installed_app_patch_matches carries the detail; is_compliant / patch_available /
    # patch_available_since above are the same answer folded into the older columns.
    # none_as_null: "no titles" is SQL NULL, not a JSON null, so `IS NULL` means what it says.
    jamf_title_ids: Mapped[list | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    patch_state: Mapped[str | None] = mapped_column(String(16), nullable=True)  # latest | behind | ahead | unknown
    this_version_seen: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latest_released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    device: Mapped[Device] = relationship(back_populates="apps")


class MdmSyncState(Base):
    __tablename__ = "mdm_sync_state"

    mdm_connection_id: Mapped[int] = mapped_column(ForeignKey("mdm_connections.id"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="idle")
    device_count: Mapped[int] = mapped_column(Integer, default=0)


class JamfOrgUnit(Base):
    """One Jamf department or building — its id, and the name it currently has.

    Jamf Pro's inventory says a Mac is in department 7; the name lives in
    `/v1/departments`, which no device record ever quotes. This is that lookup, one row
    per object per connection, refreshed by two small catalog reads that ride along with
    every sweep and every catalog refresh. Read once per request and joined in Python
    rather than per device row — the same cache-don't-calculate discipline as
    `app_catalog`, on a table of tens of rows.

    Nothing here is an observation: a name is a label, and renaming a department changes
    nothing about any Mac (docs/jamf-observations.md §2.2). The table can be dropped and
    rebuilt from Jamf without touching a single span, and it holds no history — the
    device row and the ledger hold the id, which is what actually moved when a Mac
    changed departments.

    Deleted with its connection: a name lookup for credentials that no longer exist
    resolves nothing.
    """

    __tablename__ = "jamf_org_units"
    __table_args__ = (
        UniqueConstraint("mdm_connection_id", "kind", "external_id", name="uq_jamf_org_unit"),
        Index("ix_jamf_org_units_name", "tenant_id", "kind", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    mdm_connection_id: Mapped[int] = mapped_column(
        ForeignKey("mdm_connections.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16))  # department | building
    external_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(255))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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
    # The extension-attribute definitions the title ships, key + displayName only (the script
    # is not kept): a requirement names the key, Jamf Pro creates the attribute under the display
    # name. Null marks a row fetched before the column existed; the next sync re-fetches it.
    extension_attributes: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AppCatalogEntry(Base):
    """The tenant app catalog: one row per distinct (name, bundle ID, version[, short version])
    the fleet has shown — keyed by the same `version_hash` every installed app carries — with
    when it was first and last seen on any device, and Jamf's answer for it (which titles, is it
    the latest, has Jamf seen this version, when was it released). Rows are written at device
    process and judged against the patch catalog at first sight and after every catalog sync
    (`evaluated_signature` says which catalog). Devices reach their answer through
    `installed_apps.version_hash`; the columns of the same name on `installed_apps` are copies.
    """

    __tablename__ = "app_catalog"
    __table_args__ = (
        UniqueConstraint("tenant_id", "version_hash", name="uq_app_catalog_version"),
        Index("ix_app_catalog_app", "tenant_id", "app_hash"),
        Index("ix_app_catalog_last_seen", "tenant_id", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    name: Mapped[str] = mapped_column(String(255))
    bundle_id: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(64))
    short_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    app_hash: Mapped[str] = mapped_column(String(32))
    version_hash: Mapped[str] = mapped_column(String(32))
    key_title: Mapped[str] = mapped_column(String(67))
    key_full: Mapped[str] = mapped_column(String(67), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    jamf_title_ids: Mapped[list | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    patch_state: Mapped[str | None] = mapped_column(String(16), nullable=True)  # latest | behind | ahead | unknown
    is_latest: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_available: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_available_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    this_version_seen: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latest_released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Jamf's release date of the installed version itself.
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evaluated_signature: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AppCatalogTitleMatch(Base):
    """One catalog row matched to one Jamf Patch title, with the version answers — replaced
    wholesale each time the row is judged. `basis` is `requirements` (every criterion evaluated
    and met) or `ea_assumed` (an extension attribute was resolved TRUE — Jamf's scoping device,
    not a fact about the app). `state` is latest | behind | ahead | unknown.
    """

    __tablename__ = "app_catalog_title_matches"
    __table_args__ = (
        UniqueConstraint("app_catalog_id", "title_id", name="uq_app_catalog_title_match"),
        Index("ix_app_catalog_title_matches_title", "tenant_id", "title_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    app_catalog_id: Mapped[int] = mapped_column(ForeignKey("app_catalog.id", ondelete="CASCADE"), index=True)
    title_id: Mapped[str] = mapped_column(ForeignKey("jamf_patch_titles.id", ondelete="CASCADE"))
    basis: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(16))
    version_known: Mapped[bool] = mapped_column(Boolean)
    on_latest: Mapped[bool] = mapped_column(Boolean)
    installed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    installed_released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    latest_version: Mapped[str] = mapped_column(String(64))
    latest_released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_newer_released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AppCatalogVersion(Base):
    """Jamf's side of the catalog as a local lookup: one row per title x bundle ID x listed
    version, with the hashes LoonInspect stamps on installed apps precomputed where Jamf names
    the app (`appName`). Global, like `jamf_patch_titles`; rebuilt after each catalog sync.
    """

    __tablename__ = "app_catalog_versions"
    __table_args__ = (Index("ix_app_catalog_versions_bundle_version", "bundle_id", "version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title_id: Mapped[str] = mapped_column(ForeignKey("jamf_patch_titles.id", ondelete="CASCADE"), index=True)
    title_name: Mapped[str] = mapped_column(String(255))
    publisher: Mapped[str | None] = mapped_column(String(255), nullable=True)
    app_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    bundle_id: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(64))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_latest: Mapped[bool] = mapped_column(Boolean, default=False)
    app_hash: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    version_hash: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    key_title: Mapped[str | None] = mapped_column(String(67), nullable=True)
    key_full: Mapped[str | None] = mapped_column(String(67), nullable=True, index=True)


class DataSharingSettings(Base):
    """One row per tenant: the community data-sharing consent state
    (docs/data-sharing.md). Created lazily on first access; an absent row means an
    install nobody has answered for yet.
    """

    __tablename__ = "data_sharing_settings"

    tenant_id: Mapped[uuid.UUID] = tenant_id_column(primary_key=True)

    # off | keys | reveal — app.schemas.system.SharingTier is the source of truth.
    #
    # Default "off", and it used to be "reveal". The wizard's pre-checked box is still
    # "reveal" — it just writes that answer down now (app.api.auth.setup) instead of
    # relying on this default to mean it. The old arrangement made *silence* mean the
    # most permissive tier, and there are two ways to be silent: bootstrap through
    # INITIAL_ADMIN_EMAIL/PASSWORD, which returns before the claim token is minted so
    # the wizard never renders, and a container nobody has signed into at all, whose
    # scheduler still materializes this row on its first exchange tick. Both are
    # installs that were never asked, and both shared. docs/data-sharing.md rests the
    # whole case for a pre-checked default on "every operator affirmatively sees it
    # before the first byte leaves"; the only way that sentence is true is if consent
    # is a thing someone wrote, not a thing we assumed.
    #
    # Rejected: writing an explicit "off" row in bootstrap.py's INITIAL_ADMIN_* branch
    # and leaving this default alone. Narrower, but it fixes one caller rather than the
    # rule, and leaves the next non-interactive path — a management API, a seeding
    # script, #30's per-tenant provisioning — to rediscover the same hole.
    tier: Mapped[str] = mapped_column(String(16), default="off")

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

    # AI-inference consent (INSPECT-0112), deliberately on this row and not a feature
    # flag: the flag turns the AI feature area on, this governs whether any byte may
    # leave the pod for inference — one consent surface, one log. Default off, like
    # everything behind the AI gate (app.core.ai).
    ai_inference: Mapped[bool] = mapped_column(Boolean, default=False)


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
    # The 413 path sheds the reveals and retries, so on those days `payload` is a
    # superset of the body that earned the 200: everything above left the box except
    # the reveals array. Without this marker the row is indistinguishable from an
    # ordinary reveal day, which makes "exactly what left the box" a claim the log
    # cannot support. False on every other row, including failures.
    reveals_shed: Mapped[bool] = mapped_column(Boolean, default=False)
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
    fixed envelope shape, and Elastic because the bulk API has a fixed body shape
    (NDJSON) and its own failure mode — not because their transport is different.
    "runreveal" is a preset over the generic-webhook delivery path: same bare-JSON
    POST, bearer auth, existing so the UI can prefill their ingest URL shape instead
    of making the admin reverse-engineer it.
    """

    __tablename__ = "destinations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    name: Mapped[str] = mapped_column(String(255))
    # "generic_webhook" | "splunk_hec" | "elastic" | "runreveal"
    type: Mapped[str] = mapped_column(String(32), default="generic_webhook")
    url: Mapped[str] = mapped_column(String(1024))

    # none | bearer | header | splunk_hec | elastic_api_key. "header" covers anything
    # behind an API gateway or a vendor's own REST ingestion (e.g. Snowpipe) that
    # expects its own named header rather than a standard Authorization convention.
    auth_type: Mapped[str] = mapped_column(String(16), default="none")
    auth_header_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_secret_encrypted: Mapped[str | None] = mapped_column(EncryptedString(), nullable=True)

    # Elastic only: the index (or data stream) the bulk POST targets. Null means the
    # data-stream-friendly default in app/core/outbox.py — a name, not a URL segment
    # the admin has to remember to append.
    elastic_index: Mapped[str | None] = mapped_column(String(255), nullable=True)

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

    # Set once this event has been considered against the enabled destinations — which
    # is not the same as "a delivery row exists": a destination subscribed to other
    # event types is a considered-and-declined answer, and marks the event too. When no
    # destination is enabled at all there is nothing to consider, so the event stays
    # false and waits for one to be added (see fan_out_pending). Lets the worker find
    # only new events instead of re-scanning ones it has already fanned out.
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
    # Devices per inventory page for this collection only; null inherits the
    # connection's sweep_page_size. Exists because that setting is the full-section
    # worst case, and a narrow collection may take bigger pages (#73).
    page_size: Mapped[int | None] = mapped_column(Integer, nullable=True)

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


# --- The run --------------------------------------------------------------------------


class Run(Base):
    """One pull, as an object — #31, docs/ingest-scheduling.md §4.

    Four contract clauses are the same piece of work: the row **is** the mutex, its id
    **is** the jobID stamped on every event, its window **is** the `_time` anchor for
    scheduled runs, and it is the foreign key the run log is scoped by. Before this, a
    run was a function call with a status string beside it on `mdm_sync_state`, which
    could express none of the four.

    The mutex is the partial unique index below, and acquisition is the INSERT. Two
    requests racing for the same connection both insert; one commits and runs, the other
    takes an integrity error — atomic, unlike the SELECT-then-UPDATE it replaces, where
    both readers saw 'idle' and both started a sweep. The key is
    (tenant_id, mdm_connection_id, lock_class) rather than #31's original (tenant_id):
    the resource being protected is the Jamf server, which is the connection, and a
    fifteen-minute catalog refresh has no reason to wait behind a forty-minute device
    sweep of the same one (§4.1).

    `heartbeat_at` is what keeps the mutex from being a deadlock. A process that dies
    holding a run leaves the row `running` forever, and nothing on that connection can
    sync again — strictly worse than the duplicate load the race caused, because silence
    pages nobody. A run whose heartbeat has gone stale is reclaimed by the next
    acquirer, which is why the blanket "mark every syncing row failed at startup" sweep
    could be deleted: that one was correct for a single process recovering from a crash
    and actively wrong during a rolling restart, where the starting instance failed a
    run another instance was still performing.
    """

    __tablename__ = "runs"
    __table_args__ = (
        # The mutex. Partial, so only live runs contend and history accumulates freely.
        #
        # Webhooks are excluded in the predicate rather than in code. They must ACK fast,
        # a busy tenant fires many, and serializing them behind a forty-minute sweep
        # makes the real-time path useless — so a webhook gets a run (it needs the jobID
        # and the log) but never the lock. Their ordering against a sweep is solved by
        # the ledger's monotonic guard instead, which is independently correct
        # (docs/ingest-scheduling.md §4.4).
        Index(
            "uq_run_active_lock",
            "tenant_id",
            "mdm_connection_id",
            "lock_class",
            unique=True,
            postgresql_where=text("status = 'running' AND lock_class <> 'webhook'"),
        ),
        Index("ix_runs_recent", "tenant_id", "started_at"),
        Index("ix_runs_connection", "tenant_id", "mdm_connection_id", "started_at"),
        # Reclaim scans this: live runs only, oldest heartbeat first.
        Index("ix_runs_heartbeat", "heartbeat_at", postgresql_where=text("status = 'running'")),
    )

    # The jobID. A UUID rather than a sequence because it is emitted on every event and
    # read back as a filter — a customer's Splunk search should not be able to guess a
    # neighbouring run's id, and it is minted before the row is written.
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    mdm_connection_id: Mapped[int] = mapped_column(
        ForeignKey("mdm_connections.id", ondelete="CASCADE"), index=True
    )
    # Which collection this run served, when it served one. Null for the generic
    # (non-Jamf) provider path, which has no collections.
    collection_id: Mapped[int | None] = mapped_column(
        ForeignKey("collections.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # What started this: sweep | manual | webhook. The same vocabulary the ledger stamps
    # on every span as `last_trigger`, deliberately — one word for one concept across the
    # ledger, the run, and the wire. The contract calls the scheduled case "scheduled";
    # this product has always called it "sweep" and the spans already say so.
    trigger: Mapped[str] = mapped_column(String(16), index=True)
    # What kind of comparison this is: baseline | delta. Baseline is the first successful
    # run for this connection and lock class — there is nothing to compare against yet.
    #
    # The contract named these two fields `runtype` and `run_type`, which differ by one
    # underscore and mean unrelated things; a Splunk analyst reading
    # `runtype=manual run_type=delta` cannot tell which is which, against the contract's
    # own "readable English, no abbreviations" rule two lines below. Renamed here while
    # renaming is still free — customer SPL written against the emitted names makes this
    # effectively permanent.
    comparison: Mapped[str] = mapped_column(String(16))
    # The mutex dimension: device_sweep | catalog. Derived from the collection's kind.
    lock_class: Mapped[str] = mapped_column(String(16))

    status: Mapped[str] = mapped_column(String(16), index=True)  # running | succeeded | failed

    # The `_time` anchor. A scheduled run back-dates its events to the occurrence it
    # serves — the time it was *due*, not the time the tick got to it — so a sweep that
    # started four minutes late does not shift every event it produces. Manual and
    # webhook runs anchor on their own start; a webhook's events carry device time
    # regardless, which is what makes "webhooks always land after the run stamp"
    # expressible at all (app.core.runs.event_time).
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    device_count: Mapped[int] = mapped_column(Integer, default=0)
    group_count: Mapped[int] = mapped_column(Integer, default=0)
    # Failure accounting (#92). `device_count` is the devices this run attempted;
    # processed + failed = attempted. A run may finish `succeeded` with failures on the
    # row — isolated device failures inside the tolerance — which is exactly what the
    # UI's "39,998 processed, 2 failed" and the run.completed event surface.
    devices_processed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    devices_failed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    observations: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Who asked. Null for the scheduled tick, which has no requesting account.
    actor_label: Mapped[str | None] = mapped_column(String(255), nullable=True)


class RunLogLine(Base):
    """One engine line, scoped by tenant and run — the contract's "run log queryable in
    Postgres, scoped by tenant and jobID".

    Deliberately not per device: a 40,000-device sweep writes milestones and a progress
    line every few hundred devices, not 40,000 rows. What the run-now panel polls, and
    what someone opens a month later to answer "did this run, and what happened".
    """

    __tablename__ = "run_log"
    __table_args__ = (Index("ix_run_log_run", "run_id", "id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    level: Mapped[str] = mapped_column(String(8))  # info | warning | error
    message: Mapped[str] = mapped_column(String(512))
    fields: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


# --- The change log -------------------------------------------------------------------


class ChangePolicy(Base):
    """One row per tenant: what an admin changed about the default change-log policy
    (app.changes.policy). Stored sparse — only the overrides — so a field the admin never
    touched follows future defaults and an explicit choice persists."""

    __tablename__ = "change_policies"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_change_policy_tenant"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    version: Mapped[str] = mapped_column(String(8))
    overrides: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    updated_by_account_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class DeviceChange(Base):
    """One logged change: a field that moved or an entry that was added, removed, or
    updated between two spans of one subject, after the policy said it matters.

    Derived from the ledger and deletable without loss — the spans hold the truth and a
    re-derivation under a different policy is always possible. Carries the correlation
    key the author dedups on in Splunk (serial, Jamf URL via the connection, Jamf id)
    plus the UDID, and both span ids so any change can be walked back to the evidence.
    """

    __tablename__ = "device_changes"
    __table_args__ = (
        Index("ix_device_changes_recent", "tenant_id", "observed_at"),
        Index("ix_device_changes_subject", "tenant_id", "mdm_connection_id", "subject_kind", "subject_id", "observed_at"),
        Index("ix_device_changes_section", "tenant_id", "section", "observed_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    mdm_connection_id: Mapped[int] = mapped_column(ForeignKey("mdm_connections.id", ondelete="CASCADE"), index=True)
    subject_kind: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str] = mapped_column(String(255))
    subject_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    udid: Mapped[str | None] = mapped_column(String(64), nullable=True)

    span_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("observation_spans.id", ondelete="SET NULL"), nullable=True
    )
    previous_span_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("observation_spans.id", ondelete="SET NULL"), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    trigger: Mapped[str] = mapped_column(String(16))

    section: Mapped[str] = mapped_column(String(32))
    field: Mapped[str | None] = mapped_column(String(128), nullable=True)
    entry_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    entry_identity: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    entry_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    change: Mapped[str] = mapped_column(String(16))  # changed | added | removed | updated
    old_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    level: Mapped[str] = mapped_column(String(8), index=True)
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    policy_version: Mapped[str] = mapped_column(String(8))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


# --- The posture snapshot -------------------------------------------------------------


class PostureSnapshot(Base):
    """One fleet-level number, captured as the last act of a closed full sweep — the
    tape #102 starts at launch, because history not recorded can never be backfilled.

    One row per metric per capture, never a wide row and never a JSON blob: the key
    vocabulary grows by INSERT, and every key's history reads as one indexed scan.
    Definitions are frozen per key in docs/posture-snapshot.md — a definition change
    mints a new key rather than quietly bending an old one's history.

    `full_sweep_run_id` is the run whose close stamped this capture, success and
    failure alike (a failed night's DB state is real, and the failed run id is what
    makes staleness visible). SET NULL on delete because runs are purged after 30 days
    while these rows are the durable history that outlives them.

    `value` is NUMERIC and always present: an absent row means the metric did not
    apply that night (e.g. `outbox.oldest_pending_age_s` with an empty queue), never
    that it was zero — zero is written as 0.
    """

    __tablename__ = "posture_snapshot"
    __table_args__ = (
        # The read shape: one key's history for one tenant, in time order.
        Index("ix_posture_snapshot_series", "tenant_id", "metric_key", "captured_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_id_column(index=True)
    metric_key: Mapped[str] = mapped_column(Text)
    value: Mapped[Decimal] = mapped_column(Numeric)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    full_sweep_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
