from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class MdmProvider(str, Enum):
    # Jamf only, deliberately (#79). The enum, the `provider` column, and the
    # credential-schema registry are the seam a second provider plugs into; the seam
    # stays, the stub implementations behind it did not survive to launch.
    jamf = "jamf"


class SyncStatus(str, Enum):
    idle = "idle"
    syncing = "syncing"
    failed = "failed"


class NormalizedApp(BaseModel):
    name: str
    bundle_id: str
    version: str
    # CFBundleVersion vs CFBundleShortVersionString. Jamf's inventory API exposes only
    # one version field, so this is null for recon and manual syncs and populated only
    # where the source carries both.
    short_version: str | None = None

    # Populated by process_sync, not by the MDM clients — every ingest path funnels
    # through there, so hashing happens in exactly one place.
    app_hash: str | None = None
    version_hash: str | None = None
    key_title: str | None = None
    key_full: str | None = None


class NormalizedExtensionAttribute(BaseModel):
    key: str
    value: str | None = None


class NormalizedDevice(BaseModel):
    mdm_provider: MdmProvider
    external_id: str
    serial_number: str
    hostname: str
    managed: bool | None = None
    supervised: bool | None = None
    os_version: str | None = None
    site: str | None = None
    # Jamf's own ids for the two objects the device names by id and never by name; the
    # names are resolved at read time from `jamf_org_units` (app.mdm.org_units).
    building_id: str | None = None
    department_id: str | None = None
    last_check_in: datetime | None = None
    last_inventory_at: datetime | None = None
    # None means the applications section was not part of the read's aperture; [] means
    # it was read and the device genuinely has no apps. The two must never collapse:
    # process_sync wipes app rows on [], and a scoped webhook read must not wipe (#93).
    apps: list[NormalizedApp] | None = []
    # Same sentinel as apps: None when extension_attributes was outside the aperture,
    # [] when it was read and the device genuinely has none (#98).
    extension_attributes: list[NormalizedExtensionAttribute] | None = []
    # The read aperture this view was normalized under, as contract section names —
    # stamped by normalize_computer from the same `sections` the ledger canonicalized.
    # None means an aperture-less constructor (tests, fixtures) and reads as everything.
    sections: frozenset[str] | None = None

    def observed(self, section: str) -> bool:
        """Was this section part of the read that produced this view? The scalar-write
        gate in process_sync: a field outside the aperture holds a default, not an
        observation, and must not overwrite current state (#98)."""
        return self.sections is None or section in self.sections


class MdmSyncStatusOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    # Without this the UI can't tell which connection a status row belongs to, which
    # makes per-connection sync state unrenderable.
    mdm_connection_id: int
    provider: MdmProvider
    last_sync_at: datetime | None
    status: SyncStatus
    device_count: int


class InventoryChangedEvent(BaseModel):
    event: str = "device.inventory.changed"
    provider: MdmProvider
    device_external_id: str
    added_apps: list[NormalizedApp]
    removed_apps: list[NormalizedApp]
    occurred_at: datetime

    # The meta block: the run's identity (jobId, trigger, comparison, shortDate) plus the
    # device's serial, so events split apart at a destination can still be correlated back
    # to the one pull that produced them (docs/splunk-event-shaping.md). Small and fixed
    # for now — it is duplicated onto every sub-event a Splunk destination expands this
    # into, so anything added here multiplies by the device's app count.
    meta: dict = Field(default_factory=dict)
