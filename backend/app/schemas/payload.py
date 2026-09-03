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


# The wire's own version, bumped only on a BREAKING change to delivered events —
# additive changes never touch it (#188). Deliberately not `contract.CONTRACT_VERSION`,
# which versions canonicalization, the allowlist and the aperture: those two move for
# unrelated reasons, and conflating them means every digest change would look like a
# wire break to a customer's dashboards, and vice versa.
WIRE_SCHEMA_VERSION = "v0"


class NormalizedApp(BaseModel):
    """An installed app, internally snake_case and camelCase on the wire (#188).

    `bundleId` keeps Jamf's own spelling rather than taking the `ID` uppercasing ruled
    for LoonInspect-minted keys (#188, this round): the casing law leaves a vendor's
    native keys exactly as the vendor writes them, and Jamf writes `bundleId`. Every
    other alias here names a field LoonInspect invented, so those follow the house rule.
    """

    name: str
    bundle_id: str = Field(serialization_alias="bundleId")
    version: str
    # CFBundleVersion vs CFBundleShortVersionString. Jamf's inventory API exposes only
    # one version field, so this is null for recon and manual syncs and populated only
    # where the source carries both.
    short_version: str | None = Field(default=None, serialization_alias="shortVersion")

    # Populated by process_sync, not by the MDM clients — every ingest path funnels
    # through there, so hashing happens in exactly one place.
    app_hash: str | None = Field(default=None, serialization_alias="appHash")
    version_hash: str | None = Field(default=None, serialization_alias="versionHash")
    key_title: str | None = Field(default=None, serialization_alias="keyTitle")
    key_full: str | None = Field(default=None, serialization_alias="keyFull")


class NormalizedExtensionAttribute(BaseModel):
    """One extension attribute as the device reports it: Jamf's object under Jamf's keys,
    plus `source` (#197).

    Keyed by `definitionId` — the identity the observation contract and the change log
    already use — with `name` as its label, so an admin renaming an EA in Jamf changes a
    label on the wire and never the key a dashboard groups by. `values` is the whole
    list: a multi-value EA (an LDAP attribute, a pop-up menu) reports every element, as
    the ledger has always hashed it. `enabled` rides verbatim rather than filtering: a
    definition an admin disabled still holds whatever value Jamf reports for the device,
    hiding it would be the silent drop this model exists to end, and the flag is there so
    a consumer can tell a live value from a frozen one.

    `source` is the one key LoonInspect mints on this object — the Jamf response key the
    array was found under: `extensionAttributes` for the top-level array, else the
    display section (`general`, `hardware`, `operatingSystem`, `userAndLocation`,
    `purchasing`). The contract discards it on purpose, so that moving an EA between
    display sections changes nothing in the ledger; the wire carries it because an
    analyst wants to know where the admin put it. Both are right and neither is to be
    "fixed" to match the other (docs/jamf-observations.md §7). Corollary: a move changes
    the wire event and no span, so `source` is excluded from anything that derives a
    change.

    Jamf's own keys keep Jamf's spelling on the wire — `definitionId`, `multiValue`,
    `dataType`, `inputType` — because the casing law leaves a vendor's native keys alone
    (#188); the aliases are serialization-only, like NormalizedApp's.
    """

    definition_id: str = Field(serialization_alias="definitionId")
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    multi_value: bool | None = Field(default=None, serialization_alias="multiValue")
    values: list[str] = Field(default_factory=list)
    data_type: str | None = Field(default=None, serialization_alias="dataType")
    options: list[str] = Field(default_factory=list)
    input_type: str | None = Field(default=None, serialization_alias="inputType")
    source: str


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
    """One device's inventory delta, as it goes out on the wire.

    camelCase throughout, with the token `ID` uppercased on LoonInspect-minted keys —
    both ruled in #188. The aliases are serialization-only, so the Python side stays
    snake_case and only `model_dump(by_alias=True)` at the enqueue seam
    (app.mdm.service.process_sync) sees the wire spelling. That single seam is the whole
    reason the rename is safe: nothing else serializes this model.
    """

    event: str = "device.inventory.changed"

    # The run, at the event root as well as inside `deviceMeta` — ruled on #220,
    # 2026-09-02, option 1 of four. Duplicated on purpose: `deviceMeta.jobID` is a name a
    # customer's SPL may already carry and SPL fails silently on an unknown field, so it
    # stays; the root copy is what makes the cross-family join the bare `jobID=$id$`
    # docs/runs.md promises, instead of the two-term `jobID=$id$ OR deviceMeta.jobID=$id$`
    # it had to caveat. Additive under clause 1 (app.core.wire_vocabulary), and a
    # duplicate-on-purpose is not new here: `host` rides in both the envelope and the
    # body on the same reasoning (app.core.outbox).
    #
    # The cost is ~47 bytes on the most-multiplied event on the wire once the fan-out
    # lands (#242) — that is the whole argument the other three options made, and it was
    # ruled against because a join every consumer writes twice, or writes once and
    # silently under-reports on the highest-volume family, is the more expensive mistake.
    #
    # Absent rather than null when there is no run, mirroring the null-dropping rule
    # `deviceMeta` already follows (#189, and clause 3 blesses it): a run is present on
    # both the sweep and the webhook paths, so this is a defensive branch, and a null
    # here would pay the bytes on every sub-event to say nothing. Set from the meta block
    # itself in app.mdm.service.process_sync, so the two copies cannot disagree.
    job_id: str | None = Field(default=None, serialization_alias="jobID")

    provider: MdmProvider
    device_external_id: str = Field(serialization_alias="deviceExternalID")
    added_apps: list[NormalizedApp] = Field(serialization_alias="addedApps")
    removed_apps: list[NormalizedApp] = Field(serialization_alias="removedApps")
    occurred_at: datetime = Field(serialization_alias="occurredAt")

    # The device meta block (#189): the keys stamped onto every sub-event a device
    # produces, so events split apart at a destination still correlate back to the one
    # pull that produced them. Built by app.mdm.service._device_meta at enqueue time —
    # never at delivery, where the run ContextVar is already gone.
    #
    # It is the most expensive object in the schema: measured against a captured tenant
    # record it is over half the raw feed, because it is written once per app, per EA,
    # per certificate, per profile — not once per device. Keys are capped at thirteen
    # and adding one is permanent, so anything proposed here goes through #189 first.
    device_meta: dict = Field(default_factory=dict, serialization_alias="deviceMeta")
