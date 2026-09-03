from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
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


# --- the per-device snapshot (#241) --------------------------------------------------

# The state, beside the delta that says what happened to it. `device.inventory` is what
# a device IS after a pull; `device.inventory.changed` is what HAPPENED to its app list
# (#81 ruling 6's IS/HAPPENED test, applied to the discriminator) — so the delta keeps
# its name and keeps shipping unchanged, and `event=device.inventory*` collects both.
# One per device per pass that clears the ledger's monotonic guard, sweep and webhook
# alike, whether or not anything changed; enqueued by app.mdm.service.process_sync in
# the same transaction as the ledger write and the row updates. The fan-out (#242)
# expands this event and nothing else, so its shape is decided here, where the data is.
INVENTORY_EVENT_TYPE = "device.inventory"

# `vuln.assessment` — docs/vulnerabilities.md §4a. Always present on the app item, and
# `off` is the whole block until the corpus (#248) and the join (#249) land: the
# discriminator is populated from night one so presence is searchable
# (`vuln.assessment=off` extracts to a field; `{}` does not). `unknown_app` is
# snake_case on purpose — values are not governed by the casing law (§4b).
VULN_ASSESSMENT_OFF = "off"
VulnAssessment = Literal["covered", "unknown_app", "off"]


class PatchEnrichment(BaseModel):
    """`patch{}` on the app item — the Jamf Patch answer, at its v0 floor.

    `supported` is a bool and always present, `false` when the app matches no Jamf Patch
    title (Kyle, 2026-09-01: "we need a default for the patching... a boolean ... set that
    equal to false. That way you can always search for it or not it easy"). Computed at
    enqueue from the `installed_apps` row already in the transaction — cache, don't
    calculate — and copied through by the fan-out, never stamped at delivery. What the
    block holds when `true` is ruled (#68, PR #239) and is a follow-on under additive-only
    clause 1; nothing beyond `supported` is minted here.
    """

    supported: bool


class VulnEnrichment(BaseModel):
    """`vuln{}` on the app item, at its v0 floor: `{"assessment": "off"}`.

    Under `off` the block is exactly this — the counts, the days and the id list are
    absent, not zero (docs/vulnerabilities.md §4a). Typed as the ruled closed set so a
    misspelled assessment is refused at enqueue rather than indexed for ever.
    """

    assessment: VulnAssessment = VULN_ASSESSMENT_OFF


class InventoryAppItem(BaseModel):
    """One `app[]` item on the snapshot: Jamf's application object beside LoonInspect's two
    enrichment blocks.

    This is, key for key, the fan-out sub-event's body minus the three keys every
    sub-event carries (`app.core.wire_vocabulary.SUB_EVENT_KEYS`), so #242 iterates rather
    than reshapes, and every shape decision lives on this side of the outbox. It also keeps
    the enrichment keys BESIDE Jamf's object rather than inside it — namespaced, not
    flattened (docs/splunk-wire-vocabulary.md §1) — so Jamf can never add a field that
    collides with `patch`.

    `app` is Jamf's v4 `computers-inventory` application record under Jamf's own key
    names (Kyle, 2026-09-02: "Use Jamf's v4 Names Verbatim in the sections I am copying
    them"), restricted to the ledger's allowlist (`contract._APPLICATION`): `name`,
    `path`, `version`, `cfBundleShortVersionString`, `cfBundleVersion`, `bundleId`,
    `macAppStore` — each absent where Jamf sent nothing. The four minted identity fields
    (`appHash`, `versionHash`, `keyTitle`, `keyFull`) do NOT ride here (Kyle, 2026-09-02:
    "leave them out for now we can add them in the future. We can add keys later but we
    can't take them away"); they keep riding the delta's `addedApps[]` / `removedApps[]`,
    which is not the fan-out. `alert` (#229) is name-only in v0 and writes nothing.

    All three keys are required: a payload whose app item lacks a block is a producer bug
    refused here, at enqueue, not a case the fan-out papers over.
    """

    app: dict
    patch: PatchEnrichment
    vuln: VulnEnrichment


# The snapshot's own keys — everything on the event that is not a section wrapper.
SNAPSHOT_HEAD_KEYS: tuple[str, ...] = ("event", "jobID", "occurredAt", "deviceMeta")


class InventorySnapshotEvent(BaseModel):
    """One device's inventory as Jamf reported it on one pull, under the frozen vocabulary.

    Top level: the head — `event`, `jobID`, `occurredAt`, `deviceMeta` — and then one key
    per section that was inside the read's aperture, spelled exactly as
    `app.core.wire_vocabulary.SECTION_WRAPPERS` spells it (pinned in
    tests/test_inventory_snapshot.py in both directions). The seven scalar sections are
    Jamf's object; the seven list sections are lists of items, each item the fan-out
    sub-event's body minus `SUB_EVENT_KEYS` — `{"cert": {…Jamf…}}`, and for `app`
    `{"app": {…}, "patch": {…}, "vuln": {…}}`.

    Three meanings of absence, all written into docs/runs.md §4:

    * a wrapper ABSENT — the section was outside this read's aperture (the 2026-08-29
      ruling, per section): never assert an absence the read did not observe. A scoped
      webhook read of `["general", "hardware", "operating_system"]` produces three
      wrappers and no `app` key. `None` here means exactly that and is dropped from the
      dump;
    * a wrapper `{}` or `[]` — read, and genuinely empty;
    * a key absent INSIDE a Jamf object — Jamf sent no value: an older server that does
      not report the field, or a null the canonicalizer dropped.

    Every section object is pinned to the v4 `computers-inventory` shape. A field Jamf
    adds reaches the wire when the allowlist admits it — additive under clause 1, never
    automatic; a rename or removal forced by a later major endpoint version is a breaking
    wire change and ships as a `schemaVersion` bump in `deviceMeta` (clause 6), never a
    silent reshape.

    Aliases are the wire spellings, and the model is populated BY those spellings
    (`populate_by_name` keeps the Python names usable too): the producer builds the
    wrappers from the registry and never spells one by hand.
    """

    model_config = ConfigDict(populate_by_name=True)

    event: str = INVENTORY_EVENT_TYPE
    # The run, at the root and inside `deviceMeta`, both — #220's ruling, the same as the
    # delta's. Read off the meta block in the producer so the two copies cannot drift, and
    # absent rather than null when there is no run (`to_payload`).
    job_id: str | None = Field(default=None, alias="jobID")
    # A sweep's snapshots share the run's window; a webhook's carries the device's own
    # reportDate (app.core.runs.event_time). The snapshot and the delta from one pull
    # share this value, the meta block and its `eventID` — by design (#81 ruling 4).
    occurred_at: datetime = Field(alias="occurredAt")
    # #189's block, stamped ONCE, here. Copying it onto every sub-event is the fan-out's
    # job (#242) and the "over half the raw feed" cost is paid there, not here.
    device_meta: dict = Field(default_factory=dict, alias="deviceMeta")

    # The seven one-per-device sections — what #81 called the "device anchor"; under the
    # frozen registry the anchor is one sub-event per scalar section, which is why all
    # seven ride.
    general: dict | None = None
    hardware: dict | None = None
    operating_system: dict | None = Field(default=None, alias="operatingSystem")
    user_and_location: dict | None = Field(default=None, alias="userAndLocation")
    purchasing: dict | None = None
    security: dict | None = None
    disk_encryption: dict | None = Field(default=None, alias="diskEncryption")
    # The seven list sections. `localUserAccount` sits under the registry's "one per
    # device — long" naming comment, but that is the naming rule, not cardinality: the
    # contract's `entry_kind` makes it a list, and the list wins.
    app: list[InventoryAppItem] | None = None
    ea: list[dict] | None = None
    group: list[dict] | None = None
    profile: list[dict] | None = None
    local_user_account: list[dict] | None = Field(default=None, alias="localUserAccount")
    cert: list[dict] | None = None
    update: list[dict] | None = None

    @model_validator(mode="after")
    def _items_are_wrapped(self) -> InventorySnapshotEvent:
        """Every list item carries its section's object under the section's own wrapper
        key and nothing else — the sub-event body minus `SUB_EVENT_KEYS`. `app` is typed
        above; the other six are held to the same shape here so a bare Jamf object can
        never slip into a list the fan-out iterates."""
        for name in ("ea", "group", "profile", "local_user_account", "cert", "update"):
            items = getattr(self, name)
            if items is None:
                continue
            wrapper = type(self).model_fields[name].alias or name
            for item in items:
                if set(item) != {wrapper} or not isinstance(item[wrapper], dict):
                    raise ValueError(f"every {wrapper}[] item must be {{{wrapper!r}: <Jamf's object>}}, got {item!r}")
        return self

    def to_payload(self) -> dict:
        """The stored outbox payload: wire spellings, and the two kinds of `None` dropped
        rather than shipped as null — a wrapper outside the aperture, and a run-less
        `jobID`. Nothing INSIDE a Jamf object is touched: the app object already carries
        no nulls (the canonicalizer dropped them), and the extension-attribute object
        carries Jamf's verbatim, nulls included (#197)."""
        dumped = self.model_dump(mode="json", by_alias=True)
        return {key: value for key, value in dumped.items() if value is not None}
