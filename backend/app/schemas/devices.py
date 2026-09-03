from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, computed_field
from pydantic.alias_generators import to_camel

from app.schemas.payload import MdmProvider, VulnEnrichment


class VersionOperator(str, Enum):
    eq = "eq"
    lt = "lt"
    lte = "lte"
    gt = "gt"
    gte = "gte"
    regex = "regex"


class ExtensionAttributeFilter(BaseModel):
    """One `ea=` query term: `<definition id or name>:<value>`, or the key alone."""

    key: str
    value: str | None = None


class ExtensionAttributeOut(BaseModel):
    """An extension attribute as the device last reported it — keyed by Jamf's definition
    id with the name as its label (#197), so a rename in Jamf changes the label and never
    the identity; `values` is the whole list; `source` is the inventory-display section
    the value was found under; `enabled` is the definition's flag, carried rather than
    filtered on."""

    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    definition_id: str
    name: str | None
    values: list[str]
    source: str
    enabled: bool | None


class InstalledAppOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    id: int
    name: str
    bundle_id: str
    version: str
    short_version: str | None
    app_hash: str
    version_hash: str
    is_compliant: bool | None
    patch_available: bool | None
    patch_available_since: datetime | None
    last_patch_check_at: datetime | None
    # Jamf Patch matching (app.mdm.patch.matching): the titles this build belongs to, the
    # rolling title's state and latest version, and whether Jamf has listed this version.
    jamf_title_ids: list[str] | None = None
    patch_state: str | None = None
    this_version_seen: bool | None = None
    latest_version: str | None = None
    latest_released_at: datetime | None = None
    # #68: the two halves of the sentence a surface leads with — "behind since <date> · <n>
    # releases missed" — are patch_available_since and this count. The day count below stays
    # for consumers that want it; it is derived from an unbounded date and is never the headline.
    releases_missed: int | None = None
    # #251: LoonInspect's own answer about this app, in the wire's own words. The default
    # is `off` — no corpus loaded, nobody looked — which is what every app reads until
    # #248 ships one, and it is deliberately NOT an absent field: a surface that cannot
    # tell "we looked and found nothing" from "we never looked" has re-created the exact
    # failure `assessment` was minted to prevent (docs/vulnerabilities.md §4a). The block
    # is the wire's `VulnEnrichment` rather than a REST copy of it, so the three states
    # are spelled the same in a Splunk event and on the page.
    vuln: VulnEnrichment = Field(default_factory=VulnEnrichment)

    @computed_field
    @property
    def days_since_patch_available(self) -> int | None:
        if self.patch_available_since is None:
            return None
        return (datetime.now(timezone.utc) - self.patch_available_since).days


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    id: int
    mdm_provider: MdmProvider
    mdm_connection_id: int | None
    external_id: str
    serial_number: str
    hostname: str
    last_seen_at: datetime | None
    last_check_in: datetime | None
    last_inventory_at: datetime | None
    managed: bool | None
    supervised: bool | None
    os_version: str | None
    site: str | None
    # Both halves of the same fact. The id is what Jamf put on the device and what the
    # row stores; the name is resolved per request from the connection's catalog
    # (app.mdm.org_units) and is null while that catalog has not been read since the id
    # first appeared — never the id in disguise, so a caller can always tell "no name
    # yet" from a department genuinely called "7".
    building_id: str | None
    department_id: str | None
    building: str | None = None
    department: str | None = None


class DeviceDetailOut(DeviceOut):
    apps: list[InstalledAppOut] = []
    extension_attributes: list[ExtensionAttributeOut] = []
    # #251: the corpus generation every `vuln` block below came from, so a header can
    # never disagree with the rows under it — both are read off one corpus object in one
    # request. `null` means no corpus is loaded, which is why every app reads `off`; a
    # surface says that in words and dates it with nothing, rather than showing a date it
    # does not have (docs/vulnerabilities.md §4a). It rides the device rather than a
    # separate call on purpose: a stamp fetched apart from the rows it describes can be
    # from a different moment than they are.
    corpus_as_of: date | None = None


class DeviceListResponse(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    items: list[DeviceOut]
    total: int
    page: int
    page_size: int
