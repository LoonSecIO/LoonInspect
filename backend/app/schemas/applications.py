from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class ApplicationVersionOut(_CamelModel):
    """One build of an application. `version_hash` is the key the LoonSec Global API
    is queried with, so it's surfaced here rather than kept internal."""

    version_hash: str
    version: str
    short_version: str | None
    device_count: int
    patch_available: bool | None
    is_compliant: bool | None


class ApplicationOut(_CamelModel):
    app_hash: str
    name: str
    bundle_id: str
    # Distinct devices with any version installed — the sort key for the page.
    device_count: int
    version_count: int
    versions: list[ApplicationVersionOut]


class ApplicationListResponse(_CamelModel):
    items: list[ApplicationOut]
    total: int
