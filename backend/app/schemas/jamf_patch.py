from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class JamfPatchTitleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    id: str
    name: str
    publisher: str | None
    app_name: str | None
    bundle_id: str | None
    current_version: str
    last_modified: str
    synced_at: datetime


class JamfPatchTitleListResponse(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    items: list[JamfPatchTitleOut]
    total: int


class JamfPatchTitleDetailOut(JamfPatchTitleOut):
    patches: list[dict]
    requirements: list[dict]


class JamfPatchSyncResult(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    synced: int
