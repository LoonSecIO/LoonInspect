from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class UpdateStatusOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    enabled: bool
    current_version: str
    # None is "unknown" — checking disabled, a dev build, or the provider was
    # unreachable. False means "checked and current". The UI treats None as
    # nothing-to-say, never as an error.
    update_available: bool | None
    latest_sha: str | None
    checked_at: datetime | None
