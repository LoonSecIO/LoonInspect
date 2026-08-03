from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class FeatureFlagOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    key: str
    label: str
    description: str
    enabled: bool


class FeatureFlagUpdate(BaseModel):
    enabled: bool
