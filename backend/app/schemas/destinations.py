from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_camel

from app.core.outbox import KNOWN_EVENT_TYPES

# Literals rather than a runtime membership test, so the four working values reach the
# OpenAPI schema. A bare `str` published nothing, and an API-driven caller reading the
# spec had no way to learn that `splunk_hec` was even a legal type.
DestinationType = Literal["generic_webhook", "splunk_hec", "elastic", "runreveal"]
AuthType = Literal["none", "bearer", "header", "splunk_hec", "elastic_api_key"]

# The auth scheme each destination type requires. This coupling used to live *only* in
# FIXED_AUTH in frontend/src/features/destinations/DestinationsPage.tsx, so the UI path
# worked and the API path did not: POST {"type": "splunk_hec", "authSecret": "..."}
# returned 201, encrypted and stored the token, defaulted authType to "none", and then
# 401ed for ever — because core/outbox.py only sends `Authorization: Splunk` when
# auth_type is "splunk_hec". A type absent here (generic_webhook) lets the operator
# choose.
_FIXED_AUTH: dict[str, str] = {
    "splunk_hec": "splunk_hec",
    "elastic": "elastic_api_key",
    "runreveal": "bearer",
}


def resolve_auth_type(destination_type: str, auth_type: str | None) -> str:
    """The auth scheme this destination will actually use, or a ValueError naming the
    one it must use. `None` means the caller did not say, which is the common case for
    a type that only has one right answer."""
    required = _FIXED_AUTH.get(destination_type)
    if auth_type is None:
        return required or "none"
    if required is not None and auth_type != required:
        raise ValueError(
            f"a {destination_type} destination must use authType '{required}', not '{auth_type}'"
        )
    return auth_type

# Elasticsearch's own index/data-stream naming rules, checked here so a bad name is a
# 422 at configuration time instead of a per-item bulk rejection discovered in the
# delivery log: lowercase, none of the characters Elastic forbids, no leading -/_/+.
_ELASTIC_INDEX_RE = re.compile(r'^[^\sA-Z\\/*?"<>|,#:]+$')


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


def _validate_subscribed_events(value: list[str] | None) -> list[str] | None:
    if not value:
        return value
    unknown = sorted(set(value) - KNOWN_EVENT_TYPES)
    if unknown:
        raise ValueError(f"Unknown event type(s): {', '.join(unknown)}")
    return value


def _validate_elastic_index(value: str | None) -> str | None:
    if value is None:
        return value
    if not value or value in {".", ".."} or value[0] in "-_+" or not _ELASTIC_INDEX_RE.fullmatch(value):
        raise ValueError(
            "elasticIndex must be a valid Elasticsearch index or data stream name: "
            'lowercase, no spaces, none of \\ / * ? " < > | , # :, and it cannot '
            "start with -, _ or +"
        )
    return value


class DestinationOut(_CamelModel):
    id: int
    name: str
    type: str
    url: str
    auth_type: str
    auth_header_name: str | None
    # Elastic only; null everywhere else, and null on an Elastic destination means
    # the built-in data-stream default.
    elastic_index: str | None
    # Never the secret itself. There is no read path for it anywhere in this API — the
    # admin typed it, there is nothing to show back, same posture as an API token.
    has_secret: bool
    enabled: bool
    subscribed_events: list[str] | None
    # Delivery health. `last_error` is the most recent upstream refusal for this
    # destination, read from the delivery rows rather than denormalised onto the
    # destination — a stored copy would go stale on success, and the diagnosis the
    # operator needs is exactly the one the delivery loop already writes down.
    last_error: str | None = None
    pending_count: int = 0
    failed_count: int = 0
    last_success_at: datetime | None
    last_failure_at: datetime | None
    created_at: datetime
    updated_at: datetime


class DestinationCreate(_CamelModel):
    name: str = Field(min_length=1, max_length=255)
    type: DestinationType = "generic_webhook"
    url: str = Field(min_length=1, max_length=1024)
    # Omit and it is derived from `type`; every type but generic_webhook has exactly
    # one right answer.
    auth_type: AuthType | None = None
    auth_header_name: str | None = None
    auth_secret: str | None = None
    elastic_index: str | None = Field(default=None, min_length=1, max_length=255)
    enabled: bool = True
    subscribed_events: list[str] | None = None

    @model_validator(mode="after")
    def _validate(self) -> DestinationCreate:
        self.auth_type = resolve_auth_type(self.type, self.auth_type)
        if self.auth_type == "header" and not self.auth_header_name:
            raise ValueError("authHeaderName is required when authType is 'header'")
        if self.auth_type != "none" and not self.auth_secret:
            raise ValueError("authSecret is required unless authType is 'none'")
        _validate_elastic_index(self.elastic_index)
        _validate_subscribed_events(self.subscribed_events)
        return self


class DestinationUpdate(_CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    url: str | None = Field(default=None, min_length=1, max_length=1024)
    # `type` is immutable after creation, so whether this is legal depends on the
    # stored type — checked in api/destinations.py, which knows it.
    auth_type: AuthType | None = None
    auth_header_name: str | None = None
    # Provide to rotate the secret; omit to leave the stored one unchanged. There is no
    # way to clear it back to none via this field alone — set authType to "none".
    auth_secret: str | None = None
    # Provide null explicitly to fall back to the built-in default index.
    elastic_index: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None
    subscribed_events: list[str] | None = None

    @model_validator(mode="after")
    def _validate(self) -> DestinationUpdate:
        if self.auth_type == "header" and not self.auth_header_name:
            raise ValueError("authHeaderName is required when authType is 'header'")
        _validate_elastic_index(self.elastic_index)
        _validate_subscribed_events(self.subscribed_events)
        return self
