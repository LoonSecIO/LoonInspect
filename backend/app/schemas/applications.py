from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class ApplicationOut(_CamelModel):
    """One application across the fleet, keyed by `app_hash = md5(name:bundle_id)` — the
    key the record page at `/devices/applications/:appHash` is addressed by (#299). The
    per-version breakdown this row used to carry was deleted with the expansion it fed;
    the spread is the catalog's answer, read by `appHash`."""

    app_hash: str
    name: str
    bundle_id: str
    # Distinct devices with any version installed — the sort key for the page.
    device_count: int
    version_count: int


class ApplicationListResponse(_CamelModel):
    """The list envelope every paged endpoint shares (#137): the page's rows, the count
    across every page, and the page and page size that produced them, echoed so a client
    never has to remember what it asked for."""

    items: list[ApplicationOut]
    total: int
    page: int
    page_size: int
