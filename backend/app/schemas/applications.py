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
    # #313: the patch answer at the grain the list has. Both are column reads aggregated in
    # the one GROUP BY the row already costs — `jamf_title_ids` and `patch_available` are
    # copied onto every `installed_apps` row by the catalog (docs/app-catalog.md §1), so no
    # join and no judging happens here. `matched_device_count` is the denominator that
    # keeps a zero honest: "no patch available" on an app no title matches is not a clean
    # bill, it is no answer, and the page says which by comparing the two.
    matched_device_count: int = 0
    patch_available_device_count: int = 0


class ApplicationListResponse(_CamelModel):
    """The list envelope every paged endpoint shares (#137): the page's rows, the count
    across every page, and the page and page size that produced them, echoed so a client
    never has to remember what it asked for."""

    items: list[ApplicationOut]
    total: int
    page: int
    page_size: int
