from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


Severity = Literal["low", "medium", "high", "critical"]


class ApplicationScope(_CamelModel):
    model_config = ConfigDict(extra="forbid")
    q: str = Field(default="", max_length=255)
    severities: list[Severity] = Field(default_factory=list, max_length=4)
    has_kev: bool = False


class ApplicationRisk(_CamelModel):
    """Known findings per installed build, with an explicit assessed-device denominator."""

    assessment: Literal["off", "unknown_app", "partial", "covered"]
    counts: dict[str, int] | None = None
    assessed_device_count: int = 0
    devices_with_unknown_builds: int = 0
    assessed_build_count: int = 0
    unknown_build_count: int = 0
    average_per_assessed_device: float | None = None


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
    vulnerabilities: ApplicationRisk | None = None


class ApplicationListResponse(_CamelModel):
    """The list envelope every paged endpoint shares (#137): the page's rows, the count
    across every page, and the page and page size that produced them, echoed so a client
    never has to remember what it asked for."""

    items: list[ApplicationOut]
    total: int
    page: int
    page_size: int
    corpus_as_of: str | None = None
    corpus_release: str | None = None
