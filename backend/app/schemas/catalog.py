from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.schemas.payload import VulnEnrichment


class _CamelModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)


class CatalogTitleRef(_CamelModel):
    id: str
    name: str


class CatalogEntryOut(_CamelModel):
    """One row of the tenant app catalog: a distinct (name, bundle ID, version) the fleet has
    shown, when it was first and last seen, how many devices carry it now, and Jamf's answer."""

    id: int
    name: str
    bundle_id: str
    version: str
    short_version: str | None
    app_hash: str
    version_hash: str
    key_title: str
    key_full: str
    first_seen_at: datetime
    last_seen_at: datetime
    device_count: int = 0
    jamf_title_ids: list[str] | None = None
    jamf_titles: list[CatalogTitleRef] = []
    patch_state: str | None = None
    is_latest: bool | None = None
    patch_available: bool | None = None
    patch_available_since: datetime | None = None
    releases_missed: int | None = None
    this_version_seen: bool | None = None
    latest_version: str | None = None
    latest_released_at: datetime | None = None
    released_at: datetime | None = None
    evaluated_at: datetime | None = None


class CatalogEntryAssessedOut(CatalogEntryOut):
    """A catalog row that **is** the build being answered about, so it can carry an
    assessment (#251).

    The split is the point, not the inheritance. `vuln` is scoped to `key_full` — one
    answer per distinct build — so it may only ride a row a caller asked for *by build*.
    The lookup endpoint answers by `appHash` too, where the row returned is deliberately a
    stand-in for a **different** build (the newest version the tenant has seen), and a
    clean bill from a newer build presented as the title's answer is
    `docs/vulnerabilities.md` §4a's failure one grain out — a caller reads "no findings"
    for a build nobody assessed.

    That is refused by the type rather than documented: `CatalogLookupOut.tenant` is the
    base `CatalogEntryOut`, which has no `vuln` at all, so a stand-in cannot carry one even
    by accident. The list endpoint's rows are each their own build, so they use this.
    """

    # `covered` (we looked), `unknown_app` (outside the corpus, dated) or `off` (nobody
    # looked). Defaults to `off`, which is what every row reads until #248 loads a corpus,
    # and is never absent here: a column that cannot tell "no findings" from "not
    # assessed" is the failure `assessment` exists to prevent (§4a).
    vuln: VulnEnrichment = Field(default_factory=VulnEnrichment)


class CatalogSummaryOut(_CamelModel):
    entries: int
    installed: int
    matched: int
    unmatched: int


class CatalogListResponse(_CamelModel):
    items: list[CatalogEntryAssessedOut]
    total: int
    summary: CatalogSummaryOut
    # #251: the corpus generation the blocks on `items` came from — the page's header
    # stamp, read off the same corpus object in the same request as the rows, so the two
    # can never disagree. `null` is the honest answer while no corpus is loaded, and the
    # page says so in words rather than dating the column with nothing or with today.
    #
    # Deliberately NOT on the summary: the four summary tiles count every row the tenant
    # has, and counting `covered` / `unknown_app` / `off` across all of them is a scan of
    # the whole catalog per request. Those counts are #250's, off the join #248 stores.
    corpus_as_of: date | None = None


class CatalogVersionOut(_CamelModel):
    """A Jamf-known release: the title, the version, and when Jamf says it shipped."""

    title_id: str
    title_name: str
    publisher: str | None
    app_name: str | None
    bundle_id: str
    version: str
    released_at: datetime | None
    is_latest: bool


class CatalogLookupRequest(_CamelModel):
    version_hashes: list[str] = Field(default_factory=list, max_length=500)
    key_fulls: list[str] = Field(default_factory=list, max_length=500)
    app_hashes: list[str] = Field(default_factory=list, max_length=500)


class CatalogLookupOut(_CamelModel):
    """The local lookup for one key: the tenant's row if the fleet has shown the app, and what
    Jamf knows about that exact (appName, bundleId, version).

    `tenant` is the base `CatalogEntryOut` on purpose: this endpoint answers by `appHash`
    as well as by build, and under `appHash` the row is a stand-in for the newest version
    the tenant has seen rather than the caller's build. There is no assessment to give at
    that grain, so the type does not have the field — see `CatalogEntryAssessedOut` (#251).
    """

    key: str
    tenant: CatalogEntryOut | None = None
    jamf: list[CatalogVersionOut] = []
    jamf_title_ids: list[str] = []
    is_latest: bool | None = None
    latest: str | None = None
    latest_released_at: datetime | None = None
    this_version_seen: bool = False
    released_at: datetime | None = None


class CatalogRefreshResult(_CamelModel):
    evaluated: int
