"""The MCP fleet tools: a bounded allowlist over the authenticated REST API.

The injected request function must retain the caller's credential. Going through the
API preserves its permission checks, tenant binding, response models, and run locks;
calling endpoint functions directly would bypass FastAPI's dependencies.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Protocol
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from app.core.permissions import Permission
from app.core.vuln import validate_finding_id

PositiveID = Annotated[StrictInt, Field(gt=0)]
ShortText = Annotated[StrictStr, Field(min_length=1, max_length=255)]
ContentHash = Annotated[StrictStr, Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")]
FindingID = Annotated[StrictStr, Field(min_length=1, max_length=80), AfterValidator(validate_finding_id)]
PageNumber = Annotated[StrictInt, Field(ge=1)]
PageSize = Annotated[StrictInt, Field(ge=1, le=200)]


class ApiRequest(Protocol):
    async def __call__(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, json: dict[str, Any] | None = None
    ) -> Any: ...


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_model: type[BaseModel]
    permissions: tuple[Permission, ...]
    read_only: bool
    disclosure: tuple[str, ...]
    execute: Callable[[dict[str, Any], ApiRequest], Awaitable[Any]]


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Paged(Arguments):
    page: PageNumber = 1
    page_size: PageSize = 50


class Search(Paged):
    q: ShortText | None = None


class Devices(Search):
    connection_id: PositiveID | None = None
    os_version: ShortText | None = None
    os_version_operator: Literal["eq", "lt", "lte", "gt", "gte"] = "eq"
    site: ShortText | None = None
    building: ShortText | None = None
    department: ShortText | None = None
    managed: StrictBool | None = None
    supervised: StrictBool | None = None
    last_check_in_after: AwareDatetime | None = None
    last_check_in_before: AwareDatetime | None = None
    last_inventory_after: AwareDatetime | None = None
    last_inventory_before: AwareDatetime | None = None
    include_departed: StrictBool = False


class VulnerableDevices(Devices):
    findings: Literal["findings", "kev"] = "findings"


class DeviceID(Arguments):
    device_id: PositiveID


class DeviceDetail(DeviceID):
    page: PageNumber = 1
    page_size: PageSize = 50


class DeviceHistory(DeviceID):
    page: PageNumber = 1


class DeviceHistoryPoint(DeviceDetail):
    point: Annotated[StrictStr, Field(min_length=1, max_length=40)]


class ApplicationDetail(Paged):
    app_hash: ContentHash
    installed_only: StrictBool = True


class ApplicationDevices(Paged):
    app_hash: ContentHash
    version_hash: ContentHash | None = None
    connection_id: PositiveID | None = None
    include_departed: StrictBool = False


class Catalog(Search):
    app_hash: ContentHash | None = None
    installed_only: StrictBool = True
    jamf: Literal["all", "matched", "unmatched"] = "all"
    findings: Literal["all", "findings", "kev", "unknown_app", "clean", "patchable"] = "all"
    band: Literal["critical", "high", "medium", "low"] | None = None
    order: Literal["exposure", "age", "payoff"] = "exposure"


class Vulnerability(Paged):
    finding_id: FindingID


class Changes(Search):
    connection_id: PositiveID | None = None
    subject_id: ShortText | None = None
    section: ShortText | None = None
    level: ShortText | None = None
    min_level: ShortText | None = None
    artifact: ShortText | None = None
    since: AwareDatetime | None = None
    trigger: Literal["sweep", "manual", "webhook"] | None = None


class Alerts(Paged):
    open_only: StrictBool = True
    kind: Literal["new_app"] | None = None


class Runs(Paged):
    connection_id: PositiveID | None = None
    status: Literal["running", "succeeded", "failed"] | None = None
    trigger: Literal["sweep", "manual", "webhook"] | None = None


class RunID(Arguments):
    job_id: UUID


class RunLog(RunID):
    after: Annotated[StrictInt, Field(ge=0)] = 0
    page_size: PageSize = 50


class Posture(Paged):
    keys: Annotated[list[ShortText], Field(min_length=1, max_length=100)] | None = None
    platform: Literal["macos", "ios", "ipados", "tvos", "visionos"] = "macos"
    days: Annotated[StrictInt, Field(ge=1, le=400)] | None = None
    since: AwareDatetime | None = None

    @model_validator(mode="after")
    def one_window(self) -> Posture:
        if self.days is not None and self.since is not None:
            raise ValueError("Use days or since for the posture window, never both.")
        return self


class Evidence(Paged):
    connection_id: PositiveID
    start: AwareDatetime | None = None
    as_of: AwareDatetime | None = None

    @model_validator(mode="after")
    def ordered_window(self) -> Evidence:
        if self.start is not None and self.as_of is not None and self.start >= self.as_of:
            raise ValueError("The evidence window start must be earlier than as_of.")
        return self


class ConnectionID(Arguments):
    connection_id: PositiveID


class PatchCatalog(Arguments):
    source: Literal["jamf", "fleet"] = "jamf"


Transform = Callable[[Any, dict[str, Any]], Any]
_PAGE_QUERY = {"page_size": "pageSize"}
_DEVICE_QUERY = {
    **_PAGE_QUERY,
    "connection_id": "mdmConnectionId",
    "os_version": "osVersion",
    "os_version_operator": "osVersionOperator",
    "last_check_in_after": "lastCheckInAfter",
    "last_check_in_before": "lastCheckInBefore",
    "last_inventory_after": "lastInventoryAfter",
    "last_inventory_before": "lastInventoryBefore",
    "include_departed": "includeDeparted",
    "findings": "vuln",
}


def _page(values: list, args: dict[str, Any]) -> tuple[list, dict[str, Any]]:
    page, size = args.get("page", 1), args.get("page_size", 50)
    start = (page - 1) * size
    return values[start : start + size], {
        "page": page,
        "pageSize": size,
        "total": len(values),
        "hasMore": start + size < len(values),
    }


def _connections(data: list, args: dict[str, Any]) -> dict:
    # An allowlist makes new credential/configuration fields in the REST model stay
    # out of MCP until their disclosure has been reviewed explicitly.
    rows = [{key: row[key] for key in ("id", "name", "provider", "isActive")} for row in sorted(data, key=lambda r: r["id"])]
    items, pagination = _page(rows, args)
    return {"items": items, **pagination}


def _device(data: dict, args: dict[str, Any]) -> dict:
    result = dict(data)
    pagination = {}
    for key in ("apps", "extensionAttributes"):
        result[key], pagination[key] = _page(data.get(key, []), args)
    result["pagination"] = pagination
    return result


def _vulnerability(data: dict, args: dict[str, Any]) -> dict:
    builds, pagination = _page(data["builds"], args)
    return {**data, "builds": builds, "buildsPagination": pagination}


def _history_point(data: dict, args: dict[str, Any]) -> dict:
    choices, pagination = _page(data["choices"], args)
    return {**data, "choices": choices, "choicesPagination": pagination}


def _run_log(data: dict, args: dict[str, Any]) -> dict:
    lines = data["lines"][: args["page_size"]]
    return {
        **data,
        "lines": lines,
        "nextAfter": lines[-1]["id"] if lines else args["after"],
        # complete describes the RUN's terminal state; hasMore describes this batch.
        "hasMore": len(data["lines"]) > len(lines),
    }


def _evidence(data: dict, args: dict[str, Any]) -> dict:
    rows, pagination = _page(data["rows"], args)
    devices = {row["deviceID"] for row in rows}
    totals = data["totals"]
    return {
        **data,
        "rows": rows,
        "devices": [row for row in data["devices"] if row["deviceID"] in devices],
        "totals": {**totals, "byDevice": {key: value for key, value in totals["byDevice"].items() if key in devices}},
        "pagination": {
            **pagination,
            "collection": "rows",
            "deviceTotal": len(data["devices"]),
            "scope": (
                "Rows are one page of intervals. Devices and byDevice totals name that page's devices. "
                "Fleet and byRule totals cover the full report window; the header and caveats apply to every page."
            ),
        },
    }


def _route(
    name: str,
    description: str,
    input_model: type[BaseModel],
    permissions: tuple[Permission, ...],
    disclosure: tuple[str, ...],
    path: str,
    *,
    method: str = "GET",
    path_keys: tuple[str, ...] = (),
    query_names: dict[str, str] | None = None,
    local_keys: tuple[str, ...] = (),
    transform: Transform | None = None,
) -> ToolSpec:
    async def execute(arguments: dict[str, Any], request: ApiRequest) -> Any:
        args = input_model.model_validate(arguments).model_dump(mode="json", exclude_none=True)
        query = {k: v for k, v in args.items() if k not in (*path_keys, *local_keys)}
        if isinstance(query.get("keys"), list):
            query["keys"] = ",".join(query["keys"])
        params = {(query_names or {}).get(k, k): v for k, v in query.items()}
        result = await request(method, path.format(**{k: args[k] for k in path_keys}), params=params or None)
        return transform(result, args) if transform else result

    return ToolSpec(name, description, input_model, permissions, method == "GET", disclosure, execute)


async def _instance_status(arguments: dict[str, Any], request: ApiRequest) -> dict:
    Arguments.model_validate(arguments)
    # These are independent source facts, not a second implementation of the
    # Overview's canonical Needs Attention composition or an invented all-clear.
    return {
        "version": await request("GET", "/api/system/version"),
        "updates": await request("GET", "/api/system/update-status"),
    }


async def _patch_catalog(arguments: dict[str, Any], request: ApiRequest) -> Any:
    args = PatchCatalog.model_validate(arguments)
    path = "/api/jamf-patch/sync" if args.source == "jamf" else "/api/fleet-catalog/refresh"
    return await request("POST", path)


_INVENTORY = (
    "device identifiers",
    "hostnames",
    "serial numbers",
    "inventory timestamps",
    "organization fields",
    "operating system versions",
    "management state",
)
_APPS = (
    "application names",
    "bundle identifiers",
    "versions",
    "content hashes",
    "installation counts",
    "patch assessments",
    "release and observation timestamps",
)
_VULNS = ("vulnerability assessments", "finding identifiers", "corpus dates", "detection timestamps")
_RUNS = (
    "run identifiers",
    "connection and collection identifiers",
    "run timestamps",
    "run outcomes",
    "run counts",
    "run actor labels and email addresses",
    "run error messages",
)

_SPECS = [
    ToolSpec(
        "get_instance_status",
        "Read the running build and stored update-check status. Does not run an update or assert fleet health.",
        Arguments,
        (Permission.SYSTEM_READ,),
        True,
        ("build version", "update status", "update-check timestamps and disclosed payload"),
        _instance_status,
    ),
    _route(
        "list_connections",
        "List configured Jamf connections by ID, name, provider, and active state. Credentials and URLs are omitted.",
        Paged,
        (Permission.CONNECTION_READ,),
        ("connection identifiers", "connection names", "provider", "active state"),
        "/api/mdm/connections",
        local_keys=("page", "page_size"),
        transform=_connections,
    ),
    _route(
        "list_devices",
        "Search current fleet devices with bounded pages. Dates require an ISO 8601 timezone. Departed Macs are opt-in.",
        Devices,
        (Permission.DEVICE_READ,),
        (*_INVENTORY, "vulnerable application counts"),
        "/api/devices",
        query_names=_DEVICE_QUERY,
    ),
    _route(
        "list_vulnerable_devices",
        "List Macs carrying assessed findings or KEV findings. Missing assessment is a refusal, never an empty clean fleet. "
        "For a specific CVE, use get_vulnerability then list_application_devices with each returned build's hashes.",
        VulnerableDevices,
        (Permission.DEVICE_READ, Permission.VULN_READ),
        _INVENTORY + _VULNS,
        "/api/devices",
        query_names=_DEVICE_QUERY,
    ),
    _route(
        "get_device",
        "Read one device and one page each of its apps and extension attributes. Each array has explicit pagination; "
        "vulnerability assessment off or unknown_app must not be described as clean.",
        DeviceDetail,
        (Permission.DEVICE_READ, Permission.APP_READ, Permission.VULN_READ),
        _INVENTORY + _APPS + _VULNS + ("extension attribute names and values", "Jamf record URL"),
        "/api/devices/{device_id}",
        path_keys=("device_id",),
        local_keys=("page", "page_size"),
        transform=_device,
    ),
    _route(
        "get_device_history",
        "Read the device's observation timeline, twelve points per page, with observed and collected timestamps.",
        DeviceHistory,
        (Permission.DEVICE_READ,),
        ("device identifier", "observation identifiers", "observation timestamps and kinds"),
        "/api/devices/{device_id}/history",
        path_keys=("device_id",),
    ),
    _route(
        "get_device_history_point",
        "Read recorded evidence at a point returned by get_device_history. Preserves missing-observation states; "
        "available historical fields are paged separately from the saved fields and summary.",
        DeviceHistoryPoint,
        (Permission.DEVICE_READ, Permission.APP_READ, Permission.VULN_READ),
        _INVENTORY
        + _APPS
        + _VULNS
        + (
            "historical account, profile, certificate and extension attribute values",
            "historical file paths",
            "recorded inventory summary text and provider",
        ),
        "/api/devices/{device_id}/history/point",
        path_keys=("device_id",),
        local_keys=("page", "page_size"),
        transform=_history_point,
    ),
    _route(
        "list_applications",
        "Search applications grouped across installed versions. Device counts are distinct Macs, not finding counts.",
        Search,
        (Permission.APP_READ,),
        _APPS,
        "/api/applications",
        query_names=_PAGE_QUERY,
    ),
    _route(
        "get_application",
        "Read a bounded page of builds for an app_hash from list_applications, with patch and vulnerability evidence.",
        ApplicationDetail,
        (Permission.APP_READ, Permission.VULN_READ),
        _APPS + _VULNS,
        "/api/catalog",
        query_names={**_PAGE_QUERY, "app_hash": "appHash", "installed_only": "installedOnly"},
    ),
    _route(
        "list_application_devices",
        "List Macs carrying one application, optionally one exact build. Use appHash and versionHash from a "
        "get_vulnerability build to inspect that build's affected Macs; do not sum pages across builds as unique Macs.",
        ApplicationDevices,
        (Permission.DEVICE_READ, Permission.APP_READ),
        (*_INVENTORY, "application and build hashes", "vulnerable application counts"),
        "/api/devices",
        query_names={**_DEVICE_QUERY, "app_hash": "appHash", "version_hash": "versionHash"},
    ),
    _route(
        "search_catalog",
        "Search installed build evidence by exposure, severity, known exploitation, or patch payoff. Unknown and off "
        "assessments remain distinct from clean. Every result names its corpus date.",
        Catalog,
        (Permission.APP_READ, Permission.VULN_READ),
        _APPS + _VULNS,
        "/api/catalog",
        query_names={**_PAGE_QUERY, "app_hash": "appHash", "installed_only": "installedOnly", "findings": "vuln"},
    ),
    _route(
        "get_vulnerability_status",
        "Read the corpus date answering for this organization. Null means no vulnerability answer, not zero findings.",
        Arguments,
        (Permission.VULN_READ,),
        ("corpus date",),
        "/api/vulnerabilities/status",
    ),
    _route(
        "get_vulnerability",
        "Find currently installed builds whose served assessment names a CVE or LoonVD finding ID. Builds are paged; "
        "truncatedBuilds is the source's coverage caveat, not this page's size. Drill into Macs with list_application_devices.",
        Vulnerability,
        (Permission.VULN_READ, Permission.APP_READ),
        _APPS + _VULNS,
        "/api/vulnerabilities/{finding_id}",
        path_keys=("finding_id",),
        local_keys=("page", "page_size"),
        transform=_vulnerability,
    ),
    _route(
        "list_changes",
        "Read observed fleet changes, newest first. q searches device identity; artifact searches the changed item. "
        "since requires an ISO 8601 timezone.",
        Changes,
        (Permission.DEVICE_READ,),
        (*_INVENTORY, "change fields and values", "application and account names", "observation identifiers"),
        "/api/changes",
        query_names={**_PAGE_QUERY, "connection_id": "connectionId", "subject_id": "subjectId", "min_level": "minLevel"},
    ),
    _route(
        "list_alerts",
        "Read open alerts oldest first, or closed alert history with open_only=false. Does not dismiss alerts.",
        Alerts,
        (Permission.DEVICE_READ, Permission.APP_READ),
        _INVENTORY + _APPS + ("alert state and timestamps",),
        "/api/alerts",
        query_names={**_PAGE_QUERY, "open_only": "open"},
    ),
    _route(
        "list_runs",
        "Read recent inventory runs, newest first, optionally filtered by connection, status, or trigger.",
        Runs,
        (Permission.CONNECTION_READ,),
        _RUNS,
        "/api/runs",
        query_names={**_PAGE_QUERY, "connection_id": "connectionId"},
    ),
    _route(
        "get_run",
        "Read a run's current state using the job ID returned by start_inventory_sync. A running job is not complete.",
        RunID,
        (Permission.CONNECTION_READ,),
        _RUNS,
        "/api/runs/{job_id}",
        path_keys=("job_id",),
    ),
    _route(
        "get_run_log",
        "Read a bounded batch of operator log lines. Continue with nextAfter while hasMore is true; complete describes "
        "the run, so a completed run may still have unread lines.",
        RunLog,
        (Permission.CONNECTION_READ,),
        (*_RUNS, "operator log messages and fields"),
        "/api/runs/{job_id}/log",
        path_keys=("job_id",),
        local_keys=("page_size",),
        transform=_run_log,
    ),
    _route(
        "get_delivery_status",
        "Read held events, pending SIEM deliveries, dead letters, and retention deadlines. Does not send or retry anything.",
        Arguments,
        (Permission.DESTINATION_READ,),
        ("delivery queue counts", "queue age and retention", "delivery-blocking reason"),
        "/api/outbox",
    ),
    _route(
        "get_posture_registry",
        "Read posture metric definitions and absence semantics. A metric absent from a capture is not zero.",
        Arguments,
        (Permission.AUDIT_READ,),
        ("posture metric definitions",),
        "/api/posture/registry",
    ),
    _route(
        "get_posture",
        "Read recorded fleet metrics for one platform. Omit days and since for the latest capture, or supply exactly "
        "one window. Missing rows must not be filled with zeros.",
        Posture,
        (Permission.AUDIT_READ,),
        ("posture metric names and values", "capture timestamps", "run identifiers"),
        "/api/posture",
        query_names=_PAGE_QUERY,
    ),
    _route(
        "get_evidence_report",
        "Read observation-ledger evidence for one connection and time window. Defaults to the ninety days before its "
        "last collection. Interval rows are paged; global totals and all methodological caveats are retained. "
        "Pass the returned header window as start/as_of on later pages to keep the same reporting window.",
        Evidence,
        (Permission.AUDIT_READ, Permission.DEVICE_READ),
        (*_INVENTORY, "compliance rule observations", "evidence intervals", "evidence totals and limitations"),
        "/api/evidence/report",
        query_names={"connection_id": "connectionID", "as_of": "asOf"},
        local_keys=("page", "page_size"),
        transform=_evidence,
    ),
    _route(
        "refresh_device",
        "Refresh one Mac's inventory from its existing Jamf connection. Makes outbound Jamf requests and writes "
        "observations; does not deploy software or send a command to the Mac.",
        DeviceID,
        (Permission.DEVICE_READ, Permission.DEVICE_SYNC),
        ("device identifier", "run identifier", "refresh outcome", "inventory changes"),
        "/api/devices/{device_id}/refresh",
        method="POST",
        path_keys=("device_id",),
    ),
    _route(
        "start_inventory_sync",
        "Start an inventory sweep for an existing active connection. Returns jobId immediately; poll get_run/get_run_log. "
        "If a sweep is running, returns its jobId with started=false instead of starting another.",
        ConnectionID,
        (Permission.DEVICE_SYNC,),
        _RUNS,
        "/api/mdm/connections/{connection_id}/sync",
        method="POST",
        path_keys=("connection_id",),
    ),
    ToolSpec(
        "refresh_patch_catalog",
        "Refresh Jamf's public patch catalog, or Fleet's catalog when its feature is enabled. Performs outbound reads "
        "and updates cached assessments. Jamf's first refresh can take minutes; a timeout does not prove it did not run.",
        PatchCatalog,
        (Permission.PATCH_CATALOG_SYNC,),
        False,
        ("catalog source", "catalog refresh counts and outcome"),
        _patch_catalog,
    ),
]

TOOLS: dict[str, ToolSpec] = {spec.name: spec for spec in _SPECS}
