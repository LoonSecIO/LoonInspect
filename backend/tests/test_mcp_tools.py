"""MCP's allowlist preserves REST filters, evidence caveats, and bounded disclosure."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from app.core.permissions import Permission
from app.mcp.tools import TOOLS

APP = "a" * 32
BUILD = "b" * 32
JOB = "01949b78-169a-7dfb-9568-80b10b01be0c"


async def test_device_search_translates_filters_without_widening_population():
    response = {"items": [], "total": 0, "corpusAsOf": None}
    request = AsyncMock(return_value=response)
    result = await TOOLS["list_devices"].execute(
        {
            "q": "test Mac",
            "connection_id": 7,
            "os_version": "14.7",
            "os_version_operator": "gte",
            "managed": False,
            "last_inventory_after": "2026-11-01T00:00:00Z",
            "page": 2,
            "page_size": 12,
        },
        request,
    )
    request.assert_awaited_once_with(
        "GET",
        "/api/devices",
        params={
            "page": 2,
            "pageSize": 12,
            "q": "test Mac",
            "mdmConnectionId": 7,
            "osVersion": "14.7",
            "osVersionOperator": "gte",
            "managed": False,
            "lastInventoryAfter": "2026-11-01T00:00:00Z",
            "includeDeparted": False,
        },
    )
    assert result is response  # Preserve absence, rather than manufacturing a healthy count.


async def test_exact_build_device_drilldown_keeps_both_hashes():
    request = AsyncMock(return_value={"items": []})
    await TOOLS["list_application_devices"].execute({"app_hash": APP, "version_hash": BUILD}, request)
    request.assert_awaited_once_with(
        "GET",
        "/api/devices",
        params={"page": 1, "pageSize": 50, "appHash": APP, "versionHash": BUILD, "includeDeparted": False},
    )


async def test_vulnerability_filter_and_catalog_filter_use_real_query_names():
    request = AsyncMock(return_value={"items": []})
    await TOOLS["list_vulnerable_devices"].execute({"findings": "kev"}, request)
    assert request.call_args.kwargs["params"]["vuln"] == "kev"
    request.reset_mock()
    await TOOLS["search_catalog"].execute({"findings": "patchable", "band": "high", "order": "payoff"}, request)
    request.assert_awaited_once_with(
        "GET",
        "/api/catalog",
        params={
            "page": 1,
            "pageSize": 50,
            "installedOnly": True,
            "jamf": "all",
            "vuln": "patchable",
            "band": "high",
            "order": "payoff",
        },
    )


async def test_connection_projection_is_an_allowlist_and_pages_stably():
    request = AsyncMock(
        return_value=[
            {
                "id": n,
                "name": f"Jamf {n}",
                "provider": "jamf",
                "isActive": True,
                "baseUrl": "https://secret-name.example",
                "credentialsFingerprint": "private",
                "futureSecret": "must never surface",
            }
            for n in (3, 1, 2)
        ]
    )
    result = await TOOLS["list_connections"].execute({"page": 2, "page_size": 1}, request)
    assert result == {
        "items": [{"id": 2, "name": "Jamf 2", "provider": "jamf", "isActive": True}],
        "page": 2,
        "pageSize": 1,
        "total": 3,
        "hasMore": True,
    }
    request.assert_awaited_once_with("GET", "/api/mdm/connections", params=None)


async def test_device_detail_bounds_nested_lists_and_preserves_corpus_absence():
    data = {
        "id": 8,
        "corpusAsOf": None,
        "apps": [{"name": str(n), "vuln": {"assessment": "off"}} for n in range(5)],
        "extensionAttributes": [{"name": str(n), "values": ["value"]} for n in range(3)],
    }
    request = AsyncMock(return_value=data)
    result = await TOOLS["get_device"].execute({"device_id": 8, "page": 2, "page_size": 2}, request)
    assert [app["name"] for app in result["apps"]] == ["2", "3"]
    assert result["apps"][0]["vuln"] == {"assessment": "off"}
    assert result["corpusAsOf"] is None
    assert result["pagination"]["apps"] == {"page": 2, "pageSize": 2, "total": 5, "hasMore": True}
    assert result["pagination"]["extensionAttributes"]["total"] == 3
    assert len(data["apps"]) == 5  # Paging must not mutate a shared API response.
    request.assert_awaited_once_with("GET", "/api/devices/8", params=None)


async def test_vulnerability_paging_retains_truncated_coverage_caveat():
    data = {"builds": [{"version": str(i)} for i in range(3)], "truncatedBuilds": 8, "corpusAsOf": "2026-11-21"}
    request = AsyncMock(return_value=data)
    result = await TOOLS["get_vulnerability"].execute({"finding_id": "CVE-2026-12345", "page": 2, "page_size": 2}, request)
    assert result["builds"] == [{"version": "2"}]
    assert result["truncatedBuilds"] == 8
    assert result["buildsPagination"] == {"page": 2, "pageSize": 2, "total": 3, "hasMore": False}
    request.assert_awaited_once_with("GET", "/api/vulnerabilities/CVE-2026-12345", params=None)


async def test_history_point_pages_available_fields_without_losing_saved_values_or_summary():
    data = {
        "choices": [{"key": str(i)} for i in range(3)],
        "values": [{"state": "not_observed", "value": None}],
        "summary": {"status": "disabled", "text": None},
    }
    request = AsyncMock(return_value=data)
    result = await TOOLS["get_device_history_point"].execute(
        {"device_id": 3, "point": "point-id", "page": 2, "page_size": 2}, request
    )
    assert result["choices"] == [{"key": "2"}]
    assert result["choicesPagination"] == {"page": 2, "pageSize": 2, "total": 3, "hasMore": False}
    assert result["values"] == data["values"]
    assert result["summary"] == data["summary"]
    request.assert_awaited_once_with("GET", "/api/devices/3/history/point", params={"point": "point-id"})


async def test_evidence_page_preserves_whole_report_claims_and_only_exposes_page_devices():
    data = {
        "header": {"notVisible": {"statement": "These controls are not observed."}, "refusal": "Not certification."},
        "readThisFirst": ["Some days were not observed."],
        "rules": [{"ruleID": "firewall"}],
        "rows": [{"deviceID": "a"}, {"deviceID": "b"}, {"deviceID": "c"}],
        "devices": [{"deviceID": key, "serialNumber": key} for key in ("a", "b", "c")],
        "totals": {
            "fleet": {"notObserved": {"seconds": 30}},
            "byRule": {"firewall": {"met": {"seconds": 10}}},
            "byDevice": {key: {"met": {"seconds": 3}} for key in ("a", "b", "c")},
        },
    }
    request = AsyncMock(return_value=data)
    result = await TOOLS["get_evidence_report"].execute(
        {"connection_id": 4, "start": "2026-11-01T00:00:00Z", "as_of": "2026-11-22T00:00:00Z", "page_size": 1, "page": 2},
        request,
    )
    assert result["header"] == data["header"]
    assert result["readThisFirst"] == data["readThisFirst"]
    assert result["rows"] == [{"deviceID": "b"}]
    assert result["devices"] == [{"deviceID": "b", "serialNumber": "b"}]
    assert result["totals"]["fleet"] == data["totals"]["fleet"]
    assert result["totals"]["byRule"] == data["totals"]["byRule"]
    assert set(result["totals"]["byDevice"]) == {"b"}
    assert result["pagination"]["total"] == 3
    assert result["pagination"]["deviceTotal"] == 3
    request.assert_awaited_once_with(
        "GET",
        "/api/evidence/report",
        params={"connectionID": 4, "start": "2026-11-01T00:00:00Z", "asOf": "2026-11-22T00:00:00Z"},
    )


async def test_finished_run_can_still_have_unread_logs():
    request = AsyncMock(return_value={"run": {"status": "succeeded"}, "complete": True, "lines": [{"id": i} for i in (4, 5, 6)]})
    result = await TOOLS["get_run_log"].execute({"job_id": JOB, "after": 3, "page_size": 2}, request)
    assert result["complete"] is True
    assert result["hasMore"] is True
    assert result["nextAfter"] == 5
    assert result["lines"] == [{"id": 4}, {"id": 5}]
    request.assert_awaited_once_with("GET", f"/api/runs/{JOB}/log", params={"after": 3})


async def test_empty_run_log_retains_cursor():
    request = AsyncMock(return_value={"complete": False, "lines": []})
    result = await TOOLS["get_run_log"].execute({"job_id": JOB, "after": 37}, request)
    assert result["nextAfter"] == 37
    assert result["hasMore"] is False
    assert result["complete"] is False


async def test_posture_uses_registry_keys_and_source_window():
    request = AsyncMock(return_value={"items": []})
    await TOOLS["get_posture"].execute({"keys": ["devices.total", "apps.total"], "days": 14}, request)
    request.assert_awaited_once_with(
        "GET",
        "/api/posture",
        params={"page": 1, "pageSize": 50, "keys": "devices.total,apps.total", "platform": "macos", "days": 14},
    )


@pytest.mark.parametrize(
    ("name", "arguments", "path", "params"),
    [
        ("list_applications", {"q": "Firefox"}, "/api/applications", {"page": 1, "pageSize": 50, "q": "Firefox"}),
        (
            "get_application",
            {"app_hash": APP},
            "/api/catalog",
            {"page": 1, "pageSize": 50, "appHash": APP, "installedOnly": True},
        ),
        ("get_device_history", {"device_id": 3, "page": 2}, "/api/devices/3/history", {"page": 2}),
        ("get_vulnerability_status", {}, "/api/vulnerabilities/status", None),
        (
            "list_changes",
            {"connection_id": 3, "subject_id": "20", "min_level": "high", "artifact": "Firefox"},
            "/api/changes",
            {"page": 1, "pageSize": 50, "connectionId": 3, "subjectId": "20", "minLevel": "high", "artifact": "Firefox"},
        ),
        ("list_alerts", {"open_only": False}, "/api/alerts", {"page": 1, "pageSize": 50, "open": False}),
        (
            "list_runs",
            {"connection_id": 3, "trigger": "manual", "status": "failed"},
            "/api/runs",
            {"page": 1, "pageSize": 50, "connectionId": 3, "status": "failed", "trigger": "manual"},
        ),
        ("get_run", {"job_id": JOB}, f"/api/runs/{JOB}", None),
        ("get_delivery_status", {}, "/api/outbox", None),
        ("get_posture_registry", {}, "/api/posture/registry", None),
    ],
)
async def test_read_tools_use_authenticated_rest_contract(name, arguments, path, params):
    request = AsyncMock(return_value={"source": "api"})
    assert await TOOLS[name].execute(arguments, request) == {"source": "api"}
    request.assert_awaited_once_with("GET", path, params=params)


async def test_instance_status_reports_source_facts_without_inventing_all_clear():
    request = AsyncMock(side_effect=[{"version": "1.2.0"}, {"reason": "not_checked"}])
    result = await TOOLS["get_instance_status"].execute({}, request)
    assert result == {"version": {"version": "1.2.0"}, "updates": {"reason": "not_checked"}}
    assert [call.args for call in request.await_args_list] == [
        ("GET", "/api/system/version"),
        ("GET", "/api/system/update-status"),
    ]


@pytest.mark.parametrize(
    ("name", "arguments", "path"),
    [
        ("refresh_device", {"device_id": 8}, "/api/devices/8/refresh"),
        ("start_inventory_sync", {"connection_id": 7}, "/api/mdm/connections/7/sync"),
        ("refresh_patch_catalog", {}, "/api/jamf-patch/sync"),
        ("refresh_patch_catalog", {"source": "fleet"}, "/api/fleet-catalog/refresh"),
    ],
)
async def test_mutations_use_only_fixed_existing_actions_and_do_not_retry(name, arguments, path):
    request = AsyncMock(return_value={"jobId": JOB, "started": False})
    result = await TOOLS[name].execute(arguments, request)
    assert result == {"jobId": JOB, "started": False}
    assert request.await_count == 1
    assert request.call_args.args == ("POST", path)
    assert TOOLS[name].read_only is False


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("list_devices", {"page_size": 201}),
        ("list_devices", {"page": 0}),
        ("list_devices", {"page_size": "200"}),
        ("list_devices", {"managed": "false"}),
        ("list_devices", {"last_inventory_after": "2026-11-22T12:00:00"}),
        ("list_devices", {"os_version_operator": "regex"}),
        ("get_device", {"device_id": True}),
        ("get_device", {"device_id": "../auth/tokens"}),
        ("get_device", {"device_id": -1}),
        ("get_run", {"job_id": "../../auth/tokens"}),
        ("get_application", {"app_hash": "../../auth/tokens"}),
        ("get_vulnerability", {"finding_id": "CVE-2026-1234/../../auth/tokens"}),
        ("get_vulnerability", {"finding_id": "CVE-２０２６-1234"}),
        ("get_vulnerability", {"finding_id": "LOCAL-2026-1234"}),
        ("get_vulnerability", {"finding_id": "CVE-2026-1234\n"}),
        ("get_posture", {"days": 14, "since": "2026-11-01T00:00:00Z"}),
        ("get_posture", {"days": 401}),
        ("get_evidence_report", {"connection_id": 1, "start": "2026-11-22T00:00:00Z", "as_of": "2026-11-01T00:00:00Z"}),
        ("refresh_patch_catalog", {"source": "https://attacker.invalid"}),
        ("start_inventory_sync", {"connection_id": 1, "tenant_id": "another-tenant"}),
    ],
)
async def test_invalid_arguments_fail_before_any_request(name, arguments):
    request = AsyncMock()
    with pytest.raises(ValidationError):
        await TOOLS[name].execute(arguments, request)
    request.assert_not_awaited()


@pytest.mark.parametrize("spec", list(TOOLS.values()), ids=list(TOOLS))
def test_every_tool_has_closed_schema_permission_and_disclosure(spec):
    schema = spec.input_model.model_json_schema()
    assert schema["additionalProperties"] is False
    assert spec.permissions
    assert spec.disclosure
    assert all(isinstance(permission, Permission) for permission in spec.permissions)
    assert not ({"url", "path", "sql", "command", "tenant_id", "token"} & schema.get("properties", {}).keys())
    if "page_size" in schema.get("properties", {}):
        assert schema["properties"]["page_size"]["maximum"] == 200
        assert schema["properties"]["page_size"]["default"] == 50


def test_action_permissions_are_separate_from_read_permissions():
    actions = {name for name, spec in TOOLS.items() if not spec.read_only}
    assert actions == {"refresh_device", "start_inventory_sync", "refresh_patch_catalog"}
    assert Permission.DEVICE_SYNC in TOOLS["refresh_device"].permissions
    assert Permission.DEVICE_SYNC in TOOLS["start_inventory_sync"].permissions
    assert Permission.PATCH_CATALOG_SYNC in TOOLS["refresh_patch_catalog"].permissions
    assert {Permission.DEVICE_READ, Permission.APP_READ} <= set(TOOLS["list_alerts"].permissions)


async def test_rest_refusal_is_preserved_not_replaced_with_empty_success():
    refusal = RuntimeError("No vulnerability corpus answers for this organization.")
    request = AsyncMock(side_effect=refusal)
    with pytest.raises(RuntimeError) as raised:
        await TOOLS["list_vulnerable_devices"].execute({}, request)
    assert raised.value is refusal
    assert request.await_count == 1
