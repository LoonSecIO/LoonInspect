"""Compact evidence, corpus-only changes, bounded model prose and source-time delivery."""

import copy

import pytest

from app.summaries.evidence import checked_reply, compact, compare, prompt


def snapshot(ids=None, version="1", total=1):
    return {
        "app": [
            {
                "app": {"name": "Chrome", "bundleId": "com.google.chrome", "version": version},
                "vuln": {
                    "assessment": "covered",
                    "counts": {"total": total, "severity": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "kev": 0},
                    "vulnIDs": ids or ["CVE-2025-1001"],
                    "vulnIDsTruncated": False,
                },
            }
        ],
        "security": {"fileVault2Enabled": True},
        "operatingSystem": {"version": "15", "build": "A"},
    }


def test_corpus_change_triggers_without_an_inventory_version_change():
    old = compact(snapshot())
    new = compact(snapshot(["CVE-2025-1001", "CVE-2025-1002"], total=2))
    evidence = compare(old, new)
    assert evidence["kind"] == "changed"
    assert evidence["changes"][0]["newlyListedIDs"] == ["CVE-2025-1002"]
    assert "Current findings: 2" in evidence["facts"]


def test_no_changes_and_no_private_identity_in_prompt():
    source = snapshot()
    source["deviceMeta"] = {"hostName": "private-host", "serialNumber": "private-serial"}
    assert compare(compact(source), compact(source))["kind"] == "unchanged"
    text = prompt(compare({}, compact(source)), "concise")
    assert "private-host" not in text and "private-serial" not in text
    assert "CVE-" not in text


def test_missing_app_section_never_becomes_removal_or_no_updates():
    evidence = compare(compact(snapshot()), compact({"security": {"fileVault2Enabled": True}}))
    assert evidence["kind"] == "incomplete"
    assert evidence["changes"] == []


def test_capped_answer_cannot_resolve_an_id_by_absence():
    source = snapshot(["CVE-2025-1002"])
    source["app"][0]["vuln"]["vulnIDsTruncated"] = True
    evidence = compare(compact(snapshot()), compact(source))
    assert evidence["changes"][0]["noLongerListedIDs"] == []


def test_security_change_is_code_computed():
    new = snapshot()
    new["security"]["fileVault2Enabled"] = False
    evidence = compare(compact(snapshot()), compact(new))
    assert evidence["changes"] == [{"section": "security", "field": "fileVault2Enabled", "before": True, "after": False}]


def test_prompt_has_a_fixed_budget_and_discloses_omission():
    source = snapshot()
    source["app"] = [copy.deepcopy(source["app"][0]) for _ in range(100)]
    for n, app in enumerate(source["app"]):
        app["app"]["bundleId"] = f"com.example.{n}"
        app["app"]["name"] = "long " * 24
    evidence = compare({"apps": {}}, compact(source))
    assert evidence["omitted"] > 0
    assert len(prompt(evidence, "x" * 1000)) < 3050


@pytest.mark.parametrize("answer", ["It resolved 999 findings.", "<script>alert(1)</script>", "", "a\nb"])
def test_model_cannot_add_numbers_or_markup(answer):
    with pytest.raises(ValueError):
        checked_reply(answer, "Chrome 1. Findings: 2.")


def test_severity_change_is_meaningful_even_with_identical_cve_ids():
    source = snapshot()
    source["app"][0]["vuln"]["counts"]["severity"].update(critical=0, high=1)
    evidence = compare(compact(snapshot()), compact(source))
    assert evidence["kind"] == "changed"
    assert evidence["changes"][0]["newlyListedIDs"] == []
    assert "0 critical, 1 high" in evidence["facts"]


def test_version_transition_is_one_change_and_has_old_and_new_versions():
    evidence = compare(compact(snapshot(version="1")), compact(snapshot(version="2")))
    assert len(evidence["changes"]) == 1
    assert evidence["changes"][0]["reason"] == "version_changed"
    assert "Previous version: 1" in evidence["facts"]


@pytest.mark.asyncio
async def test_fm_requests_share_a_serial_lane():
    import asyncio

    import httpx

    from app.ai.adapters import CompletionRequest, complete
    from app.ai.providers import Wire

    active = peak = 0

    async def answer(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    request = CompletionRequest(base_url="http://fm.example/v1", model="system", prompt="synthetic", serial=True)
    await asyncio.gather(*(complete(Wire.openai_chat, request, transport=httpx.MockTransport(answer)) for _ in range(3)))
    assert peak == 1


def test_unicode_fact_and_preference_budget_is_bounded_in_bytes():
    source = snapshot()
    source["app"] = [copy.deepcopy(source["app"][0]) for _ in range(100)]
    for n, app in enumerate(source["app"]):
        app["app"]["bundleId"] = f"com.example.{n}"
        app["app"]["name"] = "界" * 120
    evidence = compare({"apps": {}}, compact(source))
    assert len(evidence["facts"].encode()) <= 2400
    assert len(prompt(evidence, "界" * 500).encode()) < 3400
    assert evidence["omitted"] > 0


@pytest.mark.parametrize("options", [{"preprompt": "x" * 501}, {"intervalSeconds": 0}, {"provider": "unknown"}])
def test_settings_reject_unbounded_or_unknown_inputs(options):
    from pydantic import ValidationError

    from app.api.inventory_summaries import Options

    with pytest.raises(ValidationError):
        Options(**options)
