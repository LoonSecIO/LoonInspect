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
        "diskEncryption": {"fileVault2Enabled": True},
        "security": {"sipStatus": "ENABLED"},
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
    evidence = compare(compact(snapshot()), compact({"security": {"sipStatus": "ENABLED"}}))
    assert evidence["kind"] == "incomplete"
    assert evidence["changes"] == []


def test_capped_answer_cannot_resolve_an_id_by_absence():
    source = snapshot(["CVE-2025-1002"])
    source["app"][0]["vuln"]["vulnIDsTruncated"] = True
    evidence = compare(compact(snapshot()), compact(source))
    assert evidence["changes"][0]["noLongerListedIDs"] == []


def test_security_change_is_code_computed():
    new = snapshot()
    new["diskEncryption"]["fileVault2Enabled"] = False
    evidence = compare(compact(snapshot()), compact(new))
    assert evidence["changes"] == [{"section": "diskEncryption", "field": "fileVault2Enabled", "before": True, "after": False}]


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


def test_filevault_change_from_real_jamf_contract_fixture():
    import json
    from pathlib import Path

    from tests.test_inventory_snapshot import _snapshot

    raw = json.loads((Path(__file__).parent / "fixtures/jamf/computer_inventory_detail.json").read_text())
    before = compact(_snapshot(raw))
    raw["diskEncryption"]["fileVault2Enabled"] = False
    evidence = compare(before, compact(_snapshot(raw)))
    assert evidence["kind"] == "changed"
    assert {"section": "diskEncryption", "field": "fileVault2Enabled", "before": True, "after": False} in evidence["changes"]
    assert "diskEncryption.fileVault2Enabled: True -> False" in evidence["facts"]
    without = _snapshot(raw)
    without.pop("diskEncryption")
    assert "diskEncryption" in compare(before, compact(without))["missingSections"]


def test_partial_first_observation_then_full_snapshot_is_baseline_not_ai_work():
    partial = compact({"security": {"sipStatus": "ENABLED"}})
    assert compare(partial, compact(snapshot()))["kind"] == "baseline"


def test_name_only_change_is_not_a_vulnerability_assessment_change():
    updated = snapshot()
    updated["app"][0]["app"]["name"] = "Chrome Enterprise"
    assert compare(compact(snapshot()), compact(updated))["changes"][0]["reason"] == "metadata_changed"


@pytest.mark.asyncio
async def test_interactive_fm_overtakes_queued_background_work():
    import asyncio

    import httpx

    from app.ai.adapters import CompletionRequest, complete
    from app.ai.providers import Wire

    started, release = asyncio.Event(), asyncio.Event()
    order = []

    async def respond(request):
        import json

        label = json.loads(request.content)["messages"][-1]["content"]
        order.append(label)
        if label == "active":
            started.set()
            await release.wait()
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    def call(label, background):
        return complete(
            Wire.openai_chat,
            CompletionRequest(base_url="http://fm.example/v1", model="system", prompt=label, serial=True, background=background),
            transport=httpx.MockTransport(respond),
        )

    active = asyncio.create_task(call("active", True))
    await started.wait()
    queued = asyncio.create_task(call("background", True))
    interactive = asyncio.create_task(call("interactive", False))
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(active, queued, interactive)
    assert order == ["active", "interactive", "background"]


def test_migration_graph_has_one_head():
    from pathlib import Path

    from alembic.config import Config
    from alembic.script import ScriptDirectory

    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    assert len(ScriptDirectory.from_config(config).get_heads()) == 1


def test_missing_known_filevault_field_is_incomplete_and_new_field_is_baseline():
    old = compact(snapshot())
    partial = snapshot()
    partial["diskEncryption"] = {}
    evidence = compare(old, compact(partial))
    assert evidence["kind"] == "incomplete"
    assert "diskEncryption" in evidence["missingSections"]
    assert compare(compact(partial), old)["kind"] == "baseline"


@pytest.mark.asyncio
async def test_slow_worker_is_not_restarted_while_tick_is_active(monkeypatch):
    import asyncio

    from app.summaries import service

    active = asyncio.Event()
    calls = 0

    async def blocked_tick():
        nonlocal calls
        calls += 1
        active.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(service, "tick", blocked_tick)
    task = asyncio.create_task(service.run_worker())
    await active.wait()
    await asyncio.sleep(0.02)
    assert calls == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# --- extension attributes (#644) --------------------------------------------------------------


def with_ea(payload, *entries):
    """The snapshot plus its `ea` section: `(definitionId, name, values)` per entry."""
    return {
        **payload,
        "ea": [{"ea": {"definitionId": d, "name": n, "values": list(v), "source": "general"}} for d, n, v in entries],
    }


def test_extension_attribute_value_change_is_evidence_and_names_the_attribute():
    before = compact(with_ea(snapshot(), ("1", "Device Security EA", [])))
    after = compact(with_ea(snapshot(), ("1", "Device Security EA", ["Some<b>Value"])))
    evidence = compare(before, after)
    assert evidence["kind"] == "changed"
    assert evidence["changes"] == [
        {"section": "extensionAttributes", "field": "1", "name": "Device Security EA", "before": [], "after": ["Some b Value"]}
    ]
    assert evidence["facts"] == "Extension attribute Device Security EA: (empty) -> Some b Value."
    assert evidence["missingSections"] == []


def test_first_sight_of_a_definition_or_of_the_section_is_baseline_not_a_briefing():
    # The section itself newly observed — every device after the upgrade — extends the baseline.
    evidence = compare(compact(snapshot()), compact(with_ea(snapshot(), ("1", "Device Security EA", ["x"]))))
    assert evidence["kind"] == "baseline"
    assert evidence["changes"] == [{"section": "extensionAttributes", "reason": "newly_observed"}]
    # One definition newly observed — an admin created it — is that definition's baseline.
    before = compact(with_ea(snapshot(), ("1", "Device Security EA", ["x"])))
    after = compact(with_ea(snapshot(), ("1", "Device Security EA", ["x"]), ("2", "Is a Test Device", ["yes"])))
    evidence = compare(before, after)
    assert evidence["kind"] == "baseline"
    assert evidence["changes"] == [
        {"section": "extensionAttributes", "field": "2", "name": "Is a Test Device", "reason": "newly_observed", "after": ["yes"]}
    ]
    assert evidence["facts"] == "Extension attribute Is a Test Device: newly observed."


def test_a_definition_no_longer_reported_or_renamed_is_neither_a_change_nor_a_gap():
    before = compact(with_ea(snapshot(), ("1", "Device Security EA", ["x"]), ("2", "Is a Test Device", ["yes"])))
    gone = compact(with_ea(snapshot(), ("1", "Device Security EA", ["x"])))
    assert compare(before, gone)["kind"] == "unchanged"
    assert compare(before, gone)["missingSections"] == []
    renamed = compact(with_ea(snapshot(), ("1", "Security posture", ["x"]), ("2", "Is a Test Device", ["yes"])))
    assert compare(before, renamed)["kind"] == "unchanged"
    # The current name labels the line when the values do move.
    moved = compact(with_ea(snapshot(), ("1", "Security posture", ["y"]), ("2", "Is a Test Device", ["yes"])))
    assert compare(before, moved)["facts"] == "Extension attribute Security posture: x -> y."


def test_the_gate_admits_by_definition_id_and_a_refused_section_is_observed_not_missing():
    payload = with_ea(snapshot(), ("1", "Device Security EA", ["x"]), ("9", "Battery Cycle Count", ["241"]))
    gated = compact(payload, extension_attributes=lambda definition_id: definition_id != "9")
    assert list(gated["extensionAttributes"]) == ["1"]
    # Everything refused: the section is present and empty, so a previous state that held the
    # definitions compares as unchanged — never as incomplete, and never as a briefing.
    muted = compact(payload, extension_attributes=lambda _definition_id: False)
    assert muted["extensionAttributes"] == {}
    evidence = compare(compact(payload), muted)
    assert (evidence["kind"], evidence["missingSections"]) == ("unchanged", [])
    # The history digest leaves the section out, so it neither widens on upgrade nor moves
    # with a value the span already keys on.
    assert "extensionAttributes" not in compact(payload, extension_attributes=False)
    assert compact(payload, extension_attributes=False) == compact(snapshot())
    # A snapshot without the section, whichever gate: absent, and so still unknown to compare.
    assert "extensionAttributes" not in compact(snapshot())


def test_a_snapshot_that_dropped_the_section_from_its_aperture_is_incomplete():
    before = compact(with_ea(snapshot(), ("1", "Device Security EA", ["x"])))
    evidence = compare(before, compact(snapshot()))
    assert evidence["kind"] == "incomplete"
    assert evidence["missingSections"] == ["extensionAttributes"]


def test_a_reply_may_repeat_an_extension_attribute_value_but_not_invent_a_number():
    facts = "Extension attribute Battery Cycle Count: 241 -> 242."
    assert checked_reply("Battery Cycle Count moved from 241 to 242.", facts) == "Battery Cycle Count moved from 241 to 242."
    with pytest.raises(Exception, match="unsupported_number"):
        checked_reply("Battery Cycle Count reached 250.", facts)
