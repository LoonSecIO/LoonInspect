"""Synthetic credential-bearing source URLs stay on the transport side of the boundary."""

import json
import traceback
from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from app.ai.adapters import OUTCOME_ANSWERED
from app.ai.providers import Wire
from app.core import patch_plan_pdf, patch_plan_research, patch_plans
from app.core.provenance import source_url
from app.mdm.patch.jamf_catalog import JamfApiCatalogSource, JamfPatchCatalogUnconfigured, JamfPatchCatalogUnreachable
from app.schemas.patch_plans import BuildPlan

SECRET = "SYNTHETIC_PROVENANCE_SECRET"
APP = "a" * 32
RAW_URL = f"https://synthetic-user:{SECRET}@mirror.example.test/v1/patch/title?access={SECRET}#fragment-{SECRET}"
SAFE_URL = "https://mirror.example.test/v1/patch/title"
NOW = datetime(2026, 11, 23, tzinfo=UTC)


def saved_plan(url=RAW_URL):
    option = {
        "source": "Jamf Patch",
        "title": "Synthetic Title",
        "reference": "title",
        "targetVersion": "2",
        "url": url,
        "status": "catalog_match",
        "observedAt": NOW.isoformat(),
        "sourceRevision": "synthetic",
        "detail": "Verify the target before deployment.",
    }
    app = {
        "appHash": APP,
        "name": "Synthetic App",
        "bundleId": "test.example.synthetic",
        "devices": 1,
        "status": "draft",
        "targetVersion": "2",
        "versions": [],
        "options": [option],
        "gaps": [],
        "steps": ["Verify identity"],
    }
    snapshot = {
        "applications": [app],
        "organization": "Synthetic organization",
        "status": "Draft",
        "asOf": NOW.isoformat(),
        "applicationDevices": 1,
        "scopedDevices": 1,
        "scopeDescription": [],
        "sources": [],
        "limitations": [],
    }
    research = {
        "applications": [
            {
                "appHash": APP,
                "url": RAW_URL,
                "status": "candidate",
                "detail": "Verify the source.",
                "revision": "b" * 40,
                "sha256": "c" * 64,
            }
        ],
        "detail": "Investigation completed.",
    }
    return SimpleNamespace(
        id="synthetic-plan",
        title="Synthetic plan",
        created_at=NOW,
        created_by="Synthetic operator",
        revision=3,
        snapshot=snapshot,
        research_status="completed",
        research_started_at=NOW,
        research=research,
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (RAW_URL, SAFE_URL),
        ("https://synthetic%40user:pass%40word@[::1]:8443/v1?token=value#hidden", "https://[::1]:8443/v1"),
        ("HTTP://Mirror.Example.test:8080/v1/", "HTTP://Mirror.Example.test:8080/v1/"),
        ("https://mirror.example.test/v1?", "https://mirror.example.test/v1"),
        (f"https://user:{SECRET}@mirror.example.test:bad/v1", ""),
        (f"https://user:{SECRET}@[broken/v1", ""),
        (f"not-an-address-{SECRET}", ""),
    ],
)
def test_source_url_withholds_sensitive_components_without_changing_safe_links(value, expected):
    assert source_url(value) == expected
    assert source_url(source_url(value)) == expected


def test_historical_plan_read_preserves_storage_revision_and_hashes_exactly_its_safe_body():
    plan = saved_plan()
    original = deepcopy(vars(plan))
    first = patch_plans.plan_output(plan)
    second = patch_plans.plan_output(plan)
    assert SECRET not in json.dumps(first)
    assert first["snapshot"]["applications"][0]["options"][0]["url"] == SAFE_URL
    assert first["research"]["applications"][0]["url"] == SAFE_URL
    assert first["sha256"] == patch_plans.checksum({key: value for key, value in first.items() if key != "sha256"})
    assert first == second and first["revision"] == 3
    assert vars(plan) == original and SECRET in json.dumps(plan.snapshot)
    raw_body = {**first, "snapshot": plan.snapshot, "research": plan.research}
    assert first["sha256"] != patch_plans.checksum({key: value for key, value in raw_body.items() if key != "sha256"})


def test_redaction_targets_named_urls_only_and_keeps_safe_report_checksums():
    plan = saved_plan(SAFE_URL)
    plan.research = None
    prose = "Review https://operator.example.test/path?ticket=123 with its owner."
    plan.snapshot["operatorReview"] = {"approval": prose}
    body = patch_plans.plan_output(plan)
    assert body["snapshot"] == plan.snapshot and body["research"] is None
    assert body["snapshot"]["operatorReview"]["approval"] == prose
    assert body["sha256"] == patch_plans.checksum({key: value for key, value in body.items() if key != "sha256"})
    assert patch_plans.report_presentation(body) == body


def test_pdf_render_boundary_removes_historical_urls_and_uses_the_same_display_digest(monkeypatch):
    plan = saved_plan()
    safe = patch_plans.plan_output(plan)
    raw_report = {**safe, "snapshot": plan.snapshot, "research": plan.research, "sha256": "stale-raw-digest"}
    paragraphs = []
    real_paragraph = patch_plan_pdf.Paragraph

    def capture(text, *args, **kwargs):
        paragraphs.append(text)
        return real_paragraph(text, *args, **kwargs)

    monkeypatch.setattr(patch_plan_pdf, "Paragraph", capture)
    assert patch_plan_pdf.render_pdf(raw_report).startswith(b"%PDF")
    rendered_text = "\n".join(paragraphs)
    assert SECRET not in rendered_text and "stale-raw-digest" not in rendered_text
    assert SAFE_URL in rendered_text and safe["sha256"] in rendered_text
    assert SECRET in json.dumps(raw_report), "rendering must not rewrite a held snapshot"


async def test_ai_prompt_uses_safe_options_even_for_a_historical_snapshot(monkeypatch):
    plan = saved_plan()
    captured = []
    config = SimpleNamespace(
        provider="openai_compatible",
        host_reach=None,
        base_url="https://model.example.test/v1",
        api_key_encrypted=None,
        model="synthetic",
        ollama_policy=None,
        reasoning_effort=None,
    )
    monkeypatch.setattr(patch_plan_research, "chosen_config", AsyncMock(return_value=config))
    monkeypatch.setattr(
        patch_plan_research, "judged_endpoint", AsyncMock(return_value=(Wire.openai_chat, config.base_url, config.base_url, None))
    )
    monkeypatch.setattr(patch_plan_research, "select_model", AsyncMock())
    monkeypatch.setattr(patch_plan_research, "selected", lambda _: "synthetic")
    consent = AsyncMock()
    monkeypatch.setattr(patch_plan_research, "require_ai", consent)

    async def complete(wire, request, **kwargs):
        consent.assert_awaited_once()
        captured.append(request.prompt)
        return SimpleNamespace(content=json.dumps({APP: [1]}), outcome=OUTCOME_ANSWERED, model="synthetic")

    monkeypatch.setattr(patch_plan_research, "complete", complete)
    result = await patch_plan_research.ai_priorities(None, plan.snapshot, "openai_compatible")
    assert result["status"] == "completed"
    assert SECRET not in captured[0] and SAFE_URL in captured[0]
    assert json.loads(captured[0])[0]["options"][0]["reference"] == "title"
    assert SECRET in json.dumps(plan.snapshot)


async def test_new_snapshot_uses_safe_source_url_without_changing_catalog_configuration(monkeypatch):
    raw_base = f"https://user:{SECRET}@mirror.example.test/v1?access={SECRET}#private"
    monkeypatch.setattr(patch_plans.settings, "jamf_patch_base_url", raw_base)
    row = SimpleNamespace(
        app_hash=APP,
        name="Synthetic App",
        bundle_id="test.example.synthetic",
        version="1",
        short_version="1",
        macs=1,
        titles=[["title"]],
        assumed=False,
        all_matched=True,
        checked=NOW,
        evaluated=True,
    )
    title = SimpleNamespace(id="title", name="Synthetic Title", current_version="2", synced_at=NOW, last_modified="synthetic")

    class SnapshotDB:
        def __init__(self):
            self.results = iter([[row], [row], [(APP, 1)], []])

        async def execute(self, query):
            result = next(self.results)
            return SimpleNamespace(all=lambda: result)

        async def scalars(self, query):
            return [title]

        async def scalar(self, query):
            return 1

    monkeypatch.setattr(patch_plans, "prepare_scope", AsyncMock())
    monkeypatch.setattr(patch_plans, "earned_corpus", AsyncMock(return_value=None))
    monkeypatch.setattr(patch_plans, "corpus_as_of", lambda _: None)
    monkeypatch.setattr(patch_plans.fleet_catalog, "enabled", AsyncMock(return_value=False))
    monkeypatch.setattr(patch_plans, "risk_output", lambda *a, **kw: SimpleNamespace(model_dump=lambda **kw: {}))
    snapshot = await patch_plans.build_snapshot(SnapshotDB(), BuildPlan(appHashes=[APP]), "Synthetic organization")
    assert snapshot["applications"][0]["options"][0]["url"] == SAFE_URL
    assert SECRET not in json.dumps(snapshot)
    assert patch_plans.settings.jamf_patch_base_url == raw_base


@pytest.mark.parametrize("failure", ["http", "transport", "malformed"])
async def test_catalog_diagnostics_and_tracebacks_withhold_fetch_credentials(failure):
    raw_base = f"https://user:{SECRET}@mirror.example.test/v1?access={SECRET}#private"
    requests = []

    def answer(request):
        requests.append(request)
        if failure == "transport":
            raise httpx.ConnectError(f"Could not connect to {raw_base}", request=request)
        return httpx.Response(403 if failure == "http" else 200, text=SECRET)

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
        source = JamfApiCatalogSource(client, raw_base)
        assert source._base_url == raw_base
        with pytest.raises(JamfPatchCatalogUnreachable) as caught:
            await source.summaries()
    message = str(caught.value)
    assert SECRET not in message and "mirror.example.test" in message
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    assert "Nothing was written" in message and "docs/troubleshooting.md section 6" in message
    # The configured request semantics remain unchanged, including basic auth and query.
    assert SECRET in str(requests[0].url) and "authorization" in requests[0].headers


async def test_unusable_catalog_configuration_is_not_echoed():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200))) as client:
        with pytest.raises(JamfPatchCatalogUnconfigured) as caught:
            JamfApiCatalogSource(client, f"invalid://user:{SECRET}@mirror.example.test")
    assert SECRET not in str(caught.value)
    assert "JAMF_PATCH_BASE_URL" in str(caught.value) and "value withheld" in str(caught.value)


async def test_invalid_transport_address_is_withheld_without_rejecting_configuration_early():
    raw_base = f"https://user:{SECRET}@mirror.example.test:invalid/v1"
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200))) as client:
        source = JamfApiCatalogSource(client, raw_base)
        assert source._base_url == raw_base
        with pytest.raises(JamfPatchCatalogUnreachable) as caught:
            await source.summaries()
    assert "InvalidURL" in str(caught.value) and "JAMF_PATCH_BASE_URL" in str(caught.value)
    assert SECRET not in "".join(traceback.format_exception(caught.value))
