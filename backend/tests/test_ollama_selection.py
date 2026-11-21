import json

import httpx
import pytest
from fastapi import HTTPException

from app.ai.providers import Provider
from app.core.ollama import select_model, validate_policy


@pytest.mark.parametrize(
    "loaded,preferences,fallback,model,reason",
    [
        (["embed", "gemma"], ["embed"], None, "gemma", "loaded"),
        (["gemma", "qwen"], ["qwen", "gemma"], None, "qwen", "loaded"),
        (["embed"], [], None, None, "no_compatible_loaded"),
        ([], [], None, None, "no_compatible_loaded"),
        ([], [], "qwen", "qwen", "fallback"),
    ],
)
async def test_selection_and_capability(loaded, preferences, fallback, model, reason, monkeypatch):
    async def gate(*args, **kwargs):
        assert kwargs["carries_no_fleet_data"]

    monkeypatch.setattr("app.core.ollama.require_ai", gate)

    def handler(req):
        assert req.url.host == "127.0.0.1" and req.headers["host"] == "configured.local:11434"
        if req.url.path in ["/proxy/api/ps", "/proxy/api/tags"]:
            return httpx.Response(
                200,
                json={
                    "models": [
                        {"name": n, "digest": "digest-" + n}
                        for n in (loaded if req.url.path.endswith("ps") else ["embed", "gemma", "qwen"])
                    ]
                },
            )
        assert req.url.path == "/proxy/api/show"
        name = json.loads(req.content)["model"]
        return httpx.Response(200, json={"capabilities": ["embedding" if name == "embed" else "completion"]})

    selection = await select_model(
        None,
        provider=Provider.openai_compatible,
        pinned="qwen",
        policy={"preferences": preferences, "fallback": fallback},
        base="http://configured.local:11434/proxy/v1",
        destination="http://configured.local:11434",
        host=None,
        key=None,
        connect_ip="127.0.0.1",
        transport=httpx.MockTransport(handler),
        preview=True,
    )
    assert (selection["model"], selection["reason"]) == (model, reason)
    assert selection["installed"] == ["embed", "gemma", "qwen"] and selection["loaded"] == sorted(loaded)


async def test_unreachable_endpoint_and_pinned_default(monkeypatch):
    async def gate(*args, **kwargs):
        pass

    monkeypatch.setattr("app.core.ollama.require_ai", gate)
    calls = []

    def fail(request):
        calls.append(request.url.path)
        raise httpx.ConnectError("offline")

    args = {
        "provider": Provider.openai_compatible,
        "pinned": "qwen",
        "base": "http://localhost/v1",
        "destination": "localhost",
        "host": None,
        "key": None,
        "transport": httpx.MockTransport(fail),
    }
    assert (await select_model(None, policy=None, **args))["model"] == "qwen"
    assert not calls
    for fallback in (None, "qwen"):
        result = await select_model(None, policy={"preferences": [], "fallback": fallback}, **args)
        assert result["model"] == fallback and result["reason"].startswith("discovery_failed")
    with pytest.raises(HTTPException):
        validate_policy(Provider.apple_fm, args["base"], {"preferences": []})
