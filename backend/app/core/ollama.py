"""Resolve a concrete model after the endpoint and disclosure controls have run."""

from fastapi import HTTPException

from app.ai.adapters import AdapterError, discover_ollama
from app.ai.providers import Provider
from app.core.ai import AIRefused, require_ai


def validate_policy(provider, base, policy):
    if policy and (provider != Provider.openai_compatible or not base.rstrip("/").endswith("/v1")):
        raise HTTPException(422, "Loaded-model mode needs an Ollama OpenAI-compatible base URL ending in /v1.")


async def select_model(
    db, *, provider, pinned, policy, base, destination, host, key, transport=None, connect_ip=None, preview=False
):
    if not policy:
        return {"model": pinned, "reason": "pinned", "installed": [], "loaded": [], "digest": None}
    validate_policy(provider, base, policy)
    try:
        await require_ai(db, feature="ollama_model_discovery", destination=destination, carries_no_fleet_data=True)
    except AIRefused as exc:
        raise HTTPException(409, str(exc)) from exc
    try:
        return await discover_ollama(
            base, policy, api_key=key, host=host, transport=transport, connect_ip=connect_ip, preview=preview
        )
    except AdapterError as exc:
        fallback = policy.get("fallback")
        return {
            "model": fallback,
            "reason": "discovery_failed_fallback" if fallback else "discovery_failed",
            "loaded": [],
            "installed": [],
            "digest": None,
            "detail": exc.kind,
        }


def selected(selection):
    if selection["model"]:
        return selection["model"]
    why = "Discovery failed" if selection["reason"] == "discovery_failed" else "No compatible loaded model was found"
    raise HTTPException(409, why + ". Load a chat model on the configured Ollama endpoint or select a fallback in Settings → AI.")
