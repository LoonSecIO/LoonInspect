"""What the test box can talk to, and how the container finds it.

Three entries, two wire adapters, one host-reach seam (Kyle, 2026-09-05):

- ``apple_fm``: Apple Foundation Models, served by Apple's own ``fm serve`` on the Mac
  host (macOS 27 ships ``/usr/bin/fm``; ``fm serve`` listens on 127.0.0.1:1976 by
  default and speaks ``/v1/models`` and ``/v1/chat/completions``; verified 2026-09-05).
  The framework only executes host-side; the container is a client. No shim.
- ``openai_compatible``: any OpenAI-style ``/chat/completions``. Ollama on the host is
  the documented local default (#28); OpenAI itself, a gateway, LM Studio and vLLM are
  the same entry with a different URL. Ollama is not a provider — it is an endpoint.
- ``anthropic``: the Messages API, bring-your-own key.

Host reach is deliberately not part of the provider. It answers one question — how does
this container find the Mac that runs the shim, or the Ollama default? — and the
initial design implements exactly one answer, Docker Desktop, refusing the rest *by
name* so that a future runtime is one table row, one test case and one verification
run rather than a redesign. In the UI the pair is one card, "Apple Foundation Models
via Docker Desktop", which reads as "click here if you run LoonInspect under Docker
Desktop": the label names the pattern the operator is on, not what powers the model.

Everything here is data. The adapters (``app.ai.adapters``) do the talking.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit


class Provider(StrEnum):
    apple_fm = "apple_fm"
    openai_compatible = "openai_compatible"
    anthropic = "anthropic"


class Wire(StrEnum):
    openai_chat = "openai_chat"
    anthropic_messages = "anthropic_messages"


class HostReach(StrEnum):
    docker_desktop = "docker_desktop"
    orbstack = "orbstack"
    colima = "colima"
    podman = "podman"
    remote_mac = "remote_mac"
    # The editable URL field: whatever the operator typed, recorded as typed.
    custom = "custom"


class ReachNotImplemented(ValueError):
    """A reserved reach value. Refused by name so the reply says which runtime is
    not supported yet rather than dialling a host name nobody verified."""


# The host name a container sees under each runtime, from the record on #28. Only the
# implemented values are ever dialled; the reserved rows document what the future card
# would fill in and are verified on a real install before they move.
_REACH_HOSTNAME: dict[HostReach, str] = {
    HostReach.docker_desktop: "host.docker.internal",
    HostReach.orbstack: "host.docker.internal",
    HostReach.colima: "host.docker.internal",
    HostReach.podman: "host.containers.internal",
}

IMPLEMENTED_REACH: frozenset[HostReach] = frozenset({HostReach.docker_desktop, HostReach.custom})

# The address a connection through each reach actually arrives on, which is what the
# container puts in the `Host` header. Docker Desktop delivers `host.docker.internal`
# to the Mac's own loopback, and a local server may only answer requests that name
# the address it is bound to (Apple's `fm serve` answers 403 to any other name, so a
# local client has to say where the connection lands). Measured 2026-09-05:
# `127.0.0.1`, `127.0.0.1:1976` and `localhost:1976` are all accepted by `fm serve`.
_REACH_ARRIVES_ON: dict[HostReach, str] = {HostReach.docker_desktop: "127.0.0.1"}

WIRE_FOR: dict[Provider, Wire] = {
    Provider.apple_fm: Wire.openai_chat,
    Provider.openai_compatible: Wire.openai_chat,
    Provider.anthropic: Wire.anthropic_messages,
}


@dataclass(frozen=True)
class ProviderDefaults:
    """What picking a card fills in. ``base_url`` may carry ``{host}``, resolved from the
    reach at request time; the anthropic base does not (the SDK convention: OpenAI-style
    bases end in ``/v1``, Anthropic's does not)."""

    provider: Provider
    wire: Wire
    base_url: str
    model: str
    # none | optional | required — what the key field means for this entry.
    key: str
    # Sent as OpenAI's ``reasoning_effort`` when set. Ollama honours it and the local
    # thinking models otherwise spend their whole budget thinking and answer with
    # empty content (measured 2026-09-05: qwen3.5:2b-mlx, 1024 tokens, no content).
    reasoning_effort: str | None
    uses_host_reach: bool


DEFAULTS: dict[Provider, ProviderDefaults] = {
    Provider.apple_fm: ProviderDefaults(
        provider=Provider.apple_fm,
        wire=Wire.openai_chat,
        base_url="http://{host}:1976/v1",
        # `fm serve` names the on-device model "system" and Private Cloud Compute
        # "pcc". It refuses `reasoning_effort` for "system", so none is sent.
        model="system",
        key="none",
        reasoning_effort=None,
        uses_host_reach=True,
    ),
    Provider.openai_compatible: ProviderDefaults(
        provider=Provider.openai_compatible,
        wire=Wire.openai_chat,
        base_url="http://{host}:11434/v1",
        model="qwen3.5:2b-mlx",
        key="optional",
        reasoning_effort="none",
        uses_host_reach=True,
    ),
    Provider.anthropic: ProviderDefaults(
        provider=Provider.anthropic,
        wire=Wire.anthropic_messages,
        base_url="https://api.anthropic.com",
        model="claude-fable-5-1",
        key="required",
        reasoning_effort=None,
        uses_host_reach=False,
    ),
}

# What `fm serve` lists: the on-device model and Private Cloud Compute.
APPLE_FM_MODELS: tuple[str, ...] = ("system", "pcc")

# Alternatives the model field's help text may list; the default above is the one
# the environment names as current and most capable.
ANTHROPIC_MODELS: tuple[str, ...] = (
    "claude-fable-5-1",
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-haiku-4-5-20251001",
)


def hostname_for(reach: HostReach) -> str:
    """The host name inside the container for an implemented reach.

    ``custom`` has no host name of its own — the operator typed the whole URL — and is
    a programming error to resolve; the reserved rows raise by name.
    """
    if reach not in IMPLEMENTED_REACH:
        raise ReachNotImplemented(
            f"host reach {reach.value!r} is not supported yet; the initial design implements "
            "Docker Desktop only. Type the URL instead."
        )
    if reach is HostReach.custom:
        raise ValueError("custom reach carries no host name; use the URL as typed")
    return _REACH_HOSTNAME[reach]


def default_base_url(provider: Provider, reach: HostReach = HostReach.docker_desktop) -> str:
    """The URL a card fills in: the entry's template with ``{host}`` resolved."""
    template = DEFAULTS[provider].base_url
    if "{host}" not in template:
        return template
    return template.replace("{host}", hostname_for(reach))


def presented_host(reach: HostReach, base_url: str) -> str | None:
    """The `Host` header for a dial through ``reach``, or None to send the URL's own
    name. Only while the operator kept the reach's alias: a URL they retyped is
    ``custom`` in all but name and is sent exactly as written."""
    arrives_on = _REACH_ARRIVES_ON.get(reach)
    if arrives_on is None:
        return None
    parsed = urlsplit(base_url)
    if parsed.hostname != _REACH_HOSTNAME.get(reach):
        return None
    return f"{arrives_on}:{parsed.port}" if parsed.port else arrives_on
