"""Resolve and pin local-only inference destinations before inventory leaves the pod (#409)."""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.ai.providers import HostReach, Provider, apple_model_refused, hostname_for
from app.core.egress import BlockedBaseUrl, inference_blocked_reason, validate_inference_base_url

LOCAL_ONLY = (
    "Exclusion ranking needs Apple Foundation Models or an OpenAI-compatible endpoint on a loopback or private "
    "network address. Save a local endpoint in Settings › AI; hosted endpoints cannot receive these candidates."
)
_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def _address(value: str):
    address = ipaddress.ip_address(value)
    return getattr(address, "ipv4_mapped", None) or address


def local_address(value: str) -> bool:
    address = _address(value)
    return inference_blocked_reason(address) is None and (
        address.is_loopback or any(address in network for network in _NETWORKS if address.version == network.version)
    )


async def pinned_address(url: str, *, host_only: bool = False) -> str:
    host = urlsplit(url).hostname
    if not host:
        raise BlockedBaseUrl(LOCAL_ONLY)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=2)
            addresses = sorted({str(info[4][0]) for info in infos})
        except (OSError, UnicodeError) as exc:
            raise BlockedBaseUrl("The local AI endpoint could not be resolved. Check its address and DNS, then retry.") from exc
    else:
        addresses = [str(address)]
    requires_loopback = host_only and host.rstrip(".").lower() != hostname_for(HostReach.docker_desktop)
    if requires_loopback and not all(_address(address).is_loopback for address in addresses):
        raise BlockedBaseUrl(LOCAL_ONLY)
    if not addresses or not all(local_address(address) for address in addresses):
        raise BlockedBaseUrl(LOCAL_ONLY)
    return addresses[0]


@dataclass(frozen=True, slots=True)
class SensitiveTextDestination:
    connect_ip: str | None = None
    reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.connect_ip is not None


async def sensitive_text_destination(provider: Provider, base_url: str, model: str) -> SensitiveTextDestination:
    """Only an on-host model may receive sensitive text. Use connect_ip on the adapter request."""
    if provider not in (Provider.apple_fm, Provider.openai_compatible):
        return SensitiveTextDestination(reason="provider_unsupported")
    # fm serve also speaks OpenAI. Selecting its other card must not make PCC an on-device model.
    if apple_model_refused(Provider(provider), model) or model.strip().casefold() == "pcc":
        return SensitiveTextDestination(reason="model_not_on_host")
    try:
        url = validate_inference_base_url(base_url, carries_key=False)
        address = await pinned_address(url, host_only=True)
    except ValueError:
        return SensitiveTextDestination(reason="endpoint_not_on_host")
    return SensitiveTextDestination(connect_ip=address)
