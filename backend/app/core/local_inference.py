"""Resolve and pin local-only inference destinations before inventory leaves the pod (#409)."""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from app.core.egress import BlockedBaseUrl, inference_blocked_reason

LOCAL_ONLY = (
    "Exclusion ranking needs Apple Foundation Models or an OpenAI-compatible endpoint on a loopback or private "
    "network address. Save a local endpoint in Settings › AI; hosted endpoints cannot receive these candidates."
)
_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def local_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    address = getattr(address, "ipv4_mapped", None) or address
    return inference_blocked_reason(address) is None and (
        address.is_loopback or any(address in network for network in _NETWORKS if address.version == network.version)
    )


async def pinned_address(url: str) -> str:
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
    if not addresses or not all(local_address(address) for address in addresses):
        raise BlockedBaseUrl(LOCAL_ONLY)
    return addresses[0]
