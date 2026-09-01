"""Where this server may send an authenticated request of its own.

An MDM connection's `base_url` is a destination the caller chooses and the server then
visits holding a credential (`app/mdm/jamf/client.py` puts the client secret in the
body of a POST to `{base_url}/api/oauth/token`). That makes the column a server-side
request forgery sink with several drivers: the sweep, the scheduler, and
`POST /connections/test`. #200 and #208 pinned the stored *secret* to the stored URL;
this bounds which URLs may be stored at all, and which the test endpoint may dial
(#131).

**Private addresses are allowed on purpose.** Jamf Pro is frequently on-premises,
reached at an RFC 1918 address or through the operator's own DNS, and a product that
refuses `https://jamf.corp.internal` has broken a legitimate install to prevent an
attack its own admin has no need to mount — a worse outcome than the SSRF. What is
refused is the narrower set nothing legitimate is served from and an attacker wants
most: loopback (the app's own container, and anything sharing its network namespace),
link-local (169.254.169.254 on AWS/Azure/GCP, and the ECS task credential endpoint at
169.254.170.2 — the reason this is HIGH on a pod rather than a lab curiosity), and the
unspecified/multicast/reserved space.

Rejected: an allowlist of `*.jamfcloud.com`. It is the tightest rule available and it
would refuse every on-premises Jamf Pro in existence, which is most of the ones this
product is bought for.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from app.core.config import settings

# mdm_connections.base_url is String(512); a longer value reaches the database as an
# error rather than a refusal the caller can read.
MAX_BASE_URL_LENGTH = 512

# Long enough for a slow resolver, short enough that a dead one costs one save a
# two-second pause instead of a timeout the operator reads as a hang.
_RESOLVE_TIMEOUT_SECONDS = 2.0

_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class BlockedBaseUrl(ValueError):
    """A base_url this server refuses to send a credential to, and why.

    A ValueError so a pydantic validator can raise it and get a 422 for free; the
    routes that check outside the schema (POST /test) catch it by type to answer with
    the reason instead.
    """


def _unwrap(ip: _IpAddress) -> _IpAddress:
    """The v4 address an IPv6 literal is really carrying, if it is carrying one.

    `IPv6Address("::ffff:127.0.0.1").is_loopback` is False — the v6 predicates only
    look at the v6 space — so the tests below have to run against the embedded address
    or `::ffff:169.254.169.254` walks straight through. Teredo is deliberately not
    unwrapped: its embedded v4 is the *client* behind the NAT, not the host the request
    would reach, so refusing on it would block the wrong thing.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
    return ip


def blocked_address_reason(address: _IpAddress) -> str | None:
    """Why this address may not be dialled, or None if it may.

    Deliberately does not test `is_private`: 10/8, 172.16/12, 192.168/16 and IPv6
    unique-local are where on-premises Jamf Pro lives (see the module docstring).
    """
    ip = _unwrap(address)
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address — cloud instance metadata is served at 169.254.169.254"
    if ip.is_unspecified:
        return "the unspecified address"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_reserved:
        return "a reserved address"
    return None


def _as_ip(host: str) -> _IpAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _allowed_schemes() -> tuple[str, ...]:
    # Read at call time, not import time, so the setting is honest in a test and in a
    # process that reloads configuration.
    return ("https", "http") if settings.allow_insecure_mdm_base_url else ("https",)


def validate_mdm_base_url(value: str) -> str:
    """The URL as it should be stored, or BlockedBaseUrl naming what is wrong with it.

    Syntax and literal addresses only — a hostname is judged by
    `refuse_blocked_resolution`, which needs an event loop and so cannot live in a
    pydantic validator.
    """
    url = value.strip()
    if not url:
        raise BlockedBaseUrl("baseUrl is required")
    if len(url) > MAX_BASE_URL_LENGTH:
        raise BlockedBaseUrl(f"baseUrl must be at most {MAX_BASE_URL_LENGTH} characters")

    try:
        parsed = urlsplit(url)
        # urlsplit defers parsing the port; reading it here turns "https://host:notaport"
        # into a refusal instead of an exception thrown later, out of httpx.
        _ = parsed.port
    except ValueError as exc:
        raise BlockedBaseUrl(f"baseUrl is not a URL this server can parse: {exc}") from exc

    if parsed.scheme not in _allowed_schemes():
        if parsed.scheme == "http":
            raise BlockedBaseUrl(
                "baseUrl must use https: the client-credentials POST carries the Jamf "
                "client secret in its body, and http puts it on the wire in clear. Set "
                "ALLOW_INSECURE_MDM_BASE_URL=true to accept that for a lab instance."
            )
        raise BlockedBaseUrl(
            f"baseUrl must be an absolute https:// URL, not {parsed.scheme or 'a bare hostname'!r}"
        )

    if parsed.username or parsed.password:
        raise BlockedBaseUrl("baseUrl must not carry credentials in the URL (user:password@host)")
    if parsed.query or parsed.fragment:
        raise BlockedBaseUrl("baseUrl must be a server URL with no query string or fragment")

    host = parsed.hostname
    if not host:
        raise BlockedBaseUrl("baseUrl must name a host")

    # RFC 6761 reserves these for the loopback interface, so the name is as good as the
    # literal and refusing it by name makes the answer deterministic when the container
    # has no resolver to ask.
    if host == "localhost" or host.endswith(".localhost"):
        raise BlockedBaseUrl(f"baseUrl may not point at {host}: that is a loopback name")

    literal = _as_ip(host)
    if literal is not None:
        reason = blocked_address_reason(literal)
        if reason is not None:
            raise BlockedBaseUrl(f"baseUrl may not point at {host}: that is {reason}")

    return url


async def refuse_blocked_resolution(url: str) -> None:
    """Second pass on a hostname: refuse it if it resolves somewhere blocked.

    The literal check alone is defeated by naming a host that resolves to
    169.254.169.254 — and by `https://2852039166/`, which is not an IP literal to
    `ipaddress` but is one to `getaddrinfo`. This closes both.

    It is a speed bump, not a wall, and the difference is worth stating: the address a
    name resolves to here is not necessarily the one httpx connects to later, so a DNS
    rebind still gets through. Pinning the resolved address into the transport would
    close that, and was rejected for this change as a rewrite of every outbound path
    for the last increment of a threat that already requires connection:write.

    Fails *open* when resolution fails or times out. An operator can legitimately save
    a connection before the name resolves from inside the container — split-horizon
    DNS, a VPN that is not up yet, an air-gapped install with no resolver at all — and
    refusing to save a Jamf URL because DNS is down is an outage this product should
    not cause on its own.
    """
    host = urlsplit(url).hostname
    if host is None or _as_ip(host) is not None:
        return  # a literal was already judged, exhaustively, by validate_mdm_base_url

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), _RESOLVE_TIMEOUT_SECONDS
        )
    except (OSError, UnicodeError):
        # gaierror and TimeoutError are both OSError; UnicodeError is what an
        # undecodable IDNA label raises. All of them mean "no answer", not "blocked".
        return

    for info in infos:
        address = _as_ip(str(info[4][0]))
        if address is None:
            continue
        reason = blocked_address_reason(address)
        if reason is not None:
            raise BlockedBaseUrl(
                f"baseUrl may not point at {host}: it resolves to {address}, which is {reason}"
            )
