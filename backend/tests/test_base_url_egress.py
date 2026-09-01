"""Where a connection may point, and how much of the answer comes back (#131).

`base_url` is a destination the caller picks and the server then visits carrying a Jamf
client secret, so these are the two halves of one rule: `app.core.egress` bounds the
set of reachable destinations, and `app.api.connections._upstream_detail` bounds what a
reachable destination may say back through the test endpoint.

The accepted cases matter as much as the refused ones. Jamf Pro is routinely
on-premises, so an RFC 1918 address and an internal hostname have to keep working — a
rule that breaks a legitimate install is a worse outcome than the SSRF it prevents.

No database and no network: the resolver is replaced where a test needs an answer from
it, which is also the only way to write down what happens when there is no resolver at
all.
"""

from __future__ import annotations

import asyncio
import json
import socket

import httpx
import pytest
from pydantic import ValidationError

from app.api.connections import _DETAIL_MAX_CHARS, _upstream_detail
from app.core.config import settings
from app.core.egress import BlockedBaseUrl, refuse_blocked_resolution, validate_mdm_base_url
from app.schemas.connections import MdmConnectionCreate, MdmConnectionUpdate

# --- the refused classes, each answering with the reason ------------------------------


@pytest.mark.parametrize(
    ("url", "because"),
    [
        ("", "required"),
        ("https://" + "a" * 600 + ".example.com", "at most 512"),
        # No scheme at all: a bare host reads as a path to urlsplit, and the client
        # would have concatenated it into a relative request.
        ("jamf.example.com", "absolute https"),
        ("ftp://jamf.example.com", "absolute https"),
        ("file:///etc/passwd", "absolute https"),
        ("http://jamf.example.com", "ALLOW_INSECURE_MDM_BASE_URL"),
        ("https://someone:hunter2@jamf.example.com", "credentials in the URL"),
        ("https://jamf.example.com/?redirect=1", "query string"),
        ("https://jamf.example.com/#fragment", "fragment"),
        ("https://jamf.example.com:notaport", "not a URL this server can parse"),
        ("https://", "must name a host"),
        # Loopback, by literal and by every spelling of it.
        ("https://127.0.0.1:8443", "loopback address"),
        ("https://127.16.3.4", "loopback address"),
        ("https://[::1]", "loopback address"),
        ("https://[::ffff:127.0.0.1]", "loopback address"),
        ("https://localhost:8443", "loopback name"),
        ("https://jamf.localhost", "loopback name"),
        # The point of the finding: cloud instance metadata and the ECS task
        # credential endpoint are both link-local.
        ("https://169.254.169.254/latest/meta-data/", "link-local"),
        ("https://169.254.170.2/v2/credentials", "link-local"),
        ("https://[fe80::1]", "link-local"),
        ("https://[::ffff:169.254.169.254]", "link-local"),
        ("https://0.0.0.0", "unspecified"),
        ("https://224.0.0.1", "multicast"),
        ("https://240.0.0.1", "reserved"),
    ],
)
def test_a_refused_base_url_says_which_rule_refused_it(url: str, because: str) -> None:
    with pytest.raises(BlockedBaseUrl) as refusal:
        validate_mdm_base_url(url)
    assert because in str(refusal.value), f"{url!r} was refused, but not legibly: {refusal.value}"


# --- the accepted classes, which are the ones that break a customer -------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://acme.jamfcloud.com",
        "https://acme.jamfcloud.com/",
        # On-premises Jamf Pro: an internal name, and each of the RFC 1918 ranges by
        # address. Refusing these to stop the SSRF would break the deployment this
        # product is bought for.
        "https://jamf.corp.internal:8443",
        "https://jss:8443",
        "https://10.0.5.20:8443",
        "https://172.16.4.9:8443",
        "https://192.168.1.50",
        # IPv6 unique-local is the same case as 10/8.
        "https://[fd00:1234::20]:8443",
        # Carrier-grade NAT: where a Tailscale or similar overlay puts the host.
        "https://100.64.0.20",
        "https://jamf.example.com/context/path",
    ],
)
def test_a_legitimate_jamf_url_is_accepted(url: str) -> None:
    assert validate_mdm_base_url(url) == url


def test_surrounding_whitespace_is_trimmed_rather_than_refused() -> None:
    assert validate_mdm_base_url("  https://acme.jamfcloud.com  ") == "https://acme.jamfcloud.com"


def test_http_is_an_opt_in_and_not_a_way_round_the_address_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """ALLOW_INSECURE_MDM_BASE_URL buys plaintext for a lab, not a wider address space."""
    monkeypatch.setattr(settings, "allow_insecure_mdm_base_url", True)

    assert validate_mdm_base_url("http://jamf.corp.internal:8080") == "http://jamf.corp.internal:8080"
    with pytest.raises(BlockedBaseUrl, match="link-local"):
        validate_mdm_base_url("http://169.254.169.254/latest/meta-data/")


def test_security_the_connection_schemas_refuse_an_unvalidated_base_url() -> None:
    """SECURITY: the rule binds the row, not one route.

    `base_url` is read by the sweep, the scheduler and `POST /collections/{id}/run`,
    none of which pass through a route that could check it — so the check has to be on
    the schemas that *write* the column. This fails if either field goes back to a bare
    `str`, which is how it stood before #131.
    """
    for blocked in ("https://169.254.169.254", "http://jamf.example.com", "https://127.0.0.1:8443"):
        with pytest.raises(ValidationError):
            MdmConnectionCreate(name="probe", provider="jamf", base_url=blocked)
        with pytest.raises(ValidationError):
            MdmConnectionUpdate(base_url=blocked)

    # And the legitimate ones still construct, or the rule has broken the product.
    assert MdmConnectionCreate(
        name="on-prem", provider="jamf", base_url="https://jamf.corp.internal:8443"
    ).base_url == "https://jamf.corp.internal:8443"


# --- the resolver pass ----------------------------------------------------------------


def _resolves_to(*addresses: str):
    async def _getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in addresses]

    return _getaddrinfo


async def test_security_a_hostname_that_resolves_to_the_metadata_address_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SECURITY: the literal check alone is defeated by owning a DNS name.

    `https://metadata.attacker.example` passes every syntactic rule; what makes it an
    SSRF is the A record. Two forms are covered here — the name, and the integer
    spelling of an address, which `ipaddress` does not read as a literal but
    `getaddrinfo` does.
    """
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _resolves_to("169.254.169.254"))

    for url in ("https://metadata.attacker.example", "https://2852039166/"):
        with pytest.raises(BlockedBaseUrl) as refusal:
            await refuse_blocked_resolution(url)
        assert "169.254.169.254" in str(refusal.value)
        assert "link-local" in str(refusal.value)


async def test_a_name_that_also_resolves_somewhere_legitimate_is_still_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One blocked answer is enough: which address httpx picks is not ours to assume."""
    monkeypatch.setattr(
        asyncio.get_running_loop(), "getaddrinfo", _resolves_to("203.0.113.10", "127.0.0.1")
    )
    with pytest.raises(BlockedBaseUrl, match="loopback"):
        await refuse_blocked_resolution("https://split.example.com")


async def test_an_unresolvable_hostname_is_allowed_rather_than_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fails open, deliberately: a connection saved before its DNS exists (split
    horizon, a VPN that is not up, an air-gapped install) must still save. Refusing
    here would make the resolver an availability dependency of the settings page."""

    async def _fails(host, port, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _fails)
    await refuse_blocked_resolution("https://jamf.corp.internal:8443")


async def test_an_address_literal_is_not_sent_to_the_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    """validate_mdm_base_url already judged it, exhaustively — asking DNS about a
    literal only adds a way for a hostile resolver to answer for one."""

    async def _explodes(host, port, **kwargs):
        raise AssertionError(f"resolved {host}, which is already an address")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _explodes)
    await refuse_blocked_resolution("https://10.0.5.20:8443")


# --- what may come back ---------------------------------------------------------------


def _upstream(status: int, body: str, content_type: str) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        content=body.encode(),
        headers={"content-type": content_type},
        request=httpx.Request("POST", "https://jamf.example.com/api/oauth/token"),
    )


def test_security_an_upstream_body_is_bounded_before_it_is_echoed() -> None:
    """SECURITY: the test endpoint's `detail` is a read of a caller-chosen server.

    Bounded on two axes, and this pins both. A JSON error still comes back — that is
    what makes a bad credential diagnosable — but only as far as _DETAIL_MAX_CHARS.
    Anything that is not JSON comes back as a description, never as content: an HTML
    page from a host that is not Jamf is the read this endpoint must not perform.
    """
    long_json = json.dumps({"errors": ["x" * 4000], "canary": "CANARY-AT-THE-END"})
    detail = _upstream_detail(_upstream(401, long_json, "application/json"))
    assert "CANARY-AT-THE-END" not in detail
    assert "truncated" in detail
    assert len(detail) < _DETAIL_MAX_CHARS + 100

    short_json = '{"error":"invalid_client"}'
    assert "invalid_client" in _upstream_detail(_upstream(401, short_json, "application/json;charset=UTF-8"))

    page = "<html><title>CANARY-INTERNAL-SERVICE</title>" + "y" * 200 + "</html>"
    html_detail = _upstream_detail(_upstream(200, page, "text/html"))
    assert "CANARY" not in html_detail
    assert "text/html" in html_detail
    assert str(len(page)) in html_detail

    untyped = _upstream_detail(_upstream(500, "CANARY-PLAIN", ""))
    assert "CANARY" not in untyped


class _MockHttpx:
    """Stands in for the `httpx` name inside app.mdm.jamf.client.

    `test_connection` opens its own client (it is one request, outside the sweep's
    shared-client seam), so there is no transport to inject; replacing the module
    reference is the smallest thing that reaches it, and every other httpx attribute
    still resolves to the real module so `raise_for_status` raises the real error.
    """

    def __init__(self, handler) -> None:
        self._handler = handler

    # Capitalised because it is standing in for a class.
    def AsyncClient(self, **kwargs) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handler), **kwargs)

    def __getattr__(self, name: str):
        return getattr(httpx, name)


async def test_security_a_token_response_gives_back_only_known_non_secret_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SECURITY: the success path is a read primitive too, and a quieter one.

    A 200 from anything that speaks JSON used to have its whole body returned as the
    success detail, minus the single key `access_token`. This pins the allowlist that
    replaced it: the token never comes back, and neither does anything the client did
    not ask for.
    """
    from app.mdm.jamf import client as jamf_client

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "SECRET-TOKEN",
                "expires_in": 1799,
                "token_type": "Bearer",
                "internal_note": "CANARY-SOMEONE-ELSES-JSON",
            },
        )

    monkeypatch.setattr(jamf_client, "httpx", _MockHttpx(_handler))
    client = jamf_client.JamfClient(
        base_url="https://acme.jamfcloud.com", client_id="id", client_secret="secret"
    )

    assert await client.test_connection() == {"token_type": "Bearer", "expires_in": 1799}


async def test_a_200_that_is_not_a_token_response_raises_rather_than_returning_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A JSON array (or anything else that is not an object) used to reach `.items()`
    and 500 the route. The endpoint answers "that is not Jamf" instead."""
    from app.mdm.jamf import client as jamf_client

    monkeypatch.setattr(
        jamf_client,
        "httpx",
        _MockHttpx(lambda request: httpx.Response(200, json=["CANARY-LIST"])),
    )
    client = jamf_client.JamfClient(
        base_url="https://acme.jamfcloud.com", client_id="id", client_secret="secret"
    )

    with pytest.raises(ValueError, match="JSON object"):
        await client.test_connection()
