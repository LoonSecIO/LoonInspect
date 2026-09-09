"""Where a destination may point (#131, the other half).

`destinations.url` is the sink `base_url` is, with the scheduler as its driver: the outbox
POSTs every event there holding the destination's own credential. `app.core.egress`
bounds it twice — at the write, where the schema binds the row, and at delivery, where a
row stored before the rule or a hostname whose record has since moved can still be
refused. The accepted cases matter as much as the refused ones: a SIEM on an RFC 1918
address, `host.docker.internal`, and a webhook receiver with a token in its query string
all have to keep working.

No database and no network: the resolver is replaced where a test needs an answer from
it, and the outbox's client is replaced with one that fails the test if it dials.
"""

from __future__ import annotations

import asyncio
import socket

import httpx
import pytest
from pydantic import ValidationError

from app.core import outbox
from app.core.config import settings
from app.core.egress import BlockedDestinationUrl, refuse_blocked_resolution, validate_destination_url
from app.core.outbox import DeliveryOutcome, blocked_delivery_reason, send_test_event
from app.models.schema import Destination
from app.schemas.destinations import DestinationCreate, DestinationUpdate

# --- the refused classes, each answering with the reason ------------------------------


@pytest.mark.parametrize(
    ("url", "because"),
    [
        ("", "required"),
        ("https://" + "a" * 1100 + ".example.com", "at most 1024"),
        ("splunk.example.com:8088/services/collector", "absolute https"),
        ("ftp://splunk.example.com", "absolute https"),
        ("file:///etc/passwd", "absolute https"),
        ("http://splunk.example.com:8088/services/collector", "ALLOW_INSECURE_DESTINATION_URL"),
        ("https://someone:hunter2@splunk.example.com", "credentials in the URL"),
        ("https://hooks.example.com/ingest#fragment", "fragment"),
        ("https://splunk.example.com:notaport", "not a URL this server can parse"),
        ("https://", "must name a host"),
        ("https://127.0.0.1:8088/services/collector", "loopback address"),
        ("https://[::1]:8088", "loopback address"),
        ("https://[::ffff:127.0.0.1]", "loopback address"),
        ("https://localhost:8088/services/collector", "loopback name"),
        ("https://siem.localhost", "loopback name"),
        ("https://169.254.169.254/latest/meta-data/", "link-local"),
        ("https://169.254.170.2/v2/credentials", "link-local"),
        ("https://[fe80::1]", "link-local"),
        ("https://0.0.0.0", "unspecified"),
        ("https://224.0.0.1", "multicast"),
        ("https://240.0.0.1", "reserved"),
    ],
)
def test_a_refused_destination_url_says_which_rule_refused_it(url: str, because: str) -> None:
    with pytest.raises(BlockedDestinationUrl) as refusal:
        validate_destination_url(url)
    assert because in str(refusal.value), str(refusal.value)
    assert str(refusal.value).startswith("url "), "the message names the destination field, not baseUrl"


@pytest.mark.parametrize(
    "url",
    [
        "https://splunk.example.com:8088/services/collector",
        "https://prd-p-abcde.splunkcloud.com:443/services/collector/event",
        "https://your-cluster.es.example.com:9243",
        "https://api.runreveal.com/sources/hook/abc123",
        "https://10.0.5.20:8088/services/collector",
        "https://192.168.1.40/hook",
        "https://host.docker.internal:8088/services/collector",
        # A query string is allowed: webhook receivers carry a token or a source id there.
        "https://hooks.example.com/ingest?token=abc&source=loon",
    ],
)
def test_a_legitimate_destination_url_is_accepted(url: str) -> None:
    assert validate_destination_url(url) == url


def test_surrounding_whitespace_is_trimmed_rather_than_refused() -> None:
    assert validate_destination_url("  https://splunk.example.com:8088/services/collector \n") == (
        "https://splunk.example.com:8088/services/collector"
    )


def test_http_is_an_opt_in_and_not_a_way_round_the_address_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """ALLOW_INSECURE_DESTINATION_URL buys plaintext for a lab HEC, not a wider address
    space — and it is its own setting, not the connection one's."""
    monkeypatch.setattr(settings, "allow_insecure_destination_url", True)
    assert validate_destination_url("http://host.docker.internal:8088/services/collector") == (
        "http://host.docker.internal:8088/services/collector"
    )
    with pytest.raises(BlockedDestinationUrl, match="link-local"):
        validate_destination_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(BlockedDestinationUrl, match="loopback"):
        validate_destination_url("http://127.0.0.1:8088/services/collector")


def test_the_connection_opt_in_does_not_open_destinations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "allow_insecure_mdm_base_url", True)
    with pytest.raises(BlockedDestinationUrl, match="ALLOW_INSECURE_DESTINATION_URL"):
        validate_destination_url("http://splunk.example.com:8088/services/collector")


def test_security_the_destination_schemas_refuse_an_unvalidated_url() -> None:
    """SECURITY: the rule binds the row, not one route. The outbox reads `url` from the
    row on every tick without asking a route, so the check has to be on the schemas
    that write the column. This fails if either field goes back to a bare `str`."""
    for blocked in ("https://169.254.169.254/", "http://splunk.example.com:8088/services/collector", "https://127.0.0.1"):
        with pytest.raises(ValidationError):
            DestinationCreate(name="probe", url=blocked)
        with pytest.raises(ValidationError):
            DestinationUpdate(url=blocked)

    assert DestinationCreate(name="on-prem", url="https://siem.corp.internal:8088/services/collector").url == (
        "https://siem.corp.internal:8088/services/collector"
    )


# --- the resolver pass, named for this sink -------------------------------------------


def _resolves_to(*addresses: str):
    async def _getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in addresses]

    return _getaddrinfo


async def test_security_a_hostname_that_resolves_to_the_metadata_address_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _resolves_to("169.254.169.254"))
    with pytest.raises(BlockedDestinationUrl) as refusal:
        await refuse_blocked_resolution("https://metadata.attacker.example/hook", field="url", refusal=BlockedDestinationUrl)
    assert str(refusal.value).startswith("url may not point at metadata.attacker.example")
    assert "169.254.169.254" in str(refusal.value) and "link-local" in str(refusal.value)


async def test_an_unresolvable_hostname_is_allowed_rather_than_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fails open, as the connection rule does: an air-gapped SIEM is a supported
    destination, and a dead resolver must not turn into a dead outbox."""

    async def _fails(host, port, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _fails)
    await refuse_blocked_resolution("https://siem.corp.internal:8088", field="url", refusal=BlockedDestinationUrl)


# --- at delivery: the row as it stands ------------------------------------------------


def _destination(url: str) -> Destination:
    return Destination(name="siem", type="generic_webhook", url=url, auth_type="none", enabled=True)


async def test_a_row_stored_before_the_rule_is_refused_at_delivery_even_as_a_literal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The write-time pass never asks the resolver about a literal because the schema
    judged it; a row that predates the schema rule was never judged, so delivery judges
    literals too."""

    async def _explodes(host, port, **kwargs):
        raise AssertionError(f"resolved {host}, which is a literal")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _explodes)
    assert "loopback" in (await blocked_delivery_reason(_destination("https://127.0.0.1:8088/services/collector")) or "")
    assert "loopback name" in (await blocked_delivery_reason(_destination("https://localhost:8088/x")) or "")
    assert "link-local" in (await blocked_delivery_reason(_destination("https://169.254.169.254/x")) or "")
    assert await blocked_delivery_reason(_destination("https://10.0.5.20:8088/services/collector")) is None


async def test_a_hostname_that_moved_to_the_metadata_address_is_refused_at_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _resolves_to("169.254.169.254"))
    reason = await blocked_delivery_reason(_destination("https://siem.example.com/hook"))
    assert reason is not None and "link-local" in reason
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _resolves_to("203.0.113.10"))
    assert await blocked_delivery_reason(_destination("https://siem.example.com/hook")) is None


async def test_security_the_test_button_refuses_a_blocked_destination_without_dialling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SECURITY: POST /destinations/{id}/test is the one driver an operator can fire at
    will; it takes the same refusal, as its own verdict, and never opens a connection."""
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _resolves_to("169.254.170.2"))

    class _NeverDials(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            raise AssertionError("a blocked destination must not be dialled")

    monkeypatch.setattr(outbox.httpx, "AsyncClient", _NeverDials)
    outcome = await send_test_event(_destination("https://credentials.attacker.example/hook"))
    assert outcome == DeliveryOutcome(False, outcome.error, None)
    assert outcome.error is not None and "link-local" in outcome.error and "169.254.170.2" in outcome.error
