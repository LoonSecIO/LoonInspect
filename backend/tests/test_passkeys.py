"""Passkeys' pure rules (#955): which address can hold a passkey, how an origin is compared, and which sessions the
policy counts as answered by one. No database; the ceremonies themselves are tests/test_passkeys_db.py."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.requests import Request

from app.core import mfa, passkeys


def _request(scheme: str, host: str | None, origin: str | None = None) -> Request:
    headers = [(b"host", host.encode())] if host is not None else []
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    return Request({"type": "http", "method": "POST", "scheme": scheme, "path": "/", "headers": headers, "query_string": b""})


@pytest.mark.parametrize(
    ("value", "origin", "host"),
    [
        ("https://Inspect.Example.COM", "https://inspect.example.com", "inspect.example.com"),
        ("https://inspect.example.com:443", "https://inspect.example.com", "inspect.example.com"),
        ("http://localhost:80", "http://localhost", "localhost"),
        ("http://localhost:8001", "http://localhost:8001", "localhost"),
        ("https://inspect.example.com.:8443", "https://inspect.example.com:8443", "inspect.example.com"),
        ("http://[::1]:8001", "http://[::1]:8001", "::1"),
    ],
)
def test_an_origin_is_written_the_way_a_browser_writes_one(value: str, origin: str, host: str) -> None:
    parsed = passkeys.parse_origin(value)
    assert (parsed.origin, parsed.host) == (origin, host)


@pytest.mark.parametrize("value", [None, "", "null", "ftp://inspect.example.com", "https://", "https://host:99999"])
def test_what_is_not_an_origin_is_none(value: str | None) -> None:
    assert passkeys.parse_origin(value) is None


@pytest.mark.parametrize(
    ("host", "ip", "local"),
    [
        ("10.0.0.5", True, False),
        ("127.0.0.1", True, False),
        ("::1", True, False),
        ("localhost", False, True),
        ("looninspect.localhost", False, True),
        ("localhost.example.com", False, False),
        ("inspect.example.com", False, False),
    ],
)
def test_an_ip_address_is_never_a_host_name_and_localhost_is_its_own_case(host: str, ip: bool, local: bool) -> None:
    assert (passkeys.is_ip_address(host), passkeys.is_localhost(host)) == (ip, local)


def test_the_browsers_origin_is_compared_before_the_address_rules_so_a_proxy_is_named_first() -> None:
    """Behind a proxy that terminated HTTPS without saying so, the address seen is plain HTTP: the sentence that
    helps names both addresses and the proxy's settings, not plain HTTP."""
    with pytest.raises(passkeys.PasskeyRefused) as refused:
        passkeys.check_address(_request("http", "inspect.example.com", origin="https://inspect.example.com"))
    assert refused.value.reason == "proxy_rewrote_address"
    assert "https://inspect.example.com" in refused.value.detail and "http://inspect.example.com" in refused.value.detail
    assert "FORWARDED_ALLOW_IPS" in refused.value.detail


@pytest.mark.parametrize(
    ("scheme", "host", "reason"),
    [
        ("http", "10.0.0.5:8001", "ip_address"),
        ("https", "10.0.0.5", "ip_address"),
        ("http", "inspect.example.com:8001", "plain_http"),
        ("http", None, "no_host"),
    ],
)
def test_an_address_no_passkey_can_work_at_is_refused_with_its_reason(scheme: str, host: str | None, reason: str) -> None:
    with pytest.raises(passkeys.PasskeyRefused) as refused:
        passkeys.check_address(_request(scheme, host))
    assert refused.value.reason == reason


@pytest.mark.parametrize(
    ("scheme", "host", "origin"),
    [
        ("http", "localhost:8001", "http://localhost:8001"),
        ("https", "inspect.example.com", "https://inspect.example.com"),
        ("https", "inspect.example.com", None),  # a client that sends no Origin header: nothing to compare
        ("https", "inspect.example.com", "null"),
    ],
)
def test_a_host_name_over_https_or_localhost_over_http_is_an_address_a_passkey_can_use(
    scheme: str, host: str, origin: str | None
) -> None:
    address = passkeys.check_address(_request(scheme, host, origin=origin))
    assert address.host == host.split(":")[0]


def test_the_ip_and_plain_http_sentences_name_the_address_and_what_to_open_instead() -> None:
    at_ip = passkeys.ip_address_refusal(passkeys.parse_origin("http://127.0.0.1:8001"))
    assert "http://127.0.0.1:8001" in at_ip and "http://localhost:8001" in at_ip
    plain = passkeys.plain_http_refusal(passkeys.parse_origin("http://inspect.example.com:8001"))
    assert "http://inspect.example.com:8001" in plain and "HTTPS" in plain and "http://localhost:8001" in plain
    assert "http://localhost on" in passkeys.plain_http_refusal(passkeys.parse_origin("http://inspect.example.com"))


def _account(*providers: str) -> SimpleNamespace:
    return SimpleNamespace(identities=[SimpleNamespace(provider=provider) for provider in providers])


@pytest.mark.parametrize(
    ("providers", "method", "answers"),
    [
        (("local", "webauthn"), passkeys.METHOD, True),
        (("local", "webauthn"), passkeys.METHOD_ADDED, True),
        # Holding a passkey is not using one: a password session is not the policy's answer.
        (("local", "webauthn"), "password", False),
        (("local", "webauthn"), None, False),
        # A passkey session whose passkeys have all gone answers nothing any more.
        (("local",), passkeys.METHOD, False),
    ],
)
def test_only_a_session_a_passkey_signed_in_or_added_answers_the_policy(providers, method, answers) -> None:
    assert mfa.passkey_answers(_account(*providers), method) is answers


def test_a_passkey_session_method_fits_the_column_that_records_it() -> None:
    from app.models.schema import UserSession

    width = UserSession.__table__.c.auth_method.type.length
    assert all(len(method) <= width for method in passkeys.SESSION_METHODS)
