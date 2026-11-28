"""Passkeys' pure rules (#955): which address can hold a passkey, how an origin is compared, and which sessions the
policy counts as answered by one. No database; the ceremonies themselves are tests/test_passkeys_db.py."""

from __future__ import annotations

from pathlib import Path
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


# Host names of 253 characters, the most there can be, and 254: labels of 63 and the dots between them.
_LONGEST = ".".join(["a" * 63] * 3 + ["b" * 61])
_TOO_LONG = _LONGEST + "c"


@pytest.mark.parametrize(
    "value", [None, "", "null", "ftp://inspect.example.com", "https://", "https://host:99999", f"https://{_TOO_LONG}"]
)
def test_what_is_not_an_origin_is_none(value: str | None) -> None:
    assert passkeys.parse_origin(value) is None


def test_a_host_name_of_253_characters_is_one_and_254_is_not() -> None:
    assert (len(_LONGEST), len(_TOO_LONG)) == (passkeys.MAX_HOST_LENGTH, passkeys.MAX_HOST_LENGTH + 1)
    assert passkeys.parse_origin(f"https://{_LONGEST}").host == _LONGEST
    # Refused before a challenge is written, whose `rp_id` column holds 253 characters, where it would be a 500.
    with pytest.raises(passkeys.PasskeyRefused) as refused:
        passkeys.check_address(_request("http", f"{_TOO_LONG}.localhost:8001"))
    assert (refused.value.status, refused.value.detail, refused.value.reason) == (400, passkeys.NO_ADDRESS, "no_host")


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


# --- every refusal has its line in docs/troubleshooting.md §34 (docs/diagnosability.md rule 4) -------------------

_ROOT = Path(__file__).resolve().parents[2]


def _flat(text: str) -> str:
    """Prose as a reader sees it: emphasis gone, every line break and run of spaces one space."""
    return " ".join(text.replace("*", "").split())


def _step_through() -> str:
    document = (_ROOT / "docs" / "troubleshooting.md").read_text()
    heading = '## 34. "My passkey is not offered, or it is refused"'
    assert heading in document, "§34's heading has been reworded"
    return _flat(document.split(heading, 1)[1].split("\n## ", 1)[0])


def test_every_refusal_the_server_words_is_in_the_step_through() -> None:
    """Each sentence a passkey refusal can end in, by its opening words: rewording the code without §34 fails here,
    and so does the reverse."""
    from app.api.passkeys import SESSION_ONLY

    address = passkeys.parse_origin("http://inspect.example.com:8001")
    sentences = [
        *passkeys.SPENT.values(),
        passkeys.UNREADABLE,
        passkeys.NOT_ACCEPTED,
        passkeys.NOT_VERIFIED,
        passkeys.COUNTER,
        passkeys.OTHER_HOST,
        passkeys.ALREADY_ADDED,
        passkeys.UNSUPPORTED_KEY,
        passkeys.NAME_REQUIRED,
        passkeys.NO_ADDRESS,
        passkeys.ip_address_refusal(address),
        passkeys.plain_http_refusal(address),
        passkeys.proxy_refusal("https://inspect.example.com", "http://inspect.example.com"),
        passkeys.signed_origin_refusal("https://elsewhere.example.com", "https://inspect.example.com"),
        passkeys.too_long(1024),
        SESSION_ONLY,
        "Current password is incorrect",
        "Too many failed attempts. Try again later.",
        "Passkey not found",
        "You cannot remove your own passkeys here. Remove them under My Account › Passkeys.",
        "That account has no passkeys to remove.",
    ]
    step_through = _step_through()
    for sentence in sentences:
        # Up to seven words, stopping short of the first address: the step quotes an example address, or an ellipsis.
        words = sentence.split()[:7]
        opening = " ".join(words[: next((i for i, word in enumerate(words) if "://" in word), len(words))]).rstrip(",")
        assert len(opening.split()) >= 3, f"too few words before the address to look for: {sentence}"
        assert opening in step_through, f"docs/troubleshooting.md §34 has no line for: {sentence}"


# The page's own sentences (frontend/src/i18n/en.ts), each a fragment that holds still across its placeholders.
_PAGE = (
    "No passkey can be added or used at",
    "it is an IP address, and a passkey is bound to a host name.",
    "browsers offer passkeys only over HTTPS, or over plain HTTP at localhost.",
    "This browser offers no passkeys here: it answers that it has none of its own and no way to use one",
    "Not offered at this address: it works only at",
    "A passkey answers this too: add one here, or sign out and sign in with one you added before.",
    "The passkey request was cancelled or timed out, or this browser holds no passkey for this address.",
    "No passkey was made: the request was cancelled or timed out.",
    "This device or password manager already holds a passkey for this account at this address.",
    "This browser refused a passkey at",
    "Over HTTPS, the usual cause is a certificate this browser does not trust,",
    "This browser has no passkey or security key it can use here.",
    "The passkey request failed in this browser before LoonInspect saw an answer.",
    "LoonInspect's answer did not arrive or could not be read.",
    "Every session it signed in ends, this one included if it did.",
    "Your passkeys could not be read, which is not the same as having none. Reload the page.",
    # What the page shows for a lockout in place of the server's 429 sentence (answerError), which §34 quotes too.
    "Too many failed attempts. Wait a few minutes and try again.",
)


@pytest.mark.parametrize("fragment", _PAGE)
def test_every_sentence_the_page_says_is_in_en_ts_and_the_step_through(fragment: str) -> None:
    english = _flat((_ROOT / "frontend" / "src" / "i18n" / "en.ts").read_text())
    assert fragment in english, f"frontend/src/i18n/en.ts no longer says: {fragment}"
    assert fragment in _step_through(), f"docs/troubleshooting.md §34 has no line for: {fragment}"


def test_a_name_keeps_no_invisible_characters_and_runs_of_spaces_close_up() -> None:
    # Built from code points, so no invisible character sits in this file's own source.
    hidden = "Mac" + chr(0x202E) + "Book" + chr(0x200B) + "  Pro" + chr(0x0007) + "\n"
    assert passkeys.clean_name(hidden) == "MacBook Pro"
    for name in ("", "   ", chr(0x200B) * 3, "x" * (passkeys.MAX_NAME_LENGTH + 1)):
        with pytest.raises(passkeys.PasskeyRefused) as refused:
            passkeys.clean_name(name)
        assert (refused.value.status, refused.value.detail) == (422, passkeys.NAME_REQUIRED)


@pytest.mark.parametrize(("signed", "shown"), [(None, "(no origin)"), (42, "(no origin)"), ("x" * 500, "x" * 200)])
def test_a_signed_origin_that_is_not_one_is_quoted_short(signed: object, shown: str) -> None:
    """Whoever sent the answer chose what its client data calls the origin: a sentence quotes at most 200 characters."""
    assert passkeys._same_origin(signed) == shown
