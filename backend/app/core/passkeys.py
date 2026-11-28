"""Passkeys (#955): a WebAuthn credential that signs a person in, in a browser, at the host it was made at.

A passkey is one more `auth_identities` row, provider `webauthn`, several to an account; `AuthIdentity`
says what each column holds. The checks a ceremony needs are fido2's (Yubico's library,
docs/auth-design.md §9): the challenge, the relying-party hash, the signature. What this module puts
around them, each refusal with its sentence (docs/troubleshooting.md §34):

- the address (traps 1 and 2): a passkey is bound to a host name, over HTTPS or at localhost, so a request
  reached at an IP address, or over plain HTTP anywhere else, is refused before a challenge exists; and
  the origin the browser signed must be the one the challenge was handed out at, which a proxy that does
  not pass the scheme and the host through breaks, and the refusal names both;
- the challenge (trap 4): a `passkey_challenges` row that the first answer deletes, never a token a second
  answer could redeem too, because a synced passkey's signature counter stays at zero;
- the credential id (trap 3): kept whole, up to the 1,023 bytes WebAuthn allows, and refused past it;
- user verification on every ceremony, which is what lets a passkey alone sign in (default 1).

The routes are app.api.passkeys, and app.api.accounts for an administrator's removal; the policy gate that
counts a passkey sign-in as the second factor is app.core.mfa.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from fido2 import cbor
from fido2.cose import ES256, RS256, CoseKey, EdDSA
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestationConveyancePreference,
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.models.schema import Account, AuthIdentity, PasskeyChallenge, UserSession

logger = logging.getLogger(__name__)

PROVIDER = "webauthn"
# How a session a passkey signed in records it, and how a password session records the passkey it then added:
# both proved the device and the person just then, which is what the policy gate counts (app.core.mfa).
METHOD = "passkey"
METHOD_ADDED = "password+passkey"
SESSION_METHODS = frozenset({METHOD, METHOD_ADDED})
SIGN_IN = "sign-in"
REGISTER = "register"
CHALLENGE_TTL_SECONDS = 300
MAX_CREDENTIAL_ID_BYTES = 1023
MAX_NAME_LENGTH = 64
# What `rp.name` says in a browser's own dialog. The relying-party id, which a passkey is bound to, is the host.
RP_NAME = "LoonInspect"
# The keys a browser may make, in order of preference: P-256 (Apple, Google and most security keys), Ed25519
# (security keys) and RSA (Windows Hello). fido2 offers more; a browser takes the first it supports.
ALGORITHMS = (ES256.ALGORITHM, EdDSA.ALGORITHM, RS256.ALGORITHM)
_TRANSPORTS = frozenset({"usb", "nfc", "ble", "smart-card", "hybrid", "internal"})
_DEFAULT_PORTS = {"http": 80, "https": 443}

NO_ADDRESS = (
    "This request named no host, so LoonInspect cannot tell which address a passkey would be for. "
    "Open LoonInspect in a browser at its address."
)
SPENT = {
    SIGN_IN: "That passkey request was already answered or has expired. Choose Sign in with a passkey to start a new one.",
    REGISTER: "That passkey request was already answered or has expired. Choose Add a passkey to start again.",
}
UNREADABLE = (
    "The browser's answer could not be read as a passkey. Reload the page and try again; if it keeps happening, "
    "try another browser or password manager, and report the one that fails."
)
# One sentence for an unknown passkey, a removed one, a disabled account and a signature that does not verify:
# telling them apart to whoever sent the answer would say which passkeys and accounts exist.
NOT_ACCEPTED = (
    "This passkey was not accepted here: it may have been removed from its account, or the account may be "
    "disabled. Sign in with your password, or ask an administrator."
)
NOT_VERIFIED = (
    "Your device did not verify you for this passkey (a fingerprint, a face or the device's own password), and "
    "LoonInspect asks for that every time. Try again, and finish the check on the device."
)
COUNTER = (
    "This passkey's signature counter went backwards, which is how a copied security key shows itself, so it was "
    "not accepted. Sign in with your password and remove this passkey under My Account › Passkeys; if nobody "
    "copied it, tell an administrator."
)
OTHER_HOST = (
    "This passkey was made for another host than this page's, so LoonInspect cannot add it here. "
    "Add the passkey again from this page."
)
ALREADY_ADDED = "This passkey is already added here, so it was not added again."
UNSUPPORTED_KEY = (
    "This passkey uses a kind of key LoonInspect does not accept. Add one from another password manager or security key."
)
NAME_REQUIRED = (
    f"Give the passkey a name of 1 to {MAX_NAME_LENGTH} characters, such as the device or password manager that holds it."
)


class PasskeyRefused(Exception):
    """A ceremony refused: the status to answer, the sentence to show, and the reason the log and the audit
    record keep. `account_id` and `passkey_id` are set only where naming them tells the sender nothing new."""

    def __init__(self, status: int, detail: str, reason: str, *, account_id: str | None = None, passkey_id: str | None = None):
        super().__init__(detail)
        self.status, self.detail, self.reason = status, detail, reason
        self.account_id, self.passkey_id = account_id, passkey_id


# --- the address -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Address:
    """Where a page is: its scheme, its host (what a passkey made there is bound to, its relying-party id), and
    its origin as a browser writes one, the default port left out."""

    scheme: str
    host: str
    origin: str
    port: int | None = None


def parse_origin(value: str | None) -> Address | None:
    if not value:
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme, host = parts.scheme.lower(), (parts.hostname or "").rstrip(".")
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    if port == _DEFAULT_PORTS[scheme]:
        port = None
    shown = f"[{host}]" if ":" in host else host
    return Address(scheme=scheme, host=host, origin=f"{scheme}://{shown}" + (f":{port}" if port else ""), port=port)


def address_of(request: Request) -> Address | None:
    """The address a request was reached at, as this process learns it: its scheme once FORWARDED_ALLOW_IPS has had
    its say (uvicorn takes X-Forwarded-Proto from a proxy that setting names, app.serve), and its Host header."""
    host = request.headers.get("host")
    return parse_origin(f"{request.url.scheme}://{host}") if host else None


def _same_origin(value: str | None) -> str | None:
    parsed = parse_origin(value)
    return parsed.origin if parsed is not None else value


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def is_localhost(host: str) -> bool:
    return host == "localhost" or host.endswith(".localhost")


def _here(address: Address) -> str:
    return f"http://localhost:{address.port}" if address.port else "http://localhost"


def ip_address_refusal(address: Address) -> str:
    return (
        f"Passkeys need a host name, and this page was reached at {address.origin}, which is an IP address. "
        "Open LoonInspect at a host name to use one: an HTTPS address with a certificate this browser trusts, "
        f"or {_here(address)} on the machine it runs on."
    )


def plain_http_refusal(address: Address) -> str:
    return (
        f"Passkeys need HTTPS, and this page was reached at {address.origin} over plain HTTP. Serve LoonInspect over "
        "HTTPS at this host name with a certificate this browser trusts (a proxy in front that terminates TLS, or "
        f"TLS_MODE=provided), or open {_here(address)} on the machine it runs on."
    )


def proxy_refusal(browser: str, seen: str) -> str:
    return (
        f"This browser is at {browser}, and LoonInspect sees the request as {seen}. Whatever sits in front of "
        "LoonInspect changes the address on the way: a proxy that terminates HTTPS has to be named in "
        "FORWARDED_ALLOW_IPS, so that its X-Forwarded-Proto is believed, and has to pass the Host header through unchanged."
    )


def signed_origin_refusal(signed: str, expected: str) -> str:
    return (
        f"This browser signed the passkey for {signed}, and LoonInspect handed the request out at {expected}. "
        "Start again from the page at the address you use for LoonInspect; behind a proxy, check that it passes the "
        "Host header through unchanged and is named in FORWARDED_ALLOW_IPS."
    )


def too_long(length: int) -> str:
    return (
        f"This passkey's ID is {length:,} bytes long, and WebAuthn allows at most {MAX_CREDENTIAL_ID_BYTES:,}, so it "
        "was not added. Use another password manager or security key, and report the one that made this passkey."
    )


def check_address(request: Request) -> Address:
    """The address a challenge may be handed out at, or the refusal saying why no passkey can work there.

    The browser's own `Origin` header, which it sends with every POST, is compared first: when it and the address
    this process sees differ, something in front rewrote the scheme or the host, and both are named. Then the two
    rules no setting changes: a relying-party id cannot be an IP address, and a browser offers passkeys only to a
    secure page, which over plain HTTP means localhost alone.
    """
    seen = address_of(request)
    if seen is None:
        raise PasskeyRefused(400, NO_ADDRESS, "no_host")
    browser = parse_origin(request.headers.get("origin"))
    if browser is not None and browser.origin != seen.origin:
        raise PasskeyRefused(409, proxy_refusal(browser.origin, seen.origin), "proxy_rewrote_address")
    if is_ip_address(seen.host):
        raise PasskeyRefused(409, ip_address_refusal(seen), "ip_address")
    if seen.scheme != "https" and not is_localhost(seen.host):
        raise PasskeyRefused(409, plain_http_refusal(seen), "plain_http")
    return seen


# --- the challenge -----------------------------------------------------------------------------------


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


async def _issue(
    db: AsyncSession, purpose: str, address: Address, *, account_id: str | None = None, session_id: str | None = None
) -> bytes:
    """A fresh challenge's bytes, its row written. The rows of this purpose nobody answered in time go first, so the
    table holds five minutes of challenges however many are asked for."""
    now = datetime.now(UTC)
    # retention-clock: passkey-challenges — named in README.md and KNOWN_ISSUES.md §1; check-readme-claims.sh reads this token.
    await db.execute(delete(PasskeyChallenge).where(PasskeyChallenge.purpose == purpose, PasskeyChallenge.expires_at <= now))
    challenge = secrets.token_bytes(32)
    db.add(
        PasskeyChallenge(
            challenge_hash=_digest(challenge),
            purpose=purpose,
            account_id=account_id,
            session_id=session_id,
            rp_id=address.host,
            origin=address.origin,
            created_at=now,
            expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
        )
    )
    await db.flush()
    return challenge


async def _spend(db: AsyncSession, purpose: str, challenge: bytes):
    """The challenge's row, deleted by this answer and handed back, or None when none was waiting: never issued,
    already answered, or swept. One statement, so of two answers racing for a row exactly one gets it, and the
    deletion is committed before the answer is checked: a refused answer spends its challenge too."""
    result = await db.execute(
        delete(PasskeyChallenge)
        .where(PasskeyChallenge.challenge_hash == _digest(challenge), PasskeyChallenge.purpose == purpose)
        .returning(
            PasskeyChallenge.account_id,
            PasskeyChallenge.session_id,
            PasskeyChallenge.rp_id,
            PasskeyChallenge.origin,
            PasskeyChallenge.expires_at,
        )
    )
    row = result.first()
    await db.commit()
    if row is None or _aware(row.expires_at) <= datetime.now(UTC):
        return None
    return row


# --- the ceremonies ----------------------------------------------------------------------------------


def _server(rp_id: str, origin: str) -> Fido2Server:
    server = Fido2Server(
        PublicKeyCredentialRpEntity(name=RP_NAME, id=rp_id),
        attestation=AttestationConveyancePreference.NONE,
        # Exact, where fido2's default accepts any HTTPS origin under the relying-party id: the page's origin was
        # compared before this, with its sentence, and this holds the library to the same line.
        verify_origin=lambda signed: _same_origin(signed) == origin,
    )
    server.timeout = CHALLENGE_TTL_SECONDS * 1000
    server.allowed_algorithms = [
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=algorithm) for algorithm in ALGORITHMS
    ]
    return server


def _state(challenge: bytes) -> dict[str, Any]:
    """What fido2's `*_complete` calls compare against: the challenge this answer's row was issued for."""
    return {"challenge": websafe_encode(challenge), "user_verification": UserVerificationRequirement.REQUIRED}


def _as_json(options: Mapping[str, Any]) -> dict[str, Any]:
    """The options as plain JSON, in the shape `PublicKeyCredential.parse…OptionsFromJSON()` reads."""
    return json.loads(json.dumps(dict(options)))["publicKey"]


def _parse(kind: type[RegistrationResponse] | type[AuthenticationResponse], credential: Mapping[str, Any]):
    # Whatever fido2 cannot read, a missing field, bad base64 or CBOR, a wrong type, is one refusal.
    try:
        return kind.from_dict(credential)
    except Exception as exc:
        logger.info("passkey answer unreadable", extra={"error": type(exc).__name__})
        raise PasskeyRefused(400, UNREADABLE, "unreadable") from None


def subject_for(credential_id: bytes) -> str:
    """A passkey's `subject`: the SHA-256 of its credential id, which fits the column an id of 1,023 bytes would not."""
    return _digest(credential_id)


def passkeys_of(account: Account) -> list[AuthIdentity]:
    """The account's passkeys, oldest first, from the identities its row loaded."""
    rows = [row for row in account.identities if row.provider == PROVIDER]
    return sorted(rows, key=lambda row: (_aware(row.created_at), row.id))


async def _passkey_by_id(db: AsyncSession, credential_id: bytes) -> AuthIdentity | None:
    result = await db.execute(
        select(AuthIdentity).where(AuthIdentity.provider == PROVIDER, AuthIdentity.subject == subject_for(credential_id))
    )
    identity = result.scalar_one_or_none()
    return identity if identity is not None and identity.credential_id == credential_id else None


def _transports(credential: Mapping[str, Any]) -> list[str]:
    response = credential.get("response")
    reported = response.get("transports") if isinstance(response, Mapping) else None
    if not isinstance(reported, list):
        return []
    return sorted({value for value in reported if isinstance(value, str) and value in _TRANSPORTS})


async def begin_sign_in(db: AsyncSession, address: Address) -> dict[str, Any]:
    """A sign-in challenge. It names nobody, so it allows any passkey this host holds: a browser lists the ones it
    has, and the answer says which it used."""
    challenge = await _issue(db, SIGN_IN, address)
    options, _ = _server(address.host, address.origin).authenticate_begin(
        user_verification=UserVerificationRequirement.REQUIRED, challenge=challenge
    )
    return _as_json(options)


async def finish_sign_in(db: AsyncSession, credential: Mapping[str, Any]) -> tuple[Account, AuthIdentity]:
    """The account a passkey's answer signs in, and the passkey, its counter and last use moved; or a refusal."""
    answer = _parse(AuthenticationResponse, credential)
    client = answer.response.client_data
    row = await _spend(db, SIGN_IN, client.challenge)
    if row is None:
        raise PasskeyRefused(401, SPENT[SIGN_IN], "challenge_spent")
    if client.type != "webauthn.get" or client.cross_origin:
        raise PasskeyRefused(400, UNREADABLE, "unreadable")
    signed = _same_origin(client.origin)
    if signed != row.origin:
        raise PasskeyRefused(401, signed_origin_refusal(str(signed), row.origin), "origin_mismatch")
    data = answer.response.authenticator_data
    identity = await _passkey_by_id(db, answer.raw_id)
    if identity is None or identity.rp_id != row.rp_id or data.rp_id_hash != hashlib.sha256(row.rp_id.encode()).digest():
        raise PasskeyRefused(401, NOT_ACCEPTED, "not_accepted")
    if not data.is_user_present() or not data.is_user_verified():
        raise PasskeyRefused(401, NOT_VERIFIED, "not_verified")
    stored = AttestedCredentialData.create(Aaguid.NONE, identity.credential_id, CoseKey.parse(cbor.decode(identity.public_key)))
    try:
        _server(row.rp_id, row.origin).authenticate_complete(_state(client.challenge), [stored], answer)
    except ValueError:
        raise PasskeyRefused(401, NOT_ACCEPTED, "not_accepted") from None
    account = await db.get(Account, identity.account_id)
    handle = answer.response.user_handle
    if (
        account is None
        or account.status != "active"
        or account.is_service_account
        or (handle is not None and handle != account.id.encode())
    ):
        raise PasskeyRefused(401, NOT_ACCEPTED, "not_accepted")
    # Zero, then zero, is a synced passkey, which never counts; anything else has to climb.
    previous = identity.sign_count or 0
    if (data.counter or previous) and data.counter <= previous:
        raise PasskeyRefused(401, COUNTER, "counter_went_backwards", account_id=account.id, passkey_id=identity.id)
    identity.sign_count = data.counter
    identity.backed_up = data.is_backed_up()
    identity.last_used_at = datetime.now(UTC)
    return account, identity


async def begin_registration(db: AsyncSession, address: Address, account: Account, session: UserSession) -> dict[str, Any]:
    """A registration challenge for `account`, from `session`: a discoverable credential, user verification
    required, no attestation asked for (default 3), and the account's passkeys at this host excluded, so a
    device that already holds one says so rather than making a second."""
    challenge = await _issue(db, REGISTER, address, account_id=account.id, session_id=session.id)
    held = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY, id=row.credential_id, transports=row.transports or None
        )
        for row in passkeys_of(account)
        if row.rp_id == address.host and row.credential_id
    ]
    options, _ = _server(address.host, address.origin).register_begin(
        # The account id as the user handle: opaque, stable, and what a sign-in's answer is checked against.
        PublicKeyCredentialUserEntity(id=account.id.encode(), name=account.email, display_name=account.display_name),
        held,
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.REQUIRED,
        challenge=challenge,
        extensions={"credProps": True},
    )
    return _as_json(options)


def clean_name(name: str) -> str:
    label = " ".join(name.split())
    if not 1 <= len(label) <= MAX_NAME_LENGTH:
        raise PasskeyRefused(422, NAME_REQUIRED, "name")
    return label


async def finish_registration(
    db: AsyncSession, account: Account, session: UserSession, credential: Mapping[str, Any], name: str
) -> AuthIdentity:
    """The passkey a registration's answer adds to `account`, written and not yet committed; or a refusal."""
    label = clean_name(name)
    answer = _parse(RegistrationResponse, credential)
    client = answer.response.client_data
    row = await _spend(db, REGISTER, client.challenge)
    if row is None or row.account_id != account.id or row.session_id != session.id:
        raise PasskeyRefused(409, SPENT[REGISTER], "challenge_spent")
    if client.type != "webauthn.create" or client.cross_origin:
        raise PasskeyRefused(400, UNREADABLE, "unreadable")
    signed = _same_origin(client.origin)
    if signed != row.origin:
        raise PasskeyRefused(409, signed_origin_refusal(str(signed), row.origin), "origin_mismatch")
    if len(answer.raw_id) > MAX_CREDENTIAL_ID_BYTES:
        raise PasskeyRefused(422, too_long(len(answer.raw_id)), "credential_id_too_long")
    data = answer.response.attestation_object.auth_data
    if data.rp_id_hash != hashlib.sha256(row.rp_id.encode()).digest():
        raise PasskeyRefused(409, OTHER_HOST, "other_host")
    if not data.is_user_present() or not data.is_user_verified():
        raise PasskeyRefused(409, NOT_VERIFIED, "not_verified")
    try:
        data = _server(row.rp_id, row.origin).register_complete(_state(client.challenge), answer)
    except ValueError:
        raise PasskeyRefused(400, UNREADABLE, "unreadable") from None
    made = data.credential_data
    if made is None or made.credential_id != answer.raw_id:
        raise PasskeyRefused(400, UNREADABLE, "unreadable")
    # COSE label 3 is the key's algorithm: one of the kinds the challenge offered, or the key is refused.
    if made.public_key.get(3) not in ALGORITHMS:
        raise PasskeyRefused(409, UNSUPPORTED_KEY, "unsupported_key")
    if await _passkey_by_id(db, made.credential_id) is not None:
        raise PasskeyRefused(409, ALREADY_ADDED, "already_added")
    identity = AuthIdentity(
        account_id=account.id,
        provider=PROVIDER,
        subject=subject_for(made.credential_id),
        credential_id=bytes(made.credential_id),
        public_key=cbor.encode(made.public_key),
        sign_count=data.counter,
        transports=_transports(credential),
        backup_eligible=data.is_backup_eligible(),
        backed_up=data.is_backed_up(),
        rp_id=row.rp_id,
        name=label,
        created_at=datetime.now(UTC),
    )
    db.add(identity)
    await db.flush()
    return identity


async def remove(db: AsyncSession, identities: Iterable[AuthIdentity], *, end_their_sessions: bool) -> None:
    """Delete passkeys. Every session one signed in lets go of it first (`sessions.identity_id` points at it), and
    with `end_their_sessions` those sessions end too: a passkey removed for a lost device takes that device's
    sessions with it. An administrator's removal ends every session the account has, before this."""
    rows = list(identities)
    ids = [row.id for row in rows]
    if not ids:
        return
    if end_their_sessions:
        await db.execute(
            update(UserSession)
            .where(UserSession.identity_id.in_(ids), UserSession.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
    await db.execute(update(UserSession).where(UserSession.identity_id.in_(ids)).values(identity_id=None))
    for row in rows:
        await db.delete(row)
