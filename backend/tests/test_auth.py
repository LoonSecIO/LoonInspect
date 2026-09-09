"""The trust layer, without a database (#139).

Everything the auth surface decides before it touches a row — which paths need no
session, when a CSRF token is demanded, how a token's scopes narrow its owner's
permissions, the password bounds, how a presented token is split, and the lockout
arithmetic — is a pure function or one step from it. Until now all of it rode only the
RUN_DB_TESTS lane, so the no-database lane CI runs first (#127) proved nothing about
the code that decides who gets in. These tests give that lane teeth.

The lockout arithmetic is exercised through `_record_failure` itself with a fake session
and a row that already exists, rather than by extracting it: the row-exists path is the
one every failure after the first takes, and it is the same whichever way the
first-failure insert is written.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from app.api.auth import (
    _LOCKOUT_BASE_SECONDS,
    _LOCKOUT_MAX_EXPONENT,
    _LOCKOUT_MAX_SECONDS,
    _LOCKOUT_THRESHOLD,
    _record_failure,
)
from app.core import auth as auth_module
from app.core.auth import (
    _PROTECTED_NON_API,
    _PUBLIC_EXACT,
    _SAFE_METHODS,
    CSRF_HEADER,
    Principal,
    _verify_csrf,
    authenticate,
    is_public_path,
    scoped_permissions,
    session_expiry,
)
from app.core.config import settings
from app.core.permissions import ROLE_PERMISSIONS, Permission, Role, permissions_for
from app.core.security import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    tokens_equal,
    validate_password,
    verify_password,
)
from app.core.tokens import TOKEN_PREFIX, generate_token, parse_token
from app.models.schema import Account, AccountRole, ApiToken, LoginAttempt, UserSession

# --- is_public_path: the allowlist is the only door --------------------------------------


@pytest.mark.parametrize("path", sorted(_PUBLIC_EXACT))
def test_every_allowlisted_path_is_public(path: str) -> None:
    assert is_public_path(path) is True


def test_the_allowlist_is_the_five_routes_a_signed_out_browser_needs() -> None:
    """Adding to this set is the one change that can expose a route by accident, so the
    set itself is pinned: health for the container probe, status/setup/login for the
    sign-in flow, logout so an expired session can still clear its cookies."""
    assert {"/api/health", "/api/auth/status", "/api/auth/setup", "/api/auth/login", "/api/auth/logout"} == _PUBLIC_EXACT


def test_every_registered_api_route_needs_a_session_unless_allowlisted() -> None:
    """The property that matters, checked against the real router rather than a list
    someone remembered: a router added tomorrow is denied by default."""
    from app.main import app

    # The generated OpenAPI document is the flattest honest list of what is routed.
    api_paths = sorted(path for path in app.openapi()["paths"] if path.startswith("/api/"))
    assert len(api_paths) > 40, "the app has many routes; a short list here means the import found the wrong app"
    for path in api_paths:
        assert is_public_path(path) is (path in _PUBLIC_EXACT), path


@pytest.mark.parametrize(
    "path",
    [
        "/api/healthz",  # a longer name is not the allowlisted one
        "/api/health/",  # nor is its trailing-slash twin
        "/api/health/../accounts",  # traversal is compared literally, so it is not health
        "/api/auth/login/anything",  # a public route's sub-path is not public
        "/api/auth/loginx",
        "/api/auth",
        "/api/accounts",
        "/api/mdm/connections",
        "/api/",
    ],
)
def test_near_misses_of_public_paths_are_not_public(path: str) -> None:
    assert is_public_path(path) is False


@pytest.mark.parametrize("path", ["/webhooks/jamf/1", "/webhooks/anything/at/all"])
def test_webhook_receivers_are_exempt_from_session_auth(path: str) -> None:
    """Exempt, not unauthenticated: they carry their own per-connection credential."""
    assert is_public_path(path) is True


@pytest.mark.parametrize("path", sorted(_PROTECTED_NON_API))
def test_the_generated_docs_need_a_session(path: str) -> None:
    """The docs enumerate the whole API surface — free reconnaissance for anyone who
    can reach the port — so they are the one non-API surface that is not public."""
    assert is_public_path(path) is False


@pytest.mark.parametrize("path", ["/", "/login", "/settings/destinations", "/assets/index-abc123.js", "/favicon.svg"])
def test_the_spa_shell_and_its_assets_are_public(path: str) -> None:
    """There has to be a login page to log in from."""
    assert is_public_path(path) is True


# --- CSRF: demanded of cookies on unsafe methods, and of nothing else ---------------------


def _request(method: str, path: str = "/api/accounts", headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "root_path": "",
            "scheme": "https",
            "server": ("loon.example", 443),
            "query_string": b"",
            "headers": raw_headers,
        }
    )


def _session(csrf_token: str = "the-real-token") -> UserSession:
    return UserSession(tenant_id=uuid.uuid4(), account_id="acct", csrf_token=csrf_token)


def test_safe_methods_are_exactly_the_three_that_cannot_change_state() -> None:
    assert {"GET", "HEAD", "OPTIONS"} == _SAFE_METHODS


def test_a_matching_csrf_header_passes() -> None:
    assert _verify_csrf(_request("POST", headers={CSRF_HEADER: "the-real-token"}), _session()) is None


def test_the_header_name_is_matched_case_insensitively() -> None:
    assert _verify_csrf(_request("POST", headers={"x-csrf-token": "the-real-token"}), _session()) is None


@pytest.mark.parametrize(
    "supplied",
    [None, "", "the-real-tokeN", "the-real-token-and-more", "the-real", "a-different-token"],
    ids=["absent", "empty", "case", "longer", "prefix", "different"],
)
def test_a_missing_or_wrong_csrf_token_is_a_403(supplied: str | None) -> None:
    headers = {} if supplied is None else {CSRF_HEADER: supplied}
    with pytest.raises(HTTPException) as refused:
        _verify_csrf(_request("POST", headers=headers), _session())
    assert refused.value.status_code == 403
    assert refused.value.detail == "Invalid CSRF token"


def _principal_via(monkeypatch: pytest.MonkeyPatch, method: str) -> Principal:
    """Stub the credential lookups so `authenticate` runs everything *around* the
    database: the public-path short-circuit, the bearer-versus-cookie choice, the CSRF
    gate, and the tenant rebind."""
    tenant_id = uuid.uuid4()
    account = Account(id="acct", tenant_id=tenant_id, email="a@example.com", status="active")
    if method == "session":
        principal = Principal(account=account, permissions=frozenset(), auth_method="session", session=_session())
    else:
        token = ApiToken(id="tok", tenant_id=tenant_id, account_id="acct")
        principal = Principal(account=account, permissions=frozenset(), auth_method="api_token", token=token)

    async def session_lookup(db, request, response):
        return principal if method == "session" else None

    async def bearer_lookup(db, raw):
        return principal if method == "api_token" else None

    async def no_rebind(db, tenant_id):
        return None

    monkeypatch.setattr(auth_module, "_authenticate_session", session_lookup)
    monkeypatch.setattr(auth_module, "_authenticate_bearer", bearer_lookup)
    monkeypatch.setattr(auth_module, "rebind_tenant", no_rebind)
    return principal


async def test_a_cookie_session_needs_the_csrf_header_on_an_unsafe_method(monkeypatch) -> None:
    _principal_via(monkeypatch, "session")
    with pytest.raises(HTTPException) as refused:
        await authenticate(_request("POST"), Response(), db=object())
    assert refused.value.status_code == 403


async def test_a_cookie_session_does_not_need_it_on_a_safe_method(monkeypatch) -> None:
    principal = _principal_via(monkeypatch, "session")
    request = _request("GET")
    await authenticate(request, Response(), db=object())
    assert request.state.principal is principal


async def test_a_cookie_session_with_the_header_passes_on_an_unsafe_method(monkeypatch) -> None:
    principal = _principal_via(monkeypatch, "session")
    request = _request("DELETE", headers={CSRF_HEADER: "the-real-token"})
    await authenticate(request, Response(), db=object())
    assert request.state.principal is principal


async def test_a_bearer_token_is_never_asked_for_csrf(monkeypatch) -> None:
    """The browser attaches cookies to cross-site requests on its own, never an
    Authorization header, so CSRF is a cookie problem specifically."""
    principal = _principal_via(monkeypatch, "api_token")
    request = _request("POST", headers={"Authorization": "Bearer loon_pat_whatever"})
    await authenticate(request, Response(), db=object())
    assert request.state.principal is principal


async def test_a_public_path_is_not_authenticated_at_all(monkeypatch) -> None:
    async def never(*args):
        raise AssertionError("a public path must not look up a credential")

    monkeypatch.setattr(auth_module, "_authenticate_session", never)
    monkeypatch.setattr(auth_module, "_authenticate_bearer", never)
    await authenticate(_request("POST", path="/api/auth/login"), Response(), db=object())


async def test_no_credential_is_a_401(monkeypatch) -> None:
    async def nobody(*args):
        return None

    monkeypatch.setattr(auth_module, "_authenticate_session", nobody)
    monkeypatch.setattr(auth_module, "_authenticate_bearer", nobody)
    with pytest.raises(HTTPException) as refused:
        await authenticate(_request("GET"), Response(), db=object())
    assert refused.value.status_code == 401


# --- scoped_permissions: always an intersection ------------------------------------------


def _account(*roles: str) -> Account:
    account = Account(id="acct", tenant_id=uuid.uuid4(), email="a@example.com", status="active")
    account.roles = [AccountRole(account_id="acct", role=role, source="manual") for role in roles]
    return account


def test_no_scopes_means_the_owners_whole_set() -> None:
    assert scoped_permissions(_account("analyst"), None) == ROLE_PERMISSIONS["analyst"]
    assert scoped_permissions(_account("analyst"), []) == ROLE_PERMISSIONS["analyst"]


def test_scopes_narrow_to_what_the_owner_holds() -> None:
    assert scoped_permissions(_account("analyst"), ["device:read"]) == {Permission.DEVICE_READ}


def test_a_scope_the_owner_does_not_hold_grants_nothing() -> None:
    """A token cannot outrank its owner: a scope is a ceiling request, not a grant."""
    assert scoped_permissions(_account("viewer"), ["account:write"]) == frozenset()
    assert scoped_permissions(_account("viewer"), ["account:write", "device:read"]) == {Permission.DEVICE_READ}


def test_an_unknown_scope_is_dropped_not_fatal() -> None:
    assert scoped_permissions(_account("admin"), ["no:such-scope", "audit:read"]) == {Permission.AUDIT_READ}
    assert scoped_permissions(_account("admin"), ["no:such-scope"]) == frozenset()


def test_a_demoted_owner_takes_the_token_down_with_them() -> None:
    """The same scopes, evaluated against the roles the account holds *now*."""
    scopes = ["account:write", "device:read"]
    assert Permission.ACCOUNT_WRITE in scoped_permissions(_account("admin"), scopes)
    assert Permission.ACCOUNT_WRITE not in scoped_permissions(_account("viewer"), scopes)


def test_roles_union_and_unknown_roles_contribute_nothing() -> None:
    assert permissions_for(["viewer", "auditor"]) == ROLE_PERMISSIONS["auditor"] | ROLE_PERMISSIONS["viewer"]
    assert permissions_for(["stale-idp-role"]) == frozenset()
    assert permissions_for([]) == frozenset()


def test_the_role_model_holds_its_documented_shape() -> None:
    """Auditor is a strict subset of admin with no write anywhere; viewer is inventory
    reads only; nothing but admin can flip a consent (SYSTEM_WRITE)."""
    admin, auditor, analyst, viewer = (
        ROLE_PERMISSIONS[role.value] for role in (Role.admin, Role.auditor, Role.analyst, Role.viewer)
    )
    assert admin == frozenset(Permission)
    assert auditor < admin and viewer < analyst < admin
    assert not any(permission.value.endswith(":write") for permission in auditor)
    assert not any(permission.value.endswith(":write") for permission in analyst)
    assert viewer == {Permission.DEVICE_READ, Permission.APP_READ, Permission.VULN_READ}
    assert [role for role, granted in ROLE_PERMISSIONS.items() if Permission.SYSTEM_WRITE in granted] == ["admin"]
    assert [role for role, granted in ROLE_PERMISSIONS.items() if Permission.CONNECTION_CREDENTIAL_READ in granted] == ["admin"]


# --- the password bounds ----------------------------------------------------------------


def test_the_bounds_are_the_nist_ones() -> None:
    assert (MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == (12, 128)


@pytest.mark.parametrize("length", [MIN_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH + 1, MAX_PASSWORD_LENGTH])
def test_a_password_inside_the_bounds_is_accepted(length: int) -> None:
    assert validate_password("x" * length) is None


@pytest.mark.parametrize("length", [0, MIN_PASSWORD_LENGTH - 1, MAX_PASSWORD_LENGTH + 1, 10_000])
def test_a_password_outside_the_bounds_is_refused(length: int) -> None:
    with pytest.raises(PasswordPolicyError):
        validate_password("x" * length)


def test_length_counts_characters_not_bytes() -> None:
    """No composition rules: twelve characters of anything is a password."""
    assert validate_password("pässwörd-ünï") is None  # 12 characters, more bytes
    with pytest.raises(PasswordPolicyError):
        validate_password("pässwörd-ün")  # 11


def test_hashing_enforces_the_policy_and_verification_round_trips() -> None:
    with pytest.raises(PasswordPolicyError):
        hash_password("short")
    stored = hash_password("correct-horse-battery-staple")
    assert verify_password(stored, "correct-horse-battery-staple") is True
    assert verify_password(stored, "correct-horse-battery-stapl") is False


def test_no_stored_hash_is_indistinguishable_from_a_wrong_password() -> None:
    """An SSO-only account has no local password; the answer is False, and it still
    costs a verify against the dummy hash so timing does not enumerate accounts."""
    assert verify_password(None, "correct-horse-battery-staple") is False


def test_an_oversized_password_is_refused_before_it_reaches_the_kdf() -> None:
    assert verify_password(hash_password("correct-horse-battery-staple"), "x" * (MAX_PASSWORD_LENGTH + 1)) is False


def test_token_comparison_is_by_value() -> None:
    assert tokens_equal("abc", "abc") is True
    assert tokens_equal("abc", "abd") is False
    assert tokens_equal("abc", "abcd") is False
    assert tokens_equal("", "") is True


# --- parse_token: attacker-supplied input on every request --------------------------------


def test_a_minted_token_parses_back_to_its_id_and_secret() -> None:
    minted = generate_token()
    parsed = parse_token(minted.raw)
    assert parsed is not None
    assert (parsed.token_id, parsed.secret) == (minted.token_id, minted.secret)
    assert minted.raw.startswith(TOKEN_PREFIX)


def test_a_secret_with_underscores_survives_the_split() -> None:
    """base64url can contain underscores; the split is on the first one after the hex
    id, which cannot."""
    token_id = "0123456789abcdef0123456789abcdef"
    parsed = parse_token(f"{TOKEN_PREFIX}{token_id}_se_cr_et__")
    assert parsed is not None and parsed.secret == "se_cr_et__"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "loon_pat",
        "loon_pat_",
        "loon_pat_0123456789abcdef0123456789abcdef",  # no separator
        "loon_pat_0123456789abcdef0123456789abcdef_",  # empty secret
        "loon_pat__secret",  # empty id
        "loon_pat_0123456789abcdef0123456789abcde_secret",  # 31 hex
        "loon_pat_0123456789abcdef0123456789abcdef0_secret",  # 33 hex
        "loon_pat_0123456789ABCDEF0123456789ABCDEF_secret",  # uppercase is not what generate_token makes
        "loon_pat_0123456789abcdef0123456789abcdeg_secret",  # not hex
        "loon_pat_0123456789abcdef 123456789abcdef_secret",  # whitespace
        "Loon_pat_0123456789abcdef0123456789abcdef_secret",  # prefix is case-sensitive
        "pat_0123456789abcdef0123456789abcdef_secret",
        "Bearer loon_pat_0123456789abcdef0123456789abcdef_secret",
    ],
)
def test_anything_malformed_is_none_not_an_exception(raw: str) -> None:
    assert parse_token(raw) is None


# --- the lockout arithmetic, through the real function -------------------------------------


class _Rows:
    def __init__(self, row: LoginAttempt | None) -> None:
        self._row = row

    def scalar_one_or_none(self) -> LoginAttempt | None:
        return self._row


class _FakeSession:
    """Answers every lookup with the one row it holds and records the commit. Enough
    for the row-exists path, which is every failure after the first."""

    def __init__(self, row: LoginAttempt) -> None:
        self.row = row
        self.commits = 0

    async def execute(self, statement, *args, **kwargs) -> _Rows:
        return _Rows(self.row)

    def add(self, obj) -> None:  # pragma: no cover — the row exists, so nothing is added
        raise AssertionError("the row exists; nothing should be added")

    async def commit(self) -> None:
        self.commits += 1


async def _after_failures(count: int) -> LoginAttempt:
    """The row as it stands after `count` failures, the last one recorded by the real
    function."""
    row = LoginAttempt(identifier="who@example.com", ip="203.0.113.9", failure_count=count - 1)
    db = _FakeSession(row)
    await _record_failure(db, "who@example.com", "203.0.113.9")
    assert db.commits == 1 and row.failure_count == count
    return row


def _backoff(row: LoginAttempt) -> float:
    assert row.locked_until is not None
    return (row.locked_until - row.last_failure_at).total_seconds()


def test_the_lockout_constants_are_the_documented_ones() -> None:
    assert (_LOCKOUT_THRESHOLD, _LOCKOUT_BASE_SECONDS, _LOCKOUT_MAX_SECONDS, _LOCKOUT_MAX_EXPONENT) == (5, 60, 3600, 16)


@pytest.mark.parametrize("count", [1, 2, 3, 4])
async def test_below_the_threshold_nothing_is_locked(count: int) -> None:
    row = await _after_failures(count)
    assert row.locked_until is None
    assert row.last_failure_at is not None


async def test_the_threshold_itself_locks_for_the_base_backoff() -> None:
    """Five failures lock, not six: the off-by-one this pins."""
    assert _backoff(await _after_failures(5)) == 60


@pytest.mark.parametrize(("count", "seconds"), [(6, 120), (7, 240), (8, 480), (9, 960), (10, 1920)])
async def test_each_further_failure_doubles_the_backoff(count: int, seconds: int) -> None:
    assert _backoff(await _after_failures(count)) == seconds


@pytest.mark.parametrize("count", [11, 12, 21, 22, 40])
async def test_the_backoff_is_capped_at_an_hour(count: int) -> None:
    assert _backoff(await _after_failures(count)) == 3600


async def test_the_exponent_is_capped_so_a_long_attack_cannot_ask_for_two_to_the_nine_hundred() -> None:
    """Without the exponent cap `2 ** (count - 5)` for a large count is a huge integer
    computed on every failed login — the cheap denial of service the cap exists for.
    The observable answer is still the hour."""
    assert _backoff(await _after_failures(905)) == 3600
    assert _backoff(await _after_failures(10**6)) == 3600


async def test_the_lock_is_measured_from_the_failure_just_recorded() -> None:
    before = datetime.now(UTC)
    row = await _after_failures(5)
    assert before <= row.last_failure_at <= datetime.now(UTC)
    assert row.locked_until == row.last_failure_at + timedelta(seconds=60)


# --- session expiry: a lifetime of zero means no passive timer ------------------------------


def test_session_expiry_follows_the_configured_lifetime(monkeypatch) -> None:
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(settings, "session_lifetime_seconds", 3600)
    assert session_expiry(now) == now + timedelta(hours=1)
    monkeypatch.setattr(settings, "session_lifetime_seconds", 0)
    assert session_expiry(now) is None
