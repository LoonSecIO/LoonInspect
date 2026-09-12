"""The Jamf Pro sign-in a connection keeps between runs (#412).

Jamf Pro's API clients sign in with an OAuth client-credentials exchange, and the token
that comes back is short-lived — 179 seconds on the tenants measured (`_token_lifetime` in
app.mdm.jamf.client). A `JamfClient` has always kept its token for the one run it serves
(#221). This module keeps it for the *connection*, across runs, in one of three modes chosen
on the connection:

- **No cache** (`no_cache`): nothing is kept. Every run and every webhook signs in on its
  own connection to Jamf, as before #412.
- **Cache and hold** (`cache_and_hold`, the default): the connection holds its token, the
  lock that makes one expiry cost one token request, and one pooled HTTP client. Runs and
  webhooks borrow them, and a new token is requested only when a request needs one — free
  while the fleet is quiet.
- **Perpetual cache** (`perpetual`): the same, plus a renewal that replaces the token before
  it expires, so the first webhook after a quiet spell finds one ready. It costs a token
  request per lifetime whether or not anything arrives — about 580 a day at 179 seconds.

What is shared is the sign-in, never the client. A `JamfClient` also carries its run's 429
counters and adaptive width, which the run copies onto its own row (app.mdm.service), so
every run still gets a fresh client that *borrows* the connection's token and pool.

A held sign-in is stamped with what it was built from — the base URL, a hash of the
credentials, the User-Agent override and the mode — and one whose stamp no longer matches is
retired, never reused: a rotated secret must not keep signing in as the old one. Retiring
cancels the renewal and closes the pool once the last run using it lets go, so a settings
change in the middle of a sweep never pulls the connection out from under it.

Tokens live in this process's memory only — never logged, never persisted, gone with the
process — keyed by tenant and connection, not by connection id alone (#143).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

import httpx

if TYPE_CHECKING:
    from app.mdm.jamf.client import JamfClient

logger = logging.getLogger(__name__)

MODE_NO_CACHE = "no_cache"
MODE_CACHE_AND_HOLD = "cache_and_hold"
MODE_PERPETUAL = "perpetual"
TOKEN_CACHE_MODES = (MODE_NO_CACHE, MODE_CACHE_AND_HOLD, MODE_PERPETUAL)
# Ruled by Kyle, 2026-09-12 (#412): the saving where it matters — bursts — and nothing
# spent while nothing happens.
DEFAULT_TOKEN_CACHE_MODE = MODE_CACHE_AND_HOLD

# The pool a connection's runs share. Sized for a sweep's ceiling of four requests in
# flight (#74) with room for webhooks that arrive during it; a request past the limit waits
# for a free connection rather than failing.
POOL_MAX_CONNECTIONS = 16
POOL_MAX_KEEPALIVE = 8
# How long an idle pooled connection is kept for the next request. Measured 2026-09-12:
# Jamf Cloud reused an idle connection after every gap tried, 5 s through 240 s, so its own
# idle close is past four minutes. Not stretched toward that: the firewalls and NAT between
# a customer and Jamf can forget an idle connection sooner, and one forgotten silently
# stalls a request for the whole read timeout instead of failing fast. Two minutes covers
# a burst, and the pool gives the connection up before anything in the path is likely to.
KEEPALIVE_EXPIRY_SECONDS = 120.0
REQUEST_TIMEOUT_SECONDS = 30.0

# A failed renewal waits, doubling, before trying again — and never takes the connection
# down: until a renewal succeeds, each read signs in as it needs to, as under Cache and hold.
RENEWAL_BACKOFF_START_SECONDS = 30.0
RENEWAL_BACKOFF_CAP_SECONDS = 600.0

# Seams for the tests: the renewal waits and reads the clock through these, so a test can
# run a day of renewals in a moment. Attributes read at call time, so monkeypatching the
# module reaches every renewal.
_sleep = asyncio.sleep
_now = time.monotonic


def clock() -> float:
    """The clock token lifetimes are measured on — monotonic, so NTP stepping the wall
    clock never ages a token early or late. Read through `_now` at call time, so a test's
    fake clock reaches the client and the renewal alike."""
    return _now()


@dataclass(eq=False)
class TokenState:
    """A token, when to stop sending it, and the lock that makes one expiry cost one token
    request (#221). Owned by one `JamfClient` for one run, or by a `HeldSignIn` for a
    connection. `expires_at` is monotonic; None means Jamf named no lifetime, and only a 401
    will say the token is gone."""

    token: str | None = None
    expires_at: float | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class _Credentials(Protocol):
    client_id: str
    client_secret: str


def new_http_client() -> httpx.AsyncClient:
    """The pooled client a held sign-in lends its runs. A function, so the tests can swap
    in a mock transport."""
    return httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS,
        limits=httpx.Limits(
            max_connections=POOL_MAX_CONNECTIONS,
            max_keepalive_connections=POOL_MAX_KEEPALIVE,
            keepalive_expiry=KEEPALIVE_EXPIRY_SECONDS,
        ),
    )


def stamp(base_url: str, credentials: _Credentials, user_agent_override: str | None, mode: str) -> str:
    """What a held sign-in was built from, hashed: never the secret, and never comparable
    to it. Any difference retires the held sign-in rather than reusing it."""
    material = "\x1f".join(
        (base_url.rstrip("/"), credentials.client_id, credentials.client_secret, user_agent_override or "", mode)
    )
    return hashlib.sha256(material.encode()).hexdigest()


class HeldSignIn:
    """One connection's sign-in, kept between runs: its token state, one pooled HTTP
    client, and — under Perpetual cache — the renewal that keeps the token live."""

    def __init__(
        self,
        key: tuple[str, int],
        stamp: str,
        mode: str,
        make_client: Callable[[HeldSignIn], JamfClient],
    ) -> None:
        self.key = key
        self.stamp = stamp
        self.mode = mode
        self.tokens = TokenState()
        self._make_client = make_client
        self._http: httpx.AsyncClient | None = None
        self._leases = 0
        self._retired = False
        self._renewal: asyncio.Task[None] | None = None

    @property
    def retired(self) -> bool:
        return self._retired

    @property
    def renewing(self) -> bool:
        return self._renewal is not None and not self._renewal.done()

    def client(self) -> JamfClient:
        """A fresh client for one run, borrowing this sign-in."""
        return self._make_client(self)

    @asynccontextmanager
    async def lease(self) -> AsyncIterator[httpx.AsyncClient]:
        """The pooled client, for the length of one run. A retired sign-in still lends one
        — to a run that started before it was retired — and closes it when that run lets go."""
        if self._http is None:
            self._http = new_http_client()
        http = self._http
        self._leases += 1
        try:
            yield http
        finally:
            self._leases -= 1
            if self._retired and self._leases == 0:
                await self._close()

    def start_renewal(self) -> None:
        """Start the Perpetual cache renewal unless it is already running. Needs the event
        loop the app runs on, which is where every caller already is."""
        if self._retired or self.renewing:
            return
        self._renewal = asyncio.get_running_loop().create_task(
            renew_until_retired(self), name=f"jamf sign-in renewal {self.key[1]}"
        )

    async def retire(self) -> None:
        """Stop renewing, and close the pool once no run is using it."""
        self._retired = True
        renewal, self._renewal = self._renewal, None
        if renewal is not None and not renewal.done() and renewal is not asyncio.current_task():
            renewal.cancel()
            with suppress(asyncio.CancelledError):
                await renewal
        if self._leases == 0:
            await self._close()

    async def _close(self) -> None:
        http, self._http = self._http, None
        if http is not None:
            await http.aclose()


async def renew_until_retired(held: HeldSignIn) -> None:
    """Perpetual cache: keep a live token held, replacing each one when it enters its
    refresh margin — the deadline `_token_lifetime` already put on it — never on a fixed
    interval. A renewal takes the same lock a run's sign-in does, so the two never both
    mint a token. A failure is logged, waited out with doubling backoff, and costs nothing
    else: until a renewal succeeds, each read signs in as it needs to."""
    backoff = RENEWAL_BACKOFF_START_SECONDS
    tenant_id, connection_id = held.key
    while not held.retired:
        tokens = held.tokens
        if tokens.token is not None and tokens.expires_at is None:
            logger.info(
                "jamf pro named no lifetime for the token, so perpetual cache holds it instead of "
                "renewing it; it is replaced when a request is refused",
                extra={"tenant_id": tenant_id, "connection_id": connection_id},
            )
            return
        due = 0.0 if tokens.token is None or tokens.expires_at is None else max(0.0, tokens.expires_at - clock())
        await _sleep(due)
        if held.retired:
            return
        try:
            await held.client().sign_in()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # every failure is logged and retried; none may end the loop
            logger.warning(
                "could not renew the Jamf Pro sign-in: %s. Retrying in %d s; until then each read "
                "signs in as it needs to. Test connection on this connection checks its credentials "
                "and base URL",
                _describe(exc),
                int(backoff),
                extra={"tenant_id": tenant_id, "connection_id": connection_id, "retry_in_seconds": int(backoff)},
            )
            await _sleep(backoff)
            backoff = min(backoff * 2, RENEWAL_BACKOFF_CAP_SECONDS)
        else:
            backoff = RENEWAL_BACKOFF_START_SECONDS


def _describe(exc: BaseException) -> str:
    """The failure in one line: an HTTP status says it with its address (never a body,
    never a credential — the token request carries those in its form data); anything else
    by name."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"Jamf Pro answered {exc.response.status_code} on {exc.request.url.path}"
    return type(exc).__name__


class SignIns:
    """Every held sign-in in this process, by (tenant, connection)."""

    def __init__(self) -> None:
        self._held: dict[tuple[str, int], HeldSignIn] = {}
        # Retirements started from synchronous code (a stamp found stale while building a
        # client) run as tasks; kept here so they are not garbage-collected mid-close.
        self._retiring: set[asyncio.Task[None]] = set()

    def held_for(
        self,
        connection: Any,
        credentials: _Credentials,
        make_client: Callable[[HeldSignIn], JamfClient],
    ) -> HeldSignIn | None:
        """The connection's held sign-in under its mode — built, reused, or (after any
        settings change) replaced — or None under No cache. Under Perpetual cache, also
        makes sure the renewal is running."""
        key = (str(connection.tenant_id), connection.id)
        mode = connection.token_cache_mode or DEFAULT_TOKEN_CACHE_MODE
        current = self._held.get(key)
        if mode == MODE_NO_CACHE:
            if current is not None:
                self._retire_soon(key)
            return None
        fresh = stamp(connection.base_url, credentials, connection.user_agent_override, mode)
        if current is not None and current.stamp != fresh:
            self._retire_soon(key)
            current = None
        if current is None:
            current = HeldSignIn(key, fresh, mode, make_client)
            self._held[key] = current
        if mode == MODE_PERPETUAL:
            current.start_renewal()
        return current

    def get(self, tenant_id: str, connection_id: int) -> HeldSignIn | None:
        return self._held.get((tenant_id, connection_id))

    async def forget(self, tenant_id: str, connection_id: int) -> None:
        """Retire a connection's held sign-in now — after its settings changed, or it was
        deactivated or deleted. The next run builds a new one from the row as it stands."""
        held = self._held.pop((tenant_id, connection_id), None)
        if held is not None:
            await held.retire()

    async def retire_absent(self, tenant_id: str, keep: set[int]) -> None:
        """Retire every held sign-in of this tenant whose connection is not in `keep` —
        deleted, deactivated, or switched to No cache since it was built."""
        for held_tenant, connection_id in list(self._held):
            if held_tenant == tenant_id and connection_id not in keep:
                await self.forget(held_tenant, connection_id)

    async def close_all(self) -> None:
        """Shutdown: stop every renewal and close every pool."""
        for key in list(self._held):
            await self.forget(*key)
        if self._retiring:
            await asyncio.gather(*self._retiring, return_exceptions=True)

    def _retire_soon(self, key: tuple[str, int]) -> None:
        held = self._held.pop(key, None)
        if held is None:
            return
        task = asyncio.get_running_loop().create_task(held.retire())
        self._retiring.add(task)
        task.add_done_callback(self._retiring.discard)


# The process's registry. One uvicorn process serves the app (app.serve), so one registry
# is every held sign-in there is.
SIGN_INS = SignIns()
