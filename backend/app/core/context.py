from __future__ import annotations

import uuid
from contextvars import ContextVar, Token
from dataclasses import dataclass, replace

# Set once per request by RequestContextMiddleware and read by the log formatters, so
# every line emitted while handling a request carries the same id without any call
# site having to thread it through.
_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_actor: ContextVar[Actor | None] = ContextVar("actor", default=None)
_client: ContextVar[ClientInfo | None] = ContextVar("client", default=None)


@dataclass(frozen=True, slots=True)
class Actor:
    """Who is responsible for the current unit of work, and which tenant they act for.

    Carrying `label` alongside `id` is deliberate — audit records need to stay readable
    after an account is renamed or an IdP rewrites an email, so the human-facing value
    is captured at the moment of the action rather than resolved later.

    `tenant_id` is here for the audit trail's benefit: an audit record has to say which
    tenant an action belonged to, and reading it off the actor keeps that out of every
    call site. It is not what scopes database access — app.core.tenancy holds that, and
    app.core.database is the only reader — but the two are set together at
    authentication and must agree.
    """

    type: str  # account | api_token | system | anonymous
    id: str | None = None
    label: str = "-"
    tenant_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class ClientInfo:
    """Where the current request came from.

    Carried in context rather than passed down so audit() stays a one-liner at call
    sites instead of threading a Request through every service function.
    """

    ip: str | None = None
    user_agent: str | None = None


SYSTEM = Actor(type="system", label="system")
ANONYMOUS = Actor(type="anonymous", label="-")
NO_CLIENT = ClientInfo()


def system_actor_for(tenant_id: uuid.UUID) -> Actor:
    """The system actor, acting for one tenant.

    Scheduler jobs have no requesting user but they do have a tenant, and an audit
    record saying "system did this" without saying whose data it touched is not much of
    a record. The catalog sync's global half is the one job that correctly uses bare
    SYSTEM — the Jamf patch corpus belongs to no tenant. Its second half, the
    per-tenant catalog refresh, currently rides along under that same bare SYSTEM: an
    attribution drift (the session is still tenant-scoped; only the audit label loses
    the tenant), tracked separately rather than fixed here.
    """
    return replace(SYSTEM, tenant_id=tenant_id)


def get_request_id() -> str | None:
    return _request_id.get()


def set_request_id(request_id: str) -> Token[str | None]:
    return _request_id.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    _request_id.reset(token)


def get_actor() -> Actor:
    return _actor.get() or ANONYMOUS


def set_actor(actor: Actor) -> Token[Actor | None]:
    return _actor.set(actor)


def reset_actor(token: Token[Actor | None]) -> None:
    _actor.reset(token)


def get_client() -> ClientInfo:
    return _client.get() or NO_CLIENT


def set_client(client: ClientInfo) -> Token[ClientInfo | None]:
    return _client.set(client)


def reset_client(token: Token[ClientInfo | None]) -> None:
    _client.reset(token)
