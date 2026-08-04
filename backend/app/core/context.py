from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass

# Set once per request by RequestContextMiddleware and read by the log formatters, so
# every line emitted while handling a request carries the same id without any call
# site having to thread it through.
_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_actor: ContextVar["Actor | None"] = ContextVar("actor", default=None)
_client: ContextVar["ClientInfo | None"] = ContextVar("client", default=None)


@dataclass(frozen=True, slots=True)
class Actor:
    """Who is responsible for the current unit of work.

    Auth populates this in a later phase; for now everything is SYSTEM (scheduler
    jobs, startup) or ANONYMOUS (inbound requests). Carrying `label` alongside `id`
    is deliberate — audit records need to stay readable after an account is renamed
    or an IdP rewrites an email, so the human-facing value is captured at the moment
    of the action rather than resolved later.
    """

    type: str  # account | api_token | system | anonymous
    id: str | None = None
    label: str = "-"


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
