from __future__ import annotations

import uuid
from contextvars import ContextVar, Token

# The Postgres session variable every row-level security policy reads. Namespaced
# (`looninspect.`) because an unqualified name is not a legal custom GUC.
#
# Set per transaction, never per connection: connections are pooled and handed to
# whichever request needs one next, so a value that outlived its transaction would be
# a cross-tenant read waiting to happen. app.core.database binds it on every
# transaction start; see the after_begin listener there.
TENANT_GUC = "looninspect.tenant_id"

# Two tenants exist from install time, per the contract's bootstrap:
#
#   root         management only. Owns nothing operational — it exists so that
#                administering tenants is itself a tenant-scoped action rather than a
#                privileged side channel, once the management surface lands.
#   operational  the tenant every device, connection, account, and event belongs to
#                in a single-tenant deployment. The switcher exists in code and is
#                hidden while there is only one of these.
#
# Fixed rather than generated. Tenant ids are internal — never a URL parameter, never
# supplied by a caller, and never compared across installations — so there is nothing
# for a predictable value to leak or unlock, and a stable one means the RLS session
# variable is legible in a psql session and a log line without a lookup first.
ROOT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
OPERATIONAL_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")

ROOT_TENANT_SLUG = "root"
OPERATIONAL_TENANT_SLUG = "default"

_tenant_id: ContextVar[uuid.UUID | None] = ContextVar("tenant_id", default=None)


def get_tenant_id() -> uuid.UUID | None:
    """The tenant the current unit of work belongs to, or None outside one.

    None is not a wildcard. A database session opened without a tenant leaves the GUC
    unset, and every RLS policy then fails the query outright rather than matching
    everything — see app.core.database.
    """
    return _tenant_id.get()


def set_tenant_id(tenant_id: uuid.UUID) -> Token[uuid.UUID | None]:
    return _tenant_id.set(tenant_id)


def reset_tenant_id(token: Token[uuid.UUID | None]) -> None:
    _tenant_id.reset(token)
