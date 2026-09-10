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
#                in a single-tenant deployment. The switcher exists in code (#36:
#                `account_tenants`, `POST /api/auth/switch-tenant`, the Navbar's
#                select) and is hidden while an account holds one membership, which
#                is every account on every pod until the tenant management surface
#                (#30) can create a second tenant and grant one.
#
# Fixed rather than generated. Tenant ids are internal — never a URL parameter, never
# supplied by a caller, and never compared across installations — so there is nothing
# for a predictable value to leak or unlock, and a stable one means the RLS session
# variable is legible in a psql session and a log line without a lookup first.
ROOT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
OPERATIONAL_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")

ROOT_TENANT_SLUG = "root"
OPERATIONAL_TENANT_SLUG = "default"

# The tenant a request is scoped to *before* it has been authenticated.
#
# Something has to be bound before authentication can read anything, and this is that
# something. It is deliberately not the same idea as the acting tenant: authentication
# replaces it with whatever the credential names (see app.core.auth.authenticate).
#
# Since #35 the credential's tenant no longer depends on this value. A session cookie
# or an API token is resolved through `session_tenants` / `api_token_tenants` — two
# tables outside row-level security holding a hash and a tenant id and nothing else —
# and the request is rebound to the tenant they name before the tenant-scoped row is
# read. So a session minted in a second operational tenant resolves exactly as one in
# the first does. What this constant still scopes is the pre-authentication surface
# that is inherently about one tenant: login and setup read `accounts` and the lockout
# counter here, and an unauthenticated public route keeps it for its whole life. Which
# tenant a *login* is for, once there is more than one, is #30's question — the tenant
# management surface — not this module's.
IDENTITY_RESOLUTION_TENANT_ID = OPERATIONAL_TENANT_ID

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
