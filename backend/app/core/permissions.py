from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum


class Role(StrEnum):
    admin = "admin"
    analyst = "analyst"
    auditor = "auditor"
    viewer = "viewer"


class Permission(StrEnum):
    """What an endpoint requires, as opposed to who the caller is.

    Endpoints depend on these rather than on role names so that adding a role is a
    change to ROLE_PERMISSIONS below — data — instead of an edit to every route that
    needs to know about it.
    """

    DEVICE_READ = "device:read"
    APP_READ = "app:read"
    VULN_READ = "vuln:read"

    # Connection configuration and credential *metadata*: rotation dates, last
    # successful auth, the 3-character fingerprint. Enough to audit credential hygiene.
    CONNECTION_READ = "connection:read"
    CONNECTION_WRITE = "connection:write"
    # Deliberately separate from CONNECTION_READ: this covers operations that use or
    # reveal the live secret, which is what keeps the read-only Auditor role safe to
    # hand to someone outside the team.
    CONNECTION_CREDENTIAL_READ = "connection:credential-read"

    # Triggers an outbound refresh of Jamf's public patch catalog. Not sensitive, but
    # it hits a third party, so it isn't something a read-only role should be able to
    # fire in a loop.
    PATCH_CATALOG_SYNC = "patch:catalog-sync"

    # Trigger an on-demand inventory pull from an MDM. Not a configuration change, so
    # it isn't CONNECTION_WRITE — but it does hit a third-party API and write inventory,
    # so it stays off the read-only roles.
    DEVICE_SYNC = "device:sync"

    FEATURE_FLAG_WRITE = "feature-flag:write"

    ACCOUNT_READ = "account:read"
    ACCOUNT_WRITE = "account:write"

    AUDIT_READ = "audit:read"

    # Mint a personal API token for one's own account. Withheld from Viewer not because
    # a Viewer's token would be dangerous — a token can never exceed its owner — but to
    # keep long-lived credentials off accounts with no automation story.
    TOKEN_CREATE = "token:create"


_INVENTORY_READ = frozenset(
    {
        Permission.DEVICE_READ,
        Permission.APP_READ,
        Permission.VULN_READ,
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    Role.viewer.value: _INVENTORY_READ,
    Role.analyst.value: _INVENTORY_READ
    | {
        Permission.CONNECTION_READ,
        Permission.PATCH_CATALOG_SYNC,
        Permission.DEVICE_SYNC,
        Permission.AUDIT_READ,
        Permission.TOKEN_CREATE,
    },
    # Read-only admin: sees configuration, accounts, and history, writes nothing, and
    # never touches a live secret. A strict subset of admin, which is what makes it
    # safe to grant to an outside reviewer.
    Role.auditor.value: _INVENTORY_READ
    | {
        Permission.CONNECTION_READ,
        Permission.ACCOUNT_READ,
        Permission.AUDIT_READ,
        Permission.TOKEN_CREATE,
    },
    # Every permission, including ones added after this line was written — a new
    # permission silently locking admins out of a feature would be the worse failure.
    Role.admin.value: frozenset(Permission),
}


def permissions_for(roles: Iterable[str]) -> frozenset[Permission]:
    """Union of everything the given roles grant. Unknown role names contribute
    nothing rather than raising, so a stale grant left by a future IdP sync degrades
    to less access instead of a broken request."""
    granted: set[Permission] = set()
    for role in roles:
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)
