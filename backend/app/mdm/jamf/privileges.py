"""The Jamf Pro API Role privileges this client's calls require, per path.

Placement was the defect, not content. This list was already correct — and, bar one
misspelled name, complete — as a paragraph 370 lines into `docs/jamf-observations.md`,
a contract design record, referenced from nowhere an operator building an API Role
would ever look. It lives here so the README's setup table, the connection form's hint
and that design record all read one list, and so `tests/test_jamf_privileges.py` can
refuse a call in `client.py` whose privilege nobody wrote down.

Rejected: leaving it as prose in each fetch method's docstring, where half of it
already lived. A docstring cannot be served to the UI and cannot be diffed against the
paths the client actually calls — and that missing diff is exactly what let one name go
wrong unnoticed ("Read Computer Inventory Collection"; Jamf spells it with "Settings").

Names are Jamf's own, verbatim from each endpoint's `x-required-privileges` in the Jamf
Pro API reference. They are what an operator types into the API Role editor's search
box, so a near-miss is worth no more than an empty list.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class JamfPrivilege:
    """One privilege, and every path in `client.py` that needs it.

    `paths` holds the literal as it appears in the source, truncated at the first
    interpolation — the test that keeps this honest reads the source rather than
    importing the client, so a path can never be declared here and quietly not called.
    """

    name: str
    paths: tuple[str, ...]


REQUIRED_PRIVILEGES: tuple[JamfPrivilege, ...] = (
    # The only one whose absence stops the product: both inventory reads
    # `raise_for_status`, so a role without this fails every sweep and every webhook
    # fetch. Everything below degrades on purpose.
    JamfPrivilege(
        name="Read Computers",
        paths=("/api/v4/computers-inventory", "/api/v4/computers-inventory-detail/"),
    ),
    # Absent → 403, an empty group list and a log line; devices still sweep, group
    # definitions are simply not observed.
    JamfPrivilege(
        name="Read Smart Computer Groups",
        paths=("/api/v3/computer-groups/smart-groups", "/api/v3/computer-groups/smart-groups/"),
    ),
    # Absent → the aperture records `available: false`, which is an honest answer
    # rather than an error: the aperture's job is to say what a reading meant.
    JamfPrivilege(
        name="Read Computer Inventory Collection Settings",
        paths=("/api/v2/computer-inventory-collection-settings",),
    ),
    # Absent → `departmentId: "7"` is stored and filterable but resolves to no name.
    # An empty catalog never blanks names already cached (mdm.org_units upserts).
    JamfPrivilege(name="Read Departments", paths=("/api/v1/departments",)),
    JamfPrivilege(name="Read Buildings", paths=("/api/v1/buildings",)),
)

# Calls any enabled API client may make, with no privilege ticked anywhere.
#
# Not trivia: the token exchange is the *whole* of what "Test connection" performs, so
# an API Role holding none of the privileges above tests green and then sweeps nothing.
# That is the failure this module exists to make findable before it happens rather than
# an hour later in an empty run. `/v1/jamf-pro-version` is here too — Jamf requires
# authentication and no privilege for it — which is why a missing version is never the
# reason a sweep came back empty.
UNPRIVILEGED_PATHS: tuple[str, ...] = (
    "/api/oauth/token",
    "/api/v1/jamf-pro-version",
)

# The Jamf Pro this was read against, and the version the README quotes: the
# `jamfBinaryVersion` of tests/fixtures/jamf/computer_inventory_detail_real.json.
#
# Deliberately NOT called a minimum. The client calls the newest generation of every
# endpoint family (v4 inventory, v3 smart groups, v2 collection settings) and Jamf's
# API reference does not say which release first served any of them, so the earliest
# workable Jamf Pro is unknown. Claiming one would be a guess an operator would plan
# an upgrade around.
VERIFIED_AGAINST_JAMF_PRO = "11.31.1"


def privilege_names() -> list[str]:
    """The names, in the order the README table lists them."""
    return [privilege.name for privilege in REQUIRED_PRIVILEGES]
