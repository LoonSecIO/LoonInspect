"""The Jamf privilege registry against the endpoints the client actually calls.

The list of privileges an operator's API Role needs was correct and complete, and lived
where nobody would find it. Moving it into the README's setup path and the connection
form fixed the finding but created three copies of one fact, which is how the one wrong
name in it ("Read Computer Inventory Collection", missing Jamf's "Settings") survived in
the first place.

So: `app.mdm.jamf.privileges` is the single copy, and these tests refuse the drift.
`client.py` is read as *source*, not imported, because the question is which paths the
code contains — a declared path nobody calls, and a called path nobody declared, are
both failures and only source text sees them. The README and the design record are read
as text for the same reason.

The pattern is `test_posture_registry.py`'s, which pins docs/posture-snapshot.md against
`app.core.posture`. Pure logic; no database, no network.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
CLIENT = _ROOT / "backend" / "app" / "mdm" / "jamf" / "client.py"
DESIGN_RECORD = _ROOT / "docs" / "jamf-observations.md"
README = _ROOT / "README.md"
REAL_RECORD = Path(__file__).resolve().parent / "fixtures" / "jamf" / "computer_inventory_detail_real.json"

# Every Jamf path the client's source contains, cut at the first interpolation:
# `f"/api/v4/computers-inventory-detail/{jamf_id}"` is the call site for the literal
# prefix `/api/v4/computers-inventory-detail/`. Anchored on `/api/` rather than on the
# quote so it also catches the two token-exchange URLs, which interpolate the base URL
# and so do not start at a quote.
_PATH_IN_SOURCE = re.compile(r"/api/[A-Za-z0-9._/-]*")

# A row of the README's privilege table: the first cell, backticked.
_README_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|")


def _paths_the_client_calls() -> set[str]:
    return set(_PATH_IN_SOURCE.findall(CLIENT.read_text()))


def _readme_privilege_table() -> list[str]:
    """First-cell names from the README table headed "Jamf Pro privilege".

    Located by its header cell rather than by the section heading above it: a heading is
    prose someone may reword, while renaming the column is an edit to the table itself,
    and this test failing is the right answer to that.
    """
    lines = README.read_text().splitlines()
    for index, line in enumerate(lines):
        if line.startswith("|") and "Jamf Pro privilege" in line:
            names = []
            for row in lines[index + 2 :]:  # +2 skips the |---|---| separator
                if not row.startswith("|"):
                    return names
                match = _README_ROW.match(row)
                if match:
                    names.append(match.group(1))
            return names
    raise AssertionError("README.md no longer carries a privilege table headed 'Jamf Pro privilege'")


def test_every_jamf_call_has_a_privilege_written_down() -> None:
    """The load-bearing one. A new endpoint in client.py fails here until someone says
    which privilege it needs — which is the only way the operator-facing list stays
    true without anyone remembering to update it."""
    from app.mdm.jamf.privileges import REQUIRED_PRIVILEGES, UNPRIVILEGED_PATHS

    declared = {path for privilege in REQUIRED_PRIVILEGES for path in privilege.paths} | set(UNPRIVILEGED_PATHS)
    called = _paths_the_client_calls()

    assert called - declared == set(), (
        "app/mdm/jamf/client.py calls a Jamf endpoint no privilege in "
        "app.mdm.jamf.privileges accounts for; the README's setup table and the "
        "connection form are now both wrong about what an API Role needs"
    )
    assert declared - called == set(), (
        "app.mdm.jamf.privileges declares a path client.py no longer calls; a privilege "
        "asked of an operator for nothing is a privilege they should not be granting"
    )


def test_the_only_unprivileged_call_is_what_test_connection_makes() -> None:
    """The finding itself, pinned. "Test connection" performs the token exchange and
    nothing else, and the token exchange needs no privilege — which is exactly why a
    role with zero read privileges tests green and then sweeps nothing. If a later
    change makes some read unprivileged, or gives the token exchange a privilege, the
    README's warning and the form's hint stop being true and this fails."""
    from app.mdm.jamf.privileges import UNPRIVILEGED_PATHS

    assert "/api/oauth/token" in UNPRIVILEGED_PATHS
    assert set(UNPRIVILEGED_PATHS) == {"/api/oauth/token", "/api/v1/jamf-pro-version"}


def test_registry_names_and_paths_are_unique() -> None:
    from app.mdm.jamf.privileges import REQUIRED_PRIVILEGES

    names = [privilege.name for privilege in REQUIRED_PRIVILEGES]
    paths = [path for privilege in REQUIRED_PRIVILEGES for path in privilege.paths]

    assert len(set(names)) == len(names), "a privilege is listed twice"
    assert len(set(paths)) == len(paths), "a path is claimed by two privileges"
    assert all(name.startswith("Read ") for name in names), (
        "every privilege this product needs is a read; a write here is a change to what "
        "the README promises, not a typo"
    )


def test_readme_table_and_registry_tell_the_same_story() -> None:
    from app.mdm.jamf.privileges import privilege_names

    assert _readme_privilege_table() == privilege_names(), (
        "README.md's privilege table must list exactly app.mdm.jamf.privileges' names, "
        "in order — an operator types these into Jamf's API Role editor verbatim"
    )


def test_the_design_record_still_names_every_privilege() -> None:
    """docs/jamf-observations.md §11 is where the list started and where a reader of the
    contract will still expect it. It may say more than the README; it may not say less."""
    from app.mdm.jamf.privileges import privilege_names

    # Whitespace collapsed because the record is hard-wrapped prose: "Read Smart Computer
    # Groups" straddles two lines there, and a test that made the doc stop reflowing to
    # satisfy a substring search would be the tail wagging the dog.
    text = " ".join(DESIGN_RECORD.read_text().split())
    missing = [name for name in privilege_names() if name not in text]
    assert missing == [], f"docs/jamf-observations.md no longer names: {missing}"


def test_the_version_the_readme_quotes_is_the_one_we_actually_read() -> None:
    """The README declines to publish a minimum Jamf Pro and quotes a verified version
    instead. That claim is only worth anything while it matches the real record in the
    fixtures — this is the whole evidence behind it."""
    from app.mdm.jamf.privileges import VERIFIED_AGAINST_JAMF_PRO

    record = json.loads(REAL_RECORD.read_text())
    binary_version = record["general"]["jamfBinaryVersion"]

    assert binary_version.split("-")[0] == VERIFIED_AGAINST_JAMF_PRO
    assert f"Jamf Pro {VERIFIED_AGAINST_JAMF_PRO}" in README.read_text()


async def test_the_providers_endpoint_serves_the_privileges_to_the_form() -> None:
    """The connection form renders whatever this returns, so the form cannot hold a
    stale list. Called directly rather than over HTTP: the route's own auth is covered
    where auth is covered, and the claim here is about the payload."""
    from app.api.routes import list_providers
    from app.mdm.jamf.privileges import privilege_names
    from app.schemas.payload import MdmProvider

    providers = await list_providers()
    jamf = next(info for info in providers if info.provider is MdmProvider.jamf)

    assert jamf.required_privileges == privilege_names()
    assert "requiredPrivileges" in jamf.model_dump(by_alias=True), "the form reads camelCase"
