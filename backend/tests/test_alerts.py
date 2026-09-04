"""The NEW-app latch's decision, and the closed kind vocabulary it belongs to (#101).

`latch_delta` is the whole of what the latch decides — the database half around it only
carries the answer out — so every way the feature can be silently wrong is reachable
from here with no session: a baseline that alerts on the fleet it inherited, a version
bump that reads as an install, an uninstall that leaves the row open, a quiet pull that
still costs a query. Pure logic; no database. The end-to-end path is
`tests/test_alerts_db.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.alerts.service import KIND_LEVELS, KINDS, NEW_APP, latch_delta
from app.changes.policy import HIGH, LEVELS

DOC = Path(__file__).resolve().parents[2] / "docs" / "alerts.md"

# Three apps, as identities — md5(name:bundle_id) in production, opaque here on purpose:
# the latch never parses one, it only compares.
CHROME = "a" * 32
SLACK = "b" * 32
WIRESHARK = "c" * 32


def test_a_devices_first_inventory_opens_nothing() -> None:
    """The highest-consequence case in the feature. A baseline sweep of a 40k fleet that
    alerted on every app it found would write millions of rows and make Needs Attention
    useless forever — and there is no dismiss to dig back out with."""
    delta = latch_delta(set(), {CHROME, SLACK, WIRESHARK}, device_is_new=True)

    assert delta.to_open == frozenset()
    assert delta.departed == frozenset()


def test_a_device_row_with_no_app_history_also_primes() -> None:
    """The second door into the same flood, and the one that is easy to miss: a device
    first seen through a collection whose aperture excludes `applications` has a row and
    no app rows, so `device_is_new` is already False when its first real app read lands."""
    delta = latch_delta(set(), {CHROME, SLACK}, device_is_new=False)

    assert delta.to_open == frozenset()


def test_a_version_bump_is_not_a_new_app() -> None:
    """The silent-new-version ruling, stated in the units the latch actually works in.

    Chrome updating changes the device's `version_hash` set completely and its `app_hash`
    set not at all — which is exactly why the latch keeps a second set rather than reusing
    `process_sync`'s version-keyed map."""
    delta = latch_delta({CHROME, SLACK}, {CHROME, SLACK}, device_is_new=False)

    assert delta.to_open == frozenset()
    assert delta.departed == frozenset()


def test_a_genuine_install_opens_exactly_one() -> None:
    delta = latch_delta({CHROME, SLACK}, {CHROME, SLACK, WIRESHARK}, device_is_new=False)

    assert delta.to_open == frozenset({WIRESHARK})
    assert delta.departed == frozenset()


def test_an_uninstall_departs_exactly_one() -> None:
    delta = latch_delta({CHROME, SLACK, WIRESHARK}, {CHROME, SLACK}, device_is_new=False)

    assert delta.departed == frozenset({WIRESHARK})
    assert delta.to_open == frozenset()


def test_an_install_and_an_uninstall_in_one_pass_are_independent() -> None:
    delta = latch_delta({CHROME, SLACK}, {CHROME, WIRESHARK}, device_is_new=False)

    assert delta.to_open == frozenset({WIRESHARK})
    assert delta.departed == frozenset({SLACK})


def test_a_reinstall_after_a_close_opens_again() -> None:
    """Accepted churn (2026-08-29): no cooldown, no memory of the closed row. The partial
    unique index is on `closed_at IS NULL` precisely so this is legal rather than a
    constraint violation."""
    installed = latch_delta({CHROME}, {CHROME, WIRESHARK}, device_is_new=False)
    removed = latch_delta({CHROME, WIRESHARK}, {CHROME}, device_is_new=False)
    again = latch_delta({CHROME}, {CHROME, WIRESHARK}, device_is_new=False)

    assert installed.to_open == again.to_open == frozenset({WIRESHARK})
    assert removed.departed == frozenset({WIRESHARK})


def test_a_quiet_pull_asks_for_nothing() -> None:
    """The cost rule, pinned as a property rather than left to a comment: both halves
    empty means the caller writes nothing and queries nothing, which is what keeps the
    latch free on the path built to move 40k devices in ten minutes."""
    delta = latch_delta({CHROME, SLACK}, {CHROME, SLACK}, device_is_new=False)

    assert not delta.to_open and not delta.departed


def test_an_emptied_device_departs_everything() -> None:
    """A read that genuinely returned no applications closes every latch on the device.
    Only `[]` reaches the latch this way — `device.apps is None` never calls it at all,
    which is the caller's guard and is covered end to end in the DB lane."""
    delta = latch_delta({CHROME, SLACK}, set(), device_is_new=False)

    assert delta.departed == frozenset({CHROME, SLACK})
    assert delta.to_open == frozenset()


# --- The closed vocabulary against its own document -------------------------------------


def _documented_kinds() -> set[str]:
    """The kind rows of docs/alerts.md §2 — the table whose first column is a backticked
    name and whose second is a level."""
    return {
        match.group(1)
        for line in DOC.read_text().splitlines()
        if (match := re.match(r"^\|\s*`([a-z0-9_]+)`\s*\|\s*`(high|normal|low)`\s*\|", line))
    }


def test_the_kind_vocabulary_and_the_doc_tell_the_same_story() -> None:
    """Both directions. A kind added to the tuple without a row is undocumented; a row
    without a tuple entry is a promise nothing keeps."""
    assert _documented_kinds() == set(KINDS)
    assert len(set(KINDS)) == len(KINDS), "duplicate kind"
    assert set(KIND_LEVELS) == set(KINDS)


def test_every_kind_is_graded_in_the_closed_levels_vocabulary() -> None:
    """`level`, never a minted `severity` (#229): the product has one word for how much a
    thing matters and a second would have to be mapped onto the first forever."""
    assert all(level in LEVELS for level in KIND_LEVELS.values())
    assert KIND_LEVELS[NEW_APP] == HIGH


def test_the_module_never_says_severity() -> None:
    """Grepping the source is the only way to catch the word creeping back in as a
    column, a parameter or a dict key — a type checker has nothing to say about it."""
    source = (Path(__file__).resolve().parents[1] / "app" / "alerts" / "service.py").read_text()

    assert "severity" not in source.replace("`severity`", ""), "alerts are graded by level, not severity"


# --- The route's guard, and the claim the ruling rests on --------------------------------


def test_no_role_loses_access_when_the_guard_names_both_permissions() -> None:
    """The ruling of 2026-09-04 rests on one factual claim — *no role loses access* — and
    a claim a future role table can silently falsify belongs in a test rather than in a
    docstring.

    `GET /api/alerts` asserts `device:read` **and** `app:read`. Every role holds both
    today because `_INVENTORY_READ` grants the pair as a block, so the guard is free right
    now; the day someone splits them ("the application team sees the catalog but not the
    fleet") this test fails and says which role stopped being able to open the panel,
    instead of the panel simply going quiet on `/`.

    The refusal half — a principal holding exactly one — cannot be built from a role for
    the same reason, and is driven with scoped API tokens over HTTP in
    `tests/test_alerts_db.py`.
    """
    from app.core.permissions import ROLE_PERMISSIONS, Permission

    required = {Permission.DEVICE_READ, Permission.APP_READ}
    lost = sorted(role for role, granted in ROLE_PERMISSIONS.items() if not required <= granted)

    assert lost == [], f"roles that would lose the alerts panel: {lost}"


def test_the_route_declares_both_permissions() -> None:
    """The guard as the route table actually carries it, not as a comment claims it.

    Read off the source rather than by importing `app.main` — the pure lane has no
    database and building the app touches settings that need one. A regex is enough
    because there is exactly one route in the module and the assertion is about the two
    names appearing inside its single `require(...)`.
    """
    source = (Path(__file__).resolve().parents[1] / "app" / "api" / "alerts.py").read_text()
    guards = re.findall(r"Depends\(require\(([^)]*)\)\)", source)

    assert guards == ["Permission.DEVICE_READ, Permission.APP_READ"], guards
