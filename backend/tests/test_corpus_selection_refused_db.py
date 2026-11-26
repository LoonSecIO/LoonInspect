"""A refused corpus selection answers its own sentence on every route, never a bare 500 (#932).

With `VULN_TENANT_SELECTION` on, every read of stored vulnerability answers first binds the
organization's selected release (`app.core.vuln_selection.load_selected_corpus`), and a selection
naming a release this database does not hold is refused with a sentence written for the operator.
Before #932 no handler took it: a dozen routes answered Starlette's plain-text 500, and a device's
Update from Jamf blamed the Jamf connection.

The state is planted the way a restore leaves it, because the selection's foreign keys leave no other
way in: as the database superuser under `session_replication_role = replica`, which is how a data-only
restore with triggers disabled writes. So this needs `ADMIN_DATABASE_URL`, as
tests/test_migration_round_trip_db.py does, and skips without it; CI sets it.

Every route is then walked as tests/test_route_sweep_db.py walks its own lane, with that file's
tenants and plumbing, and with the Fleet catalog flag on too, so the migration list reads the
corpus. A route answers the refusal (503, the sentence as `detail`) or what it answers anyway, and
never a 5xx otherwise. REFUSES is asserted both ways, as that file's STOPS are: a route that starts
binding the selection, or stops, moves in or out of it.
"""

from __future__ import annotations

import logging
import os

import pytest
import pytest_asyncio
from sqlalchemy import make_url, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.feature_flags import FLEET_MAINTAINED_APPS_FLAG
from tests.test_route_sweep_db import (  # noqa: F401 — `offline` and `tenants` are fixtures
    ROUTES,
    Crash,
    _cases,
    _client,
    _doomed,
    _handled,
    _params,
    _probes,
    _said,
    _send,
    _values,
    offline,
    tenants,
)

ADMIN_URL = os.environ.get("ADMIN_DATABASE_URL", "")
pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.skipif(not ADMIN_URL, reason="set ADMIN_DATABASE_URL: only a superuser plants a selection whose release is gone"),
    pytest.mark.asyncio(loop_scope="session"),
]

MISSING = "d" * 64  # a release signature no test loads
SENTENCE = "The selected intelligence is missing. Restore the database backup and contact support."
# The routes that bind the selected release in the state the sweep sets up, by the page an operator meets
# the sentence on. A route that reads the corpus only past a row the sweep does not hold (a Jamf Patch
# title, a severity rule) is not here, and answers the same way once it does.
REFUSES = {
    "Devices and a device's page": [
        *("GET /api/devices", "GET /api/devices/{device_id}", "POST /api/devices/{device_id}/refresh"),
    ],
    "Devices › Applications and the Catalog": ["GET /api/applications", "GET /api/catalog", "POST /api/catalog/refresh"],
    "a patch plan": ["POST /api/application-patch-plans"],
    "Posture › Vulnerabilities": [
        *("GET /api/vulnerabilities/status", "GET /api/vulnerabilities/{vuln_id}", "POST /api/vulnerabilities/prompt"),
    ],
    "the Fleet migration list, with the Fleet catalog flag on": [
        *("GET /api/fleet-catalog/migration", "GET /api/fleet-catalog/migration/apps/{app_hash}"),
        "POST /api/fleet-catalog/briefing",
    ],
}
REFUSED = {route for routes in REFUSES.values() for route in routes}


async def _superuser(*statements: tuple[str, dict]) -> list[list]:
    """Each statement in one transaction in the test database, as ADMIN_DATABASE_URL's role, with
    foreign keys unchecked as a data-only restore with triggers disabled leaves them; each one's rows."""
    url = make_url(ADMIN_URL).set(drivername="postgresql+asyncpg", database=make_url(settings.database_url).database)
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL session_replication_role = replica"))
            results = [await connection.execute(text(sql), params) for sql, params in statements]
            return [list(result.all()) if result.returns_rows else [] for result in results]
    finally:
        await engine.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def refusing(tenants):  # noqa: F811
    """The second tenant, selecting a release the database does not hold, with the preview and the Fleet
    catalog flag on; whatever that tenant held before is put back afterwards."""
    keys = {"t": str(tenants["t2"]["tenant_id"]), "s": MISSING, "flag": FLEET_MAINTAINED_APPS_FLAG}
    selection, flag, *_ = await _superuser(
        ("SELECT signature, previous_signature, selected_at FROM vuln_corpus_selections WHERE tenant_id = :t", keys),
        ("SELECT enabled FROM feature_flags WHERE tenant_id = :t AND key = :flag", keys),
        (
            "INSERT INTO vuln_corpus_acquisitions (tenant_id, signature, basis) VALUES (:t, :s, 'delivery') "
            "ON CONFLICT DO NOTHING",
            keys,
        ),
        (
            "INSERT INTO vuln_corpus_selections (tenant_id, signature) VALUES (:t, :s) "
            "ON CONFLICT (tenant_id) DO UPDATE SET signature = :s, previous_signature = NULL",
            keys,
        ),
        (
            "INSERT INTO feature_flags (tenant_id, key, enabled, updated_at) VALUES (:t, :flag, true, now()) "
            "ON CONFLICT (tenant_id, key) DO UPDATE SET enabled = true",
            keys,
        ),
    )
    held = [row for row in selection if row.signature != MISSING]  # a run cut short left its own behind
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(settings, "vuln_tenant_selection", True)
            yield tenants["t2"]
    finally:
        if held:
            was = dict(zip(("was", "before", "at"), held[0], strict=True))
            sql = "UPDATE vuln_corpus_selections SET signature = :was, previous_signature = :before, selected_at = :at"
            selection_back = (f"{sql} WHERE tenant_id = :t", keys | was)
        else:
            selection_back = ("DELETE FROM vuln_corpus_selections WHERE tenant_id = :t", keys)
        if flag:
            sql = "UPDATE feature_flags SET enabled = :on WHERE tenant_id = :t AND key = :flag"
            flag_back = (sql, keys | {"on": flag[0].enabled})
        else:
            flag_back = ("DELETE FROM feature_flags WHERE tenant_id = :t AND key = :flag", keys)
        await _superuser(selection_back, ("DELETE FROM vuln_corpus_acquisitions WHERE signature = :s", keys), flag_back)


async def test_the_planted_selection_names_a_release_the_database_does_not_hold(refusing) -> None:
    """A vacuity guard: the sweep below is only about this state if the state is real."""
    selected, releases = await _superuser(
        ("SELECT signature FROM vuln_corpus_selections WHERE tenant_id = :t", {"t": str(refusing["tenant_id"])}),
        ("SELECT count(*) FROM vuln_corpus_releases WHERE signature = :s", {"s": MISSING}),
    )
    assert [row.signature for row in selected] == [MISSING] and releases[0][0] == 0


async def test_the_refusal_is_logged_once_without_a_traceback_and_the_service_stays_up(
    refusing, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import app.main as main_module

    monkeypatch.setattr(main_module, "_selection_refusal_reported", False)
    async with _client(refusing) as client:
        with caplog.at_level(logging.ERROR, logger="app.main"):
            answers = [await client.get(path) for path in ("/api/catalog", "/api/applications", "/api/devices")]
        assert [(a.status_code, a.json()) for a in answers] == [(503, {"detail": SENTENCE})] * 3
        lines = [record for record in caplog.records if record.getMessage() == SENTENCE]
        assert len(lines) == 1 and lines[0].levelno == logging.ERROR and lines[0].exc_info is None
        # The service is up: health and sign-in do not read vulnerability answers.
        assert (await client.get("/api/health")).status_code == 200
        assert (await client.get("/api/auth/me")).status_code == 200


@pytest.mark.parametrize(("method", "path", "route"), _cases("refused", ROUTES))
async def test_a_refused_selection_answers_its_sentence_on_every_route_that_binds_it(refusing, method, path, route) -> None:
    mine = refusing
    values = _values(mine)
    if method != "GET":
        values |= {name: await _doomed(mine, name) for where, name, _, _ in _probes(path, route) if where == "path"}
    async with _client(mine) as client:
        response = await _send(client, method, path, route, values, {name for _, name, _, _ in _params(path, route)})
    if response.status_code == 500 and response.text == "Internal Server Error":
        raise Crash(_said(method, path, response))
    json = response.headers.get("content-type") == "application/json"
    refused = response.status_code == 503 and json and response.json() == {"detail": SENTENCE}
    listed = f"{method} {path}" in REFUSED
    assert refused == listed, f"{_said(method, path, response)}: {'listed in' if listed else 'not in'} REFUSES"
    if not refused:
        _handled(method, path, response)


async def test_every_entry_names_a_route() -> None:
    """An entry for a route that is gone, or misspelt, would be asked nothing."""
    served = {f"{m} {p}" for m, p, _ in ROUTES}
    assert not REFUSED - served, sorted(REFUSED - served)
