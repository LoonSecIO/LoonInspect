"""`GET /api/vulnerabilities/{vuln_id}` refuses an id outside §5's shape before it asks the
database anything (#533, #684). Pure: the router on a bare app answered by the handlers
`app.main` registers, the permission granted, and a session that fails the test if the route
reaches for it — the shape is refused before the tier and before any query, so nothing here
needs Postgres. What the route answers for an id it accepts is `test_vuln_answer_db.py`'s."""

from __future__ import annotations

from urllib.parse import quote

import httpx
import pytest
from fastapi import FastAPI

from app import main as app_main
from app.api.vulnerabilities import router
from app.core.database import get_vuln_read_db
from tests.test_vuln_block import LOOSE_IDS

# Refused before #684 too, and the id `test_vuln_answer_db.py` asks the route with.
FOURTH = "GHSA-72mh-4hwj-fh5w"


class _Untouched:
    """The session the route is handed. A shape refusal never reaches it."""

    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"the lookup reached for the database ({name}) before refusing the id's shape")


def _client() -> httpx.AsyncClient:
    api = FastAPI()
    api.exception_handlers.update(app_main.app.exception_handlers)
    api.include_router(router)
    lookup = next(route for route in router.routes if route.path == "/api/vulnerabilities/{vuln_id}")
    # `require(Permission.VULN_READ)`, granted: who may ask is not what this file is about.
    (permission,) = (depends.dependency for depends in lookup.dependencies)
    api.dependency_overrides[permission] = lambda: None
    api.dependency_overrides[get_vuln_read_db] = _Untouched
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=api), base_url="https://lookup.example.com")


@pytest.mark.parametrize("finding_id", LOOSE_IDS)
async def test_other_digits_or_a_newline_after_the_id_is_refused_like_any_other_shape(finding_id: str) -> None:
    """#684. These went on to the tier and the query as ids — a 200 with no builds, or the tier's
    409 — and now meet what any id outside the two namespaces meets: a 422 carrying §5's
    sentence, with only the id in it changed. Each id is encoded whole, as the page's
    `encodeURIComponent` sends the one a hand-edited URL carries."""
    async with _client() as client:
        fourth, answer = [await client.get(f"/api/vulnerabilities/{quote(value, safe='')}") for value in (FOURTH, finding_id)]
    assert (fourth.status_code, answer.status_code) == (422, 422)
    assert answer.json() == {"detail": fourth.json()["detail"].replace(repr(FOURTH), repr(finding_id))}
