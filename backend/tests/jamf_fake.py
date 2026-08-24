"""A stand-in Jamf Pro tenant for end-to-end tests: enough of the API surface the
connector touches, answered from the two fixture records, behind httpx.MockTransport.

Two computers, one smart group, a version, and no permission to read inventory-
collection settings. Records every request path so a test can assert what was fetched
— and, for the device sweep, which `filter=`, `section=`, and `page-size=` reached
Jamf. Pagination is real (slices by page/page-size, totalCount at request time), so the
concurrent pager's waves and its totalCount-floor tail are exercised against the same
arithmetic a tenant performs:

- `seed(n)` grows the fleet with clones so page_size=1 tests have pages to fan out.
- `appear_after_first_page` holds devices that enroll right after page 0 is served —
  the case where totalCount is a floor, not gospel.
- `transient` scripts one-shot answers (a 429 with Retry-After, a 502) in front of any
  request whose full URL contains the match string — a path, or one page's "&page=5" —
  consumed in order.
- `async_handler` is the same tenant with the event loop allowed between requests, so
  waves actually overlap and `max_in_flight` can prove how wide the client ran.
"""

from __future__ import annotations

import asyncio
import json
import uuid as uuidlib
from pathlib import Path

import httpx

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"
HOST = "https://e2e.jamfcloud.com"


class FakeJamf:
    """Just enough of a tenant: two computers, one smart group, a version, no
    permission to read inventory-collection settings."""

    def __init__(self) -> None:
        self.synthetic = json.loads((FIXTURES / "computer_inventory_detail.json").read_text())
        self.real = json.loads((FIXTURES / "computer_inventory_detail_real.json").read_text())
        # Unique ids per run so re-running locally never collides with a previous pass.
        suffix = uuidlib.uuid4().hex[:6]
        self.synthetic["id"] = f"42{suffix}"
        self.real["id"] = f"3{suffix}"
        self._extra: list[dict] = []
        self.appear_after_first_page: list[dict] = []
        self.transient: list[tuple[str, int, dict[str, str]]] = []
        self.requests: list[str] = []
        self.filters: list[str | None] = []  # the RSQL `filter=` each inventory page asked for
        self.sections: list[str | None] = []  # the `section=` each inventory page asked for
        self.page_sizes: list[int] = []  # the `page-size=` each inventory page asked for
        self.in_flight = 0
        self.max_in_flight = 0

    @property
    def computers(self) -> list[dict]:
        return [self.real, self.synthetic, *self._extra]

    def seed(self, count: int) -> None:
        """Grow the fleet with clones of the synthetic record — distinct ids, serials,
        and UDIDs, so each clone is its own device to the ledger."""
        for index in range(count):
            clone = json.loads(json.dumps(self.synthetic))
            clone["id"] = f"9{index:04d}{uuidlib.uuid4().hex[:4]}"
            clone["udid"] = str(uuidlib.uuid4()).upper()
            clone.setdefault("hardware", {})["serialNumber"] = f"CLONE{uuidlib.uuid4().hex[:8].upper()}"
            self._extra.append(clone)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(f"{request.method} {path}")
        for index, (match, status, headers) in enumerate(self.transient):
            if match in str(request.url):
                self.transient.pop(index)
                return httpx.Response(status, headers=headers, json={"httpStatus": status})
        if path == "/api/oauth/token":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 1799, "token_type": "Bearer"})
        if request.headers.get("Authorization") != "Bearer tok":
            return httpx.Response(401, json={"httpStatus": 401})
        if path == "/api/v1/jamf-pro-version":
            return httpx.Response(200, json={"version": "11.31.1-t1787060595569"})
        if path == "/api/v2/computer-inventory-collection-settings":
            return httpx.Response(403, json={"httpStatus": 403, "errors": []})
        if path == "/api/v4/computers-inventory":
            page = int(request.url.params.get("page", "0"))
            size = int(request.url.params.get("page-size", "100"))
            self.filters.append(request.url.params.get("filter"))
            self.sections.append(request.url.params.get("section"))
            self.page_sizes.append(size)
            fleet = self.computers
            results = fleet[page * size : (page + 1) * size]
            if page == 0 and self.appear_after_first_page:
                # The totalCount-floor case: the fleet grows right after page 0 is
                # served, as a device enrolling mid-sweep does. The totalCount already
                # sent named the old fleet; only the serial tail can find the new one.
                self._extra.extend(self.appear_after_first_page)
                self.appear_after_first_page = []
            return httpx.Response(200, json={"totalCount": len(fleet), "results": results})
        if path.startswith("/api/v4/computers-inventory-detail/"):
            wanted = path.rsplit("/", 1)[1]
            for computer in self.computers:
                if computer["id"] == wanted:
                    return httpx.Response(200, json=computer)
            return httpx.Response(404, json={"httpStatus": 404})
        if path == "/api/v3/computer-groups/smart-groups":
            return httpx.Response(200, json={"totalCount": 1, "results": [{"id": "1", "name": "All Managed Clients"}]})
        if path == "/api/v3/computer-groups/smart-groups/1":
            return httpx.Response(
                200,
                json={
                    "name": "All Managed Clients",
                    "siteId": "-1",
                    "criteria": [
                        {"name": "Managed", "priority": 0, "andOr": "and", "searchType": "is", "value": "Managed"}
                    ],
                },
            )
        return httpx.Response(404, json={"httpStatus": 404, "path": path})

    async def async_handler(self, request: httpx.Request) -> httpx.Response:
        """The sync handler behind one real await, so concurrent requests interleave
        on the event loop and `max_in_flight` records how wide the client actually ran."""
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0)
            return self.handler(request)
        finally:
            self.in_flight -= 1
