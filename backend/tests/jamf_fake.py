"""A stand-in Jamf Pro tenant for end-to-end tests: enough of the API surface the
connector touches, answered from the two fixture records, behind httpx.MockTransport.

Two computers, one smart group, a version, and no permission to read inventory-
collection settings. Records every request path so a test can assert what was fetched
— and, for the device sweep, which `filter=` reached Jamf.
"""

from __future__ import annotations

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
        self.requests: list[str] = []
        self.filters: list[str | None] = []  # the RSQL `filter=` each inventory page asked for
        self.sections: list[str | None] = []  # the `section=` each inventory page asked for

    @property
    def computers(self) -> list[dict]:
        return [self.real, self.synthetic]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(f"{request.method} {path}")
        if path == "/api/oauth/token":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 1799, "token_type": "Bearer"})
        if request.headers.get("Authorization") != "Bearer tok":
            return httpx.Response(401, json={"httpStatus": 401})
        if path == "/api/v1/jamf-pro-version":
            return httpx.Response(200, json={"version": "11.31.1-t1787060595569"})
        if path == "/api/v1/computer-inventory-collection-settings":
            return httpx.Response(403, json={"httpStatus": 403, "errors": []})
        if path == "/api/v1/computers-inventory":
            page = int(request.url.params.get("page", "0"))
            self.filters.append(request.url.params.get("filter"))
            self.sections.append(request.url.params.get("section"))
            results = self.computers if page == 0 else []
            return httpx.Response(200, json={"totalCount": len(self.computers), "results": results})
        if path.startswith("/api/v1/computers-inventory-detail/"):
            wanted = path.rsplit("/", 1)[1]
            for computer in self.computers:
                if computer["id"] == wanted:
                    return httpx.Response(200, json=computer)
            return httpx.Response(404, json={"httpStatus": 404})
        if path == "/api/v2/computer-groups/smart-groups":
            return httpx.Response(200, json={"totalCount": 1, "results": [{"id": "1", "name": "All Managed Clients"}]})
        if path == "/api/v2/computer-groups/smart-groups/1":
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
