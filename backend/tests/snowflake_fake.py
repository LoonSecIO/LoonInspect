"""Deterministic Named Channel protocol peer; no Snowflake account or network access."""

from __future__ import annotations

import json

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CONFIG = {
    "account": "EXAMPLE-TEST",
    "user": "LI_WRITER",
    "database": "LI",
    "schema": "EVENTS",
    "pipe": "EVENTS_PIPE",
    "role": "LI_WRITER",
}
URL = "https://example-test.snowflakecomputing.com"


def pem() -> str:
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        .decode()
    )


class FakeSnowflake:
    def __init__(self):
        self.channels: dict[str, dict] = {}
        self.rows: list[dict] = []
        self.appends: list[tuple[str, bytes]] = []
        self.requests: list[httpx.Request] = []
        self.lose_response = False
        self.drop_request = False
        self.delay = False
        self.pending: dict[str, tuple[str, list[dict]]] = {}
        self.status_override: dict | None = None
        self.on_append = None

    def _status(self, channel: str) -> dict:
        return self.channels.setdefault(
            channel,
            {"channel_status_code": "SUCCESS", "rows_inserted": 0, "rows_error_count": 0, "last_committed_offset_token": None},
        )

    def commit(self, channel: str, offset: str, rows: list[dict]) -> None:
        state = self._status(channel)
        for row in rows:
            if row["PAYLOAD"].get("syntheticReject"):
                state["rows_error_count"] += 1
            else:
                state["rows_inserted"] += 1
                self.rows.append(row)
        state["last_committed_offset_token"] = offset

    def flush(self) -> None:
        for channel, (offset, rows) in self.pending.items():
            self.commit(channel, offset, rows)
        self.pending.clear()

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/hostname"):
            return httpx.Response(200, text="example-test.ingest.snowflakecomputing.com")
        if path == "/oauth/token":
            return httpx.Response(200, json={"token": "synthetic-ingestion-token"})
        if request.method == "PUT":
            assert json.loads(request.content) == {"fail_on_uncommitted_rows": True}
            channel = path.rsplit("/", 1)[-1]
            if channel in self.pending:
                return httpx.Response(409, json={"message": "SYNTHETIC_PRIVATE_UPSTREAM"})
            return httpx.Response(
                200, json={"channel_status": self._status(channel), "next_continuation_token": "synthetic-continuation"}
            )
        if path.endswith("/rows"):
            channel = path.split("/")[-2]
            self.appends.append((channel, request.content))
            if self.on_append:
                await self.on_append(request)
            if self.drop_request:
                self.drop_request = False
                raise httpx.ReadTimeout("SYNTHETIC_PRIVATE_UPSTREAM")
            rows = [json.loads(line) for line in request.content.splitlines()]
            assert set(request.url.params) == {"continuationToken", "offsetToken"}
            offset = request.url.params["offsetToken"]
            if self.delay:
                self.pending[channel] = (offset, rows)
            else:
                self.commit(channel, offset, rows)
            if self.lose_response:
                self.lose_response = False
                raise httpx.ReadTimeout("SYNTHETIC_PRIVATE_UPSTREAM")
            return httpx.Response(200, json={"next_continuation_token": "synthetic-next"})
        if path.endswith(":bulk-channel-status"):
            channels = json.loads(request.content)["channel_names"]
            return httpx.Response(
                200, json={"channel_statuses": {name: self.status_override or self._status(name) for name in channels}}
            )
        raise AssertionError(f"Unexpected synthetic operation: {request.method} {path}")


def install(monkeypatch, fake: FakeSnowflake) -> None:
    from app.core import snowflake_transport

    real_client = httpx.AsyncClient

    class MockClient(real_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(fake)
            super().__init__(*args, **kwargs)

    async def safe_dns(url: str) -> None:
        assert url.endswith(".snowflakecomputing.com")

    monkeypatch.setattr(httpx, "AsyncClient", MockClient)
    monkeypatch.setattr(snowflake_transport, "refuse_destination_resolution", safe_dns)
