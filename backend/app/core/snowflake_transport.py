"""Bounded Snowpipe Streaming Named Channel REST transport, without SDK/native dependencies.

The caller owns durable batches and row accounting. A successful append is only an
acknowledgement, never a delivered verdict. Reopening always refuses uncommitted rows;
recovery never drops a channel. Upstream bodies, tokens and exception text stay private.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from dataclasses import dataclass

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.core.egress import refuse_destination_resolution
from app.schemas.snowflake import SnowflakeConfig, ingest_url, private_key, validate_snowflake_url

MAX_RESPONSE_BYTES = 512 * 1024


class SnowflakeError(Exception):
    """An operator-safe diagnosis; never include upstream response or exception text."""


@dataclass(frozen=True)
class ChannelStatus:
    inserted: int
    rejected: int
    offset: str | None

    def baseline(self) -> dict:
        return {"inserted": self.inserted, "rejected": self.rejected, "offset": self.offset}


def channel_status(value: object) -> ChannelStatus:
    if not isinstance(value, dict) or value.get("channel_status_code") not in {"SUCCESS", "ACTIVE"}:
        raise SnowflakeError(
            "Snowflake channel is unavailable. Check the pipe, writer role and channel status in "
            "Snowflake; queued events are retained."
        )
    counts = (value.get("rows_inserted"), value.get("rows_error_count"))
    if any(type(count) is not int or count < 0 for count in counts):
        raise SnowflakeError(
            "Snowflake did not return valid row counts. Delivery remains unresolved; check channel status in Snowflake."
        )
    offset = value.get("last_committed_offset_token")
    if offset is not None and (not isinstance(offset, str) or len(offset) > 1024):
        raise SnowflakeError(
            "Snowflake returned an invalid checkpoint. Delivery remains unresolved; check channel status in Snowflake."
        )
    return ChannelStatus(counts[0], counts[1], offset or None)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def key_pair_jwt(config: SnowflakeConfig, secret: str) -> str:
    key = private_key(secret)
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = base64.b64encode(hashlib.sha256(public).digest()).decode()
    subject = f"{config.account}.{config.user}"
    now = int(time.time())
    claims = {
        "iss": f"{subject}.SHA256:{fingerprint}",
        "sub": subject,
        "iat": now,
        "exp": now + 900,
        "scp": f"session:role:{config.role}",
    }
    header = _b64(b'{"alg":"RS256","typ":"JWT"}')
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    encoded = f"{header}.{payload}"
    signature = key.sign(encoded.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded}.{_b64(signature)}"


class SnowflakeClient:
    def __init__(
        self, client: httpx.AsyncClient, config: SnowflakeConfig, url: str, secret: str, *, deadline: float | None = None
    ):
        self.client = client
        self.config = config
        self.control = validate_snowflake_url(url, config)
        self.secret = secret
        self.ingest = ""
        self.token = ""
        self.deadline = deadline if deadline is not None else time.monotonic() + 20
        self.path = f"/v2/streaming/databases/{config.database}/schemas/{config.schema_name}/pipes/{config.pipe}"

    async def _request(self, method: str, url: str, *, raw: bool = False, **kwargs):
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise SnowflakeError(
                    "Snowflake exceeded the request time budget. Check network and service health; queued events will retry."
                )
            async with (
                asyncio.timeout(remaining),
                self.client.stream(method, url, follow_redirects=False, timeout=10, **kwargs) as response,
            ):
                if not 200 <= response.status_code < 300:
                    code = response.status_code
                    if code == 409:
                        raise SnowflakeError(
                            "Snowflake has uncommitted data or channel recovery in progress. Delivery remains "
                            "unresolved and will be checked again; do not drop the channel."
                        )
                    if code in (401, 403):
                        raise SnowflakeError(
                            f"Snowflake refused authentication or permission (HTTP {code}). "
                            "Check the account, service user, RSA public key and writer role grants."
                        )
                    if code == 404:
                        raise SnowflakeError(
                            "Snowflake could not find the endpoint or pipe (HTTP 404). "
                            "Check account, database, schema and pipe names."
                        )
                    raise SnowflakeError(
                        f"Snowflake request failed (HTTP {code}). Check service status and network access; "
                        "queued events remain available for retry."
                    )
                data = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    data.extend(chunk)
                    if len(data) > MAX_RESPONSE_BYTES:
                        raise SnowflakeError(
                            "Snowflake returned an oversized response. Delivery remains unresolved; check the endpoint "
                            "and service status."
                        )
                return data.decode() if raw else json.loads(data)
        except (httpx.HTTPError, TimeoutError, ValueError, UnicodeError, RecursionError) as exc:
            raise SnowflakeError(
                "Snowflake could not be reached or returned an unreadable response. Check HTTPS, DNS, "
                "network access and the account URL; queued events are retained."
            ) from exc

    async def _resolve(self, url: str) -> None:
        try:
            async with asyncio.timeout(max(0, self.deadline - time.monotonic())):
                await refuse_destination_resolution(url)
        except TimeoutError as exc:
            raise SnowflakeError("Snowflake DNS lookup timed out. Check network and DNS; queued events will retry.") from exc

    async def authenticate(self) -> None:
        await self._resolve(self.control)
        jwt = key_pair_jwt(self.config, self.secret)
        headers = {"Authorization": f"Bearer {jwt}", "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT"}
        host = await self._request("GET", self.control + "/v2/streaming/hostname", headers=headers, raw=True)
        self.ingest = ingest_url(host)
        await self._resolve(self.ingest)
        result = await self._request(
            "POST",
            self.control + "/oauth/token",
            headers=headers,
            data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "scope": self.ingest.removeprefix("https://")},
        )
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("token"), str)
            or not result["token"]
            or len(result["token"]) > 32768
        ):
            raise SnowflakeError(
                "Snowflake did not issue an ingestion token. Check service-user authentication and the writer role."
            )
        self.token = result["token"]

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    async def open(self, channel: str) -> tuple[ChannelStatus, str]:
        result = await self._request(
            "PUT", self.ingest + self.path + f"/channels/{channel}", headers=self.headers, json={"fail_on_uncommitted_rows": True}
        )
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("next_continuation_token"), str)
            or not result["next_continuation_token"]
        ):
            raise SnowflakeError(
                "Snowflake did not open the channel. Check the pipe and writer role; delivery remains unresolved."
            )
        return channel_status(result.get("channel_status")), result["next_continuation_token"]

    async def append(self, channel: str, continuation: str, offset: str, body: str) -> None:
        await self._request(
            "POST",
            self.ingest + self.path.replace("/v2/streaming/", "/v2/streaming/data/") + f"/channels/{channel}/rows",
            headers={**self.headers, "Content-Type": "application/x-ndjson"},
            params={"continuationToken": continuation, "offsetToken": offset},
            content=body.encode("utf-8"),
        )

    async def status(self, channel: str) -> ChannelStatus:
        result = await self._request(
            "POST", self.ingest + self.path + ":bulk-channel-status", headers=self.headers, json={"channel_names": [channel]}
        )
        if not isinstance(result, dict) or not isinstance(result.get("channel_statuses"), dict):
            raise SnowflakeError(
                "Snowflake did not return channel status. Delivery remains unresolved and will be checked again."
            )
        return channel_status(result["channel_statuses"].get(channel))
