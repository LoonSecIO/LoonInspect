"""Snowflake authentication, endpoint confinement and bounded safe response handling."""

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pydantic import ValidationError

from app.core.snowflake_transport import MAX_RESPONSE_BYTES, SnowflakeClient, SnowflakeError, key_pair_jwt
from app.schemas.destinations import DestinationCreate
from app.schemas.snowflake import SnowflakeConfig, ingest_url, private_key
from tests.snowflake_fake import CONFIG, URL, pem


@pytest.fixture(scope="module")
def secret():
    return pem()


def test_signed_key_pair_claims_and_private_key_validation(secret):
    config = SnowflakeConfig.model_validate(CONFIG)
    token = key_pair_jwt(config, secret)
    header, body, signature = token.split(".")

    def decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    claims = json.loads(decode(body))
    assert claims["sub"] == "EXAMPLE-TEST.LI_WRITER"
    assert claims["iss"].startswith(claims["sub"] + ".SHA256:")
    assert claims["scp"] == "session:role:LI_WRITER"
    assert claims["exp"] - claims["iat"] == 900
    private_key(secret).public_key().verify(decode(signature), f"{header}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert secret not in token


@pytest.mark.parametrize(
    "host",
    [
        "https://example.snowflakecomputing.com",
        "example.snowflakecomputing.com.evil.test",
        "localhost",
        "127.0.0.1",
        "example.snowflakecomputing.com/path",
        "a@b.snowflakecomputing.com",
        "a..snowflakecomputing.com",
    ],
)
def test_discovered_host_cannot_redirect_credential(host):
    with pytest.raises(ValueError):
        ingest_url(host)


def test_create_requires_complete_native_target_and_key(secret):
    result = DestinationCreate(name="warehouse", type="snowflake", url=URL, snowflake_config=CONFIG, auth_secret=secret)
    assert result.auth_type == "snowflake_jwt"
    assert result.snowflake_config.account == "EXAMPLE-TEST"
    for changes in [
        {"snowflake_config": None},
        {"auth_secret": "not-a-key"},
        {"url": "https://other-account.snowflakecomputing.com"},
        {"allow_insecure_http": True},
        {"snowflake_config": {**CONFIG, "pipe": "name/escape"}},
    ]:
        with pytest.raises(ValidationError):
            DestinationCreate(
                **(
                    {"name": "warehouse", "type": "snowflake", "url": URL, "snowflake_config": CONFIG, "auth_secret": secret}
                    | changes
                )
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [302, 401, 403, 404, 409, 429, 500])
async def test_upstream_failure_never_echoes_body_or_credentials(secret, code):
    seen = []

    def reply(request):
        seen.append(request)
        return httpx.Response(code, text="SYNTHETIC_PRIVATE_UPSTREAM", headers={"Location": "https://other.test/collect"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as http:
        client = SnowflakeClient(http, SnowflakeConfig.model_validate(CONFIG), URL, secret)
        with pytest.raises(SnowflakeError) as error:
            await client._request("GET", URL)
    assert len(seen) == 1
    assert "SYNTHETIC_PRIVATE" not in str(error.value)
    assert "Snowflake" in str(error.value)


@pytest.mark.asyncio
async def test_oversized_and_malformed_response_are_bounded(secret):
    for response in [b"x" * (MAX_RESPONSE_BYTES + 1), b"SYNTHETIC_PRIVATE_INVALID_JSON"]:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request, body=response: httpx.Response(200, content=body))
        ) as http:
            client = SnowflakeClient(http, SnowflakeConfig.model_validate(CONFIG), URL, secret)
            with pytest.raises(SnowflakeError) as error:
                await client._request("GET", URL)
        assert "SYNTHETIC_PRIVATE" not in str(error.value)


@pytest.mark.asyncio
async def test_exchange_deadline_prevents_another_network_request(secret):
    seen = []

    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as http:
        client = SnowflakeClient(http, SnowflakeConfig.model_validate(CONFIG), URL, secret)
        await client._request("GET", URL)
        client.deadline = 0
        with pytest.raises(SnowflakeError, match="time budget"):
            await client._request("GET", URL)
    assert len(seen) == 1


def test_documented_active_status_and_unknown_status_are_distinguished():
    from app.core.snowflake_transport import ChannelStatus, channel_status

    for code in ("SUCCESS", "ACTIVE"):
        assert channel_status(
            {"channel_status_code": code, "rows_inserted": 2, "rows_error_count": 1, "last_committed_offset_token": "offset"}
        ) == ChannelStatus(2, 1, "offset")
    with pytest.raises(SnowflakeError, match="channel is unavailable"):
        channel_status({"channel_status_code": "INVALID", "rows_inserted": 2, "rows_error_count": 1})
