"""Configuration validated before native Snowflake credentials can leave the app."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.egress import validate_destination_url

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_$]{0,254}\Z")
_ACCOUNT = re.compile(r"[A-Za-z0-9_]+-[A-Za-z0-9_]+\Z")


class SnowflakeConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    account: str = Field(min_length=3, max_length=255)
    user: str = Field(min_length=1, max_length=255)
    database: str = Field(min_length=1, max_length=255)
    schema_name: str = Field(alias="schema", min_length=1, max_length=255)
    pipe: str = Field(min_length=1, max_length=255)
    role: str = Field(min_length=1, max_length=255)

    @field_validator("account")
    @classmethod
    def account_identifier(cls, value: str) -> str:
        if not _ACCOUNT.fullmatch(value):
            raise ValueError("Snowflake account must be the organization-account identifier from Account details")
        return value.upper()

    @field_validator("user", "database", "schema_name", "pipe", "role")
    @classmethod
    def identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError(
                "Snowflake names must be unquoted identifiers: letters, digits, underscores or $, starting "
                "with a letter or underscore"
            )
        return value.upper()

    @property
    def account_url(self) -> str:
        return f"https://{self.account.lower().replace('_', '-')}.snowflakecomputing.com"


def validate_snowflake_url(value: str, config: SnowflakeConfig) -> str:
    validated = validate_destination_url(value, allow_insecure=False)
    if validated.rstrip("/").lower() != config.account_url:
        raise ValueError("Snowflake URL must be https://<organization-account>.snowflakecomputing.com, matching account")
    return config.account_url


def ingest_url(host: str) -> str:
    """Only a plain Snowflake hostname can receive the scoped ingestion credential."""
    host = host.strip().replace("_", "-").lower()
    if len(host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError("Snowflake returned an invalid ingestion hostname; check the account URL")
    if not host.endswith(".snowflakecomputing.com") or ".." in host:
        raise ValueError("Snowflake returned an unexpected ingestion hostname; check the account URL")
    url = validate_destination_url(f"https://{host}", allow_insecure=False)
    if urlsplit(url).hostname != host:
        raise ValueError("Snowflake returned an invalid ingestion hostname; check the account URL")
    return url


def private_key(value: str) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(value.encode(), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError(
            "Snowflake requires an unencrypted PEM RSA private key; it is encrypted when stored in LoonInspect"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError("Snowflake requires an RSA private key of at least 2048 bits")
    return key
