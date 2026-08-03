from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.schemas.payload import MdmProvider


class _CredentialsBase(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class JamfCredentials(_CredentialsBase):
    client_id: str = Field(description="Client ID")
    client_secret: str = Field(description="Client Secret", json_schema_extra={"secret": True})

    FINGERPRINT_FIELD: ClassVar[str] = "client_secret"


class SimpleMdmCredentials(_CredentialsBase):
    api_key: str = Field(description="API Key", json_schema_extra={"secret": True})

    FINGERPRINT_FIELD: ClassVar[str] = "api_key"


class AddigyCredentials(_CredentialsBase):
    # Not implemented yet — placeholder shape, adjust once a real Addigy client exists.
    api_key: str = Field(description="API Key", json_schema_extra={"secret": True})

    FINGERPRINT_FIELD: ClassVar[str] = "api_key"


class NanoCredentials(_CredentialsBase):
    # Not implemented yet — placeholder shape, adjust once a real Nano MDM client exists.
    api_key: str = Field(description="API Key", json_schema_extra={"secret": True})

    FINGERPRINT_FIELD: ClassVar[str] = "api_key"


CREDENTIAL_SCHEMAS: dict[MdmProvider, type[_CredentialsBase]] = {
    MdmProvider.jamf: JamfCredentials,
    MdmProvider.simplemdm: SimpleMdmCredentials,
    MdmProvider.addigy: AddigyCredentials,
    MdmProvider.nano: NanoCredentials,
}


def field_specs(schema: type[_CredentialsBase]) -> list[dict[str, object]]:
    specs = []
    for key, field in schema.model_fields.items():
        extra = field.json_schema_extra if isinstance(field.json_schema_extra, dict) else {}
        specs.append(
            {
                "key": field.alias or to_camel(key),
                "label": field.description or key,
                "secret": bool(extra.get("secret", False)),
            }
        )
    return specs


def fingerprint_field(provider: MdmProvider) -> str | None:
    schema = CREDENTIAL_SCHEMAS.get(provider)
    return getattr(schema, "FINGERPRINT_FIELD", None) if schema else None
