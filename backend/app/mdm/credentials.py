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


CREDENTIAL_SCHEMAS: dict[MdmProvider, type[_CredentialsBase]] = {
    MdmProvider.jamf: JamfCredentials,
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


def secret_fields(provider: MdmProvider) -> frozenset[str]:
    """Canonical (snake_case) names of the fields that are secret material.

    Read off the same `secret: True` marker `field_specs` turns into password inputs,
    rather than a second hand-kept list: a provider added later with a secret nobody
    remembered to name here would silently lose the re-entry rule in
    `api.connections.update_connection`, and losing a control by omission is the
    failure mode worth engineering out.

    Canonical names, not aliases, because the callers compare against stored
    credentials — which `create_connection` writes under the schema's field names.
    """
    schema = CREDENTIAL_SCHEMAS.get(provider)
    if schema is None:
        return frozenset()
    return frozenset(
        name
        for name, field in schema.model_fields.items()
        if isinstance(field.json_schema_extra, dict) and field.json_schema_extra.get("secret")
    )


def fingerprint_field(provider: MdmProvider) -> str | None:
    schema = CREDENTIAL_SCHEMAS.get(provider)
    return getattr(schema, "FINGERPRINT_FIELD", None) if schema else None
