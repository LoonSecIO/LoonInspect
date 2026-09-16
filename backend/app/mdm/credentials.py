from __future__ import annotations

import hashlib
import json
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic.alias_generators import to_camel

from app.schemas.payload import MdmProvider


class _CredentialsBase(BaseModel):
    # hide_input_in_errors: api/connections.py answers a refused credential set with
    # str(ValidationError), and pydantic's string quotes input_value — the whole set,
    # client secret included, whenever a field is missing. The field and the reason stay.
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, hide_input_in_errors=True)


class JamfCredentials(_CredentialsBase):
    client_id: str = Field(description="Client ID")
    client_secret: str = Field(description="Client Secret", json_schema_extra={"secret": True})

    FINGERPRINT_FIELD: ClassVar[str] = "client_secret"


CREDENTIAL_SCHEMAS: dict[MdmProvider, type[_CredentialsBase]] = {
    MdmProvider.jamf: JamfCredentials,
}


# What the operator calls the thing they have to re-enter. Never the class name: the
# sentence built below is read on Settings > Connections and in a failed run's error, by
# someone who has never seen `JamfCredentials` and must not have to (#393,
# docs/diagnosability.md rule 3).
CREDENTIAL_NOUN: dict[MdmProvider, str] = {
    MdmProvider.jamf: "Jamf API client",
}


class CredentialUnusable(RuntimeError):
    """What the column holds is not a credential — the neighbour of #374's wrong
    ENCRYPTION_KEY, where the key is right and the payload opened under it is `{}` or
    missing a field.

    Carries the sentence `refusal_sentence` builds and nothing else. A RuntimeError so a
    caller that already handles one keeps working; a type of its own so the sweep can
    refuse in words instead of letting pydantic's report reach `runs.error`.
    """


def decoded_credentials(stored: str | None) -> object:
    """The credential column as Python, without raising.

    `{}` for an empty column and `None` for a value that is not JSON at all — both of
    which fail validation below and become a sentence, which is the point: every way the
    column can hold a non-credential has to end at the same refusal, not at a decoder
    traceback in a different frame.
    """
    if not stored:
        return {}
    try:
        return json.loads(stored)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _names(aliases: list[str], conjunction: str) -> str:
    unique = list(dict.fromkeys(aliases))
    if len(unique) == 1:
        return unique[0]
    return f"{', '.join(unique[:-1])} {conjunction} {unique[-1]}"


def refusal_sentence(provider: MdmProvider, connection_name: str, exc: ValidationError) -> str:
    """One sentence: what to do, for which connection, and which field is wrong.

    Field names in the spelling the connection form shows (`clientId`), because the
    reader's next action is to find that box and fill it. Never a value — `hide_input_in_errors`
    keeps pydantic from quoting the stored set, and nothing here re-introduces it.
    """
    missing: list[str] = []
    unusable: list[str] = []
    for error in exc.errors():
        loc = error.get("loc") or ()
        if not loc:
            # A payload that is not an object at all: no field to name, so the clause
            # below says so rather than inventing one.
            continue
        (missing if error.get("type") == "missing" else unusable).append(to_camel(str(loc[0])))
    clauses = []
    if missing:
        clauses.append(f"has no {_names(missing, 'or')}")
    if unusable:
        clauses.append(f"cannot use its {_names(unusable, 'and')}")
    problem = " and ".join(clauses) or "is not a set of credential fields"
    noun = CREDENTIAL_NOUN.get(provider, "credential")
    return f'Re-enter the {noun} for "{connection_name}" on Settings › Connections — the stored credential {problem}.'


def credential_problem(provider: MdmProvider, connection_name: str, stored: str | None) -> str | None:
    """The same sentence as reportable state: what is wrong with this connection's stored
    credential, or None when nothing is.

    Computed at read time from the decrypted column rather than kept in one, because a
    column would have to be filled by a migration that decrypts — and a migration that
    decrypts is a migration that fails on a restore without its key (`88a6f0da5041`).
    """
    schema = CREDENTIAL_SCHEMAS.get(provider)
    if schema is None:
        return None
    try:
        schema.model_validate(decoded_credentials(stored))
    except ValidationError as exc:
        return refusal_sentence(provider, connection_name, exc)
    return None


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


# Twelve hex characters: 48 bits, which is more than enough to answer the only question
# the field is asked — "is this the same secret as before?" — and far too little to be
# worth anything else. Widen the column in a migration before widening this.
FINGERPRINT_LENGTH = 12


def credential_fingerprint(secret: str) -> str:
    """A short, non-reversible tag for a stored secret: the first twelve hex characters
    of SHA-256 over it.

    It exists so an operator can see that a rotation took, and so an auditor can ask
    "are these credentials being rotated?" without holding `CONNECTION_CREDENTIAL_READ`.
    Until #316 the tag was `secret[:3]` — three characters of the plaintext, returned to
    every role with `CONNECTION_READ`, which contradicted the role model the README
    documents. A truncated hash gives the same answer and discloses nothing of the value:
    the secrets it tags are the long random strings Jamf mints, so a prefix of their hash
    is not a foothold for guessing them either. Never recorded in the audit log, for the
    reason `api.connections` gives at the write site.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]
