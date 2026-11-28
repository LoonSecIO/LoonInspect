"""The wire shapes of a passkey (#955): the options a browser is handed, its answer, and the list on My Account."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.core.security import MAX_PASSWORD_LENGTH


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class PasskeyOptionsOut(_CamelModel):
    """What `navigator.credentials` is handed: `publicKey` is the JSON that `PublicKeyCredential.parseCreationOptionsFromJSON()`
    or `parseRequestOptionsFromJSON()` reads. The challenge in it is good for one answer, within five minutes."""

    public_key: dict[str, Any]


class PasskeyOptionsRequest(_CamelModel):
    """Adding a passkey starts with the current password, as changing it does: a session alone adds no way in."""

    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class PasskeySignInRequest(_CamelModel):
    """The browser's answer, as `PublicKeyCredential.toJSON()` writes it."""

    credential: dict[str, Any]


class PasskeyAddRequest(_CamelModel):
    """A new passkey: what its owner calls it, and the browser's answer, as `PublicKeyCredential.toJSON()` writes it.
    The name's own rule (1 to 64 characters once spaces are tidied) is the route's, with its sentence."""

    name: str = Field(max_length=256)
    credential: dict[str, Any]


class PasskeyOut(_CamelModel):
    """One passkey on My Account: its name, the host it works at (the one it was made at), and when it was made and
    last signed in, which is null until it first does."""

    id: str
    name: str
    host: str
    created_at: datetime
    last_used_at: datetime | None
