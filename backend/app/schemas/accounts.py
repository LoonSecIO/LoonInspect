from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pydantic.alias_generators import to_camel

from app.core.security import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class AccountSummaryOut(_CamelModel):
    id: str
    email: str
    display_name: str
    status: str
    roles: list[str]
    is_break_glass: bool
    is_service_account: bool
    # Non-null means an external system owns this record's lifecycle, and local edits
    # to the fields it manages will be reverted by the next sync.
    external_source: str | None
    created_at: datetime
    last_login_at: datetime | None


class AccountCreateRequest(_CamelModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=255)
    # Set by the administrator and conveyed out of band. There is no mail transport in
    # this application, so an emailed invite link isn't available; a token the admin
    # has to hand over anyway would be the same problem with more moving parts.
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    roles: list[str] = Field(default_factory=list)


class AccountUpdateRequest(_CamelModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    status: str | None = None
    roles: list[str] | None = None


class PasswordChangeRequest(_CamelModel):
    current_password: str
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class PasswordResetRequest(_CamelModel):
    """Administrative reset. Deliberately does not take the current password — the
    whole point is recovering an account whose password nobody has."""

    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
