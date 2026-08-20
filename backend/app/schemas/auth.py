from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pydantic.alias_generators import to_camel

from app.core.permissions import Role
from app.core.security import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH

# Re-exported so callers can keep importing the wire-facing names from one module,
# while the authoritative definition stays next to the permission bundles it drives.
__all__ = [
    "AccountOut",
    "AccountStatus",
    "AuthStatusOut",
    "LoginRequest",
    "Role",
    "SetupRequest",
]


class AccountStatus(StrEnum):
    active = "active"
    disabled = "disabled"
    invited = "invited"


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class AuthStatusOut(_CamelModel):
    """Unauthenticated probe the SPA calls before rendering anything, so it knows
    whether to show the login screen or the first-run wizard."""

    setup_required: bool
    authenticated: bool
    # The running build, e.g. "2026.08.20+99361ed" — or the dev sentinel. Shown on
    # the sign-in screen; deliberately exposed unauthenticated (see issue #41).
    version: str


class AccountOut(_CamelModel):
    id: str
    email: str
    display_name: str
    roles: list[str]
    # Effective permissions, resolved server-side from the roles above. Sent so the UI
    # can hide what the caller can't use — the server enforces independently, this is
    # only to avoid showing people buttons that will 403.
    permissions: list[str]
    is_break_glass: bool


class LoginRequest(_CamelModel):
    email: EmailStr
    # Not length-validated here: a rejected login must not reveal whether the failure
    # was policy or credentials. The DoS cap lives in verify_password().
    password: str


class SetupRequest(_CamelModel):
    claim_token: str
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
