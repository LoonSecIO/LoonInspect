from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pydantic.alias_generators import to_camel

from app.core.permissions import Role
from app.core.security import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH

# Re-exported so callers can keep importing the wire-facing names from one module,
# while the authoritative definition stays next to the permission bundles it drives.
__all__ = [
    "AccountOut",
    "AuthStatusOut",
    "LoginRequest",
    "Role",
    "SetupRequest",
]


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class AuthStatusOut(_CamelModel):
    """Unauthenticated probe the SPA calls before rendering anything, so it knows
    whether to show the login screen or the first-run wizard."""

    setup_required: bool
    authenticated: bool
    # The running build, e.g. "2026.08.20+99361ed" — or the dev sentinel. None for an
    # anonymous caller on a claimed instance: once the repo is public the sha resolves
    # to a commit, so an exact build read off the sign-in page is a list of the fixes
    # this instance is missing (issue #130, narrowing the #41 exposure). Still sent
    # pre-auth while setup_required, where nobody owns the instance yet and the
    # first-run operator has no other surface to read it from.
    version: str | None


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
    # The wizard's community-sharing checkbox, carried here so the answer is recorded
    # in the same request that creates the administrator. It used to be a second,
    # best-effort PUT the browser fired afterwards and swallowed the failure of, which
    # only worked because "no write" happened to mean "reveal"; with consent defaulting
    # off, a dropped follow-up request would silently discard a yes.
    #
    # Defaulted False and not required: a caller that omits it — an older UI build, a
    # script someone wrote against last month's API — gets an install that does not
    # share. The failure mode of a missing consent field has to be no consent.
    #
    # A bool rather than the SharingTier enum because the wizard asks one yes/no
    # question; picking "keys" over "reveal" is a Settings decision, not a first-run one.
    share_community_data: bool = False
