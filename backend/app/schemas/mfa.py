from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class MfaChallengeOut(_CamelModel):
    """What the password step answers with, as HTTP 202, when the account has a second
    factor: a short-lived challenge and the ways to answer it."""

    challenge: str
    methods: list[str]


class MfaLoginRequest(_CamelModel):
    challenge: str = Field(min_length=1, max_length=512)
    # Six digits, or a recovery code; spaces and hyphens are forgiven.
    code: str = Field(min_length=6, max_length=32)


class MfaCodeRequest(_CamelModel):
    code: str = Field(min_length=6, max_length=32)


class MfaEnrolOut(_CamelModel):
    """Shown once: the secret as text and as the otpauth URL an authenticator app scans."""

    secret: str
    otpauth_url: str


class MfaConfirmOut(_CamelModel):
    """Shown once: the recovery codes, each good for one sign-in without the phone."""

    recovery_codes: list[str]
    confirmed_at: datetime


class MfaStatusOut(_CamelModel):
    enrolled: bool
    # An enrolment that was started and not yet proved by a code.
    pending: bool
    confirmed_at: datetime | None
    recovery_codes_remaining: int
