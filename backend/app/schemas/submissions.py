"""Coverage requests and corrections (#623), bounded as Support's contract bounds them; the service judges the rest."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from pydantic.alias_generators import to_camel

Line = Annotated[str, StringConstraints(min_length=1, max_length=256)]
Version = Annotated[str, StringConstraints(min_length=1, max_length=64)]
Url = Annotated[str, StringConstraints(max_length=512, pattern=r"^https://[!-~]+$")]
Finding = Annotated[str, StringConstraints(max_length=32, pattern=r"^(CVE-[0-9]{4}-[0-9]{4,}|LoonVD-[0-9]{4}-[0-9]{6})$")]


class Camel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)


class SubmissionIn(Camel):
    """What a case sends, and the one-time acts: permission, and sending an excluded app (a preview ignores both)."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["coverage", "correction"]
    app_name: Line
    bundle_id: Line | None = None
    platform: Literal["macos", "ios", "ipados", "tvos", "visionos"]
    versions: Annotated[list[Version], Field(min_length=1, max_length=20)]
    public_url: Url | None = None
    text: Annotated[str, StringConstraints(min_length=1, max_length=2000)] | None = None
    contact: Line | None = None
    finding: Finding | None = None
    finding_release: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | None = None
    permission: bool = False
    excluded_override: bool = False


class SubmissionPreviewOut(Camel):
    payload: dict  # exactly what Send puts on the wire, less the case key it mints then
    excluded_by: str | None  # the data-sharing exclusion pattern the bundle identifier matches


class SubmissionCaseOut(Camel):
    id: uuid.UUID
    created_at: datetime
    kind: str
    app_name: str
    bundle_id: str | None
    platform: str
    versions: list[str]
    public_url: str | None
    text: str | None
    contact: str | None
    finding: str | None
    finding_release: str | None
    state: str  # `pending` until the service acknowledges the case, then the contract's word, or `expired`
    received_at: datetime | None
    closed_at: datetime | None
    release: str | None
    coverage: str | None
    note: str | None
    last_status_at: datetime | None
    retry_at: datetime | None
    last_error: str | None
    withdrawn_at: datetime | None
    excluded_override: bool
    permission_at: datetime | None


class SubmissionCasesOut(Camel):
    enabled: bool  # whether this instance may send a new case (INTELLIGENCE_ACCESS)
    cases: list[SubmissionCaseOut]
