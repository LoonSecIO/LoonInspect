"""Coverage requests and corrections (#623), bounded as Support's contract bounds them; the service judges the rest."""

from __future__ import annotations

import unicodedata
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints, ValidationInfo
from pydantic.alias_generators import to_camel
from pydantic_core import PydanticCustomError

# Support's "text" (docs/contracts/submissions.md) as Kyle ruled Support #17's decision 6 on 2026-09-27: not blank, no
# format character but the joiners (ZWNJ inside Persian words, ZWJ inside emoji sequences), no unpaired surrogate, no
# line or paragraph separator, no control character; `text` alone keeps newline and tab. Blank is Support #27's: nothing
# left once whitespace and the two joiners go, since a joiner alone shows nothing. The dialog checks the same
# (frontend/src/features/submissions/dialog.ts), and frontend/src/features/submissions/textRule.cases.json is the
# table both sides are tested against.
HIDDEN = frozenset({"Cf", "Cs", "Zl", "Zp", "Cc"})
JOINERS = chr(0x200C) + chr(0x200D)
_UNJOINED = dict.fromkeys(map(ord, JOINERS))  # for str.translate: drops both joiners


def text_refusal(field: str, value: str) -> str | None:
    """The sentence refusing `value` as `field`, the dialog's word for word, or None. It names the first hidden
    character by code point and place, counting code points from 1 (a plain emoji is one)."""
    kept = JOINERS + ("\n\t" if field == "text" else "")
    for at, char in enumerate(value, 1):
        if unicodedata.category(char) in HIDDEN and char not in kept:
            controls = "control character but newline and tab" if field == "text" else "control character"
            typed = field in ("text", "contact")  # the administrator writes these; the inventory names the build
            fix = "Delete it, then preview." if typed else "It comes from the inventory, so this build cannot be sent."
            return (
                f"{field} has U+{ord(char):04X} at character {at}, which a case cannot carry: no format character but the"
                f" joiners U+200C and U+200D, no unpaired surrogate, no line or paragraph separator, and no {controls}. {fix}"
            )
    if value.translate(_UNJOINED).strip():
        return None
    return (
        f"{field} is blank: it holds only spaces, tabs, line breaks or the joiners U+200C and U+200D,"
        " and a case takes no blank text."
    )


def _text(value: object, info: ValidationInfo) -> object:
    """Before the length check, which calls an unpaired surrogate raw data it cannot parse and names no field."""
    if isinstance(value, str) and (said := text_refusal(str(info.field_name), value)):
        raise PydanticCustomError("text_rule", said)
    return value


Line = Annotated[str, StringConstraints(min_length=1, max_length=256), BeforeValidator(_text)]
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
    text: Annotated[str, StringConstraints(min_length=1, max_length=2000), BeforeValidator(_text)] | None = None
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
    enabled: bool  # whether this instance may send a new case (INTELLIGENCE_ACCESS and INTELLIGENCE_SUBMISSIONS)
    cases: list[SubmissionCaseOut]
