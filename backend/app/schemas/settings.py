"""Tenant settings that are typed text (#116) or one word of a few (#653), rather than switches."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_camel

from app.core import mfa
from app.mdm.patch.policy import MAX_DAYS, MAX_RELEASES

# Long enough for a paragraph an auditor reads, short enough that the page header stays a
# header. A policy longer than this is a document, and belongs in one.
STATEMENT_MAX_LENGTH = 4000


class PatchRule(BaseModel):
    """The organization's rule: the closed vocabulary of `app.mdm.patch.policy`. Both limits
    null is how the rule is cleared — nothing is judged, which is every tenant's start."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    max_days_behind: int | None = Field(default=None, ge=0, le=MAX_DAYS)
    max_releases_behind: int | None = Field(default=None, ge=0, le=MAX_RELEASES)
    # For a build carrying a critical or high finding, in place of `max_days_behind`.
    max_days_behind_severe: int | None = Field(default=None, ge=0, le=MAX_DAYS)

    @model_validator(mode="after")
    def _severe_is_never_looser(self) -> PatchRule:
        severe, ordinary = self.max_days_behind_severe, self.max_days_behind
        if severe is not None and ordinary is not None and severe > ordinary:
            raise ValueError(
                f"The limit for builds with critical or high findings ({severe} days) is longer than the ordinary limit "
                f"({ordinary} days). It replaces the ordinary limit for those builds, so it has to be the shorter of the two."
            )
        return self

    @property
    def limited(self) -> bool:
        return any(limit is not None for limit in (self.max_days_behind, self.max_releases_behind, self.max_days_behind_severe))


class PatchRuleOverride(PatchRule):
    """One title's own rule, which replaces the organization's for that title."""

    exempt: bool = False

    @model_validator(mode="after")
    def _says_something(self) -> PatchRuleOverride:
        limited = self.limited
        if self.exempt and limited:
            raise ValueError("An exempt title is not judged, so it carries no limits. Send exempt alone, or the limits alone.")
        if not self.exempt and not limited:
            raise ValueError(
                "An override needs a limit or exempt. To judge this title by the organization's rule again, delete the override."
            )
        return self


class PatchRuleOverrideOut(PatchRuleOverride):
    title_id: str
    # Null when the catalog no longer lists the title; the override is kept and named by id.
    title_name: str | None = None


class PatchingRulesOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    # Null when no organization-wide rule is confirmed.
    default: PatchRule | None = None
    overrides: list[PatchRuleOverrideOut] = Field(default_factory=list)
    updated_at: datetime | None = None
    updated_by: str | None = None


class PatchingPolicyOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    # "" when the org has stated nothing; the page says so in words rather than showing
    # nothing, so an empty statement and a failed read cannot look alike (#150).
    statement: str = ""
    updated_at: datetime | None = None
    updated_by: str | None = None
    # The confirmed rules, which are what a build is judged against; the statement is not.
    # Always present, empty when nothing is confirmed. Built by the route from
    # `app.mdm.patch.policy.Rules`, never validated off the row's stored document.
    rules: PatchingRulesOut = Field(default_factory=PatchingRulesOut)


class PatchingPolicyUpdate(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    statement: str = Field(max_length=STATEMENT_MAX_LENGTH)


class MfaPolicy(BaseModel):
    """Who must sign in with a second factor (#653); any other word is refused before the row."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    mfa_required: mfa.Policy
