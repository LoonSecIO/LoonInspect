"""Validated device scopes and immutable application patch-plan snapshots."""

import re
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_camel

from app.ai.providers import Provider
from app.schemas.applications import ApplicationScope


class ReportModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)


class ScopeRule(ReportModel):
    model_config = ConfigDict(extra="forbid")
    field: Literal["managed", "supervised", "contact", "inventory", "group", "ea", "site", "department", "building", "os_version"]
    operator: Literal[
        "is",
        "is_not",
        "contains",
        "like",
        "not_like",
        "matches_regex",
        "does_not_match_regex",
        "within",
        "older",
        "before",
        "after",
        "unknown",
    ] = "is"
    value: str = Field(default="", max_length=255)
    key: str = Field(default="", max_length=255)

    @model_validator(mode="after")
    def valid_rule(self):
        allowed = {
            "managed": {"is", "unknown"},
            "supervised": {"is", "unknown"},
            "contact": {"within", "older", "before", "after", "unknown"},
            "inventory": {"within", "older", "before", "after", "unknown"},
            "group": {"is", "is_not"},
            "ea": {"is", "is_not", "like", "not_like", "matches_regex", "does_not_match_regex", "unknown"},
        }.get(self.field, {"is", "is_not", "contains", "unknown"})
        if self.operator not in allowed:
            raise ValueError("This comparison is not supported for the selected device field.")
        if self.operator != "unknown" and not self.value.strip():
            raise ValueError("Enter a value for every device condition.")
        if self.field in {"managed", "supervised"} and self.operator != "unknown" and self.value not in {"true", "false"}:
            raise ValueError("Managed and Supervised must be true, false, or unknown.")
        if (
            self.field in {"contact", "inventory"}
            and self.operator in {"within", "older"}
            and (not self.value.isdigit() or not 1 <= int(self.value) <= 3650)
        ):
            raise ValueError("The activity window must be between 1 and 3650 days.")
        if self.operator in {"before", "after"}:
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", self.value):
                raise ValueError("Enter a calendar date as YYYY-MM-DD.")
            date.fromisoformat(self.value)
        if self.field in {"ea", "group"} and not self.key.strip():
            raise ValueError("Select an extension attribute or the group's Jamf connection.")
        if self.field == "group" and (not self.key.isdigit() or not 1 <= int(self.key) <= 2147483647):
            raise ValueError("A group needs its Jamf connection ID.")
        return self


class ScopeGroup(ReportModel):
    """A nonempty bracket inside a device scope; the connection remains at the root."""

    model_config = ConfigDict(extra="forbid")
    match: Literal["all", "any"] = "all"
    rules: list["ScopeRule | ScopeGroup"] = Field(min_length=1, max_length=20)


class DeviceScope(ReportModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["advanced_search", "smart_group"] = "advanced_search"
    connection_id: int | None = Field(default=None, ge=1, le=2147483647)
    match: Literal["all", "any"] = "all"
    rules: list[ScopeRule | ScopeGroup] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def smart_group_managed(self):
        pending = list(self.rules)
        while pending:
            rule = pending.pop()
            if isinstance(rule, ScopeGroup):
                pending.extend(rule.rules)
            elif self.mode == "smart_group" and rule.field == "managed":
                raise ValueError(
                    "Smart group style already includes only managed devices. Remove Managed conditions or use Advanced search."
                )
        return self

    @model_validator(mode="before")
    @classmethod
    def bound_tree(cls, value):
        """Bound the whole tree before recursively parsing it, including invalid input."""
        if not isinstance(value, dict):
            return value
        pending, conditions, groups = [(value, 1)], 0, 0
        while pending:
            node, depth = pending.pop()
            if not isinstance(node, dict):
                continue
            if "rules" in node:
                groups += 1
                if depth > 4 or groups > 10:
                    raise ValueError("Use at most four group levels and ten AND/OR groups.")
                children = node["rules"]
                if isinstance(children, list):
                    if len(children) > 20:
                        raise ValueError("Use at most twenty conditions across the device filter.")
                    pending.extend((child, depth + 1) for child in children)
            else:
                conditions += 1
                if conditions > 20:
                    raise ValueError("Use at most twenty conditions across the device filter.")
        return value


class BuildPlan(ReportModel):
    model_config = ConfigDict(extra="forbid")
    scope: DeviceScope = Field(default_factory=DeviceScope)
    application_scope: ApplicationScope = Field(default_factory=ApplicationScope)
    app_hashes: list[str] = Field(min_length=1, max_length=50)
    title: str = Field(default="Application patch plan", min_length=1, max_length=160)

    @model_validator(mode="after")
    def valid_hashes(self):
        import re

        if any(not re.fullmatch(r"[0-9a-f]{32}", value) for value in self.app_hashes):
            raise ValueError("Select installed applications before building a plan.")
        self.app_hashes = list(dict.fromkeys(self.app_hashes))
        return self


class ResearchPlan(ReportModel):
    provider: str | None = None
    installomator: bool = True


class ProposeScope(ReportModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=2000)
    scope: DeviceScope = Field(default_factory=DeviceScope)
    provider: Provider | None = None


class ReviewPlan(ReportModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=1)
    owner: str = Field(default="", max_length=255)
    window: str = Field(default="", max_length=500)
    pilot: str = Field(default="", max_length=2000)
    recovery: str = Field(default="", max_length=2000)
    exceptions: str = Field(default="", max_length=4000)
    approval: str = Field(default="", max_length=1000)
