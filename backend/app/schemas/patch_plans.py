"""Validated device scopes and immutable application patch-plan snapshots."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_camel


class ReportModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)


class ScopeRule(ReportModel):
    field: Literal["managed", "contact", "inventory", "group", "ea", "site", "department", "building", "os_version"]
    operator: Literal["is", "is_not", "contains", "within", "older", "unknown"] = "is"
    value: str = Field(default="", max_length=255)
    key: str = Field(default="", max_length=255)

    @model_validator(mode="after")
    def valid_rule(self):
        allowed = {
            "managed": {"is", "unknown"},
            "contact": {"within", "older", "unknown"},
            "inventory": {"within", "older", "unknown"},
            "group": {"is", "is_not"},
            "ea": {"is", "is_not", "unknown"},
        }.get(self.field, {"is", "is_not", "contains", "unknown"})
        if self.operator not in allowed:
            raise ValueError("This comparison is not supported for the selected device field.")
        if self.operator != "unknown" and not self.value.strip():
            raise ValueError("Enter a value for every device condition.")
        if self.field == "managed" and self.operator != "unknown" and self.value not in {"true", "false"}:
            raise ValueError("Managed must be true, false, or unknown.")
        if (
            self.field in {"contact", "inventory"}
            and self.operator != "unknown"
            and (not self.value.isdigit() or not 1 <= int(self.value) <= 3650)
        ):
            raise ValueError("The activity window must be between 1 and 3650 days.")
        if self.field in {"ea", "group"} and not self.key.strip():
            raise ValueError("Select an extension attribute or the group's Jamf connection.")
        if self.field == "group" and (not self.key.isdigit() or int(self.key) < 1):
            raise ValueError("A group needs its Jamf connection ID.")
        return self


class DeviceScope(ReportModel):
    model_config = ConfigDict(extra="forbid")
    connection_id: int | None = Field(default=None, ge=1)
    match: Literal["all", "any"] = "all"
    rules: list[ScopeRule] = Field(default_factory=list, max_length=20)


class BuildPlan(ReportModel):
    model_config = ConfigDict(extra="forbid")
    scope: DeviceScope = Field(default_factory=DeviceScope)
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


class ReviewPlan(ReportModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=1)
    owner: str = Field(default="", max_length=255)
    window: str = Field(default="", max_length=500)
    pilot: str = Field(default="", max_length=2000)
    recovery: str = Field(default="", max_length=2000)
    exceptions: str = Field(default="", max_length=4000)
    approval: str = Field(default="", max_length=1000)
