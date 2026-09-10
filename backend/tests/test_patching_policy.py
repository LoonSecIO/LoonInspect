"""The stated patching policy's pure facts (#116): a bounded statement, and the audit
action that names who stated it."""

from __future__ import annotations

import pytest
from pydantic import ValidationError


def test_the_statement_is_bounded_and_the_action_is_named() -> None:
    from app.core.audit import AuditAction
    from app.schemas.settings import STATEMENT_MAX_LENGTH, PatchingPolicyOut, PatchingPolicyUpdate

    assert PatchingPolicyUpdate(statement="x" * STATEMENT_MAX_LENGTH).statement
    with pytest.raises(ValidationError):
        PatchingPolicyUpdate(statement="x" * (STATEMENT_MAX_LENGTH + 1))
    # An unstated policy is an empty statement, not a missing field (#150).
    assert PatchingPolicyOut().model_dump(by_alias=True) == {"statement": "", "updatedAt": None, "updatedBy": None}
    assert AuditAction.PATCHING_POLICY_UPDATED == "patching-policy.updated"
