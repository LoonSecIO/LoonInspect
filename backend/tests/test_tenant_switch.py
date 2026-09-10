"""The switch's pure facts (#36): a principal answers the acting tenant over the row's,
the request names its tenant, and the audit action exists."""

from __future__ import annotations

import uuid
from types import SimpleNamespace


def test_a_principal_acts_for_the_switched_tenant_and_keeps_its_home() -> None:
    from app.core.auth import Principal

    home, acting = uuid.uuid4(), uuid.uuid4()
    account = SimpleNamespace(tenant_id=home)
    session = SimpleNamespace(tenant_id=home)
    plain = Principal(account=account, permissions=frozenset(), auth_method="session", session=session)
    switched = Principal(
        account=account, permissions=frozenset(), auth_method="session", session=session, acting_tenant_id=acting
    )
    assert plain.tenant_id == home and plain.home_tenant_id == home
    assert switched.tenant_id == acting and switched.home_tenant_id == home


def test_the_request_and_the_action_are_named() -> None:
    from app.core.audit import AuditAction
    from app.schemas.auth import SwitchTenantRequest

    target = uuid.uuid4()
    assert SwitchTenantRequest.model_validate({"tenantId": str(target)}).tenant_id == target
    assert AuditAction.TENANT_SWITCHED == "auth.tenant.switched"
